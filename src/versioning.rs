use crate::error::{LoreError, Result};
use crate::model::{BlockId, BlockType, KeyFingerprint, OrderKey, ProjectName, StoredBlock};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;

const DEFAULT_GIT_EXPORT_BRANCH: &str = "main";
const DEFAULT_GIT_EXPORT_AUTHOR_NAME: &str = "Lore";
const DEFAULT_GIT_EXPORT_AUTHOR_EMAIL: &str = "lore@localhost";
const MAX_GIT_REMOTE_URL_LEN: usize = 2048;
const MAX_GIT_BRANCH_LEN: usize = 128;
const MAX_GIT_AUTHOR_FIELD_LEN: usize = 256;
const DEFAULT_MAX_VERSIONS_PER_PROJECT: usize = 500;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectVersionActorKind {
    User,
    Agent,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectVersionActor {
    pub kind: ProjectVersionActorKind,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectVersionOperationType {
    CreateBlock,
    UpdateBlock,
    MoveBlock,
    DeleteBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredMediaSnapshot {
    pub media_type: String,
    pub bytes_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredBlockSnapshot {
    pub id: BlockId,
    pub project: ProjectName,
    pub block_type: BlockType,
    pub order: OrderKey,
    pub author: KeyFingerprint,
    pub content: String,
    pub media: Option<StoredMediaSnapshot>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredProjectVersionOperation {
    pub operation_type: ProjectVersionOperationType,
    pub block_id: BlockId,
    pub before: Option<StoredBlockSnapshot>,
    pub after: Option<StoredBlockSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredProjectVersion {
    pub id: String,
    pub project: ProjectName,
    pub actor: ProjectVersionActor,
    pub summary: String,
    pub operations: Vec<StoredProjectVersionOperation>,
    pub git_commit: Option<String>,
    pub git_export_error: Option<String>,
    pub reverted_from_version_id: Option<String>,
    pub reverted_by_version_id: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitExportConfig {
    #[serde(default)]
    pub enabled: bool,
    pub remote_url: String,
    #[serde(default = "default_git_export_branch")]
    pub branch: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default = "default_git_export_author_name")]
    pub author_name: String,
    #[serde(default = "default_git_export_author_email")]
    pub author_email: String,
    #[serde(default)]
    pub auto_export: bool,
    pub updated_at: OffsetDateTime,
}

impl GitExportConfig {
    pub fn default() -> Self {
        Self {
            enabled: false,
            remote_url: String::new(),
            branch: default_git_export_branch(),
            token: None,
            author_name: default_git_export_author_name(),
            author_email: default_git_export_author_email(),
            auto_export: false,
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.remote_url.is_empty()
            && self.branch == default_git_export_branch()
            && self.token.is_none()
            && self.author_name == default_git_export_author_name()
            && self.author_email == default_git_export_author_email()
            && !self.enabled
            && !self.auto_export
        {
            return Ok(());
        }
        validate_git_remote_url(&self.remote_url)?;
        validate_git_branch(&self.branch)?;
        validate_git_author_field(&self.author_name, "git author name")?;
        validate_git_author_field(&self.author_email, "git author email")?;
        if self.enabled && self.remote_url.trim().is_empty() {
            return Err(LoreError::Validation(
                "git export requires a remote url".into(),
            ));
        }
        Ok(())
    }

    pub fn is_configured(&self) -> bool {
        self.enabled && !self.remote_url.trim().is_empty()
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum GitExportTokenUpdate<'a> {
    Preserve,
    Replace(&'a str),
    Clear,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitExportStatus {
    pub ok: bool,
    pub detail: String,
    pub commit: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct ProjectHistoryStore {
    root: PathBuf,
    max_versions: usize,
}

impl ProjectHistoryStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_versions: DEFAULT_MAX_VERSIONS_PER_PROJECT,
        }
    }

    pub fn with_max_versions(mut self, max_versions: usize) -> Self {
        if max_versions > 0 {
            self.max_versions = max_versions;
        }
        self
    }

    pub fn list_recent_project(
        &self,
        project: &ProjectName,
        limit: usize,
    ) -> Result<Vec<StoredProjectVersion>> {
        let mut versions = self.load_project(project)?;
        versions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        versions.truncate(limit);
        Ok(versions)
    }

    pub fn append(&self, version: StoredProjectVersion) -> Result<()> {
        let mut versions = self.load_project(&version.project)?;
        versions.push(version);
        if versions.len() > self.max_versions {
            versions.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            let excess = versions.len() - self.max_versions;
            versions.drain(..excess);
        }
        self.save_project_versions(&versions)
    }

    pub fn get(&self, project: &ProjectName, id: &str) -> Result<Option<StoredProjectVersion>> {
        Ok(self
            .load_project(project)?
            .into_iter()
            .find(|version| version.id == id))
    }

    pub fn mark_reverted(
        &self,
        project: &ProjectName,
        id: &str,
        reverted_by_version_id: &str,
    ) -> Result<()> {
        let mut versions = self.load_project(project)?;
        let mut changed = false;
        for version in &mut versions {
            if version.id == id {
                version.reverted_by_version_id = Some(reverted_by_version_id.to_string());
                changed = true;
                break;
            }
        }
        if changed {
            self.save_project_versions(&versions)?;
        }
        Ok(())
    }

    fn load_project(&self, project: &ProjectName) -> Result<Vec<StoredProjectVersion>> {
        let path = self.project_history_path(project);
        if !path.exists() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    fn save_project_versions(&self, versions: &[StoredProjectVersion]) -> Result<()> {
        self.ensure_layout()?;
        let Some(project) = versions.first().map(|version| version.project.clone()) else {
            return Ok(());
        };
        write_json_atomic(self.project_history_path(&project), versions)
    }

    fn history_dir(&self) -> PathBuf {
        self.root.join("config").join("project-history")
    }

    fn project_history_path(&self, project: &ProjectName) -> PathBuf {
        self.history_dir()
            .join(format!("{}.json", project.as_str()))
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.history_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.history_dir(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GitExportConfigStore {
    root: PathBuf,
}

impl GitExportConfigStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<GitExportConfig> {
        let path = self.config_path();
        if path.exists() {
            let config: GitExportConfig = serde_json::from_slice(&fs::read(path)?)?;
            config.validate()?;
            return Ok(config);
        }
        Ok(GitExportConfig::default())
    }

    pub fn update(
        &self,
        enabled: bool,
        remote_url: String,
        branch: String,
        token: GitExportTokenUpdate<'_>,
        author_name: String,
        author_email: String,
        auto_export: bool,
    ) -> Result<GitExportConfig> {
        self.ensure_layout()?;
        let existing = self.load()?;
        let config = GitExportConfig {
            enabled,
            remote_url: remote_url.trim().to_string(),
            branch: branch.trim().to_string(),
            token: match token {
                GitExportTokenUpdate::Preserve => existing.token,
                GitExportTokenUpdate::Replace(value) => Some(value.trim().to_string()),
                GitExportTokenUpdate::Clear => None,
            },
            author_name: author_name.trim().to_string(),
            author_email: author_email.trim().to_string(),
            auto_export,
            updated_at: OffsetDateTime::now_utc(),
        };
        config.validate()?;
        write_json_atomic(self.config_path(), &config)?;
        Ok(config)
    }

    fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn config_path(&self) -> PathBuf {
        self.config_dir().join("git-export.json")
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.config_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.config_dir(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GitExportStatusStore {
    root: PathBuf,
}

impl GitExportStatusStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<Option<GitExportStatus>> {
        let path = self.status_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }

    pub fn save(&self, status: &GitExportStatus) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.status_path(), status)
    }

    fn status_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn status_path(&self) -> PathBuf {
        self.status_dir().join("git-export-status.json")
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.status_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.status_dir(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

pub fn run_git_export(
    lore_root: &Path,
    config: &GitExportConfig,
    summary: &str,
) -> Result<Option<String>> {
    config.validate()?;
    if !config.is_configured() {
        return Ok(None);
    }

    let repo_dir = lore_root.join("config").join("git-export-repo");
    fs::create_dir_all(&repo_dir)?;
    ensure_git_repo(&repo_dir)?;
    configure_remote(&repo_dir, config)?;
    configure_author(&repo_dir, config)?;
    checkout_branch(&repo_dir, config)?;
    clear_worktree(&repo_dir)?;
    copy_snapshot_dir(&lore_root.join("projects"), &repo_dir.join("projects"))?;
    copy_snapshot_dir(
        &lore_root.join("config").join("project-history"),
        &repo_dir.join("history"),
    )?;
    let status = run_git(&repo_dir, config, &["status", "--porcelain"])?;
    if status.trim().is_empty() {
        return Ok(Some(
            run_git(&repo_dir, config, &["rev-parse", "HEAD"]).unwrap_or_default(),
        ));
    }
    run_git(&repo_dir, config, &["add", "-A"])?;
    let message = format!("Lore export: {}", summary.trim());
    run_git(&repo_dir, config, &["commit", "-m", &message])?;
    run_git(&repo_dir, config, &["push", "-u", "origin", &config.branch])?;
    Ok(Some(run_git(&repo_dir, config, &["rev-parse", "HEAD"])?))
}

pub fn block_matches_snapshot(
    current: &crate::model::Block,
    snapshot: &StoredBlockSnapshot,
) -> bool {
    current.id == snapshot.id
        && current.project == snapshot.project
        && current.block_type == snapshot.block_type
        && current.order == snapshot.order
        && current.author == snapshot.author
        && current.content == snapshot.content
        && current.media_type
            == snapshot
                .media
                .as_ref()
                .map(|media| media.media_type.clone())
        && current.created_at == snapshot.created_at
}

fn ensure_git_repo(repo_dir: &Path) -> Result<()> {
    if repo_dir.join(".git").exists() {
        return Ok(());
    }
    run_git_without_repo(repo_dir, &["init"])?;
    Ok(())
}

fn configure_remote(repo_dir: &Path, config: &GitExportConfig) -> Result<()> {
    let remotes = run_git(repo_dir, config, &["remote"])?;
    if remotes.lines().any(|line| line.trim() == "origin") {
        run_git(
            repo_dir,
            config,
            &["remote", "set-url", "origin", &config.remote_url],
        )?;
    } else {
        run_git(
            repo_dir,
            config,
            &["remote", "add", "origin", &config.remote_url],
        )?;
    }
    Ok(())
}

fn configure_author(repo_dir: &Path, config: &GitExportConfig) -> Result<()> {
    run_git(
        repo_dir,
        config,
        &["config", "user.name", &config.author_name],
    )?;
    run_git(
        repo_dir,
        config,
        &["config", "user.email", &config.author_email],
    )?;
    Ok(())
}

fn checkout_branch(repo_dir: &Path, config: &GitExportConfig) -> Result<()> {
    let fetch_result = run_git(repo_dir, config, &["fetch", "origin", &config.branch]);
    if run_git(repo_dir, config, &["rev-parse", "--verify", &config.branch]).is_ok() {
        run_git(repo_dir, config, &["checkout", &config.branch])?;
        return Ok(());
    }
    if fetch_result.is_ok()
        && run_git(
            repo_dir,
            config,
            &[
                "rev-parse",
                "--verify",
                &format!("origin/{}", config.branch),
            ],
        )
        .is_ok()
    {
        run_git(
            repo_dir,
            config,
            &[
                "checkout",
                "-B",
                &config.branch,
                &format!("origin/{}", config.branch),
            ],
        )?;
    } else {
        run_git(repo_dir, config, &["checkout", "--orphan", &config.branch])?;
    }
    Ok(())
}

fn clear_worktree(repo_dir: &Path) -> Result<()> {
    for entry in fs::read_dir(repo_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().and_then(|value| value.to_str()) == Some(".git") {
            continue;
        }
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn copy_snapshot_dir(source: &Path, destination: &Path) -> Result<()> {
    if !source.exists() {
        return Ok(());
    }
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_snapshot_dir(&source_path, &destination_path)?;
        } else {
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

fn run_git(repo_dir: &Path, config: &GitExportConfig, args: &[&str]) -> Result<String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo_dir);
    if let Some(token) = &config.token {
        let auth = BASE64.encode(format!("x-access-token:{token}"));
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.extraHeader")
            .env("GIT_CONFIG_VALUE_0", format!("Authorization: Basic {auth}"));
    }
    command.args(args);
    let output = command.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("git command failed: git {}", args.join(" "))
        } else {
            stderr
        };
        return Err(LoreError::ExternalService(message));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_git_without_repo(repo_dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(repo_dir)
        .args(args)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("git command failed: git {}", args.join(" "))
        } else {
            stderr
        };
        return Err(LoreError::ExternalService(message));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn default_git_export_branch() -> String {
    DEFAULT_GIT_EXPORT_BRANCH.to_string()
}

fn default_git_export_author_name() -> String {
    DEFAULT_GIT_EXPORT_AUTHOR_NAME.to_string()
}

fn default_git_export_author_email() -> String {
    DEFAULT_GIT_EXPORT_AUTHOR_EMAIL.to_string()
}

fn validate_git_remote_url(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_GIT_REMOTE_URL_LEN {
        return Err(LoreError::Validation(format!(
            "git remote url must be 1..={MAX_GIT_REMOTE_URL_LEN} characters"
        )));
    }
    if !(value.starts_with("https://")
        || value.starts_with("http://")
        || value.starts_with("file://"))
    {
        return Err(LoreError::Validation(
            "git remote url must start with http://, https://, or file://".into(),
        ));
    }
    Ok(())
}

fn validate_git_branch(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_GIT_BRANCH_LEN {
        return Err(LoreError::Validation(format!(
            "git branch must be 1..={MAX_GIT_BRANCH_LEN} characters"
        )));
    }
    if value.starts_with('-') {
        return Err(LoreError::Validation(
            "git branch must not start with a dash".into(),
        ));
    }
    if value.contains(' ') || value.contains("..") {
        return Err(LoreError::Validation(
            "git branch contains unsafe characters".into(),
        ));
    }
    Ok(())
}

fn validate_git_author_field(value: &str, label: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_GIT_AUTHOR_FIELD_LEN {
        return Err(LoreError::Validation(format!(
            "{label} must be 1..={MAX_GIT_AUTHOR_FIELD_LEN} characters"
        )));
    }
    Ok(())
}

fn write_json_atomic(path: PathBuf, value: &(impl Serialize + ?Sized)) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!(
        "tmp-{}",
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

pub fn snapshot_from_stored_block(
    stored: StoredBlock,
    content: String,
    media: Option<(String, Vec<u8>)>,
) -> StoredBlockSnapshot {
    StoredBlockSnapshot {
        id: stored.id,
        project: stored.project,
        block_type: stored.block_type,
        order: stored.order,
        author: stored.author,
        content,
        media: media.map(|(media_type, bytes)| StoredMediaSnapshot {
            media_type,
            bytes_base64: BASE64.encode(bytes),
        }),
        created_at: stored.created_at,
    }
}

pub fn media_bytes(snapshot: &StoredMediaSnapshot) -> Result<Vec<u8>> {
    BASE64
        .decode(snapshot.bytes_base64.as_bytes())
        .map_err(|_| LoreError::Validation("stored media snapshot is not valid base64".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProjectName;

    fn make_version(project: &ProjectName, summary: &str) -> StoredProjectVersion {
        StoredProjectVersion {
            id: uuid::Uuid::new_v4().to_string(),
            project: project.clone(),
            actor: ProjectVersionActor {
                kind: ProjectVersionActorKind::User,
                name: "test".into(),
            },
            summary: summary.into(),
            operations: Vec::new(),
            git_commit: None,
            git_export_error: None,
            reverted_from_version_id: None,
            reverted_by_version_id: None,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn enforces_retention_limit() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProjectHistoryStore::new(dir.path()).with_max_versions(3);
        let project = ProjectName::new("test.docs").unwrap();

        for i in 0..5 {
            store
                .append(make_version(&project, &format!("v{i}")))
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let versions = store.load_project(&project).unwrap();
        assert_eq!(versions.len(), 3, "should retain at most 3 versions");
        let summaries: Vec<&str> = versions.iter().map(|v| v.summary.as_str()).collect();
        assert_eq!(summaries, vec!["v2", "v3", "v4"], "should keep newest");
    }
}
