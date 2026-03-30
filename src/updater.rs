use crate::error::{LoreError, Result};
use flate2::read::GzDecoder;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use tar::Archive;
use time::OffsetDateTime;
use uuid::Uuid;

pub const DEFAULT_UPDATE_REPO: &str = "brontoguana/lore";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoUpdateConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_update_repo")]
    pub github_repo: String,
    pub updated_at: OffsetDateTime,
}

impl AutoUpdateConfig {
    pub fn default() -> Self {
        Self {
            enabled: false,
            github_repo: default_update_repo(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn new(enabled: bool, github_repo: String) -> Result<Self> {
        validate_github_repo(&github_repo)?;
        Ok(Self {
            enabled,
            github_repo,
            updated_at: OffsetDateTime::now_utc(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoUpdateStatus {
    pub checked_at: OffsetDateTime,
    pub current_version: String,
    pub latest_version: Option<String>,
    pub detail: String,
    pub applied: bool,
    pub ok: bool,
}

#[derive(Debug, Clone)]
pub struct AutoUpdateConfigStore {
    root: PathBuf,
}

impl AutoUpdateConfigStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<AutoUpdateConfig> {
        let path = self.config_path();
        if path.exists() {
            return Ok(serde_json::from_slice(&fs::read(path)?)?);
        }
        Ok(AutoUpdateConfig::default())
    }

    pub fn update(&self, enabled: bool, github_repo: String) -> Result<AutoUpdateConfig> {
        let config = AutoUpdateConfig::new(enabled, github_repo)?;
        self.ensure_layout()?;
        write_json_atomic(self.config_path(), &config)?;
        Ok(config)
    }

    fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn config_path(&self) -> PathBuf {
        self.config_dir().join("auto-update.json")
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
pub struct AutoUpdateStatusStore {
    root: PathBuf,
}

impl AutoUpdateStatusStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<Option<AutoUpdateStatus>> {
        let path = self.status_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }

    pub fn save(&self, status: &AutoUpdateStatus) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.status_path(), status)
    }

    fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn status_path(&self) -> PathBuf {
        self.config_dir().join("auto-update-status.json")
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
pub struct UpdateCheck {
    pub current_version: String,
    pub latest_version: String,
    pub needs_update: bool,
    pub detail: String,
    archive_url: String,
    checksum_url: String,
}

#[derive(Debug, Clone)]
pub enum SelfUpdateOutcome {
    UpToDate(AutoUpdateStatus),
    Updated(AutoUpdateStatus),
}

pub async fn check_for_update(
    client: &reqwest::Client,
    binary_name: &str,
    current_version: &str,
    github_repo: &str,
) -> Result<UpdateCheck> {
    validate_github_repo(github_repo)?;
    let release = fetch_latest_release(client, github_repo).await?;
    let target = detect_target()?;
    let archive_name = format!("{binary_name}-{target}.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let archive_url = release
        .assets
        .iter()
        .find(|asset| asset.name == archive_name)
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| {
            LoreError::ExternalService(format!("release asset missing: {archive_name}"))
        })?;
    let checksum_url = release
        .assets
        .iter()
        .find(|asset| asset.name == checksum_name)
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| {
            LoreError::ExternalService(format!("release asset missing: {checksum_name}"))
        })?;
    let latest_version = normalize_version_tag(&release.tag_name);
    let current_version = normalize_version_tag(current_version);
    let needs_update = version_is_newer(&latest_version, &current_version);
    Ok(UpdateCheck {
        detail: if needs_update {
            format!("update available: {current_version} -> {latest_version}")
        } else {
            format!("up to date: {current_version}")
        },
        current_version,
        latest_version,
        needs_update,
        archive_url,
        checksum_url,
    })
}

pub async fn maybe_apply_self_update(
    client: &reqwest::Client,
    binary_name: &str,
    current_version: &str,
    github_repo: &str,
    executable_path: &Path,
) -> Result<SelfUpdateOutcome> {
    let check = check_for_update(client, binary_name, current_version, github_repo).await?;
    if !check.needs_update {
        return Ok(SelfUpdateOutcome::UpToDate(AutoUpdateStatus {
            checked_at: OffsetDateTime::now_utc(),
            current_version: check.current_version,
            latest_version: Some(check.latest_version),
            detail: check.detail,
            applied: false,
            ok: true,
        }));
    }
    let archive = fetch_bytes(client, &check.archive_url).await?;
    let checksum = fetch_text(client, &check.checksum_url).await?;
    verify_checksum(&archive, &checksum)?;
    replace_executable(binary_name, executable_path, &archive)?;
    let current_version = check.current_version.clone();
    let latest_version = check.latest_version.clone();
    Ok(SelfUpdateOutcome::Updated(AutoUpdateStatus {
        checked_at: OffsetDateTime::now_utc(),
        current_version,
        latest_version: Some(latest_version.clone()),
        detail: format!(
            "updated {binary_name} from {} to {}",
            check.current_version, latest_version
        ),
        applied: true,
        ok: true,
    }))
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
}

async fn fetch_latest_release(
    client: &reqwest::Client,
    github_repo: &str,
) -> Result<GithubRelease> {
    client
        .get(format!(
            "https://api.github.com/repos/{github_repo}/releases/latest"
        ))
        .header(USER_AGENT, format!("lore/{}", env!("CARGO_PKG_VERSION")))
        .header(ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .error_for_status()
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .json::<GithubRelease>()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))
}

async fn fetch_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    client
        .get(url)
        .header(USER_AGENT, format!("lore/{}", env!("CARGO_PKG_VERSION")))
        .send()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .error_for_status()
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|err| LoreError::ExternalService(err.to_string()))
}

async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    client
        .get(url)
        .header(USER_AGENT, format!("lore/{}", env!("CARGO_PKG_VERSION")))
        .send()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .error_for_status()
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .text()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))
}

fn replace_executable(
    binary_name: &str,
    executable_path: &Path,
    archive_bytes: &[u8],
) -> Result<()> {
    let extracted = extract_binary(binary_name, archive_bytes)?;
    let parent = executable_path.parent().ok_or_else(|| {
        LoreError::ExternalService("current executable has no parent directory".into())
    })?;
    let temp_path = parent.join(format!(".{binary_name}.update-{}", Uuid::new_v4()));
    fs::write(&temp_path, extracted)?;
    copy_permissions(executable_path, &temp_path)?;
    fs::rename(&temp_path, executable_path)?;
    Ok(())
}

fn extract_binary(binary_name: &str, archive_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut archive = Archive::new(GzDecoder::new(Cursor::new(archive_bytes)));
    let entries = archive
        .entries()
        .map_err(|err| LoreError::ExternalService(err.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|err| LoreError::ExternalService(err.to_string()))?;
        let path = entry
            .path()
            .map_err(|err| LoreError::ExternalService(err.to_string()))?;
        if path.file_name().and_then(|value| value.to_str()) == Some(binary_name) {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|err| LoreError::ExternalService(err.to_string()))?;
            return Ok(bytes);
        }
    }
    Err(LoreError::ExternalService(format!(
        "archive does not contain executable {binary_name}"
    )))
}

fn verify_checksum(archive: &[u8], checksum_text: &str) -> Result<()> {
    let expected = checksum_text
        .split_whitespace()
        .next()
        .ok_or_else(|| LoreError::ExternalService("checksum file is empty".into()))?;
    let actual = hex_sha256(archive);
    if actual != expected {
        return Err(LoreError::ExternalService(
            "release checksum verification failed".into(),
        ));
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    let digest = hash.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn copy_permissions(source: &Path, target: &Path) -> Result<()> {
    let permissions = fs::metadata(source)?.permissions();
    fs::set_permissions(target, permissions)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn detect_target() -> Result<String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => {
            return Err(LoreError::ExternalService(format!(
                "unsupported architecture for self-update: {other}"
            )));
        }
    };
    let os = match std::env::consts::OS {
        "linux" => "unknown-linux-gnu",
        "macos" => "apple-darwin",
        other => {
            return Err(LoreError::ExternalService(format!(
                "unsupported operating system for self-update: {other}"
            )));
        }
    };
    Ok(format!("{arch}-{os}"))
}

fn default_update_repo() -> String {
    DEFAULT_UPDATE_REPO.to_string()
}

fn normalize_version_tag(value: &str) -> String {
    value.trim().trim_start_matches('v').to_string()
}

fn version_is_newer(candidate: &str, current: &str) -> bool {
    compare_versions(candidate, current).is_gt()
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left_parts = left
        .split(['.', '-'])
        .map(version_part_value)
        .collect::<Vec<_>>();
    let right_parts = right
        .split(['.', '-'])
        .map(version_part_value)
        .collect::<Vec<_>>();
    let len = left_parts.len().max(right_parts.len());
    for index in 0..len {
        let left_value = *left_parts.get(index).unwrap_or(&0);
        let right_value = *right_parts.get(index).unwrap_or(&0);
        match left_value.cmp(&right_value) {
            std::cmp::Ordering::Equal => {}
            non_equal => return non_equal,
        }
    }
    left.cmp(right)
}

fn version_part_value(part: &str) -> u64 {
    part.parse::<u64>().unwrap_or(0)
}

fn validate_github_repo(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 200 {
        return Err(LoreError::Validation(
            "github repo must be 1..=200 characters".into(),
        ));
    }
    if value.starts_with('/') || value.ends_with('/') || value.matches('/').count() != 1 {
        return Err(LoreError::Validation(
            "github repo must use owner/repo format".into(),
        ));
    }
    if value.chars().any(|ch| ch.is_ascii_whitespace()) {
        return Err(LoreError::Validation(
            "github repo must not contain whitespace".into(),
        ));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/'))
    {
        return Err(LoreError::Validation(
            "github repo must use ascii letters, digits, '-', '_', '.', and '/'".into(),
        ));
    }
    Ok(())
}

fn write_json_atomic(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    let bytes = serde_json::to_vec_pretty(value)?;
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut file = File::create(&tmp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AutoUpdateConfigStore, DEFAULT_UPDATE_REPO, compare_versions, normalize_version_tag,
    };

    #[test]
    fn default_auto_update_config_uses_default_repo() {
        let dir = tempfile::tempdir().unwrap();
        let store = AutoUpdateConfigStore::new(dir.path());
        let config = store.load().unwrap();
        assert!(!config.enabled);
        assert_eq!(config.github_repo, DEFAULT_UPDATE_REPO);
    }

    #[test]
    fn compare_versions_handles_semver_like_tags() {
        assert!(compare_versions("1.2.0", "1.1.9").is_gt());
        assert!(compare_versions("1.2.0", "1.2.0").is_eq());
        assert!(compare_versions("1.2.0", "1.2.1").is_lt());
        assert_eq!(normalize_version_tag("v0.1.0"), "0.1.0");
    }
}
