use crate::error::{LoreError, Result};
use flate2::read::GzDecoder;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;
use time::OffsetDateTime;
use uuid::Uuid;

pub const SERVER_SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/lore-server.service";
pub const SERVER_SYSTEMD_SERVICE_NAME: &str = "lore-server";
pub const DEFAULT_UPDATE_REPO: &str = "brontoguana/lore";
pub const SERVER_RELEASE_CLI_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStream {
    #[default]
    Stable,
    Prerelease,
}

impl ReleaseStream {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Prerelease => "prerelease",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoUpdateConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_update_repo")]
    pub github_repo: String,
    #[serde(default)]
    pub release_stream: ReleaseStream,
    #[serde(default)]
    pub auto_update_machines: bool,
    #[serde(default)]
    pub last_machine_rollout_version: Option<String>,
    pub updated_at: OffsetDateTime,
}

impl AutoUpdateConfig {
    pub fn default() -> Self {
        Self {
            enabled: false,
            github_repo: default_update_repo(),
            release_stream: ReleaseStream::Stable,
            auto_update_machines: false,
            last_machine_rollout_version: None,
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn new(
        enabled: bool,
        github_repo: String,
        release_stream: ReleaseStream,
        auto_update_machines: bool,
        last_machine_rollout_version: Option<String>,
    ) -> Result<Self> {
        validate_github_repo(&github_repo)?;
        Ok(Self {
            enabled,
            github_repo,
            release_stream,
            auto_update_machines,
            last_machine_rollout_version,
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

    pub fn update(
        &self,
        enabled: bool,
        github_repo: String,
        release_stream: ReleaseStream,
        auto_update_machines: bool,
    ) -> Result<AutoUpdateConfig> {
        let current = self.load()?;
        let config = AutoUpdateConfig::new(
            enabled,
            github_repo,
            release_stream,
            auto_update_machines,
            current.last_machine_rollout_version,
        )?;
        self.ensure_layout()?;
        write_json_atomic(self.config_path(), &config)?;
        Ok(config)
    }

    pub fn set_last_machine_rollout_version(
        &self,
        version: Option<String>,
    ) -> Result<AutoUpdateConfig> {
        let current = self.load()?;
        let config = AutoUpdateConfig::new(
            current.enabled,
            current.github_repo,
            current.release_stream,
            current.auto_update_machines,
            version,
        )?;
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

pub fn server_systemd_unit_exists() -> bool {
    Path::new(SERVER_SYSTEMD_UNIT_PATH).exists()
}

pub fn restart_server_via_systemd() -> Result<()> {
    if !server_systemd_unit_exists() {
        return Err(LoreError::ExternalService(format!(
            "systemd unit file not found: {SERVER_SYSTEMD_UNIT_PATH}"
        )));
    }

    run_sudo_systemctl(&["daemon-reload"])?;
    match run_sudo_systemctl(&["restart", SERVER_SYSTEMD_SERVICE_NAME]) {
        Ok(()) => Ok(()),
        Err(restart_err) => {
            if service_is_active(SERVER_SYSTEMD_SERVICE_NAME) {
                return Err(LoreError::ExternalService(format!(
                    "systemd restart failed while {SERVER_SYSTEMD_SERVICE_NAME} remained active: {restart_err}"
                )));
            }

            match run_sudo_systemctl(&["start", SERVER_SYSTEMD_SERVICE_NAME]) {
                Ok(()) if service_is_active(SERVER_SYSTEMD_SERVICE_NAME) => Ok(()),
                Ok(()) => Err(LoreError::ExternalService(format!(
                    "systemd restart failed and recovery start did not leave {SERVER_SYSTEMD_SERVICE_NAME} active: {restart_err}"
                ))),
                Err(start_err) => Err(LoreError::ExternalService(format!(
                    "systemd restart failed: {restart_err}; recovery start failed: {start_err}"
                ))),
            }
        }
    }
}

fn run_sudo_systemctl(args: &[&str]) -> Result<()> {
    let output = Command::new("sudo")
        .arg("-n")
        .arg("systemctl")
        .args(args)
        .output()
        .map_err(LoreError::Io)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {}", output.status.code().unwrap_or(-1))
    };
    Err(LoreError::ExternalService(format!(
        "sudo -n systemctl {} failed: {detail}",
        args.join(" ")
    )))
}

fn service_is_active(service_name: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", service_name])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub async fn check_for_update(
    client: &reqwest::Client,
    binary_name: &str,
    current_version: &str,
    github_repo: &str,
    release_stream: ReleaseStream,
) -> Result<UpdateCheck> {
    validate_github_repo(github_repo)?;
    let target = detect_target()?;
    eprintln!(
        "updater: checking {github_repo} ({}) for {binary_name} on {target}, current version {current_version}",
        release_stream.as_str()
    );
    let release = fetch_release(client, github_repo, release_stream, binary_name, &target).await?;
    eprintln!("updater: found release {}", release.tag_name);
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
    if needs_update {
        eprintln!("updater: update available {current_version} -> {latest_version}");
    } else {
        eprintln!("updater: up to date ({current_version})");
    }
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
    release_stream: ReleaseStream,
    executable_path: &Path,
) -> Result<SelfUpdateOutcome> {
    let check = check_for_update(
        client,
        binary_name,
        current_version,
        github_repo,
        release_stream,
    )
    .await?;
    if !check.needs_update {
        eprintln!("updater: no update needed");
        return Ok(SelfUpdateOutcome::UpToDate(AutoUpdateStatus {
            checked_at: OffsetDateTime::now_utc(),
            current_version: check.current_version,
            latest_version: Some(check.latest_version),
            detail: check.detail,
            applied: false,
            ok: true,
        }));
    }
    eprintln!(
        "updater: downloading {} -> {}",
        check.current_version, check.latest_version
    );
    let archive = fetch_bytes(client, &check.archive_url).await?;
    eprintln!(
        "updater: downloaded {} bytes, verifying checksum",
        archive.len()
    );
    let checksum = fetch_text(client, &check.checksum_url).await?;
    verify_checksum(&archive, &checksum)?;
    eprintln!(
        "updater: checksum verified, replacing binary at {}",
        executable_path.display()
    );
    replace_executable(binary_name, executable_path, &archive)?;
    eprintln!("updater: binary replaced successfully");
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

pub async fn apply_update_to_version(
    client: &reqwest::Client,
    binary_name: &str,
    current_version: &str,
    target_version: &str,
    github_repo: &str,
    executable_path: &Path,
) -> Result<SelfUpdateOutcome> {
    validate_github_repo(github_repo)?;
    let target = detect_target()?;
    let current_version = normalize_version_tag(current_version);
    let target_version = normalize_version_tag(target_version);
    if current_version == target_version {
        eprintln!("updater: already at target version {current_version}");
        return Ok(SelfUpdateOutcome::UpToDate(AutoUpdateStatus {
            checked_at: OffsetDateTime::now_utc(),
            current_version,
            latest_version: Some(target_version),
            detail: "already at target version".to_string(),
            applied: false,
            ok: true,
        }));
    }
    let tag = format!("v{target_version}");
    eprintln!("updater: fetching exact release {tag} from {github_repo}");
    let release = fetch_release_by_tag(client, github_repo, &tag).await?;
    let archive_name = format!("{binary_name}-{target}.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let archive_url = release
        .assets
        .iter()
        .find(|asset| asset.name == archive_name)
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| {
            LoreError::ExternalService(format!("release {tag} missing asset: {archive_name}"))
        })?;
    let checksum_url = release
        .assets
        .iter()
        .find(|asset| asset.name == checksum_name)
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| {
            LoreError::ExternalService(format!("release {tag} missing asset: {checksum_name}"))
        })?;
    eprintln!("updater: downloading {current_version} -> {target_version}");
    let archive = fetch_bytes(client, &archive_url).await?;
    eprintln!(
        "updater: downloaded {} bytes, verifying checksum",
        archive.len()
    );
    let checksum = fetch_text(client, &checksum_url).await?;
    verify_checksum(&archive, &checksum)?;
    eprintln!(
        "updater: checksum verified, replacing binary at {}",
        executable_path.display()
    );
    replace_executable(binary_name, executable_path, &archive)?;
    eprintln!("updater: binary replaced successfully");
    Ok(SelfUpdateOutcome::Updated(AutoUpdateStatus {
        checked_at: OffsetDateTime::now_utc(),
        current_version: current_version.clone(),
        latest_version: Some(target_version.clone()),
        detail: format!("updated {binary_name} from {current_version} to {target_version}"),
        applied: true,
        ok: true,
    }))
}

pub async fn download_update_to_path(
    client: &reqwest::Client,
    binary_name: &str,
    current_version: &str,
    target_version: &str,
    github_repo: &str,
    destination_path: &Path,
) -> Result<SelfUpdateOutcome> {
    validate_github_repo(github_repo)?;
    let target = detect_target()?;
    let current_version = normalize_version_tag(current_version);
    let target_version = normalize_version_tag(target_version);
    if current_version == target_version && destination_path.exists() {
        eprintln!("updater: already at target version {current_version}");
        return Ok(SelfUpdateOutcome::UpToDate(AutoUpdateStatus {
            checked_at: OffsetDateTime::now_utc(),
            current_version,
            latest_version: Some(target_version),
            detail: "already at target version".to_string(),
            applied: false,
            ok: true,
        }));
    }
    let tag = format!("v{target_version}");
    eprintln!("updater: fetching exact release {tag} from {github_repo}");
    let release = fetch_release_by_tag(client, github_repo, &tag).await?;
    let archive_name = format!("{binary_name}-{target}.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let archive_url = release
        .assets
        .iter()
        .find(|asset| asset.name == archive_name)
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| {
            LoreError::ExternalService(format!("release {tag} missing asset: {archive_name}"))
        })?;
    let checksum_url = release
        .assets
        .iter()
        .find(|asset| asset.name == checksum_name)
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| {
            LoreError::ExternalService(format!("release {tag} missing asset: {checksum_name}"))
        })?;
    eprintln!("updater: downloading {current_version} -> {target_version}");
    let archive = fetch_bytes(client, &archive_url).await?;
    eprintln!(
        "updater: downloaded {} bytes, verifying checksum",
        archive.len()
    );
    let checksum = fetch_text(client, &checksum_url).await?;
    verify_checksum(&archive, &checksum)?;
    let extracted = extract_binary(binary_name, &archive)?;
    eprintln!(
        "updater: checksum verified, staging binary at {}",
        destination_path.display()
    );
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_binary_atomic(destination_path, &extracted)?;
    Ok(SelfUpdateOutcome::Updated(AutoUpdateStatus {
        checked_at: OffsetDateTime::now_utc(),
        current_version: current_version.clone(),
        latest_version: Some(target_version.clone()),
        detail: format!("downloaded {binary_name} from {current_version} to {target_version}"),
        applied: true,
        ok: true,
    }))
}

pub async fn sync_release_binaries_to_directory(
    client: &reqwest::Client,
    binary_name: &str,
    target_version: &str,
    github_repo: &str,
    output_dir: &Path,
) -> Result<Vec<String>> {
    validate_github_repo(github_repo)?;
    let target_version = normalize_version_tag(target_version);
    fs::create_dir_all(output_dir)?;
    if release_binaries_are_current(binary_name, output_dir, &target_version) {
        return Ok(SERVER_RELEASE_CLI_TARGETS
            .iter()
            .map(|target| (*target).to_string())
            .collect());
    }

    let tag = format!("v{target_version}");
    let release = fetch_release_by_tag(client, github_repo, &tag).await?;
    let staging_dir = output_dir.join(format!(".sync-{}", Uuid::new_v4()));
    fs::create_dir_all(&staging_dir)?;

    for target in SERVER_RELEASE_CLI_TARGETS {
        let archive_name = format!("{binary_name}-{target}.tar.gz");
        let checksum_name = format!("{archive_name}.sha256");
        let archive_url = release
            .assets
            .iter()
            .find(|asset| asset.name == archive_name)
            .map(|asset| asset.browser_download_url.clone())
            .ok_or_else(|| {
                LoreError::ExternalService(format!("release {tag} missing asset: {archive_name}"))
            })?;
        let checksum_url = release
            .assets
            .iter()
            .find(|asset| asset.name == checksum_name)
            .map(|asset| asset.browser_download_url.clone())
            .ok_or_else(|| {
                LoreError::ExternalService(format!("release {tag} missing asset: {checksum_name}"))
            })?;
        let archive = fetch_bytes(client, &archive_url).await?;
        let checksum = fetch_text(client, &checksum_url).await?;
        verify_checksum(&archive, &checksum)?;
        let extracted = extract_binary(binary_name, &archive)?;
        write_binary_atomic(
            &staging_dir.join(release_binary_filename(binary_name, target)),
            &extracted,
        )?;
    }

    for target in SERVER_RELEASE_CLI_TARGETS {
        let filename = release_binary_filename(binary_name, target);
        fs::rename(staging_dir.join(&filename), output_dir.join(&filename))?;
    }
    let _ = fs::remove_dir(&staging_dir);
    fs::write(
        output_dir.join(format!("{binary_name}-release-version.txt")),
        target_version.as_bytes(),
    )?;
    Ok(SERVER_RELEASE_CLI_TARGETS
        .iter()
        .map(|target| (*target).to_string())
        .collect())
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
}

async fn fetch_release_by_tag(
    client: &reqwest::Client,
    github_repo: &str,
    tag: &str,
) -> Result<GithubRelease> {
    client
        .get(format!(
            "https://api.github.com/repos/{github_repo}/releases/tags/{tag}"
        ))
        .header(USER_AGENT, format!("lore/{}", env!("CARGO_PKG_VERSION")))
        .header(ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .error_for_status()
        .map_err(|err| LoreError::ExternalService(format!("release tag {tag} not found: {err}")))?
        .json::<GithubRelease>()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))
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

async fn fetch_release(
    client: &reqwest::Client,
    github_repo: &str,
    release_stream: ReleaseStream,
    binary_name: &str,
    target: &str,
) -> Result<GithubRelease> {
    match release_stream {
        ReleaseStream::Stable => fetch_latest_release(client, github_repo).await,
        ReleaseStream::Prerelease => {
            fetch_latest_prerelease(client, github_repo, binary_name, target).await
        }
    }
}

async fn fetch_latest_prerelease(
    client: &reqwest::Client,
    github_repo: &str,
    binary_name: &str,
    target: &str,
) -> Result<GithubRelease> {
    let archive_name = format!("{binary_name}-{target}.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let releases = client
        .get(format!(
            "https://api.github.com/repos/{github_repo}/releases"
        ))
        .header(USER_AGENT, format!("lore/{}", env!("CARGO_PKG_VERSION")))
        .header(ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .error_for_status()
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .json::<Vec<GithubRelease>>()
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))?;
    let mut candidates: Vec<GithubRelease> = releases
        .into_iter()
        .filter(|release| {
            release.prerelease
                && !release.draft
                && release
                    .assets
                    .iter()
                    .any(|asset| asset.name == archive_name)
                && release
                    .assets
                    .iter()
                    .any(|asset| asset.name == checksum_name)
        })
        .collect();
    candidates.sort_by(|a, b| {
        let a_ver = normalize_version_tag(&a.tag_name);
        let b_ver = normalize_version_tag(&b.tag_name);
        compare_versions(&b_ver, &a_ver)
    });
    candidates.into_iter().next().ok_or_else(|| {
        LoreError::ExternalService(format!("no matching prerelease found for target {target}"))
    })
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
        if matches!(
            path.file_name().and_then(|value| value.to_str()),
            Some(name) if name == binary_name || name == format!("{binary_name}.exe")
        ) {
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

pub fn hex_sha256(bytes: &[u8]) -> String {
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
    #[cfg(unix)]
    {
        // On Unix we always set 0o755 regardless of source permissions,
        // so skip reading source metadata (which fails if the running
        // binary was already deleted by a prior update).
        let _ = source;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    {
        let permissions = fs::metadata(source)?.permissions();
        fs::set_permissions(target, permissions)?;
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
    let (left_base, left_pre) = split_version(left);
    let (right_base, right_pre) = split_version(right);
    let left_parts: Vec<u64> = left_base.split('.').map(version_part_value).collect();
    let right_parts: Vec<u64> = right_base.split('.').map(version_part_value).collect();
    let len = left_parts.len().max(right_parts.len());
    for index in 0..len {
        let left_value = *left_parts.get(index).unwrap_or(&0);
        let right_value = *right_parts.get(index).unwrap_or(&0);
        match left_value.cmp(&right_value) {
            std::cmp::Ordering::Equal => {}
            non_equal => return non_equal,
        }
    }
    match (left_pre, right_pre) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(l), Some(r)) => version_part_value(l).cmp(&version_part_value(r)),
    }
}

fn split_version(v: &str) -> (&str, Option<&str>) {
    match v.find('-') {
        Some(i) => (&v[..i], Some(&v[i + 1..])),
        None => (v, None),
    }
}

fn version_part_value(part: &str) -> u64 {
    if let Ok(n) = part.parse::<u64>() {
        return n;
    }
    let digits: String = part.chars().skip_while(|c| !c.is_ascii_digit()).collect();
    digits.parse::<u64>().unwrap_or(0)
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

fn release_binary_filename(binary_name: &str, target: &str) -> String {
    format!("{binary_name}-{target}")
}

fn release_binaries_are_current(
    binary_name: &str,
    output_dir: &Path,
    target_version: &str,
) -> bool {
    let marker = output_dir.join(format!("{binary_name}-release-version.txt"));
    let recorded_version = match fs::read_to_string(marker) {
        Ok(value) => value,
        Err(_) => return false,
    };
    if normalize_version_tag(recorded_version.trim()) != target_version {
        return false;
    }
    SERVER_RELEASE_CLI_TARGETS.iter().all(|target| {
        output_dir
            .join(release_binary_filename(binary_name, target))
            .exists()
    })
}

fn write_binary_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    fs::write(&tmp_path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;
    }
    fs::rename(tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AutoUpdateConfigStore, DEFAULT_UPDATE_REPO, ReleaseStream, compare_versions,
        normalize_version_tag,
    };

    #[test]
    fn default_auto_update_config_uses_default_repo() {
        let dir = tempfile::tempdir().unwrap();
        let store = AutoUpdateConfigStore::new(dir.path());
        let config = store.load().unwrap();
        assert!(!config.enabled);
        assert_eq!(config.github_repo, DEFAULT_UPDATE_REPO);
        assert_eq!(config.release_stream, ReleaseStream::Stable);
        assert!(!config.auto_update_machines);
        assert_eq!(config.last_machine_rollout_version, None);
    }

    #[test]
    fn updating_auto_update_config_preserves_rollout_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = AutoUpdateConfigStore::new(dir.path());
        store
            .set_last_machine_rollout_version(Some("0.1.65-rc100".to_string()))
            .unwrap();

        let config = store
            .update(
                true,
                DEFAULT_UPDATE_REPO.to_string(),
                ReleaseStream::Prerelease,
                true,
            )
            .unwrap();

        assert!(config.enabled);
        assert_eq!(config.release_stream, ReleaseStream::Prerelease);
        assert!(config.auto_update_machines);
        assert_eq!(
            config.last_machine_rollout_version.as_deref(),
            Some("0.1.65-rc100")
        );
    }

    #[test]
    fn compare_versions_handles_semver_like_tags() {
        assert!(compare_versions("1.2.0", "1.1.9").is_gt());
        assert!(compare_versions("1.2.0", "1.2.0").is_eq());
        assert!(compare_versions("1.2.0", "1.2.1").is_lt());
        assert_eq!(normalize_version_tag("v0.1.0"), "0.1.0");
    }

    #[test]
    fn compare_versions_handles_rc_tags() {
        assert!(compare_versions("0.1.65-rc11", "0.1.65-rc8").is_gt());
        assert!(compare_versions("0.1.65-rc2", "0.1.65-rc1").is_gt());
        assert!(compare_versions("0.1.65-rc1", "0.1.65-rc1").is_eq());
        assert!(compare_versions("0.1.65-rc1", "0.1.65-rc2").is_lt());
        assert!(compare_versions("0.1.65-rc13", "0.1.65-rc9").is_gt());
    }

    #[test]
    fn stable_version_is_newer_than_rc() {
        assert!(compare_versions("0.1.65", "0.1.65-rc13").is_gt());
        assert!(compare_versions("0.1.65-rc13", "0.1.65").is_lt());
        assert!(compare_versions("0.1.66", "0.1.65-rc13").is_gt());
    }
}
