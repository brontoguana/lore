use crate::error::{LoreError, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalScheme {
    Http,
    Https,
}

impl ExternalScheme {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(LoreError::Validation(
                "external scheme must be http or https".into(),
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UiTheme {
    Parchment,
    Graphite,
    Signal,
}

impl UiTheme {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "parchment" => Ok(Self::Parchment),
            "graphite" => Ok(Self::Graphite),
            "signal" => Ok(Self::Signal),
            _ => Err(LoreError::Validation(
                "theme must be parchment, graphite, or signal".into(),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parchment => "parchment",
            Self::Graphite => "graphite",
            Self::Signal => "signal",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Parchment => "Parchment",
            Self::Graphite => "Graphite",
            Self::Signal => "Signal",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Parchment, Self::Graphite, Self::Signal]
    }
}

fn default_ui_theme() -> UiTheme {
    UiTheme::Parchment
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    pub external_scheme: ExternalScheme,
    pub external_host: String,
    pub external_port: u16,
    #[serde(default = "default_ui_theme")]
    pub default_theme: UiTheme,
    pub updated_at: OffsetDateTime,
}

const DEFAULT_EXTERNAL_AUTH_USERNAME_HEADER: &str = "x-forwarded-user";
const DEFAULT_EXTERNAL_AUTH_SECRET_HEADER: &str = "x-lore-proxy-auth";
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_OIDC_URL_LEN: usize = 2048;
const MAX_OIDC_CLIENT_ID_LEN: usize = 256;
const MAX_OIDC_CLIENT_SECRET_LEN: usize = 2048;
const MAX_OIDC_CALLBACK_PATH_LEN: usize = 256;
const DEFAULT_OIDC_CALLBACK_PATH: &str = "/login/oidc/callback";
const DEFAULT_OIDC_USERNAME_CLAIM: &str = "preferred_username";
const OIDC_LOGIN_STATE_TTL_SECS: i64 = 600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_external_auth_username_header")]
    pub username_header: String,
    #[serde(default = "default_external_auth_secret_header")]
    pub secret_header: String,
    #[serde(default)]
    pub secret_value: Option<String>,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OidcUsernameClaim {
    PreferredUsername,
    Email,
    Subject,
}

impl OidcUsernameClaim {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreferredUsername => "preferred_username",
            Self::Email => "email",
            Self::Subject => "sub",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "preferred_username" => Ok(Self::PreferredUsername),
            "email" => Ok(Self::Email),
            "sub" => Ok(Self::Subject),
            _ => Err(LoreError::Validation(
                "oidc username claim must be preferred_username, email, or sub".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    pub issuer_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default = "default_oidc_callback_path")]
    pub callback_path: String,
    #[serde(default = "default_oidc_username_claim")]
    pub username_claim: OidcUsernameClaim,
    pub updated_at: OffsetDateTime,
}

impl OidcConfig {
    pub fn default() -> Self {
        Self {
            enabled: false,
            issuer_url: String::new(),
            client_id: String::new(),
            client_secret: None,
            callback_path: default_oidc_callback_path(),
            username_claim: default_oidc_username_claim(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.issuer_url.is_empty() && self.client_id.is_empty() && self.client_secret.is_none() {
            return Ok(());
        }
        validate_url(&self.issuer_url, "oidc issuer url", MAX_OIDC_URL_LEN)?;
        validate_nonempty_text(&self.client_id, "oidc client id", MAX_OIDC_CLIENT_ID_LEN)?;
        validate_callback_path(&self.callback_path)?;
        if self.enabled
            && self
                .client_secret
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            return Err(LoreError::Validation(
                "oidc requires a non-empty client secret".into(),
            ));
        }
        if let Some(secret) = &self.client_secret {
            validate_nonempty_text(secret, "oidc client secret", MAX_OIDC_CLIENT_SECRET_LEN)?;
        }
        Ok(())
    }

    pub fn is_configured(&self) -> bool {
        self.enabled
            && !self.issuer_url.is_empty()
            && !self.client_id.is_empty()
            && self.client_secret.is_some()
    }

    pub fn has_client_secret(&self) -> bool {
        self.client_secret.is_some()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OidcSecretUpdate<'a> {
    Preserve,
    Replace(&'a str),
    Clear,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredOidcLoginState {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub created_at: OffsetDateTime,
    pub return_to: Option<String>,
}

impl ExternalAuthConfig {
    pub fn default() -> Self {
        Self {
            enabled: false,
            username_header: default_external_auth_username_header(),
            secret_header: default_external_auth_secret_header(),
            secret_value: None,
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_header_name(&self.username_header, "external auth username header")?;
        validate_header_name(&self.secret_header, "external auth secret header")?;
        if self.enabled && self.secret_value.as_deref().unwrap_or("").trim().is_empty() {
            return Err(LoreError::Validation(
                "external auth requires a non-empty shared secret".into(),
            ));
        }
        Ok(())
    }

    pub fn is_configured(&self) -> bool {
        self.enabled && self.secret_value.is_some()
    }

    pub fn has_secret(&self) -> bool {
        self.secret_value.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct OidcConfigStore {
    root: PathBuf,
}

impl OidcConfigStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<OidcConfig> {
        let path = self.config_path();
        if path.exists() {
            let config: OidcConfig = serde_json::from_slice(&fs::read(path)?)?;
            config.validate()?;
            return Ok(config);
        }
        Ok(OidcConfig::default())
    }

    pub fn update(
        &self,
        enabled: bool,
        issuer_url: String,
        client_id: String,
        client_secret: OidcSecretUpdate<'_>,
        callback_path: String,
        username_claim: OidcUsernameClaim,
    ) -> Result<OidcConfig> {
        self.ensure_layout()?;
        let existing = self.load()?;
        let config = OidcConfig {
            enabled,
            issuer_url: issuer_url.trim().to_string(),
            client_id: client_id.trim().to_string(),
            client_secret: match client_secret {
                OidcSecretUpdate::Preserve => existing.client_secret,
                OidcSecretUpdate::Replace(value) => Some(value.trim().to_string()),
                OidcSecretUpdate::Clear => None,
            },
            callback_path: callback_path.trim().to_string(),
            username_claim,
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
        self.config_dir().join("oidc.json")
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
pub struct OidcLoginStateStore {
    root: PathBuf,
}

impl OidcLoginStateStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn save(&self, state: StoredOidcLoginState) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.state_path(&state.state), &state)
    }

    pub fn take(&self, state: &str) -> Result<Option<StoredOidcLoginState>> {
        if state.is_empty()
            || !state
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Ok(None);
        }
        self.ensure_layout()?;
        let path = self.state_path(state);
        if !path.exists() {
            return Ok(None);
        }
        let stored: StoredOidcLoginState = serde_json::from_slice(&fs::read(&path)?)?;
        fs::remove_file(path)?;
        let age = OffsetDateTime::now_utc() - stored.created_at;
        if age.whole_seconds() > OIDC_LOGIN_STATE_TTL_SECS {
            return Ok(None);
        }
        Ok(Some(stored))
    }

    fn state_dir(&self) -> PathBuf {
        self.root.join("config").join("oidc-states")
    }

    fn state_path(&self, state: &str) -> PathBuf {
        self.state_dir().join(format!("{state}.json"))
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.state_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.state_dir(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ExternalAuthSecretUpdate<'a> {
    Preserve,
    Replace(&'a str),
    Clear,
}

#[derive(Debug, Clone)]
pub struct ExternalAuthStore {
    root: PathBuf,
}

impl ExternalAuthStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<ExternalAuthConfig> {
        let path = self.config_path();
        if path.exists() {
            let config: ExternalAuthConfig = serde_json::from_slice(&fs::read(path)?)?;
            config.validate()?;
            return Ok(config);
        }
        Ok(ExternalAuthConfig::default())
    }

    pub fn update(
        &self,
        enabled: bool,
        username_header: String,
        secret_header: String,
        secret_value: ExternalAuthSecretUpdate<'_>,
    ) -> Result<ExternalAuthConfig> {
        self.ensure_layout()?;
        let existing = self.load()?;
        let config = ExternalAuthConfig {
            enabled,
            username_header: username_header.trim().to_ascii_lowercase(),
            secret_header: secret_header.trim().to_ascii_lowercase(),
            secret_value: match secret_value {
                ExternalAuthSecretUpdate::Preserve => existing.secret_value,
                ExternalAuthSecretUpdate::Replace(value) => Some(value.trim().to_string()),
                ExternalAuthSecretUpdate::Clear => None,
            },
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
        self.config_dir().join("external-auth.json")
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

impl ServerConfig {
    pub fn new(
        external_scheme: ExternalScheme,
        external_host: String,
        external_port: u16,
        default_theme: UiTheme,
    ) -> Result<Self> {
        validate_host(&external_host)?;
        validate_port(external_port)?;
        Ok(Self {
            external_scheme,
            external_host,
            external_port,
            default_theme,
            updated_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn base_url(&self) -> String {
        let default_port = match self.external_scheme {
            ExternalScheme::Http => 80,
            ExternalScheme::Https => 443,
        };
        if self.external_port == default_port {
            format!("{}://{}", self.external_scheme.as_str(), self.external_host)
        } else {
            format!(
                "{}://{}:{}",
                self.external_scheme.as_str(),
                self.external_host,
                self.external_port
            )
        }
    }

    pub fn setup_url(&self) -> String {
        format!("{}/setup", self.base_url())
    }

    pub fn setup_text_url(&self) -> String {
        format!("{}/setup.txt", self.base_url())
    }

    pub fn mcp_url(&self) -> String {
        format!("{}/mcp", self.base_url())
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfigStore {
    root: PathBuf,
    default_port: u16,
}

impl ServerConfigStore {
    pub fn new(root: impl Into<PathBuf>, default_port: u16) -> Self {
        Self {
            root: root.into(),
            default_port,
        }
    }

    pub fn load(&self) -> Result<ServerConfig> {
        let path = self.config_path();
        if path.exists() {
            return Ok(serde_json::from_slice(&fs::read(path)?)?);
        }
        ServerConfig::new(
            ExternalScheme::Http,
            "localhost".to_string(),
            self.default_port,
            UiTheme::Parchment,
        )
    }

    pub fn update(
        &self,
        external_scheme: ExternalScheme,
        external_host: String,
        external_port: u16,
        default_theme: UiTheme,
    ) -> Result<ServerConfig> {
        let config =
            ServerConfig::new(external_scheme, external_host, external_port, default_theme)?;
        self.ensure_layout()?;
        write_json_atomic(self.config_path(), &config)?;
        Ok(config)
    }

    fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn config_path(&self) -> PathBuf {
        self.config_dir().join("server.json")
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

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() || host.len() > 255 {
        return Err(LoreError::Validation(
            "external host must be 1..=255 characters".into(),
        ));
    }
    if host.contains('/') || host.contains('?') || host.contains('#') || host.contains('@') {
        return Err(LoreError::Validation(
            "external host must not contain path or auth characters".into(),
        ));
    }
    if host.contains(':') {
        return Err(LoreError::Validation(
            "external host must not include a port".into(),
        ));
    }
    if host.chars().any(|ch| ch.is_ascii_whitespace()) {
        return Err(LoreError::Validation(
            "external host must not contain whitespace".into(),
        ));
    }
    if !host
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
    {
        return Err(LoreError::Validation(
            "external host must use ascii letters, digits, '.' or '-'".into(),
        ));
    }
    Ok(())
}

fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(LoreError::Validation(
            "external port must be between 1 and 65535".into(),
        ));
    }
    Ok(())
}

fn default_external_auth_username_header() -> String {
    DEFAULT_EXTERNAL_AUTH_USERNAME_HEADER.to_string()
}

fn default_external_auth_secret_header() -> String {
    DEFAULT_EXTERNAL_AUTH_SECRET_HEADER.to_string()
}

fn default_oidc_callback_path() -> String {
    DEFAULT_OIDC_CALLBACK_PATH.to_string()
}

fn default_oidc_username_claim() -> OidcUsernameClaim {
    OidcUsernameClaim::parse(DEFAULT_OIDC_USERNAME_CLAIM).expect("default oidc username claim")
}

fn validate_url(value: &str, label: &str, max_len: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_len {
        return Err(LoreError::Validation(format!(
            "{label} must be 1..={max_len} characters"
        )));
    }
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(LoreError::Validation(format!(
            "{label} must start with http:// or https://"
        )));
    }
    Ok(())
}

fn validate_nonempty_text(value: &str, label: &str, max_len: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_len {
        return Err(LoreError::Validation(format!(
            "{label} must be 1..={max_len} characters"
        )));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(LoreError::Validation(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

fn validate_callback_path(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_OIDC_CALLBACK_PATH_LEN {
        return Err(LoreError::Validation(format!(
            "oidc callback path must be 1..={MAX_OIDC_CALLBACK_PATH_LEN} characters"
        )));
    }
    if value != DEFAULT_OIDC_CALLBACK_PATH {
        return Err(LoreError::Validation(format!(
            "oidc callback path must currently be {DEFAULT_OIDC_CALLBACK_PATH}"
        )));
    }
    Ok(())
}

fn validate_header_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_HEADER_NAME_LEN {
        return Err(LoreError::Validation(format!(
            "{label} must be 1..={MAX_HEADER_NAME_LEN} characters"
        )));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(LoreError::Validation(format!(
            "{label} must contain only lowercase ascii letters, digits, or '-'"
        )));
    }
    Ok(())
}

fn write_json_atomic<T>(path: PathBuf, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp_path, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ExternalAuthSecretUpdate, ExternalAuthStore, ExternalScheme, OidcConfigStore,
        OidcLoginStateStore, OidcSecretUpdate, OidcUsernameClaim, ServerConfigStore,
        StoredOidcLoginState, UiTheme,
    };
    use tempfile::tempdir;
    use time::OffsetDateTime;

    #[test]
    fn loads_default_config_from_bind_port() {
        let dir = tempdir().unwrap();
        let store = ServerConfigStore::new(dir.path(), 8123);
        let config = store.load().unwrap();
        assert_eq!(config.base_url(), "http://localhost:8123");
        assert_eq!(config.default_theme, UiTheme::Parchment);
    }

    #[test]
    fn persists_updated_config() {
        let dir = tempdir().unwrap();
        let store = ServerConfigStore::new(dir.path(), 8080);
        store
            .update(
                ExternalScheme::Https,
                "lore.example.com".into(),
                443,
                UiTheme::Graphite,
            )
            .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.base_url(), "https://lore.example.com");
        assert_eq!(loaded.default_theme, UiTheme::Graphite);
    }

    #[test]
    fn external_auth_defaults_to_disabled() {
        let dir = tempdir().unwrap();
        let store = ExternalAuthStore::new(dir.path());
        let config = store.load().unwrap();
        assert!(!config.enabled);
        assert_eq!(config.username_header, "x-forwarded-user");
    }

    #[test]
    fn external_auth_persists_secret_and_headers() {
        let dir = tempdir().unwrap();
        let store = ExternalAuthStore::new(dir.path());
        let config = store
            .update(
                true,
                "x-auth-user".into(),
                "x-auth-secret".into(),
                ExternalAuthSecretUpdate::Replace("shared-secret"),
            )
            .unwrap();
        assert!(config.is_configured());
        let loaded = store.load().unwrap();
        assert_eq!(loaded.username_header, "x-auth-user");
        assert_eq!(loaded.secret_header, "x-auth-secret");
        assert_eq!(loaded.secret_value.as_deref(), Some("shared-secret"));
    }

    #[test]
    fn oidc_persists_config() {
        let dir = tempdir().unwrap();
        let store = OidcConfigStore::new(dir.path());
        let config = store
            .update(
                true,
                "https://issuer.example.com".into(),
                "lore-web".into(),
                OidcSecretUpdate::Replace("top-secret"),
                "/login/oidc/callback".into(),
                OidcUsernameClaim::PreferredUsername,
            )
            .unwrap();
        assert!(config.is_configured());
        assert!(config.has_client_secret());
    }

    #[test]
    fn oidc_login_state_expires() {
        let dir = tempdir().unwrap();
        let store = OidcLoginStateStore::new(dir.path());
        store
            .save(StoredOidcLoginState {
                state: "abc".into(),
                nonce: "nonce".into(),
                pkce_verifier: "verifier".into(),
                created_at: OffsetDateTime::now_utc() - time::Duration::seconds(601),
                return_to: None,
            })
            .unwrap();
        assert!(store.take("abc").unwrap().is_none());
    }

    #[test]
    fn oidc_login_state_rejects_path_traversal() {
        let dir = tempdir().unwrap();
        let store = OidcLoginStateStore::new(dir.path());
        assert!(store.take("../../etc/passwd").unwrap().is_none());
        assert!(store.take("../auth/users").unwrap().is_none());
        assert!(store.take("").unwrap().is_none());
        assert!(store.take("state/with/slashes").unwrap().is_none());
        assert!(store.take("state.with.dots").unwrap().is_none());
        // valid chars should pass through to normal not-found
        assert!(store.take("abc-def_123").unwrap().is_none());
    }
}
