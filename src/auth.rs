use crate::config::{ColorMode, UiTheme};
use crate::error::{LoreError, Result};
use crate::model::ProjectName;
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_USERNAME_LEN: usize = 32;
const MAX_ROLE_NAME_LEN: usize = 32;
const MAX_AGENT_TOKEN_NAME_LEN: usize = 64;
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 256;
const SESSION_TTL_SECS: i64 = 60 * 60 * 24 * 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSession {
    pub token_hash: String,
    pub username: UserName,
    pub csrf_token: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub token: String,
    pub csrf_token: String,
    pub user: AuthenticatedUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredMachine {
    pub name: String,
    pub username: UserName,
    pub token_hash: String,
    pub created_at: OffsetDateTime,
    #[serde(default)]
    pub cli_version: Option<String>,
    #[serde(default)]
    pub pending_update: bool,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedMachine {
    pub machine_name: String,
    pub user: AuthenticatedUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAgentToken {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub token_hash: String,
    #[serde(default)]
    pub owner: Option<UserName>,
    pub grants: Vec<ProjectGrant>,
    #[serde(default)]
    pub backend: AgentBackend,
    #[serde(default)]
    pub endpoint_id: Option<String>,
    #[serde(default)]
    pub machine_name: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewAgentToken {
    pub display_name: String,
    pub owner: UserName,
    pub grants: Vec<ProjectGrant>,
    pub backend: AgentBackend,
    pub endpoint_id: Option<String>,
}

impl NewAgentToken {
    pub fn slug(&self) -> String {
        slugify_agent_name(&self.display_name)
    }

    pub fn validate(&self) -> Result<()> {
        validate_agent_display_name(&self.display_name)?;
        let slug = self.slug();
        validate_agent_token_name(&slug)?;
        if self.grants.is_empty() {
            return Err(LoreError::Validation(
                "agent token must grant at least one project permission".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for grant in &self.grants {
            if !seen.insert(grant.project.clone()) {
                return Err(LoreError::Validation(
                    "agent token cannot contain duplicate project grants".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentBackend {
    Claude,
    Gemini,
    Codex,
    #[serde(rename = "openai")]
    OpenAi,
}

impl Default for AgentBackend {
    fn default() -> Self {
        Self::Claude
    }
}

impl Display for AgentBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Claude => write!(f, "claude"),
            Self::Gemini => write!(f, "gemini"),
            Self::Codex => write!(f, "codex"),
            Self::OpenAi => write!(f, "openai"),
        }
    }
}

impl std::str::FromStr for AgentBackend {
    type Err = LoreError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "claude" => Ok(Self::Claude),
            "gemini" => Ok(Self::Gemini),
            "codex" => Ok(Self::Codex),
            "openai" => Ok(Self::OpenAi),
            _ => Err(LoreError::Validation(format!("unknown backend: {s}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreatedAgentToken {
    pub token: String,
    pub stored: StoredAgentToken,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedAgent {
    pub token: String,
    pub name: String,
    pub owner: Option<UserName>,
    pub owner_is_admin: bool,
    pub grants: Vec<ProjectGrant>,
    pub backend: AgentBackend,
    pub endpoint_id: Option<String>,
    pub machine_name: Option<String>,
}

impl AuthenticatedAgent {
    pub fn can_read(&self, project: &ProjectName) -> bool {
        self.owner_is_admin
            || self.grants.iter().any(|grant| &grant.project == project)
    }

    pub fn can_write(&self, project: &ProjectName) -> bool {
        self.owner_is_admin
            || self.grants
                .iter()
                .any(|grant| &grant.project == project && grant.permission.allows_write())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct UserName(String);

impl UserName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_USERNAME_LEN {
            return Err(LoreError::Validation(format!(
                "username must be 1..={MAX_USERNAME_LEN} characters"
            )));
        }
        if !value.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.' | '@')
        }) {
            return Err(LoreError::Validation(
                "username must contain only lowercase ascii letters, digits, '.', '_', '-' or '@'"
                    .into(),
            ));
        }
        if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
            return Err(LoreError::Validation(
                "username contains unsafe dot usage".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for UserName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ROLE_NAME_LEN {
            return Err(LoreError::Validation(format!(
                "role name must be 1..={MAX_ROLE_NAME_LEN} characters"
            )));
        }
        if !value.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.')
        }) {
            return Err(LoreError::Validation(
                "role name must contain only lowercase ascii letters, digits, '.', '_' or '-'"
                    .into(),
            ));
        }
        if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
            return Err(LoreError::Validation(
                "role name contains unsafe dot usage".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for RoleName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectPermission {
    Read,
    ReadWrite,
}

impl ProjectPermission {
    pub fn allows_write(self) -> bool {
        matches!(self, Self::ReadWrite)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectGrant {
    pub project: ProjectName,
    pub permission: ProjectPermission,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredRole {
    pub name: RoleName,
    pub grants: Vec<ProjectGrant>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredUser {
    pub username: UserName,
    pub password_hash: String,
    pub role_names: Vec<RoleName>,
    pub is_admin: bool,
    #[serde(default)]
    pub theme: Option<UiTheme>,
    #[serde(default)]
    pub color_mode: Option<ColorMode>,
    pub disabled_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewRole {
    pub name: RoleName,
    pub grants: Vec<ProjectGrant>,
}

impl NewRole {
    pub fn validate(&self) -> Result<()> {
        if self.grants.is_empty() {
            return Err(LoreError::Validation(
                "role must grant at least one project permission".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for grant in &self.grants {
            if !seen.insert(grant.project.clone()) {
                return Err(LoreError::Validation(
                    "role cannot contain duplicate project grants".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: UserName,
    pub password: String,
    pub role_names: Vec<RoleName>,
    pub is_admin: bool,
}

impl NewUser {
    pub fn validate(&self) -> Result<()> {
        validate_password(&self.password)?;
        let mut seen = std::collections::BTreeSet::new();
        for role_name in &self.role_names {
            if !seen.insert(role_name.clone()) {
                return Err(LoreError::Validation(
                    "user cannot contain duplicate role assignments".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: UserName,
    pub is_admin: bool,
    pub roles: Vec<StoredRole>,
    pub theme: Option<UiTheme>,
    pub color_mode: Option<ColorMode>,
}

impl AuthenticatedUser {
    pub fn can_read(&self, project: &ProjectName) -> bool {
        self.is_admin
            || self
                .roles
                .iter()
                .flat_map(|role| &role.grants)
                .any(|grant| &grant.project == project)
    }

    pub fn can_write(&self, project: &ProjectName) -> bool {
        self.is_admin
            || self
                .roles
                .iter()
                .flat_map(|role| &role.grants)
                .any(|grant| &grant.project == project && grant.permission.allows_write())
    }
}

#[derive(Debug)]
pub struct LocalAuthStore {
    conn: Arc<Mutex<Connection>>,
}

impl Clone for LocalAuthStore {
    fn clone(&self) -> Self {
        panic!("LocalAuthStore should not be cloned; wrap in Arc instead");
    }
}

const AUTH_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role_names TEXT NOT NULL DEFAULT '[]',
    is_admin INTEGER NOT NULL DEFAULT 0,
    theme TEXT,
    color_mode TEXT,
    disabled_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY,
    grants TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_tokens (
    name TEXT NOT NULL,
    display_name TEXT,
    token_hash TEXT NOT NULL UNIQUE,
    owner TEXT,
    grants TEXT NOT NULL DEFAULT '[]',
    backend TEXT NOT NULL DEFAULT 'claude',
    machine_name TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_tokens_name_owner ON agent_tokens(name, owner);
CREATE TABLE IF NOT EXISTS machines (
    name TEXT NOT NULL,
    username TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    cli_version TEXT,
    pending_update INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (name, username)
);
";

fn fmt_dt(dt: &OffsetDateTime) -> String {
    dt.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

fn parse_dt(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Parse a tool-use line into (base, repeat_count). A trailing " (xN)" is
/// treated as a repeat marker. Mirrors the UI aggregation in chat_stream.
fn parse_tool_repeat(line: &str) -> (&str, Option<u32>) {
    if let Some(open) = line.rfind(" (x") {
        if line.ends_with(')') {
            let inner = &line[open + 3..line.len() - 1];
            if let Ok(n) = inner.parse::<u32>() {
                return (&line[..open], Some(n));
            }
        }
    }
    (line, None)
}

/// Check whether a column exists on a table.
fn has_column(conn: &Connection, table: &str, column: &str) -> bool {
    let mut stmt = match conn.prepare(&format!("PRAGMA table_info({})", table)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap_or_else(|_| panic!("PRAGMA table_info({table}) failed"))
        .filter_map(|r| r.ok())
        .collect();
    cols.contains(&column.to_string())
}

fn run_migrations(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    )
    .expect("failed to create schema_version table");

    let current: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    struct Migration {
        version: i64,
        sql: &'static str,
        table: &'static str,
        column: &'static str,
    }

    let migrations: &[Migration] = &[
        Migration {
            version: 1,
            sql: "ALTER TABLE agent_tokens ADD COLUMN endpoint_id TEXT",
            table: "agent_tokens",
            column: "endpoint_id",
        },
        Migration {
            version: 2,
            sql: "ALTER TABLE conversations ADD COLUMN pinned_context TEXT NOT NULL DEFAULT ''",
            table: "conversations",
            column: "pinned_context",
        },
        Migration {
            version: 3,
            sql: "ALTER TABLE conversations ADD COLUMN manage_config TEXT",
            table: "conversations",
            column: "manage_config",
        },
    ];

    for m in migrations {
        if current >= m.version {
            continue;
        }
        if !has_column(conn, m.table, m.column) {
            conn.execute(m.sql, []).unwrap_or_else(|e| {
                panic!("schema migration {} failed: {e}", m.version);
            });
        }
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![m.version],
        )
        .unwrap_or_else(|e| {
            panic!("failed to record migration {}: {e}", m.version);
        });
        eprintln!("schema: applied migration {}", m.version);
    }
}

/// Open (or create) the shared lore.db and run all schema creation
/// and migrations.  Returns a connection that can be shared between
/// LocalAuthStore and ChatStore.
pub fn open_lore_db(root: &Path) -> Arc<Mutex<Connection>> {
    let db_path = root.join("lore.db");
    fs::create_dir_all(root).expect("failed to create data directory");
    let conn = Connection::open(&db_path).expect("failed to open database");
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
        .expect("failed to set pragmas");
    conn.execute_batch(AUTH_SCHEMA)
        .expect("failed to create auth schema");
    conn.execute_batch(CHAT_SCHEMA)
        .expect("failed to create chat schema");
    run_migrations(&conn);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600));
    }
    Arc::new(Mutex::new(conn))
}

impl LocalAuthStore {
    /// Open a standalone auth store (creates its own DB connection).
    /// Used for CLI bootstrap commands and tests.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::from_conn(open_lore_db(&root.into()))
    }

    /// Create from an existing shared connection.
    pub fn from_conn(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    pub fn cleanup_orphans(&self) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => { eprintln!("warning: could not acquire db lock for auth cleanup"); return; }
        };

        // Expired sessions
        let now = fmt_dt(&OffsetDateTime::now_utc());
        match conn.execute("DELETE FROM sessions WHERE expires_at < ?1", params![now]) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} expired session(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: session cleanup failed: {e}"),
        }

        // Sessions for non-existent users
        match conn.execute(
            "DELETE FROM sessions WHERE username NOT IN (SELECT username FROM users)",
            [],
        ) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} session(s) for deleted user(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: session cleanup failed: {e}"),
        }

        // Agent tokens for non-existent users
        match conn.execute(
            "DELETE FROM agent_tokens WHERE owner IS NOT NULL AND owner NOT IN (SELECT username FROM users)",
            [],
        ) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} agent token(s) for deleted user(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: agent token cleanup failed: {e}"),
        }

        // Machines for non-existent users
        match conn.execute(
            "DELETE FROM machines WHERE username NOT IN (SELECT username FROM users)",
            [],
        ) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} machine registration(s) for deleted user(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: machine cleanup failed: {e}"),
        }
    }

    pub fn has_users(&self) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(count > 0)
    }

    pub fn bootstrap_admin(&self, username: UserName, password: String) -> Result<StoredUser> {
        if self.has_users()? {
            return Err(LoreError::PermissionDenied);
        }
        let user = NewUser {
            username,
            password,
            role_names: Vec::new(),
            is_admin: true,
        };
        self.create_user_unchecked(user)
    }

    pub fn list_roles(&self) -> Result<Vec<StoredRole>> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let mut stmt = conn.prepare("SELECT name, grants, created_at FROM roles ORDER BY name")
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let grants_json: String = row.get(1)?;
            let created_at: String = row.get(2)?;
            Ok((name, grants_json, created_at))
        }).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let mut roles = Vec::new();
        for row in rows {
            let (name, grants_json, created_at) = row.map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
            roles.push(StoredRole {
                name: RoleName::new(name)?,
                grants: serde_json::from_str(&grants_json).unwrap_or_default(),
                created_at: parse_dt(&created_at),
            });
        }
        Ok(roles)
    }

    pub fn create_role(&self, role: NewRole) -> Result<StoredRole> {
        role.validate()?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let existing: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM roles WHERE name = ?1", params![role.name.as_str()],
            |row| row.get(0),
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if existing {
            return Err(LoreError::Validation("role already exists".into()));
        }
        let mut grants = role.grants;
        grants.sort_by(|a, b| a.project.cmp(&b.project));
        let now = OffsetDateTime::now_utc();
        let grants_json = serde_json::to_string(&grants)?;
        conn.execute(
            "INSERT INTO roles (name, grants, created_at) VALUES (?1, ?2, ?3)",
            params![role.name.as_str(), grants_json, fmt_dt(&now)],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(StoredRole { name: role.name, grants, created_at: now })
    }

    pub fn update_role(&self, role: NewRole) -> Result<StoredRole> {
        role.validate()?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let created_at: String = conn.query_row(
            "SELECT created_at FROM roles WHERE name = ?1", params![role.name.as_str()],
            |row| row.get(0),
        ).map_err(|_| LoreError::Validation("role does not exist".into()))?;
        let mut grants = role.grants;
        grants.sort_by(|a, b| a.project.cmp(&b.project));
        let grants_json = serde_json::to_string(&grants)?;
        conn.execute(
            "UPDATE roles SET grants = ?1 WHERE name = ?2",
            params![grants_json, role.name.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(StoredRole { name: role.name, grants, created_at: parse_dt(&created_at) })
    }

    /// Update all role grants that reference `old_slug` to point to `new_slug`.
    pub fn rename_project_in_grants(
        &self,
        old_slug: &ProjectName,
        new_slug: &ProjectName,
    ) -> Result<()> {
        let roles = self.list_roles()?;
        for role in roles {
            let needs_update = role.grants.iter().any(|g| &g.project == old_slug);
            if needs_update {
                let new_grants: Vec<ProjectGrant> = role
                    .grants
                    .into_iter()
                    .map(|mut g| {
                        if &g.project == old_slug {
                            g.project = new_slug.clone();
                        }
                        g
                    })
                    .collect();
                self.update_role(NewRole {
                    name: role.name,
                    grants: new_grants,
                })?;
            }
        }
        Ok(())
    }

    pub fn list_users(&self) -> Result<Vec<StoredUser>> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::load_users_from_conn(&conn)
    }

    pub fn create_user(&self, user: NewUser) -> Result<StoredUser> {
        user.validate()?;
        {
            let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
            let mut stmt = conn.prepare("SELECT name FROM roles")
                .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
            let known_roles: Vec<String> = stmt.query_map([], |row| row.get(0))
                .map_err(|e| LoreError::Validation(format!("db error: {e}")))?
                .filter_map(|r| r.ok())
                .collect();
            for role_name in &user.role_names {
                if !known_roles.iter().any(|r| r == role_name.as_str()) {
                    return Err(LoreError::Validation(format!("unknown role: {}", role_name.as_str())));
                }
            }
        }
        self.create_user_unchecked(user)
    }

    pub fn update_user_password(&self, username: &UserName, password: String) -> Result<StoredUser> {
        validate_password(&password)?;
        let new_hash = hash_password(&password)?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let updated = conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE username = ?2",
            params![new_hash, username.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if updated == 0 {
            return Err(LoreError::PermissionDenied);
        }
        Self::get_stored_user_from_conn(&conn, username)
    }

    pub fn set_user_disabled(&self, username: &UserName, disabled: bool) -> Result<StoredUser> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let user = Self::get_stored_user_from_conn(&conn, username)?;
        if disabled && user.is_admin {
            let active_admins: i64 = conn.query_row(
                "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled_at IS NULL", [],
                |row| row.get(0),
            ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
            if active_admins <= 1 {
                return Err(LoreError::Validation("cannot disable the last admin user".into()));
            }
        }
        let disabled_at = if disabled { Some(fmt_dt(&OffsetDateTime::now_utc())) } else { None };
        conn.execute(
            "UPDATE users SET disabled_at = ?1 WHERE username = ?2",
            params![disabled_at, username.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        drop(conn);
        if disabled {
            self.revoke_sessions_for_user(username)?;
        }
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::get_stored_user_from_conn(&conn, username)
    }

    pub fn update_user_theme(
        &self,
        username: &UserName,
        theme: Option<UiTheme>,
        color_mode: Option<ColorMode>,
    ) -> Result<StoredUser> {
        let theme_str = theme.map(|t| serde_json::to_value(t).unwrap().as_str().unwrap().to_string());
        let color_str = color_mode.map(|c| serde_json::to_value(c).unwrap().as_str().unwrap().to_string());
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let updated = conn.execute(
            "UPDATE users SET theme = ?1, color_mode = ?2 WHERE username = ?3",
            params![theme_str, color_str, username.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if updated == 0 {
            return Err(LoreError::PermissionDenied);
        }
        Self::get_stored_user_from_conn(&conn, username)
    }

    pub fn list_agent_tokens(&self) -> Result<Vec<StoredAgentToken>> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::load_agent_tokens_from_conn(&conn)
    }

    pub fn create_agent_token(&self, token: NewAgentToken) -> Result<CreatedAgentToken> {
        token.validate()?;
        let slug = token.slug();
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM agent_tokens WHERE name = ?1 AND owner = ?2",
            params![slug, token.owner.as_str()], |row| row.get(0),
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if exists {
            return Err(LoreError::Validation("agent already exists".into()));
        }
        let mut grants = token.grants;
        grants.sort_by(|a, b| a.project.cmp(&b.project));
        let raw_token = format!("lore_at_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        let now = OffsetDateTime::now_utc();
        let stored = StoredAgentToken {
            name: slug,
            display_name: Some(token.display_name),
            token_hash: hash_agent_token(&raw_token),
            owner: Some(token.owner),
            grants: grants.clone(),
            backend: token.backend,
            endpoint_id: token.endpoint_id,
            machine_name: None,
            created_at: now,
        };
        conn.execute(
            "INSERT INTO agent_tokens (name, display_name, token_hash, owner, grants, backend, endpoint_id, machine_name, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![stored.name, stored.display_name, stored.token_hash,
                    stored.owner.as_ref().map(|u| u.as_str().to_string()),
                    serde_json::to_string(&grants)?,
                    stored.backend.to_string(), stored.endpoint_id, stored.machine_name, fmt_dt(&now)],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(CreatedAgentToken { token: raw_token, stored })
    }

    pub fn rotate_agent_token(&self, name: &str, owner: &UserName) -> Result<CreatedAgentToken> {
        validate_agent_token_name(name)?;
        let raw_token = format!("lore_at_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        let new_hash = hash_agent_token(&raw_token);
        let now = OffsetDateTime::now_utc();
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let updated = conn.execute(
            "UPDATE agent_tokens SET token_hash = ?1, created_at = ?2 WHERE name = ?3 AND owner = ?4",
            params![new_hash, fmt_dt(&now), name, owner.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if updated == 0 {
            return Err(LoreError::Validation("agent does not exist".into()));
        }
        let stored = Self::get_agent_token_from_conn(&conn, name, Some(owner))?;
        Ok(CreatedAgentToken { token: raw_token, stored })
    }

    pub fn revoke_agent_token(&self, name: &str, owner: &UserName) -> Result<()> {
        validate_agent_token_name(name)?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let deleted = conn.execute(
            "DELETE FROM agent_tokens WHERE name = ?1 AND owner = ?2",
            params![name, owner.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if deleted == 0 {
            return Err(LoreError::Validation("agent does not exist".into()));
        }
        Ok(())
    }

    pub fn revoke_agent_token_by_name(&self, name: &str) -> Result<()> {
        validate_agent_token_name(name)?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let deleted = conn.execute(
            "DELETE FROM agent_tokens WHERE name = ?1", params![name],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if deleted == 0 {
            return Err(LoreError::Validation("agent does not exist".into()));
        }
        Ok(())
    }

    pub fn rotate_agent_token_by_name(&self, name: &str) -> Result<CreatedAgentToken> {
        validate_agent_token_name(name)?;
        let raw_token = format!("lore_at_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        let new_hash = hash_agent_token(&raw_token);
        let now = OffsetDateTime::now_utc();
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let updated = conn.execute(
            "UPDATE agent_tokens SET token_hash = ?1, created_at = ?2 WHERE name = ?3",
            params![new_hash, fmt_dt(&now), name],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if updated == 0 {
            return Err(LoreError::Validation("agent does not exist".into()));
        }
        let stored = Self::get_agent_token_from_conn(&conn, name, None)?;
        Ok(CreatedAgentToken { token: raw_token, stored })
    }

    pub fn list_agent_tokens_for_user(&self, owner: &UserName) -> Result<Vec<StoredAgentToken>> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::load_agent_tokens_filtered(&conn, Some(owner))
    }

    pub fn update_agent_display_name(
        &self,
        name: &str,
        owner: &UserName,
        new_display_name: &str,
    ) -> Result<()> {
        validate_agent_display_name(new_display_name)?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let updated = conn.execute(
            "UPDATE agent_tokens SET display_name = ?1 WHERE name = ?2 AND owner = ?3",
            params![new_display_name, name, owner.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if updated == 0 {
            return Err(LoreError::Validation("agent does not exist".into()));
        }
        Ok(())
    }

    pub fn set_agent_backend(
        &self,
        name: &str,
        owner: &UserName,
        backend: AgentBackend,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let updated = conn.execute(
            "UPDATE agent_tokens SET backend = ?1 WHERE name = ?2 AND owner = ?3",
            params![backend.to_string(), name, owner.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if updated == 0 {
            return Err(LoreError::Validation("agent does not exist".into()));
        }
        Ok(())
    }

    pub fn set_agent_endpoint_id(
        &self,
        name: &str,
        owner: &UserName,
        endpoint_id: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let updated = conn.execute(
            "UPDATE agent_tokens SET endpoint_id = ?1 WHERE name = ?2 AND owner = ?3",
            params![endpoint_id, name, owner.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if updated == 0 {
            return Err(LoreError::Validation("agent does not exist".into()));
        }
        Ok(())
    }

    pub fn update_agent_token_grants(
        &self,
        name: &str,
        owner: &UserName,
        grants: Vec<ProjectGrant>,
    ) -> Result<StoredAgentToken> {
        validate_agent_token_name(name)?;
        if grants.is_empty() {
            return Err(LoreError::Validation(
                "agent must grant at least one project permission".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for grant in &grants {
            if !seen.insert(grant.project.clone()) {
                return Err(LoreError::Validation(
                    "agent cannot contain duplicate project grants".into(),
                ));
            }
        }
        let mut sorted_grants = grants;
        sorted_grants.sort_by(|a, b| a.project.cmp(&b.project));
        let grants_json = serde_json::to_string(&sorted_grants)?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let updated = conn.execute(
            "UPDATE agent_tokens SET grants = ?1 WHERE name = ?2 AND owner = ?3",
            params![grants_json, name, owner.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if updated == 0 {
            return Err(LoreError::Validation("agent does not exist".into()));
        }
        Self::get_agent_token_from_conn(&conn, name, Some(owner))
    }

    pub fn authenticate_agent_token(&self, token: &str) -> Result<AuthenticatedAgent> {
        if token.trim().is_empty() {
            return Err(LoreError::PermissionDenied);
        }
        let token_hash = hash_agent_token(token);
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let row = conn.query_row(
            "SELECT name, display_name, owner, grants, backend, machine_name, endpoint_id FROM agent_tokens WHERE token_hash = ?1",
            params![token_hash],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        ).map_err(|_| LoreError::PermissionDenied)?;
        let owner = row.2.map(|s| UserName::new(s)).transpose()?;
        let backend: AgentBackend = row.4.parse().unwrap_or_default();

        // Compute grants dynamically from the owner's current roles
        let (owner_is_admin, grants) = if let Some(ref owner_name) = owner {
            match Self::get_stored_user_from_conn(&conn, owner_name) {
                Ok(stored_user) => {
                    if stored_user.disabled_at.is_some() {
                        return Err(LoreError::PermissionDenied);
                    }
                    let user = Self::user_from_stored_conn(&conn, &stored_user)?;
                    let grants = user.roles.iter()
                        .flat_map(|role| role.grants.clone())
                        .collect();
                    (user.is_admin, grants)
                }
                Err(_) => {
                    // Owner no longer exists
                    return Err(LoreError::PermissionDenied);
                }
            }
        } else {
            // No owner — fall back to static grants in the token
            let grants: Vec<ProjectGrant> = serde_json::from_str(&row.3).unwrap_or_default();
            (false, grants)
        };

        Ok(AuthenticatedAgent {
            token: token.to_string(),
            name: row.0,
            owner,
            owner_is_admin,
            grants,
            backend,
            endpoint_id: row.6,
            machine_name: row.5,
        })
    }

    // --- Machine registration ---

    pub fn register_machine(
        &self,
        username: &str,
        password: &str,
        machine_name: &str,
    ) -> Result<(String, StoredMachine)> {
        let user = self.authenticate(username, password)?;
        let machine_name = machine_name.trim().to_string();
        if machine_name.is_empty() || machine_name.len() > 64 {
            return Err(LoreError::Validation("machine name must be 1..=64 characters".into()));
        }
        let raw_token = format!("lore_mt_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        let token_hash = hash_agent_token(&raw_token);
        let now = OffsetDateTime::now_utc();
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        // Upsert: if machine exists for this user, rotate token
        let existing: Option<String> = conn.query_row(
            "SELECT token_hash FROM machines WHERE name = ?1 AND username = ?2",
            params![machine_name, user.username.as_str()],
            |row| row.get(0),
        ).ok();
        if existing.is_some() {
            conn.execute(
                "UPDATE machines SET token_hash = ?1, created_at = ?2 WHERE name = ?3 AND username = ?4",
                params![token_hash, fmt_dt(&now), machine_name, user.username.as_str()],
            ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        } else {
            conn.execute(
                "INSERT INTO machines (name, username, token_hash, created_at, pending_update) VALUES (?1, ?2, ?3, ?4, 0)",
                params![machine_name, user.username.as_str(), token_hash, fmt_dt(&now)],
            ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        }
        let stored = Self::get_machine_from_conn(&conn, &machine_name, &user.username)?
            .ok_or_else(|| LoreError::Validation("failed to read machine after insert".into()))?;
        Ok((raw_token, stored))
    }

    pub fn authenticate_machine_token(&self, token: &str) -> Result<AuthenticatedMachine> {
        if token.trim().is_empty() {
            return Err(LoreError::PermissionDenied);
        }
        let token_hash = hash_agent_token(token);
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let row = conn.query_row(
            "SELECT name, username FROM machines WHERE token_hash = ?1",
            params![token_hash], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).map_err(|_| LoreError::PermissionDenied)?;
        let username = UserName::new(row.1)?;
        let user_row = Self::get_stored_user_from_conn(&conn, &username)?;
        let user = Self::user_from_stored_conn(&conn, &user_row)?;
        Ok(AuthenticatedMachine { machine_name: row.0, user })
    }

    pub fn list_machines_for_user(&self, username: &UserName) -> Result<Vec<StoredMachine>> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::load_machines_filtered(&conn, Some(username))
    }

    pub fn list_all_machines(&self) -> Result<Vec<StoredMachine>> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::load_machines_filtered(&conn, None)
    }

    pub fn revoke_machine(&self, name: &str, username: &UserName) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let deleted = conn.execute(
            "DELETE FROM machines WHERE name = ?1 AND username = ?2",
            params![name, username.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        if deleted == 0 {
            return Err(LoreError::Validation("machine does not exist".into()));
        }
        Ok(())
    }

    pub fn revoke_machine_by_name(&self, name: &str, username: &UserName) -> Result<()> {
        self.revoke_machine(name, username)
    }

    pub fn update_machine_version(&self, name: &str, username: &UserName, version: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        conn.execute(
            "UPDATE machines SET cli_version = ?1 WHERE name = ?2 AND username = ?3",
            params![version, name, username.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn get_machine(&self, name: &str, username: &UserName) -> Result<Option<StoredMachine>> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::get_machine_from_conn(&conn, name, username)
    }

    pub fn provision_agent(
        &self,
        username: &UserName,
        display_name: &str,
        grants: Vec<ProjectGrant>,
        machine_name: Option<&str>,
    ) -> Result<CreatedAgentToken> {
        validate_agent_display_name(display_name)?;
        let slug = slugify_agent_name(display_name);
        validate_agent_token_name(&slug)?;
        if grants.is_empty() {
            return Err(LoreError::Validation("agent must have at least one project grant".into()));
        }
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let raw_token = format!("lore_at_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        let new_hash = hash_agent_token(&raw_token);
        let now = OffsetDateTime::now_utc();
        // Re-provision if agent already exists for this user.
        // Do NOT overwrite backend — it's configured separately via the UI.
        let existing: Option<i64> = conn.query_row(
            "SELECT rowid FROM agent_tokens WHERE name = ?1 AND owner = ?2",
            params![slug, username.as_str()], |row| row.get(0),
        ).ok();
        if let Some(rowid) = existing {
            let mut sorted_grants = grants;
            sorted_grants.sort_by(|a, b| a.project.cmp(&b.project));
            let grants_json = serde_json::to_string(&sorted_grants)?;
            let mn_update = machine_name.map(|s| s.to_string());
            if let Some(ref mn) = mn_update {
                conn.execute(
                    "UPDATE agent_tokens SET token_hash=?1, display_name=?2, machine_name=?3, grants=?4, created_at=?5 WHERE rowid=?6",
                    params![new_hash, display_name, mn, grants_json, fmt_dt(&now), rowid],
                ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
            } else {
                conn.execute(
                    "UPDATE agent_tokens SET token_hash=?1, display_name=?2, grants=?3, created_at=?4 WHERE rowid=?5",
                    params![new_hash, display_name, grants_json, fmt_dt(&now), rowid],
                ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
            }
            let stored = Self::get_agent_token_from_conn(&conn, &slug, Some(username))?;
            return Ok(CreatedAgentToken { token: raw_token, stored });
        }
        let mut sorted_grants = grants;
        sorted_grants.sort_by(|a, b| a.project.cmp(&b.project));
        let grants_json = serde_json::to_string(&sorted_grants)?;
        let default_backend = AgentBackend::default().to_string();
        conn.execute(
            "INSERT INTO agent_tokens (name, display_name, token_hash, owner, grants, backend, machine_name, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![slug, display_name, new_hash, username.as_str(), grants_json, default_backend, machine_name, fmt_dt(&now)],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let stored = Self::get_agent_token_from_conn(&conn, &slug, Some(username))?;
        Ok(CreatedAgentToken { token: raw_token, stored })
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Result<AuthenticatedUser> {
        let username = UserName::new(username.to_string())?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let user = Self::get_stored_user_from_conn(&conn, &username)?;
        verify_password_hash(&user.password_hash, password)?;
        Self::user_from_stored_conn(&conn, &user)
    }

    pub fn create_session(&self, username: &str, password: &str) -> Result<NewSession> {
        let user = self.authenticate(username, password)?;
        self.create_session_for_authenticated_user(user)
    }

    pub fn create_session_for_user(&self, username: &UserName) -> Result<NewSession> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let stored = Self::get_stored_user_from_conn(&conn, username)?;
        let user = Self::user_from_stored_conn(&conn, &stored)?;
        drop(conn);
        self.create_session_for_authenticated_user(user)
    }

    pub fn authenticate_external_username(&self, username: &str) -> Result<AuthenticatedUser> {
        let username = UserName::new(username.to_string())?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let stored = Self::get_stored_user_from_conn(&conn, &username)?;
        Self::user_from_stored_conn(&conn, &stored)
    }

    fn create_session_for_authenticated_user(&self, user: AuthenticatedUser) -> Result<NewSession> {
        let token = Uuid::new_v4().to_string();
        let csrf_token = Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let expires_at = now
            + time::Duration::try_from(Duration::from_secs(SESSION_TTL_SECS as u64))
                .map_err(|_| LoreError::Validation("invalid session ttl".into()))?;
        let session = StoredSession {
            token_hash: hash_session_token(&token),
            username: user.username.clone(),
            csrf_token: csrf_token.clone(),
            created_at: now,
            expires_at,
        };
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        conn.execute(
            "INSERT INTO sessions (token_hash, username, csrf_token, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session.token_hash, session.username.as_str(), session.csrf_token, fmt_dt(&now), fmt_dt(&expires_at)],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(NewSession { token, csrf_token, user })
    }

    pub fn revoke_sessions_for_user(&self, username: &UserName) -> Result<usize> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let removed = conn.execute(
            "DELETE FROM sessions WHERE username = ?1", params![username.as_str()],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(removed)
    }

    pub fn active_session_count(&self, username: &UserName) -> Result<usize> {
        let now = fmt_dt(&OffsetDateTime::now_utc());
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE username = ?1 AND expires_at > ?2",
            params![username.as_str(), now], |row| row.get(0),
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(count as usize)
    }

    pub fn authenticate_session(&self, token: &str) -> Result<(AuthenticatedUser, StoredSession)> {
        if token.trim().is_empty() {
            return Err(LoreError::PermissionDenied);
        }
        let token_hash = hash_session_token(token);
        let now = OffsetDateTime::now_utc();
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let row = conn.query_row(
            "SELECT username, csrf_token, created_at, expires_at FROM sessions WHERE token_hash = ?1",
            params![token_hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
        ).map_err(|_| LoreError::PermissionDenied)?;
        let expires_at = parse_dt(&row.3);
        if expires_at <= now {
            let _ = conn.execute("DELETE FROM sessions WHERE token_hash = ?1", params![token_hash]);
            return Err(LoreError::PermissionDenied);
        }
        let username = UserName::new(row.0)?;
        let session = StoredSession {
            token_hash,
            username: username.clone(),
            csrf_token: row.1,
            created_at: parse_dt(&row.2),
            expires_at,
        };
        let stored_user = Self::get_stored_user_from_conn(&conn, &username)?;
        let user = Self::user_from_stored_conn(&conn, &stored_user)?;
        Ok((user, session))
    }

    pub fn revoke_session(&self, token: &str) -> Result<()> {
        if token.trim().is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        conn.execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            params![hash_session_token(token)],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn authorize_read(&self, user: &AuthenticatedUser, project: &ProjectName) -> Result<()> {
        if user.can_read(project) { Ok(()) } else { Err(LoreError::PermissionDenied) }
    }

    pub fn authorize_write(&self, user: &AuthenticatedUser, project: &ProjectName) -> Result<()> {
        if user.can_write(project) { Ok(()) } else { Err(LoreError::PermissionDenied) }
    }

    pub(crate) fn create_user_unchecked(&self, user: NewUser) -> Result<StoredUser> {
        user.validate()?;
        let password_hash = hash_password(&user.password)?;
        let now = OffsetDateTime::now_utc();
        let role_names_json = serde_json::to_string(&user.role_names)?;
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        conn.execute(
            "INSERT INTO users (username, password_hash, role_names, is_admin, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user.username.as_str(), password_hash, role_names_json, user.is_admin as i32, fmt_dt(&now)],
        ).map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                LoreError::Validation("user already exists".into())
            } else {
                LoreError::Validation(format!("db error: {e}"))
            }
        })?;
        Self::get_stored_user_from_conn(&conn, &user.username)
    }

    // --- Private helpers ---

    fn get_stored_user_from_conn(conn: &Connection, username: &UserName) -> Result<StoredUser> {
        conn.query_row(
            "SELECT username, password_hash, role_names, is_admin, theme, color_mode, disabled_at, created_at FROM users WHERE username = ?1",
            params![username.as_str()],
            |row| {
                Ok(StoredUser {
                    username: UserName::new(row.get::<_, String>(0)?).unwrap(),
                    password_hash: row.get(1)?,
                    role_names: serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default(),
                    is_admin: row.get::<_, i32>(3)? != 0,
                    theme: row.get::<_, Option<String>>(4)?.and_then(|s| serde_json::from_value(serde_json::Value::String(s)).ok()),
                    color_mode: row.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_value(serde_json::Value::String(s)).ok()),
                    disabled_at: row.get::<_, Option<String>>(6)?.map(|s| parse_dt(&s)),
                    created_at: parse_dt(&row.get::<_, String>(7)?),
                })
            },
        ).map_err(|_| LoreError::PermissionDenied)
    }

    fn load_users_from_conn(conn: &Connection) -> Result<Vec<StoredUser>> {
        let mut stmt = conn.prepare(
            "SELECT username, password_hash, role_names, is_admin, theme, color_mode, disabled_at, created_at FROM users ORDER BY username"
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredUser {
                username: UserName::new(row.get::<_, String>(0)?).unwrap(),
                password_hash: row.get(1)?,
                role_names: serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default(),
                is_admin: row.get::<_, i32>(3)? != 0,
                theme: row.get::<_, Option<String>>(4)?.and_then(|s| serde_json::from_value(serde_json::Value::String(s)).ok()),
                color_mode: row.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_value(serde_json::Value::String(s)).ok()),
                disabled_at: row.get::<_, Option<String>>(6)?.map(|s| parse_dt(&s)),
                created_at: parse_dt(&row.get::<_, String>(7)?),
            })
        }).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))
    }

    fn user_from_stored_conn(conn: &Connection, user: &StoredUser) -> Result<AuthenticatedUser> {
        if user.disabled_at.is_some() {
            return Err(LoreError::PermissionDenied);
        }
        let mut roles = Vec::new();
        for role_name in &user.role_names {
            let role = conn.query_row(
                "SELECT name, grants, created_at FROM roles WHERE name = ?1",
                params![role_name.as_str()],
                |row| {
                    let grants_json: String = row.get(1)?;
                    let created_at: String = row.get(2)?;
                    Ok((grants_json, created_at))
                },
            );
            if let Ok((grants_json, created_at)) = role {
                roles.push(StoredRole {
                    name: role_name.clone(),
                    grants: serde_json::from_str(&grants_json).unwrap_or_default(),
                    created_at: parse_dt(&created_at),
                });
            }
        }
        Ok(AuthenticatedUser {
            username: user.username.clone(),
            is_admin: user.is_admin,
            roles,
            theme: user.theme,
            color_mode: user.color_mode,
        })
    }

    fn load_agent_tokens_from_conn(conn: &Connection) -> Result<Vec<StoredAgentToken>> {
        Self::load_agent_tokens_filtered(conn, None)
    }

    fn load_agent_tokens_filtered(conn: &Connection, owner: Option<&UserName>) -> Result<Vec<StoredAgentToken>> {
        let sql = if owner.is_some() {
            "SELECT name, display_name, token_hash, owner, grants, backend, machine_name, created_at, endpoint_id FROM agent_tokens WHERE owner = ?1 ORDER BY name"
        } else {
            "SELECT name, display_name, token_hash, owner, grants, backend, machine_name, created_at, endpoint_id FROM agent_tokens ORDER BY name"
        };
        let mut stmt = conn.prepare(sql).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let rows = if let Some(o) = owner {
            stmt.query_map(params![o.as_str()], Self::row_to_agent_token)
        } else {
            stmt.query_map([], Self::row_to_agent_token)
        }.map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))
    }

    fn row_to_agent_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAgentToken> {
        Ok(StoredAgentToken {
            name: row.get(0)?,
            display_name: row.get(1)?,
            token_hash: row.get(2)?,
            owner: row.get::<_, Option<String>>(3)?.map(|s| UserName::new(s).unwrap()),
            grants: serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or_default(),
            backend: row.get::<_, String>(5)?.parse().unwrap_or_default(),
            machine_name: row.get(6)?,
            created_at: parse_dt(&row.get::<_, String>(7)?),
            endpoint_id: row.get(8)?,
        })
    }

    fn get_agent_token_from_conn(conn: &Connection, name: &str, owner: Option<&UserName>) -> Result<StoredAgentToken> {
        let result = if let Some(o) = owner {
            conn.query_row(
                "SELECT name, display_name, token_hash, owner, grants, backend, machine_name, created_at, endpoint_id FROM agent_tokens WHERE name = ?1 AND owner = ?2",
                params![name, o.as_str()], Self::row_to_agent_token,
            )
        } else {
            conn.query_row(
                "SELECT name, display_name, token_hash, owner, grants, backend, machine_name, created_at, endpoint_id FROM agent_tokens WHERE name = ?1",
                params![name], Self::row_to_agent_token,
            )
        };
        result.map_err(|_| LoreError::Validation("agent does not exist".into()))
    }

    fn load_machines_filtered(conn: &Connection, username: Option<&UserName>) -> Result<Vec<StoredMachine>> {
        let sql = if username.is_some() {
            "SELECT name, username, token_hash, created_at, cli_version, pending_update FROM machines WHERE username = ?1"
        } else {
            "SELECT name, username, token_hash, created_at, cli_version, pending_update FROM machines"
        };
        let mut stmt = conn.prepare(sql).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let rows = if let Some(u) = username {
            stmt.query_map(params![u.as_str()], Self::row_to_machine)
        } else {
            stmt.query_map([], Self::row_to_machine)
        }.map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))
    }

    fn row_to_machine(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMachine> {
        Ok(StoredMachine {
            name: row.get(0)?,
            username: UserName::new(row.get::<_, String>(1)?).unwrap(),
            token_hash: row.get(2)?,
            created_at: parse_dt(&row.get::<_, String>(3)?),
            cli_version: row.get(4)?,
            pending_update: false,
        })
    }

    fn get_machine_from_conn(conn: &Connection, name: &str, username: &UserName) -> Result<Option<StoredMachine>> {
        let result = conn.query_row(
            "SELECT name, username, token_hash, created_at, cli_version, pending_update FROM machines WHERE name = ?1 AND username = ?2",
            params![name, username.as_str()], Self::row_to_machine,
        );
        match result {
            Ok(m) => Ok(Some(m)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LoreError::Validation(format!("db error: {e}"))),
        }
    }
}

fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN || password.len() > MAX_PASSWORD_LEN {
        return Err(LoreError::Validation(format!(
            "password must be {MIN_PASSWORD_LEN}..={MAX_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

fn validate_agent_display_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_AGENT_TOKEN_NAME_LEN {
        return Err(LoreError::Validation(format!(
            "agent name must be 1..={MAX_AGENT_TOKEN_NAME_LEN} characters"
        )));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ' '))
    {
        return Err(LoreError::Validation(
            "agent name must contain only letters, digits, spaces, '.', '_' or '-'".into(),
        ));
    }
    Ok(())
}

fn slugify_agent_name(display_name: &str) -> String {
    let slug: String = display_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    // Collapse consecutive hyphens
    let mut result = String::with_capacity(slug.len());
    let mut prev_hyphen = false;
    for ch in slug.chars() {
        if ch == '-' {
            if !prev_hyphen {
                result.push(ch);
            }
            prev_hyphen = true;
        } else {
            result.push(ch);
            prev_hyphen = false;
        }
    }
    result.trim_matches('-').to_string()
}

fn validate_agent_token_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_AGENT_TOKEN_NAME_LEN {
        return Err(LoreError::Validation(format!(
            "agent token name must be 1..={MAX_AGENT_TOKEN_NAME_LEN} characters"
        )));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(LoreError::Validation(
            "agent token name must contain only lowercase ascii letters, digits, '.', '_' or '-'"
                .into(),
        ));
    }
    if name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return Err(LoreError::Validation(
            "agent token name contains unsafe dot usage".into(),
        ));
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    validate_password(password)?;
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| LoreError::Validation(format!("failed to hash password: {err}")))
}

fn verify_password_hash(password_hash: &str, password: &str) -> Result<()> {
    let parsed_hash = PasswordHash::new(password_hash).map_err(|_| LoreError::PermissionDenied)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| LoreError::PermissionDenied)
}

fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"session:");
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn hash_agent_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"agent-token:");
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}


// --- Chat types and storage ---

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatRole {
    User,
    Assistant,
    Tool,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: u64,
    pub role: ChatRole,
    pub content: String,
    pub timestamp: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedChatItem {
    pub id: u64,
    pub text: String,
    pub timestamp: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentChatStatus {
    Offline,
    Idle,
    Thinking,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManageConfig {
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub endpoint_id: String,
    #[serde(default)]
    pub goals: String,
    #[serde(default)]
    pub stopping_point: String,
    #[serde(default)]
    pub periodic_checks: String,
    #[serde(default)]
    pub red_flags: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub turn_counter: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatConversation {
    pub messages: Vec<ChatMessage>,
    pub pins: Vec<PinnedChatItem>,
    pub pinned_context: String,
    pub summary: String,
    pub window_size: usize,
    pub next_id: u64,
    pub agent_status: AgentChatStatus,
    pub last_seen: Option<OffsetDateTime>,
    #[serde(default)]
    pub profile_url: Option<String>,
    #[serde(default)]
    pub auto_message: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub git_branch: Option<String>,
    #[serde(default)]
    pub manage_config: Option<ManageConfig>,
}

impl Default for ChatConversation {
    fn default() -> Self {
        Self {
            messages: Vec::new(),
            pins: Vec::new(),
            pinned_context: String::new(),
            summary: String::new(),
            window_size: 22,
            next_id: 1,
            agent_status: AgentChatStatus::Offline,
            last_seen: None,
            profile_url: None,
            auto_message: None,
            cwd: None,
            git_branch: None,
            manage_config: None,
        }
    }
}

#[derive(Debug)]
pub struct ChatStore {
    conn: Arc<Mutex<Connection>>,
}

impl Clone for ChatStore {
    fn clone(&self) -> Self {
        panic!("ChatStore should not be cloned; wrap in Arc instead");
    }
}

const CHAT_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS conversations (
    owner TEXT NOT NULL,
    agent TEXT NOT NULL,
    agent_status TEXT NOT NULL DEFAULT 'offline',
    last_seen TEXT,
    summary TEXT NOT NULL DEFAULT '',
    window_size INTEGER NOT NULL DEFAULT 22,
    cwd TEXT,
    git_branch TEXT,
    model TEXT,
    effort TEXT,
    profile_url TEXT,
    auto_message TEXT,
    next_id INTEGER NOT NULL DEFAULT 1,
    pinned_context TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (owner, agent)
);
CREATE TABLE IF NOT EXISTS messages (
    owner TEXT NOT NULL,
    agent TEXT NOT NULL,
    id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (owner, agent, id)
);
CREATE TABLE IF NOT EXISTS pins (
    owner TEXT NOT NULL,
    agent TEXT NOT NULL,
    id INTEGER NOT NULL,
    text TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (owner, agent, id)
);
CREATE TABLE IF NOT EXISTS backend_preferences (
    owner TEXT NOT NULL,
    backend TEXT NOT NULL,
    model TEXT,
    effort TEXT,
    PRIMARY KEY (owner, backend)
);
";

impl ChatStore {
    /// Open a standalone chat store (creates its own DB connection).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::from_conn(open_lore_db(&root.into()))
    }

    /// Create from an existing shared connection.
    pub fn from_conn(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    pub fn cleanup_orphans(&self) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => { eprintln!("warning: could not acquire db lock for chat cleanup"); return; }
        };

        // Conversations for non-existent users
        match conn.execute(
            "DELETE FROM conversations WHERE owner NOT IN (SELECT username FROM users)",
            [],
        ) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} conversation(s) for deleted user(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: conversation cleanup failed: {e}"),
        }

        // Conversations for agents with no token
        match conn.execute(
            "DELETE FROM conversations WHERE agent NOT IN (SELECT DISTINCT name FROM agent_tokens)",
            [],
        ) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} conversation(s) for deleted agent(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: conversation cleanup failed: {e}"),
        }

        // Orphaned messages (conversation was deleted above, or never existed)
        match conn.execute(
            "DELETE FROM messages WHERE NOT EXISTS (SELECT 1 FROM conversations c WHERE c.owner = messages.owner AND c.agent = messages.agent)",
            [],
        ) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} orphaned message(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: message cleanup failed: {e}"),
        }

        // Orphaned pins
        match conn.execute(
            "DELETE FROM pins WHERE NOT EXISTS (SELECT 1 FROM conversations c WHERE c.owner = pins.owner AND c.agent = pins.agent)",
            [],
        ) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} orphaned pin(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: pin cleanup failed: {e}"),
        }

        // Backend preferences for non-existent users
        match conn.execute(
            "DELETE FROM backend_preferences WHERE owner NOT IN (SELECT username FROM users)",
            [],
        ) {
            Ok(n) if n > 0 => eprintln!("cleanup: removed {n} backend preference(s) for deleted user(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: backend preference cleanup failed: {e}"),
        }
    }

    fn ensure_conversation(conn: &Connection, owner: &str, agent: &str) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT OR IGNORE INTO conversations (owner, agent) VALUES (?1, ?2)",
            params![owner, agent],
        )?;
        Ok(())
    }

    pub fn load_conversation(&self, owner: &str, agent: &str) -> Result<ChatConversation> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let conv = conn.query_row(
            "SELECT agent_status, last_seen, summary, window_size, cwd, git_branch, profile_url, auto_message, next_id, pinned_context, manage_config FROM conversations WHERE owner = ?1 AND agent = ?2",
            params![owner, agent],
            |row| {
                let mc_json: Option<String> = row.get(10)?;
                let manage_config = mc_json.and_then(|s| serde_json::from_str::<ManageConfig>(&s).ok());
                Ok(ChatConversation {
                    messages: Vec::new(),
                    pins: Vec::new(),
                    pinned_context: row.get::<_, String>(9)?,
                    summary: row.get::<_, String>(2)?,
                    window_size: row.get::<_, i64>(3)? as usize,
                    next_id: row.get::<_, i64>(8)? as u64,
                    agent_status: match row.get::<_, String>(0)?.as_str() {
                        "idle" => AgentChatStatus::Idle,
                        "thinking" => AgentChatStatus::Thinking,
                        _ => AgentChatStatus::Offline,
                    },
                    last_seen: row.get::<_, Option<String>>(1)?.map(|s| parse_dt(&s)),
                    profile_url: row.get(6)?,
                    auto_message: row.get(7)?,
                    cwd: row.get(4)?,
                    git_branch: row.get(5)?,
                    manage_config,
                })
            },
        );
        let mut conv = match conv {
            Ok(c) => c,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(ChatConversation::default()),
            Err(e) => return Err(LoreError::Validation(format!("db error: {e}"))),
        };
        // Load messages
        let mut stmt = conn.prepare(
            "SELECT id, role, content, timestamp FROM messages WHERE owner = ?1 AND agent = ?2 ORDER BY id"
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conv.messages = stmt.query_map(params![owner, agent], |row| {
            Ok(ChatMessage {
                id: row.get::<_, i64>(0)? as u64,
                role: match row.get::<_, String>(1)?.as_str() {
                    "assistant" => ChatRole::Assistant,
                    "tool" => ChatRole::Tool,
                    "error" => ChatRole::Error,
                    // fallback to User for unknown roles
                    _ => ChatRole::User,
                },
                content: row.get(2)?,
                timestamp: parse_dt(&row.get::<_, String>(3)?),
            })
        }).map_err(|e| LoreError::Validation(format!("db error: {e}")))?
        .filter_map(|r| r.ok())
        .collect();
        // Load pins
        let mut stmt = conn.prepare(
            "SELECT id, text, timestamp FROM pins WHERE owner = ?1 AND agent = ?2 ORDER BY id"
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conv.pins = stmt.query_map(params![owner, agent], |row| {
            Ok(PinnedChatItem {
                id: row.get::<_, i64>(0)? as u64,
                text: row.get(1)?,
                timestamp: parse_dt(&row.get::<_, String>(2)?),
            })
        }).map_err(|e| LoreError::Validation(format!("db error: {e}")))?
        .filter_map(|r| r.ok())
        .collect();
        if conv.pinned_context.is_empty() && !conv.pins.is_empty() {
            let migrated: Vec<&str> = conv.pins.iter().map(|p| p.text.as_str()).collect();
            conv.pinned_context = migrated.join("\n");
            let _ = conn.execute(
                "UPDATE conversations SET pinned_context = ?1 WHERE owner = ?2 AND agent = ?3",
                params![conv.pinned_context, owner, agent],
            );
        }
        Ok(conv)
    }

    pub fn save_conversation(&self, owner: &str, agent: &str, conv: &ChatConversation) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let status_str = match conv.agent_status {
            AgentChatStatus::Idle => "idle",
            AgentChatStatus::Thinking => "thinking",
            AgentChatStatus::Offline => "offline",
        };
        let last_seen_str = conv.last_seen.as_ref().map(|dt| fmt_dt(dt));
        let manage_json = conv.manage_config.as_ref().map(|mc| serde_json::to_string(mc).unwrap_or_default());
        conn.execute(
            "INSERT INTO conversations (owner, agent, agent_status, last_seen, summary, window_size, cwd, git_branch, profile_url, auto_message, next_id, pinned_context, manage_config) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
             ON CONFLICT(owner, agent) DO UPDATE SET agent_status=?3, last_seen=?4, summary=?5, window_size=?6, cwd=?7, git_branch=?8, profile_url=?9, auto_message=?10, next_id=?11, pinned_context=?12, manage_config=?13",
            params![owner, agent, status_str, last_seen_str, conv.summary, conv.window_size as i64,
                    conv.cwd, conv.git_branch, conv.profile_url, conv.auto_message, conv.next_id as i64, conv.pinned_context, manage_json],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        // Replace messages
        conn.execute("DELETE FROM messages WHERE owner = ?1 AND agent = ?2", params![owner, agent])
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        for msg in &conv.messages {
            let role_str = match msg.role {
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
                ChatRole::Tool => "tool",
                ChatRole::Error => "error",
            };
            conn.execute(
                "INSERT INTO messages (owner, agent, id, role, content, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![owner, agent, msg.id as i64, role_str, msg.content, fmt_dt(&msg.timestamp)],
            ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        }
        // Replace pins
        conn.execute("DELETE FROM pins WHERE owner = ?1 AND agent = ?2", params![owner, agent])
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        for pin in &conv.pins {
            conn.execute(
                "INSERT INTO pins (owner, agent, id, text, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![owner, agent, pin.id as i64, pin.text, fmt_dt(&pin.timestamp)],
            ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        }
        Ok(())
    }

    pub fn append_message(&self, owner: &str, agent: &str, role: ChatRole, content: String) -> Result<ChatMessage> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let next_id: i64 = conn.query_row(
            "SELECT next_id FROM conversations WHERE owner = ?1 AND agent = ?2",
            params![owner, agent], |row| row.get(0),
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let now = OffsetDateTime::now_utc();
        let role_str = match role {
            ChatRole::User => "user",
            ChatRole::Assistant => "assistant",
            ChatRole::Tool => "tool",
            ChatRole::Error => "error",
        };
        conn.execute(
            "INSERT INTO messages (owner, agent, id, role, content, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![owner, agent, next_id, role_str, content, fmt_dt(&now)],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET next_id = ?1 WHERE owner = ?2 AND agent = ?3",
            params![next_id + 1, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(ChatMessage { id: next_id as u64, role, content, timestamp: now })
    }

    /// Append a tool-use detail. If the most recent message for this (owner,agent)
    /// is already a Tool message, extend it with a new line (with x-count dedup on
    /// consecutive duplicates, mirroring the live UI aggregation). Otherwise insert
    /// a new Tool message. Returns the resulting stored message.
    pub fn append_or_extend_tool(&self, owner: &str, agent: &str, detail: &str) -> Result<ChatMessage> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;

        let last: Option<(i64, String, String, String)> = conn.query_row(
            "SELECT id, role, content, timestamp FROM messages WHERE owner = ?1 AND agent = ?2 ORDER BY id DESC LIMIT 1",
            params![owner, agent],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional().map_err(|e| LoreError::Validation(format!("db error: {e}")))?;

        if let Some((last_id, last_role, last_content, last_ts)) = last {
            if last_role == "tool" {
                let mut lines: Vec<String> = last_content.split('\n').map(|s| s.to_string()).collect();
                let prev = lines.last().cloned().unwrap_or_default();
                let (prev_base, prev_count) = parse_tool_repeat(&prev);
                if prev_base == detail {
                    let new_count = prev_count.unwrap_or(1) + 1;
                    let new_line = format!("{detail} (x{new_count})");
                    let last_idx = lines.len() - 1;
                    lines[last_idx] = new_line;
                } else {
                    lines.push(detail.to_string());
                }
                let new_content = lines.join("\n");
                conn.execute(
                    "UPDATE messages SET content = ?1 WHERE owner = ?2 AND agent = ?3 AND id = ?4",
                    params![new_content, owner, agent, last_id],
                ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
                return Ok(ChatMessage {
                    id: last_id as u64,
                    role: ChatRole::Tool,
                    content: new_content,
                    timestamp: parse_dt(&last_ts),
                });
            }
        }

        let next_id: i64 = conn.query_row(
            "SELECT next_id FROM conversations WHERE owner = ?1 AND agent = ?2",
            params![owner, agent], |row| row.get(0),
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let now = OffsetDateTime::now_utc();
        conn.execute(
            "INSERT INTO messages (owner, agent, id, role, content, timestamp) VALUES (?1, ?2, ?3, 'tool', ?4, ?5)",
            params![owner, agent, next_id, detail, fmt_dt(&now)],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET next_id = ?1 WHERE owner = ?2 AND agent = ?3",
            params![next_id + 1, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(ChatMessage {
            id: next_id as u64,
            role: ChatRole::Tool,
            content: detail.to_string(),
            timestamp: now,
        })
    }

    pub fn update_agent_status(&self, owner: &str, agent: &str, status: AgentChatStatus) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let status_str = match status {
            AgentChatStatus::Idle => "idle",
            AgentChatStatus::Thinking => "thinking",
            AgentChatStatus::Offline => "offline",
        };
        let now = fmt_dt(&OffsetDateTime::now_utc());
        conn.execute(
            "UPDATE conversations SET agent_status = ?1, last_seen = ?2 WHERE owner = ?3 AND agent = ?4",
            params![status_str, now, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn update_cwd(&self, owner: &str, agent: &str, cwd: &str, git_branch: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET cwd = ?1, git_branch = ?2 WHERE owner = ?3 AND agent = ?4",
            params![cwd, git_branch, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn update_summary(&self, owner: &str, agent: &str, summary: String) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET summary = ?1 WHERE owner = ?2 AND agent = ?3",
            params![summary, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn update_window_size(&self, owner: &str, agent: &str, size: usize) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET window_size = ?1 WHERE owner = ?2 AND agent = ?3",
            params![size as i64, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn clear_messages(&self, owner: &str, agent: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute("DELETE FROM messages WHERE owner = ?1 AND agent = ?2", params![owner, agent])
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET next_id = 1 WHERE owner = ?1 AND agent = ?2",
            params![owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn set_messages(&self, owner: &str, agent: &str, messages: Vec<ChatMessage>, summary: String) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute("DELETE FROM messages WHERE owner = ?1 AND agent = ?2", params![owner, agent])
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        for msg in &messages {
            let role_str = match msg.role {
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
                ChatRole::Tool => "tool",
                ChatRole::Error => "error",
            };
            conn.execute(
                "INSERT INTO messages (owner, agent, id, role, content, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![owner, agent, msg.id as i64, role_str, msg.content, fmt_dt(&msg.timestamp)],
            ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        }
        conn.execute(
            "UPDATE conversations SET summary = ?1 WHERE owner = ?2 AND agent = ?3",
            params![summary, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn set_pinned_context(&self, owner: &str, agent: &str, text: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET pinned_context = ?1 WHERE owner = ?2 AND agent = ?3",
            params![text, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn get_pinned_context(&self, owner: &str, agent: &str) -> Result<String> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let result = conn.query_row(
            "SELECT pinned_context FROM conversations WHERE owner = ?1 AND agent = ?2",
            params![owner, agent],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(s) => Ok(s),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(String::new()),
            Err(e) => Err(LoreError::Validation(format!("db error: {e}"))),
        }
    }

    pub fn get_manage_config(&self, owner: &str, agent: &str) -> Result<Option<ManageConfig>> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let result = conn.query_row(
            "SELECT manage_config FROM conversations WHERE owner = ?1 AND agent = ?2",
            params![owner, agent],
            |row| row.get::<_, Option<String>>(0),
        );
        match result {
            Ok(Some(s)) => Ok(serde_json::from_str(&s).ok()),
            Ok(None) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LoreError::Validation(format!("db error: {e}"))),
        }
    }

    pub fn save_manage_config(&self, owner: &str, agent: &str, config: &ManageConfig) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        let json = serde_json::to_string(config).unwrap_or_default();
        conn.execute(
            "UPDATE conversations SET manage_config = ?1 WHERE owner = ?2 AND agent = ?3",
            params![json, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn get_backend_prefs(&self, owner: &str, backend: &str) -> Result<(Option<String>, Option<String>)> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        let result = conn.query_row(
            "SELECT model, effort FROM backend_preferences WHERE owner = ?1 AND backend = ?2",
            params![owner, backend],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        match result {
            Ok(prefs) => Ok(prefs),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok((None, None)),
            Err(e) => Err(LoreError::Validation(format!("db error: {e}"))),
        }
    }

    pub fn set_backend_model(&self, owner: &str, backend: &str, model: Option<String>) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        conn.execute(
            "INSERT INTO backend_preferences (owner, backend, model) VALUES (?1, ?2, ?3) \
             ON CONFLICT(owner, backend) DO UPDATE SET model = ?3",
            params![owner, backend, model],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn set_backend_effort(&self, owner: &str, backend: &str, effort: Option<String>) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        conn.execute(
            "INSERT INTO backend_preferences (owner, backend, effort) VALUES (?1, ?2, ?3) \
             ON CONFLICT(owner, backend) DO UPDATE SET effort = ?3",
            params![owner, backend, effort],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn update_profile_url(&self, owner: &str, agent: &str, url: Option<String>) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET profile_url = ?1 WHERE owner = ?2 AND agent = ?3",
            params![url, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }

    pub fn update_auto_message(&self, owner: &str, agent: &str, msg: Option<String>) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| LoreError::Validation("db lock poisoned".into()))?;
        Self::ensure_conversation(&conn, owner, agent)
            .map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        conn.execute(
            "UPDATE conversations SET auto_message = ?1 WHERE owner = ?2 AND agent = ?3",
            params![msg, owner, agent],
        ).map_err(|e| LoreError::Validation(format!("db error: {e}")))?;
        Ok(())
    }
}

pub struct ChatAuditLog {
    root: PathBuf,
}

impl ChatAuditLog {
    pub fn new(data_root: impl Into<PathBuf>) -> Self {
        let root = data_root.into().join("auditlog");
        Self { root }
    }

    pub fn log(&self, agent: &str, owner: &str, kind: &str, content: &str) {
        if let Err(e) = self.write_entry(agent, owner, kind, content) {
            eprintln!("audit log write failed: {e}");
        }
    }

    fn write_entry(&self, agent: &str, owner: &str, kind: &str, content: &str) -> std::io::Result<()> {
        let agent_dir = self.root.join(sanitize_path_component(agent));
        fs::create_dir_all(&agent_dir)?;
        let now = OffsetDateTime::now_utc();
        let date_str = format!("{:04}-{:02}-{:02}", now.year(), now.month() as u8, now.day());
        let log_path = agent_dir.join(format!("{date_str}.log"));
        let ts = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            now.year(), now.month() as u8, now.day(),
            now.hour(), now.minute(), now.second()
        );
        let escaped = content.replace('\n', "\\n");
        let line = format!("[{ts}] [{kind}:{owner}] {escaped}\n");
        let mut f = OpenOptions::new().create(true).append(true).open(&log_path)?;
        f.write_all(line.as_bytes())
    }

    pub fn cleanup_old_logs(&self, max_age_days: u64) {
        if let Err(e) = self.do_cleanup(max_age_days) {
            eprintln!("audit log cleanup failed: {e}");
        }
    }

    fn do_cleanup(&self, max_age_days: u64) -> std::io::Result<()> {
        if !self.root.exists() {
            return Ok(());
        }
        let now = OffsetDateTime::now_utc();
        for agent_entry in fs::read_dir(&self.root)? {
            let agent_entry = agent_entry?;
            if !agent_entry.file_type()?.is_dir() {
                continue;
            }
            let agent_dir = agent_entry.path();
            for log_entry in fs::read_dir(&agent_dir)? {
                let log_entry = log_entry?;
                let name = log_entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.ends_with(".log") {
                    continue;
                }
                let date_part = &name_str[..name_str.len() - 4];
                if let Some(file_date) = parse_date(date_part) {
                    let age = now - file_date;
                    if age.whole_days() > max_age_days as i64 {
                        let _ = fs::remove_file(log_entry.path());
                    }
                }
            }
            if dir_is_empty(&agent_dir) {
                let _ = fs::remove_dir(&agent_dir);
            }
        }
        Ok(())
    }
}

fn sanitize_path_component(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

fn parse_date(s: &str) -> Option<OffsetDateTime> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 { return None; }
    let y: i32 = parts[0].parse().ok()?;
    let m: u8 = parts[1].parse().ok()?;
    let d: u8 = parts[2].parse().ok()?;
    let month = time::Month::try_from(m).ok()?;
    let date = time::Date::from_calendar_date(y, month, d).ok()?;
    Some(OffsetDateTime::new_utc(date, time::Time::MIDNIGHT))
}

fn dir_is_empty(path: &Path) -> bool {
    fs::read_dir(path).map(|mut d| d.next().is_none()).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::{
        AgentBackend, LocalAuthStore, NewAgentToken, NewRole, NewUser, ProjectGrant,
        ProjectPermission, RoleName, UserName,
    };
    use crate::config::{ColorMode, UiTheme};
    use crate::model::ProjectName;
    use tempfile::tempdir;

    #[test]
    fn hashes_passwords_and_authenticates_users() {
        let dir = tempdir().unwrap();
        let auth = LocalAuthStore::new(dir.path());

        auth.bootstrap_admin(
            UserName::new("admin".to_string()).unwrap(),
            "correct-horse-battery".into(),
        )
        .unwrap();

        // Verify password is not stored in plaintext (check DB doesn't contain raw password)
        let db_bytes = std::fs::read(dir.path().join("lore.db")).unwrap();
        let db_str = String::from_utf8_lossy(&db_bytes);
        assert!(!db_str.contains("correct-horse-battery"));

        let user = auth.authenticate("admin", "correct-horse-battery").unwrap();
        assert!(user.is_admin);
    }

    #[test]
    fn roles_grant_project_permissions() {
        let dir = tempdir().unwrap();
        let auth = LocalAuthStore::new(dir.path());
        auth.bootstrap_admin(
            UserName::new("admin".to_string()).unwrap(),
            "correct-horse-battery".into(),
        )
        .unwrap();

        auth.create_role(NewRole {
            name: RoleName::new("writers".to_string()).unwrap(),
            grants: vec![ProjectGrant {
                project: ProjectName::new("alpha.docs").unwrap(),
                permission: ProjectPermission::ReadWrite,
            }],
        })
        .unwrap();

        auth.create_user(NewUser {
            username: UserName::new("alice".to_string()).unwrap(),
            password: "very-secure-passphrase".into(),
            role_names: vec![RoleName::new("writers".to_string()).unwrap()],
            is_admin: false,
        })
        .unwrap();

        let user = auth
            .authenticate("alice", "very-secure-passphrase")
            .unwrap();
        assert!(user.can_read(&ProjectName::new("alpha.docs").unwrap()));
        assert!(user.can_write(&ProjectName::new("alpha.docs").unwrap()));
        assert!(!user.can_read(&ProjectName::new("beta.docs").unwrap()));
        assert_eq!(user.theme, None);
    }

    #[test]
    fn stores_optional_user_theme_preference() {
        let dir = tempdir().unwrap();
        let auth = LocalAuthStore::new(dir.path());
        auth.bootstrap_admin(
            UserName::new("admin".to_string()).unwrap(),
            "correct-horse-battery".into(),
        )
        .unwrap();

        auth.update_user_theme(
            &UserName::new("admin".to_string()).unwrap(),
            Some(UiTheme::Signal),
            Some(ColorMode::Dark),
        )
        .unwrap();

        let user = auth.authenticate("admin", "correct-horse-battery").unwrap();
        assert_eq!(user.theme, Some(UiTheme::Signal));
        assert_eq!(user.color_mode, Some(ColorMode::Dark));
    }

    #[test]
    fn creates_and_authenticates_sessions_without_storing_raw_token() {
        let dir = tempdir().unwrap();
        let auth = LocalAuthStore::new(dir.path());
        auth.bootstrap_admin(
            UserName::new("admin".to_string()).unwrap(),
            "correct-horse-battery".into(),
        )
        .unwrap();

        let session = auth
            .create_session("admin", "correct-horse-battery")
            .unwrap();

        // Verify raw token is not in the database
        let db_bytes = std::fs::read(dir.path().join("lore.db")).unwrap();
        let db_str = String::from_utf8_lossy(&db_bytes);
        assert!(!db_str.contains(&session.token));

        let (user, stored_session) = auth.authenticate_session(&session.token).unwrap();
        assert!(user.is_admin);
        assert_eq!(stored_session.csrf_token, session.csrf_token);
    }

    #[test]
    fn creates_and_authenticates_agent_tokens_without_storing_raw_token() {
        let dir = tempdir().unwrap();
        let auth = LocalAuthStore::new(dir.path());
        auth.bootstrap_admin(
            UserName::new("admin".to_string()).unwrap(),
            "correct-horse-battery".into(),
        )
        .unwrap();

        let created = auth
            .create_agent_token(NewAgentToken {
                display_name: "worker-alpha".into(),
                owner: UserName::new("admin").unwrap(),
                grants: vec![ProjectGrant {
                    project: ProjectName::new("alpha.docs").unwrap(),
                    permission: ProjectPermission::ReadWrite,
                }],
                backend: AgentBackend::default(),
                endpoint_id: None,
            })
            .unwrap();

        // Verify raw token is not in the database
        let db_bytes = std::fs::read(dir.path().join("lore.db")).unwrap();
        let db_str = String::from_utf8_lossy(&db_bytes);
        assert!(!db_str.contains(&created.token));

        let agent = auth.authenticate_agent_token(&created.token).unwrap();
        assert_eq!(agent.name, "worker-alpha");
        assert!(agent.can_write(&ProjectName::new("alpha.docs").unwrap()));
    }

    #[test]
    fn cannot_disable_last_admin() {
        let dir = tempdir().unwrap();
        let auth = LocalAuthStore::new(dir.path());
        auth.bootstrap_admin(
            UserName::new("admin".to_string()).unwrap(),
            "correct-horse-battery".into(),
        )
        .unwrap();
        let err = auth
            .set_user_disabled(&UserName::new("admin".to_string()).unwrap(), true)
            .unwrap_err();
        assert!(err.to_string().contains("last admin"));
    }

    #[test]
    fn can_disable_admin_when_another_exists() {
        let dir = tempdir().unwrap();
        let auth = LocalAuthStore::new(dir.path());
        auth.bootstrap_admin(
            UserName::new("admin1".to_string()).unwrap(),
            "correct-horse-battery".into(),
        )
        .unwrap();
        auth.create_user_unchecked(NewUser {
            username: UserName::new("admin2".to_string()).unwrap(),
            password: "another-secure-pass".into(),
            role_names: vec![],
            is_admin: true,
        })
        .unwrap();
        auth.set_user_disabled(&UserName::new("admin1".to_string()).unwrap(), true)
            .unwrap();
    }
}
