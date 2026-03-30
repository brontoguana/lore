use crate::config::UiTheme;
use crate::error::{LoreError, Result};
use crate::model::ProjectName;
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
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
pub struct StoredAgentToken {
    pub name: String,
    pub token_hash: String,
    pub grants: Vec<ProjectGrant>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewAgentToken {
    pub name: String,
    pub grants: Vec<ProjectGrant>,
}

impl NewAgentToken {
    pub fn validate(&self) -> Result<()> {
        validate_agent_token_name(&self.name)?;
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

#[derive(Debug, Clone)]
pub struct CreatedAgentToken {
    pub token: String,
    pub stored: StoredAgentToken,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedAgent {
    pub token: String,
    pub name: String,
    pub grants: Vec<ProjectGrant>,
}

impl AuthenticatedAgent {
    pub fn can_read(&self, project: &ProjectName) -> bool {
        self.grants.iter().any(|grant| &grant.project == project)
    }

    pub fn can_write(&self, project: &ProjectName) -> bool {
        self.grants
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

#[derive(Debug, Clone)]
pub struct LocalAuthStore {
    root: PathBuf,
}

impl LocalAuthStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn has_users(&self) -> Result<bool> {
        Ok(!self.load_users()?.is_empty())
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
        self.load_roles()
    }

    pub fn create_role(&self, role: NewRole) -> Result<StoredRole> {
        role.validate()?;
        let mut roles = self.load_roles()?;
        if roles.iter().any(|existing| existing.name == role.name) {
            return Err(LoreError::Validation("role already exists".into()));
        }

        let mut grants = role.grants;
        grants.sort_by(|a, b| a.project.cmp(&b.project));
        let stored = StoredRole {
            name: role.name,
            grants,
            created_at: OffsetDateTime::now_utc(),
        };
        roles.push(stored.clone());
        roles.sort_by(|a, b| a.name.cmp(&b.name));
        self.save_roles(&roles)?;
        Ok(stored)
    }

    pub fn update_role(&self, role: NewRole) -> Result<StoredRole> {
        role.validate()?;
        let mut roles = self.load_roles()?;
        let index = roles
            .iter()
            .position(|existing| existing.name == role.name)
            .ok_or_else(|| LoreError::Validation("role does not exist".into()))?;

        let mut grants = role.grants;
        grants.sort_by(|a, b| a.project.cmp(&b.project));
        let stored = StoredRole {
            name: role.name,
            grants,
            created_at: roles[index].created_at,
        };
        roles[index] = stored.clone();
        roles.sort_by(|a, b| a.name.cmp(&b.name));
        self.save_roles(&roles)?;
        Ok(stored)
    }

    pub fn list_users(&self) -> Result<Vec<StoredUser>> {
        self.load_users()
    }

    pub fn create_user(&self, user: NewUser) -> Result<StoredUser> {
        user.validate()?;
        let roles = self.load_roles()?;
        for role_name in &user.role_names {
            if !roles.iter().any(|role| &role.name == role_name) {
                return Err(LoreError::Validation(format!(
                    "unknown role: {}",
                    role_name.as_str()
                )));
            }
        }
        self.create_user_unchecked(user)
    }

    pub fn update_user_password(
        &self,
        username: &UserName,
        password: String,
    ) -> Result<StoredUser> {
        validate_password(&password)?;
        let mut users = self.load_users()?;
        let index = users
            .iter()
            .position(|existing| &existing.username == username)
            .ok_or(LoreError::PermissionDenied)?;
        users[index].password_hash = hash_password(&password)?;
        let stored = users[index].clone();
        self.save_users(&users)?;
        Ok(stored)
    }

    pub fn set_user_disabled(&self, username: &UserName, disabled: bool) -> Result<StoredUser> {
        let mut users = self.load_users()?;
        let index = users
            .iter()
            .position(|existing| &existing.username == username)
            .ok_or(LoreError::PermissionDenied)?;
        users[index].disabled_at = if disabled {
            Some(OffsetDateTime::now_utc())
        } else {
            None
        };
        let stored = users[index].clone();
        self.save_users(&users)?;
        if disabled {
            self.revoke_sessions_for_user(username)?;
        }
        Ok(stored)
    }

    pub fn update_user_theme(
        &self,
        username: &UserName,
        theme: Option<UiTheme>,
    ) -> Result<StoredUser> {
        let mut users = self.load_users()?;
        let index = users
            .iter()
            .position(|existing| &existing.username == username)
            .ok_or(LoreError::PermissionDenied)?;
        users[index].theme = theme;
        let stored = users[index].clone();
        self.save_users(&users)?;
        Ok(stored)
    }

    pub fn list_agent_tokens(&self) -> Result<Vec<StoredAgentToken>> {
        self.load_agent_tokens()
    }

    pub fn create_agent_token(&self, token: NewAgentToken) -> Result<CreatedAgentToken> {
        token.validate()?;
        let mut tokens = self.load_agent_tokens()?;
        if tokens.iter().any(|existing| existing.name == token.name) {
            return Err(LoreError::Validation("agent token already exists".into()));
        }

        let mut grants = token.grants;
        grants.sort_by(|a, b| a.project.cmp(&b.project));
        let raw_token = format!("lore_at_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        let stored = StoredAgentToken {
            name: token.name,
            token_hash: hash_agent_token(&raw_token),
            grants,
            created_at: OffsetDateTime::now_utc(),
        };
        tokens.push(stored.clone());
        tokens.sort_by(|a, b| a.name.cmp(&b.name));
        self.save_agent_tokens(&tokens)?;
        Ok(CreatedAgentToken {
            token: raw_token,
            stored,
        })
    }

    pub fn rotate_agent_token(&self, name: &str) -> Result<CreatedAgentToken> {
        validate_agent_token_name(name)?;
        let mut tokens = self.load_agent_tokens()?;
        let index = tokens
            .iter()
            .position(|existing| existing.name == name)
            .ok_or_else(|| LoreError::Validation("agent token does not exist".into()))?;
        let raw_token = format!("lore_at_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        tokens[index].token_hash = hash_agent_token(&raw_token);
        tokens[index].created_at = OffsetDateTime::now_utc();
        let stored = tokens[index].clone();
        self.save_agent_tokens(&tokens)?;
        Ok(CreatedAgentToken {
            token: raw_token,
            stored,
        })
    }

    pub fn revoke_agent_token(&self, name: &str) -> Result<()> {
        validate_agent_token_name(name)?;
        let mut tokens = self.load_agent_tokens()?;
        let original_len = tokens.len();
        tokens.retain(|token| token.name != name);
        if tokens.len() == original_len {
            return Err(LoreError::Validation("agent token does not exist".into()));
        }
        self.save_agent_tokens(&tokens)?;
        Ok(())
    }

    pub fn authenticate_agent_token(&self, token: &str) -> Result<AuthenticatedAgent> {
        if token.trim().is_empty() {
            return Err(LoreError::PermissionDenied);
        }
        let token_hash = hash_agent_token(token);
        let stored = self
            .load_agent_tokens()?
            .into_iter()
            .find(|stored| stored.token_hash == token_hash)
            .ok_or(LoreError::PermissionDenied)?;
        Ok(AuthenticatedAgent {
            token: token.to_string(),
            name: stored.name,
            grants: stored.grants,
        })
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Result<AuthenticatedUser> {
        let username = UserName::new(username.to_string())?;
        let user = self.stored_user(&username)?;
        verify_password_hash(&user.password_hash, password)?;
        self.user_from_stored(&user)
    }

    pub fn create_session(&self, username: &str, password: &str) -> Result<NewSession> {
        let user = self.authenticate(username, password)?;
        self.create_session_for_authenticated_user(user)
    }

    pub fn create_session_for_user(&self, username: &UserName) -> Result<NewSession> {
        let user = self.user_from_stored(&self.stored_user(username)?)?;
        self.create_session_for_authenticated_user(user)
    }

    pub fn authenticate_external_username(&self, username: &str) -> Result<AuthenticatedUser> {
        let username = UserName::new(username.to_string())?;
        let user = self.stored_user(&username)?;
        self.user_from_stored(&user)
    }

    fn create_session_for_authenticated_user(&self, user: AuthenticatedUser) -> Result<NewSession> {
        let token = Uuid::new_v4().to_string();
        let csrf_token = Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let session = StoredSession {
            token_hash: hash_session_token(&token),
            username: user.username.clone(),
            csrf_token: csrf_token.clone(),
            created_at: now,
            expires_at: now
                + time::Duration::try_from(Duration::from_secs(SESSION_TTL_SECS as u64))
                    .map_err(|_| LoreError::Validation("invalid session ttl".into()))?,
        };
        self.save_session(&session)?;
        Ok(NewSession {
            token,
            csrf_token,
            user,
        })
    }

    pub fn revoke_sessions_for_user(&self, username: &UserName) -> Result<usize> {
        self.ensure_layout()?;
        let mut removed = 0usize;
        for entry in fs::read_dir(self.sessions_dir())? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let session: StoredSession = serde_json::from_slice(&fs::read(&path)?)?;
            if &session.username == username {
                fs::remove_file(path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn active_session_count(&self, username: &UserName) -> Result<usize> {
        self.ensure_layout()?;
        let now = OffsetDateTime::now_utc();
        let mut count = 0usize;
        for entry in fs::read_dir(self.sessions_dir())? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let session: StoredSession = serde_json::from_slice(&fs::read(&path)?)?;
            if &session.username == username && session.expires_at > now {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn authenticate_session(&self, token: &str) -> Result<(AuthenticatedUser, StoredSession)> {
        if token.trim().is_empty() {
            return Err(LoreError::PermissionDenied);
        }
        let token_hash = hash_session_token(token);
        let path = self.session_path(&token_hash);
        if !path.exists() {
            return Err(LoreError::PermissionDenied);
        }
        let session: StoredSession = serde_json::from_slice(&fs::read(&path)?)?;
        if session.expires_at <= OffsetDateTime::now_utc() {
            let _ = fs::remove_file(&path);
            return Err(LoreError::PermissionDenied);
        }

        let user = self.stored_user(&session.username)?;
        Ok((self.user_from_stored(&user)?, session))
    }

    pub fn revoke_session(&self, token: &str) -> Result<()> {
        if token.trim().is_empty() {
            return Ok(());
        }
        let path = self.session_path(&hash_session_token(token));
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn authorize_read(&self, user: &AuthenticatedUser, project: &ProjectName) -> Result<()> {
        if user.can_read(project) {
            Ok(())
        } else {
            Err(LoreError::PermissionDenied)
        }
    }

    pub fn authorize_write(&self, user: &AuthenticatedUser, project: &ProjectName) -> Result<()> {
        if user.can_write(project) {
            Ok(())
        } else {
            Err(LoreError::PermissionDenied)
        }
    }

    fn create_user_unchecked(&self, user: NewUser) -> Result<StoredUser> {
        user.validate()?;
        let mut users = self.load_users()?;
        if users
            .iter()
            .any(|existing| existing.username == user.username)
        {
            return Err(LoreError::Validation("user already exists".into()));
        }

        let password_hash = hash_password(&user.password)?;
        let stored = StoredUser {
            username: user.username,
            password_hash,
            role_names: user.role_names,
            is_admin: user.is_admin,
            theme: None,
            disabled_at: None,
            created_at: OffsetDateTime::now_utc(),
        };
        users.push(stored.clone());
        users.sort_by(|a, b| a.username.cmp(&b.username));
        self.save_users(&users)?;
        Ok(stored)
    }

    fn auth_dir(&self) -> PathBuf {
        self.root.join("auth")
    }

    fn users_path(&self) -> PathBuf {
        self.auth_dir().join("users.json")
    }

    fn roles_path(&self) -> PathBuf {
        self.auth_dir().join("roles.json")
    }

    fn sessions_dir(&self) -> PathBuf {
        self.auth_dir().join("sessions")
    }

    fn agent_tokens_path(&self) -> PathBuf {
        self.auth_dir().join("agent_tokens.json")
    }

    fn session_path(&self, token_hash: &str) -> PathBuf {
        self.sessions_dir().join(format!("{token_hash}.json"))
    }

    fn load_users(&self) -> Result<Vec<StoredUser>> {
        read_json(self.users_path())
    }

    fn load_roles(&self) -> Result<Vec<StoredRole>> {
        read_json(self.roles_path())
    }

    fn load_agent_tokens(&self) -> Result<Vec<StoredAgentToken>> {
        read_json(self.agent_tokens_path())
    }

    fn save_users(&self, users: &[StoredUser]) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.users_path(), users)
    }

    fn save_roles(&self, roles: &[StoredRole]) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.roles_path(), roles)
    }

    fn save_agent_tokens(&self, tokens: &[StoredAgentToken]) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.agent_tokens_path(), tokens)
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.auth_dir())?;
        fs::create_dir_all(self.sessions_dir())?;
        lock_down_dir(&self.auth_dir())?;
        lock_down_dir(&self.sessions_dir())?;
        Ok(())
    }

    fn stored_user(&self, username: &UserName) -> Result<StoredUser> {
        self.load_users()?
            .into_iter()
            .find(|user| &user.username == username)
            .ok_or(LoreError::PermissionDenied)
    }

    fn user_from_stored(&self, user: &StoredUser) -> Result<AuthenticatedUser> {
        if user.disabled_at.is_some() {
            return Err(LoreError::PermissionDenied);
        }
        let all_roles = self.load_roles()?;
        let roles = all_roles
            .into_iter()
            .filter(|role| user.role_names.iter().any(|name| name == &role.name))
            .collect();

        Ok(AuthenticatedUser {
            username: user.username.clone(),
            is_admin: user.is_admin,
            roles,
            theme: user.theme,
        })
    }

    fn save_session(&self, session: &StoredSession) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.session_path(&session.token_hash), session)
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

fn read_json<T>(path: PathBuf) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
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
    lock_down_file(&tmp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp_path, &path)?;
    lock_down_file(&path)?;
    Ok(())
}

fn lock_down_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn lock_down_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LocalAuthStore, NewAgentToken, NewRole, NewUser, ProjectGrant, ProjectPermission, RoleName,
        UserName,
    };
    use crate::config::UiTheme;
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

        let users_path = dir.path().join("auth/users.json");
        let users_json = std::fs::read_to_string(users_path).unwrap();
        assert!(!users_json.contains("correct-horse-battery"));
        assert!(users_json.contains("$argon2"));

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
        )
        .unwrap();

        let user = auth.authenticate("admin", "correct-horse-battery").unwrap();
        assert_eq!(user.theme, Some(UiTheme::Signal));
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
        let session_files = std::fs::read_dir(dir.path().join("auth/sessions"))
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(session_files.len(), 1);
        let stored = std::fs::read_to_string(session_files[0].as_ref().unwrap().path()).unwrap();
        assert!(!stored.contains(&session.token));

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
                name: "worker-alpha".into(),
                grants: vec![ProjectGrant {
                    project: ProjectName::new("alpha.docs").unwrap(),
                    permission: ProjectPermission::ReadWrite,
                }],
            })
            .unwrap();

        let tokens_path = dir.path().join("auth/agent_tokens.json");
        let tokens_json = std::fs::read_to_string(tokens_path).unwrap();
        assert!(!tokens_json.contains(&created.token));

        let agent = auth.authenticate_agent_token(&created.token).unwrap();
        assert_eq!(agent.name, "worker-alpha");
        assert!(agent.can_write(&ProjectName::new("alpha.docs").unwrap()));
    }
}
