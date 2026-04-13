use crate::error::{LoreError, Result};
use crate::model::{Block, BlockId, BlockType, ProjectName};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_ENDPOINT_URL_LEN: usize = 2048;
const MAX_MODEL_LEN: usize = 256;
const MAX_ENDPOINT_NAME_LEN: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EndpointKind {
    Anthropic,
    Gemini,
    #[serde(rename = "openai")]
    OpenAi,
}

impl Display for EndpointKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anthropic => write!(f, "anthropic"),
            Self::Gemini => write!(f, "gemini"),
            Self::OpenAi => write!(f, "openai"),
        }
    }
}

impl std::str::FromStr for EndpointKind {
    type Err = LoreError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "anthropic" => Ok(Self::Anthropic),
            "gemini" => Ok(Self::Gemini),
            "openai" => Ok(Self::OpenAi),
            _ => Err(LoreError::Validation(format!(
                "unknown endpoint kind: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    pub id: String,
    pub name: String,
    pub kind: EndpointKind,
    pub url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Endpoint {
    pub fn validate(&self) -> Result<()> {
        let name = self.name.trim();
        if name.is_empty() || name.len() > MAX_ENDPOINT_NAME_LEN {
            return Err(LoreError::Validation(format!(
                "endpoint name must be 1..={MAX_ENDPOINT_NAME_LEN} characters"
            )));
        }
        validate_endpoint_url(&self.url)?;
        validate_model(&self.model)?;
        Ok(())
    }

    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    pub fn is_configured(&self) -> bool {
        !self.url.is_empty() && !self.model.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct EndpointStore {
    root: PathBuf,
}

impl EndpointStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn list(&self) -> Result<Vec<Endpoint>> {
        let path = self.endpoints_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let endpoints: Vec<Endpoint> = serde_json::from_slice(&fs::read(path)?)?;
        Ok(endpoints)
    }

    pub fn get(&self, id: &str) -> Result<Option<Endpoint>> {
        Ok(self.list()?.into_iter().find(|e| e.id == id))
    }

    pub fn create(
        &self,
        name: String,
        kind: EndpointKind,
        url: String,
        model: String,
        api_key: Option<String>,
    ) -> Result<Endpoint> {
        self.ensure_layout()?;
        let endpoint = Endpoint {
            id: Uuid::new_v4().to_string(),
            name: name.trim().to_string(),
            kind,
            url: url.trim().to_string(),
            model: model.trim().to_string(),
            api_key: api_key
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty()),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        endpoint.validate()?;
        let mut endpoints = self.list()?;
        endpoints.push(endpoint.clone());
        write_json_atomic(self.endpoints_path(), &endpoints)?;
        Ok(endpoint)
    }

    pub fn update(
        &self,
        id: &str,
        name: String,
        kind: EndpointKind,
        url: String,
        model: String,
        api_key: ApiKeyUpdate<'_>,
    ) -> Result<Endpoint> {
        self.ensure_layout()?;
        let mut endpoints = self.list()?;
        let Some(endpoint) = endpoints.iter_mut().find(|e| e.id == id) else {
            return Err(LoreError::Validation("endpoint not found".into()));
        };
        endpoint.name = name.trim().to_string();
        endpoint.kind = kind;
        endpoint.url = url.trim().to_string();
        endpoint.model = model.trim().to_string();
        match api_key {
            ApiKeyUpdate::Preserve => {}
            ApiKeyUpdate::Replace(value) => {
                endpoint.api_key = Some(value.trim().to_string());
            }
            ApiKeyUpdate::Clear => {
                endpoint.api_key = None;
            }
        }
        endpoint.updated_at = OffsetDateTime::now_utc();
        endpoint.validate()?;
        let updated = endpoint.clone();
        write_json_atomic(self.endpoints_path(), &endpoints)?;
        Ok(updated)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let mut endpoints = self.list()?;
        let before = endpoints.len();
        endpoints.retain(|e| e.id != id);
        if endpoints.len() == before {
            return Err(LoreError::Validation("endpoint not found".into()));
        }
        write_json_atomic(self.endpoints_path(), &endpoints)
    }

    fn endpoints_path(&self) -> PathBuf {
        self.config_dir().join("endpoints.json")
    }

    fn config_dir(&self) -> PathBuf {
        self.root.join("config")
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
const MAX_QUESTION_LEN: usize = 4000;
const MAX_INSTRUCTION_LEN: usize = 6000;
pub const MAX_CONTEXT_BLOCKS: usize = 10;
pub const MAX_PROMPT_CHARS: usize = 16 * 1024;
pub const MAX_ANSWER_CHARS: usize = 8 * 1024;
pub const REQUEST_TIMEOUT_SECS: u64 = 20;
pub const MAX_PROVIDER_TIMEOUT_SECS: u64 = 120;
pub const DEFAULT_MAX_CONCURRENT_RUNS: usize = 4;
pub const MAX_PROJECT_ACTION_OPERATIONS: usize = 5;
pub const RATE_LIMIT_REQUESTS: usize = 6;
pub const RATE_LIMIT_WINDOW_SECS: i64 = 60;
const MAX_HISTORY_PER_PROJECT: usize = 20;
const MAX_PENDING_ACTIONS_PER_PROJECT: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LibrarianConfig {
    #[serde(default)]
    pub endpoint_id: Option<String>,
    #[serde(default)]
    pub endpoint_url: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_max_concurrent_runs")]
    pub max_concurrent_runs: usize,
    #[serde(default)]
    pub action_requires_approval: bool,
    pub updated_at: OffsetDateTime,
}

impl LibrarianConfig {
    pub fn default() -> Self {
        Self {
            endpoint_id: None,
            endpoint_url: String::new(),
            model: String::new(),
            api_key: None,
            request_timeout_secs: default_request_timeout_secs(),
            max_concurrent_runs: default_max_concurrent_runs(),
            action_requires_approval: false,
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_request_timeout_secs(self.request_timeout_secs)?;
        validate_max_concurrent_runs(self.max_concurrent_runs)?;
        Ok(())
    }

    pub fn is_configured(&self) -> bool {
        self.endpoint_id.is_some()
    }

    pub fn needs_migration(&self) -> bool {
        self.endpoint_id.is_none()
            && !self.endpoint_url.is_empty()
            && !self.model.is_empty()
            && self.api_key.is_some()
    }

    pub fn has_api_key(&self) -> bool {
        self.endpoint_id.is_some() || self.api_key.is_some()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ApiKeyUpdate<'a> {
    Preserve,
    Replace(&'a str),
    Clear,
}

#[derive(Debug, Clone)]
pub struct LibrarianConfigStore {
    root: PathBuf,
}

impl LibrarianConfigStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<LibrarianConfig> {
        let path = self.config_path();
        if path.exists() {
            let config: LibrarianConfig = serde_json::from_slice(&fs::read(path)?)?;
            config.validate()?;
            return Ok(config);
        }
        Ok(LibrarianConfig::default())
    }

    pub fn update(
        &self,
        endpoint_id: Option<String>,
        request_timeout_secs: u64,
        max_concurrent_runs: usize,
        action_requires_approval: bool,
    ) -> Result<LibrarianConfig> {
        self.ensure_layout()?;
        let config = LibrarianConfig {
            endpoint_id,
            endpoint_url: String::new(),
            model: String::new(),
            api_key: None,
            request_timeout_secs,
            max_concurrent_runs,
            action_requires_approval,
            updated_at: OffsetDateTime::now_utc(),
        };
        config.validate()?;
        write_json_atomic(self.config_path(), &config)?;
        Ok(config)
    }

    pub fn set_endpoint_id(&self, endpoint_id: Option<String>) -> Result<LibrarianConfig> {
        let existing = self.load()?;
        self.update(
            endpoint_id,
            existing.request_timeout_secs,
            existing.max_concurrent_runs,
            existing.action_requires_approval,
        )
    }

    fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn config_path(&self) -> PathBuf {
        self.config_dir().join("librarian.json")
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
pub struct LibrarianRequest {
    pub project: ProjectName,
    pub question: String,
    pub context_blocks: Vec<Block>,
}

impl LibrarianRequest {
    pub fn validate(&self) -> Result<()> {
        let question = self.question.trim();
        if question.is_empty() {
            return Err(LoreError::Validation(
                "librarian question must not be empty".into(),
            ));
        }
        if question.len() > MAX_QUESTION_LEN {
            return Err(LoreError::Validation(format!(
                "librarian question exceeds maximum size of {MAX_QUESTION_LEN} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProjectLibrarianRequest {
    pub project: ProjectName,
    pub instruction: String,
    pub context_blocks: Vec<Block>,
}

impl ProjectLibrarianRequest {
    pub fn validate(&self) -> Result<()> {
        let instruction = self.instruction.trim();
        if instruction.is_empty() {
            return Err(LoreError::Validation(
                "project librarian instruction must not be empty".into(),
            ));
        }
        if instruction.len() > MAX_INSTRUCTION_LEN {
            return Err(LoreError::Validation(format!(
                "project librarian instruction exceeds maximum size of {MAX_INSTRUCTION_LEN} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibrarianAnswer {
    pub answer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCheckResult {
    pub ok: bool,
    pub detail: String,
    pub checked_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LibrarianRunKind {
    Answer,
    ActionRequest,
    ProjectAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LibrarianRunStatus {
    Success,
    Error,
    RateLimited,
    PendingApproval,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LibrarianActorKind {
    User,
    Agent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LibrarianActor {
    pub kind: LibrarianActorKind,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectLibrarianOperationType {
    CreateBlock,
    UpdateBlock,
    MoveBlock,
    DeleteBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProjectLibrarianOperation {
    CreateBlock {
        block_type: BlockType,
        content: String,
        after_block_id: Option<BlockId>,
    },
    UpdateBlock {
        block_id: BlockId,
        block_type: Option<BlockType>,
        content: Option<String>,
        after_block_id: Option<BlockId>,
    },
    MoveBlock {
        block_id: BlockId,
        after_block_id: Option<BlockId>,
    },
    DeleteBlock {
        block_id: BlockId,
    },
}

impl ProjectLibrarianOperation {
    pub fn operation_type(&self) -> ProjectLibrarianOperationType {
        match self {
            Self::CreateBlock { .. } => ProjectLibrarianOperationType::CreateBlock,
            Self::UpdateBlock { .. } => ProjectLibrarianOperationType::UpdateBlock,
            Self::MoveBlock { .. } => ProjectLibrarianOperationType::MoveBlock,
            Self::DeleteBlock { .. } => ProjectLibrarianOperationType::DeleteBlock,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectLibrarianPlan {
    pub summary: String,
    pub operations: Vec<ProjectLibrarianOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredLibrarianOperation {
    pub operation_type: ProjectLibrarianOperationType,
    pub block_id: Option<BlockId>,
    pub after_block_id: Option<BlockId>,
    pub block_type: Option<BlockType>,
    pub content_preview: Option<String>,
}

impl From<&ProjectLibrarianOperation> for StoredLibrarianOperation {
    fn from(value: &ProjectLibrarianOperation) -> Self {
        match value {
            ProjectLibrarianOperation::CreateBlock {
                block_type,
                content,
                after_block_id,
            } => Self {
                operation_type: ProjectLibrarianOperationType::CreateBlock,
                block_id: None,
                after_block_id: after_block_id.clone(),
                block_type: Some(*block_type),
                content_preview: Some(truncate_chars(content, 120)),
            },
            ProjectLibrarianOperation::UpdateBlock {
                block_id,
                block_type,
                content,
                after_block_id,
            } => Self {
                operation_type: ProjectLibrarianOperationType::UpdateBlock,
                block_id: Some(block_id.clone()),
                after_block_id: after_block_id.clone(),
                block_type: *block_type,
                content_preview: content.as_deref().map(|value| truncate_chars(value, 120)),
            },
            ProjectLibrarianOperation::MoveBlock {
                block_id,
                after_block_id,
            } => Self {
                operation_type: ProjectLibrarianOperationType::MoveBlock,
                block_id: Some(block_id.clone()),
                after_block_id: after_block_id.clone(),
                block_type: None,
                content_preview: None,
            },
            ProjectLibrarianOperation::DeleteBlock { block_id } => Self {
                operation_type: ProjectLibrarianOperationType::DeleteBlock,
                block_id: Some(block_id.clone()),
                after_block_id: None,
                block_type: None,
                content_preview: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredLibrarianRun {
    pub id: String,
    pub project: ProjectName,
    pub actor: LibrarianActor,
    #[serde(default = "default_librarian_run_kind")]
    pub kind: LibrarianRunKind,
    #[serde(default)]
    pub parent_run_id: Option<String>,
    pub question: String,
    pub answer: Option<String>,
    pub source_block_ids: Vec<BlockId>,
    #[serde(default)]
    pub operations: Vec<StoredLibrarianOperation>,
    pub provider_endpoint_url: String,
    pub provider_model: String,
    pub status: LibrarianRunStatus,
    pub error: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingLibrarianAction {
    pub id: String,
    pub project: ProjectName,
    pub actor: LibrarianActor,
    pub parent_run_id: String,
    pub pending_run_id: String,
    pub instruction: String,
    pub summary: String,
    pub source_block_ids: Vec<BlockId>,
    pub operations: Vec<ProjectLibrarianOperation>,
    pub provider_endpoint_url: String,
    pub provider_model: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct PendingLibrarianActionStore {
    root: PathBuf,
}

impl PendingLibrarianActionStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn append(&self, action: PendingLibrarianAction) -> Result<()> {
        self.ensure_layout()?;
        let path = self.project_pending_path(&action.project);
        let mut actions: Vec<PendingLibrarianAction> = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            Vec::new()
        };
        actions.push(action);
        actions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        actions.truncate(MAX_PENDING_ACTIONS_PER_PROJECT);
        write_json_atomic(path, &actions)
    }

    pub fn list_project(
        &self,
        project: &ProjectName,
        limit: usize,
    ) -> Result<Vec<PendingLibrarianAction>> {
        let path = self.project_pending_path(project);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut actions: Vec<PendingLibrarianAction> = serde_json::from_slice(&fs::read(path)?)?;
        actions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        actions.truncate(limit);
        Ok(actions)
    }

    pub fn list_all(&self, limit: usize) -> Result<Vec<PendingLibrarianAction>> {
        let dir = self.pending_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut actions = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let mut project_actions: Vec<PendingLibrarianAction> =
                serde_json::from_slice(&fs::read(path)?)?;
            actions.append(&mut project_actions);
        }
        actions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        actions.truncate(limit);
        Ok(actions)
    }

    pub fn take(&self, project: &ProjectName, id: &str) -> Result<Option<PendingLibrarianAction>> {
        let path = self.project_pending_path(project);
        if !path.exists() {
            return Ok(None);
        }
        let mut actions: Vec<PendingLibrarianAction> = serde_json::from_slice(&fs::read(&path)?)?;
        let Some(index) = actions.iter().position(|action| action.id == id) else {
            return Ok(None);
        };
        let action = actions.remove(index);
        write_json_atomic(path, &actions)?;
        Ok(Some(action))
    }

    pub fn get(&self, project: &ProjectName, id: &str) -> Result<Option<PendingLibrarianAction>> {
        Ok(self
            .list_project(project, MAX_PENDING_ACTIONS_PER_PROJECT)?
            .into_iter()
            .find(|action| action.id == id))
    }

    fn pending_dir(&self) -> PathBuf {
        self.root.join("config").join("librarian-pending-actions")
    }

    fn project_pending_path(&self, project: &ProjectName) -> PathBuf {
        self.pending_dir()
            .join(format!("{}.json", project.as_str()))
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.pending_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.pending_dir(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LibrarianHistoryStore {
    root: PathBuf,
}

impl LibrarianHistoryStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn list_recent_project(
        &self,
        project: &ProjectName,
        limit: usize,
    ) -> Result<Vec<StoredLibrarianRun>> {
        let path = self.project_history_path(project);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut runs: Vec<StoredLibrarianRun> = serde_json::from_slice(&fs::read(path)?)?;
        runs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        runs.truncate(limit);
        Ok(runs)
    }

    pub fn append(&self, run: StoredLibrarianRun) -> Result<()> {
        self.ensure_layout()?;
        let path = self.project_history_path(&run.project);
        let mut runs: Vec<StoredLibrarianRun> = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            Vec::new()
        };
        runs.push(run);
        runs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        runs.truncate(MAX_HISTORY_PER_PROJECT);
        write_json_atomic(path, &runs)
    }

    pub fn list_recent_all(&self, limit: usize) -> Result<Vec<StoredLibrarianRun>> {
        let history_dir = self.history_dir();
        if !history_dir.exists() {
            return Ok(Vec::new());
        }
        let mut runs = Vec::new();
        for entry in fs::read_dir(history_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let mut project_runs: Vec<StoredLibrarianRun> =
                serde_json::from_slice(&fs::read(path)?)?;
            runs.append(&mut project_runs);
        }
        runs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        runs.truncate(limit);
        Ok(runs)
    }

    fn history_dir(&self) -> PathBuf {
        self.root.join("config").join("librarian-history")
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
pub struct LibrarianProviderStatusStore {
    root: PathBuf,
}

impl LibrarianProviderStatusStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<Option<ProviderCheckResult>> {
        let path = self.status_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }

    pub fn save(&self, status: &ProviderCheckResult) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.status_path(), status)
    }

    fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn status_path(&self) -> PathBuf {
        self.config_dir().join("librarian-provider-status.json")
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

#[async_trait]
pub trait AnswerLibrarianClient: Send + Sync {
    async fn answer(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
        request: &LibrarianRequest,
    ) -> Result<LibrarianAnswer>;

    async fn healthcheck(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
    ) -> Result<ProviderCheckResult>;

    async fn plan_action(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
        request: &ProjectLibrarianRequest,
    ) -> Result<ProjectLibrarianPlan>;
}

#[derive(Clone)]
pub struct HttpLibrarianClient {
    client: Client,
}

impl HttpLibrarianClient {
    pub fn new() -> Self {
        let client = Client::builder().build().unwrap_or_else(|_| Client::new());
        Self { client }
    }
}

impl Default for HttpLibrarianClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AnswerLibrarianClient for HttpLibrarianClient {
    async fn answer(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
        request: &LibrarianRequest,
    ) -> Result<LibrarianAnswer> {
        request.validate()?;
        if !endpoint.is_configured() {
            return Err(LoreError::Validation(
                "answer librarian endpoint is not configured".into(),
            ));
        }

        let system = "You are Lore Answer Librarian. You are read-only. You have access to exactly one Lore project and only the project context provided in this request. Answer only from that context. If the context is insufficient, say so plainly. Do not claim to run commands, browse the web, inspect anything outside the provided Lore blocks, or take actions.";
        let user_msg = build_prompt(request);
        let body = build_provider_request_body(endpoint, system, &user_msg, 0.1);
        let url = build_provider_url(endpoint);
        let http = add_provider_auth(self.client.post(&url).json(&body), endpoint);

        let response = http
            .timeout(Duration::from_secs(timeout_secs))
            .send()
            .await
            .map_err(|err| LoreError::ExternalService(err.to_string()))?;
        let status = response.status();
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|err| LoreError::ExternalService(err.to_string()))?;
        if !status.is_success() {
            let detail = extract_provider_error(&value);
            return Err(LoreError::ExternalService(detail));
        }

        let answer = extract_provider_response_text(endpoint, &value)
            .ok_or_else(|| {
                LoreError::ExternalService("provider response did not contain answer text".into())
            })?;
        let answer = answer.trim();
        if answer.is_empty() {
            return Err(LoreError::ExternalService(
                "provider response did not contain answer text".into(),
            ));
        }

        Ok(LibrarianAnswer {
            answer: clamp_answer(answer),
        })
    }

    async fn healthcheck(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
    ) -> Result<ProviderCheckResult> {
        if !endpoint.is_configured() {
            return Err(LoreError::Validation(
                "answer librarian endpoint is not configured".into(),
            ));
        }
        let body = build_provider_request_body(
            endpoint,
            "Reply with the single word OK.",
            "Connectivity check",
            0.0,
        );
        let url = build_provider_url(endpoint);
        let http = add_provider_auth(self.client.post(&url).json(&body), endpoint);
        let response = http
            .timeout(Duration::from_secs(timeout_secs))
            .send()
            .await
            .map_err(|err| LoreError::ExternalService(err.to_string()))?;
        let status = response.status();
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|err| LoreError::ExternalService(err.to_string()))?;
        if !status.is_success() {
            let detail = extract_provider_error(&value);
            return Ok(ProviderCheckResult {
                ok: false,
                detail,
                checked_at: OffsetDateTime::now_utc(),
            });
        }
        Ok(ProviderCheckResult {
            ok: true,
            detail: "provider connectivity check succeeded".into(),
            checked_at: OffsetDateTime::now_utc(),
        })
    }

    async fn plan_action(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
        request: &ProjectLibrarianRequest,
    ) -> Result<ProjectLibrarianPlan> {
        request.validate()?;
        if !endpoint.is_configured() {
            return Err(LoreError::Validation(
                "project librarian endpoint is not configured".into(),
            ));
        }

        let system = "You are Lore Project Librarian. You operate on exactly one Lore project. You have no shell, no web, no access outside the provided project blocks, and no admin powers. Return only valid JSON with a short summary and a list of up to 5 Lore block operations. Allowed operation types are create_block, update_block, move_block, and delete_block. Use only block ids from the provided context. If no safe project-local action should be taken, return an empty operations array.";
        let user_msg = build_action_prompt(request);
        let body = build_provider_request_body(endpoint, system, &user_msg, 0.1);
        let url = build_provider_url(endpoint);
        let http = add_provider_auth(self.client.post(&url).json(&body), endpoint);

        let response = http
            .timeout(Duration::from_secs(timeout_secs))
            .send()
            .await
            .map_err(|err| LoreError::ExternalService(err.to_string()))?;
        let status = response.status();
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|err| LoreError::ExternalService(err.to_string()))?;
        if !status.is_success() {
            let detail = extract_provider_error(&value);
            return Err(LoreError::ExternalService(detail));
        }
        let content = extract_provider_response_text(endpoint, &value)
            .ok_or_else(|| {
                LoreError::ExternalService(
                    "provider response did not contain project action plan text".into(),
                )
            })?;
        let content = content.trim();
        if content.is_empty() {
            return Err(LoreError::ExternalService(
                "provider response did not contain project action plan text".into(),
            ));
        }
        parse_action_plan(content)
    }
}

fn build_provider_request_body(
    endpoint: &Endpoint,
    system_prompt: &str,
    user_message: &str,
    temperature: f32,
) -> serde_json::Value {
    match endpoint.kind {
        EndpointKind::OpenAi => json!({
            "model": endpoint.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]
        }),
        EndpointKind::Anthropic => json!({
            "model": endpoint.model,
            "max_tokens": 8192,
            "temperature": temperature,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_message}
            ]
        }),
        EndpointKind::Gemini => json!({
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_message}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": 8192
            }
        }),
    }
}

fn build_provider_url(endpoint: &Endpoint) -> String {
    match endpoint.kind {
        EndpointKind::Gemini => {
            let base = endpoint.url.trim_end_matches('/');
            let url = format!(
                "{base}/v1beta/models/{}:generateContent",
                endpoint.model
            );
            if let Some(ref api_key) = endpoint.api_key {
                format!("{url}?key={api_key}")
            } else {
                url
            }
        }
        _ => endpoint.url.clone(),
    }
}

fn add_provider_auth(
    mut req: reqwest::RequestBuilder,
    endpoint: &Endpoint,
) -> reqwest::RequestBuilder {
    match endpoint.kind {
        EndpointKind::OpenAi => {
            if let Some(ref api_key) = endpoint.api_key {
                req = req.bearer_auth(api_key);
            }
        }
        EndpointKind::Anthropic => {
            if let Some(ref api_key) = endpoint.api_key {
                req = req.header("x-api-key", api_key);
            }
            req = req.header("anthropic-version", "2023-06-01");
        }
        EndpointKind::Gemini => {}
    }
    req
}

fn extract_provider_response_text(
    endpoint: &Endpoint,
    value: &serde_json::Value,
) -> Option<String> {
    match endpoint.kind {
        EndpointKind::OpenAi => value
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|c| c.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|msg| msg.get("content"))
            .and_then(extract_content_text)
            .map(|s| s.to_string()),
        EndpointKind::Anthropic => value
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|c| c.first())
            .and_then(|part| part.get("text"))
            .and_then(|t| t.as_str())
            .map(|s| s.to_string()),
        EndpointKind::Gemini => value
            .get("candidates")
            .and_then(|c| c.as_array())
            .and_then(|c| c.first())
            .and_then(|candidate| candidate.get("content"))
            .and_then(|content| content.get("parts"))
            .and_then(|parts| parts.as_array())
            .and_then(|parts| parts.first())
            .and_then(|part| part.get("text"))
            .and_then(|t| t.as_str())
            .map(|s| s.to_string()),
    }
}

fn extract_provider_error(value: &serde_json::Value) -> String {
    value
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("provider request failed")
        .to_string()
}

fn extract_content_text(value: &serde_json::Value) -> Option<&str> {
    if let Some(text) = value.as_str() {
        return Some(text);
    }
    let parts = value.as_array()?;
    for part in parts {
        if let Some(text) = part.get("text").and_then(|value| value.as_str()) {
            return Some(text);
        }
    }
    None
}

pub fn build_prompt(request: &LibrarianRequest) -> String {
    let mut prompt = format!(
        "Project: {}\nQuestion: {}\n\nUse only the Lore blocks below.\n",
        request.project.as_str(),
        request.question.trim()
    );
    if request.context_blocks.is_empty() {
        prompt.push_str("\nNo blocks were available for this project.\n");
        return prompt;
    }

    prompt.push_str("\nContext blocks:\n");
    for block in &request.context_blocks {
        let block_type = match block.block_type {
            crate::model::BlockType::Markdown => "markdown",
            crate::model::BlockType::Html => "html",
            crate::model::BlockType::Svg => "svg",
            crate::model::BlockType::Image => "image",
        };
        prompt.push_str(&format!(
            "\nBlock {}\nType: {}\nOrder: {}\nAuthor: {}\nContent:\n{}\n",
            block.id.as_str(),
            block_type,
            block.order.as_str(),
            block.author.as_str(),
            truncate_content(&block.content),
        ));
    }
    if prompt.chars().count() > MAX_PROMPT_CHARS {
        truncate_chars(&prompt, MAX_PROMPT_CHARS)
    } else {
        prompt
    }
}

pub fn build_action_prompt(request: &ProjectLibrarianRequest) -> String {
    let mut prompt = format!(
        "Project: {}\nInstruction: {}\n\nUse only this project context.\nReturn JSON with this shape:\n{{\"summary\":\"...\",\"operations\":[...]}}\n\nOperation examples:\n{{\"type\":\"create_block\",\"block_type\":\"markdown\",\"content\":\"text\",\"after_block_id\":null}}\n{{\"type\":\"update_block\",\"block_id\":\"...\",\"block_type\":\"markdown\",\"content\":\"new text\",\"after_block_id\":null}}\n{{\"type\":\"move_block\",\"block_id\":\"...\",\"after_block_id\":\"...\"}}\n{{\"type\":\"delete_block\",\"block_id\":\"...\"}}\n",
        request.project.as_str(),
        request.instruction.trim()
    );
    if request.context_blocks.is_empty() {
        prompt.push_str("\nNo blocks were available for this project.\n");
        return prompt;
    }
    prompt.push_str("\nContext blocks:\n");
    for block in &request.context_blocks {
        let block_type = match block.block_type {
            BlockType::Markdown => "markdown",
            BlockType::Html => "html",
            BlockType::Svg => "svg",
            BlockType::Image => "image",
        };
        prompt.push_str(&format!(
            "\nBlock {}\nType: {}\nOrder: {}\nAuthor: {}\nContent:\n{}\n",
            block.id.as_str(),
            block_type,
            block.order.as_str(),
            block.author.as_str(),
            truncate_content(&block.content),
        ));
    }
    if prompt.chars().count() > MAX_PROMPT_CHARS {
        truncate_chars(&prompt, MAX_PROMPT_CHARS)
    } else {
        prompt
    }
}

fn truncate_content(content: &str) -> String {
    const MAX_BLOCK_CHARS: usize = 2000;
    let content: String = content.chars().take(MAX_BLOCK_CHARS).collect();
    if content.len() == MAX_BLOCK_CHARS {
        format!("{content}\n[truncated]")
    } else {
        content
    }
}

pub fn clamp_answer(answer: &str) -> String {
    truncate_chars(answer.trim(), MAX_ANSWER_CHARS)
}

pub fn parse_action_plan(content: &str) -> Result<ProjectLibrarianPlan> {
    let content = strip_code_fence(content.trim());
    let plan: ProjectLibrarianPlan = serde_json::from_str(content)
        .map_err(|_| LoreError::Validation("project librarian returned invalid JSON".into()))?;
    if plan.summary.trim().is_empty() {
        return Err(LoreError::Validation(
            "project librarian summary must not be empty".into(),
        ));
    }
    if plan.operations.len() > MAX_PROJECT_ACTION_OPERATIONS {
        return Err(LoreError::Validation(format!(
            "project librarian returned too many operations; maximum is {MAX_PROJECT_ACTION_OPERATIONS}"
        )));
    }
    Ok(ProjectLibrarianPlan {
        summary: clamp_answer(&plan.summary),
        operations: plan.operations,
    })
}

pub fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut truncated = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        truncated.push_str("\n[truncated]");
    }
    truncated
}

fn strip_code_fence(value: &str) -> &str {
    let value = value.trim();
    if let Some(stripped) = value.strip_prefix("```json") {
        return stripped.trim().trim_end_matches("```").trim();
    }
    if let Some(stripped) = value.strip_prefix("```") {
        return stripped.trim().trim_end_matches("```").trim();
    }
    value
}

fn validate_endpoint_url(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_URL_LEN {
        return Err(LoreError::Validation(format!(
            "librarian endpoint url must be 1..={MAX_ENDPOINT_URL_LEN} characters"
        )));
    }
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(LoreError::Validation(
            "librarian endpoint url must start with http:// or https://".into(),
        ));
    }
    Ok(())
}

fn validate_model(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_MODEL_LEN {
        return Err(LoreError::Validation(format!(
            "librarian model must be 1..={MAX_MODEL_LEN} characters"
        )));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(LoreError::Validation(
            "librarian model must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn validate_request_timeout_secs(value: u64) -> Result<()> {
    if !(1..=MAX_PROVIDER_TIMEOUT_SECS).contains(&value) {
        return Err(LoreError::Validation(format!(
            "librarian request timeout must be between 1 and {MAX_PROVIDER_TIMEOUT_SECS} seconds"
        )));
    }
    Ok(())
}

fn validate_max_concurrent_runs(value: usize) -> Result<()> {
    if !(1..=32).contains(&value) {
        return Err(LoreError::Validation(
            "librarian max concurrent runs must be between 1 and 32".into(),
        ));
    }
    Ok(())
}

fn default_request_timeout_secs() -> u64 {
    REQUEST_TIMEOUT_SECS
}

fn default_max_concurrent_runs() -> usize {
    DEFAULT_MAX_CONCURRENT_RUNS
}

fn default_librarian_run_kind() -> LibrarianRunKind {
    LibrarianRunKind::Answer
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
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn endpoint_store_crud() {
        let dir = tempdir().unwrap();
        let store = EndpointStore::new(dir.path());
        assert!(store.list().unwrap().is_empty());

        let ep = store
            .create(
                "Test EP".into(),
                EndpointKind::OpenAi,
                "https://api.example.com/v1/chat/completions".into(),
                "gpt-test".into(),
                Some("secret".into()),
            )
            .unwrap();
        assert_eq!(ep.name, "Test EP");
        assert_eq!(ep.kind, EndpointKind::OpenAi);
        assert_eq!(store.list().unwrap().len(), 1);

        let updated = store
            .update(
                &ep.id,
                "Renamed".into(),
                EndpointKind::Anthropic,
                "https://api.anthropic.com/v1/messages".into(),
                "claude-test".into(),
                ApiKeyUpdate::Preserve,
            )
            .unwrap();
        assert_eq!(updated.name, "Renamed");
        assert_eq!(updated.kind, EndpointKind::Anthropic);
        assert_eq!(updated.api_key.as_deref(), Some("secret"));

        store.delete(&ep.id).unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn librarian_config_with_endpoint_id() {
        let dir = tempdir().unwrap();
        let store = LibrarianConfigStore::new(dir.path());
        let config = store
            .update(
                Some("ep-123".into()),
                REQUEST_TIMEOUT_SECS,
                DEFAULT_MAX_CONCURRENT_RUNS,
                false,
            )
            .unwrap();
        assert_eq!(config.endpoint_id.as_deref(), Some("ep-123"));
        assert!(config.is_configured());
    }

    #[test]
    fn librarian_config_migration_detection() {
        let dir = tempdir().unwrap();
        let store = LibrarianConfigStore::new(dir.path());
        let legacy_config = LibrarianConfig {
            endpoint_id: None,
            endpoint_url: "https://api.example.com/v1/chat/completions".into(),
            model: "gpt-test".into(),
            api_key: Some("secret".into()),
            request_timeout_secs: REQUEST_TIMEOUT_SECS,
            max_concurrent_runs: DEFAULT_MAX_CONCURRENT_RUNS,
            action_requires_approval: false,
            updated_at: OffsetDateTime::now_utc(),
        };
        std::fs::create_dir_all(dir.path().join("config")).unwrap();
        std::fs::write(
            dir.path().join("config/librarian.json"),
            serde_json::to_vec_pretty(&legacy_config).unwrap(),
        )
        .unwrap();
        let config = store.load().unwrap();
        assert!(config.needs_migration());
        assert!(!config.is_configured());
    }
}
