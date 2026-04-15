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
use tokio::sync::mpsc;
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

pub fn infer_kind_from_url(url: &str) -> EndpointKind {
    let lower = url.to_lowercase();
    if lower.contains("anthropic.com") {
        EndpointKind::Anthropic
    } else if lower.contains("googleapis.com") || lower.contains("generativelanguage") {
        EndpointKind::Gemini
    } else {
        EndpointKind::OpenAi
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

    async fn answer_raw(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
        system: &str,
        user_msg: &str,
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

async fn send_librarian_llm_request(
    client: &Client,
    endpoint: &Endpoint,
    timeout_secs: u64,
    system: &str,
    user_msg: &str,
) -> Result<LibrarianAnswer> {
    if !endpoint.is_configured() {
        return Err(LoreError::Validation(
            "answer librarian endpoint is not configured".into(),
        ));
    }
    let body = build_provider_request_body(endpoint, system, user_msg, 0.1);
    let url = build_provider_url(endpoint);
    let http = add_provider_auth(client.post(&url).json(&body), endpoint);
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

#[async_trait]
impl AnswerLibrarianClient for HttpLibrarianClient {
    async fn answer(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
        request: &LibrarianRequest,
    ) -> Result<LibrarianAnswer> {
        request.validate()?;
        let system = "You are Lore Answer Librarian. You are read-only. You have access to exactly one Lore project and only the project context provided in this request. Answer only from that context. If the context is insufficient, say so plainly. Do not claim to run commands, browse the web, inspect anything outside the provided Lore blocks, or take actions.";
        let user_msg = build_prompt(request);
        send_librarian_llm_request(&self.client, endpoint, timeout_secs, system, &user_msg).await
    }

    async fn answer_raw(
        &self,
        endpoint: &Endpoint,
        timeout_secs: u64,
        system: &str,
        user_msg: &str,
    ) -> Result<LibrarianAnswer> {
        send_librarian_llm_request(&self.client, endpoint, timeout_secs, system, user_msg).await
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

pub async fn list_provider_models(
    url: &str,
    api_key: Option<&str>,
    timeout_secs: u64,
) -> Result<Vec<String>> {
    let kind = infer_kind_from_url(url);
    let client = Client::builder().build().unwrap_or_else(|_| Client::new());
    let base = url.trim_end_matches('/');

    let req = match kind {
        EndpointKind::Anthropic => {
            let murl = if let Some(idx) = base.find("/v1/") {
                format!("{}/v1/models", &base[..idx])
            } else {
                format!("{}/v1/models", base)
            };
            let mut r = client.get(&murl);
            if let Some(key) = api_key {
                r = r.header("x-api-key", key);
            }
            r.header("anthropic-version", "2023-06-01")
        }
        EndpointKind::OpenAi => {
            let murl = if let Some(idx) = base.find("/v1/") {
                format!("{}/v1/models", &base[..idx])
            } else {
                format!("{}/v1/models", base)
            };
            let mut r = client.get(&murl);
            if let Some(key) = api_key {
                r = r.bearer_auth(key);
            }
            r
        }
        EndpointKind::Gemini => {
            let base_clean = base
                .split("/v1beta")
                .next()
                .unwrap_or(base)
                .split("/v1")
                .next()
                .unwrap_or(base);
            let murl = if let Some(key) = api_key {
                format!("{}/v1beta/models?key={}", base_clean, key)
            } else {
                format!("{}/v1beta/models", base_clean)
            };
            client.get(&murl)
        }
    };

    let response = req
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
        .map_err(|e| LoreError::ExternalService(format!("models request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(LoreError::ExternalService(format!(
            "models endpoint returned {}",
            response.status()
        )));
    }

    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LoreError::ExternalService(format!("invalid models response: {e}")))?;

    let mut models = Vec::new();
    match kind {
        EndpointKind::Anthropic | EndpointKind::OpenAi => {
            if let Some(data) = value.get("data").and_then(|d| d.as_array()) {
                for item in data {
                    if let Some(id) = item.get("id").and_then(|i| i.as_str()) {
                        models.push(id.to_string());
                    }
                }
            }
        }
        EndpointKind::Gemini => {
            if let Some(list) = value.get("models").and_then(|m| m.as_array()) {
                for item in list {
                    if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                        let model_name = name.strip_prefix("models/").unwrap_or(name);
                        let methods = item
                            .get("supportedGenerationMethods")
                            .and_then(|m| m.as_array());
                        let supports_generate = methods
                            .map(|arr| {
                                arr.iter()
                                    .any(|v| v.as_str() == Some("generateContent"))
                            })
                            .unwrap_or(true);
                        if supports_generate {
                            models.push(model_name.to_string());
                        }
                    }
                }
            }
        }
    }

    models.sort();
    Ok(models)
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

pub fn extract_provider_error(value: &serde_json::Value) -> String {
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

pub fn build_prompt_multi_project(
    projects_context: &[(ProjectName, Vec<Block>)],
    question: &str,
) -> String {
    let project_names: Vec<&str> = projects_context.iter().map(|(p, _)| p.as_str()).collect();
    let mut prompt = format!(
        "Projects: {}\nQuestion: {}\n\nUse only the Lore blocks below. Reference project names where relevant.\n",
        project_names.join(", "),
        question.trim(),
    );
    let total_blocks: usize = projects_context.iter().map(|(_, blocks)| blocks.len()).sum();
    if total_blocks == 0 {
        prompt.push_str("\nNo blocks were available.\n");
        return prompt;
    }
    prompt.push_str("\nContext blocks:\n");
    for (project, blocks) in projects_context {
        for block in blocks {
            let block_type = match block.block_type {
                BlockType::Markdown => "markdown",
                BlockType::Html => "html",
                BlockType::Svg => "svg",
                BlockType::Image => "image",
            };
            prompt.push_str(&format!(
                "\nProject: {}\nBlock {}\nType: {}\nOrder: {}\nAuthor: {}\nContent:\n{}\n",
                project.as_str(),
                block.id.as_str(),
                block_type,
                block.order.as_str(),
                block.author.as_str(),
                truncate_content(&block.content),
            ));
        }
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

// --- Chat completions proxy ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChatMessage {
    pub role: String,
    #[serde(default)]
    pub content: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_calls: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProxyChatRequest {
    pub messages: Vec<ProxyChatMessage>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(default)]
    pub tools: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<u64>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub stop: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub enum ProxyStreamChunk {
    Delta { content: Option<String>, tool_calls: Option<Vec<serde_json::Value>>, finish_reason: Option<String> },
    Done,
    Error(String),
}

fn translate_messages_to_anthropic(
    messages: &[ProxyChatMessage],
    tools: &Option<Vec<serde_json::Value>>,
) -> (Option<String>, Vec<serde_json::Value>, Option<Vec<serde_json::Value>>) {
    let mut system_prompt = None;
    let mut out = Vec::new();
    for msg in messages {
        if msg.role == "system" {
            if let Some(ref c) = msg.content {
                let text = content_to_text(c);
                system_prompt = Some(match system_prompt {
                    Some(existing) => format!("{existing}\n{text}"),
                    None => text,
                });
            }
            continue;
        }
        if msg.role == "tool" {
            out.push(json!({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": msg.tool_call_id.as_deref().unwrap_or(""),
                    "content": content_to_text(&msg.content.clone().unwrap_or(json!(""))),
                }]
            }));
            continue;
        }
        if msg.role == "assistant" {
            let mut content_blocks = Vec::new();
            if let Some(ref c) = msg.content {
                let text = content_to_text(c);
                if !text.is_empty() {
                    content_blocks.push(json!({"type": "text", "text": text}));
                }
            }
            if let Some(ref tcs) = msg.tool_calls {
                for tc in tcs {
                    let input: serde_json::Value = tc.get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(|a| a.as_str())
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or(json!({}));
                    content_blocks.push(json!({
                        "type": "tool_use",
                        "id": tc.get("id").and_then(|i| i.as_str()).unwrap_or(""),
                        "name": tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or(""),
                        "input": input,
                    }));
                }
            }
            if content_blocks.is_empty() {
                content_blocks.push(json!({"type": "text", "text": ""}));
            }
            out.push(json!({"role": "assistant", "content": content_blocks}));
            continue;
        }
        // user
        out.push(json!({"role": "user", "content": content_to_text(&msg.content.clone().unwrap_or(json!("")))}));
    }

    let translated_tools = tools.as_ref().map(|tl| {
        tl.iter().map(|t| {
            let func = t.get("function").cloned().unwrap_or(json!({}));
            json!({
                "name": func.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                "description": func.get("description").and_then(|d| d.as_str()).unwrap_or(""),
                "input_schema": func.get("parameters").cloned().unwrap_or(json!({"type": "object"})),
            })
        }).collect()
    });
    (system_prompt, out, translated_tools)
}

fn translate_messages_to_gemini(
    messages: &[ProxyChatMessage],
    tools: &Option<Vec<serde_json::Value>>,
) -> (Option<serde_json::Value>, Vec<serde_json::Value>, Option<serde_json::Value>) {
    let mut system_instruction = None;
    let mut contents = Vec::new();
    for msg in messages {
        if msg.role == "system" {
            if let Some(ref c) = msg.content {
                system_instruction = Some(json!({"parts": [{"text": content_to_text(c)}]}));
            }
            continue;
        }
        if msg.role == "tool" {
            contents.push(json!({
                "role": "user",
                "parts": [{
                    "functionResponse": {
                        "name": msg.name.as_deref().unwrap_or("tool"),
                        "response": {"result": content_to_text(&msg.content.clone().unwrap_or(json!("")))}
                    }
                }]
            }));
            continue;
        }
        if msg.role == "assistant" {
            let mut parts = Vec::new();
            if let Some(ref c) = msg.content {
                let text = content_to_text(c);
                if !text.is_empty() {
                    parts.push(json!({"text": text}));
                }
            }
            if let Some(ref tcs) = msg.tool_calls {
                for tc in tcs {
                    let args: serde_json::Value = tc.get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(|a| a.as_str())
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or(json!({}));
                    parts.push(json!({
                        "functionCall": {
                            "name": tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or(""),
                            "args": args,
                        }
                    }));
                }
            }
            if parts.is_empty() {
                parts.push(json!({"text": ""}));
            }
            contents.push(json!({"role": "model", "parts": parts}));
            continue;
        }
        // user
        contents.push(json!({
            "role": "user",
            "parts": [{"text": content_to_text(&msg.content.clone().unwrap_or(json!("")))}]
        }));
    }

    let translated_tools = tools.as_ref().map(|tl| {
        let decls: Vec<serde_json::Value> = tl.iter().map(|t| {
            let func = t.get("function").cloned().unwrap_or(json!({}));
            json!({
                "name": func.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                "description": func.get("description").and_then(|d| d.as_str()).unwrap_or(""),
                "parameters": func.get("parameters").cloned().unwrap_or(json!({"type": "object"})),
            })
        }).collect();
        json!([{"functionDeclarations": decls}])
    });
    (system_instruction, contents, translated_tools)
}

fn content_to_text(value: &serde_json::Value) -> String {
    if let Some(s) = value.as_str() {
        return s.to_string();
    }
    if let Some(arr) = value.as_array() {
        let mut out = String::new();
        for part in arr {
            if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                    out.push_str(t);
                }
            }
        }
        return out;
    }
    value.to_string()
}

pub fn build_proxy_request(
    endpoint: &Endpoint,
    req: &ProxyChatRequest,
    streaming: bool,
) -> (String, serde_json::Value) {
    let model = req.model.as_deref().unwrap_or(&endpoint.model);
    let max_tokens = req.max_tokens.unwrap_or(8192);

    match endpoint.kind {
        EndpointKind::OpenAi => {
            let mut body = json!({
                "model": model,
                "messages": req.messages,
                "stream": streaming,
            });
            if let Some(t) = req.temperature { body["temperature"] = json!(t); }
            if let Some(p) = req.top_p { body["top_p"] = json!(p); }
            if let Some(ref s) = req.stop { body["stop"] = s.clone(); }
            body["max_tokens"] = json!(max_tokens);
            if let Some(ref tools) = req.tools {
                if !tools.is_empty() {
                    body["tools"] = json!(tools);
                }
            }
            (endpoint.url.clone(), body)
        }
        EndpointKind::Anthropic => {
            let (system, messages, tools) = translate_messages_to_anthropic(&req.messages, &req.tools);
            let mut body = json!({
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "stream": streaming,
            });
            if let Some(sys) = system { body["system"] = json!(sys); }
            if let Some(t) = req.temperature { body["temperature"] = json!(t); }
            if let Some(p) = req.top_p { body["top_p"] = json!(p); }
            if let Some(ref s) = req.stop { body["stop_sequences"] = s.clone(); }
            if let Some(tl) = tools {
                if !tl.is_empty() {
                    body["tools"] = json!(tl);
                }
            }
            let base = endpoint.url.trim_end_matches('/');
            let url = if base.ends_with("/messages") {
                base.to_string()
            } else if base.contains("/v1") {
                format!("{}/messages", base.split("/v1").next().unwrap_or(base).to_string() + "/v1")
            } else {
                format!("{base}/v1/messages")
            };
            (url, body)
        }
        EndpointKind::Gemini => {
            let (system_instruction, contents, tools) = translate_messages_to_gemini(&req.messages, &req.tools);
            let mut body = json!({
                "contents": contents,
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                },
            });
            if let Some(si) = system_instruction {
                body["system_instruction"] = si;
            }
            if let Some(t) = req.temperature { body["generationConfig"]["temperature"] = json!(t); }
            if let Some(p) = req.top_p { body["generationConfig"]["topP"] = json!(p); }
            if let Some(ref s) = req.stop { body["generationConfig"]["stopSequences"] = s.clone(); }
            if let Some(tl) = tools {
                body["tools"] = tl;
            }
            let base = endpoint.url.trim_end_matches('/');
            let base_clean = base.split("/v1beta").next().unwrap_or(base).split("/v1").next().unwrap_or(base);
            let action = if streaming { "streamGenerateContent?alt=sse" } else { "generateContent" };
            let url = if let Some(ref key) = endpoint.api_key {
                format!("{base_clean}/v1beta/models/{model}:{action}&key={key}")
            } else {
                format!("{base_clean}/v1beta/models/{model}:{action}")
            };
            (url, body)
        }
    }
}

pub fn add_proxy_auth(
    req: reqwest::RequestBuilder,
    endpoint: &Endpoint,
) -> reqwest::RequestBuilder {
    add_provider_auth(req, endpoint)
}

pub async fn proxy_streaming(
    client: &Client,
    endpoint: &Endpoint,
    url: &str,
    body: &serde_json::Value,
    timeout_secs: u64,
    tx: mpsc::Sender<ProxyStreamChunk>,
) {
    let http = add_provider_auth(client.post(url).json(body), endpoint);
    let response = match http.timeout(Duration::from_secs(timeout_secs)).send().await {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(ProxyStreamChunk::Error(e.to_string())).await;
            return;
        }
    };
    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .map(|v| extract_provider_error(&v))
            .unwrap_or_else(|| format!("provider returned {status}"));
        let _ = tx.send(ProxyStreamChunk::Error(detail)).await;
        return;
    }

    match endpoint.kind {
        EndpointKind::OpenAi => stream_openai(response, tx).await,
        EndpointKind::Anthropic => stream_anthropic(response, tx).await,
        EndpointKind::Gemini => stream_gemini(response, tx).await,
    }
}

pub async fn proxy_non_streaming(
    client: &Client,
    endpoint: &Endpoint,
    url: &str,
    body: &serde_json::Value,
    timeout_secs: u64,
) -> Result<serde_json::Value> {
    let (status, value) = proxy_non_streaming_raw(client, endpoint, url, body, timeout_secs).await?;
    if !status.is_success() {
        return Err(LoreError::ExternalService(extract_provider_error(&value)));
    }
    Ok(value)
}

pub async fn proxy_non_streaming_raw(
    client: &Client,
    endpoint: &Endpoint,
    url: &str,
    body: &serde_json::Value,
    timeout_secs: u64,
) -> Result<(reqwest::StatusCode, serde_json::Value)> {
    let http = add_provider_auth(client.post(url).json(body), endpoint);
    let response = http.timeout(Duration::from_secs(timeout_secs)).send().await
        .map_err(|e| LoreError::ExternalService(e.to_string()))?;
    let status = response.status();
    let value: serde_json::Value = response.json().await
        .map_err(|e| LoreError::ExternalService(e.to_string()))?;
    let translated = if status.is_success() {
        match endpoint.kind {
            EndpointKind::OpenAi => value,
            EndpointKind::Anthropic => anthropic_response_to_openai(&value),
            EndpointKind::Gemini => gemini_response_to_openai(&value, &endpoint.model),
        }
    } else {
        value
    };
    Ok((status, translated))
}

fn anthropic_response_to_openai(value: &serde_json::Value) -> serde_json::Value {
    let mut content_text = String::new();
    let mut tool_calls = Vec::new();
    let mut tc_idx = 0;
    if let Some(blocks) = value.get("content").and_then(|c| c.as_array()) {
        for block in blocks {
            match block.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                        content_text.push_str(t);
                    }
                }
                Some("tool_use") => {
                    tool_calls.push(json!({
                        "index": tc_idx,
                        "id": block.get("id").and_then(|i| i.as_str()).unwrap_or(""),
                        "type": "function",
                        "function": {
                            "name": block.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                            "arguments": block.get("input").map(|i| i.to_string()).unwrap_or_else(|| "{}".into()),
                        }
                    }));
                    tc_idx += 1;
                }
                _ => {}
            }
        }
    }
    let finish = value.get("stop_reason").and_then(|s| s.as_str()).map(|s| match s {
        "end_turn" => "stop",
        "tool_use" => "tool_calls",
        "max_tokens" => "length",
        other => other,
    }).unwrap_or("stop");

    let mut msg = json!({"role": "assistant"});
    if !content_text.is_empty() { msg["content"] = json!(content_text); }
    if !tool_calls.is_empty() { msg["tool_calls"] = json!(tool_calls); }
    json!({
        "id": value.get("id").and_then(|i| i.as_str()).unwrap_or(""),
        "object": "chat.completion",
        "model": value.get("model").and_then(|m| m.as_str()).unwrap_or(""),
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": value.get("usage").cloned().unwrap_or(json!({})),
    })
}

fn gemini_response_to_openai(value: &serde_json::Value, model: &str) -> serde_json::Value {
    let candidate = value.get("candidates").and_then(|c| c.as_array()).and_then(|c| c.first());
    let mut content_text = String::new();
    let mut tool_calls = Vec::new();
    let mut tc_idx = 0;
    if let Some(parts) = candidate.and_then(|c| c.get("content")).and_then(|c| c.get("parts")).and_then(|p| p.as_array()) {
        for part in parts {
            if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                content_text.push_str(t);
            }
            if let Some(fc) = part.get("functionCall") {
                tool_calls.push(json!({
                    "index": tc_idx,
                    "id": format!("call_{}", Uuid::new_v4()),
                    "type": "function",
                    "function": {
                        "name": fc.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                        "arguments": fc.get("args").map(|a| a.to_string()).unwrap_or_else(|| "{}".into()),
                    }
                }));
                tc_idx += 1;
            }
        }
    }
    let finish = if !tool_calls.is_empty() { "tool_calls" }
        else if candidate.and_then(|c| c.get("finishReason")).and_then(|f| f.as_str()) == Some("MAX_TOKENS") { "length" }
        else { "stop" };

    let mut msg = json!({"role": "assistant"});
    if !content_text.is_empty() { msg["content"] = json!(content_text); }
    if !tool_calls.is_empty() { msg["tool_calls"] = json!(tool_calls); }
    json!({
        "id": format!("chatcmpl-{}", Uuid::new_v4()),
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
    })
}

// --- SSE stream parsers ---

async fn stream_openai(response: reqwest::Response, tx: mpsc::Sender<ProxyStreamChunk>) {
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => { let _ = tx.send(ProxyStreamChunk::Error(e.to_string())).await; return; }
        };
        buf.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(pos) = buf.find("\n\n") {
            let event_block = buf[..pos].to_string();
            buf = buf[pos + 2..].to_string();
            for line in event_block.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    if data.trim() == "[DONE]" {
                        let _ = tx.send(ProxyStreamChunk::Done).await;
                        return;
                    }
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
                        if let Some(choice) = v.get("choices").and_then(|c| c.as_array()).and_then(|c| c.first()) {
                            let delta = choice.get("delta").cloned().unwrap_or(json!({}));
                            let _ = tx.send(ProxyStreamChunk::Delta {
                                content: delta.get("content").and_then(|c| c.as_str()).map(|s| s.to_string()),
                                tool_calls: delta.get("tool_calls").and_then(|t| t.as_array()).cloned(),
                                finish_reason: choice.get("finish_reason").and_then(|f| f.as_str()).map(|s| s.to_string()),
                            }).await;
                        }
                    }
                }
            }
        }
    }
    let _ = tx.send(ProxyStreamChunk::Done).await;
}

async fn stream_anthropic(response: reqwest::Response, tx: mpsc::Sender<ProxyStreamChunk>) {
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut buf = String::new();
    let mut current_tool_id = String::new();
    let mut current_tool_name = String::new();
    let mut current_tool_args = String::new();
    let mut tool_index: i64 = -1;

    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => { let _ = tx.send(ProxyStreamChunk::Error(e.to_string())).await; return; }
        };
        buf.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(pos) = buf.find("\n\n") {
            let event_block = buf[..pos].to_string();
            buf = buf[pos + 2..].to_string();

            let mut event_type = "";
            let mut data_str = "";
            for line in event_block.lines() {
                if let Some(et) = line.strip_prefix("event: ") {
                    event_type = et.trim();
                } else if let Some(d) = line.strip_prefix("data: ") {
                    data_str = d;
                }
            }
            if data_str.is_empty() { continue; }
            let data: serde_json::Value = match serde_json::from_str(data_str) {
                Ok(v) => v,
                Err(_) => continue,
            };

            match event_type {
                "content_block_delta" => {
                    if let Some(delta) = data.get("delta") {
                        match delta.get("type").and_then(|t| t.as_str()) {
                            Some("text_delta") => {
                                let _ = tx.send(ProxyStreamChunk::Delta {
                                    content: delta.get("text").and_then(|t| t.as_str()).map(|s| s.to_string()),
                                    tool_calls: None,
                                    finish_reason: None,
                                }).await;
                            }
                            Some("input_json_delta") => {
                                if let Some(partial) = delta.get("partial_json").and_then(|p| p.as_str()) {
                                    current_tool_args.push_str(partial);
                                    let _ = tx.send(ProxyStreamChunk::Delta {
                                        content: None,
                                        tool_calls: Some(vec![json!({
                                            "index": tool_index,
                                            "function": {"arguments": partial}
                                        })]),
                                        finish_reason: None,
                                    }).await;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "content_block_start" => {
                    if let Some(cb) = data.get("content_block") {
                        if cb.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                            tool_index += 1;
                            current_tool_id = cb.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                            current_tool_name = cb.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                            current_tool_args.clear();
                            let _ = tx.send(ProxyStreamChunk::Delta {
                                content: None,
                                tool_calls: Some(vec![json!({
                                    "index": tool_index,
                                    "id": current_tool_id,
                                    "type": "function",
                                    "function": {"name": current_tool_name, "arguments": ""}
                                })]),
                                finish_reason: None,
                            }).await;
                        }
                    }
                }
                "message_delta" => {
                    let reason = data.get("delta").and_then(|d| d.get("stop_reason")).and_then(|s| s.as_str());
                    let finish = reason.map(|r| match r {
                        "end_turn" => "stop".to_string(),
                        "tool_use" => "tool_calls".to_string(),
                        "max_tokens" => "length".to_string(),
                        other => other.to_string(),
                    });
                    if finish.is_some() {
                        let _ = tx.send(ProxyStreamChunk::Delta {
                            content: None,
                            tool_calls: None,
                            finish_reason: finish,
                        }).await;
                    }
                }
                "message_stop" => {
                    let _ = tx.send(ProxyStreamChunk::Done).await;
                    return;
                }
                "error" => {
                    let msg = data.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).unwrap_or("stream error");
                    let _ = tx.send(ProxyStreamChunk::Error(msg.to_string())).await;
                    return;
                }
                _ => {}
            }
        }
    }
    let _ = tx.send(ProxyStreamChunk::Done).await;
}

async fn stream_gemini(response: reqwest::Response, tx: mpsc::Sender<ProxyStreamChunk>) {
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut buf = String::new();
    let mut tool_idx_offset: usize = 0;

    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => { let _ = tx.send(ProxyStreamChunk::Error(e.to_string())).await; return; }
        };
        buf.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(pos) = buf.find("\n\n") {
            let event_block = buf[..pos].to_string();
            buf = buf[pos + 2..].to_string();
            for line in event_block.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    let v: serde_json::Value = match serde_json::from_str(data) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let candidate = v.get("candidates").and_then(|c| c.as_array()).and_then(|c| c.first());
                    if let Some(parts) = candidate.and_then(|c| c.get("content")).and_then(|c| c.get("parts")).and_then(|p| p.as_array()) {
                        for part in parts {
                            if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                                let _ = tx.send(ProxyStreamChunk::Delta {
                                    content: Some(t.to_string()),
                                    tool_calls: None,
                                    finish_reason: None,
                                }).await;
                            }
                            if let Some(fc) = part.get("functionCall") {
                                let _ = tx.send(ProxyStreamChunk::Delta {
                                    content: None,
                                    tool_calls: Some(vec![json!({
                                        "index": tool_idx_offset,
                                        "id": format!("call_{}", Uuid::new_v4()),
                                        "type": "function",
                                        "function": {
                                            "name": fc.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                                            "arguments": fc.get("args").map(|a| a.to_string()).unwrap_or_else(|| "{}".into()),
                                        }
                                    })]),
                                    finish_reason: None,
                                }).await;
                                tool_idx_offset += 1;
                            }
                        }
                    }
                    let finish = candidate.and_then(|c| c.get("finishReason")).and_then(|f| f.as_str());
                    if let Some(reason) = finish {
                        let fr = match reason {
                            "STOP" => "stop",
                            "MAX_TOKENS" => "length",
                            _ => if tool_idx_offset > 0 { "tool_calls" } else { "stop" },
                        };
                        let _ = tx.send(ProxyStreamChunk::Delta {
                            content: None,
                            tool_calls: None,
                            finish_reason: Some(fr.to_string()),
                        }).await;
                    }
                }
            }
        }
    }
    let _ = tx.send(ProxyStreamChunk::Done).await;
}

pub fn format_openai_stream_chunk(
    chunk: &ProxyStreamChunk,
    model: &str,
    completion_id: &str,
) -> Option<String> {
    match chunk {
        ProxyStreamChunk::Delta { content, tool_calls, finish_reason } => {
            let mut delta = json!({});
            if let Some(c) = content { delta["content"] = json!(c); }
            if let Some(tc) = tool_calls { delta["tool_calls"] = json!(tc); }
            let mut choice = json!({"index": 0, "delta": delta});
            if let Some(fr) = finish_reason { choice["finish_reason"] = json!(fr); }
            let obj = json!({
                "id": completion_id,
                "object": "chat.completion.chunk",
                "model": model,
                "choices": [choice],
            });
            Some(format!("data: {}\n\n", obj))
        }
        ProxyStreamChunk::Done => Some("data: [DONE]\n\n".to_string()),
        ProxyStreamChunk::Error(msg) => {
            let obj = json!({"error": {"message": msg, "type": "proxy_error"}});
            Some(format!("data: {}\n\n", obj))
        }
    }
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
