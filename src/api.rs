use crate::audit::{AuditActor, AuditActorKind, AuditStore, StoredAuditEvent};
use crate::auth::{
    AgentBackend, AgentChatStatus, AuthenticatedAgent, AuthenticatedUser, ChatAuditLog,
    ChatConversation, ChatMessage, ChatRole, ChatStore, CreatedAgentToken, LocalAuthStore,
    ManageConfig, NewAgentToken, NewRole, NewSession, NewUser, PinnedChatItem, ProjectGrant,
    ProjectPermission, RoleName, StoredAgentToken, StoredMachine, UserName, hash_agent_token,
};
use crate::config::{
    ColorMode, ExternalAuthSecretUpdate, ExternalAuthStore, ExternalScheme, OidcConfig,
    OidcConfigStore, OidcLoginStateStore, OidcSecretUpdate, OidcUsernameClaim, ServerConfig,
    ServerConfigStore, StoredOidcLoginState, UiTheme,
};
use crate::error::LoreError;
use crate::librarian::{
    AnswerLibrarianClient, ApiKeyUpdate, Endpoint, EndpointKind, EndpointStore,
    HttpLibrarianClient, LibrarianActor, LibrarianActorKind, LibrarianAnswer, LibrarianConfigStore,
    LibrarianHistoryStore, LibrarianProviderStatusStore, LibrarianRequest, LibrarianRunKind,
    LibrarianRunStatus, MAX_CONTEXT_BLOCKS, MAX_PROJECT_ACTION_OPERATIONS, MAX_PROMPT_CHARS,
    PendingLibrarianAction, PendingLibrarianActionStore, ProjectLibrarianOperation,
    ProjectLibrarianRequest, ProviderCheckResult, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECS,
    StoredLibrarianOperation, build_action_prompt, build_prompt, build_prompt_multi_project,
};
use crate::manager::{
    ManagerPromptConfig, ManagerPromptConfigStore, ManagerPromptOverride, ManagerPromptStage,
    describe_manager_delay, extract_manager_delay_prefix,
};
use crate::model::{
    Block, BlockId, BlockType, DocumentId, ImageUpload, KeyFingerprint, NewBlock, OrderKey,
    ProjectName, RESERVED_AGENT_CONTEXT, RESERVED_MAP, RESERVED_OVERVIEW, UpdateBlock,
    reserved_block_display_name,
};
use crate::store::FileBlockStore;
use crate::ui::{
    AgentTokenSummary, ChatAgentSummary, ProjectListEntry, UiAuditEvent, UiDiffLine,
    UiDiffLineKind, UiLibrarianAnswer, UiPendingLibrarianAction, UiProjectVersion,
    UiProjectVersionOperation, UiUserSummary, UserProjectAccess, render_admin_audit_page,
    render_admin_errors_page, render_admin_page, render_agent_guide_page, render_agents_page,
    render_chat_agent_list, render_chat_main_panel, render_chat_page, render_document_page,
    render_login_page, render_project_audit_page, render_project_history_page, render_project_page,
    render_projects_page, render_settings_page, render_setup_page,
};
use crate::updater::{
    AutoUpdateConfig, AutoUpdateConfigStore, AutoUpdateStatus, AutoUpdateStatusStore,
    ReleaseStream, SERVER_RELEASE_CLI_TARGETS, check_for_update, hex_sha256,
    maybe_apply_self_update, sync_release_binaries_to_directory,
};
use crate::versioning::{
    GitExportConfig, GitExportConfigStore, GitExportStatus, GitExportStatusStore,
    GitExportTokenUpdate, ProjectHistoryStore, ProjectVersionActor, ProjectVersionActorKind,
    ProjectVersionOperationType, StoredBlockSnapshot, StoredProjectVersion,
    StoredProjectVersionOperation, run_git_export,
};
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post, put};
use axum::{Form, Json, Router};
use base64::Engine;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreUserInfoClaims,
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use uuid::Uuid;

const API_KEY_HEADER: &str = "x-lore-key";
const MCP_SESSION_HEADER: &str = "mcp-session-id";
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const SESSION_COOKIE: &str = "lore_session";
const LOGIN_RATE_LIMIT_ATTEMPTS: usize = 8;
const LOGIN_RATE_LIMIT_WINDOW_SECS: i64 = 300;
const AGENT_AUTH_RATE_LIMIT_ATTEMPTS: usize = 20;
const AGENT_AUTH_RATE_LIMIT_WINDOW_SECS: i64 = 60;
const GLOBAL_LIBRARIAN_RATE_LIMIT: usize = 30;
const GLOBAL_LIBRARIAN_RATE_LIMIT_WINDOW_SECS: i64 = 60;
const MACHINE_COMMAND_TIMEOUT_SECS: u64 = 15;

fn librarian_chat_agent_name(project: Option<&ProjectName>) -> String {
    match project {
        Some(project) => format!("librarian:{}", project.as_str()),
        None => "librarian".to_string(),
    }
}

fn librarian_history_messages_from_runs(
    runs: &[crate::librarian::StoredLibrarianRun],
) -> Vec<Value> {
    let mut messages: Vec<Value> = Vec::new();
    for run in runs {
        messages.push(json!({
            "role": "user",
            "content": run.question.clone(),
            "timestamp": run.created_at.unix_timestamp(),
        }));
        let content = if let Some(ref answer) = run.answer {
            answer.clone()
        } else if let Some(ref error) = run.error {
            format!("Error: {}", error)
        } else {
            "No response.".to_string()
        };
        let status = format!("{:?}", run.status);
        messages.push(json!({
            "role": "assistant",
            "content": content,
            "timestamp": run.created_at.unix_timestamp(),
            "status": status,
            "run_id": run.id,
            "context_block_count": run.source_block_ids.len(),
        }));
    }
    messages
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineCommand {
    id: String,
    command_type: String,
    params: Value,
}

#[derive(Clone)]
pub struct AppState {
    store: Arc<FileBlockStore>,
    auth: Arc<LocalAuthStore>,
    auth_audit: Arc<AuditStore>,
    config: Arc<ServerConfigStore>,
    external_auth: Arc<ExternalAuthStore>,
    oidc: Arc<OidcConfigStore>,
    oidc_states: Arc<OidcLoginStateStore>,
    endpoint_store: Arc<EndpointStore>,
    librarian_config: Arc<LibrarianConfigStore>,
    librarian_history: Arc<LibrarianHistoryStore>,
    project_history: Arc<ProjectHistoryStore>,
    git_export_config: Arc<GitExportConfigStore>,
    git_export_status: Arc<GitExportStatusStore>,
    pending_librarian_actions: Arc<PendingLibrarianActionStore>,
    librarian_provider_status: Arc<LibrarianProviderStatusStore>,
    auto_update_config: Arc<AutoUpdateConfigStore>,
    auto_update_status: Arc<AutoUpdateStatusStore>,
    manager_prompt_config: Arc<ManagerPromptConfigStore>,
    update_check_cache: Arc<Mutex<Option<(Instant, AutoUpdateStatus)>>>,
    librarian_client: Arc<dyn AnswerLibrarianClient>,
    librarian_rate_limits: Arc<Mutex<HashMap<String, Vec<OffsetDateTime>>>>,
    librarian_inflight_runs: Arc<Mutex<usize>>,
    login_rate_limits: Arc<Mutex<HashMap<String, Vec<OffsetDateTime>>>>,
    agent_auth_rate_limits: Arc<Mutex<Vec<OffsetDateTime>>>,
    global_librarian_rate_limits: Arc<Mutex<Vec<OffsetDateTime>>>,
    mcp_sessions: Arc<Mutex<HashMap<String, McpSessionEntry>>>,
    chat: Arc<ChatStore>,
    chat_audit: Arc<ChatAuditLog>,
    chat_senders: Arc<Mutex<HashMap<String, tokio::sync::broadcast::Sender<ChatEvent>>>>,
    chat_agent_notifiers: Arc<Mutex<HashMap<String, Arc<tokio::sync::Notify>>>>,
    chat_agent_stops: Arc<Mutex<HashSet<String>>>,
    machine_commands: Arc<Mutex<HashMap<String, Vec<MachineCommand>>>>,
    machine_command_results: Arc<Mutex<HashMap<String, Value>>>,
    machine_poll_notifiers: Arc<Mutex<HashMap<String, Arc<tokio::sync::Notify>>>>,
    machine_result_notifiers: Arc<Mutex<HashMap<String, Arc<tokio::sync::Notify>>>>,
    machine_agent_statuses: Arc<Mutex<HashMap<String, Vec<Value>>>>,
    librarian_client_http: reqwest::Client,
    agent_recent_activity: Arc<Mutex<HashMap<String, AgentRecentActivity>>>,
    machine_update_timestamps: Arc<Mutex<HashMap<String, Instant>>>,
    machine_update_signal_state: Arc<Mutex<HashMap<String, bool>>>,
}

#[derive(Debug, Clone)]
struct RecentFileEntry {
    path: String,
    operation: String,
    timestamp: i64,
}

#[derive(Debug, Clone)]
struct RecentCommandEntry {
    command: String,
    timestamp: i64,
}

#[derive(Debug, Clone, Default)]
struct AgentRecentActivity {
    files: Vec<RecentFileEntry>,
    commands: Vec<RecentCommandEntry>,
}

const RECENT_FILES_MAX: usize = 5;
const RECENT_COMMANDS_MAX: usize = 6;

impl AgentRecentActivity {
    fn record_file(&mut self, path: String, operation: String) {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.files.retain(|f| f.path != path);
        self.files.insert(
            0,
            RecentFileEntry {
                path,
                operation,
                timestamp: now,
            },
        );
        self.files.truncate(RECENT_FILES_MAX);
    }

    fn record_command(&mut self, command: String) {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.commands.insert(
            0,
            RecentCommandEntry {
                command,
                timestamp: now,
            },
        );
        self.commands.truncate(RECENT_COMMANDS_MAX);
    }

    fn format_section(&self) -> String {
        let mut parts = Vec::new();
        if !self.files.is_empty() {
            let mut lines = vec!["Recently accessed files (most recent first):".to_string()];
            for f in &self.files {
                let ago = format_ago(f.timestamp);
                lines.push(format!("  {} ({}) ({})", f.path, f.operation, ago));
            }
            parts.push(lines.join("\n"));
        }
        if !self.commands.is_empty() {
            let mut lines = vec!["Recently run commands:".to_string()];
            for c in &self.commands {
                let ago = format_ago(c.timestamp);
                lines.push(format!("  {} ({})", c.command, ago));
            }
            parts.push(lines.join("\n"));
        }
        parts.join("\n\n")
    }
}

fn format_ago(unix_ts: i64) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let diff = now - unix_ts;
    if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

fn parse_tool_use_for_tracking(detail: &str) -> Option<(&str, &str, &str)> {
    let d = detail.trim();
    if let Some(rest) = d.strip_prefix("Read ") {
        Some(("file", rest.trim(), "read"))
    } else if let Some(rest) = d.strip_prefix("Edit ") {
        Some(("file", rest.trim(), "edit"))
    } else if let Some(rest) = d.strip_prefix("Write ") {
        Some(("file", rest.trim(), "write"))
    } else if let Some(rest) = d.strip_prefix("Delete ") {
        Some(("file", rest.trim(), "delete"))
    } else if let Some(rest) = d.strip_prefix("MultiEdit ") {
        Some(("file", rest.trim(), "edit"))
    } else if let Some(rest) = d.strip_prefix("Bash: ") {
        Some(("command", rest.trim(), "bash"))
    } else {
        None
    }
}

fn record_tool_activity(state: &AppState, owner: &str, agent: &str, detail: &str) {
    if let Some((kind, value, op)) = parse_tool_use_for_tracking(detail) {
        let key = format!("{owner}_{agent}");
        let mut map = state.agent_recent_activity.lock().unwrap();
        let activity = map.entry(key).or_default();
        match kind {
            "file" => activity.record_file(value.to_string(), op.to_string()),
            "command" => activity.record_command(value.to_string()),
            _ => {}
        }
    }
}

fn record_api_tool_activity(
    state: &AppState,
    owner: &str,
    agent: &str,
    tool_name: &str,
    args: &Value,
) {
    let get_str = |key: &str| -> &str {
        args.as_object()
            .and_then(|m| m.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    };
    match tool_name {
        "read_block" | "read_blocks_around" => {
            let project = get_str("project");
            let block = get_str("block_id");
            let short = if block.len() > 8 { &block[..8] } else { block };
            let path = if project.is_empty() {
                short.to_string()
            } else {
                format!("{project}/{short}")
            };
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key).or_default().record_file(path, "read".into());
        }
        "create_block" => {
            let project = get_str("project");
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key)
                .or_default()
                .record_file(project.to_string(), "create".into());
        }
        "update_block" => {
            let project = get_str("project");
            let block = get_str("block_id");
            let short = if block.len() > 8 { &block[..8] } else { block };
            let path = if project.is_empty() {
                short.to_string()
            } else {
                format!("{project}/{short}")
            };
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key).or_default().record_file(path, "edit".into());
        }
        "move_block" | "delete_block" | "split_block" => {
            let block = get_str("block_id");
            let short = if block.len() > 8 { &block[..8] } else { block };
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key).or_default().record_file(
                short.to_string(),
                tool_name.strip_suffix("_block").unwrap_or(tool_name).into(),
            );
        }
        "combine_blocks" => {
            let project = get_str("project");
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key)
                .or_default()
                .record_file(project.to_string(), "combine".into());
        }
        "read_document" => {
            let project = get_str("project");
            let doc = get_str("document_id");
            let short = if doc.len() > 8 { &doc[..8] } else { doc };
            let path = if project.is_empty() {
                short.to_string()
            } else {
                format!("{project}/{short}")
            };
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key).or_default().record_file(path, "read".into());
        }
        "write_document" => {
            let project = get_str("project");
            let doc = get_str("document_id");
            let short = if doc.len() > 8 { &doc[..8] } else { doc };
            let path = if project.is_empty() {
                short.to_string()
            } else {
                format!("{project}/{short}")
            };
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key)
                .or_default()
                .record_file(path, "write".into());
        }
        "get_project_overview" | "get_file_map" | "get_agent_context" => {
            let project = get_str("project");
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key)
                .or_default()
                .record_file(project.to_string(), "read".into());
        }
        "update_file_map" | "edit_file_map" => {
            let project = get_str("project");
            let key = format!("{owner}_{agent}");
            let mut map = state.agent_recent_activity.lock().unwrap();
            map.entry(key)
                .or_default()
                .record_file(format!("{project}/file-map"), "edit".into());
        }
        _ => {}
    }
}

#[derive(Debug, Clone)]
struct McpSessionEntry {
    agent: AuthenticatedAgent,
    token_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct ChatEvent {
    event_type: String,
    agent: String,
    owner: String,
    data: Value,
}

impl AppState {
    pub fn new(store: FileBlockStore) -> Self {
        Self::with_librarian(store, Arc::new(HttpLibrarianClient::new()))
    }

    fn with_librarian(
        store: FileBlockStore,
        librarian_client: Arc<dyn AnswerLibrarianClient>,
    ) -> Self {
        let default_port = default_external_port();
        let root = store.root().to_path_buf();
        let provider_status_root = root.clone();
        let auto_update_root = root.clone();
        let chat_root = root.clone();
        let db = crate::auth::open_lore_db(&root);
        let auth = LocalAuthStore::from_conn(Arc::clone(&db));
        let chat = ChatStore::from_conn(db);
        let chat_audit = ChatAuditLog::new(root.clone());
        chat_audit.cleanup_old_logs(90);
        auth.cleanup_orphans();
        chat.cleanup_orphans();
        let config = ServerConfigStore::new(root.clone(), default_port);
        let endpoint_store = EndpointStore::new(root.clone());
        let librarian_config_store = LibrarianConfigStore::new(root.clone());
        if let Ok(lc) = librarian_config_store.load() {
            if lc.needs_migration() {
                if let Ok(ep) = endpoint_store.create(
                    "Migrated".into(),
                    EndpointKind::OpenAi,
                    lc.endpoint_url.clone(),
                    lc.model.clone(),
                    lc.api_key.clone(),
                ) {
                    let _ = librarian_config_store.set_endpoint_id(Some(ep.id));
                }
            }
        }
        let state = Self {
            store: Arc::new(store),
            auth: Arc::new(auth),
            auth_audit: Arc::new(AuditStore::new(root.clone())),
            config: Arc::new(config),
            external_auth: Arc::new(ExternalAuthStore::new(root.clone())),
            oidc: Arc::new(OidcConfigStore::new(root.clone())),
            oidc_states: Arc::new(OidcLoginStateStore::new(root.clone())),
            endpoint_store: Arc::new(endpoint_store),
            librarian_config: Arc::new(librarian_config_store),
            librarian_history: Arc::new(LibrarianHistoryStore::new(root.clone())),
            project_history: Arc::new(ProjectHistoryStore::new(root.clone())),
            git_export_config: Arc::new(GitExportConfigStore::new(root.clone())),
            git_export_status: Arc::new(GitExportStatusStore::new(root.clone())),
            pending_librarian_actions: Arc::new(PendingLibrarianActionStore::new(
                provider_status_root.clone(),
            )),
            librarian_provider_status: Arc::new(LibrarianProviderStatusStore::new(
                provider_status_root,
            )),
            auto_update_config: Arc::new(AutoUpdateConfigStore::new(auto_update_root.clone())),
            auto_update_status: Arc::new(AutoUpdateStatusStore::new(auto_update_root)),
            manager_prompt_config: Arc::new(ManagerPromptConfigStore::new(root.clone())),
            update_check_cache: Arc::new(Mutex::new(None)),
            librarian_client,
            librarian_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            librarian_inflight_runs: Arc::new(Mutex::new(0)),
            login_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            agent_auth_rate_limits: Arc::new(Mutex::new(Vec::new())),
            global_librarian_rate_limits: Arc::new(Mutex::new(Vec::new())),
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            chat: Arc::new(chat),
            chat_audit: Arc::new(chat_audit),
            chat_senders: Arc::new(Mutex::new(HashMap::new())),
            chat_agent_notifiers: Arc::new(Mutex::new(HashMap::new())),
            chat_agent_stops: Arc::new(Mutex::new(HashSet::new())),
            machine_commands: Arc::new(Mutex::new(HashMap::new())),
            machine_command_results: Arc::new(Mutex::new(HashMap::new())),
            machine_poll_notifiers: Arc::new(Mutex::new(HashMap::new())),
            machine_result_notifiers: Arc::new(Mutex::new(HashMap::new())),
            machine_agent_statuses: Arc::new(Mutex::new(HashMap::new())),
            librarian_client_http: reqwest::Client::builder()
                .pool_max_idle_per_host(32)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            agent_recent_activity: Arc::new(Mutex::new(HashMap::new())),
            machine_update_timestamps: Arc::new(Mutex::new(HashMap::new())),
            machine_update_signal_state: Arc::new(Mutex::new(HashMap::new())),
        };
        let _ = maybe_mark_machine_auto_update_rollout(&state);
        state
    }
}

pub fn build_app(store: FileBlockStore) -> Router {
    build_app_with_librarian(store, Arc::new(HttpLibrarianClient::new()))
}

fn build_app_with_librarian(
    store: FileBlockStore,
    librarian_client: Arc<dyn AnswerLibrarianClient>,
) -> Router {
    let router = Router::new()
        .route("/", get(root_redirect))
        .route("/login", get(login_page).post(login_submit))
        .route("/login/oidc", get(oidc_login_start))
        .route("/login/oidc/callback", get(oidc_login_callback))
        .route("/login/external", post(external_login_submit))
        .route("/logout", post(logout_submit))
        .route("/setup", get(setup_page))
        .route("/setup.txt", get(setup_text))
        .route("/mcp", get(mcp_get).post(mcp_post).delete(mcp_delete))
        .route("/v1/health", get(health_check))
        .route("/v1/blocks", post(create_block).get(list_blocks))
        .route("/v1/search", axum::routing::get(search_blocks))
        .route("/v1/blocks/{id}", delete(delete_block).patch(update_block))
        .route("/v1/admin/roles", get(list_roles).post(create_role))
        .route("/v1/admin/roles/{name}", post(update_role))
        .route("/v1/admin/users", get(list_users).post(create_user))
        .route(
            "/v1/admin/users/{username}/password",
            post(update_user_password),
        )
        .route("/v1/admin/users/{username}/disable", post(disable_user))
        .route("/v1/admin/users/{username}/enable", post(enable_user))
        .route(
            "/v1/admin/users/{username}/sessions/revoke",
            post(revoke_user_sessions),
        )
        .route(
            "/v1/admin/agent-tokens",
            get(list_agent_tokens).post(create_agent_token),
        )
        .route("/v1/admin/agent-tokens/{name}", delete(delete_agent_token))
        .route(
            "/v1/admin/agent-tokens/{name}/rotate",
            post(rotate_agent_token),
        )
        .route(
            "/v1/admin/server-config",
            get(get_server_config).post(update_server_config),
        )
        .route(
            "/v1/admin/endpoints",
            get(list_endpoints).post(create_endpoint),
        )
        .route(
            "/v1/admin/endpoints/{id}",
            put(update_endpoint).delete(delete_endpoint),
        )
        .route("/v1/admin/endpoints/{id}/test", post(test_endpoint))
        .route(
            "/v1/admin/librarian-config",
            get(get_librarian_config).post(update_librarian_config),
        )
        .route(
            "/v1/admin/librarian-config/test",
            post(test_librarian_config),
        )
        .route(
            "/v1/admin/git-export-config",
            get(get_git_export_config).post(update_git_export_config),
        )
        .route("/v1/admin/git-export/sync", post(sync_git_export))
        .route(
            "/v1/admin/external-auth-config",
            get(get_external_auth_config).post(update_external_auth_config),
        )
        .route(
            "/v1/admin/oidc-config",
            get(get_oidc_config).post(update_oidc_config),
        )
        .route(
            "/v1/admin/auto-update-config",
            get(get_auto_update_config).post(update_auto_update_config),
        )
        .route("/v1/admin/auto-update/check", post(check_auto_update))
        .route("/v1/admin/auto-update/apply", post(apply_auto_update))
        .route("/v1/admin/librarian-runs", get(list_admin_librarian_runs))
        .route("/v1/projects", get(list_projects))
        .route("/v1/context", get(get_all_agent_context))
        .route("/v1/machines/register", post(register_machine))
        .route("/v1/machines/poll", post(machine_service_poll))
        .route("/v1/machines/ready", post(machine_service_ready))
        .route(
            "/v1/machines/binary/{target}",
            get(machine_binary_download_for_target),
        )
        .route(
            "/v1/machines/command/{id}/result",
            post(machine_command_result),
        )
        .route("/v1/agents/provision", post(provision_agent_with_body))
        .route("/v1/chat/poll", get(chat_agent_poll))
        .route("/v1/chat/stop-requested", get(chat_agent_take_stop_request))
        .route("/v1/chat/respond", post(chat_agent_respond))
        .route("/v1/chat/status", post(chat_agent_update_status))
        .route("/v1/chat/history", get(chat_agent_history))
        .route("/v1/chat/errors/report", post(chat_agent_errors_report))
        .route("/v1/chat/compact", post(chat_agent_compact))
        .route("/v1/chat/config", get(chat_agent_config))
        .route("/v1/chat/manage", get(chat_agent_get_manage))
        .route(
            "/v1/chat/manager/requested",
            post(chat_agent_manager_requested),
        )
        .route("/v1/chat/manager", post(chat_agent_manager_report))
        .route(
            "/v1/chat/manager/completions",
            post(chat_manager_proxy_completions),
        )
        .route("/v1/chat/completions", post(chat_proxy_completions))
        .route(
            "/v1/chat/lore-tools",
            get(chat_agent_lore_tools).post(chat_agent_lore_tool_call),
        )
        .route(
            "/v1/projects/{project}/blocks",
            get(list_project_blocks).post(create_project_block),
        )
        .route(
            "/v1/projects/{project}/blocks/{id}",
            get(read_block)
                .patch(update_project_block)
                .delete(delete_project_block),
        )
        .route(
            "/v1/projects/{project}/blocks/{id}/around",
            get(read_blocks_around),
        )
        .route("/v1/projects/{project}/blocks/{id}/move", post(move_block))
        .route("/v1/projects/{project}/grep", get(grep_blocks))
        .route(
            "/v1/projects/{project}/documents",
            get(api_list_documents).post(api_create_document),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}",
            put(api_rename_document).delete(api_delete_document),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}/blocks",
            get(api_list_doc_blocks).post(api_create_doc_block),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}/blocks/{block_id}",
            get(api_read_doc_block)
                .patch(api_update_doc_block)
                .delete(api_delete_doc_block),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}/blocks/{block_id}/move",
            post(api_move_doc_block),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}/blocks/{block_id}/edit",
            post(api_edit_doc_block),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}/blocks/{block_id}/split",
            post(api_split_doc_block),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}/blocks/combine",
            post(api_combine_doc_blocks),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}/grep",
            get(api_grep_doc_blocks),
        )
        .route(
            "/v1/projects/{project}/documents/{doc_id}/text",
            get(api_read_document_text).put(api_write_document_text),
        )
        .route(
            "/v1/projects/{project}/reserved/{block_id}",
            get(api_read_reserved_block).patch(api_update_reserved_block),
        )
        .route(
            "/v1/projects/{project}/librarian/answer",
            post(answer_librarian),
        )
        .route(
            "/v1/projects/{project}/librarian/action",
            post(run_project_librarian_action),
        )
        .route(
            "/v1/projects/{project}/librarian/action/{id}/approve",
            post(approve_project_librarian_action),
        )
        .route(
            "/v1/projects/{project}/librarian/action/{id}/reject",
            post(reject_project_librarian_action),
        )
        .route(
            "/v1/projects/{project}/librarian/runs",
            get(list_project_librarian_runs),
        )
        .route("/v1/projects/{project}/history", get(list_project_history))
        .route(
            "/v1/projects/{project}/history/{id}/revert",
            post(revert_project_version),
        )
        .route("/ui", get(projects_page))
        .route("/ui/projects", post(create_project_from_ui))
        .route("/ui/agents", get(agents_page))
        .route("/ui/agents/guide", get(agent_guide_page))
        .route(
            "/ui/agents/machines/{name}/revoke",
            post(revoke_machine_from_ui),
        )
        .route(
            "/ui/agents/machines/{name}/update",
            post(update_machine_from_ui),
        )
        .route(
            "/ui/agents/{name}/grants",
            post(update_agent_grants_from_ui),
        )
        .route("/ui/agents/{name}/rotate", post(rotate_agent_from_ui))
        .route("/ui/agents/{name}/delete", post(delete_agent_from_ui))
        .route("/ui/chat", get(chat_page))
        .route("/ui/chat/panel", get(chat_panel))
        .route("/ui/chat/stream", get(chat_sse_stream))
        .route("/ui/chat/librarian/history", get(librarian_chat_history))
        .route("/ui/chat/librarian/ask", post(librarian_chat_ask))
        .route(
            "/ui/chat/librarian/config",
            get(librarian_chat_get_config).post(librarian_chat_save_config),
        )
        .route(
            "/ui/chat/librarian/action/{id}/approve",
            post(librarian_chat_approve_action),
        )
        .route(
            "/ui/chat/librarian/action/{id}/reject",
            post(librarian_chat_reject_action),
        )
        .route("/ui/chat/librarian/clear", post(librarian_chat_clear))
        .route("/ui/chat/{agent}/send", post(chat_send_message))
        .route("/ui/chat/{agent}/message", post(chat_update_message))
        .route("/ui/chat/{agent}/command", post(chat_slash_command))
        .route(
            "/ui/chat/{agent}/config",
            post(chat_save_config).get(chat_get_config),
        )
        .route(
            "/ui/chat/{agent}/manage",
            post(chat_save_manage).get(chat_get_manage),
        )
        .route("/ui/chat/{agent}/errors", get(chat_errors_list))
        .route("/ui/settings", get(settings_page))
        .route("/ui/settings/theme", post(update_theme_from_ui))
        .route("/ui/admin", get(admin_page))
        .route("/ui/admin/audit", get(admin_audit_page))
        .route("/ui/admin/errors", get(admin_errors_page))
        .route("/v1/admin/errors", get(admin_errors_list))
        .route(
            "/ui/admin/errors/reporting-toggle-json",
            post(toggle_agent_error_reporting_json),
        )
        .route("/ui/admin/roles", post(create_role_from_ui))
        .route("/ui/admin/roles/{name}", post(update_role_from_ui))
        .route("/ui/admin/users", post(create_user_from_ui))
        .route(
            "/ui/admin/users/{username}/password",
            post(update_user_password_from_ui),
        )
        .route(
            "/ui/admin/users/{username}/disable",
            post(disable_user_from_ui),
        )
        .route(
            "/ui/admin/users/{username}/enable",
            post(enable_user_from_ui),
        )
        .route(
            "/ui/admin/users/{username}/sessions/revoke",
            post(revoke_user_sessions_from_ui),
        )
        .route("/ui/admin/setup", post(update_setup_from_ui))
        .route("/ui/admin/endpoints", post(create_endpoint_from_ui))
        .route("/ui/admin/endpoints/list-models", post(list_models_from_ui))
        .route("/ui/admin/endpoints/{id}", post(update_endpoint_from_ui))
        .route(
            "/ui/admin/endpoints/{id}/delete",
            post(delete_endpoint_from_ui),
        )
        .route("/ui/admin/endpoints/{id}/test", post(test_endpoint_from_ui))
        .route("/ui/admin/librarian", post(update_librarian_from_ui))
        .route("/ui/admin/librarian/test", post(test_librarian_from_ui))
        .route("/ui/admin/git-export", post(update_git_export_from_ui))
        .route("/ui/admin/git-export/sync", post(sync_git_export_from_ui))
        .route(
            "/ui/admin/external-auth",
            post(update_external_auth_from_ui),
        )
        .route("/ui/admin/oidc", post(update_oidc_from_ui))
        .route("/ui/admin/auto-update", post(update_auto_update_from_ui))
        .route(
            "/ui/admin/manager-prompts",
            post(update_manager_prompts_from_ui),
        )
        .route(
            "/ui/admin/auto-update/toggle-json",
            post(toggle_auto_update_json),
        )
        .route(
            "/ui/admin/auto-update/check",
            post(check_auto_update_from_ui),
        )
        .route(
            "/ui/admin/auto-update/apply",
            post(apply_auto_update_from_ui),
        )
        .route(
            "/ui/admin/auto-update/check-json",
            post(check_auto_update_json),
        )
        .route(
            "/ui/admin/auto-update/apply-json",
            post(apply_auto_update_json),
        )
        .route(
            "/ui/admin/update-all-machines-json",
            post(update_all_machines_json),
        )
        .route(
            "/ui/agents/machines/{name}/update-json",
            post(update_machine_json),
        )
        .route(
            "/ui/agents/machines/{name}/status-json",
            post(machine_status_json),
        )
        .route(
            "/ui/agents/machines/{name}/list-dir",
            post(machine_list_dir_json),
        )
        .route("/ui/agents/machines/{name}/mkdir", post(machine_mkdir_json))
        .route(
            "/ui/agents/machines/{name}/create-agent",
            post(machine_create_agent_json),
        )
        .route(
            "/ui/agents/machines/{name}/stop-agent",
            post(machine_stop_agent_json),
        )
        .route(
            "/ui/agents/machines/{name}/restart-agent",
            post(machine_restart_agent_json),
        )
        .route(
            "/ui/agents/machines/{name}/remove-agent",
            post(machine_remove_agent_json),
        )
        .route("/ui/chat/{agent}/profile-pic", post(upload_profile_pic))
        .route("/ui/{project}", axum::routing::get(project_page))
        .route("/ui/{project}/context", post(update_agent_context_from_ui))
        .route(
            "/ui/{project}/reserved/{block_id}",
            post(update_reserved_block_from_ui),
        )
        .route("/ui/{project}/documents", post(create_document_from_ui))
        .route(
            "/ui/{project}/doc/{doc_id}",
            axum::routing::get(document_page),
        )
        .route(
            "/ui/{project}/doc/{doc_id}/rename",
            post(rename_document_from_ui),
        )
        .route(
            "/ui/{project}/doc/{doc_id}/delete",
            post(delete_document_from_ui),
        )
        .route(
            "/ui/{project}/doc/{doc_id}/blocks",
            post(create_doc_block_from_form),
        )
        .route(
            "/ui/{project}/doc/{doc_id}/blocks/{id}/edit",
            post(update_doc_block_from_form),
        )
        .route(
            "/ui/{project}/doc/{doc_id}/blocks/{id}/delete",
            post(delete_doc_block_from_form),
        )
        .route(
            "/ui/{project}/doc/{doc_id}/blocks/{id}/pin",
            post(toggle_doc_block_pin_from_form),
        )
        .route(
            "/ui/{project}/doc/{doc_id}/blocks/{id}/media",
            axum::routing::get(doc_block_media),
        )
        .route("/ui/{project}/rename", post(rename_project_from_ui))
        .route("/ui/{project}/move", post(move_project_from_ui))
        .route("/ui/{project}/delete", post(delete_project_from_ui))
        .route(
            "/ui/{project}/audit",
            axum::routing::get(project_audit_page),
        )
        .route(
            "/ui/{project}/history",
            axum::routing::get(project_history_page),
        )
        .route("/ui/{project}/librarian", post(answer_librarian_from_ui))
        .route(
            "/ui/{project}/librarian/action",
            post(run_project_librarian_action_from_ui),
        )
        .route(
            "/ui/{project}/librarian/action/{id}/approve",
            post(approve_project_librarian_action_from_ui),
        )
        .route(
            "/ui/{project}/librarian/action/{id}/reject",
            post(reject_project_librarian_action_from_ui),
        )
        .route(
            "/ui/{project}/history/{id}/revert",
            post(revert_project_version_from_ui),
        )
        .route(
            "/ui/{project}/blocks/{id}/media",
            axum::routing::get(block_media),
        )
        .route("/ui/{project}/blocks", post(create_block_from_form))
        .route(
            "/ui/{project}/blocks/{id}/edit",
            post(update_block_from_form),
        )
        .route(
            "/ui/{project}/blocks/{id}/delete",
            post(delete_block_from_form),
        )
        .route("/ui/{project}/blocks/{id}/move", post(move_block_from_form))
        .route(
            "/ui/{project}/blocks/{id}/pin",
            post(toggle_block_pin_from_form),
        )
        .route("/ui/{project}/compact", post(compact_blocks_from_form))
        .layer(axum::middleware::map_response(add_security_headers));

    let state = AppState::with_librarian(store, librarian_client);
    spawn_error_file_sweeper(state.clone());
    spawn_release_binary_sync(state.clone());
    router.with_state(state)
}

fn spawn_error_file_sweeper(state: AppState) {
    tokio::spawn(async move {
        sweep_agent_error_files(&state);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        interval.tick().await; // consume the initial immediate tick
        loop {
            interval.tick().await;
            sweep_agent_error_files(&state);
        }
    });
}

fn spawn_release_binary_sync(state: AppState) {
    if env!("CARGO_PKG_VERSION").contains('-') {
        return;
    }
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    tokio::spawn(async move {
        let github_repo = state
            .auto_update_config
            .load()
            .map(|config| config.github_repo)
            .unwrap_or_else(|_| crate::updater::DEFAULT_UPDATE_REPO.to_string());
        if let Err(err) = sync_release_binaries_to_directory(
            &reqwest::Client::new(),
            "lore",
            env!("CARGO_PKG_VERSION"),
            &github_repo,
            &state.store.root().join("updates"),
        )
        .await
        {
            eprintln!("warning: failed to sync CLI release binaries: {err}");
        }
    });
}

async fn add_security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        ),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    response
}

#[derive(Debug, Deserialize)]
struct CreateBlockRequest {
    project: String,
    block_type: BlockType,
    content: String,
    left: Option<String>,
    right: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListBlocksQuery {
    project: String,
}

#[derive(Debug, Deserialize)]
struct SearchBlocksQuery {
    project: String,
    q: String,
}

#[derive(Debug, Deserialize)]
struct GrepBlocksQuery {
    q: String,
    block_type: Option<String>,
    author: Option<String>,
    since_days: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct BlocksAroundQuery {
    before: Option<usize>,
    after: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct DeleteBlockQuery {
    project: String,
}

#[derive(Debug, Deserialize)]
struct SettingsPageQuery {
    flash: Option<String>,
    preview: Option<String>,
    mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentsPageQuery {
    selected: Option<String>,
    flash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProjectPageQuery {
    flash: Option<String>,
}

#[derive(Deserialize)]
struct AdminPageQuery {
    flash: Option<String>,
    section: Option<String>,
}

struct CreateBlockForm {
    csrf_token: String,
    block_type: BlockType,
    content: String,
    after_block_id: Option<String>,
    image_upload: Option<ImageUpload>,
}

#[derive(Debug, Deserialize)]
struct UpdateBlockRequest {
    project: String,
    block_type: BlockType,
    content: String,
    left: Option<String>,
    right: Option<String>,
}

struct UpdateBlockForm {
    csrf_token: String,
    block_type: Option<BlockType>,
    content: String,
    after_block_id: Option<String>,
    image_upload: Option<ImageUpload>,
}

#[derive(Debug, Deserialize)]
struct DeleteBlockForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct ProjectBlockRequest {
    block_type: BlockType,
    content: String,
    after_block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProjectBlockUpdateRequest {
    block_type: BlockType,
    content: String,
    after_block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MoveBlockRequest {
    after_block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateDocumentRequest {
    name: String,
    #[serde(default)]
    parent_document_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RenameDocumentRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct DocBlockCreateRequest {
    block_type: BlockType,
    content: String,
    after_block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DocBlockUpdateRequest {
    block_type: BlockType,
    content: String,
    after_block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DocBlockEditRequest {
    old_string: String,
    new_string: String,
}

#[derive(Debug, Deserialize)]
struct DocBlockSplitRequest {
    position: usize,
}

#[derive(Debug, Deserialize)]
struct DocBlockCombineRequest {
    block_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReadDocumentTextQuery {
    start_block_id: Option<String>,
    end_block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WriteDocumentTextRequest {
    content: String,
}

#[derive(Debug, Deserialize)]
struct ReadBlockRangeQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct DocGrepQuery {
    q: String,
    #[serde(default)]
    context_lines: Option<usize>,
}

#[derive(Debug, Serialize)]
struct DocGrepMatch {
    block_id: String,
    block_type: String,
    line: usize,
    content: String,
    context_before: Vec<String>,
    context_after: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ProjectDocGrepMatch {
    document_id: String,
    document_name: String,
    block_id: String,
    block_type: String,
    line: usize,
    content: String,
    context_before: Vec<String>,
    context_after: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReservedBlockUpdateRequest {
    content: String,
}

#[derive(Debug, Deserialize)]
struct CreateRoleRequest {
    name: String,
    grants: Vec<CreateProjectGrantRequest>,
}

#[derive(Debug, Deserialize)]
struct UpdateUserPasswordRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
struct CreateProjectGrantRequest {
    project: String,
    permission: ProjectPermission,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    roles: Vec<String>,
    is_admin: bool,
}

#[derive(Debug, Deserialize)]
struct CreateAgentTokenRequest {
    name: String,
    owner: String,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    endpoint_id: Option<String>,
    grants: Vec<CreateProjectGrantRequest>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct CsrfForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct CreateProjectUiForm {
    csrf_token: String,
    project_name: String,
    #[serde(default)]
    parent: String,
}

#[derive(Debug, Deserialize)]
struct RenameProjectUiForm {
    csrf_token: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct AgentContextUiForm {
    csrf_token: String,
    #[serde(default)]
    agent_context: String,
}

#[derive(Debug, Deserialize)]
struct ReservedBlockUiForm {
    csrf_token: String,
    #[serde(default)]
    content: String,
}

#[derive(Debug, Deserialize)]
struct CreateDocumentUiForm {
    csrf_token: String,
    name: String,
    #[serde(default)]
    parent_document_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RenameDocumentUiForm {
    csrf_token: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct DeleteDocumentUiForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct MoveProjectUiForm {
    csrf_token: String,
    #[serde(default)]
    new_parent: String,
    #[serde(default)]
    after: String,
}

#[derive(Debug, Deserialize)]
struct CreateRoleUiForm {
    csrf_token: String,
    name: String,
    grants: String,
}

#[derive(Debug, Deserialize)]
struct UpdateRoleUiForm {
    csrf_token: String,
    grants: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserUiForm {
    csrf_token: String,
    username: String,
    password: String,
    roles: String,
    is_admin: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateUserPasswordUiForm {
    csrf_token: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct UserActionUiForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct UpdateAgentGrantsUiForm {
    csrf_token: String,
    grants: String,
}

#[derive(Debug, Deserialize)]
struct RegisterMachineRequest {
    username: String,
    password: String,
    machine_name: String,
}

#[derive(Debug, Deserialize)]
struct ProvisionAgentRequest {
    name: String,
    backend: Option<String>,
    #[serde(default)]
    grants: Option<Vec<CreateProjectGrantRequest>>,
    #[serde(default)]
    inherit_owner_grants: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateServerConfigRequest {
    external_scheme: String,
    external_host: String,
    external_port: u16,
    default_theme: String,
}

#[derive(Debug, Deserialize)]
struct UpdateSetupUiForm {
    csrf_token: String,
    external_scheme: String,
    external_host: String,
    external_port: u16,
}

#[derive(Debug, Deserialize)]
struct UpdateThemeUiForm {
    csrf_token: String,
    theme: String,
    #[serde(default)]
    color_mode: String,
}

#[derive(Debug, Deserialize)]
struct UpdateGitExportConfigRequest {
    enabled: bool,
    remote_url: String,
    branch: String,
    token: Option<String>,
    clear_token: Option<bool>,
    author_name: String,
    author_email: String,
    auto_export: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateGitExportUiForm {
    csrf_token: String,
    enabled: Option<String>,
    remote_url: String,
    branch: String,
    token: String,
    clear_token: Option<String>,
    author_name: String,
    author_email: String,
    auto_export: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateLibrarianConfigRequest {
    endpoint_id: Option<String>,
    request_timeout_secs: Option<u64>,
    max_concurrent_runs: Option<usize>,
    action_requires_approval: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateLibrarianUiForm {
    csrf_token: String,
    endpoint_id: Option<String>,
    request_timeout_secs: Option<u64>,
    max_concurrent_runs: Option<usize>,
    action_requires_approval: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateEndpointRequest {
    name: String,
    kind: Option<String>,
    url: String,
    model: String,
    api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateEndpointRequest {
    name: String,
    kind: Option<String>,
    url: String,
    model: String,
    api_key: Option<String>,
    clear_api_key: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CreateEndpointUiForm {
    csrf_token: String,
    name: String,
    url: String,
    model: String,
    api_key: String,
}

#[derive(Debug, Deserialize)]
struct UpdateEndpointUiForm {
    csrf_token: String,
    name: String,
    url: String,
    model: String,
    api_key: String,
    clear_api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListModelsRequest {
    endpoint_id: Option<String>,
    url: Option<String>,
    api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeleteEndpointUiForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct TestEndpointUiForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct AskLibrarianRequest {
    question: String,
    block_type: Option<String>,
    author: Option<String>,
    since_days: Option<u32>,
    max_sources: Option<usize>,
    around: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AskLibrarianForm {
    csrf_token: String,
    question: String,
    block_type: Option<String>,
    author: Option<String>,
    since_days: Option<u32>,
    include_history: Option<String>,
    max_sources: Option<usize>,
    around: Option<usize>,
    allow_edits: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LibrarianProviderTestUiForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct GitExportSyncUiForm {
    csrf_token: String,
}

#[derive(Debug, Serialize)]
struct ExternalAuthConfigSummary {
    enabled: bool,
    username_header: String,
    secret_header: String,
    has_secret: bool,
}

#[derive(Debug, Serialize)]
struct OidcConfigSummary {
    enabled: bool,
    issuer_url: String,
    client_id: String,
    callback_path: String,
    username_claim: String,
    has_client_secret: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateExternalAuthConfigRequest {
    enabled: bool,
    username_header: String,
    secret_header: String,
    secret_value: Option<String>,
    clear_secret: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateExternalAuthUiForm {
    csrf_token: String,
    enabled: Option<String>,
    username_header: String,
    secret_header: String,
    secret_value: String,
    clear_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateOidcConfigRequest {
    enabled: bool,
    issuer_url: String,
    client_id: String,
    client_secret: Option<String>,
    callback_path: String,
    username_claim: String,
    clear_client_secret: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateOidcUiForm {
    csrf_token: String,
    enabled: Option<String>,
    issuer_url: String,
    client_id: String,
    client_secret: String,
    callback_path: String,
    username_claim: String,
    clear_client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateAutoUpdateConfigRequest {
    enabled: bool,
    github_repo: String,
    #[serde(default)]
    release_stream: Option<ReleaseStream>,
    #[serde(default)]
    auto_update_machines: Option<bool>,
    confirm_password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateAutoUpdateUiForm {
    csrf_token: String,
    enabled: Option<String>,
    github_repo: String,
    release_stream: Option<ReleaseStream>,
    auto_update_machines: Option<String>,
    confirm_password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateManagerPromptsUiForm {
    csrf_token: String,
    review_latest_output_enabled: Option<String>,
    review_latest_output_text: Option<String>,
    run_periodic_checks_enabled: Option<String>,
    run_periodic_checks_text: Option<String>,
    validate_periodic_checks_enabled: Option<String>,
    validate_periodic_checks_text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AutoUpdateCheckUiForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct AutoUpdateApplyUiForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct ProjectLibrarianActionRequest {
    instruction: String,
    block_type: Option<String>,
    author: Option<String>,
    since_days: Option<u32>,
    max_sources: Option<usize>,
    around: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct LibrarianRunsQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ProjectHistoryQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ProjectLibrarianActionForm {
    csrf_token: String,
    instruction: String,
    block_type: Option<String>,
    author: Option<String>,
    since_days: Option<u32>,
    include_history: Option<String>,
    max_sources: Option<usize>,
    around: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProjectSummary {
    project: String,
}

#[derive(Debug, Serialize)]
struct BlockWindow {
    anchor: BlockId,
    blocks: Vec<Block>,
}

#[derive(Debug, Serialize)]
struct GrepMatch {
    block: Block,
    preview: String,
}

#[derive(Debug, Serialize)]
struct RoleSummary {
    name: RoleName,
    grants: Vec<ProjectGrant>,
    created_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct UserSummary {
    username: UserName,
    roles: Vec<RoleName>,
    is_admin: bool,
    disabled: bool,
    active_sessions: usize,
    created_at: time::OffsetDateTime,
}

#[derive(Debug, Clone)]
struct BlockFilterOptions {
    block_type: Option<BlockType>,
    author: Option<String>,
    since_days: Option<u32>,
}

#[derive(Debug, Clone)]
struct LibrarianOptions {
    filters: BlockFilterOptions,
    max_sources: usize,
    around: usize,
}

#[derive(Debug, Serialize)]
struct ServerConfigSummary {
    external_scheme: String,
    external_host: String,
    external_port: u16,
    default_theme: String,
    base_url: String,
    setup_url: String,
    setup_text_url: String,
    mcp_url: String,
    updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct LibrarianConfigSummary {
    endpoint_id: Option<String>,
    configured: bool,
    request_timeout_secs: u64,
    max_concurrent_runs: usize,
    action_requires_approval: bool,
    updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct EndpointSummary {
    id: String,
    name: String,
    kind: String,
    url: String,
    model: String,
    has_api_key: bool,
    configured: bool,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct LibrarianProviderStatusSummary {
    ok: bool,
    detail: String,
    checked_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct GitExportConfigSummary {
    enabled: bool,
    remote_url: String,
    branch: String,
    has_token: bool,
    author_name: String,
    author_email: String,
    auto_export: bool,
    configured: bool,
    updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct GitExportStatusSummary {
    ok: bool,
    detail: String,
    commit: Option<String>,
    created_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct AutoUpdateConfigSummary {
    enabled: bool,
    github_repo: String,
    release_stream: String,
    auto_update_machines: bool,
    last_machine_rollout_version: Option<String>,
    configured: bool,
    updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct AutoUpdateStatusSummary {
    ok: bool,
    applied: bool,
    detail: String,
    current_version: String,
    latest_version: Option<String>,
    checked_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct LibrarianAnswerBody {
    project: ProjectName,
    created_at: time::OffsetDateTime,
    actor: LibrarianActor,
    question: String,
    answer: Option<String>,
    status: LibrarianRunStatus,
    error: Option<String>,
    context_blocks: Vec<Block>,
}

#[derive(Debug, Serialize)]
struct ProjectLibrarianRunSummary {
    runs: Vec<UiLibrarianAnswer>,
    pending_actions: Vec<UiPendingLibrarianAction>,
}

#[derive(Debug, Serialize)]
struct ProjectHistorySummary {
    versions: Vec<UiProjectVersion>,
}

enum RequestActor {
    Agent(AuthenticatedAgent),
    User(AuthenticatedUser),
}

struct UiSession {
    token: String,
    csrf_token: String,
    user: AuthenticatedUser,
}

impl From<LibrarianAnswerBody> for UiLibrarianAnswer {
    fn from(value: LibrarianAnswerBody) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            project: Some(value.project.as_str().to_string()),
            created_at: value.created_at,
            kind: LibrarianRunKind::Answer,
            parent_run_id: None,
            question: value.question,
            answer: value.answer,
            status: value.status,
            error: value.error,
            actor: Some(value.actor),
            context_blocks: value.context_blocks,
            operations: Vec::new(),
        }
    }
}

impl From<ProjectLibrarianActionBody> for UiLibrarianAnswer {
    fn from(value: ProjectLibrarianActionBody) -> Self {
        Self {
            id: value.run_id,
            project: Some(value.project.as_str().to_string()),
            created_at: value.created_at,
            kind: LibrarianRunKind::ProjectAction,
            parent_run_id: Some(value.parent_run_id),
            question: value.instruction,
            answer: Some(value.summary),
            status: if value.requires_approval {
                LibrarianRunStatus::PendingApproval
            } else {
                LibrarianRunStatus::Success
            },
            error: None,
            actor: Some(value.actor),
            context_blocks: value.context_blocks,
            operations: value.operations,
        }
    }
}

fn librarian_actor_for_user(user: &AuthenticatedUser) -> LibrarianActor {
    LibrarianActor {
        kind: LibrarianActorKind::User,
        name: user.username.as_str().to_string(),
    }
}

fn librarian_actor_for_request_actor(actor: &RequestActor) -> LibrarianActor {
    match actor {
        RequestActor::Agent(agent) => LibrarianActor {
            kind: LibrarianActorKind::Agent,
            name: agent.name.clone(),
        },
        RequestActor::User(user) => librarian_actor_for_user(user),
    }
}

fn project_version_actor_for_request_actor(actor: &RequestActor) -> ProjectVersionActor {
    match actor {
        RequestActor::Agent(agent) => ProjectVersionActor {
            kind: ProjectVersionActorKind::Agent,
            name: agent.name.clone(),
        },
        RequestActor::User(user) => ProjectVersionActor {
            kind: ProjectVersionActorKind::User,
            name: user.username.as_str().to_string(),
        },
    }
}

fn project_version_actor_for_user(user: &AuthenticatedUser) -> ProjectVersionActor {
    ProjectVersionActor {
        kind: ProjectVersionActorKind::User,
        name: user.username.as_str().to_string(),
    }
}

async fn root_redirect() -> Redirect {
    Redirect::to("/ui")
}

async fn login_page(
    State(state): State<AppState>,
    Query(query): Query<ProjectPageQuery>,
) -> UiResult<Html<String>> {
    let server_config = state.config.load()?;
    Ok(Html(render_login_page(
        server_config.default_theme,
        ColorMode::System,
        state.auth.has_users()?,
        state.external_auth.load()?.is_configured(),
        state.oidc.load()?.is_configured(),
        query.flash.as_deref(),
    )))
}

async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> UiResult<Response> {
    if let Err(_) = enforce_login_rate_limit(&state, &form.username) {
        return Ok(Redirect::to(
            "/login?flash=too%20many%20login%20attempts%20—%20try%20again%20later",
        )
        .into_response());
    }
    let session = match state.auth.create_session(&form.username, &form.password) {
        Ok(s) => s,
        Err(LoreError::PermissionDenied) => {
            return Ok(
                Redirect::to("/login?flash=Incorrect%20username%20or%20password").into_response(),
            );
        }
        Err(e) => return Err(e.into()),
    };
    clear_login_rate_limit(&state, &form.username);
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "local sign-in",
        Some(session.user.username.as_str().to_string()),
        None,
    )?;
    Ok(session_redirect_response(
        &state,
        &session,
        Redirect::to("/ui?flash=Signed%20in"),
    ))
}

async fn oidc_login_start(State(state): State<AppState>) -> UiResult<Redirect> {
    let oidc = state.oidc.load()?;
    if !oidc.is_configured() {
        return Err(LoreError::PermissionDenied.into());
    }
    let server = state.config.load()?;
    let provider_metadata = discover_oidc_provider_metadata(&oidc).await?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(oidc.client_id.clone()),
        oidc.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!("{}{}", server.base_url(), oidc.callback_path))
            .map_err(|err| LoreError::Validation(format!("invalid oidc redirect url: {err}")))?,
    );
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    state.oidc_states.save(StoredOidcLoginState {
        state: csrf_state.secret().to_string(),
        nonce: nonce.secret().to_string(),
        pkce_verifier: pkce_verifier.secret().to_string(),
        created_at: OffsetDateTime::now_utc(),
        return_to: None,
    })?;
    Ok(Redirect::to(auth_url.as_str()))
}

async fn oidc_login_callback(
    State(state): State<AppState>,
    Query(query): Query<OidcCallbackQuery>,
) -> UiResult<Response> {
    let Some(login_state) = state.oidc_states.take(&query.state)? else {
        return Err(LoreError::PermissionDenied.into());
    };
    let oidc = state.oidc.load()?;
    let server = state.config.load()?;
    let provider_metadata = discover_oidc_provider_metadata(&oidc).await?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(oidc.client_id.clone()),
        oidc.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!("{}{}", server.base_url(), oidc.callback_path))
            .map_err(|err| LoreError::Validation(format!("invalid oidc redirect url: {err}")))?,
    );
    let http_client = oidc_http_client()?;
    let token_response = client
        .exchange_code(AuthorizationCode::new(query.code))
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(login_state.pkce_verifier))
        .request_async(&http_client)
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))?;
    if let Some(id_token) = token_response.id_token() {
        let expected_nonce = Nonce::new(login_state.nonce);
        let _ = id_token
            .claims(&client.id_token_verifier(), &expected_nonce)
            .map_err(|err| {
                LoreError::ExternalService(format!("OIDC ID token verification failed: {err}"))
            })?;
    }
    let user_info: CoreUserInfoClaims = client
        .user_info(token_response.access_token().to_owned(), None)
        .map_err(|err| LoreError::ExternalService(err.to_string()))?
        .request_async(&http_client)
        .await
        .map_err(|err| LoreError::ExternalService(err.to_string()))?;
    let username = oidc_username_from_claims(&oidc, &user_info)?;
    let session = state
        .auth
        .create_session_for_user(&UserName::new(username.clone())?)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::Oidc,
            name: username.clone(),
        },
        "oidc sign-in",
        Some(username),
        Some(format!("issuer {}", oidc.issuer_url)),
    )?;
    Ok(session_redirect_response(
        &state,
        &session,
        Redirect::to("/ui?flash=Signed%20in%20with%20OIDC"),
    ))
}

async fn external_login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> UiResult<Response> {
    let user = authenticate_external_user(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let session = state.auth.create_session_for_user(&user.username)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::ExternalAuth,
            name: user.username.as_str().to_string(),
        },
        "trusted-header sign-in",
        Some(user.username.as_str().to_string()),
        None,
    )?;
    Ok(session_redirect_response(
        &state,
        &session,
        Redirect::to("/ui?flash=Signed%20in%20with%20external%20auth"),
    ))
}

async fn logout_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.auth.revoke_session(&session.token)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "sign-out",
        Some(session.user.username.as_str().to_string()),
        None,
    )?;
    Ok(clear_session_redirect_response(
        &state,
        Redirect::to("/login?flash=Signed%20out"),
    ))
}

async fn setup_page(State(state): State<AppState>) -> UiResult<Html<String>> {
    let config = state.config.load()?;
    let setup_instruction = build_agent_setup_instruction(&config, None);
    Ok(Html(render_setup_page(&config, &setup_instruction)))
}

async fn health_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(serde_json::json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")}))
}

async fn setup_text(State(state): State<AppState>) -> UiResult<Response> {
    let config = state.config.load()?;
    let body = build_agent_setup_instruction(&config, None);
    let content_type = HeaderValue::from_static("text/plain; charset=utf-8");
    Ok(([(header::CONTENT_TYPE, content_type)], body).into_response())
}

async fn create_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateBlockRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(payload.project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let new_block = NewBlock {
        project: project.clone(),
        block_type: payload.block_type,
        content: payload.content,
        author_key: actor_author_value(&actor),
        left: payload.left.map(OrderKey::new).transpose()?,
        right: payload.right.map(OrderKey::new).transpose()?,
        image_upload: None,
    };

    let block = match actor {
        RequestActor::Agent(_) => state.store.create_block(new_block)?,
        RequestActor::User(_) => state.store.create_block_as_project_writer(new_block)?,
    };
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "Create block",
        vec![create_version_operation(&state, &project, &block.id, None)?],
    )?;
    Ok(Json(block))
}

async fn list_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListBlocksQuery>,
) -> ApiResult<Json<Vec<Block>>> {
    let project = ProjectName::new(query.project)?;
    authorize_project_read(&state, &headers, &project)?;
    let blocks = state.store.list_blocks(&project)?;
    Ok(Json(blocks))
}

async fn search_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchBlocksQuery>,
) -> ApiResult<Json<Vec<Block>>> {
    let project = ProjectName::new(query.project)?;
    authorize_project_read(&state, &headers, &project)?;
    let blocks = state.store.search_blocks(&project, &query.q)?;
    Ok(Json(blocks))
}

async fn list_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ProjectSummary>>> {
    let actor = require_authenticated_actor(&state, &headers)?;
    let infos = state.store.list_project_infos()?;
    let projects = infos
        .into_iter()
        .filter(|info| match &actor {
            RequestActor::Agent(agent) => agent.can_read(&info.slug),
            RequestActor::User(user) if user.is_admin => true,
            RequestActor::User(user) => user.can_read(&info.slug),
        })
        .map(|info| ProjectSummary {
            project: info.display_name,
        })
        .collect();
    Ok(Json(projects))
}

async fn get_all_agent_context(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<String> {
    let actor = require_authenticated_actor(&state, &headers)?;
    let projects = state.store.list_projects()?;
    let visible = filter_projects_for_actor(&actor, &projects);
    let mut parts: Vec<String> = Vec::new();
    for project in visible {
        let meta = state.store.read_project_meta(&project);
        if let Some(ctx) = meta.agent_context {
            if !ctx.trim().is_empty() {
                parts.push(format!("# {}\n{}", meta.display_name, ctx));
            }
        }
    }
    Ok(parts.join("\n\n"))
}

async fn list_project_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> ApiResult<Json<Vec<Block>>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    Ok(Json(state.store.list_blocks(&project)?))
}

async fn create_project_block(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ProjectBlockRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let after_block_id = payload
        .after_block_id
        .map(BlockId::from_string)
        .transpose()?;
    let (left, right) = state
        .store
        .resolve_after_block(&project, after_block_id.as_ref(), None)?;
    let new_block = NewBlock {
        project: project.clone(),
        block_type: payload.block_type,
        content: payload.content,
        author_key: actor_author_value(&actor),
        left,
        right,
        image_upload: None,
    };
    let block = match actor {
        RequestActor::Agent(_) => state.store.create_block(new_block)?,
        RequestActor::User(_) => state.store.create_block_as_project_writer(new_block)?,
    };
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "Create block",
        vec![create_version_operation(&state, &project, &block.id, None)?],
    )?;
    Ok(Json(block))
}

async fn read_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let block_id = BlockId::from_string(id)?;
    Ok(Json(state.store.get_block(&project, &block_id)?))
}

async fn read_blocks_around(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
    Query(query): Query<BlocksAroundQuery>,
) -> ApiResult<Json<BlockWindow>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let block_id = BlockId::from_string(id)?;
    let before = query.before.unwrap_or(2);
    let after = query.after.unwrap_or(2);
    let blocks = state
        .store
        .read_blocks_around(&project, &block_id, before, after)?;
    Ok(Json(BlockWindow {
        anchor: block_id,
        blocks,
    }))
}

async fn grep_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<GrepBlocksQuery>,
) -> ApiResult<Json<Vec<GrepMatch>>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let filters = block_filters_from_parts(
        query.block_type.as_deref(),
        query.author.as_deref(),
        query.since_days,
    )?;
    let matches = state
        .store
        .search_blocks(&project, &query.q)?
        .into_iter()
        .filter(|block| block_matches_filters(block, &filters))
        .map(|block| GrepMatch {
            preview: grep_preview(&block.content, &query.q),
            block,
        })
        .collect();
    Ok(Json(matches))
}

// ---- Document endpoints ----

async fn api_list_documents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> ApiResult<Json<Value>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let docs = state.store.list_documents(&project)?;
    Ok(Json(json!({ "documents": serialize_doc_tree(&docs) })))
}

fn serialize_doc_tree(docs: &[crate::store::DocumentInfo]) -> Vec<Value> {
    docs.iter()
        .map(|d| {
            json!({
                "id": d.id.as_str(),
                "name": d.display_name,
                "children": serialize_doc_tree(&d.children),
            })
        })
        .collect()
}

async fn api_create_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(body): Json<CreateDocumentRequest>,
) -> ApiResult<Json<Value>> {
    let project = ProjectName::new(project)?;
    authorize_project_write(&state, &headers, &project)?;
    let parent_doc = body
        .parent_document_id
        .map(DocumentId::from_string)
        .transpose()?;
    let doc = state
        .store
        .create_document(&project, parent_doc.as_ref(), &body.name)?;
    Ok(Json(json!({
        "id": doc.id.as_str(),
        "name": doc.display_name,
    })))
}

async fn api_rename_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Json(body): Json<RenameDocumentRequest>,
) -> ApiResult<Json<Value>> {
    let project = ProjectName::new(project)?;
    authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    state.store.rename_document(&project, &doc_id, &body.name)?;
    Ok(Json(json!({ "renamed": true })))
}

async fn api_delete_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let project = ProjectName::new(project)?;
    authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    state.store.delete_document(&project, &doc_id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_list_doc_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
) -> ApiResult<Json<Vec<Block>>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    Ok(Json(state.store.list_doc_blocks(&project, &doc_id)?))
}

async fn api_read_doc_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, block_id)): Path<(String, String, String)>,
    Query(query): Query<ReadBlockRangeQuery>,
) -> ApiResult<Json<Value>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let block_id = BlockId::from_string(block_id)?;
    let block = state.store.get_doc_block(&project, &doc_id, &block_id)?;
    if query.offset.is_some() || query.limit.is_some() {
        let lines: Vec<&str> = block.content.lines().collect();
        let total = lines.len();
        let start = query.offset.unwrap_or(0).min(total);
        let end = match query.limit {
            Some(l) => (start + l).min(total),
            None => total,
        };
        let sliced: String = lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{}\t{}", start + i + 1, l))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(Json(json!({
            "block_id": block.id.as_str(),
            "block_type": format!("{:?}", block.block_type).to_lowercase(),
            "total_lines": total,
            "offset": start,
            "limit": end - start,
            "content": sliced,
        })))
    } else {
        Ok(Json(json!({ "block": block })))
    }
}

async fn api_create_doc_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Json(body): Json<DocBlockCreateRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let after_block_id = body.after_block_id.map(BlockId::from_string).transpose()?;
    let (left, right) =
        state
            .store
            .resolve_after_doc_block(&project, &doc_id, after_block_id.as_ref(), None)?;
    let new_block = NewBlock {
        project: project.clone(),
        block_type: body.block_type,
        content: body.content,
        author_key: actor_author_value(&actor),
        left,
        right,
        image_upload: None,
    };
    let block = match actor {
        RequestActor::Agent(_) => state.store.create_doc_block(&doc_id, new_block)?,
        RequestActor::User(_) => state
            .store
            .create_doc_block_as_project_writer(&doc_id, new_block)?,
    };
    let version_op = create_doc_version_operation(&state, &project, &doc_id, &block.id)?;
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "create document block",
        vec![version_op],
    )?;
    Ok(Json(block))
}

async fn api_update_doc_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, block_id)): Path<(String, String, String)>,
    Json(body): Json<DocBlockUpdateRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let block_id = BlockId::from_string(block_id)?;
    let has_after = body.after_block_id.is_some();
    let after_block_id = body.after_block_id.map(BlockId::from_string).transpose()?;
    let (left, right) = if has_after {
        state.store.resolve_after_doc_block(
            &project,
            &doc_id,
            after_block_id.as_ref(),
            Some(&block_id),
        )?
    } else {
        (None, None)
    };
    let before = state
        .store
        .snapshot_doc_block(&project, &doc_id, &block_id)?;
    let update = UpdateBlock {
        project: project.clone(),
        block_id,
        block_type: body.block_type,
        content: body.content,
        author_key: actor_author_value(&actor),
        left,
        right,
        image_upload: None,
    };
    let block = match actor {
        RequestActor::Agent(_) => state.store.update_doc_block(&doc_id, update)?,
        RequestActor::User(_) => state
            .store
            .update_doc_block_as_project_writer(&doc_id, update)?,
    };
    let version_op = update_doc_version_operation(
        &state,
        &project,
        &doc_id,
        &block.id,
        before,
        ProjectVersionOperationType::UpdateBlock,
    )?;
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "update document block",
        vec![version_op],
    )?;
    Ok(Json(block))
}

async fn api_delete_doc_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, block_id)): Path<(String, String, String)>,
) -> ApiResult<StatusCode> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let block_id = BlockId::from_string(block_id)?;
    let before = state
        .store
        .snapshot_doc_block(&project, &doc_id, &block_id)?;
    match actor {
        RequestActor::Agent(ref agent) => {
            state
                .store
                .delete_doc_block(&project, &doc_id, &block_id, &agent.token)?
        }
        RequestActor::User(_) => state
            .store
            .delete_doc_block_as_project_writer(&project, &doc_id, &block_id)?,
    }
    let version_op = StoredProjectVersionOperation {
        operation_type: ProjectVersionOperationType::DeleteBlock,
        block_id,
        before: Some(before),
        after: None,
        document_id: Some(doc_id.as_str().to_string()),
    };
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "delete document block",
        vec![version_op],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_move_doc_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, block_id)): Path<(String, String, String)>,
    Json(body): Json<MoveBlockRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let block_id = BlockId::from_string(block_id)?;
    let before = state
        .store
        .snapshot_doc_block(&project, &doc_id, &block_id)?;
    let after_block_id = body.after_block_id.map(BlockId::from_string).transpose()?;
    let block = match actor {
        RequestActor::Agent(ref agent) => state.store.move_doc_block_after(
            &project,
            &doc_id,
            &block_id,
            after_block_id.as_ref(),
            &agent.token,
        )?,
        RequestActor::User(ref user) => state.store.move_doc_block_after_as_project_writer(
            &project,
            &doc_id,
            &block_id,
            after_block_id.as_ref(),
            user.username.as_str(),
        )?,
    };
    let version_op = update_doc_version_operation(
        &state,
        &project,
        &doc_id,
        &block.id,
        before,
        ProjectVersionOperationType::MoveBlock,
    )?;
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "move document block",
        vec![version_op],
    )?;
    Ok(Json(block))
}

async fn api_edit_doc_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, block_id)): Path<(String, String, String)>,
    Json(body): Json<DocBlockEditRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let block_id = BlockId::from_string(block_id)?;
    let existing = state.store.get_doc_block(&project, &doc_id, &block_id)?;
    let count = existing.content.matches(&body.old_string).count();
    if count == 0 {
        return Err(LoreError::Validation("old_string not found in block".into()).into());
    }
    if count > 1 {
        return Err(LoreError::Validation(format!(
            "old_string found {count} times — must be unique. Provide more context."
        ))
        .into());
    }
    let before = state
        .store
        .snapshot_doc_block(&project, &doc_id, &block_id)?;
    let new_content = existing
        .content
        .replacen(&body.old_string, &body.new_string, 1);
    let update = UpdateBlock {
        project: project.clone(),
        block_id,
        block_type: existing.block_type,
        content: new_content,
        author_key: actor_author_value(&actor),
        left: None,
        right: None,
        image_upload: None,
    };
    let block = match actor {
        RequestActor::Agent(_) => state.store.update_doc_block(&doc_id, update)?,
        RequestActor::User(_) => state
            .store
            .update_doc_block_as_project_writer(&doc_id, update)?,
    };
    let version_op = update_doc_version_operation(
        &state,
        &project,
        &doc_id,
        &block.id,
        before,
        ProjectVersionOperationType::UpdateBlock,
    )?;
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "edit document block",
        vec![version_op],
    )?;
    Ok(Json(block))
}

async fn api_split_doc_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, block_id)): Path<(String, String, String)>,
    Json(body): Json<DocBlockSplitRequest>,
) -> ApiResult<Json<Value>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let block_id = BlockId::from_string(block_id)?;
    let before = state
        .store
        .snapshot_doc_block(&project, &doc_id, &block_id)?;
    let author = match &actor {
        RequestActor::Agent(agent) => KeyFingerprint::from_api_key(&agent.token)?,
        RequestActor::User(user) => KeyFingerprint::from_user_name(user.username.as_str())?,
    };
    let (updated, new_block) =
        state
            .store
            .split_doc_block(&project, &doc_id, &block_id, body.position, author)?;
    let ops = vec![
        update_doc_version_operation(
            &state,
            &project,
            &doc_id,
            &updated.id,
            before,
            ProjectVersionOperationType::UpdateBlock,
        )?,
        create_doc_version_operation(&state, &project, &doc_id, &new_block.id)?,
    ];
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "split document block",
        ops,
    )?;
    Ok(Json(json!({ "original": updated, "new_block": new_block })))
}

async fn api_combine_doc_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Json(body): Json<DocBlockCombineRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let block_ids: Vec<BlockId> = body
        .block_ids
        .into_iter()
        .map(BlockId::from_string)
        .collect::<crate::error::Result<Vec<_>>>()?;
    // Snapshot all blocks before combining
    let befores: Vec<_> = block_ids
        .iter()
        .map(|bid| state.store.snapshot_doc_block(&project, &doc_id, bid))
        .collect::<crate::error::Result<Vec<_>>>()?;
    let author = match &actor {
        RequestActor::Agent(agent) => KeyFingerprint::from_api_key(&agent.token)?,
        RequestActor::User(user) => KeyFingerprint::from_user_name(user.username.as_str())?,
    };
    let merged = state
        .store
        .combine_doc_blocks(&project, &doc_id, &block_ids, author)?;
    let mut ops = Vec::new();
    // First block was updated
    ops.push(update_doc_version_operation(
        &state,
        &project,
        &doc_id,
        &merged.id,
        befores[0].clone(),
        ProjectVersionOperationType::UpdateBlock,
    )?);
    // Remaining blocks were deleted
    for (i, bid) in block_ids[1..].iter().enumerate() {
        ops.push(StoredProjectVersionOperation {
            operation_type: ProjectVersionOperationType::DeleteBlock,
            block_id: bid.clone(),
            before: Some(befores[i + 1].clone()),
            after: None,
            document_id: Some(doc_id.as_str().to_string()),
        });
    }
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "combine document blocks",
        ops,
    )?;
    Ok(Json(merged))
}

async fn api_read_document_text(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Query(query): Query<ReadDocumentTextQuery>,
) -> ApiResult<Json<Value>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let start = query.start_block_id.map(BlockId::from_string).transpose()?;
    let end = query.end_block_id.map(BlockId::from_string).transpose()?;
    let text = state
        .store
        .read_document_text(&project, &doc_id, start.as_ref(), end.as_ref())?;
    Ok(Json(json!({ "content": text })))
}

async fn api_write_document_text(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Json(body): Json<WriteDocumentTextRequest>,
) -> ApiResult<Json<Value>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;

    let entries = crate::store::parse_document_text(&body.content)?;

    // Snapshot current blocks before write (for version tracking)
    let current_blocks = state.store.list_doc_blocks(&project, &doc_id)?;
    let mut before_snapshots: HashMap<String, StoredBlockSnapshot> = HashMap::new();
    for block in &current_blocks {
        if let Ok(snap) = state.store.snapshot_doc_block(&project, &doc_id, &block.id) {
            before_snapshots.insert(block.id.as_str().to_string(), snap);
        }
    }

    let author = match &actor {
        RequestActor::Agent(agent) => KeyFingerprint::from_api_key(&agent.token)?,
        RequestActor::User(user) => KeyFingerprint::from_user_name(user.username.as_str())?,
    };
    let result = state
        .store
        .write_document_text(&project, &doc_id, entries, author)?;

    // Build version operations
    let mut ops = Vec::new();
    for block in &result.updated {
        if let Some(before) = before_snapshots.get(block.id.as_str()) {
            if let Ok(after) = state.store.snapshot_doc_block(&project, &doc_id, &block.id) {
                ops.push(StoredProjectVersionOperation {
                    operation_type: ProjectVersionOperationType::UpdateBlock,
                    block_id: block.id.clone(),
                    before: Some(before.clone()),
                    after: Some(after),
                    document_id: Some(doc_id.as_str().to_string()),
                });
            }
        }
    }
    for (_, block) in &result.created {
        if let Ok(after) = state.store.snapshot_doc_block(&project, &doc_id, &block.id) {
            ops.push(StoredProjectVersionOperation {
                operation_type: ProjectVersionOperationType::CreateBlock,
                block_id: block.id.clone(),
                before: None,
                after: Some(after),
                document_id: Some(doc_id.as_str().to_string()),
            });
        }
    }
    for deleted_id in &result.deleted {
        if let Some(before) = before_snapshots.get(deleted_id.as_str()) {
            ops.push(StoredProjectVersionOperation {
                operation_type: ProjectVersionOperationType::DeleteBlock,
                block_id: deleted_id.clone(),
                before: Some(before.clone()),
                after: None,
                document_id: Some(doc_id.as_str().to_string()),
            });
        }
    }
    if !ops.is_empty() {
        record_project_version(
            &state,
            &project_version_actor_for_request_actor(&actor),
            &project,
            "write document text",
            ops,
        )?;
    }

    // Build response
    let created_map: Vec<Value> = result
        .created
        .iter()
        .map(|(placeholder, block)| {
            json!({
                "placeholder_id": placeholder,
                "block_id": block.id.as_str(),
            })
        })
        .collect();
    let updated_ids: Vec<&str> = result.updated.iter().map(|b| b.id.as_str()).collect();
    let deleted_ids: Vec<&str> = result.deleted.iter().map(|b| b.as_str()).collect();

    Ok(Json(json!({
        "created": created_map,
        "updated": updated_ids,
        "deleted": deleted_ids,
    })))
}

async fn api_grep_doc_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Query(query): Query<DocGrepQuery>,
) -> ApiResult<Json<Vec<DocGrepMatch>>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let blocks = state.store.list_doc_blocks(&project, &doc_id)?;
    let ctx_lines = query.context_lines.unwrap_or(2);
    let needle = query.q.to_lowercase();
    let matches = grep_blocks_with_lines(&blocks, &needle, ctx_lines);
    Ok(Json(matches))
}

fn grep_blocks_with_lines(blocks: &[Block], needle: &str, ctx_lines: usize) -> Vec<DocGrepMatch> {
    let mut results = Vec::new();
    for block in blocks {
        let lines: Vec<&str> = block.content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.to_lowercase().contains(needle) {
                let start = i.saturating_sub(ctx_lines);
                let end = (i + ctx_lines + 1).min(lines.len());
                results.push(DocGrepMatch {
                    block_id: block.id.as_str().to_string(),
                    block_type: format!("{:?}", block.block_type).to_lowercase(),
                    line: i + 1,
                    content: line.to_string(),
                    context_before: lines[start..i].iter().map(|s| s.to_string()).collect(),
                    context_after: lines[i + 1..end].iter().map(|s| s.to_string()).collect(),
                });
            }
        }
    }
    results
}

async fn api_read_reserved_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, block_id)): Path<(String, String)>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let block = state.store.get_reserved_block(&project, &block_id)?;
    Ok(Json(block))
}

async fn api_update_reserved_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, block_id)): Path<(String, String)>,
    Json(body): Json<ReservedBlockUpdateRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let is_agent = matches!(actor, RequestActor::Agent(_));
    let block = state
        .store
        .update_reserved_block(&project, &block_id, &body.content, is_agent)?;
    Ok(Json(block))
}

async fn list_agent_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<AgentTokenSummary>>> {
    require_admin(&state, &headers)?;
    let tokens = state
        .auth
        .list_agent_tokens()?
        .into_iter()
        .map(|token| agent_token_summary(&state, token))
        .collect();
    Ok(Json(tokens))
}

async fn create_agent_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAgentTokenRequest>,
) -> ApiResult<Json<Value>> {
    let admin = require_admin(&state, &headers)?;
    let owner = UserName::new(&payload.owner)?;
    let backend = payload
        .backend
        .as_deref()
        .and_then(|b| b.parse().ok())
        .unwrap_or_default();
    let created = state.auth.create_agent_token(NewAgentToken {
        display_name: payload.name,
        owner: owner.clone(),
        grants: payload
            .grants
            .into_iter()
            .map(|grant| {
                Ok(ProjectGrant {
                    project: ProjectName::new(grant.project)?,
                    permission: grant.permission,
                })
            })
            .collect::<Result<Vec<_>, LoreError>>()?,
        backend,
        endpoint_id: payload.endpoint_id.clone(),
    })?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "create agent token",
        Some(created.stored.name.clone()),
        Some("api".into()),
    )?;
    Ok(Json(json!({
        "token": created.token,
        "summary": agent_token_summary(&state, created.stored),
    })))
}

async fn delete_agent_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    let admin = require_admin(&state, &headers)?;
    state.auth.revoke_agent_token_by_name(&name)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "revoke agent token",
        Some(name),
        Some("api".into()),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rotate_agent_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let admin = require_admin(&state, &headers)?;
    let created = state.auth.rotate_agent_token_by_name(&name)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "rotate agent token",
        Some(created.stored.name.clone()),
        Some("api".into()),
    )?;
    Ok(Json(json!({
        "token": created.token,
        "summary": agent_token_summary(&state, created.stored),
    })))
}

async fn list_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<RoleSummary>>> {
    require_admin(&state, &headers)?;
    let roles = state
        .auth
        .list_roles()?
        .into_iter()
        .map(|role| RoleSummary {
            name: role.name,
            grants: role.grants,
            created_at: role.created_at,
        })
        .collect();
    Ok(Json(roles))
}

async fn create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateRoleRequest>,
) -> ApiResult<Json<RoleSummary>> {
    let admin = require_admin(&state, &headers)?;
    let role = state.auth.create_role(NewRole {
        name: RoleName::new(payload.name)?,
        grants: payload
            .grants
            .into_iter()
            .map(|grant| {
                Ok(ProjectGrant {
                    project: ProjectName::new(grant.project)?,
                    permission: grant.permission,
                })
            })
            .collect::<Result<Vec<_>, LoreError>>()?,
    })?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "create role",
        Some(role.name.as_str().to_string()),
        Some("api".into()),
    )?;
    Ok(Json(RoleSummary {
        name: role.name,
        grants: role.grants,
        created_at: role.created_at,
    }))
}

async fn update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(payload): Json<CreateRoleRequest>,
) -> ApiResult<Json<RoleSummary>> {
    let admin = require_admin(&state, &headers)?;
    if payload.name != name {
        return Err(LoreError::Validation("role name in path must match payload".into()).into());
    }
    let role = state.auth.update_role(NewRole {
        name: RoleName::new(payload.name)?,
        grants: payload
            .grants
            .into_iter()
            .map(|grant| {
                Ok(ProjectGrant {
                    project: ProjectName::new(grant.project)?,
                    permission: grant.permission,
                })
            })
            .collect::<Result<Vec<_>, LoreError>>()?,
    })?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "update role",
        Some(role.name.as_str().to_string()),
        Some("api".into()),
    )?;
    Ok(Json(RoleSummary {
        name: role.name,
        grants: role.grants,
        created_at: role.created_at,
    }))
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<UserSummary>>> {
    require_admin(&state, &headers)?;
    let users = state
        .auth
        .list_users()?
        .into_iter()
        .map(|user| user_summary(&state, user))
        .collect::<Result<Vec<_>, LoreError>>()?;
    Ok(Json(users))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateUserRequest>,
) -> ApiResult<Json<UserSummary>> {
    let admin = require_admin(&state, &headers)?;
    let user = state.auth.create_user(NewUser {
        username: UserName::new(payload.username)?,
        password: payload.password,
        role_names: payload
            .roles
            .into_iter()
            .map(RoleName::new)
            .collect::<Result<Vec<_>, LoreError>>()?,
        is_admin: payload.is_admin,
    })?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "create user",
        Some(user.username.as_str().to_string()),
        Some("api".into()),
    )?;
    Ok(Json(user_summary(&state, user)?))
}

async fn update_user_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(payload): Json<UpdateUserPasswordRequest>,
) -> ApiResult<Json<UserSummary>> {
    let admin = require_admin(&state, &headers)?;
    let username = UserName::new(username)?;
    let user = state
        .auth
        .update_user_password(&username, payload.password)?;
    state.auth.revoke_sessions_for_user(&username)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "reset user password",
        Some(username.as_str().to_string()),
        Some("api".into()),
    )?;
    Ok(Json(user_summary(&state, user)?))
}

async fn disable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> ApiResult<Json<UserSummary>> {
    let admin = require_admin(&state, &headers)?;
    let username = UserName::new(username)?;
    let user = state.auth.set_user_disabled(&username, true)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "disable user",
        Some(username.as_str().to_string()),
        Some("api".into()),
    )?;
    Ok(Json(user_summary(&state, user)?))
}

async fn enable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> ApiResult<Json<UserSummary>> {
    let admin = require_admin(&state, &headers)?;
    let username = UserName::new(username)?;
    let user = state.auth.set_user_disabled(&username, false)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "enable user",
        Some(username.as_str().to_string()),
        Some("api".into()),
    )?;
    Ok(Json(user_summary(&state, user)?))
}

async fn revoke_user_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> ApiResult<Json<Value>> {
    let admin = require_admin(&state, &headers)?;
    let username = UserName::new(username)?;
    let revoked = state.auth.revoke_sessions_for_user(&username)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "revoke user sessions",
        Some(username.as_str().to_string()),
        Some("api".into()),
    )?;
    Ok(Json(json!({
        "username": username.as_str(),
        "revoked_sessions": revoked,
    })))
}

async fn get_server_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ServerConfigSummary>> {
    require_admin(&state, &headers)?;
    Ok(Json(server_config_summary(&state.config.load()?)))
}

async fn update_server_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateServerConfigRequest>,
) -> ApiResult<Json<ServerConfigSummary>> {
    let admin = require_admin(&state, &headers)?;
    let config = state.config.update(
        ExternalScheme::parse(&payload.external_scheme)?,
        payload.external_host,
        payload.external_port,
        UiTheme::parse(&payload.default_theme)?,
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "update setup address",
        None,
        Some("api".into()),
    )?;
    Ok(Json(server_config_summary(&config)))
}

async fn get_librarian_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<LibrarianConfigSummary>> {
    require_admin(&state, &headers)?;
    Ok(Json(librarian_config_summary(
        &state.librarian_config.load()?,
    )))
}

async fn update_librarian_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateLibrarianConfigRequest>,
) -> ApiResult<Json<LibrarianConfigSummary>> {
    let admin = require_admin(&state, &headers)?;
    let existing = state.librarian_config.load()?;
    let config = state.librarian_config.update(
        payload.endpoint_id,
        payload
            .request_timeout_secs
            .unwrap_or(existing.request_timeout_secs),
        payload
            .max_concurrent_runs
            .unwrap_or(existing.max_concurrent_runs),
        payload
            .action_requires_approval
            .unwrap_or(existing.action_requires_approval),
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "update librarian config",
        None,
        Some("api".into()),
    )?;
    Ok(Json(librarian_config_summary(&config)))
}

async fn test_librarian_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<LibrarianProviderStatusSummary>> {
    require_admin(&state, &headers)?;
    let (endpoint, config) = resolve_librarian_endpoint(&state)?;
    let status = state
        .librarian_client
        .healthcheck(&endpoint, config.request_timeout_secs)
        .await?;
    state.librarian_provider_status.save(&status)?;
    Ok(Json(provider_status_summary(status)))
}

async fn list_endpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<EndpointSummary>>> {
    require_admin(&state, &headers)?;
    let endpoints = state.endpoint_store.list()?;
    Ok(Json(endpoints.iter().map(endpoint_summary).collect()))
}

async fn create_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateEndpointRequest>,
) -> ApiResult<Json<EndpointSummary>> {
    let admin = require_admin(&state, &headers)?;
    let kind: EndpointKind = match payload.kind {
        Some(k) => k.parse()?,
        None => crate::librarian::infer_kind_from_url(&payload.url),
    };
    let ep = state.endpoint_store.create(
        payload.name,
        kind,
        payload.url,
        payload.model,
        payload.api_key,
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        &format!("create endpoint: {}", ep.name),
        None,
        Some("api".into()),
    )?;
    Ok(Json(endpoint_summary(&ep)))
}

async fn update_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateEndpointRequest>,
) -> ApiResult<Json<EndpointSummary>> {
    let admin = require_admin(&state, &headers)?;
    let kind: EndpointKind = match payload.kind {
        Some(k) => k.parse()?,
        None => crate::librarian::infer_kind_from_url(&payload.url),
    };
    let ep = state.endpoint_store.update(
        &id,
        payload.name,
        kind,
        payload.url,
        payload.model,
        api_key_update_from_request(payload.api_key.as_deref(), payload.clear_api_key),
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        &format!("update endpoint: {}", ep.name),
        None,
        Some("api".into()),
    )?;
    Ok(Json(endpoint_summary(&ep)))
}

async fn delete_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let admin = require_admin(&state, &headers)?;
    state.endpoint_store.delete(&id)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "delete endpoint",
        None,
        Some("api".into()),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn test_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<LibrarianProviderStatusSummary>> {
    require_admin(&state, &headers)?;
    let endpoint = state
        .endpoint_store
        .get(&id)?
        .ok_or_else(|| LoreError::Validation("endpoint not found".into()))?;
    let config = state.librarian_config.load()?;
    let status = state
        .librarian_client
        .healthcheck(&endpoint, config.request_timeout_secs)
        .await?;
    Ok(Json(provider_status_summary(status)))
}

async fn get_git_export_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<GitExportConfigSummary>> {
    require_admin(&state, &headers)?;
    Ok(Json(git_export_config_summary(
        &state.git_export_config.load()?,
    )))
}

async fn update_git_export_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateGitExportConfigRequest>,
) -> ApiResult<Json<GitExportConfigSummary>> {
    let admin = require_admin(&state, &headers)?;
    let config = state.git_export_config.update(
        payload.enabled,
        payload.remote_url,
        payload.branch,
        git_export_token_update_from_request(payload.token.as_deref(), payload.clear_token),
        payload.author_name,
        payload.author_email,
        payload.auto_export,
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "update git export config",
        None,
        Some("api".into()),
    )?;
    Ok(Json(git_export_config_summary(&config)))
}

async fn sync_git_export(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<GitExportStatusSummary>> {
    let admin = require_admin(&state, &headers)?;
    let status = run_manual_git_export(&state, "Manual admin export")?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "run git export",
        None,
        Some("api".into()),
    )?;
    Ok(Json(git_export_status_summary(status)))
}

async fn get_external_auth_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ExternalAuthConfigSummary>> {
    require_admin(&state, &headers)?;
    Ok(Json(external_auth_config_summary(
        &state.external_auth.load()?,
    )))
}

async fn update_external_auth_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateExternalAuthConfigRequest>,
) -> ApiResult<Json<ExternalAuthConfigSummary>> {
    let admin = require_admin(&state, &headers)?;
    let config = state.external_auth.update(
        payload.enabled,
        payload.username_header,
        payload.secret_header,
        external_auth_secret_update_from_request(
            payload.secret_value.as_deref(),
            payload.clear_secret,
        ),
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "update external auth config",
        None,
        Some(format!("enabled={}", config.enabled)),
    )?;
    Ok(Json(external_auth_config_summary(&config)))
}

async fn get_oidc_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<OidcConfigSummary>> {
    require_admin(&state, &headers)?;
    Ok(Json(oidc_config_summary(&state.oidc.load()?)))
}

async fn update_oidc_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateOidcConfigRequest>,
) -> ApiResult<Json<OidcConfigSummary>> {
    let admin = require_admin(&state, &headers)?;
    let config = state.oidc.update(
        payload.enabled,
        payload.issuer_url,
        payload.client_id,
        oidc_secret_update_from_request(
            payload.client_secret.as_deref(),
            payload.clear_client_secret,
        ),
        payload.callback_path,
        OidcUsernameClaim::parse(&payload.username_claim)?,
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "update oidc config",
        None,
        Some(format!(
            "enabled={} claim={}",
            config.enabled,
            config.username_claim.as_str()
        )),
    )?;
    Ok(Json(oidc_config_summary(&config)))
}

async fn get_auto_update_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AutoUpdateConfigSummary>> {
    require_admin(&state, &headers)?;
    Ok(Json(auto_update_config_summary(
        &state.auto_update_config.load()?,
    )))
}

async fn update_auto_update_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateAutoUpdateConfigRequest>,
) -> ApiResult<Json<AutoUpdateConfigSummary>> {
    let admin = require_admin(&state, &headers)?;
    let current_config = state.auto_update_config.load()?;
    let release_stream = payload
        .release_stream
        .unwrap_or(current_config.release_stream);
    let auto_update_machines = payload
        .auto_update_machines
        .unwrap_or(current_config.auto_update_machines);
    if payload.github_repo != current_config.github_repo {
        let password = payload.confirm_password.as_deref().unwrap_or("");
        state
            .auth
            .authenticate(admin.username.as_str(), password)
            .map_err(|_| {
                LoreError::Validation(
                    "password confirmation required when changing the update source repository"
                        .into(),
                )
            })?;
    }
    let config = state.auto_update_config.update(
        payload.enabled,
        payload.github_repo,
        release_stream,
        auto_update_machines,
    )?;
    let repo_changed = config.github_repo != current_config.github_repo;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        if repo_changed {
            "critical: update source repo changed"
        } else {
            "update auto update config"
        },
        None,
        Some(format!(
            "enabled={} repo={} stream={} auto_update_machines={}",
            config.enabled,
            config.github_repo,
            config.release_stream.as_str(),
            config.auto_update_machines,
        )),
    )?;
    Ok(Json(auto_update_config_summary(&config)))
}

async fn check_auto_update(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AutoUpdateStatusSummary>> {
    let admin = require_admin(&state, &headers)?;
    let status = run_auto_update_check(&state).await?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "check auto update",
        None,
        Some(format!(
            "latest={}",
            status.latest_version.as_deref().unwrap_or("unknown")
        )),
    )?;
    Ok(Json(auto_update_status_summary(&status)))
}

async fn apply_auto_update(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AutoUpdateStatusSummary>> {
    let admin = require_admin(&state, &headers)?;
    let executable_path = std::env::current_exe().map_err(LoreError::Io)?;
    let status = run_auto_update_apply(&state).await?;
    let applied = status.applied;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        if applied {
            "critical: server update applied"
        } else {
            "server update check (already up to date)"
        },
        None,
        Some(status.detail.clone()),
    )?;
    let summary = auto_update_status_summary(&status);
    if applied {
        schedule_server_restart(executable_path);
    }
    Ok(Json(summary))
}

async fn list_admin_librarian_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LibrarianRunsQuery>,
) -> ApiResult<Json<ProjectLibrarianRunSummary>> {
    require_admin(&state, &headers)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let runs = ui_librarian_answers_from_history_all(
        &state.store,
        state.librarian_history.list_recent_all(limit)?,
    )?;
    let pending_actions = ui_pending_librarian_actions_all(
        &state.store,
        state.pending_librarian_actions.list_all(limit)?,
    )?;
    Ok(Json(ProjectLibrarianRunSummary {
        runs,
        pending_actions,
    }))
}

async fn delete_block(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<DeleteBlockQuery>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let project = ProjectName::new(query.project)?;
    let block_id = BlockId::from_string(id)?;
    let actor = authorize_project_write(&state, &headers, &project)?;

    let before = state.store.snapshot_block(&project, &block_id)?;
    match actor {
        RequestActor::Agent(ref agent) => {
            state
                .store
                .delete_block(&project, &block_id, &agent.token)?
        }
        RequestActor::User(_) => state
            .store
            .delete_block_as_project_writer(&project, &block_id)?,
    }
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "Delete block",
        vec![StoredProjectVersionOperation {
            operation_type: ProjectVersionOperationType::DeleteBlock,
            block_id: block_id.clone(),
            before: Some(before),
            after: None,
            document_id: None,
        }],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_project_block(
    State(state): State<AppState>,
    Path((project, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let project = ProjectName::new(project)?;
    let block_id = BlockId::from_string(id)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let before = state.store.snapshot_block(&project, &block_id)?;
    match actor {
        RequestActor::Agent(ref agent) => {
            state
                .store
                .delete_block(&project, &block_id, &agent.token)?
        }
        RequestActor::User(_) => state
            .store
            .delete_block_as_project_writer(&project, &block_id)?,
    }
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "Delete block",
        vec![StoredProjectVersionOperation {
            operation_type: ProjectVersionOperationType::DeleteBlock,
            block_id: block_id.clone(),
            before: Some(before),
            after: None,
            document_id: None,
        }],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_block(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<UpdateBlockRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(payload.project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let update = UpdateBlock {
        project: project.clone(),
        block_id: BlockId::from_string(id)?,
        block_type: payload.block_type,
        content: payload.content,
        author_key: actor_author_value(&actor),
        left: payload.left.map(OrderKey::new).transpose()?,
        right: payload.right.map(OrderKey::new).transpose()?,
        image_upload: None,
    };

    let before = state
        .store
        .snapshot_block(&update.project, &update.block_id)?;
    let block = match actor {
        RequestActor::Agent(_) => state.store.update_block(update)?,
        RequestActor::User(_) => state.store.update_block_as_project_writer(update)?,
    };
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "Update block",
        vec![update_version_operation(
            &state,
            &project,
            &block.id,
            before,
            ProjectVersionOperationType::UpdateBlock,
        )?],
    )?;
    Ok(Json(block))
}

async fn update_project_block(
    State(state): State<AppState>,
    Path((project, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(payload): Json<ProjectBlockUpdateRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let block_id = BlockId::from_string(id)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let after_block_id = payload
        .after_block_id
        .map(BlockId::from_string)
        .transpose()?;
    let (left, right) =
        state
            .store
            .resolve_after_block(&project, after_block_id.as_ref(), Some(&block_id))?;
    let update = UpdateBlock {
        project: project.clone(),
        block_id,
        block_type: payload.block_type,
        content: payload.content,
        author_key: actor_author_value(&actor),
        left,
        right,
        image_upload: None,
    };
    let before = state
        .store
        .snapshot_block(&update.project, &update.block_id)?;
    let block = match actor {
        RequestActor::Agent(_) => state.store.update_block(update)?,
        RequestActor::User(_) => state.store.update_block_as_project_writer(update)?,
    };
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "Update block",
        vec![update_version_operation(
            &state,
            &project,
            &block.id,
            before,
            ProjectVersionOperationType::UpdateBlock,
        )?],
    )?;
    Ok(Json(block))
}

async fn move_block(
    State(state): State<AppState>,
    Path((project, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(payload): Json<MoveBlockRequest>,
) -> ApiResult<Json<Block>> {
    let project = ProjectName::new(project)?;
    let block_id = BlockId::from_string(id)?;
    let after_block_id = payload
        .after_block_id
        .map(BlockId::from_string)
        .transpose()?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let before = state.store.snapshot_block(&project, &block_id)?;
    let block = match actor {
        RequestActor::Agent(ref agent) => state.store.move_block_after(
            &project,
            &block_id,
            after_block_id.as_ref(),
            &agent.token,
        )?,
        RequestActor::User(ref user) => state.store.move_block_after_as_project_writer(
            &project,
            &block_id,
            after_block_id.as_ref(),
            user.username.as_str(),
        )?,
    };
    record_project_version(
        &state,
        &project_version_actor_for_request_actor(&actor),
        &project,
        "Move block",
        vec![update_version_operation(
            &state,
            &project,
            &block.id,
            before,
            ProjectVersionOperationType::MoveBlock,
        )?],
    )?;
    Ok(Json(block))
}

async fn projects_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ProjectPageQuery>,
) -> UiResult<Html<String>> {
    let session = require_ui_session(&state, &headers)?;
    let server_config = state.config.load()?;
    let infos = state.store.list_project_infos()?;
    let visible: Vec<ProjectListEntry> = infos
        .into_iter()
        .filter(|info| session.user.is_admin || session.user.can_read(&info.slug))
        .map(|info| ProjectListEntry {
            can_write: session.user.can_write(&info.slug),
            display_name: info.display_name,
            parent: info.parent,
            sort_order: info.sort_order,
            project: info.slug,
        })
        .collect();
    let mut project_docs = std::collections::HashMap::new();
    for entry in &visible {
        if let Ok(docs) = state.store.list_documents(&entry.project) {
            project_docs.insert(entry.project.as_str().to_string(), docs);
        }
    }
    Ok(Html(render_projects_page(
        resolved_theme(&session.user, &server_config),
        resolved_color_mode(&session.user),
        session.user.username.as_str(),
        session.user.is_admin,
        &visible,
        &project_docs,
        &session.csrf_token,
        query.flash.as_deref(),
    )))
}

async fn admin_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AdminPageQuery>,
) -> UiResult<Html<String>> {
    let session = require_ui_admin(&state, &headers)?;
    let config = state.config.load()?;
    let external_auth_config = state.external_auth.load()?;
    let oidc_config = state.oidc.load()?;
    let auto_update_config = state.auto_update_config.load()?;
    let manager_prompt_config = state.manager_prompt_config.load()?;
    let librarian_config = state.librarian_config.load()?;
    let endpoints = state.endpoint_store.list()?;
    let git_export_config = state.git_export_config.load()?;
    let librarian_audit = state.librarian_history.list_recent_all(12)?;
    let pending_actions = state.pending_librarian_actions.list_all(12)?;
    let auth_audit = state.auth_audit.list_recent(12)?;
    let projects = state.store.list_project_infos()?;
    let all_tokens = state.auth.list_agent_tokens()?;
    let mut user_agents: std::collections::HashMap<String, Vec<AgentTokenSummary>> =
        std::collections::HashMap::new();
    for token in all_tokens {
        let owner_key = token
            .owner
            .as_ref()
            .map(|u| u.as_str().to_string())
            .unwrap_or_else(|| "(unowned)".to_string());
        user_agents
            .entry(owner_key)
            .or_default()
            .push(agent_token_summary(&state, token));
    }
    let all_machines = state.auth.list_all_machines()?;
    let mut user_machines: std::collections::HashMap<String, Vec<StoredMachine>> =
        std::collections::HashMap::new();
    for machine in all_machines {
        user_machines
            .entry(machine.username.as_str().to_string())
            .or_default()
            .push(machine);
    }
    for (username, machines) in &mut user_machines {
        for machine in machines {
            let key = format!("{}_{}", username, machine.name);
            machine.pending_update =
                machine_update_requested(&state, &key, machine.cli_version.as_deref())?;
        }
    }
    Ok(Html(render_admin_page(
        resolved_theme(&session.user, &config),
        resolved_color_mode(&session.user),
        session.user.username.as_str(),
        &session.csrf_token,
        &state.auth.list_roles()?,
        &state
            .auth
            .list_users()?
            .into_iter()
            .map(|user| ui_user_summary(&state, user))
            .collect::<Result<Vec<_>, LoreError>>()?,
        &user_agents,
        &user_machines,
        &config,
        &external_auth_config,
        &oidc_config,
        &auto_update_config,
        &manager_prompt_config,
        &librarian_config,
        &endpoints,
        &git_export_config,
        state.auto_update_status.load()?.as_ref(),
        state.librarian_provider_status.load()?,
        state.git_export_status.load()?.as_ref(),
        &ui_librarian_answers_from_history_all(&state.store, librarian_audit)?,
        &ui_pending_librarian_actions_all(&state.store, pending_actions)?,
        &ui_auth_audit_events(auth_audit),
        &projects,
        query.flash.as_deref(),
        query.section.as_deref().unwrap_or("users"),
    )))
}

async fn agents_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentsPageQuery>,
) -> UiResult<Html<String>> {
    let session = require_ui_session(&state, &headers)?;
    let config = state.config.load()?;
    let mut agents: Vec<AgentTokenSummary> = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?
        .into_iter()
        .map(|token| agent_token_summary(&state, token))
        .collect();
    let mut machines = state.auth.list_machines_for_user(&session.user.username)?;
    for m in &mut machines {
        let key = format!("{}_{}", session.user.username, m.name);
        m.pending_update = machine_update_requested(&state, &key, m.cli_version.as_deref())?;
    }

    // Enrich agents with process status from machine service reports
    {
        for agent in &mut agents {
            agent.process_status = machine_agent_process_status(
                &state,
                session.user.username.as_str(),
                &agent.name,
                agent.machine_name.as_deref(),
            );
            if agent.process_status.as_deref() == Some("restarting") {
                agent.status = "restarting".to_string();
            }
        }
    }

    let user_projects = build_user_project_access(&state, &session.user)?;
    let endpoints = state.endpoint_store.list()?;
    Ok(Html(render_agents_page(
        &config,
        session.user.username.as_str(),
        session.user.is_admin,
        resolved_theme(&session.user, &config),
        resolved_color_mode(&session.user),
        &session.csrf_token,
        &agents,
        &machines,
        &user_projects,
        &endpoints,
        query.selected.as_deref(),
        query.flash.as_deref(),
    )))
}

async fn agent_guide_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> UiResult<Html<String>> {
    let session = require_ui_session(&state, &headers)?;
    let config = state.config.load()?;
    Ok(Html(render_agent_guide_page(
        &config,
        resolved_theme(&session.user, &config),
        resolved_color_mode(&session.user),
        session.user.username.as_str(),
        session.user.is_admin,
        &session.csrf_token,
    )))
}

async fn update_agent_grants_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UpdateAgentGrantsUiForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let grants = parse_agent_grants(&form.grants)?;
    validate_user_grants(&state, &session.user, &grants)?;
    state
        .auth
        .update_agent_token_grants(&name, &session.user.username, grants)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update agent grants",
        Some(name.clone()),
        None,
    )?;
    Ok(Redirect::to(&format!(
        "/ui/agents?selected={}&flash=Agent%20updated",
        urlencoding::encode(&name),
    ))
    .into_response())
}

async fn rotate_agent_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let created = state
        .auth
        .rotate_agent_token(&name, &session.user.username)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "rotate agent token",
        Some(name.clone()),
        None,
    )?;
    Ok(Redirect::to(&format!(
        "/ui/agents?selected={}&created_token={}&flash=Token%20regenerated.%20Copy%20it%20now.",
        urlencoding::encode(&name),
        urlencoding::encode(&created.token),
    ))
    .into_response())
}

async fn delete_agent_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let agent = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?
        .into_iter()
        .find(|agent| agent.name == name)
        .ok_or_else(|| LoreError::Validation("agent does not exist".into()))?;
    if let Some(machine_name) = agent.machine_name.as_deref() {
        let machine_key = format!("{}_{}", session.user.username, machine_name);
        let params = json!({ "agent_name": name });
        let result =
            queue_machine_command_and_wait(&state, &machine_key, "remove_agent", params).await?;
        if let Some(error) = result.get("error").and_then(|v| v.as_str()) {
            return Err(LoreError::Validation(error.to_string()).into());
        }
    }
    state
        .auth
        .revoke_agent_token(&name, &session.user.username)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "delete agent",
        Some(name.clone()),
        None,
    )?;
    Ok(Redirect::to("/ui/agents?flash=Agent%20deleted").into_response())
}

fn build_user_project_access(
    state: &AppState,
    user: &AuthenticatedUser,
) -> Result<Vec<UserProjectAccess>, LoreError> {
    let projects = state.store.list_project_infos()?;
    Ok(projects
        .into_iter()
        .filter_map(|p| {
            if user.is_admin {
                Some(UserProjectAccess {
                    slug: p.slug.as_str().to_string(),
                    display_name: p.display_name,
                    max_permission: ProjectPermission::ReadWrite,
                })
            } else {
                let max_perm = user
                    .roles
                    .iter()
                    .flat_map(|role| &role.grants)
                    .filter(|grant| grant.project == p.slug)
                    .map(|grant| grant.permission)
                    .max_by_key(|perm| if perm.allows_write() { 1 } else { 0 });
                max_perm.map(|perm| UserProjectAccess {
                    slug: p.slug.as_str().to_string(),
                    display_name: p.display_name,
                    max_permission: perm,
                })
            }
        })
        .collect())
}

fn validate_user_grants(
    state: &AppState,
    user: &AuthenticatedUser,
    grants: &[ProjectGrant],
) -> Result<(), LoreError> {
    for grant in grants {
        if user.is_admin {
            continue;
        }
        let user_can_write = user
            .roles
            .iter()
            .flat_map(|role| &role.grants)
            .any(|g| g.project == grant.project && g.permission.allows_write());
        let user_can_read = user
            .roles
            .iter()
            .flat_map(|role| &role.grants)
            .any(|g| g.project == grant.project);
        if grant.permission.allows_write() && !user_can_write {
            return Err(LoreError::Validation(format!(
                "you do not have write access to project {}",
                grant.project.as_str()
            )));
        }
        if !user_can_read {
            return Err(LoreError::Validation(format!(
                "you do not have access to project {}",
                grant.project.as_str()
            )));
        }
    }
    Ok(())
}

async fn settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SettingsPageQuery>,
) -> UiResult<Html<String>> {
    let session = require_ui_session(&state, &headers)?;
    let config = state.config.load()?;
    let preview_theme = query
        .preview
        .as_deref()
        .and_then(|s| UiTheme::parse(s).ok());
    let preview_mode = query.mode.as_deref().and_then(|s| ColorMode::parse(s).ok());
    let theme = preview_theme.unwrap_or_else(|| resolved_theme(&session.user, &config));
    let color_mode = preview_mode.unwrap_or_else(|| resolved_color_mode(&session.user));
    Ok(Html(render_settings_page(
        theme,
        color_mode,
        session.user.username.as_str(),
        &session.csrf_token,
        session.user.theme,
        session.user.color_mode,
        config.default_theme,
        session.user.is_admin,
        query.flash.as_deref(),
    )))
}

async fn create_project_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateProjectUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let parent = if form.parent.trim().is_empty() {
        None
    } else {
        Some(form.parent.trim())
    };
    let info = state.store.create_project(&form.project_name, parent)?;
    state
        .auth
        .remove_project_from_all_agent_grants(&info.slug)?;
    // Create an initial markdown block so the user can start editing immediately
    let initial_block = NewBlock {
        project: info.slug.clone(),
        block_type: BlockType::Markdown,
        content: String::new(),
        author_key: session.user.username.to_string(),
        left: None,
        right: None,
        image_upload: None,
    };
    state.store.create_block_as_project_writer(initial_block)?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Project%20created",
        info.slug.as_str(),
    )))
}

async fn update_agent_context_from_ui(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AgentContextUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    state.auth.authorize_write(&session.user, &project)?;
    state
        .store
        .write_agent_context(&project, &form.agent_context)?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Agent%20context%20saved",
        project.as_str(),
    )))
}

async fn update_reserved_block_from_ui(
    State(state): State<AppState>,
    Path((project, block_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<ReservedBlockUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    state.auth.authorize_write(&session.user, &project)?;
    state
        .store
        .update_reserved_block(&project, &block_id, &form.content, false)?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Saved",
        project.as_str(),
    )))
}

async fn document_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Query(query): Query<ProjectPageQuery>,
) -> UiResult<Html<String>> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_read(&session.user, &project)?;
    let meta = state.store.read_project_meta(&project);
    let doc_id = DocumentId::from_string(doc_id)?;
    let blocks = state.store.list_doc_blocks(&project, &doc_id)?;
    let all_docs = state.store.list_documents(&project).unwrap_or_default();
    let child_docs = find_doc_children(&all_docs, &doc_id);
    let doc_name = find_doc_name(&all_docs, &doc_id).unwrap_or_else(|| "Document".to_string());
    let server_config = state.config.load()?;
    let page = render_document_page(
        resolved_theme(&session.user, &server_config),
        resolved_color_mode(&session.user),
        &project,
        &meta.display_name,
        doc_id.as_str(),
        &doc_name,
        &blocks,
        &child_docs,
        query.flash.as_deref(),
        session.user.username.as_str(),
        session.user.can_write(&project),
        session.user.is_admin,
        &session.csrf_token,
        &state.store,
    );
    Ok(Html(page))
}

fn find_doc_name(docs: &[crate::store::DocumentInfo], target: &DocumentId) -> Option<String> {
    for doc in docs {
        if doc.id == *target {
            return Some(doc.display_name.clone());
        }
        if let Some(name) = find_doc_name(&doc.children, target) {
            return Some(name);
        }
    }
    None
}

fn find_doc_children(
    docs: &[crate::store::DocumentInfo],
    target: &DocumentId,
) -> Vec<crate::store::DocumentInfo> {
    for doc in docs {
        if doc.id == *target {
            return doc.children.clone();
        }
        let found = find_doc_children(&doc.children, target);
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

async fn create_document_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Form(form): Form<CreateDocumentUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    state.auth.authorize_write(&session.user, &project)?;
    let parent_doc = form
        .parent_document_id
        .filter(|s| !s.is_empty())
        .map(DocumentId::from_string)
        .transpose()?;
    let doc = state
        .store
        .create_document(&project, parent_doc.as_ref(), &form.name)?;
    Ok(Redirect::to(&format!(
        "/ui/{}/doc/{}?flash=Document%20created",
        project.as_str(),
        doc.id.as_str(),
    )))
}

async fn rename_document_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Form(form): Form<RenameDocumentUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    state.auth.authorize_write(&session.user, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    state.store.rename_document(&project, &doc_id, &form.name)?;
    Ok(Redirect::to(&format!(
        "/ui/{}/doc/{}?flash=Document%20renamed",
        project.as_str(),
        doc_id.as_str(),
    )))
}

async fn delete_document_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    Form(form): Form<DeleteDocumentUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    state.auth.authorize_write(&session.user, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    state.store.delete_document(&project, &doc_id)?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Document%20deleted",
        project.as_str(),
    )))
}

async fn create_doc_block_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id)): Path<(String, String)>,
    multipart: Multipart,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    let form = parse_create_block_form(multipart).await?;
    verify_csrf(&session, &form.csrf_token)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let after_block_id = form.after_block_id.map(BlockId::from_string).transpose()?;
    let (left, right) =
        state
            .store
            .resolve_after_doc_block(&project, &doc_id, after_block_id.as_ref(), None)?;
    let new_block = NewBlock {
        project: project.clone(),
        block_type: form.block_type,
        content: form.content,
        author_key: session.user.username.as_str().to_string(),
        left,
        right,
        image_upload: form.image_upload,
    };
    let block = state
        .store
        .create_doc_block_as_project_writer(&doc_id, new_block)?;
    let version_op = create_doc_version_operation(&state, &project, &doc_id, &block.id)?;
    let actor = ProjectVersionActor {
        kind: ProjectVersionActorKind::User,
        name: session.user.username.as_str().to_string(),
    };
    record_project_version(
        &state,
        &actor,
        &project,
        "create document block",
        vec![version_op],
    )?;
    Ok(Redirect::to(&format!(
        "/ui/{}/doc/{}?flash=Block%20created",
        project.as_str(),
        doc_id.as_str(),
    )))
}

async fn update_doc_block_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, id)): Path<(String, String, String)>,
    multipart: Multipart,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    let doc_id_parsed = DocumentId::from_string(doc_id.clone())?;
    let block_id = BlockId::from_string(id)?;
    let form = parse_update_block_form(multipart).await?;
    verify_csrf(&session, &form.csrf_token)?;
    let block_type = match form.block_type {
        Some(bt) => bt,
        None => {
            let existing = state
                .store
                .get_doc_block(&project, &doc_id_parsed, &block_id)?;
            existing.block_type
        }
    };
    let (left, right) = match form.after_block_id {
        Some(aid) => {
            let after_id = BlockId::from_string(aid)?;
            state.store.resolve_after_doc_block(
                &project,
                &doc_id_parsed,
                Some(&after_id),
                Some(&block_id),
            )?
        }
        None => (None, None),
    };
    let before = state
        .store
        .snapshot_doc_block(&project, &doc_id_parsed, &block_id)?;
    let update = UpdateBlock {
        project: project.clone(),
        block_id: block_id.clone(),
        block_type,
        content: form.content,
        author_key: session.user.username.as_str().to_string(),
        left,
        right,
        image_upload: form.image_upload,
    };
    state
        .store
        .update_doc_block_as_project_writer(&doc_id_parsed, update)?;
    let version_op = update_doc_version_operation(
        &state,
        &project,
        &doc_id_parsed,
        &block_id,
        before,
        ProjectVersionOperationType::UpdateBlock,
    )?;
    let actor = ProjectVersionActor {
        kind: ProjectVersionActorKind::User,
        name: session.user.username.as_str().to_string(),
    };
    record_project_version(
        &state,
        &actor,
        &project,
        "update document block",
        vec![version_op],
    )?;
    Ok(Redirect::to(&format!(
        "/ui/{}/doc/{}?flash=Block%20saved",
        project.as_str(),
        doc_id,
    )))
}

async fn delete_doc_block_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, id)): Path<(String, String, String)>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    state.auth.authorize_write(&session.user, &project)?;
    let doc_id_parsed = DocumentId::from_string(doc_id.clone())?;
    let block_id = BlockId::from_string(id)?;
    let before = state
        .store
        .snapshot_doc_block(&project, &doc_id_parsed, &block_id)?;
    state
        .store
        .delete_doc_block_as_project_writer(&project, &doc_id_parsed, &block_id)?;
    let version_op = StoredProjectVersionOperation {
        operation_type: ProjectVersionOperationType::DeleteBlock,
        block_id,
        before: Some(before),
        after: None,
        document_id: Some(doc_id.clone()),
    };
    let actor = ProjectVersionActor {
        kind: ProjectVersionActorKind::User,
        name: session.user.username.as_str().to_string(),
    };
    record_project_version(
        &state,
        &actor,
        &project,
        "delete document block",
        vec![version_op],
    )?;
    Ok(Redirect::to(&format!(
        "/ui/{}/doc/{}?flash=Block%20deleted",
        project.as_str(),
        doc_id,
    )))
}

async fn toggle_doc_block_pin_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, id)): Path<(String, String, String)>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    state.auth.authorize_write(&session.user, &project)?;
    let doc_id_parsed = DocumentId::from_string(doc_id.clone())?;
    let block_id = BlockId::from_string(id)?;
    let block = state
        .store
        .get_doc_block(&project, &doc_id_parsed, &block_id)?;
    let update = UpdateBlock {
        project: project.clone(),
        block_id,
        block_type: block.block_type,
        content: block.content,
        author_key: session.user.username.as_str().to_string(),
        left: None,
        right: None,
        image_upload: None,
    };
    state
        .store
        .update_doc_block_as_project_writer(&doc_id_parsed, update)?;
    Ok(Redirect::to(&format!(
        "/ui/{}/doc/{}",
        project.as_str(),
        doc_id,
    )))
}

async fn rename_project_from_ui(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RenameProjectUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    let slug_change = state.store.rename_project(&project, &form.display_name)?;
    let redirect_slug = if let Some((old_slug, new_slug)) = slug_change {
        if let Err(e) = state.auth.rename_project_in_grants(&old_slug, &new_slug) {
            eprintln!("warning: failed to update grants after rename: {e}");
        }
        new_slug
    } else {
        project
    };
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Project%20renamed",
        redirect_slug.as_str(),
    )))
}

async fn move_project_from_ui(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Form(form): Form<MoveProjectUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    let new_parent = if form.new_parent.trim().is_empty() {
        None
    } else {
        Some(form.new_parent.trim())
    };
    let after = if form.after.trim().is_empty() {
        None
    } else {
        Some(form.after.trim())
    };
    state.store.move_project(&project, new_parent, after)?;
    Ok(Redirect::to("/ui?flash=Project%20moved"))
}

#[derive(Debug, Deserialize)]
struct CsrfOnlyForm {
    csrf_token: String,
}

async fn delete_project_from_ui(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfOnlyForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let project = ProjectName::new(&project)?;
    state.store.delete_project(&project)?;
    Ok(Redirect::to("/ui?flash=Project%20deleted"))
}

async fn create_role_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateRoleUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let role_name = form.name.clone();
    state.auth.create_role(NewRole {
        name: RoleName::new(form.name)?,
        grants: parse_role_grants(&form.grants)?,
    })?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "create role",
        Some(role_name),
        None,
    )?;
    Ok(Redirect::to("/ui/admin?section=roles&flash=Role%20created"))
}

async fn update_role_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UpdateRoleUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let role_name = name.clone();
    state.auth.update_role(NewRole {
        name: RoleName::new(name)?,
        grants: parse_role_grants(&form.grants)?,
    })?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update role",
        Some(role_name),
        None,
    )?;
    Ok(Redirect::to("/ui/admin?section=roles&flash=Role%20updated"))
}

async fn create_user_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateUserUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let username = form.username.clone();
    state.auth.create_user(NewUser {
        username: UserName::new(form.username)?,
        password: form.password,
        role_names: parse_role_names_csv(&form.roles)?,
        is_admin: form.is_admin.as_deref() == Some("true"),
    })?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "create user",
        Some(username),
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=User%20created"))
}

async fn update_user_password_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<UpdateUserPasswordUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let username = UserName::new(username)?;
    state.auth.update_user_password(&username, form.password)?;
    state.auth.revoke_sessions_for_user(&username)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "reset user password",
        Some(username.as_str().to_string()),
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=User%20password%20updated"))
}

async fn disable_user_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state
        .auth
        .set_user_disabled(&UserName::new(&username)?, true)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "disable user",
        Some(username),
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=User%20disabled"))
}

async fn enable_user_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state
        .auth
        .set_user_disabled(&UserName::new(&username)?, false)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "enable user",
        Some(username),
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=User%20enabled"))
}

async fn revoke_user_sessions_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state
        .auth
        .revoke_sessions_for_user(&UserName::new(&username)?)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "revoke user sessions",
        Some(username),
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=User%20sessions%20revoked"))
}

async fn update_setup_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateSetupUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let current_theme = state.config.load()?.default_theme;
    state.config.update(
        ExternalScheme::parse(&form.external_scheme)?,
        form.external_host,
        form.external_port,
        current_theme,
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update setup address",
        None,
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=Setup%20address%20saved"))
}

async fn update_theme_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateThemeUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let theme = if form.theme.trim().is_empty() {
        None
    } else {
        Some(UiTheme::parse(&form.theme)?)
    };
    let color_mode = if form.color_mode.trim().is_empty() || form.color_mode.trim() == "system" {
        None
    } else {
        Some(ColorMode::parse(&form.color_mode)?)
    };
    state
        .auth
        .update_user_theme(&session.user.username, theme, color_mode)?;
    // If admin is the only user, also set as server default theme
    if session.user.is_admin {
        if let Some(t) = theme {
            let users = state.auth.list_users()?;
            if users.len() == 1 {
                let config = state.config.load()?;
                let _ = state.config.update(
                    config.external_scheme,
                    config.external_host.clone(),
                    config.external_port,
                    t,
                );
            }
        }
    }
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update user theme",
        Some(session.user.username.as_str().to_string()),
        Some(
            theme
                .map(|value| format!("theme={}", value.as_str()))
                .unwrap_or_else(|| "theme=default".into()),
        ),
    )?;
    Ok(Redirect::to("/ui/settings?flash=Theme%20saved"))
}

async fn update_librarian_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateLibrarianUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let existing = state.librarian_config.load()?;
    let endpoint_id = form.endpoint_id.filter(|id| !id.is_empty());
    state.librarian_config.update(
        endpoint_id,
        form.request_timeout_secs
            .unwrap_or(existing.request_timeout_secs),
        form.max_concurrent_runs
            .unwrap_or(existing.max_concurrent_runs),
        form.action_requires_approval.as_deref() == Some("true"),
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update librarian config",
        None,
        None,
    )?;
    Ok(Redirect::to(
        "/ui/admin?section=librarian&flash=Librarian%20config%20saved",
    ))
}

async fn test_librarian_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LibrarianProviderTestUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let (endpoint, config) = resolve_librarian_endpoint(&state)?;
    let status = state
        .librarian_client
        .healthcheck(&endpoint, config.request_timeout_secs)
        .await?;
    let ok = status.ok;
    state.librarian_provider_status.save(&status)?;
    let flash = if ok {
        "Librarian%20provider%20test%20succeeded"
    } else {
        "Librarian%20provider%20test%20failed"
    };
    Ok(Redirect::to(&format!(
        "/ui/admin?section=librarian&flash={flash}"
    )))
}

async fn create_endpoint_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateEndpointUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let kind = crate::librarian::infer_kind_from_url(&form.url);
    let api_key = if form.api_key.is_empty() {
        None
    } else {
        Some(form.api_key)
    };
    let ep = state
        .endpoint_store
        .create(form.name, kind, form.url, form.model, api_key)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        &format!("create endpoint: {}", ep.name),
        None,
        None,
    )?;
    Ok(Redirect::to(
        "/ui/admin?section=endpoints&flash=Endpoint%20created",
    ))
}

async fn update_endpoint_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<UpdateEndpointUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let kind = crate::librarian::infer_kind_from_url(&form.url);
    let ep = state.endpoint_store.update(
        &id,
        form.name,
        kind,
        form.url,
        form.model,
        api_key_update_from_form(&form.api_key, form.clear_api_key.as_deref()),
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        &format!("update endpoint: {}", ep.name),
        None,
        None,
    )?;
    Ok(Redirect::to(
        "/ui/admin?section=endpoints&flash=Endpoint%20saved",
    ))
}

async fn delete_endpoint_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<DeleteEndpointUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.endpoint_store.delete(&id)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "delete endpoint",
        None,
        None,
    )?;
    Ok(Redirect::to(
        "/ui/admin?section=endpoints&flash=Endpoint%20deleted",
    ))
}

async fn test_endpoint_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<TestEndpointUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let endpoint = state
        .endpoint_store
        .get(&id)?
        .ok_or_else(|| LoreError::Validation("endpoint not found".into()))?;
    let config = state.librarian_config.load()?;
    let status = state
        .librarian_client
        .healthcheck(&endpoint, config.request_timeout_secs)
        .await?;
    let flash = if status.ok {
        "Endpoint%20test%20succeeded"
    } else {
        "Endpoint%20test%20failed"
    };
    Ok(Redirect::to(&format!(
        "/ui/admin?section=endpoints&flash={flash}"
    )))
}

async fn list_models_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ListModelsRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_ui_admin(&state, &headers)?;
    let config = state.librarian_config.load()?;
    let timeout = config.request_timeout_secs;

    let (url, api_key) = if let Some(ref eid) = payload.endpoint_id {
        let ep = state
            .endpoint_store
            .get(eid)?
            .ok_or_else(|| LoreError::Validation("endpoint not found".into()))?;
        let url = payload.url.as_deref().unwrap_or(&ep.url).to_string();
        let key = payload.api_key.clone().or_else(|| ep.api_key.clone());
        (url, key)
    } else {
        let url = payload
            .url
            .clone()
            .ok_or_else(|| LoreError::Validation("url is required".into()))?;
        (url, payload.api_key.clone())
    };

    let models = crate::librarian::list_provider_models(&url, api_key.as_deref(), timeout).await?;
    Ok(Json(serde_json::json!({ "models": models })))
}

async fn update_git_export_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateGitExportUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.git_export_config.update(
        form.enabled.as_deref() == Some("true"),
        form.remote_url,
        form.branch,
        git_export_token_update_from_form(&form.token, form.clear_token.as_deref()),
        form.author_name,
        form.author_email,
        form.auto_export.as_deref() == Some("true"),
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update git export config",
        None,
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=Git%20export%20saved"))
}

async fn sync_git_export_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<GitExportSyncUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let status = run_manual_git_export(&state, "Manual admin export")?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "run git export",
        None,
        None,
    )?;
    let flash = if status.ok {
        "Git%20export%20succeeded"
    } else {
        "Git%20export%20failed"
    };
    Ok(Redirect::to(&format!("/ui/admin?flash={flash}")))
}

async fn update_external_auth_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateExternalAuthUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.external_auth.update(
        form.enabled.as_deref() == Some("true"),
        form.username_header,
        form.secret_header,
        external_auth_secret_update_from_form(&form.secret_value, form.clear_secret.as_deref()),
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update external auth config",
        None,
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=External%20auth%20saved"))
}

async fn update_oidc_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateOidcUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.oidc.update(
        form.enabled.as_deref() == Some("true"),
        form.issuer_url,
        form.client_id,
        oidc_secret_update_from_form(&form.client_secret, form.clear_client_secret.as_deref()),
        form.callback_path,
        OidcUsernameClaim::parse(&form.username_claim)?,
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update oidc config",
        None,
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=OIDC%20saved"))
}

async fn toggle_auto_update_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> ApiResult<axum::Json<serde_json::Value>> {
    let session = require_ui_admin(&state, &headers)?;
    let csrf = form.get("csrf_token").map(|s| s.as_str()).unwrap_or("");
    verify_csrf(&session, csrf)?;
    let enabled = form.get("enabled").map(|s| s == "true").unwrap_or(false);
    let current = state.auto_update_config.load()?;
    let release_stream = form
        .get("release_stream")
        .and_then(|value| parse_release_stream(value))
        .unwrap_or(current.release_stream);
    let auto_update_machines = form
        .get("auto_update_machines")
        .map(|s| s == "true")
        .unwrap_or(current.auto_update_machines);
    state.auto_update_config.update(
        enabled,
        current.github_repo,
        release_stream,
        auto_update_machines,
    )?;
    Ok(axum::Json(serde_json::json!({ "ok": true })))
}

async fn update_auto_update_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateAutoUpdateUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let current_config = state.auto_update_config.load()?;
    let release_stream = form.release_stream.unwrap_or(current_config.release_stream);
    let auto_update_machines = form.auto_update_machines.as_deref() == Some("true");
    if form.github_repo != current_config.github_repo {
        let password = form.confirm_password.as_deref().unwrap_or("");
        state
            .auth
            .authenticate(session.user.username.as_str(), password)
            .map_err(|_| {
                LoreError::Validation(
                    "password confirmation required when changing the update source repository"
                        .into(),
                )
            })?;
    }
    let config = state.auto_update_config.update(
        form.enabled.as_deref() == Some("true"),
        form.github_repo,
        release_stream,
        auto_update_machines,
    )?;
    let repo_changed = config.github_repo != current_config.github_repo;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        if repo_changed {
            "critical: update source repo changed"
        } else {
            "update auto update config"
        },
        None,
        Some(format!(
            "enabled={} repo={} stream={} auto_update_machines={}",
            config.enabled,
            config.github_repo,
            config.release_stream.as_str(),
            config.auto_update_machines,
        )),
    )?;
    Ok(Redirect::to("/ui/admin?flash=Auto%20update%20saved"))
}

fn manager_prompt_override_from_form(enabled: bool, text: Option<String>) -> ManagerPromptOverride {
    ManagerPromptOverride {
        enabled,
        text: text.unwrap_or_default(),
    }
}

async fn update_manager_prompts_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateManagerPromptsUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;

    let config = ManagerPromptConfig::new(
        manager_prompt_override_from_form(
            form.review_latest_output_enabled.as_deref() == Some("true"),
            form.review_latest_output_text,
        ),
        manager_prompt_override_from_form(
            form.run_periodic_checks_enabled.as_deref() == Some("true"),
            form.run_periodic_checks_text,
        ),
        manager_prompt_override_from_form(
            form.validate_periodic_checks_enabled.as_deref() == Some("true"),
            form.validate_periodic_checks_text,
        ),
    );
    state.manager_prompt_config.save(&config)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update manager prompts",
        None,
        Some(format!(
            "review_latest_output={} run_periodic_checks={} validate_periodic_checks={}",
            config.review_latest_output.enabled,
            config.run_periodic_checks.enabled,
            config.validate_periodic_checks.enabled,
        )),
    )?;
    Ok(Redirect::to(
        "/ui/admin?section=manager&flash=Manager%20prompts%20saved",
    ))
}

async fn check_auto_update_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AutoUpdateCheckUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let status = run_auto_update_check(&state).await?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "check auto update",
        None,
        Some(format!(
            "latest={}",
            status.latest_version.as_deref().unwrap_or("unknown")
        )),
    )?;
    let flash = if status.ok {
        "Auto%20update%20check%20completed"
    } else {
        "Auto%20update%20check%20failed"
    };
    Ok(Redirect::to(&format!("/ui/admin?flash={flash}")))
}

async fn apply_auto_update_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AutoUpdateApplyUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let executable_path = std::env::current_exe().map_err(LoreError::Io)?;
    let status = run_auto_update_apply(&state).await?;
    let applied = status.applied;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        if applied {
            "critical: server update applied"
        } else {
            "server update check (already up to date)"
        },
        None,
        Some(status.detail.clone()),
    )?;
    let flash = if applied {
        schedule_server_restart(executable_path);
        "Update%20applied%20—%20server%20restarting"
    } else {
        "Already%20up%20to%20date"
    };
    Ok(Redirect::to(&format!("/ui/admin?flash={flash}")))
}

async fn check_auto_update_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AutoUpdateCheckUiForm>,
) -> ApiResult<Json<AutoUpdateStatusSummary>> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let status = run_auto_update_check(&state).await?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "check auto update",
        None,
        Some(format!(
            "latest={}",
            status.latest_version.as_deref().unwrap_or("unknown")
        )),
    )?;
    Ok(Json(auto_update_status_summary(&status)))
}

async fn apply_auto_update_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AutoUpdateApplyUiForm>,
) -> ApiResult<Json<AutoUpdateStatusSummary>> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let executable_path = std::env::current_exe().map_err(LoreError::Io)?;
    let status = run_auto_update_apply(&state).await?;
    let applied = status.applied;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        if applied {
            "critical: server update applied"
        } else {
            "server update check (already up to date)"
        },
        None,
        Some(status.detail.clone()),
    )?;
    let summary = auto_update_status_summary(&status);
    if applied {
        schedule_server_restart(executable_path);
    }
    Ok(Json(summary))
}

async fn update_all_machines_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AutoUpdateCheckUiForm>,
) -> ApiResult<Json<serde_json::Value>> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let server_version = env!("CARGO_PKG_VERSION");
    let all_machines = state.auth.list_all_machines()?;
    let mut count = 0usize;
    for m in &all_machines {
        let outdated = m
            .cli_version
            .as_deref()
            .map(|v| v.trim_start_matches('v') != server_version)
            .unwrap_or(true);
        if outdated {
            let key = format!("{}_{}", m.username, m.name);
            set_machine_pending_update(&state, &key);
            count += 1;
        }
    }
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "update all machines",
        None,
        Some(format!("{count} machines queued for update")),
    )?;
    notify_all_machine_polls(&state);
    Ok(Json(serde_json::json!({ "count": count })))
}

#[derive(Deserialize)]
struct ProfilePicForm {
    csrf_token: String,
    data_url: String,
}

async fn upload_profile_pic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent): Path<String>,
    Form(form): Form<ProfilePicForm>,
) -> UiResult<Json<serde_json::Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let owner = session.user.username.as_str();

    // Validate it's a data URL with an image content type
    if !form.data_url.starts_with("data:image/") {
        return Err(LoreError::Validation("Invalid image data".into()).into());
    }
    // Cap at ~200KB to keep chat store reasonable
    if form.data_url.len() > 200_000 {
        return Err(LoreError::Validation("Image too large (max ~150KB)".into()).into());
    }

    state
        .chat
        .update_profile_url(owner, &agent, Some(form.data_url))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn project_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<ProjectPageQuery>,
) -> UiResult<Html<String>> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_read(&session.user, &project)?;
    let meta = state.store.read_project_meta(&project);
    let _ = state.store.ensure_reserved_blocks(&project);
    let mut reserved_blocks = Vec::new();
    for &rid in crate::model::RESERVED_BLOCK_IDS {
        if let Ok(block) = state.store.get_reserved_block(&project, rid) {
            reserved_blocks.push(block);
        }
    }
    let documents = state.store.list_documents(&project).unwrap_or_default();
    let server_config = state.config.load()?;
    let page = render_project_page(
        resolved_theme(&session.user, &server_config),
        resolved_color_mode(&session.user),
        &project,
        &meta.display_name,
        meta.id.as_deref().unwrap_or(""),
        &reserved_blocks,
        &documents,
        query.flash.as_deref(),
        session.user.username.as_str(),
        session.user.can_write(&project),
        session.user.is_admin,
        &session.csrf_token,
    );
    Ok(Html(page))
}

async fn project_audit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> UiResult<Html<String>> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_read(&session.user, &project)?;
    let meta = state.store.read_project_meta(&project);
    let runs = ui_librarian_answers_from_history(
        &state.store,
        &project,
        state.librarian_history.list_recent_project(&project, 50)?,
    )?;
    let pending = ui_pending_librarian_actions(
        &state.store,
        &project,
        state.pending_librarian_actions.list_project(&project, 50)?,
    )?;
    Ok(Html(render_project_audit_page(
        resolved_theme(&session.user, &state.config.load()?),
        resolved_color_mode(&session.user),
        &project,
        &meta.display_name,
        session.user.username.as_str(),
        session.user.is_admin,
        session.user.can_write(&project),
        &session.csrf_token,
        &runs,
        &pending,
    )))
}

async fn admin_audit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> UiResult<Html<String>> {
    let session = require_ui_admin(&state, &headers)?;
    let runs = ui_librarian_answers_from_history_all(
        &state.store,
        state.librarian_history.list_recent_all(100)?,
    )?;
    let pending = ui_pending_librarian_actions_all(
        &state.store,
        state.pending_librarian_actions.list_all(100)?,
    )?;
    Ok(Html(render_admin_audit_page(
        resolved_theme(&session.user, &state.config.load()?),
        resolved_color_mode(&session.user),
        session.user.username.as_str(),
        &session.csrf_token,
        &runs,
        &pending,
        &ui_auth_audit_events(state.auth_audit.list_recent(100)?),
    )))
}

async fn project_history_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> UiResult<Html<String>> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_read(&session.user, &project)?;
    let meta = state.store.read_project_meta(&project);
    let versions = ui_project_versions(state.project_history.list_recent_project(&project, 100)?);
    Ok(Html(render_project_history_page(
        resolved_theme(&session.user, &state.config.load()?),
        resolved_color_mode(&session.user),
        &project,
        &meta.display_name,
        session.user.username.as_str(),
        session.user.is_admin,
        session.user.can_write(&project),
        &session.csrf_token,
        &versions,
    )))
}

async fn answer_librarian(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(payload): Json<AskLibrarianRequest>,
) -> ApiResult<Json<LibrarianAnswerBody>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_read(&state, &headers, &project)?;
    let options = librarian_options_from_request(&payload)?;
    let user_scope = match &actor {
        RequestActor::User(u) => Some(u.clone()),
        _ => None,
    };
    let answer = answer_librarian_for_project(
        &state,
        &project,
        payload.question,
        options,
        librarian_actor_for_request_actor(&actor),
        user_scope.as_ref(),
    )
    .await?;
    Ok(Json(answer))
}

async fn answer_librarian_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Form(form): Form<AskLibrarianForm>,
) -> UiResult<Response> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_read(&session.user, &project)?;
    verify_csrf(&session, &form.csrf_token)?;
    let options = librarian_options_from_form(&form)?;
    let allow_edits = form.allow_edits.as_deref() == Some("1");
    if allow_edits && session.user.can_write(&project) {
        let _ = execute_project_librarian_action(
            &state,
            &project,
            form.question,
            options,
            &session.user,
        )
        .await?;
    } else {
        let _ = answer_librarian_for_project(
            &state,
            &project,
            form.question,
            options,
            librarian_actor_for_user(&session.user),
            Some(&session.user),
        )
        .await?;
    };
    Ok(Redirect::to(&format!(
        "/ui/chat?agent=librarian&project={}",
        urlencoding::encode(project.as_str())
    ))
    .into_response())
}

async fn run_project_librarian_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(payload): Json<ProjectLibrarianActionRequest>,
) -> ApiResult<Json<ProjectLibrarianActionBody>> {
    let project = ProjectName::new(project)?;
    let actor = require_authenticated_actor(&state, &headers)?;
    let user = match actor {
        RequestActor::User(user) => user,
        RequestActor::Agent(_) => return Err(LoreError::PermissionDenied.into()),
    };
    let options = action_librarian_options_from_request(&payload)?;
    let result =
        execute_project_librarian_action(&state, &project, payload.instruction, options, &user)
            .await?;
    Ok(Json(result))
}

async fn run_project_librarian_action_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Form(form): Form<ProjectLibrarianActionForm>,
) -> UiResult<Response> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let options = action_librarian_options_from_form(&form)?;
    let _ = execute_project_librarian_action(
        &state,
        &project,
        form.instruction,
        options,
        &session.user,
    )
    .await?;
    Ok(Redirect::to(&format!(
        "/ui/chat?agent=librarian&project={}",
        urlencoding::encode(project.as_str())
    ))
    .into_response())
}

async fn approve_project_librarian_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
) -> ApiResult<Json<ProjectLibrarianActionBody>> {
    let project = ProjectName::new(project)?;
    let actor = require_authenticated_actor(&state, &headers)?;
    let user = match actor {
        RequestActor::User(user) => user,
        RequestActor::Agent(_) => return Err(LoreError::PermissionDenied.into()),
    };
    Ok(Json(
        approve_pending_project_librarian_action(&state, &project, &id, &user).await?,
    ))
}

async fn reject_project_librarian_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let project = ProjectName::new(project)?;
    let actor = require_authenticated_actor(&state, &headers)?;
    let user = match actor {
        RequestActor::User(user) => user,
        RequestActor::Agent(_) => return Err(LoreError::PermissionDenied.into()),
    };
    reject_pending_project_librarian_action(&state, &project, &id, &user)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn approve_project_librarian_action_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    approve_pending_project_librarian_action(&state, &project, &id, &session.user).await?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Pending%20project%20librarian%20action%20approved",
        project.as_str()
    )))
}

async fn reject_project_librarian_action_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    reject_pending_project_librarian_action(&state, &project, &id, &session.user)?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Pending%20project%20librarian%20action%20rejected",
        project.as_str()
    )))
}

async fn list_project_librarian_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<LibrarianRunsQuery>,
) -> ApiResult<Json<ProjectLibrarianRunSummary>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    Ok(Json(ProjectLibrarianRunSummary {
        runs: ui_librarian_answers_from_history(
            &state.store,
            &project,
            state
                .librarian_history
                .list_recent_project(&project, limit)?,
        )?,
        pending_actions: ui_pending_librarian_actions(
            &state.store,
            &project,
            state
                .pending_librarian_actions
                .list_project(&project, limit)?,
        )?,
    }))
}

async fn list_project_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Query(query): Query<ProjectHistoryQuery>,
) -> ApiResult<Json<ProjectHistorySummary>> {
    let project = ProjectName::new(project)?;
    authorize_project_read(&state, &headers, &project)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    Ok(Json(ProjectHistorySummary {
        versions: ui_project_versions(state.project_history.list_recent_project(&project, limit)?),
    }))
}

async fn revert_project_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
) -> ApiResult<Json<UiProjectVersion>> {
    let project = ProjectName::new(project)?;
    let actor = authorize_project_write(&state, &headers, &project)?;
    let version = revert_recorded_project_version(&state, &project, &id, &actor)?;
    Ok(Json(ui_project_version(version)))
}

async fn revert_project_version_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    verify_csrf(&session, &form.csrf_token)?;
    let actor = RequestActor::User(session.user.clone());
    revert_recorded_project_version(&state, &project, &id, &actor)?;
    Ok(Redirect::to(&format!(
        "/ui/{}/history?flash=Project%20version%20reverted",
        project.as_str()
    )))
}

async fn create_block_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    multipart: Multipart,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    let form = parse_create_block_form(multipart).await?;
    verify_csrf(&session, &form.csrf_token)?;
    let after_block_id = form.after_block_id.map(BlockId::from_string).transpose()?;
    let (left, right) = state
        .store
        .resolve_after_block(&project, after_block_id.as_ref(), None)?;
    let new_block = NewBlock {
        project: project.clone(),
        block_type: form.block_type,
        content: form.content,
        author_key: session.user.username.as_str().to_string(),
        left,
        right,
        image_upload: form.image_upload,
    };

    let block = state.store.create_block_as_project_writer(new_block)?;
    record_project_version(
        &state,
        &project_version_actor_for_user(&session.user),
        &project,
        "Create block",
        vec![create_version_operation(&state, &project, &block.id, None)?],
    )?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Block%20created",
        project.as_str()
    )))
}

async fn update_block_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
    multipart: Multipart,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    let block_id = BlockId::from_string(id)?;
    let form = parse_update_block_form(multipart).await?;
    verify_csrf(&session, &form.csrf_token)?;
    let block_type = match form.block_type {
        Some(bt) => bt,
        None => {
            let existing = state.store.get_block(&project, &block_id)?;
            existing.block_type
        }
    };
    let (left, right) = match form.after_block_id {
        Some(aid) => {
            let after_id = BlockId::from_string(aid)?;
            state
                .store
                .resolve_after_block(&project, Some(&after_id), Some(&block_id))?
        }
        None => (None, None),
    };
    let update = UpdateBlock {
        project: project.clone(),
        block_id: block_id.clone(),
        block_type,
        content: form.content,
        author_key: session.user.username.as_str().to_string(),
        left,
        right,
        image_upload: form.image_upload,
    };

    let before = state.store.snapshot_block(&project, &block_id)?;
    let block = state.store.update_block_as_project_writer(update)?;
    record_project_version(
        &state,
        &project_version_actor_for_user(&session.user),
        &project,
        "Update block",
        vec![update_version_operation(
            &state,
            &project,
            &block.id,
            before,
            ProjectVersionOperationType::UpdateBlock,
        )?],
    )?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Block%20updated",
        project.as_str()
    )))
}

async fn delete_block_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
    Form(form): Form<DeleteBlockForm>,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    verify_csrf(&session, &form.csrf_token)?;
    let block_id = BlockId::from_string(id)?;
    let before = state.store.snapshot_block(&project, &block_id)?;
    state
        .store
        .delete_block_as_project_writer(&project, &block_id)?;
    record_project_version(
        &state,
        &project_version_actor_for_user(&session.user),
        &project,
        "Delete block",
        vec![StoredProjectVersionOperation {
            operation_type: ProjectVersionOperationType::DeleteBlock,
            block_id,
            before: Some(before),
            after: None,
            document_id: None,
        }],
    )?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Block%20deleted",
        project.as_str()
    )))
}

#[derive(Deserialize)]
struct MoveBlockUiForm {
    csrf_token: String,
    after_block_id: Option<String>,
}

async fn move_block_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
    Form(form): Form<MoveBlockUiForm>,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    verify_csrf(&session, &form.csrf_token)?;
    let block_id = BlockId::from_string(id)?;
    let after_block_id = form
        .after_block_id
        .filter(|s| !s.is_empty())
        .map(BlockId::from_string)
        .transpose()?;
    let before = state.store.snapshot_block(&project, &block_id)?;
    state.store.move_block_after_as_project_writer(
        &project,
        &block_id,
        after_block_id.as_ref(),
        session.user.username.as_str(),
    )?;
    record_project_version(
        &state,
        &project_version_actor_for_user(&session.user),
        &project,
        "Move block",
        vec![update_version_operation(
            &state,
            &project,
            &block_id,
            before,
            ProjectVersionOperationType::MoveBlock,
        )?],
    )?;
    Ok(Redirect::to(&format!("/ui/{}", project.as_str())))
}

#[derive(Deserialize)]
struct TogglePinForm {
    csrf_token: String,
}

async fn toggle_block_pin_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
    Form(form): Form<TogglePinForm>,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    verify_csrf(&session, &form.csrf_token)?;
    let block_id = BlockId::from_string(id)?;
    let block = state.store.get_block(&project, &block_id)?;
    state
        .store
        .set_block_pinned(&project, &block_id, !block.pinned)?;
    let label = if block.pinned { "unpinned" } else { "pinned" };
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Block%20{}",
        project.as_str(),
        label
    )))
}

async fn compact_blocks_from_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Form(form): Form<CsrfOnlyForm>,
) -> UiResult<Redirect> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_write(&session.user, &project)?;
    verify_csrf(&session, &form.csrf_token)?;
    let removed = state.store.compact_markdown_blocks(&project)?;
    let msg = if removed == 0 {
        "Nothing%20to%20compact".to_string()
    } else {
        format!("Compacted%20({removed}%20blocks%20merged)")
    };
    Ok(Redirect::to(&format!(
        "/ui/{}?flash={}",
        project.as_str(),
        msg
    )))
}

async fn block_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
) -> UiResult<Response> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_read(&session.user, &project)?;
    let block_id = BlockId::from_string(id)?;
    let (media_type, bytes) = state.store.read_block_media(&project, &block_id)?;
    let content_type = HeaderValue::from_str(&media_type)
        .map_err(|_| LoreError::Validation("stored media type is invalid".into()))?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, content_type)],
        Body::from(bytes),
    )
        .into_response())
}

async fn doc_block_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, doc_id, id)): Path<(String, String, String)>,
) -> UiResult<Response> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_read(&session.user, &project)?;
    let doc_id = DocumentId::from_string(doc_id)?;
    let block_id = BlockId::from_string(id)?;
    let (media_type, bytes) = state
        .store
        .read_doc_block_media(&project, &doc_id, &block_id)?;
    let content_type = HeaderValue::from_str(&media_type)
        .map_err(|_| LoreError::Validation("stored media type is invalid".into()))?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, content_type)],
        Body::from(bytes),
    )
        .into_response())
}

fn extract_agent_token_candidate(headers: &HeaderMap) -> Result<Option<String>, LoreError> {
    if let Some(value) = headers.get(API_KEY_HEADER) {
        let value = value.to_str().map_err(|_| {
            LoreError::Validation(format!("{API_KEY_HEADER} header must be valid ascii"))
        })?;
        if value.trim().is_empty() {
            return Err(LoreError::Validation(format!(
                "{API_KEY_HEADER} header must not be empty"
            )));
        }
        return Ok(Some(value.to_owned()));
    }

    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        let value = value.to_str().map_err(|_| {
            LoreError::Validation("authorization header must be valid ascii".into())
        })?;
        if let Some(token) = value.strip_prefix("Bearer ") {
            if token.trim().is_empty() {
                return Err(LoreError::Validation(
                    "bearer token must not be empty".into(),
                ));
            }
            return Ok(Some(token.to_string()));
        }
    }

    Ok(None)
}

fn collect_project_context(state: &AppState, grants: &[crate::auth::ProjectGrant]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for grant in grants {
        let meta = state.store.read_project_meta(&grant.project);
        let mut project_parts: Vec<String> = Vec::new();

        let agent_ctx = state
            .store
            .get_reserved_block(&grant.project, RESERVED_AGENT_CONTEXT)
            .ok()
            .map(|b| b.content)
            .or(meta.agent_context)
            .unwrap_or_default();
        if !agent_ctx.trim().is_empty() {
            project_parts.push(agent_ctx.trim().to_string());
        }

        if let Ok(overview) = state
            .store
            .get_reserved_block(&grant.project, RESERVED_OVERVIEW)
        {
            if !overview.content.trim().is_empty() {
                project_parts.push(format!("## Overview\n{}", overview.content.trim()));
            }
        }

        if let Ok(map) = state.store.get_reserved_block(&grant.project, RESERVED_MAP) {
            if !map.content.trim().is_empty() {
                project_parts.push(format!("## File Map\n{}", map.content.trim()));
            }
        }

        if !project_parts.is_empty() {
            parts.push(format!(
                "# {}\n{}",
                meta.display_name,
                project_parts.join("\n\n")
            ));
        }
    }
    parts.join("\n\n")
}

fn authenticate_agent(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AuthenticatedAgent>, LoreError> {
    match extract_agent_token_candidate(headers)? {
        Some(token) => {
            enforce_agent_auth_rate_limit(state)?;
            match state.auth.authenticate_agent_token(&token) {
                Ok(agent) => Ok(Some(agent)),
                Err(e) => {
                    record_failed_agent_auth(state);
                    Err(e)
                }
            }
        }
        None => Ok(None),
    }
}

fn require_authenticated_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<RequestActor, LoreError> {
    if let Some(agent) = authenticate_agent(state, headers)? {
        return Ok(RequestActor::Agent(agent));
    }

    if let Ok((username, password)) = extract_basic_credentials(headers) {
        enforce_login_rate_limit(state, &username)?;
        match state.auth.authenticate(&username, &password) {
            Ok(user) => {
                clear_login_rate_limit(state, &username);
                return Ok(RequestActor::User(user));
            }
            Err(e) => return Err(e),
        }
    }

    if let Some(user) = authenticate_external_user(state, headers)? {
        return Ok(RequestActor::User(user));
    }

    Err(LoreError::Validation(
        "missing authentication credentials".into(),
    ))
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<AuthenticatedUser, LoreError> {
    match require_authenticated_actor(state, headers)? {
        RequestActor::Agent(_) => Err(LoreError::PermissionDenied),
        RequestActor::User(user) if user.is_admin => Ok(user),
        RequestActor::User(_) => Err(LoreError::PermissionDenied),
    }
}

fn authorize_project_read(
    state: &AppState,
    headers: &HeaderMap,
    project: &ProjectName,
) -> Result<RequestActor, LoreError> {
    let actor = require_authenticated_actor(state, headers)?;
    match &actor {
        RequestActor::Agent(agent) => authorize_agent_read(agent, project)?,
        RequestActor::User(user) => state.auth.authorize_read(user, project)?,
    }
    Ok(actor)
}

fn authorize_project_write(
    state: &AppState,
    headers: &HeaderMap,
    project: &ProjectName,
) -> Result<RequestActor, LoreError> {
    let actor = require_authenticated_actor(state, headers)?;
    match &actor {
        RequestActor::Agent(agent) => authorize_agent_write(agent, project)?,
        RequestActor::User(user) => state.auth.authorize_write(user, project)?,
    }
    Ok(actor)
}

fn require_ui_session(state: &AppState, headers: &HeaderMap) -> Result<UiSession, LoreError> {
    if let Some(token) = extract_cookie(headers, SESSION_COOKIE) {
        let (user, session) = state.auth.authenticate_session(&token)?;
        return Ok(UiSession {
            token,
            csrf_token: session.csrf_token,
            user,
        });
    }
    Err(LoreError::PermissionDenied)
}

fn require_ui_admin(state: &AppState, headers: &HeaderMap) -> Result<UiSession, LoreError> {
    let session = require_ui_session(state, headers)?;
    if session.user.is_admin {
        Ok(session)
    } else {
        Err(LoreError::PermissionDenied)
    }
}

fn verify_csrf(session: &UiSession, submitted: &str) -> Result<(), LoreError> {
    if submitted.is_empty() || !constant_time_eq(submitted, &session.csrf_token) {
        return Err(LoreError::PermissionDenied);
    }
    Ok(())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn filter_projects_for_actor(actor: &RequestActor, projects: &[ProjectName]) -> Vec<ProjectName> {
    match actor {
        RequestActor::Agent(agent) => projects
            .iter()
            .filter(|project| agent.can_read(project))
            .cloned()
            .collect(),
        RequestActor::User(user) if user.is_admin => projects.to_vec(),
        RequestActor::User(user) => projects
            .iter()
            .filter(|project| user.can_read(project))
            .cloned()
            .collect(),
    }
}

fn actor_author_value(actor: &RequestActor) -> String {
    match actor {
        RequestActor::Agent(agent) => agent.token.clone(),
        RequestActor::User(user) => user.username.as_str().to_string(),
    }
}

fn authenticate_external_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AuthenticatedUser>, LoreError> {
    let config = state.external_auth.load()?;
    if !config.is_configured() {
        return Ok(None);
    }
    let username_header = HeaderName::from_bytes(config.username_header.as_bytes())
        .map_err(|_| LoreError::Validation("external auth username header is invalid".into()))?;
    let secret_header = HeaderName::from_bytes(config.secret_header.as_bytes())
        .map_err(|_| LoreError::Validation("external auth secret header is invalid".into()))?;
    let Some(username_value) = headers.get(&username_header) else {
        return Ok(None);
    };
    let Some(secret_value) = headers.get(&secret_header) else {
        return Ok(None);
    };
    let username = username_value
        .to_str()
        .map_err(|_| LoreError::Validation("external auth username header must be ascii".into()))?
        .trim()
        .to_string();
    let provided_secret = secret_value
        .to_str()
        .map_err(|_| LoreError::Validation("external auth secret header must be ascii".into()))?;
    if username.is_empty() {
        return Err(LoreError::PermissionDenied);
    }
    if Some(provided_secret) != config.secret_value.as_deref() {
        return Err(LoreError::PermissionDenied);
    }
    Ok(Some(state.auth.authenticate_external_username(&username)?))
}

fn extract_basic_credentials(headers: &HeaderMap) -> Result<(String, String), LoreError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| LoreError::Validation("missing authorization header".into()))?;
    let value = value
        .to_str()
        .map_err(|_| LoreError::Validation("authorization header must be valid ascii".into()))?;
    let encoded = value
        .strip_prefix("Basic ")
        .ok_or_else(|| LoreError::Validation("authorization header must use Basic auth".into()))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| LoreError::Validation("authorization header is not valid base64".into()))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| LoreError::Validation("authorization header must contain utf-8".into()))?;
    let (username, password) = decoded.split_once(':').ok_or_else(|| {
        LoreError::Validation("authorization header must contain username:password".into())
    })?;
    if username.is_empty() || password.is_empty() {
        return Err(LoreError::Validation(
            "authorization header must contain username and password".into(),
        ));
    }
    Ok((username.to_string(), password.to_string()))
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let header_value = headers.get(header::COOKIE)?.to_str().ok()?;
    for segment in header_value.split(';') {
        let trimmed = segment.trim();
        let (cookie_name, value) = trimmed.split_once('=')?;
        if cookie_name == name {
            return Some(value.to_string());
        }
    }
    None
}

fn session_cookie_value(token: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{secure_flag}"
    )
}

fn clear_session_cookie_value(secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure_flag}")
}

fn session_redirect_response(
    state: &AppState,
    session: &NewSession,
    redirect: Redirect,
) -> Response {
    let secure = state
        .config
        .load()
        .map_or(false, |c| c.external_scheme == ExternalScheme::Https);
    (
        [(
            header::SET_COOKIE,
            session_cookie_value(&session.token, secure),
        )],
        redirect,
    )
        .into_response()
}

fn clear_session_redirect_response(state: &AppState, redirect: Redirect) -> Response {
    let secure = state
        .config
        .load()
        .map_or(false, |c| c.external_scheme == ExternalScheme::Https);
    (
        [(header::SET_COOKIE, clear_session_cookie_value(secure))],
        redirect,
    )
        .into_response()
}

fn external_auth_secret_update_from_request<'a>(
    secret: Option<&'a str>,
    clear: Option<bool>,
) -> ExternalAuthSecretUpdate<'a> {
    if clear == Some(true) {
        ExternalAuthSecretUpdate::Clear
    } else if secret.unwrap_or("").trim().is_empty() {
        ExternalAuthSecretUpdate::Preserve
    } else {
        ExternalAuthSecretUpdate::Replace(secret.unwrap())
    }
}

fn external_auth_secret_update_from_form<'a>(
    secret: &'a str,
    clear: Option<&str>,
) -> ExternalAuthSecretUpdate<'a> {
    if clear == Some("true") {
        ExternalAuthSecretUpdate::Clear
    } else if secret.trim().is_empty() {
        ExternalAuthSecretUpdate::Preserve
    } else {
        ExternalAuthSecretUpdate::Replace(secret)
    }
}

fn default_external_port() -> u16 {
    std::env::var("LORE_BIND")
        .ok()
        .and_then(|value| value.rsplit(':').next().map(str::to_string))
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(7043)
}

fn build_agent_setup_instruction(config: &ServerConfig, token: Option<&str>) -> String {
    let auth_block = token.map_or_else(
        || "Authentication is required. Ask the Lore admin for a scoped agent token, then use it as Authorization: Bearer <token> for HTTP and MCP.".to_string(),
        |token| {
            format!(
                "Use this scoped agent token for both HTTP and MCP:\nAuthorization: Bearer {token}"
            )
        },
    );
    format!(
        "Lore setup for agents\n\nVisit this URL first:\n{}\n\nUse HTTP when the agent runs as a command, shell wrapper, CI job, cron task, or any runtime that can make ordinary web requests but does not support MCP cleanly.\n\nUse MCP when the agent host supports MCP tool servers natively and you want Lore to appear as a discoverable tool server with familiar grep/read/edit-style tools.\n\nLore base URL:\n{}\n\nLore MCP endpoint:\n{}\n\n{}\n\nTell the agent to review the setup page, choose HTTP or MCP for the current runtime, and then propose the exact integration steps for that environment.",
        config.setup_url(),
        config.base_url(),
        config.mcp_url(),
        auth_block
    )
}

fn resolved_theme(user: &AuthenticatedUser, config: &ServerConfig) -> UiTheme {
    user.theme.unwrap_or(config.default_theme)
}

fn resolved_color_mode(user: &AuthenticatedUser) -> ColorMode {
    user.color_mode.unwrap_or(ColorMode::System)
}

fn user_summary(state: &AppState, user: crate::auth::StoredUser) -> Result<UserSummary, LoreError> {
    let active_sessions = state.auth.active_session_count(&user.username)?;
    Ok(UserSummary {
        username: user.username,
        roles: user.role_names,
        is_admin: user.is_admin,
        disabled: user.disabled_at.is_some(),
        active_sessions,
        created_at: user.created_at,
    })
}

fn ui_user_summary(
    state: &AppState,
    user: crate::auth::StoredUser,
) -> Result<UiUserSummary, LoreError> {
    let active_sessions = state.auth.active_session_count(&user.username)?;
    Ok(UiUserSummary {
        username: user.username.as_str().to_string(),
        role_names: user
            .role_names
            .iter()
            .map(|role| role.as_str().to_string())
            .collect(),
        is_admin: user.is_admin,
        disabled: user.disabled_at.is_some(),
        active_sessions,
        created_at: user.created_at,
    })
}

fn block_filters_from_parts(
    block_type: Option<&str>,
    author: Option<&str>,
    since_days: Option<u32>,
) -> Result<BlockFilterOptions, LoreError> {
    Ok(BlockFilterOptions {
        block_type: block_type
            .filter(|value| !value.trim().is_empty())
            .map(parse_block_type)
            .transpose()?,
        author: author
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_lowercase),
        since_days,
    })
}

fn librarian_options_from_request(
    payload: &AskLibrarianRequest,
) -> Result<LibrarianOptions, LoreError> {
    librarian_options_from_parts(
        payload.block_type.as_deref(),
        payload.author.as_deref(),
        payload.since_days,
        payload.max_sources,
        payload.around,
    )
}

fn librarian_options_from_form(form: &AskLibrarianForm) -> Result<LibrarianOptions, LoreError> {
    librarian_options_from_parts(
        form.block_type.as_deref(),
        form.author.as_deref(),
        form.since_days,
        form.max_sources,
        form.around,
    )
}

fn action_librarian_options_from_request(
    payload: &ProjectLibrarianActionRequest,
) -> Result<LibrarianOptions, LoreError> {
    librarian_options_from_parts(
        payload.block_type.as_deref(),
        payload.author.as_deref(),
        payload.since_days,
        payload.max_sources,
        payload.around,
    )
}

fn action_librarian_options_from_form(
    form: &ProjectLibrarianActionForm,
) -> Result<LibrarianOptions, LoreError> {
    librarian_options_from_parts(
        form.block_type.as_deref(),
        form.author.as_deref(),
        form.since_days,
        form.max_sources,
        form.around,
    )
}

fn librarian_options_from_parts(
    block_type: Option<&str>,
    author: Option<&str>,
    since_days: Option<u32>,
    max_sources: Option<usize>,
    around: Option<usize>,
) -> Result<LibrarianOptions, LoreError> {
    let max_sources = max_sources
        .unwrap_or(MAX_CONTEXT_BLOCKS)
        .clamp(1, MAX_CONTEXT_BLOCKS);
    let around = around.unwrap_or(2).min(4);
    Ok(LibrarianOptions {
        filters: block_filters_from_parts(block_type, author, since_days)?,
        max_sources,
        around,
    })
}

fn block_matches_filters(block: &Block, filters: &BlockFilterOptions) -> bool {
    if let Some(block_type) = filters.block_type {
        if block.block_type != block_type {
            return false;
        }
    }
    if let Some(author) = &filters.author {
        if !block.author.as_str().to_lowercase().contains(author) {
            return false;
        }
    }
    if let Some(since_days) = filters.since_days {
        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(i64::from(since_days));
        if block.created_at < cutoff {
            return false;
        }
    }
    true
}

fn agent_token_summary(state: &AppState, token: StoredAgentToken) -> AgentTokenSummary {
    let display_name = token
        .display_name
        .clone()
        .unwrap_or_else(|| token.name.clone());
    let owner = token.owner.as_ref().map(|u| u.as_str().to_string());
    let status = state
        .chat
        .load_conversation(owner.as_deref().unwrap_or(""), &token.name)
        .map(|conv| match conv.agent_status {
            AgentChatStatus::Idle => "idle".to_string(),
            AgentChatStatus::Thinking => "thinking".to_string(),
            AgentChatStatus::Offline => "offline".to_string(),
        })
        .unwrap_or_else(|_| "offline".to_string());
    AgentTokenSummary {
        name: token.name,
        display_name,
        owner,
        grants: token.grants,
        backend: token.backend.to_string(),
        endpoint_id: token.endpoint_id,
        machine_name: token.machine_name,
        process_status: None,
        status,
        created_at: token.created_at,
    }
}

fn machine_agent_process_status(
    state: &AppState,
    owner: &str,
    agent_name: &str,
    machine_name: Option<&str>,
) -> Option<String> {
    let machine_name = machine_name?;
    let machine_key = format!("{owner}_{machine_name}");
    let statuses = state.machine_agent_statuses.lock().unwrap();
    let agent_list = statuses.get(&machine_key)?;
    agent_list
        .iter()
        .find(|entry| entry["name"].as_str() == Some(agent_name))
        .and_then(|entry| entry["status"].as_str())
        .map(str::to_string)
}

fn server_config_summary(config: &ServerConfig) -> ServerConfigSummary {
    ServerConfigSummary {
        external_scheme: config.external_scheme.as_str().to_string(),
        external_host: config.external_host.clone(),
        external_port: config.external_port,
        default_theme: config.default_theme.as_str().to_string(),
        base_url: config.base_url(),
        setup_url: config.setup_url(),
        setup_text_url: config.setup_text_url(),
        mcp_url: config.mcp_url(),
        updated_at: config.updated_at,
    }
}

fn librarian_config_summary(config: &crate::librarian::LibrarianConfig) -> LibrarianConfigSummary {
    LibrarianConfigSummary {
        endpoint_id: config.endpoint_id.clone(),
        configured: config.is_configured(),
        request_timeout_secs: config.request_timeout_secs,
        max_concurrent_runs: config.max_concurrent_runs,
        action_requires_approval: config.action_requires_approval,
        updated_at: config.updated_at,
    }
}

fn endpoint_summary(ep: &Endpoint) -> EndpointSummary {
    EndpointSummary {
        id: ep.id.clone(),
        name: ep.name.clone(),
        kind: ep.kind.to_string(),
        url: ep.url.clone(),
        model: ep.model.clone(),
        has_api_key: ep.has_api_key(),
        configured: ep.is_configured(),
        created_at: ep.created_at,
        updated_at: ep.updated_at,
    }
}

fn resolve_librarian_endpoint(
    state: &AppState,
) -> Result<(Endpoint, crate::librarian::LibrarianConfig), LoreError> {
    let config = state.librarian_config.load()?;
    let endpoint_id = config.endpoint_id.as_deref().ok_or_else(|| {
        LoreError::Validation("librarian is not configured: no endpoint selected".into())
    })?;
    let endpoint = state.endpoint_store.get(endpoint_id)?.ok_or_else(|| {
        LoreError::Validation("configured librarian endpoint no longer exists".into())
    })?;
    Ok((endpoint, config))
}

fn git_export_config_summary(config: &GitExportConfig) -> GitExportConfigSummary {
    GitExportConfigSummary {
        enabled: config.enabled,
        remote_url: config.remote_url.clone(),
        branch: config.branch.clone(),
        has_token: config.has_token(),
        author_name: config.author_name.clone(),
        author_email: config.author_email.clone(),
        auto_export: config.auto_export,
        configured: config.is_configured(),
        updated_at: config.updated_at,
    }
}

fn external_auth_config_summary(
    config: &crate::config::ExternalAuthConfig,
) -> ExternalAuthConfigSummary {
    ExternalAuthConfigSummary {
        enabled: config.enabled,
        username_header: config.username_header.clone(),
        secret_header: config.secret_header.clone(),
        has_secret: config.has_secret(),
    }
}

fn oidc_config_summary(config: &OidcConfig) -> OidcConfigSummary {
    OidcConfigSummary {
        enabled: config.enabled,
        issuer_url: config.issuer_url.clone(),
        client_id: config.client_id.clone(),
        callback_path: config.callback_path.clone(),
        username_claim: config.username_claim.as_str().to_string(),
        has_client_secret: config.has_client_secret(),
    }
}

fn auto_update_config_summary(config: &AutoUpdateConfig) -> AutoUpdateConfigSummary {
    AutoUpdateConfigSummary {
        enabled: config.enabled,
        github_repo: config.github_repo.clone(),
        release_stream: config.release_stream.as_str().to_string(),
        auto_update_machines: config.auto_update_machines,
        last_machine_rollout_version: config.last_machine_rollout_version.clone(),
        configured: !config.github_repo.trim().is_empty(),
        updated_at: config.updated_at,
    }
}

fn parse_release_stream(value: &str) -> Option<ReleaseStream> {
    match value {
        "stable" => Some(ReleaseStream::Stable),
        "prerelease" => Some(ReleaseStream::Prerelease),
        _ => None,
    }
}

fn auto_update_status_summary(status: &AutoUpdateStatus) -> AutoUpdateStatusSummary {
    AutoUpdateStatusSummary {
        ok: status.ok,
        applied: status.applied,
        detail: status.detail.clone(),
        current_version: status.current_version.clone(),
        latest_version: status.latest_version.clone(),
        checked_at: status.checked_at,
    }
}

fn provider_status_summary(status: ProviderCheckResult) -> LibrarianProviderStatusSummary {
    LibrarianProviderStatusSummary {
        ok: status.ok,
        detail: status.detail,
        checked_at: status.checked_at,
    }
}

fn git_export_status_summary(status: GitExportStatus) -> GitExportStatusSummary {
    GitExportStatusSummary {
        ok: status.ok,
        detail: status.detail,
        commit: status.commit,
        created_at: status.created_at,
    }
}

async fn run_auto_update_check(state: &AppState) -> Result<AutoUpdateStatus, LoreError> {
    const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(40);
    if let Some((cached_at, cached)) = state.update_check_cache.lock().unwrap().as_ref() {
        if cached_at.elapsed() < CACHE_TTL {
            return Ok(cached.clone());
        }
    }
    let config = state.auto_update_config.load()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| LoreError::ExternalService(e.to_string()))?;
    let check = check_for_update(
        &client,
        "lore-server",
        env!("CARGO_PKG_VERSION"),
        &config.github_repo,
        config.release_stream,
    )
    .await?;
    let status = AutoUpdateStatus {
        checked_at: OffsetDateTime::now_utc(),
        current_version: check.current_version,
        latest_version: Some(check.latest_version),
        detail: if config.enabled {
            format!("{}; enabled for next restart", check.detail)
        } else {
            format!(
                "{}; automatic server updates are currently disabled",
                check.detail
            )
        },
        applied: false,
        ok: true,
    };
    state.auto_update_status.save(&status)?;
    *state.update_check_cache.lock().unwrap() = Some((Instant::now(), status.clone()));
    Ok(status)
}

async fn run_auto_update_apply(state: &AppState) -> Result<AutoUpdateStatus, LoreError> {
    let config = state.auto_update_config.load()?;
    let executable_path = std::env::current_exe().map_err(LoreError::Io)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| LoreError::ExternalService(e.to_string()))?;
    match maybe_apply_self_update(
        &client,
        "lore-server",
        env!("CARGO_PKG_VERSION"),
        &config.github_repo,
        config.release_stream,
        &executable_path,
    )
    .await
    {
        Ok(outcome) => {
            let status = match outcome {
                crate::updater::SelfUpdateOutcome::UpToDate(status) => status,
                crate::updater::SelfUpdateOutcome::Updated(status) => status,
            };
            state.auto_update_status.save(&status)?;
            Ok(status)
        }
        Err(err) => {
            let status = AutoUpdateStatus {
                checked_at: OffsetDateTime::now_utc(),
                current_version: env!("CARGO_PKG_VERSION").to_string(),
                latest_version: None,
                detail: format!("update failed: {err}"),
                applied: false,
                ok: false,
            };
            state.auto_update_status.save(&status)?;
            Err(err)
        }
    }
}

fn schedule_server_restart(executable_path: std::path::PathBuf) {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    tokio::spawn(async move {
        eprintln!("updater: restarting server in 3 seconds");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        // If running as a systemd service, restart through systemd so the
        // service manager tracks the new process and dependent services
        // (like Caddy) are not disrupted.
        if std::path::Path::new("/etc/systemd/system/lore-server.service").exists() {
            let status = std::process::Command::new("sudo")
                .args(["systemctl", "restart", "lore-server"])
                .status();
            match status {
                Ok(s) if s.success() => std::process::exit(0),
                Ok(s) => {
                    eprintln!(
                        "warning: systemctl restart failed (exit {}), falling back to exec",
                        s.code().unwrap_or(-1)
                    );
                }
                Err(err) => {
                    eprintln!("warning: systemctl restart failed ({err}), falling back to exec");
                }
            }
        }
        let mut command = std::process::Command::new(&executable_path);
        command.args(args);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = command.exec();
            eprintln!("warning: failed to relaunch updated server: {err}");
            std::process::exit(1);
        }
        #[cfg(not(unix))]
        {
            if let Err(err) = command.spawn() {
                eprintln!("warning: failed to relaunch updated server: {err}");
            }
            std::process::exit(0);
        }
    });
}

fn api_key_update_from_request(api_key: Option<&str>, clear: Option<bool>) -> ApiKeyUpdate<'_> {
    if clear.unwrap_or(false) {
        ApiKeyUpdate::Clear
    } else if let Some(api_key) = api_key {
        if api_key.trim().is_empty() {
            ApiKeyUpdate::Preserve
        } else {
            ApiKeyUpdate::Replace(api_key)
        }
    } else {
        ApiKeyUpdate::Preserve
    }
}

fn api_key_update_from_form<'a>(api_key: &'a str, clear: Option<&str>) -> ApiKeyUpdate<'a> {
    if clear == Some("true") {
        ApiKeyUpdate::Clear
    } else if api_key.trim().is_empty() {
        ApiKeyUpdate::Preserve
    } else {
        ApiKeyUpdate::Replace(api_key)
    }
}

fn git_export_token_update_from_request(
    token: Option<&str>,
    clear: Option<bool>,
) -> GitExportTokenUpdate<'_> {
    if clear.unwrap_or(false) {
        GitExportTokenUpdate::Clear
    } else if let Some(token) = token {
        if token.trim().is_empty() {
            GitExportTokenUpdate::Preserve
        } else {
            GitExportTokenUpdate::Replace(token)
        }
    } else {
        GitExportTokenUpdate::Preserve
    }
}

fn git_export_token_update_from_form<'a>(
    token: &'a str,
    clear: Option<&str>,
) -> GitExportTokenUpdate<'a> {
    if clear == Some("true") {
        GitExportTokenUpdate::Clear
    } else if token.trim().is_empty() {
        GitExportTokenUpdate::Preserve
    } else {
        GitExportTokenUpdate::Replace(token)
    }
}

fn oidc_secret_update_from_request<'a>(
    secret: Option<&'a str>,
    clear: Option<bool>,
) -> OidcSecretUpdate<'a> {
    if clear == Some(true) {
        OidcSecretUpdate::Clear
    } else if secret.unwrap_or("").trim().is_empty() {
        OidcSecretUpdate::Preserve
    } else {
        OidcSecretUpdate::Replace(secret.unwrap())
    }
}

fn oidc_secret_update_from_form<'a>(secret: &'a str, clear: Option<&str>) -> OidcSecretUpdate<'a> {
    if clear == Some("true") {
        OidcSecretUpdate::Clear
    } else if secret.trim().is_empty() {
        OidcSecretUpdate::Preserve
    } else {
        OidcSecretUpdate::Replace(secret)
    }
}

fn ui_auth_audit_events(events: Vec<StoredAuditEvent>) -> Vec<UiAuditEvent> {
    events
        .into_iter()
        .map(|event| UiAuditEvent {
            id: event.id,
            created_at: event.created_at,
            actor: event.actor,
            action: event.action,
            target: event.target,
            detail: event.detail,
        })
        .collect()
}

fn append_audit_event(
    state: &AppState,
    actor: AuditActor,
    action: impl Into<String>,
    target: Option<String>,
    detail: Option<String>,
) -> Result<(), LoreError> {
    state.auth_audit.append(StoredAuditEvent {
        id: Uuid::new_v4().to_string(),
        actor,
        action: action.into(),
        target,
        detail,
        created_at: OffsetDateTime::now_utc(),
    })
}

fn oidc_http_client() -> Result<reqwest::Client, LoreError> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| LoreError::ExternalService(err.to_string()))
}

async fn discover_oidc_provider_metadata(
    config: &OidcConfig,
) -> Result<CoreProviderMetadata, LoreError> {
    let http_client = oidc_http_client()?;
    CoreProviderMetadata::discover_async(
        IssuerUrl::new(config.issuer_url.clone())
            .map_err(|err| LoreError::Validation(format!("invalid oidc issuer url: {err}")))?,
        &http_client,
    )
    .await
    .map_err(|err| LoreError::ExternalService(err.to_string()))
}

fn oidc_username_from_claims(
    config: &OidcConfig,
    claims: &CoreUserInfoClaims,
) -> Result<String, LoreError> {
    let standard = claims.standard_claims();
    let raw = match config.username_claim {
        OidcUsernameClaim::PreferredUsername => standard
            .preferred_username()
            .map(|value| value.as_str().to_string()),
        OidcUsernameClaim::Email => standard.email().map(|value| value.as_str().to_string()),
        OidcUsernameClaim::Subject => Some(standard.subject().as_str().to_string()),
    }
    .ok_or_else(|| {
        LoreError::ExternalService(format!(
            "oidc provider did not return {}",
            config.username_claim.as_str()
        ))
    })?;
    Ok(raw.trim().to_ascii_lowercase())
}

async fn answer_librarian_for_project(
    state: &AppState,
    project: &ProjectName,
    question: String,
    options: LibrarianOptions,
    actor: LibrarianActor,
    user_scope: Option<&crate::auth::AuthenticatedUser>,
) -> Result<LibrarianAnswerBody, LoreError> {
    let created_at = OffsetDateTime::now_utc();
    let mut source_blocks = Vec::new();
    let (endpoint, config) = resolve_librarian_endpoint(state)?;
    let _guard = acquire_librarian_slot(state, &config)?;
    let result = async {
        enforce_librarian_rate_limit(state, &actor, project)?;
        enforce_global_librarian_rate_limit(state)?;
        let mut request = build_librarian_request(&state.store, project, &question, &options)?;
        if let Some(user) = user_scope {
            let errors = collect_errors_for_librarian(state, user, 40);
            let block = format_errors_block_for_prompt(&errors, 4000);
            if !block.is_empty() {
                request.context_errors = Some(block);
            }
        }
        source_blocks = request.context_blocks.clone();
        let LibrarianAnswer { answer } = state
            .librarian_client
            .answer(&endpoint, config.request_timeout_secs, &request)
            .await?;
        Ok(LibrarianAnswerBody {
            project: project.clone(),
            created_at,
            actor: actor.clone(),
            question: request.question,
            answer: Some(answer),
            status: LibrarianRunStatus::Success,
            error: None,
            context_blocks: source_blocks.clone(),
        })
    }
    .await;

    if let Err(ref e) = result {
        record_server_error(
            state,
            "llm_api",
            format!("librarian answer for project {project} failed: {e}"),
            None,
            Some(endpoint.id.clone()),
            None,
            None,
        );
    }
    let audit = librarian_audit_entry(
        project,
        actor,
        created_at,
        &endpoint.url,
        &endpoint.model,
        &question,
        &source_blocks,
        &result,
    );
    state.librarian_history.append(audit)?;
    result
}

#[derive(Debug, Serialize)]
struct ProjectLibrarianActionBody {
    project: ProjectName,
    created_at: time::OffsetDateTime,
    actor: LibrarianActor,
    instruction: String,
    summary: String,
    parent_run_id: String,
    run_id: String,
    pending_action_id: Option<String>,
    requires_approval: bool,
    context_blocks: Vec<Block>,
    operations: Vec<StoredLibrarianOperation>,
}

struct LibrarianInFlightGuard {
    counter: Arc<Mutex<usize>>,
}

impl Drop for LibrarianInFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut count) = self.counter.lock() {
            if *count > 0 {
                *count -= 1;
            }
        }
    }
}

fn acquire_librarian_slot(
    state: &AppState,
    config: &crate::librarian::LibrarianConfig,
) -> Result<LibrarianInFlightGuard, LoreError> {
    let mut count = state
        .librarian_inflight_runs
        .lock()
        .map_err(|_| LoreError::Validation("librarian concurrency state is unavailable".into()))?;
    if *count >= config.max_concurrent_runs {
        return Err(LoreError::Validation(format!(
            "librarian concurrency limit reached; maximum is {}",
            config.max_concurrent_runs
        )));
    }
    *count += 1;
    Ok(LibrarianInFlightGuard {
        counter: Arc::clone(&state.librarian_inflight_runs),
    })
}

async fn execute_project_librarian_action(
    state: &AppState,
    project: &ProjectName,
    instruction: String,
    options: LibrarianOptions,
    user: &AuthenticatedUser,
) -> Result<ProjectLibrarianActionBody, LoreError> {
    state.auth.authorize_write(user, project)?;
    let actor = librarian_actor_for_user(user);
    let created_at = OffsetDateTime::now_utc();
    let (endpoint, config) = resolve_librarian_endpoint(state)?;
    let _guard = acquire_librarian_slot(state, &config)?;
    let request = build_project_librarian_request(&state.store, project, &instruction, &options)?;
    let parent_run_id = Uuid::new_v4().to_string();
    let parent_run = crate::librarian::StoredLibrarianRun {
        id: parent_run_id.clone(),
        project: project.clone(),
        actor: actor.clone(),
        kind: LibrarianRunKind::ActionRequest,
        parent_run_id: None,
        question: request.instruction.clone(),
        answer: Some("Project librarian action requested".into()),
        source_block_ids: request
            .context_blocks
            .iter()
            .map(|block| block.id.clone())
            .collect(),
        operations: Vec::new(),
        provider_endpoint_url: endpoint.url.clone(),
        provider_model: endpoint.model.clone(),
        status: LibrarianRunStatus::Success,
        error: None,
        created_at,
    };
    state.librarian_history.append(parent_run)?;

    let result = async {
        enforce_librarian_rate_limit(state, &actor, project)?;
        enforce_global_librarian_rate_limit(state)?;
        let plan = state
            .librarian_client
            .plan_action(&endpoint, config.request_timeout_secs, &request)
            .await?;
        if plan.operations.len() > MAX_PROJECT_ACTION_OPERATIONS {
            return Err(LoreError::Validation(format!(
                "project librarian returned too many operations; maximum is {MAX_PROJECT_ACTION_OPERATIONS}"
            )));
        }
        let operations = plan
            .operations
            .iter()
            .map(StoredLibrarianOperation::from)
            .collect::<Vec<_>>();
        if config.action_requires_approval {
            let pending_action_id = Uuid::new_v4().to_string();
            let pending_run_id = Uuid::new_v4().to_string();
            let pending_action = PendingLibrarianAction {
                id: pending_action_id.clone(),
                project: project.clone(),
                actor: actor.clone(),
                parent_run_id: parent_run_id.clone(),
                pending_run_id: pending_run_id.clone(),
                instruction: request.instruction.clone(),
                summary: plan.summary.clone(),
                source_block_ids: request
                    .context_blocks
                    .iter()
                    .map(|block| block.id.clone())
                    .collect(),
                operations: plan.operations.clone(),
                provider_endpoint_url: endpoint.url.clone(),
                provider_model: endpoint.model.clone(),
                created_at,
            };
            state.pending_librarian_actions.append(pending_action)?;
            Ok(ProjectLibrarianActionBody {
                project: project.clone(),
                created_at,
                actor: actor.clone(),
                instruction: request.instruction.clone(),
                summary: plan.summary,
                parent_run_id: parent_run_id.clone(),
                run_id: pending_run_id,
                pending_action_id: Some(pending_action_id),
                requires_approval: true,
                context_blocks: request.context_blocks.clone(),
                operations,
            })
        } else {
            let recorded_operations =
                execute_project_librarian_plan(state, project, user, &plan.operations)?;
            record_project_version(
                state,
                &project_version_actor_for_user(user),
                project,
                &format!("Project librarian action: {}", plan.summary),
                recorded_operations,
            )?;
            Ok(ProjectLibrarianActionBody {
                project: project.clone(),
                created_at,
                actor: actor.clone(),
                instruction: request.instruction.clone(),
                summary: plan.summary,
                parent_run_id: parent_run_id.clone(),
                run_id: Uuid::new_v4().to_string(),
                pending_action_id: None,
                requires_approval: false,
                context_blocks: request.context_blocks.clone(),
                operations,
            })
        }
    }
    .await;

    let child_run = project_librarian_action_audit_entry(
        project,
        actor,
        created_at,
        &endpoint.url,
        &endpoint.model,
        &request,
        &parent_run_id,
        &result,
    );
    let response = match result {
        Ok(mut body) => {
            body.run_id = child_run.id.clone();
            body
        }
        Err(err) => {
            state.librarian_history.append(child_run)?;
            return Err(err);
        }
    };
    state.librarian_history.append(child_run)?;
    Ok(response)
}

async fn approve_pending_project_librarian_action(
    state: &AppState,
    project: &ProjectName,
    id: &str,
    user: &AuthenticatedUser,
) -> Result<ProjectLibrarianActionBody, LoreError> {
    state.auth.authorize_write(user, project)?;
    let pending = state
        .pending_librarian_actions
        .take(project, id)?
        .ok_or_else(|| {
            LoreError::Validation("pending project librarian action does not exist".into())
        })?;
    execute_project_librarian_stored_action(state, pending, user)
}

fn reject_pending_project_librarian_action(
    state: &AppState,
    project: &ProjectName,
    id: &str,
    user: &AuthenticatedUser,
) -> Result<(), LoreError> {
    state.auth.authorize_write(user, project)?;
    let pending = state
        .pending_librarian_actions
        .take(project, id)?
        .ok_or_else(|| {
            LoreError::Validation("pending project librarian action does not exist".into())
        })?;
    state
        .librarian_history
        .append(crate::librarian::StoredLibrarianRun {
            id: Uuid::new_v4().to_string(),
            project: project.clone(),
            actor: librarian_actor_for_user(user),
            kind: LibrarianRunKind::ProjectAction,
            parent_run_id: Some(pending.pending_run_id),
            question: pending.instruction,
            answer: Some("Pending project librarian action rejected".into()),
            source_block_ids: pending.source_block_ids,
            operations: pending
                .operations
                .iter()
                .map(StoredLibrarianOperation::from)
                .collect(),
            provider_endpoint_url: pending.provider_endpoint_url,
            provider_model: pending.provider_model,
            status: LibrarianRunStatus::Rejected,
            error: None,
            created_at: OffsetDateTime::now_utc(),
        })?;
    Ok(())
}

fn execute_project_librarian_stored_action(
    state: &AppState,
    pending: PendingLibrarianAction,
    user: &AuthenticatedUser,
) -> Result<ProjectLibrarianActionBody, LoreError> {
    let recorded_operations =
        execute_project_librarian_plan(state, &pending.project, user, &pending.operations)?;
    record_project_version(
        state,
        &project_version_actor_for_user(user),
        &pending.project,
        &format!("Project librarian action: {}", pending.summary),
        recorded_operations,
    )?;
    let run_id = Uuid::new_v4().to_string();
    let created_at = OffsetDateTime::now_utc();
    state
        .librarian_history
        .append(crate::librarian::StoredLibrarianRun {
            id: run_id.clone(),
            project: pending.project.clone(),
            actor: librarian_actor_for_user(user),
            kind: LibrarianRunKind::ProjectAction,
            parent_run_id: Some(pending.pending_run_id.clone()),
            question: pending.instruction.clone(),
            answer: Some(pending.summary.clone()),
            source_block_ids: pending.source_block_ids.clone(),
            operations: pending
                .operations
                .iter()
                .map(StoredLibrarianOperation::from)
                .collect(),
            provider_endpoint_url: pending.provider_endpoint_url,
            provider_model: pending.provider_model,
            status: LibrarianRunStatus::Success,
            error: None,
            created_at,
        })?;
    Ok(ProjectLibrarianActionBody {
        project: pending.project,
        created_at,
        actor: librarian_actor_for_user(user),
        instruction: pending.instruction,
        summary: pending.summary,
        parent_run_id: pending.parent_run_id,
        run_id,
        pending_action_id: None,
        requires_approval: false,
        context_blocks: Vec::new(),
        operations: pending
            .operations
            .iter()
            .map(StoredLibrarianOperation::from)
            .collect(),
    })
}

fn build_librarian_request(
    store: &FileBlockStore,
    project: &ProjectName,
    question: &str,
    options: &LibrarianOptions,
) -> Result<LibrarianRequest, LoreError> {
    let question = question.trim().to_string();
    let context_blocks = build_librarian_context(store, project, &question, options)?;
    let request = LibrarianRequest {
        project: project.clone(),
        question,
        context_blocks,
        context_errors: None,
    };
    request.validate()?;
    let prompt = build_prompt(&request);
    if prompt.chars().count() > MAX_PROMPT_CHARS {
        return Err(LoreError::Validation(format!(
            "librarian prompt exceeds maximum size of {MAX_PROMPT_CHARS} characters"
        )));
    }
    Ok(request)
}

fn build_project_librarian_request(
    store: &FileBlockStore,
    project: &ProjectName,
    instruction: &str,
    options: &LibrarianOptions,
) -> Result<ProjectLibrarianRequest, LoreError> {
    let instruction = instruction.trim().to_string();
    let context_blocks = build_librarian_context(store, project, &instruction, options)?;
    let request = ProjectLibrarianRequest {
        project: project.clone(),
        instruction,
        context_blocks,
    };
    request.validate()?;
    let prompt = build_action_prompt(&request);
    if prompt.chars().count() > MAX_PROMPT_CHARS {
        return Err(LoreError::Validation(format!(
            "project librarian prompt exceeds maximum size of {MAX_PROMPT_CHARS} characters"
        )));
    }
    Ok(request)
}

fn build_librarian_context(
    store: &FileBlockStore,
    project: &ProjectName,
    question: &str,
    options: &LibrarianOptions,
) -> Result<Vec<Block>, LoreError> {
    let mut all_blocks: Vec<Block> = store
        .list_blocks(project)?
        .into_iter()
        .filter(|block| block_matches_filters(block, &options.filters))
        .collect();
    let doc_blocks = store.list_all_blocks_across_docs(project)?;
    let doc_map: std::collections::HashMap<String, DocumentId> = doc_blocks
        .iter()
        .map(|(doc_id, block)| (block.id.as_str().to_string(), doc_id.clone()))
        .collect();
    all_blocks.extend(
        doc_blocks
            .into_iter()
            .map(|(_, block)| block)
            .filter(|block| block_matches_filters(block, &options.filters)),
    );
    if all_blocks.is_empty() {
        return Ok(Vec::new());
    }

    let ranked = rank_blocks_for_librarian(&all_blocks, question);
    let anchor_ids = if ranked.is_empty() {
        all_blocks
            .iter()
            .rev()
            .take(3)
            .map(|block| block.id.clone())
            .collect::<Vec<_>>()
    } else {
        ranked
            .iter()
            .take(4)
            .map(|block| block.id.clone())
            .collect::<Vec<_>>()
    };

    let mut context_by_id = BTreeMap::new();
    for block_id in &anchor_ids {
        let around_blocks = if let Some(doc_id) = doc_map.get(block_id.as_str()) {
            store.read_doc_blocks_around(
                project,
                doc_id,
                block_id,
                options.around,
                options.around,
            )?
        } else {
            store.read_blocks_around(project, block_id, options.around, options.around)?
        };
        for block in around_blocks {
            if !block_matches_filters(&block, &options.filters) {
                continue;
            }
            context_by_id
                .entry(block.id.as_str().to_string())
                .or_insert(block);
            if context_by_id.len() >= options.max_sources {
                break;
            }
        }
        if context_by_id.len() >= options.max_sources {
            break;
        }
    }

    let mut context = context_by_id.into_values().collect::<Vec<_>>();
    context.sort_by(|a, b| {
        a.order
            .cmp(&b.order)
            .then_with(|| a.created_at.cmp(&b.created_at))
    });
    trim_context_to_prompt_limit(project, question, &mut context);
    Ok(context)
}

fn rank_blocks_for_librarian<'a>(blocks: &'a [Block], question: &str) -> Vec<&'a Block> {
    let tokens = question_tokens(question);
    let mut scored = blocks
        .iter()
        .filter_map(|block| {
            let haystack = format!(
                "{}\n{}\n{:?}\n{}",
                block.content.to_lowercase(),
                block.order.as_str().to_lowercase(),
                block.block_type,
                block.author.as_str().to_lowercase()
            );
            let mut score = 0usize;
            for token in &tokens {
                if haystack.contains(token) {
                    score += 1;
                }
            }
            if !question.trim().is_empty()
                && block
                    .content
                    .to_lowercase()
                    .contains(&question.to_lowercase())
            {
                score += 3;
            }
            if score == 0 {
                None
            } else {
                Some((score, block))
            }
        })
        .collect::<Vec<_>>();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.created_at.cmp(&a.1.created_at))
            .then_with(|| a.1.order.cmp(&b.1.order))
    });
    scored.into_iter().map(|(_, block)| block).collect()
}

fn question_tokens(question: &str) -> Vec<String> {
    question
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(|part| part.trim().to_lowercase())
        .filter(|part| part.len() >= 3)
        .collect()
}

fn trim_context_to_prompt_limit(project: &ProjectName, question: &str, context: &mut Vec<Block>) {
    while !context.is_empty() {
        let request = LibrarianRequest {
            project: project.clone(),
            question: question.to_string(),
            context_blocks: context.clone(),
            context_errors: None,
        };
        if build_prompt(&request).chars().count() <= MAX_PROMPT_CHARS {
            break;
        }
        context.remove(0);
    }
}

fn enforce_librarian_rate_limit(
    state: &AppState,
    actor: &LibrarianActor,
    project: &ProjectName,
) -> Result<(), LoreError> {
    let now = OffsetDateTime::now_utc();
    let key = format!("{:?}:{}:{}", actor.kind, actor.name, project.as_str());
    let mut limits = state
        .librarian_rate_limits
        .lock()
        .map_err(|_| LoreError::Validation("librarian rate limit state is unavailable".into()))?;
    let entry = limits.entry(key).or_default();
    entry.retain(|ts| (*ts + time::Duration::seconds(RATE_LIMIT_WINDOW_SECS)) > now);
    if entry.len() >= RATE_LIMIT_REQUESTS {
        return Err(LoreError::Validation(format!(
            "librarian rate limit exceeded for this project; try again in {} seconds",
            RATE_LIMIT_WINDOW_SECS
        )));
    }
    entry.push(now);
    Ok(())
}

fn enforce_global_librarian_rate_limit(state: &AppState) -> Result<(), LoreError> {
    let now = OffsetDateTime::now_utc();
    let mut entries = state.global_librarian_rate_limits.lock().map_err(|_| {
        LoreError::Validation("global librarian rate limit state is unavailable".into())
    })?;
    entries.retain(|ts| {
        (*ts + time::Duration::seconds(GLOBAL_LIBRARIAN_RATE_LIMIT_WINDOW_SECS)) > now
    });
    if entries.len() >= GLOBAL_LIBRARIAN_RATE_LIMIT {
        return Err(LoreError::Validation(format!(
            "server-wide librarian rate limit exceeded; try again in {} seconds",
            GLOBAL_LIBRARIAN_RATE_LIMIT_WINDOW_SECS
        )));
    }
    entries.push(now);
    Ok(())
}

fn enforce_agent_auth_rate_limit(state: &AppState) -> Result<(), LoreError> {
    let now = OffsetDateTime::now_utc();
    let entries = state
        .agent_auth_rate_limits
        .lock()
        .map_err(|_| LoreError::Validation("agent auth rate limit state is unavailable".into()))?;
    let recent = entries
        .iter()
        .filter(|ts| (**ts + time::Duration::seconds(AGENT_AUTH_RATE_LIMIT_WINDOW_SECS)) > now)
        .count();
    if recent >= AGENT_AUTH_RATE_LIMIT_ATTEMPTS {
        return Err(LoreError::Validation(format!(
            "too many failed agent authentication attempts; try again in {} seconds",
            AGENT_AUTH_RATE_LIMIT_WINDOW_SECS
        )));
    }
    Ok(())
}

fn record_failed_agent_auth(state: &AppState) {
    if let Ok(mut entries) = state.agent_auth_rate_limits.lock() {
        let now = OffsetDateTime::now_utc();
        entries
            .retain(|ts| (*ts + time::Duration::seconds(AGENT_AUTH_RATE_LIMIT_WINDOW_SECS)) > now);
        entries.push(now);
    }
}

fn validate_plan_block_ids_in_project(
    state: &AppState,
    project: &ProjectName,
    operations: &[ProjectLibrarianOperation],
) -> Result<(), LoreError> {
    let mut valid_ids: std::collections::HashSet<String> = state
        .store
        .list_blocks(project)?
        .iter()
        .map(|b| b.id.as_str().to_string())
        .collect();
    for (_, block) in state.store.list_all_blocks_across_docs(project)? {
        valid_ids.insert(block.id.as_str().to_string());
    }
    for op in operations {
        let ids: Vec<&str> = match op {
            ProjectLibrarianOperation::CreateBlock { after_block_id, .. } => {
                after_block_id.iter().map(|id| id.as_str()).collect()
            }
            ProjectLibrarianOperation::UpdateBlock {
                block_id,
                after_block_id,
                ..
            } => {
                let mut v = vec![block_id.as_str()];
                if let Some(after) = after_block_id {
                    v.push(after.as_str());
                }
                v
            }
            ProjectLibrarianOperation::MoveBlock {
                block_id,
                after_block_id,
            } => {
                let mut v = vec![block_id.as_str()];
                if let Some(after) = after_block_id {
                    v.push(after.as_str());
                }
                v
            }
            ProjectLibrarianOperation::DeleteBlock { block_id } => {
                vec![block_id.as_str()]
            }
        };
        for id in ids {
            if !valid_ids.contains(id) {
                return Err(LoreError::Validation(format!(
                    "librarian plan references block '{}' which does not belong to project '{}'",
                    id,
                    project.as_str()
                )));
            }
        }
    }
    Ok(())
}

fn execute_project_librarian_plan(
    state: &AppState,
    project: &ProjectName,
    user: &AuthenticatedUser,
    operations: &[ProjectLibrarianOperation],
) -> Result<Vec<StoredProjectVersionOperation>, LoreError> {
    validate_plan_block_ids_in_project(state, project, operations)?;
    let mut recorded = Vec::new();
    for operation in operations {
        match operation {
            ProjectLibrarianOperation::CreateBlock {
                block_type,
                content,
                after_block_id,
            } => {
                let target_doc = if let Some(after_id) = after_block_id {
                    state.store.find_block_document(project, after_id).ok()
                } else {
                    state.store.first_document_id(project)?.or(None)
                };
                if let Some(doc_id) = target_doc {
                    let (left, right) = state.store.resolve_after_doc_block(
                        project,
                        &doc_id,
                        after_block_id.as_ref(),
                        None,
                    )?;
                    let block = state.store.create_doc_block_as_project_writer(
                        &doc_id,
                        NewBlock {
                            project: project.clone(),
                            block_type: *block_type,
                            content: content.clone(),
                            author_key: user.username.as_str().to_string(),
                            left,
                            right,
                            image_upload: None,
                        },
                    )?;
                    recorded.push(create_doc_version_operation(
                        state, project, &doc_id, &block.id,
                    )?);
                } else {
                    let (left, right) =
                        state
                            .store
                            .resolve_after_block(project, after_block_id.as_ref(), None)?;
                    let block = state.store.create_block_as_project_writer(NewBlock {
                        project: project.clone(),
                        block_type: *block_type,
                        content: content.clone(),
                        author_key: user.username.as_str().to_string(),
                        left,
                        right,
                        image_upload: None,
                    })?;
                    recorded.push(create_version_operation(
                        state,
                        project,
                        &block.id,
                        Some(ProjectVersionOperationType::CreateBlock),
                    )?);
                }
            }
            ProjectLibrarianOperation::UpdateBlock {
                block_id,
                block_type,
                content,
                after_block_id,
            } => {
                if let Ok(doc_id) = state.store.find_block_document(project, block_id) {
                    let before = state.store.snapshot_doc_block(project, &doc_id, block_id)?;
                    let existing = state.store.get_doc_block(project, &doc_id, block_id)?;
                    let (left, right) =
                        if block_type.is_some() || content.is_some() || after_block_id.is_some() {
                            state.store.resolve_after_doc_block(
                                project,
                                &doc_id,
                                after_block_id.as_ref(),
                                Some(block_id),
                            )?
                        } else {
                            (None, None)
                        };
                    let block = state.store.update_doc_block_as_project_writer(
                        &doc_id,
                        UpdateBlock {
                            project: project.clone(),
                            block_id: block_id.clone(),
                            block_type: block_type.unwrap_or(existing.block_type),
                            content: content.clone().unwrap_or(existing.content),
                            author_key: user.username.as_str().to_string(),
                            left,
                            right,
                            image_upload: None,
                        },
                    )?;
                    recorded.push(update_doc_version_operation(
                        state,
                        project,
                        &doc_id,
                        &block.id,
                        before,
                        ProjectVersionOperationType::UpdateBlock,
                    )?);
                } else {
                    let before = state.store.snapshot_block(project, block_id)?;
                    let existing = state.store.get_block(project, block_id)?;
                    let (left, right) =
                        if block_type.is_some() || content.is_some() || after_block_id.is_some() {
                            state.store.resolve_after_block(
                                project,
                                after_block_id.as_ref(),
                                Some(block_id),
                            )?
                        } else {
                            (None, None)
                        };
                    let block = state.store.update_block_as_project_writer(UpdateBlock {
                        project: project.clone(),
                        block_id: block_id.clone(),
                        block_type: block_type.unwrap_or(existing.block_type),
                        content: content.clone().unwrap_or(existing.content),
                        author_key: user.username.as_str().to_string(),
                        left,
                        right,
                        image_upload: None,
                    })?;
                    recorded.push(update_version_operation(
                        state,
                        project,
                        &block.id,
                        before,
                        ProjectVersionOperationType::UpdateBlock,
                    )?);
                }
            }
            ProjectLibrarianOperation::MoveBlock {
                block_id,
                after_block_id,
            } => {
                if let Ok(doc_id) = state.store.find_block_document(project, block_id) {
                    let before = state.store.snapshot_doc_block(project, &doc_id, block_id)?;
                    let block = state.store.move_doc_block_after_as_project_writer(
                        project,
                        &doc_id,
                        block_id,
                        after_block_id.as_ref(),
                        user.username.as_str(),
                    )?;
                    recorded.push(update_doc_version_operation(
                        state,
                        project,
                        &doc_id,
                        &block.id,
                        before,
                        ProjectVersionOperationType::MoveBlock,
                    )?);
                } else {
                    let before = state.store.snapshot_block(project, block_id)?;
                    let block = state.store.move_block_after_as_project_writer(
                        project,
                        block_id,
                        after_block_id.as_ref(),
                        user.username.as_str(),
                    )?;
                    recorded.push(update_version_operation(
                        state,
                        project,
                        &block.id,
                        before,
                        ProjectVersionOperationType::MoveBlock,
                    )?);
                }
            }
            ProjectLibrarianOperation::DeleteBlock { block_id } => {
                if let Ok(doc_id) = state.store.find_block_document(project, block_id) {
                    let before = state.store.snapshot_doc_block(project, &doc_id, block_id)?;
                    state
                        .store
                        .delete_doc_block_as_project_writer(project, &doc_id, block_id)?;
                    recorded.push(StoredProjectVersionOperation {
                        operation_type: ProjectVersionOperationType::DeleteBlock,
                        block_id: block_id.clone(),
                        before: Some(before),
                        after: None,
                        document_id: Some(doc_id.as_str().to_string()),
                    });
                } else {
                    let before = state.store.snapshot_block(project, block_id)?;
                    state
                        .store
                        .delete_block_as_project_writer(project, block_id)?;
                    recorded.push(StoredProjectVersionOperation {
                        operation_type: ProjectVersionOperationType::DeleteBlock,
                        block_id: block_id.clone(),
                        before: Some(before),
                        after: None,
                        document_id: None,
                    });
                }
            }
        }
    }
    Ok(recorded)
}

fn enforce_login_rate_limit(state: &AppState, username: &str) -> Result<(), LoreError> {
    let key = username.trim().to_lowercase();
    let now = OffsetDateTime::now_utc();
    let mut limits = state
        .login_rate_limits
        .lock()
        .map_err(|_| LoreError::Validation("login rate limit state is unavailable".into()))?;
    let entry = limits.entry(key).or_default();
    entry.retain(|ts| (*ts + time::Duration::seconds(LOGIN_RATE_LIMIT_WINDOW_SECS)) > now);
    if entry.len() >= LOGIN_RATE_LIMIT_ATTEMPTS {
        return Err(LoreError::Validation(format!(
            "too many login attempts; try again in {} seconds",
            LOGIN_RATE_LIMIT_WINDOW_SECS
        )));
    }
    entry.push(now);
    Ok(())
}

fn clear_login_rate_limit(state: &AppState, username: &str) {
    if let Ok(mut limits) = state.login_rate_limits.lock() {
        limits.remove(&username.trim().to_lowercase());
    }
}

fn create_version_operation(
    state: &AppState,
    project: &ProjectName,
    block_id: &BlockId,
    operation_type: Option<ProjectVersionOperationType>,
) -> Result<StoredProjectVersionOperation, LoreError> {
    Ok(StoredProjectVersionOperation {
        operation_type: operation_type.unwrap_or(ProjectVersionOperationType::CreateBlock),
        block_id: block_id.clone(),
        before: None,
        after: Some(state.store.snapshot_block(project, block_id)?),
        document_id: None,
    })
}

fn update_version_operation(
    state: &AppState,
    project: &ProjectName,
    block_id: &BlockId,
    before: StoredBlockSnapshot,
    operation_type: ProjectVersionOperationType,
) -> Result<StoredProjectVersionOperation, LoreError> {
    Ok(StoredProjectVersionOperation {
        operation_type,
        block_id: block_id.clone(),
        before: Some(before),
        after: Some(state.store.snapshot_block(project, block_id)?),
        document_id: None,
    })
}

fn create_doc_version_operation(
    state: &AppState,
    project: &ProjectName,
    doc_id: &DocumentId,
    block_id: &BlockId,
) -> Result<StoredProjectVersionOperation, LoreError> {
    Ok(StoredProjectVersionOperation {
        operation_type: ProjectVersionOperationType::CreateBlock,
        block_id: block_id.clone(),
        before: None,
        after: Some(state.store.snapshot_doc_block(project, doc_id, block_id)?),
        document_id: Some(doc_id.as_str().to_string()),
    })
}

fn update_doc_version_operation(
    state: &AppState,
    project: &ProjectName,
    doc_id: &DocumentId,
    block_id: &BlockId,
    before: StoredBlockSnapshot,
    operation_type: ProjectVersionOperationType,
) -> Result<StoredProjectVersionOperation, LoreError> {
    Ok(StoredProjectVersionOperation {
        operation_type,
        block_id: block_id.clone(),
        before: Some(before),
        after: Some(state.store.snapshot_doc_block(project, doc_id, block_id)?),
        document_id: Some(doc_id.as_str().to_string()),
    })
}

fn record_project_version(
    state: &AppState,
    actor: &ProjectVersionActor,
    project: &ProjectName,
    summary: &str,
    operations: Vec<StoredProjectVersionOperation>,
) -> Result<StoredProjectVersion, LoreError> {
    let created_at = OffsetDateTime::now_utc();
    let mut version = StoredProjectVersion {
        id: Uuid::new_v4().to_string(),
        project: project.clone(),
        actor: actor.clone(),
        summary: summary.trim().to_string(),
        operations,
        git_commit: None,
        git_export_error: None,
        reverted_from_version_id: None,
        reverted_by_version_id: None,
        created_at,
    };
    if let Some((commit, error)) = maybe_auto_export(state, &version.summary)? {
        version.git_commit = commit;
        version.git_export_error = error;
    }
    state.project_history.append(version.clone())?;
    Ok(version)
}

fn maybe_auto_export(
    state: &AppState,
    summary: &str,
) -> Result<Option<(Option<String>, Option<String>)>, LoreError> {
    let config = state.git_export_config.load()?;
    if !config.is_configured() || !config.auto_export {
        return Ok(None);
    }
    let now = OffsetDateTime::now_utc();
    match run_git_export(state.store.root(), &config, summary) {
        Ok(commit) => {
            state.git_export_status.save(&GitExportStatus {
                ok: true,
                detail: "automatic export succeeded".into(),
                commit: commit.clone(),
                created_at: now,
            })?;
            Ok(Some((commit, None)))
        }
        Err(err) => {
            state.git_export_status.save(&GitExportStatus {
                ok: false,
                detail: err.to_string(),
                commit: None,
                created_at: now,
            })?;
            Ok(Some((None, Some(err.to_string()))))
        }
    }
}

fn run_manual_git_export(state: &AppState, summary: &str) -> Result<GitExportStatus, LoreError> {
    let config = state.git_export_config.load()?;
    if !config.is_configured() {
        return Err(LoreError::Validation("git export is not configured".into()));
    }
    let now = OffsetDateTime::now_utc();
    let status = match run_git_export(state.store.root(), &config, summary) {
        Ok(commit) => GitExportStatus {
            ok: true,
            detail: "git export completed".into(),
            commit,
            created_at: now,
        },
        Err(err) => GitExportStatus {
            ok: false,
            detail: err.to_string(),
            commit: None,
            created_at: now,
        },
    };
    state.git_export_status.save(&status)?;
    Ok(status)
}

fn revert_recorded_project_version(
    state: &AppState,
    project: &ProjectName,
    id: &str,
    actor: &RequestActor,
) -> Result<StoredProjectVersion, LoreError> {
    let version = state
        .project_history
        .get(project, id)?
        .ok_or_else(|| LoreError::Validation("project version does not exist".into()))?;
    if version.reverted_by_version_id.is_some() {
        return Err(LoreError::Validation(
            "project version has already been reverted".into(),
        ));
    }
    ensure_version_can_be_reverted(state, &version)?;
    for operation in version.operations.iter().rev() {
        let doc_id = operation
            .document_id
            .as_ref()
            .map(|s| DocumentId::from_string(s.clone()))
            .transpose()?;
        match operation.operation_type {
            ProjectVersionOperationType::CreateBlock => {
                if let Some(ref did) = doc_id {
                    state.store.delete_doc_block_as_project_writer(
                        project,
                        did,
                        &operation.block_id,
                    )?;
                } else {
                    state
                        .store
                        .delete_block_as_project_writer(project, &operation.block_id)?;
                }
            }
            ProjectVersionOperationType::UpdateBlock | ProjectVersionOperationType::MoveBlock => {
                let before = operation.before.as_ref().ok_or_else(|| {
                    LoreError::Validation("recorded version is missing a before snapshot".into())
                })?;
                if let Some(ref did) = doc_id {
                    state
                        .store
                        .restore_doc_block_snapshot(project, did, before)?;
                } else {
                    state.store.restore_block_snapshot(before)?;
                }
            }
            ProjectVersionOperationType::DeleteBlock => {
                let before = operation.before.as_ref().ok_or_else(|| {
                    LoreError::Validation("recorded version is missing a deleted snapshot".into())
                })?;
                if let Some(ref did) = doc_id {
                    state
                        .store
                        .restore_doc_block_snapshot(project, did, before)?;
                } else {
                    state.store.restore_block_snapshot(before)?;
                }
            }
        }
    }
    let mut reverted = StoredProjectVersion {
        id: Uuid::new_v4().to_string(),
        project: project.clone(),
        actor: project_version_actor_for_request_actor(actor),
        summary: format!("Revert version {}", version.id),
        operations: build_revert_operations(&version.operations),
        git_commit: None,
        git_export_error: None,
        reverted_from_version_id: Some(version.id.clone()),
        reverted_by_version_id: None,
        created_at: OffsetDateTime::now_utc(),
    };
    if let Some((commit, error)) = maybe_auto_export(state, &reverted.summary)? {
        reverted.git_commit = commit;
        reverted.git_export_error = error;
    }
    state.project_history.append(reverted.clone())?;
    state
        .project_history
        .mark_reverted(project, &version.id, &reverted.id)?;
    Ok(reverted)
}

fn ensure_version_can_be_reverted(
    state: &AppState,
    version: &StoredProjectVersion,
) -> Result<(), LoreError> {
    for operation in &version.operations {
        let doc_id = operation
            .document_id
            .as_ref()
            .map(|s| DocumentId::from_string(s.clone()))
            .transpose()?;
        match operation.operation_type {
            ProjectVersionOperationType::CreateBlock
            | ProjectVersionOperationType::UpdateBlock
            | ProjectVersionOperationType::MoveBlock => {
                let after = operation.after.as_ref().ok_or_else(|| {
                    LoreError::Validation("recorded version is missing an after snapshot".into())
                })?;
                let matches = if let Some(ref did) = doc_id {
                    state.store.doc_block_matches_snapshot(
                        &version.project,
                        did,
                        &operation.block_id,
                        after,
                    )?
                } else {
                    state.store.block_matches_snapshot(
                        &version.project,
                        &operation.block_id,
                        after,
                    )?
                };
                if !matches {
                    return Err(LoreError::Validation(
                        "this version can no longer be reverted cleanly because later changes touched the same block".into(),
                    ));
                }
            }
            ProjectVersionOperationType::DeleteBlock => {
                let block_exists = if let Some(ref did) = doc_id {
                    state
                        .store
                        .get_doc_block(&version.project, did, &operation.block_id)
                        .is_ok()
                } else {
                    state
                        .store
                        .get_block(&version.project, &operation.block_id)
                        .is_ok()
                };
                if block_exists {
                    return Err(LoreError::Validation(
                        "this version can no longer be reverted cleanly because the deleted block already exists again".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn build_revert_operations(
    operations: &[StoredProjectVersionOperation],
) -> Vec<StoredProjectVersionOperation> {
    operations
        .iter()
        .rev()
        .map(|operation| StoredProjectVersionOperation {
            operation_type: match operation.operation_type {
                ProjectVersionOperationType::CreateBlock => {
                    ProjectVersionOperationType::DeleteBlock
                }
                ProjectVersionOperationType::DeleteBlock => {
                    ProjectVersionOperationType::CreateBlock
                }
                ProjectVersionOperationType::UpdateBlock => {
                    ProjectVersionOperationType::UpdateBlock
                }
                ProjectVersionOperationType::MoveBlock => ProjectVersionOperationType::MoveBlock,
            },
            block_id: operation.block_id.clone(),
            before: operation.after.clone(),
            after: operation.before.clone(),
            document_id: operation.document_id.clone(),
        })
        .collect()
}

fn librarian_audit_entry(
    project: &ProjectName,
    actor: LibrarianActor,
    created_at: OffsetDateTime,
    provider_endpoint_url: &str,
    provider_model: &str,
    question: &str,
    source_blocks: &[Block],
    result: &Result<LibrarianAnswerBody, LoreError>,
) -> crate::librarian::StoredLibrarianRun {
    let (status, answer, error) = match result {
        Ok(body) => (LibrarianRunStatus::Success, body.answer.clone(), None),
        Err(LoreError::Validation(message)) if message.contains("rate limit") => {
            (LibrarianRunStatus::RateLimited, None, Some(message.clone()))
        }
        Err(err) => (LibrarianRunStatus::Error, None, Some(err.to_string())),
    };
    crate::librarian::StoredLibrarianRun {
        id: Uuid::new_v4().to_string(),
        project: project.clone(),
        actor,
        kind: LibrarianRunKind::Answer,
        parent_run_id: None,
        question: question.trim().to_string(),
        answer,
        source_block_ids: source_blocks.iter().map(|block| block.id.clone()).collect(),
        operations: Vec::new(),
        provider_endpoint_url: provider_endpoint_url.to_string(),
        provider_model: provider_model.to_string(),
        status,
        error,
        created_at,
    }
}

fn project_librarian_action_audit_entry(
    project: &ProjectName,
    actor: LibrarianActor,
    created_at: OffsetDateTime,
    provider_endpoint_url: &str,
    provider_model: &str,
    request: &ProjectLibrarianRequest,
    parent_run_id: &str,
    result: &Result<ProjectLibrarianActionBody, LoreError>,
) -> crate::librarian::StoredLibrarianRun {
    let (id, status, answer, error, operations) = match result {
        Ok(body) if body.requires_approval => (
            body.run_id.clone(),
            LibrarianRunStatus::PendingApproval,
            Some(body.summary.clone()),
            None,
            body.operations.clone(),
        ),
        Ok(body) => (
            body.run_id.clone(),
            LibrarianRunStatus::Success,
            Some(body.summary.clone()),
            None,
            body.operations.clone(),
        ),
        Err(LoreError::Validation(message)) if message.contains("rate limit") => (
            Uuid::new_v4().to_string(),
            LibrarianRunStatus::RateLimited,
            None,
            Some(message.clone()),
            Vec::new(),
        ),
        Err(err) => (
            Uuid::new_v4().to_string(),
            LibrarianRunStatus::Error,
            None,
            Some(err.to_string()),
            Vec::new(),
        ),
    };
    crate::librarian::StoredLibrarianRun {
        id,
        project: project.clone(),
        actor,
        kind: LibrarianRunKind::ProjectAction,
        parent_run_id: Some(parent_run_id.to_string()),
        question: request.instruction.trim().to_string(),
        answer,
        source_block_ids: request
            .context_blocks
            .iter()
            .map(|block| block.id.clone())
            .collect(),
        operations,
        provider_endpoint_url: provider_endpoint_url.to_string(),
        provider_model: provider_model.to_string(),
        status,
        error,
        created_at,
    }
}

fn ui_project_versions(history: Vec<StoredProjectVersion>) -> Vec<UiProjectVersion> {
    history.into_iter().map(ui_project_version).collect()
}

fn ui_project_version(version: StoredProjectVersion) -> UiProjectVersion {
    UiProjectVersion {
        id: version.id,
        created_at: version.created_at,
        actor: version.actor,
        summary: version.summary,
        operations: version
            .operations
            .into_iter()
            .map(ui_project_version_operation)
            .collect(),
        git_commit: version.git_commit,
        git_export_error: version.git_export_error,
        reverted_from_version_id: version.reverted_from_version_id,
        reverted_by_version_id: version.reverted_by_version_id,
    }
}

fn ui_project_version_operation(
    operation: StoredProjectVersionOperation,
) -> UiProjectVersionOperation {
    UiProjectVersionOperation {
        operation_type: operation.operation_type,
        block_id: operation.block_id.as_str().to_string(),
        before_preview: operation.before.as_ref().map(snapshot_preview),
        after_preview: operation.after.as_ref().map(snapshot_preview),
        changed_fields: changed_fields_for_operation(&operation),
        diff_lines: diff_lines_for_operation(&operation),
        before_order: operation
            .before
            .as_ref()
            .map(|snapshot| snapshot.order.as_str().to_string()),
        after_order: operation
            .after
            .as_ref()
            .map(|snapshot| snapshot.order.as_str().to_string()),
        before_block_type: operation
            .before
            .as_ref()
            .map(|snapshot| ui_block_type(snapshot.block_type)),
        after_block_type: operation
            .after
            .as_ref()
            .map(|snapshot| ui_block_type(snapshot.block_type)),
        before_media_type: operation.before.as_ref().and_then(|snapshot| {
            snapshot
                .media
                .as_ref()
                .map(|media| media.media_type.clone())
        }),
        after_media_type: operation.after.as_ref().and_then(|snapshot| {
            snapshot
                .media
                .as_ref()
                .map(|media| media.media_type.clone())
        }),
    }
}

fn snapshot_preview(snapshot: &StoredBlockSnapshot) -> String {
    let text = snapshot.content.lines().next().unwrap_or("").trim();
    if text.is_empty() {
        format!("{:?} block {}", snapshot.block_type, snapshot.id.as_str())
    } else {
        truncate_preview(text, 64)
    }
}

fn ui_block_type(value: BlockType) -> String {
    match value {
        BlockType::Markdown => "markdown",
        BlockType::Html => "html",
        BlockType::Svg => "svg",
        BlockType::Image => "image",
    }
    .to_string()
}

fn changed_fields_for_operation(operation: &StoredProjectVersionOperation) -> Vec<String> {
    let mut fields = Vec::new();
    if operation
        .before
        .as_ref()
        .map(|snapshot| snapshot.block_type)
        != operation.after.as_ref().map(|snapshot| snapshot.block_type)
    {
        fields.push("type".into());
    }
    if operation
        .before
        .as_ref()
        .map(|snapshot| snapshot.order.as_str().to_string())
        != operation
            .after
            .as_ref()
            .map(|snapshot| snapshot.order.as_str().to_string())
    {
        fields.push("order".into());
    }
    if operation
        .before
        .as_ref()
        .map(|snapshot| snapshot.content.as_str())
        != operation
            .after
            .as_ref()
            .map(|snapshot| snapshot.content.as_str())
    {
        fields.push("content".into());
    }
    if operation.before.as_ref().and_then(|snapshot| {
        snapshot
            .media
            .as_ref()
            .map(|media| media.media_type.clone())
    }) != operation.after.as_ref().and_then(|snapshot| {
        snapshot
            .media
            .as_ref()
            .map(|media| media.media_type.clone())
    }) {
        fields.push("media".into());
    }
    fields
}

fn diff_lines_for_operation(operation: &StoredProjectVersionOperation) -> Vec<UiDiffLine> {
    match (operation.before.as_ref(), operation.after.as_ref()) {
        (None, Some(after)) => truncated_diff_lines(&after.content, UiDiffLineKind::Added),
        (Some(before), None) => truncated_diff_lines(&before.content, UiDiffLineKind::Removed),
        (Some(before), Some(after)) if before.content != after.content => {
            content_diff_lines(&before.content, &after.content)
        }
        _ => Vec::new(),
    }
}

fn truncated_diff_lines(content: &str, kind: UiDiffLineKind) -> Vec<UiDiffLine> {
    let lines = content.lines().collect::<Vec<_>>();
    let mut rendered = lines
        .iter()
        .take(12)
        .map(|line| UiDiffLine {
            kind,
            text: (*line).to_string(),
        })
        .collect::<Vec<_>>();
    if lines.len() > 12 {
        rendered.push(UiDiffLine {
            kind: UiDiffLineKind::Context,
            text: format!("… {} more lines", lines.len() - 12),
        });
    }
    rendered
}

fn content_diff_lines(before: &str, after: &str) -> Vec<UiDiffLine> {
    let before_lines = before.lines().collect::<Vec<_>>();
    let after_lines = after.lines().collect::<Vec<_>>();
    let mut prefix = 0usize;
    while prefix < before_lines.len()
        && prefix < after_lines.len()
        && before_lines[prefix] == after_lines[prefix]
    {
        prefix += 1;
    }

    let mut suffix = 0usize;
    while suffix < before_lines.len().saturating_sub(prefix)
        && suffix < after_lines.len().saturating_sub(prefix)
        && before_lines[before_lines.len() - 1 - suffix]
            == after_lines[after_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let before_changed = &before_lines[prefix..before_lines.len().saturating_sub(suffix)];
    let after_changed = &after_lines[prefix..after_lines.len().saturating_sub(suffix)];
    let before_context_start = prefix.saturating_sub(2);
    let before_context = &before_lines[before_context_start..prefix];
    let after_context_end = (after_lines.len().saturating_sub(suffix) + 2).min(after_lines.len());
    let after_context = &after_lines[after_lines.len().saturating_sub(suffix)..after_context_end];

    let mut lines = Vec::new();
    lines.extend(render_leading_context_lines(
        before_context_start,
        before_context,
    ));
    lines.extend(render_changed_lines(
        before_changed,
        UiDiffLineKind::Removed,
    ));
    lines.extend(render_changed_lines(after_changed, UiDiffLineKind::Added));
    lines.extend(render_trailing_context_lines(
        after_lines.len().saturating_sub(after_context_end),
        after_context,
    ));
    if lines.is_empty() {
        lines.push(UiDiffLine {
            kind: UiDiffLineKind::Context,
            text: "(content unchanged)".into(),
        });
    }
    lines
}

fn render_leading_context_lines(omitted_count: usize, lines: &[&str]) -> Vec<UiDiffLine> {
    let mut rendered = Vec::new();
    if omitted_count > 0 && !lines.is_empty() {
        rendered.push(UiDiffLine {
            kind: UiDiffLineKind::Context,
            text: format!("… {} unchanged lines", omitted_count),
        });
    }
    rendered.extend(lines.iter().map(|line| UiDiffLine {
        kind: UiDiffLineKind::Context,
        text: (*line).to_string(),
    }));
    rendered
}

fn render_trailing_context_lines(omitted_count: usize, lines: &[&str]) -> Vec<UiDiffLine> {
    let mut rendered = lines
        .iter()
        .map(|line| UiDiffLine {
            kind: UiDiffLineKind::Context,
            text: (*line).to_string(),
        })
        .collect::<Vec<_>>();
    if omitted_count > 0 && !lines.is_empty() {
        rendered.push(UiDiffLine {
            kind: UiDiffLineKind::Context,
            text: format!("… {} unchanged lines", omitted_count),
        });
    }
    rendered
}

fn render_changed_lines(lines: &[&str], kind: UiDiffLineKind) -> Vec<UiDiffLine> {
    let mut rendered = lines
        .iter()
        .take(12)
        .map(|line| UiDiffLine {
            kind,
            text: (*line).to_string(),
        })
        .collect::<Vec<_>>();
    if lines.len() > 12 {
        rendered.push(UiDiffLine {
            kind: UiDiffLineKind::Context,
            text: format!("… {} more changed lines", lines.len() - 12),
        });
    }
    rendered
}

fn truncate_preview(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let preview = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{preview}...")
    } else {
        preview
    }
}

fn ui_librarian_answers_from_history(
    store: &FileBlockStore,
    project: &ProjectName,
    history: Vec<crate::librarian::StoredLibrarianRun>,
) -> Result<Vec<UiLibrarianAnswer>, LoreError> {
    let all_blocks = store.list_blocks(project)?;
    let by_id = all_blocks
        .into_iter()
        .map(|block| (block.id.as_str().to_string(), block))
        .collect::<HashMap<_, _>>();
    Ok(history
        .into_iter()
        .map(|run| UiLibrarianAnswer {
            id: run.id,
            project: Some(project.as_str().to_string()),
            created_at: run.created_at,
            kind: run.kind,
            parent_run_id: run.parent_run_id,
            question: run.question,
            answer: run.answer,
            status: run.status,
            error: run.error,
            actor: Some(run.actor),
            context_blocks: run
                .source_block_ids
                .into_iter()
                .filter_map(|id| by_id.get(id.as_str()).cloned())
                .collect(),
            operations: run.operations,
        })
        .collect())
}

fn ui_librarian_answers_from_history_all(
    store: &FileBlockStore,
    history: Vec<crate::librarian::StoredLibrarianRun>,
) -> Result<Vec<UiLibrarianAnswer>, LoreError> {
    let mut by_project_and_id = HashMap::new();
    for project in store.list_projects()? {
        for block in store.list_blocks(&project)? {
            by_project_and_id.insert(format!("{}:{}", project.as_str(), block.id.as_str()), block);
        }
    }
    Ok(history
        .into_iter()
        .map(|run| UiLibrarianAnswer {
            id: run.id,
            project: Some(run.project.as_str().to_string()),
            created_at: run.created_at,
            kind: run.kind,
            parent_run_id: run.parent_run_id,
            question: format!("[{}] {}", run.project.as_str(), run.question),
            answer: run.answer,
            status: run.status,
            error: run.error,
            actor: Some(run.actor),
            context_blocks: run
                .source_block_ids
                .into_iter()
                .filter_map(|id| {
                    by_project_and_id
                        .get(&format!("{}:{}", run.project.as_str(), id.as_str()))
                        .cloned()
                })
                .collect(),
            operations: run.operations,
        })
        .collect())
}

fn ui_pending_librarian_actions(
    store: &FileBlockStore,
    project: &ProjectName,
    pending: Vec<crate::librarian::PendingLibrarianAction>,
) -> Result<Vec<UiPendingLibrarianAction>, LoreError> {
    let all_blocks = store.list_blocks(project)?;
    let by_id = all_blocks
        .into_iter()
        .map(|block| (block.id.as_str().to_string(), block))
        .collect::<HashMap<_, _>>();
    Ok(pending
        .into_iter()
        .map(|action| UiPendingLibrarianAction {
            id: action.id,
            project: Some(project.as_str().to_string()),
            created_at: action.created_at,
            actor: action.actor,
            parent_run_id: action.parent_run_id,
            pending_run_id: action.pending_run_id,
            instruction: action.instruction,
            summary: action.summary,
            context_blocks: action
                .source_block_ids
                .into_iter()
                .filter_map(|id| by_id.get(id.as_str()).cloned())
                .collect(),
            operations: action
                .operations
                .iter()
                .map(StoredLibrarianOperation::from)
                .collect(),
        })
        .collect())
}

fn ui_pending_librarian_actions_all(
    store: &FileBlockStore,
    pending: Vec<crate::librarian::PendingLibrarianAction>,
) -> Result<Vec<UiPendingLibrarianAction>, LoreError> {
    let mut by_project_and_id = HashMap::new();
    for project in store.list_projects()? {
        for block in store.list_blocks(&project)? {
            by_project_and_id.insert(format!("{}:{}", project.as_str(), block.id.as_str()), block);
        }
    }
    Ok(pending
        .into_iter()
        .map(|action| UiPendingLibrarianAction {
            id: action.id,
            project: Some(action.project.as_str().to_string()),
            created_at: action.created_at,
            actor: action.actor,
            parent_run_id: action.parent_run_id,
            pending_run_id: action.pending_run_id,
            instruction: action.instruction,
            summary: action.summary,
            context_blocks: action
                .source_block_ids
                .into_iter()
                .filter_map(|id| {
                    by_project_and_id
                        .get(&format!("{}:{}", action.project.as_str(), id.as_str()))
                        .cloned()
                })
                .collect(),
            operations: action
                .operations
                .iter()
                .map(StoredLibrarianOperation::from)
                .collect(),
        })
        .collect())
}

async fn mcp_get() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

async fn mcp_delete(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session_id) = extract_header_ascii(&headers, MCP_SESSION_HEADER) else {
        return mcp_http_error(
            StatusCode::BAD_REQUEST,
            None,
            "missing MCP session header".into(),
        );
    };
    if let Ok(mut sessions) = state.mcp_sessions.lock() {
        if sessions.remove(&session_id).is_some() {
            return StatusCode::NO_CONTENT.into_response();
        }
        return mcp_http_error(StatusCode::BAD_REQUEST, None, "unknown MCP session".into());
    }
    mcp_http_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        None,
        "failed to access MCP session state".into(),
    )
}

async fn mcp_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let config = match state.config.load() {
        Ok(config) => config,
        Err(err) => {
            return mcp_http_error(StatusCode::INTERNAL_SERVER_ERROR, None, err.to_string());
        }
    };
    if let Err(err) = validate_mcp_origin(&headers, &config) {
        return mcp_http_error(StatusCode::FORBIDDEN, None, err.to_string());
    }
    if let Err(err) = validate_mcp_accept(&headers) {
        return mcp_http_error(StatusCode::BAD_REQUEST, None, err.to_string());
    }

    let id = payload.get("id").cloned();
    let method = match payload.get("method").and_then(Value::as_str) {
        Some(method) => method,
        None => {
            return mcp_http_error(
                StatusCode::BAD_REQUEST,
                id,
                "invalid json-rpc request: missing method".into(),
            );
        }
    };

    if let Some(version) = extract_header_ascii(&headers, MCP_PROTOCOL_VERSION_HEADER) {
        if version != MCP_PROTOCOL_VERSION && version != "2025-03-26" {
            return mcp_http_error(
                StatusCode::BAD_REQUEST,
                id,
                format!("unsupported MCP protocol version: {version}"),
            );
        }
    }

    match method {
        "initialize" => mcp_initialize(&state, &headers, id, &config),
        "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
        "ping" => mcp_json_response(id, json!({}), None),
        "tools/list" => match require_mcp_agent(&state, &headers) {
            Ok(_) => mcp_json_response(id, json!({ "tools": mcp_tools() }), None),
            Err(err) => mcp_http_error(StatusCode::FORBIDDEN, id, err.to_string()),
        },
        "tools/call" => match require_mcp_agent(&state, &headers)
            .and_then(|agent| call_mcp_tool(&state, &agent, payload.get("params")))
        {
            Ok(result) => mcp_json_response(id, result, None),
            Err(err) => mcp_json_response(
                id,
                json!({
                    "content": [{ "type": "text", "text": err.to_string() }],
                    "isError": true
                }),
                None,
            ),
        },
        _ => mcp_http_error(
            StatusCode::BAD_REQUEST,
            id,
            format!("unknown MCP method: {method}"),
        ),
    }
}

fn mcp_initialize(
    state: &AppState,
    headers: &HeaderMap,
    id: Option<Value>,
    config: &ServerConfig,
) -> Response {
    let raw_token = match extract_agent_token_candidate(headers) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return mcp_http_error(
                StatusCode::FORBIDDEN,
                id,
                "missing agent bearer token".into(),
            );
        }
        Err(err) => return mcp_http_error(StatusCode::FORBIDDEN, id, err.to_string()),
    };
    if let Err(e) = enforce_agent_auth_rate_limit(state) {
        return mcp_http_error(StatusCode::TOO_MANY_REQUESTS, id, e.to_string());
    }
    let agent = match state.auth.authenticate_agent_token(&raw_token) {
        Ok(a) => a,
        Err(err) => {
            record_failed_agent_auth(state);
            return mcp_http_error(StatusCode::FORBIDDEN, id, err.to_string());
        }
    };
    let token_hash = hash_agent_token(&raw_token);

    let session_id = Uuid::new_v4().to_string();
    match state.mcp_sessions.lock() {
        Ok(mut sessions) => {
            sessions.insert(session_id.clone(), McpSessionEntry { agent, token_hash });
        }
        Err(_) => {
            return mcp_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                id,
                "failed to create MCP session".into(),
            );
        }
    }

    mcp_json_response(
        id,
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": "lore",
                "title": "Lore MCP",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": format!(
                "{}\n\nAfter initialize, send the returned MCP session header on each tools/list, tools/call, and DELETE /mcp request.",
                build_agent_setup_instruction(config, None)
            )
        }),
        Some(&session_id),
    )
}

fn call_mcp_tool(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: Option<&Value>,
) -> Result<Value, LoreError> {
    let params = params
        .and_then(|value| value.as_object())
        .ok_or_else(|| LoreError::Validation("tool call params must be an object".into()))?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| LoreError::Validation("tool call name is required".into()))?;
    let args = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let structured = match name {
        "list_projects" => {
            let infos = state.store.list_project_infos()?;
            let projects = infos
                .into_iter()
                .filter(|info| agent.can_read(&info.slug))
                .map(|info| {
                    let perm = if agent.can_write(&info.slug) {
                        "read-write"
                    } else {
                        "read"
                    };
                    json!({ "project": info.display_name, "permission": perm })
                })
                .collect::<Vec<_>>();
            json!({ "projects": projects })
        }
        "list_documents" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_read(agent, &project)?;
            let docs = state.store.list_documents(&project)?;
            json!({ "documents": serialize_doc_tree(&docs) })
        }
        "get_project_overview" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_read(agent, &project)?;
            let block = state
                .store
                .get_reserved_block(&project, RESERVED_OVERVIEW)?;
            json!({ "project": project.as_str(), "overview": block.content })
        }
        "get_file_map" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_read(agent, &project)?;
            let block = state.store.get_reserved_block(&project, RESERVED_MAP)?;
            json!({ "project": project.as_str(), "file_map": block.content })
        }
        "update_file_map" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let content = required_string(&args, "content")?;
            let block =
                state
                    .store
                    .update_reserved_block(&project, RESERVED_MAP, &content, true)?;
            json!({ "project": project.as_str(), "file_map": block.content })
        }
        "edit_file_map" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let old_string = required_string(&args, "old_string")?;
            let new_string = required_string(&args, "new_string")?;
            let existing = state.store.get_reserved_block(&project, RESERVED_MAP)?;
            let count = existing.content.matches(&old_string).count();
            if count == 0 {
                return Err(LoreError::Validation(
                    "old_string not found in file map".into(),
                ));
            }
            if count > 1 {
                return Err(LoreError::Validation(format!(
                    "old_string found {count} times — must be unique"
                )));
            }
            let new_content = existing.content.replacen(&old_string, &new_string, 1);
            let block =
                state
                    .store
                    .update_reserved_block(&project, RESERVED_MAP, &new_content, true)?;
            json!({ "edited": true, "project": project.as_str(), "file_map": block.content })
        }
        "get_agent_context" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_read(agent, &project)?;
            let block = state
                .store
                .get_reserved_block(&project, RESERVED_AGENT_CONTEXT)?;
            json!({ "project": project.as_str(), "agent_context": block.content })
        }
        "create_document" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_name = required_string(&args, "name")?;
            let parent_doc = optional_string(&args, "parent_document_id")
                .map(DocumentId::from_string)
                .transpose()?;
            let doc = state
                .store
                .create_document(&project, parent_doc.as_ref(), &doc_name)?;
            json!({ "document_id": doc.id.as_str(), "name": doc.display_name })
        }
        "rename_document" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let new_name = required_string(&args, "name")?;
            state.store.rename_document(&project, &doc_id, &new_name)?;
            json!({ "renamed": true, "document_id": doc_id.as_str() })
        }
        "delete_document" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            state.store.delete_document(&project, &doc_id)?;
            json!({ "deleted": true, "document_id": doc_id.as_str() })
        }
        "list_blocks" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_read(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let blocks = state.store.list_doc_blocks(&project, &doc_id)?;
            let summaries: Vec<Value> = blocks
                .iter()
                .map(|b| {
                    let preview = b
                        .content
                        .lines()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(80)
                        .collect::<String>();
                    json!({
                        "block_id": b.id.as_str(),
                        "block_type": format!("{:?}", b.block_type).to_lowercase(),
                        "preview": preview,
                        "lines": b.content.lines().count(),
                    })
                })
                .collect();
            json!({ "blocks": summaries })
        }
        "read_block" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_read(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let block_id = required_block_id(&args, "block_id")?;
            let block = state.store.get_doc_block(&project, &doc_id, &block_id)?;
            let offset = optional_usize(&args, "offset");
            let limit = optional_usize(&args, "limit");
            if offset.is_some() || limit.is_some() {
                let lines: Vec<&str> = block.content.lines().collect();
                let total = lines.len();
                let start = offset.unwrap_or(0).min(total);
                let end = match limit {
                    Some(l) => (start + l).min(total),
                    None => total,
                };
                let numbered: String = lines[start..end]
                    .iter()
                    .enumerate()
                    .map(|(i, l)| format!("{}\t{}", start + i + 1, l))
                    .collect::<Vec<_>>()
                    .join("\n");
                json!({
                    "block_id": block.id.as_str(),
                    "block_type": format!("{:?}", block.block_type).to_lowercase(),
                    "total_lines": total,
                    "offset": start,
                    "limit": end - start,
                    "content": numbered,
                })
            } else {
                json!({ "block": block })
            }
        }
        "update_block" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let block_id = required_block_id(&args, "block_id")?;
            let content = required_string(&args, "content")?;
            let existing = state.store.get_doc_block(&project, &doc_id, &block_id)?;
            let block_type =
                optional_block_type(&args, "block_type")?.unwrap_or(existing.block_type);
            let before = state
                .store
                .snapshot_doc_block(&project, &doc_id, &block_id)?;
            let block = state.store.update_doc_block(
                &doc_id,
                UpdateBlock {
                    project: project.clone(),
                    block_id: block_id.clone(),
                    block_type,
                    content,
                    author_key: agent.token.clone(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )?;
            let version_op = update_doc_version_operation(
                state,
                &project,
                &doc_id,
                &block_id,
                before,
                ProjectVersionOperationType::UpdateBlock,
            )?;
            let actor = ProjectVersionActor {
                kind: ProjectVersionActorKind::Agent,
                name: agent.name.clone(),
            };
            record_project_version(
                state,
                &actor,
                &project,
                "update document block (MCP)",
                vec![version_op],
            )?;
            json!({ "block": block })
        }
        "edit_block" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let block_id = required_block_id(&args, "block_id")?;
            let old_string = required_string(&args, "old_string")?;
            let new_string = required_string(&args, "new_string")?;
            let existing = state.store.get_doc_block(&project, &doc_id, &block_id)?;
            let count = existing.content.matches(&old_string).count();
            if count == 0 {
                return Err(LoreError::Validation(
                    "old_string not found in block".into(),
                ));
            }
            if count > 1 {
                return Err(LoreError::Validation(format!(
                    "old_string found {count} times — must be unique"
                )));
            }
            let before = state
                .store
                .snapshot_doc_block(&project, &doc_id, &block_id)?;
            let new_content = existing.content.replacen(&old_string, &new_string, 1);
            let block = state.store.update_doc_block(
                &doc_id,
                UpdateBlock {
                    project: project.clone(),
                    block_id: block_id.clone(),
                    block_type: existing.block_type,
                    content: new_content,
                    author_key: agent.token.clone(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )?;
            let version_op = update_doc_version_operation(
                state,
                &project,
                &doc_id,
                &block_id,
                before,
                ProjectVersionOperationType::UpdateBlock,
            )?;
            let actor = ProjectVersionActor {
                kind: ProjectVersionActorKind::Agent,
                name: agent.name.clone(),
            };
            record_project_version(
                state,
                &actor,
                &project,
                "edit document block (MCP)",
                vec![version_op],
            )?;
            json!({ "edited": true, "block": block })
        }
        "create_block" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let after_block_id = optional_block_id(&args, "after_block_id")?;
            let (left, right) = state.store.resolve_after_doc_block(
                &project,
                &doc_id,
                after_block_id.as_ref(),
                None,
            )?;
            let block_type =
                optional_block_type(&args, "block_type")?.unwrap_or(BlockType::Markdown);
            let block = state.store.create_doc_block(
                &doc_id,
                NewBlock {
                    project: project.clone(),
                    block_type,
                    content: required_string(&args, "content")?,
                    author_key: agent.token.clone(),
                    left,
                    right,
                    image_upload: None,
                },
            )?;
            let version_op = create_doc_version_operation(state, &project, &doc_id, &block.id)?;
            let actor = ProjectVersionActor {
                kind: ProjectVersionActorKind::Agent,
                name: agent.name.clone(),
            };
            record_project_version(
                state,
                &actor,
                &project,
                "create document block (MCP)",
                vec![version_op],
            )?;
            json!({ "block": block })
        }
        "move_block" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let block_id = required_block_id(&args, "block_id")?;
            let after_block_id = optional_block_id(&args, "after_block_id")?;
            let before = state
                .store
                .snapshot_doc_block(&project, &doc_id, &block_id)?;
            let block = state.store.move_doc_block_after(
                &project,
                &doc_id,
                &block_id,
                after_block_id.as_ref(),
                &agent.token,
            )?;
            let version_op = update_doc_version_operation(
                state,
                &project,
                &doc_id,
                &block.id,
                before,
                ProjectVersionOperationType::MoveBlock,
            )?;
            let actor = ProjectVersionActor {
                kind: ProjectVersionActorKind::Agent,
                name: agent.name.clone(),
            };
            record_project_version(
                state,
                &actor,
                &project,
                "move document block (MCP)",
                vec![version_op],
            )?;
            json!({ "block": block })
        }
        "delete_block" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let block_id = required_block_id(&args, "block_id")?;
            let before = state
                .store
                .snapshot_doc_block(&project, &doc_id, &block_id)?;
            state
                .store
                .delete_doc_block(&project, &doc_id, &block_id, &agent.token)?;
            let version_op = StoredProjectVersionOperation {
                operation_type: ProjectVersionOperationType::DeleteBlock,
                block_id: block_id.clone(),
                before: Some(before),
                after: None,
                document_id: Some(doc_id.as_str().to_string()),
            };
            let actor = ProjectVersionActor {
                kind: ProjectVersionActorKind::Agent,
                name: agent.name.clone(),
            };
            record_project_version(
                state,
                &actor,
                &project,
                "delete document block (MCP)",
                vec![version_op],
            )?;
            json!({ "deleted": true, "block_id": block_id.as_str() })
        }
        "split_block" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let block_id = required_block_id(&args, "block_id")?;
            let position = required_usize(&args, "position")?;
            let before = state
                .store
                .snapshot_doc_block(&project, &doc_id, &block_id)?;
            let author = KeyFingerprint::from_api_key(&agent.token)?;
            let (updated, new_block) = state
                .store
                .split_doc_block(&project, &doc_id, &block_id, position, author)?;
            let ops = vec![
                update_doc_version_operation(
                    state,
                    &project,
                    &doc_id,
                    &updated.id,
                    before,
                    ProjectVersionOperationType::UpdateBlock,
                )?,
                create_doc_version_operation(state, &project, &doc_id, &new_block.id)?,
            ];
            let actor = ProjectVersionActor {
                kind: ProjectVersionActorKind::Agent,
                name: agent.name.clone(),
            };
            record_project_version(state, &actor, &project, "split document block (MCP)", ops)?;
            json!({ "original": updated, "new_block": new_block })
        }
        "combine_blocks" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let block_ids: Vec<BlockId> = required_string_array(&args, "block_ids")?
                .into_iter()
                .map(|s| BlockId::from_string(s))
                .collect::<crate::error::Result<Vec<_>>>()?;
            let befores: Vec<_> = block_ids
                .iter()
                .map(|bid| state.store.snapshot_doc_block(&project, &doc_id, bid))
                .collect::<crate::error::Result<Vec<_>>>()?;
            let author = KeyFingerprint::from_api_key(&agent.token)?;
            let merged = state
                .store
                .combine_doc_blocks(&project, &doc_id, &block_ids, author)?;
            let mut ops = vec![update_doc_version_operation(
                state,
                &project,
                &doc_id,
                &merged.id,
                befores[0].clone(),
                ProjectVersionOperationType::UpdateBlock,
            )?];
            for (i, bid) in block_ids[1..].iter().enumerate() {
                ops.push(StoredProjectVersionOperation {
                    operation_type: ProjectVersionOperationType::DeleteBlock,
                    block_id: bid.clone(),
                    before: Some(befores[i + 1].clone()),
                    after: None,
                    document_id: Some(doc_id.as_str().to_string()),
                });
            }
            let actor = ProjectVersionActor {
                kind: ProjectVersionActorKind::Agent,
                name: agent.name.clone(),
            };
            record_project_version(
                state,
                &actor,
                &project,
                "combine document blocks (MCP)",
                ops,
            )?;
            json!({ "merged": true, "block": merged })
        }
        "grep_blocks" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_read(agent, &project)?;
            let query = required_string(&args, "query")?;
            let ctx_lines = optional_usize(&args, "context_lines").unwrap_or(2);
            let needle = query.to_lowercase();
            let doc_id = optional_string(&args, "document_id")
                .map(DocumentId::from_string)
                .transpose()?;
            match doc_id {
                Some(did) => {
                    let blocks = state.store.list_doc_blocks(&project, &did)?;
                    let matches = grep_blocks_with_lines(&blocks, &needle, ctx_lines);
                    json!({ "matches": matches })
                }
                None => {
                    let docs = state.store.list_documents(&project)?;
                    let matches = grep_all_docs(state, &project, &docs, &needle, ctx_lines);
                    json!({ "matches": matches })
                }
            }
        }
        "read_document" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_read(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let start = optional_string(&args, "start_block_id")
                .map(BlockId::from_string)
                .transpose()?;
            let end = optional_string(&args, "end_block_id")
                .map(BlockId::from_string)
                .transpose()?;
            let text =
                state
                    .store
                    .read_document_text(&project, &doc_id, start.as_ref(), end.as_ref())?;
            json!({ "content": text })
        }
        "write_document" => {
            let project = required_project(&args, "project", &state.store)?;
            authorize_agent_write(agent, &project)?;
            let doc_id = required_document_id(&args, "document_id")?;
            let content = required_string(&args, "content")?;

            let entries = crate::store::parse_document_text(&content)?;

            // Snapshot current blocks before write
            let current_blocks = state.store.list_doc_blocks(&project, &doc_id)?;
            let mut before_snapshots: HashMap<String, StoredBlockSnapshot> = HashMap::new();
            for block in &current_blocks {
                if let Ok(snap) = state.store.snapshot_doc_block(&project, &doc_id, &block.id) {
                    before_snapshots.insert(block.id.as_str().to_string(), snap);
                }
            }

            let author = KeyFingerprint::from_api_key(&agent.token)?;
            let result = state
                .store
                .write_document_text(&project, &doc_id, entries, author)?;

            // Build version operations
            let mut ops = Vec::new();
            for block in &result.updated {
                if let Some(before) = before_snapshots.get(block.id.as_str()) {
                    if let Ok(after) = state.store.snapshot_doc_block(&project, &doc_id, &block.id)
                    {
                        ops.push(StoredProjectVersionOperation {
                            operation_type: ProjectVersionOperationType::UpdateBlock,
                            block_id: block.id.clone(),
                            before: Some(before.clone()),
                            after: Some(after),
                            document_id: Some(doc_id.as_str().to_string()),
                        });
                    }
                }
            }
            for (_, block) in &result.created {
                if let Ok(after) = state.store.snapshot_doc_block(&project, &doc_id, &block.id) {
                    ops.push(StoredProjectVersionOperation {
                        operation_type: ProjectVersionOperationType::CreateBlock,
                        block_id: block.id.clone(),
                        before: None,
                        after: Some(after),
                        document_id: Some(doc_id.as_str().to_string()),
                    });
                }
            }
            for deleted_id in &result.deleted {
                if let Some(before) = before_snapshots.get(deleted_id.as_str()) {
                    ops.push(StoredProjectVersionOperation {
                        operation_type: ProjectVersionOperationType::DeleteBlock,
                        block_id: deleted_id.clone(),
                        before: Some(before.clone()),
                        after: None,
                        document_id: Some(doc_id.as_str().to_string()),
                    });
                }
            }
            if !ops.is_empty() {
                let actor = ProjectVersionActor {
                    kind: ProjectVersionActorKind::Agent,
                    name: agent.name.clone(),
                };
                record_project_version(state, &actor, &project, "write document (MCP)", ops)?;
            }

            let created_map: Vec<Value> = result
                .created
                .iter()
                .map(|(placeholder, block)| {
                    json!({
                        "placeholder_id": placeholder,
                        "block_id": block.id.as_str(),
                    })
                })
                .collect();
            let updated_ids: Vec<&str> = result.updated.iter().map(|b| b.id.as_str()).collect();
            let deleted_ids: Vec<&str> = result.deleted.iter().map(|b| b.as_str()).collect();

            json!({
                "created": created_map,
                "updated": updated_ids,
                "deleted": deleted_ids,
            })
        }
        other => {
            return Err(LoreError::Validation(format!("unknown tool: {other}")));
        }
    };

    Ok(json!({
        "content": [{ "type": "text", "text": structured.to_string() }],
        "structuredContent": structured
    }))
}

fn required_document_id(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<DocumentId, LoreError> {
    DocumentId::from_string(required_string(args, key)?)
}

fn grep_all_docs(
    state: &AppState,
    project: &ProjectName,
    docs: &[crate::store::DocumentInfo],
    needle: &str,
    ctx_lines: usize,
) -> Vec<ProjectDocGrepMatch> {
    let mut results = Vec::new();
    for doc in docs {
        if let Ok(blocks) = state.store.list_doc_blocks(project, &doc.id) {
            for m in grep_blocks_with_lines(&blocks, needle, ctx_lines) {
                results.push(ProjectDocGrepMatch {
                    document_id: doc.id.as_str().to_string(),
                    document_name: doc.display_name.clone(),
                    block_id: m.block_id,
                    block_type: m.block_type,
                    line: m.line,
                    content: m.content,
                    context_before: m.context_before,
                    context_after: m.context_after,
                });
            }
        }
        results.extend(grep_all_docs(
            state,
            project,
            &doc.children,
            needle,
            ctx_lines,
        ));
    }
    results
}

fn require_mcp_agent(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedAgent, LoreError> {
    let session_id = extract_header_ascii(headers, MCP_SESSION_HEADER)
        .ok_or_else(|| LoreError::Validation("missing MCP session header".into()))?;
    let raw_token = extract_agent_token_candidate(headers)?
        .ok_or_else(|| LoreError::Validation("missing bearer token on MCP request".into()))?;
    let presented_hash = hash_agent_token(&raw_token);
    let sessions = state
        .mcp_sessions
        .lock()
        .map_err(|_| LoreError::Validation("failed to access MCP session state".into()))?;
    let entry = sessions
        .get(&session_id)
        .ok_or_else(|| LoreError::Validation("unknown MCP session".into()))?;
    if !constant_time_eq(&presented_hash, &entry.token_hash) {
        return Err(LoreError::PermissionDenied);
    }
    Ok(entry.agent.clone())
}

fn validate_mcp_origin(headers: &HeaderMap, config: &ServerConfig) -> Result<(), LoreError> {
    let Some(origin) = extract_header_ascii(headers, header::ORIGIN.as_str()) else {
        return Ok(());
    };
    if origin == config.base_url() {
        Ok(())
    } else {
        Err(LoreError::PermissionDenied)
    }
}

fn validate_mcp_accept(headers: &HeaderMap) -> Result<(), LoreError> {
    let Some(accept) = extract_header_ascii(headers, header::ACCEPT.as_str()) else {
        return Ok(());
    };
    if accept.contains("application/json") || accept.contains("text/event-stream") {
        Ok(())
    } else {
        Err(LoreError::Validation(
            "MCP requests must accept application/json or text/event-stream".into(),
        ))
    }
}

fn extract_header_ascii(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_string)
}

fn authorize_agent_read(
    agent: &AuthenticatedAgent,
    project: &ProjectName,
) -> Result<(), LoreError> {
    if agent.can_read(project) {
        Ok(())
    } else {
        Err(LoreError::PermissionDenied)
    }
}

fn authorize_agent_write(
    agent: &AuthenticatedAgent,
    project: &ProjectName,
) -> Result<(), LoreError> {
    if agent.can_write(project) {
        Ok(())
    } else {
        Err(LoreError::PermissionDenied)
    }
}

fn required_string(args: &serde_json::Map<String, Value>, key: &str) -> Result<String, LoreError> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| LoreError::Validation(format!("{key} is required")))
}

fn optional_string(args: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_string)
}

fn required_project(
    args: &serde_json::Map<String, Value>,
    key: &str,
    store: &FileBlockStore,
) -> Result<ProjectName, LoreError> {
    let input = required_string(args, key)?;
    store.resolve_project(&input)
}

fn required_block_id(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<BlockId, LoreError> {
    BlockId::from_string(required_string(args, key)?)
}

fn optional_block_id(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<BlockId>, LoreError> {
    match args.get(key) {
        Some(Value::String(value)) => Ok(Some(BlockId::from_string(value.clone())?)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(LoreError::Validation(format!(
            "{key} must be a string or null"
        ))),
    }
}

fn optional_usize(args: &serde_json::Map<String, Value>, key: &str) -> Option<usize> {
    args.get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

fn required_usize(args: &serde_json::Map<String, Value>, key: &str) -> Result<usize, LoreError> {
    optional_usize(args, key)
        .ok_or_else(|| LoreError::Validation(format!("{key} is required (integer)")))
}

fn required_string_array(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, LoreError> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .ok_or_else(|| LoreError::Validation(format!("{key} is required (array of strings)")))
}

fn optional_block_type(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<BlockType>, LoreError> {
    match args.get(key) {
        Some(Value::String(value)) => Ok(Some(parse_block_type(value)?)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(LoreError::Validation(format!(
            "{key} must be a string or null"
        ))),
    }
}

fn mcp_json_response(id: Option<Value>, result: Value, session_id: Option<&str>) -> Response {
    let mut response =
        Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        HeaderName::from_static(MCP_PROTOCOL_VERSION_HEADER),
        HeaderValue::from_static(MCP_PROTOCOL_VERSION),
    );
    if let Some(session_id) = session_id {
        if let Ok(value) = HeaderValue::from_str(session_id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static(MCP_SESSION_HEADER), value);
        }
    }
    response
}

fn mcp_http_error(status: StatusCode, id: Option<Value>, message: String) -> Response {
    let mut response = (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32600,
                "message": message
            }
        })),
    )
        .into_response();
    response.headers_mut().insert(
        HeaderName::from_static(MCP_PROTOCOL_VERSION_HEADER),
        HeaderValue::from_static(MCP_PROTOCOL_VERSION),
    );
    response
}

fn mcp_tools() -> Vec<Value> {
    vec![
        json!({
            "name": "list_projects",
            "title": "List Projects",
            "description": "List projects the agent has access to, with names and permission levels.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "list_documents",
            "title": "List Documents",
            "description": "List documents under a project as a tree. Returns document IDs, names, and nesting structure.",
            "inputSchema": schema_with_required_property("project", "string", "Lore project name")
        }),
        json!({
            "name": "get_project_overview",
            "title": "Get Project Overview",
            "description": "Read the project overview — a short summary of what the project is about.",
            "inputSchema": schema_with_required_property("project", "string", "Lore project name")
        }),
        json!({
            "name": "get_file_map",
            "title": "Get File Map",
            "description": "Read the project file map — a listing of key project files.",
            "inputSchema": schema_with_required_property("project", "string", "Lore project name")
        }),
        json!({
            "name": "update_file_map",
            "title": "Update File Map",
            "description": "Replace the entire file map content for a project.",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("content", "string", "New file map content")
            ])
        }),
        json!({
            "name": "edit_file_map",
            "title": "Edit File Map",
            "description": "Apply a targeted find-and-replace within the project file map. The old_string must match exactly once.",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("old_string", "string", "Exact text to find (must be unique)"),
                ("new_string", "string", "Replacement text")
            ])
        }),
        json!({
            "name": "get_agent_context",
            "title": "Get Agent Context",
            "description": "Read the agent context for a project — instructions and context set by the project owner for agents.",
            "inputSchema": schema_with_required_property("project", "string", "Lore project name")
        }),
        json!({
            "name": "create_document",
            "title": "Create Document",
            "description": "Create a new document under a project or parent document.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "name": { "type": "string", "description": "Document display name" },
                    "parent_document_id": { "type": ["string", "null"], "description": "Parent document ID for nesting (null = directly under project)" }
                },
                "required": ["project", "name"]
            }
        }),
        json!({
            "name": "rename_document",
            "title": "Rename Document",
            "description": "Rename an existing document.",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("document_id", "string", "Document UUID"),
                ("name", "string", "New display name")
            ])
        }),
        json!({
            "name": "delete_document",
            "title": "Delete Document",
            "description": "Delete a document and all its contents (blocks and sub-documents).",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("document_id", "string", "Document UUID")
            ])
        }),
        json!({
            "name": "list_blocks",
            "title": "List Blocks",
            "description": "List all blocks in a document. Returns block IDs, types, and first-line previews.",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("document_id", "string", "Document UUID")
            ])
        }),
        json!({
            "name": "read_block",
            "title": "Read Block",
            "description": "Read a document block's content or a line range within it. Use offset/limit for large blocks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "block_id": { "type": "string", "description": "Block UUID" },
                    "offset": { "type": "integer", "description": "Starting line (0-based). Omit to read from beginning.", "minimum": 0 },
                    "limit": { "type": "integer", "description": "Max lines to read. Omit to read all.", "minimum": 1 }
                },
                "required": ["project", "document_id", "block_id"]
            }
        }),
        json!({
            "name": "update_block",
            "title": "Update Block",
            "description": "Replace the entire content of a document block. Use for small blocks or full rewrites.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "block_id": { "type": "string", "description": "Block UUID" },
                    "content": { "type": "string", "description": "New content" },
                    "block_type": { "type": ["string", "null"], "enum": ["markdown", "html", "svg", "image", null] }
                },
                "required": ["project", "document_id", "block_id", "content"]
            }
        }),
        json!({
            "name": "edit_block",
            "title": "Edit Block",
            "description": "Apply a targeted find-and-replace within a document block. The old_string must match exactly once.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "block_id": { "type": "string", "description": "Block UUID" },
                    "old_string": { "type": "string", "description": "Exact text to find (must be unique)" },
                    "new_string": { "type": "string", "description": "Replacement text" }
                },
                "required": ["project", "document_id", "block_id", "old_string", "new_string"]
            }
        }),
        json!({
            "name": "create_block",
            "title": "Create Block",
            "description": "Create a new typed block in a document (default type: markdown).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "block_type": { "type": "string", "enum": ["markdown", "html", "svg", "image"], "description": "Block type (default: markdown)" },
                    "content": { "type": "string", "description": "Block content" },
                    "after_block_id": { "type": ["string", "null"], "description": "Place after this block (null = at start; CLI append mode resolves this automatically)" }
                },
                "required": ["project", "document_id", "content"]
            }
        }),
        json!({
            "name": "delete_block",
            "title": "Delete Block",
            "description": "Delete a block from a document.",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("document_id", "string", "Document UUID"),
                ("block_id", "string", "Block UUID")
            ])
        }),
        json!({
            "name": "move_block",
            "title": "Move Block",
            "description": "Reorder a block within a document.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "block_id": { "type": "string", "description": "Block UUID" },
                    "after_block_id": { "type": ["string", "null"], "description": "Place after this block (null = move to start)" }
                },
                "required": ["project", "document_id", "block_id"]
            }
        }),
        json!({
            "name": "split_block",
            "title": "Split Block",
            "description": "Split a markdown block at a character position. The original block keeps content before the position; a new block is created after it with the remaining content. Useful for inserting images or SVGs between text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "block_id": { "type": "string", "description": "Block UUID to split" },
                    "position": { "type": "integer", "description": "Character offset at which to split (1 to len-1)", "minimum": 1 }
                },
                "required": ["project", "document_id", "block_id", "position"]
            }
        }),
        json!({
            "name": "combine_blocks",
            "title": "Combine Blocks",
            "description": "Merge consecutive markdown blocks into one. Content is joined with newlines. The first block is kept; the rest are deleted. Blocks must be consecutive, non-pinned, and all markdown.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "block_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Ordered list of block UUIDs to combine (minimum 2)",
                        "minItems": 2
                    }
                },
                "required": ["project", "document_id", "block_ids"]
            }
        }),
        json!({
            "name": "grep_blocks",
            "title": "Grep Blocks",
            "description": "Search across block content in a document or all documents in a project. Returns block IDs, line numbers, and context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": ["string", "null"], "description": "Document UUID (null = search all documents in project)" },
                    "query": { "type": "string", "description": "Search query (case-insensitive substring match)" },
                    "context_lines": { "type": "integer", "description": "Lines of context before/after each match (default: 2)", "minimum": 0 }
                },
                "required": ["project", "query"]
            }
        }),
        json!({
            "name": "read_document",
            "title": "Read Document",
            "description": "Read all blocks in a document (or a range) as a single text with block boundary markers. Each block is wrapped in @@block id=ID type=TYPE ... @@end id=ID. Use for reading an entire document like a file. For surgical reads, prefer read_block.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "start_block_id": { "type": ["string", "null"], "description": "First block to include (null = from start)" },
                    "end_block_id": { "type": ["string", "null"], "description": "Last block to include (null = to end)" }
                },
                "required": ["project", "document_id"]
            }
        }),
        json!({
            "name": "write_document",
            "title": "Write Document",
            "description": "Write back a document using the same marker format from read_document. Lore diffs against current state: changed content is updated, missing blocks are deleted, new blocks are created. Image blocks are validated but never modified. SVG and markdown blocks can be edited. For new blocks, use any non-UUID string as the ID (e.g. 'new_heading', 'intro') — Lore replaces it with a real UUID. Existing blocks must use their real UUID. Returns a summary of changes made.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "document_id": { "type": "string", "description": "Document UUID" },
                    "content": { "type": "string", "description": "Full document in marker format (@@block id=ID type=TYPE ... @@end id=ID)" }
                },
                "required": ["project", "document_id", "content"]
            }
        }),
    ]
}

fn schema_with_required_property(name: &str, kind: &str, description: &str) -> Value {
    schema_with_required_properties(&[(name, kind, description)])
}

fn schema_with_required_properties(fields: &[(&str, &str, &str)]) -> Value {
    let mut properties = BTreeMap::new();
    let mut required = Vec::new();
    for (name, kind, description) in fields {
        properties.insert(
            (*name).to_string(),
            json!({
                "type": *kind,
                "description": *description,
            }),
        );
        required.push((*name).to_string());
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": required
    })
}

type ApiResult<T> = Result<T, ApiError>;
type UiResult<T> = Result<T, UiError>;

struct ApiError(LoreError);
struct UiError(LoreError);

impl From<LoreError> for ApiError {
    fn from(value: LoreError) -> Self {
        Self(value)
    }
}

impl From<LoreError> for UiError {
    fn from(value: LoreError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            LoreError::Validation(_) | LoreError::InvalidOrderRange => StatusCode::BAD_REQUEST,
            LoreError::BlockNotFound(_) => StatusCode::NOT_FOUND,
            LoreError::PermissionDenied | LoreError::BlockPinned => StatusCode::FORBIDDEN,
            LoreError::ExternalService(_) => StatusCode::BAD_GATEWAY,
            LoreError::Io(_) | LoreError::Json(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(ErrorBody {
            error: self.0.to_string(),
        });
        (status, body).into_response()
    }
}

impl IntoResponse for UiError {
    fn into_response(self) -> Response {
        if matches!(self.0, LoreError::PermissionDenied) {
            return Redirect::to("/login").into_response();
        }

        let status = match self.0 {
            LoreError::Validation(_) | LoreError::InvalidOrderRange => StatusCode::BAD_REQUEST,
            LoreError::BlockNotFound(_) => StatusCode::NOT_FOUND,
            LoreError::PermissionDenied => unreachable!(),
            LoreError::BlockPinned => StatusCode::FORBIDDEN,
            LoreError::ExternalService(_) => StatusCode::BAD_GATEWAY,
            LoreError::Io(_) | LoreError::Json(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Html(format!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Lore error</title><style>body{{margin:0;padding:24px;font-family:Inter,-apple-system,system-ui,sans-serif;background:#f0f0f0;color:#1a1a1a;line-height:1.5}}main{{max-width:32rem;margin:4rem auto;background:#fff;border:1px solid rgba(0,0,0,.1);border-radius:12px;padding:2rem;box-shadow:0 4px 12px rgba(0,0,0,0.08)}}h1{{margin:0 0 1rem;font-size:1.5rem;font-weight:700}}p{{margin:0 0 1rem}}a{{color:#4a6fa5;font-weight:600;text-decoration:none}}@media(prefers-color-scheme:dark){{body{{background:#1a1a2e;color:#e0e0e0}}main{{background:#252540;border-color:rgba(255,255,255,.1);box-shadow:0 4px 12px rgba(0,0,0,0.3)}}a{{color:#7da1d4}}}}</style></head><body><main><h1>Request failed</h1><p>{}</p><p><a href=\"javascript:history.back()\">Go back</a></p></main></body></html>",
            v_htmlescape::escape(&self.0.to_string())
        ));

        (status, body).into_response()
    }
}

async fn parse_create_block_form(mut multipart: Multipart) -> Result<CreateBlockForm, LoreError> {
    let mut csrf_token = String::new();
    let mut block_type = None;
    let mut content = String::new();
    let mut after_block_id = None;
    let mut image_upload = None;

    while let Some(field) = next_form_field(&mut multipart).await? {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "csrf_token" => csrf_token = field_text(field).await?,
            "block_type" => block_type = Some(parse_block_type(&field_text(field).await?)?),
            "content" => content = field_text(field).await?,
            "after_block_id" => after_block_id = empty_to_none(field_text(field).await?),
            "image_file" => image_upload = parse_image_upload(field).await?,
            _ => {}
        }
    }

    Ok(CreateBlockForm {
        csrf_token,
        block_type: block_type
            .ok_or_else(|| LoreError::Validation("block type is required".into()))?,
        content,
        after_block_id,
        image_upload,
    })
}

async fn parse_update_block_form(mut multipart: Multipart) -> Result<UpdateBlockForm, LoreError> {
    let mut csrf_token = String::new();
    let mut block_type = None;
    let mut content = String::new();
    let mut after_block_id = None;
    let mut image_upload = None;

    while let Some(field) = next_form_field(&mut multipart).await? {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "csrf_token" => csrf_token = field_text(field).await?,
            "block_type" => block_type = Some(parse_block_type(&field_text(field).await?)?),
            "content" => content = field_text(field).await?,
            "after_block_id" => after_block_id = empty_to_none(field_text(field).await?),
            "image_file" => image_upload = parse_image_upload(field).await?,
            _ => {}
        }
    }

    Ok(UpdateBlockForm {
        csrf_token,
        block_type,
        content,
        after_block_id,
        image_upload,
    })
}

async fn next_form_field(
    multipart: &mut Multipart,
) -> Result<Option<axum::extract::multipart::Field<'_>>, LoreError> {
    multipart
        .next_field()
        .await
        .map_err(|err| LoreError::Validation(format!("invalid multipart form: {err}")))
}

async fn field_text(field: axum::extract::multipart::Field<'_>) -> Result<String, LoreError> {
    field
        .text()
        .await
        .map_err(|err| LoreError::Validation(format!("invalid text field: {err}")))
}

async fn parse_image_upload(
    field: axum::extract::multipart::Field<'_>,
) -> Result<Option<ImageUpload>, LoreError> {
    let media_type = field.content_type().map(str::to_owned).unwrap_or_default();
    let bytes = field
        .bytes()
        .await
        .map_err(|err| LoreError::Validation(format!("invalid image upload: {err}")))?;
    if bytes.is_empty() {
        return Ok(None);
    }

    Ok(Some(ImageUpload {
        media_type,
        bytes: bytes.to_vec(),
    }))
}

fn parse_block_type(value: &str) -> Result<BlockType, LoreError> {
    match value {
        "markdown" => Ok(BlockType::Markdown),
        "html" => Ok(BlockType::Html),
        "svg" => Ok(BlockType::Svg),
        "image" => Ok(BlockType::Image),
        _ => Err(LoreError::Validation("unsupported block type".into())),
    }
}

fn parse_role_grants(input: &str) -> Result<Vec<ProjectGrant>, LoreError> {
    let grants = parse_project_grants(input)?;
    if grants.is_empty() {
        return Err(LoreError::Validation(
            "role must grant at least one project permission".into(),
        ));
    }
    Ok(grants)
}

fn parse_agent_grants(input: &str) -> Result<Vec<ProjectGrant>, LoreError> {
    parse_project_grants(input)
}

fn parse_project_grants(input: &str) -> Result<Vec<ProjectGrant>, LoreError> {
    let mut grants = Vec::new();
    for line in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (project, permission) = line.split_once(':').ok_or_else(|| {
            LoreError::Validation("grants must use one project:permission pair per line".into())
        })?;
        let permission = permission
            .trim()
            .to_ascii_lowercase()
            .replace([' ', '-'], "_");
        let permission = match permission.as_str() {
            "" | "none" | "no_access" => continue,
            "read" | "read_only" | "readonly" => ProjectPermission::Read,
            "read_write" | "readwrite" | "read/write" => ProjectPermission::ReadWrite,
            _ => {
                return Err(LoreError::Validation(
                    "permission must be read or read_write".into(),
                ));
            }
        };
        grants.push(ProjectGrant {
            project: ProjectName::new(project.trim())?,
            permission,
        });
    }
    Ok(grants)
}

fn parse_role_names_csv(input: &str) -> Result<Vec<RoleName>, LoreError> {
    input
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| RoleName::new(value.to_string()))
        .collect()
}

fn empty_to_none(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn grep_preview(content: &str, needle: &str) -> String {
    let content = content.trim();
    if content.is_empty() {
        return String::new();
    }

    let needle = needle.trim();
    if needle.is_empty() {
        return content.chars().take(120).collect();
    }

    let content_lower = content.to_lowercase();
    let needle_lower = needle.to_lowercase();
    let Some(index) = content_lower.find(&needle_lower) else {
        return content.chars().take(120).collect();
    };

    let start = index.saturating_sub(40);
    let end = (index + needle.len() + 40).min(content.len());
    let mut preview = content[start..end].trim().to_string();
    if start > 0 {
        preview.insert_str(0, "...");
    }
    if end < content.len() {
        preview.push_str("...");
    }
    preview
}

// --- Chat handlers ---

#[derive(Debug, Deserialize)]
struct ChatPageQuery {
    agent: Option<String>,
    project: Option<String>,
}

fn is_pending_follow_up_user_message(conv: &ChatConversation, msg: &ChatMessage) -> bool {
    matches!(msg.role, ChatRole::User)
        && !msg.excluded_from_context
        && msg.id > conv.active_turn_user_id
}

const UI_CHAT_VERBATIM_EXCHANGE_LIMIT: usize = 50;

fn unsummarized_messages(conv: &ChatConversation) -> &[ChatMessage] {
    let start = conv
        .messages
        .iter()
        .position(|msg| msg.id > conv.summary_until_id)
        .unwrap_or(conv.messages.len());
    &conv.messages[start..]
}

fn chat_message_json(msg: &ChatMessage) -> Value {
    json!({
        "id": msg.id,
        "role": match msg.role { ChatRole::User => "user", ChatRole::Assistant => "assistant", ChatRole::Tool => "tool", ChatRole::Error => "error" },
        "content": msg.content,
        "timestamp": msg.timestamp.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "excluded_from_context": msg.excluded_from_context,
    })
}

fn agent_context_messages(messages: &[ChatMessage]) -> Vec<&ChatMessage> {
    messages
        .iter()
        .filter(|msg| !msg.excluded_from_context)
        .collect()
}

fn recent_exchange_tail(messages: &[ChatMessage], exchange_limit: usize) -> &[ChatMessage] {
    if exchange_limit == 0 || messages.is_empty() {
        return &messages[messages.len()..];
    }
    let visible: Vec<&ChatMessage> = messages.iter().collect();
    let boundaries = exchange_boundaries(&visible);
    if boundaries.len() <= exchange_limit {
        return messages;
    }
    &messages[boundaries[boundaries.len() - exchange_limit]..]
}

fn chat_messages_value_ordered(conv: &ChatConversation) -> (Vec<Value>, Vec<Value>) {
    let mut main = Vec::new();
    let mut pending = Vec::new();
    for msg in recent_exchange_tail(&conv.messages, UI_CHAT_VERBATIM_EXCHANGE_LIMIT) {
        let value = chat_message_json(msg);
        if is_pending_follow_up_user_message(conv, msg) {
            pending.push(value);
        } else {
            main.push(value);
        }
    }
    (main, pending)
}

fn should_append_finished_message(conv: &ChatConversation) -> bool {
    if conv.agent_status != AgentChatStatus::Idle {
        return false;
    }
    if conv.active_turn_user_id == 0 || conv.last_delivered_user_id != conv.active_turn_user_id {
        return false;
    }
    let Some(last_msg) = conv
        .messages
        .iter()
        .rev()
        .take_while(|msg| msg.id > conv.summary_until_id)
        .find(|msg| !is_pending_follow_up_user_message(conv, msg))
    else {
        return false;
    };
    if last_msg.id <= conv.active_turn_user_id {
        return false;
    }
    matches!(
        last_msg.role,
        ChatRole::Assistant | ChatRole::Tool | ChatRole::Error
    )
}

fn chat_messages_value_for_panel(conv: &ChatConversation) -> Vec<Value> {
    let (mut messages, pending_follow_ups) = chat_messages_value_ordered(conv);
    if should_append_finished_message(conv) {
        messages.push(json!({
            "role": "system",
            "content": "✅ Finished",
        }));
    }
    messages.extend(pending_follow_ups);
    messages
}

fn active_turn_user_id_for_ui(conv: &ChatConversation) -> u64 {
    conv.active_turn_user_id
}

fn build_chat_agents(
    state: &AppState,
    username: &UserName,
) -> Result<Vec<ChatAgentSummary>, LoreError> {
    let user = username.as_str().to_string();
    let agents: Vec<StoredAgentToken> = state.auth.list_agent_tokens_for_user(username)?;
    let mut chat_agents: Vec<(Option<OffsetDateTime>, ChatAgentSummary)> = Vec::new();
    for agent in &agents {
        let owner = agent.owner.as_ref().map(|o| o.as_str()).unwrap_or("");
        let conv = state.chat.load_conversation(owner, &agent.name)?;
        let last_msg = conv
            .messages
            .iter()
            .rev()
            .find(|m| !m.excluded_from_context);
        let last_user = conv
            .messages
            .iter()
            .rev()
            .find(|m| m.role == ChatRole::User && !m.excluded_from_context);
        let last_user_at = last_user.map(|m| m.timestamp);
        let snippet = last_msg.map(|m| m.content.chars().take(60).collect::<String>());
        let time_str = last_user_at.map(format_chat_time);
        chat_agents.push((
            last_user_at,
            ChatAgentSummary {
                name: agent.name.clone(),
                display_name: agent
                    .display_name
                    .clone()
                    .unwrap_or_else(|| agent.name.clone()),
                owner: owner.to_string(),
                status: match conv.agent_status {
                    AgentChatStatus::Idle => "idle".to_string(),
                    AgentChatStatus::Thinking => "thinking".to_string(),
                    AgentChatStatus::Offline => "offline".to_string(),
                },
                manage_enabled: conv
                    .manage_config
                    .as_ref()
                    .map(|mc| mc.enabled)
                    .unwrap_or(false),
                last_message: snippet,
                last_message_time: time_str,
                profile_url: conv.profile_url.clone(),
                cwd: conv.cwd.clone(),
                git_branch: conv.git_branch.clone(),
            },
        ));
    }
    chat_agents.sort_by(|(a_ts, a_agent), (b_ts, b_agent)| {
        b_ts.cmp(a_ts).then_with(|| {
            if a_agent.owner == user && b_agent.owner == user {
                a_agent.name.cmp(&b_agent.name)
            } else {
                a_agent
                    .owner
                    .cmp(&b_agent.owner)
                    .then_with(|| a_agent.name.cmp(&b_agent.name))
            }
        })
    });
    Ok(chat_agents.into_iter().map(|(_, agent)| agent).collect())
}

fn load_chat_panel_data(
    state: &AppState,
    owner: &str,
    selected_agent: Option<&str>,
) -> Result<(Vec<Value>, Option<String>, Option<String>, u64), LoreError> {
    if let Some(agent_name) = selected_agent {
        if agent_name == "librarian" {
            Ok((Vec::new(), Some("librarian".to_string()), None, 0))
        } else {
            let conv = state.chat.load_conversation(owner, agent_name)?;
            let agent_status = match conv.agent_status {
                AgentChatStatus::Idle => "idle",
                AgentChatStatus::Thinking => "thinking",
                AgentChatStatus::Offline => "offline",
            };
            Ok((
                chat_messages_value_for_panel(&conv),
                Some(agent_name.to_string()),
                Some(agent_status.to_string()),
                active_turn_user_id_for_ui(&conv),
            ))
        }
    } else {
        Ok((Vec::new(), None, None, 0))
    }
}

async fn chat_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ChatPageQuery>,
) -> UiResult<Html<String>> {
    let session = require_ui_session(&state, &headers)?;
    let config = state.config.load()?;
    let chat_agents = build_chat_agents(&state, &session.user.username)?;

    let project_infos = state.store.list_project_infos().unwrap_or_default();
    let projects_for_ui: Vec<(String, String)> = project_infos
        .iter()
        .filter(|p| session.user.is_admin || session.user.can_read(&p.slug))
        .map(|p| (p.slug.as_str().to_string(), p.display_name.clone()))
        .collect();

    let (messages, selected_owned, _selected_status, active_turn_user_id) = load_chat_panel_data(
        &state,
        session.user.username.as_str(),
        query.agent.as_deref(),
    )?;
    let messages_json = serde_json::to_string(&messages).unwrap_or_else(|_| "[]".into());
    let selected = selected_owned.as_deref();

    Ok(Html(render_chat_page(
        resolved_theme(&session.user, &config),
        resolved_color_mode(&session.user),
        session.user.username.as_str(),
        &session.csrf_token,
        session.user.is_admin,
        &chat_agents,
        selected,
        &messages_json,
        active_turn_user_id,
        None,
        &projects_for_ui,
    )))
}

async fn chat_panel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ChatPageQuery>,
) -> Response {
    match chat_panel_inner(&state, &headers, &query).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

async fn chat_panel_inner(
    state: &AppState,
    headers: &HeaderMap,
    query: &ChatPageQuery,
) -> Result<Value, LoreError> {
    let session = require_ui_session(state, headers)?;
    let chat_agents = build_chat_agents(state, &session.user.username)?;
    let project_infos = state.store.list_project_infos().unwrap_or_default();
    let projects_for_ui: Vec<(String, String)> = project_infos
        .iter()
        .filter(|p| session.user.is_admin || session.user.can_read(&p.slug))
        .map(|p| (p.slug.as_str().to_string(), p.display_name.clone()))
        .collect();
    let (messages, selected_owned, selected_status, active_turn_user_id) = load_chat_panel_data(
        state,
        session.user.username.as_str(),
        query.agent.as_deref(),
    )?;
    let selected = selected_owned.as_deref();
    let panel_html = render_chat_main_panel(
        &chat_agents,
        selected,
        &session.csrf_token,
        &projects_for_ui,
    );
    let profile_url = selected.and_then(|name| {
        chat_agents
            .iter()
            .find(|agent| agent.name == name)
            .and_then(|agent| agent.profile_url.clone())
    });
    Ok(json!({
        "ok": true,
        "selected_agent": selected,
        "is_librarian": selected == Some("librarian"),
        "agent_list_html": render_chat_agent_list(&chat_agents, selected),
        "panel_html": panel_html,
        "messages": messages,
        "agent_status": selected_status,
        "active_turn_user_id": active_turn_user_id,
        "profile_url": profile_url,
    }))
}

#[derive(Debug, Deserialize)]
struct LibrarianChatHistoryQuery {
    project: Option<String>,
}

async fn librarian_chat_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LibrarianChatHistoryQuery>,
) -> Response {
    match librarian_chat_history_inner(&state, &headers, &query).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => Json(json!({ "messages": [], "pending_actions": [], "error": e.to_string() }))
            .into_response(),
    }
}

async fn librarian_chat_history_inner(
    state: &AppState,
    headers: &HeaderMap,
    query: &LibrarianChatHistoryQuery,
) -> Result<Value, LoreError> {
    let session = require_ui_session(state, headers)?;
    let owner = session.user.username.as_str();
    let specific_project = match query.project {
        Some(ref p) if !p.is_empty() => Some(ProjectName::new(p.clone())?),
        _ => None,
    };

    let (runs, pending) = if let Some(ref project) = specific_project {
        state.auth.authorize_read(&session.user, project)?;
        (
            state.librarian_history.list_recent_project(project, 50)?,
            state.pending_librarian_actions.list_project(project, 20)?,
        )
    } else {
        let all_runs = state.librarian_history.list_recent_all(50)?;
        let accessible_runs = all_runs
            .into_iter()
            .filter(|r| session.user.can_read(&r.project))
            .collect();
        let all_pending = state.pending_librarian_actions.list_all(20)?;
        let accessible_pending = all_pending
            .into_iter()
            .filter(|a| session.user.can_read(&a.project))
            .collect();
        (accessible_runs, accessible_pending)
    };

    let conv = state
        .chat
        .load_conversation(owner, &librarian_chat_agent_name(specific_project.as_ref()))?;
    let messages: Vec<Value> = if conv.messages.is_empty() {
        librarian_history_messages_from_runs(&runs)
    } else {
        conv.messages
            .iter()
            .map(|m| {
                json!({
                    "id": m.id,
                    "role": match m.role { ChatRole::User => "user", ChatRole::Assistant => "assistant", ChatRole::Tool => "tool", ChatRole::Error => "error" },
                    "content": m.content,
                    "timestamp": m.timestamp.unix_timestamp(),
                })
            })
            .collect()
    };

    let pending_json: Vec<Value> = pending
        .iter()
        .map(|action| {
            json!({
                "id": action.id,
                "summary": action.summary,
                "operation_count": action.operations.len(),
            })
        })
        .collect();

    Ok(json!({ "messages": messages, "pending_actions": pending_json }))
}

#[derive(Debug, Deserialize)]
struct LibrarianChatAskForm {
    csrf_token: String,
    project: String,
    question: String,
    include_history: Option<String>,
    allow_edits: Option<String>,
}

async fn librarian_chat_ask(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LibrarianChatAskForm>,
) -> Response {
    match librarian_chat_ask_inner(&state, &headers, form).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

async fn librarian_chat_ask_inner(
    state: &AppState,
    headers: &HeaderMap,
    form: LibrarianChatAskForm,
) -> Result<Value, LoreError> {
    let session = require_ui_session(state, headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let owner = session.user.username.as_str();

    let options = librarian_options_from_parts(None, None, None, None, None)?;

    let allow_edits = form.allow_edits.as_deref() == Some("1");

    if form.project.is_empty() {
        let chat_agent = librarian_chat_agent_name(None);
        let _ =
            state
                .chat
                .append_message(owner, &chat_agent, ChatRole::User, form.question.clone());
        let projects: Vec<ProjectName> = state
            .store
            .list_projects()?
            .into_iter()
            .filter(|p| session.user.can_read(p))
            .collect();
        if projects.is_empty() {
            let answer = "No accessible projects.".to_string();
            let _ =
                state
                    .chat
                    .append_message(owner, &chat_agent, ChatRole::Assistant, answer.clone());
            return Ok(json!({ "ok": true, "answer": "No accessible projects." }));
        }
        if allow_edits {
            let mut combined_answers = Vec::new();
            let mut errors = Vec::new();
            let mut any_pending = false;
            for project in &projects {
                if session.user.can_write(project) {
                    match execute_project_librarian_action(
                        state,
                        project,
                        form.question.clone(),
                        options.clone(),
                        &session.user,
                    )
                    .await
                    {
                        Ok(action_result) => {
                            if !action_result.summary.is_empty() {
                                combined_answers
                                    .push(format!("[{}] {}", project, action_result.summary));
                            }
                            if action_result.requires_approval {
                                any_pending = true;
                            }
                        }
                        Err(e) => errors.push(format!("[{}] {}", project, e)),
                    }
                }
            }
            if combined_answers.is_empty() && !errors.is_empty() {
                let error_text = errors.join("\n");
                let _ = state.chat.append_message(
                    owner,
                    &chat_agent,
                    ChatRole::Error,
                    error_text.clone(),
                );
                return Ok(json!({ "ok": false, "error": error_text }));
            }
            let answer = if combined_answers.is_empty() {
                "No results found across projects.".to_string()
            } else {
                combined_answers.join("\n\n")
            };
            let _ =
                state
                    .chat
                    .append_message(owner, &chat_agent, ChatRole::Assistant, answer.clone());
            return Ok(json!({ "ok": true, "answer": answer, "pending": any_pending }));
        }

        let (endpoint, config) = resolve_librarian_endpoint(state)?;
        let _guard = acquire_librarian_slot(state, &config)?;
        let created_at = OffsetDateTime::now_utc();
        let actor = librarian_actor_for_user(&session.user);
        let blocks_per_project = (options.max_sources / projects.len()).max(2);
        let mut projects_context: Vec<(ProjectName, Vec<Block>)> = Vec::new();
        for project in &projects {
            let mut opts = options.clone();
            opts.max_sources = blocks_per_project;
            if let Ok(blocks) =
                build_librarian_context(&state.store, project, &form.question, &opts)
            {
                if !blocks.is_empty() {
                    projects_context.push((project.clone(), blocks));
                }
            }
        }
        if projects_context.is_empty() {
            let answer = "No relevant content found across projects.".to_string();
            let _ =
                state
                    .chat
                    .append_message(owner, &chat_agent, ChatRole::Assistant, answer.clone());
            return Ok(
                json!({ "ok": true, "answer": "No relevant content found across projects." }),
            );
        }
        let system = "You are Lore Answer Librarian. You are read-only. You have access to multiple Lore projects and only the project context provided in this request. Answer from that context, referencing project names where relevant. If the context is insufficient, say so plainly. Do not claim to run commands, browse the web, inspect anything outside the provided Lore blocks, or take actions. If a 'Recent agent/server errors' section is provided, you may reference it when the user asks about errors, agent failures, or reliability.";
        let errors_records = collect_errors_for_librarian(state, &session.user, 40);
        let errors_block = format_errors_block_for_prompt(&errors_records, 4000);
        let errors_opt = if errors_block.is_empty() {
            None
        } else {
            Some(errors_block.as_str())
        };
        let user_msg = build_prompt_multi_project(&projects_context, &form.question, errors_opt);
        if user_msg.chars().count() > MAX_PROMPT_CHARS {
            return Ok(
                json!({ "ok": false, "error": "Combined context exceeds maximum prompt size." }),
            );
        }
        let all_source_blocks: Vec<Block> = projects_context
            .iter()
            .flat_map(|(_, blocks)| blocks.clone())
            .collect();
        let result = state
            .librarian_client
            .answer_raw(&endpoint, config.request_timeout_secs, system, &user_msg)
            .await;
        if let Err(ref e) = result {
            let req_preview = format!("SYSTEM:\n{system}\n\nUSER:\n{user_msg}");
            record_server_error(
                state,
                "llm_api",
                format!("librarian multi-project answer failed: {e}"),
                None,
                Some(endpoint.id.clone()),
                Some(req_preview),
                None,
            );
        }
        let first_project = projects_context[0].0.clone();
        let audit = librarian_audit_entry(
            &first_project,
            actor,
            created_at,
            &endpoint.url,
            &endpoint.model,
            &form.question,
            &all_source_blocks,
            &result
                .as_ref()
                .map(|a| LibrarianAnswerBody {
                    project: first_project.clone(),
                    created_at,
                    actor: librarian_actor_for_user(&session.user),
                    question: form.question.clone(),
                    answer: Some(a.answer.clone()),
                    status: LibrarianRunStatus::Success,
                    error: None,
                    context_blocks: all_source_blocks.clone(),
                })
                .map_err(|e| LoreError::Validation(e.to_string())),
        );
        state.librarian_history.append(audit)?;
        return match result {
            Ok(answer) => {
                let _ = state.chat.append_message(
                    owner,
                    &chat_agent,
                    ChatRole::Assistant,
                    answer.answer.clone(),
                );
                Ok(json!({ "ok": true, "answer": answer.answer }))
            }
            Err(e) => {
                let err = e.to_string();
                let _ = state
                    .chat
                    .append_message(owner, &chat_agent, ChatRole::Error, err.clone());
                Ok(json!({ "ok": false, "error": err }))
            }
        };
    }

    let project = ProjectName::new(form.project)?;
    state.auth.authorize_read(&session.user, &project)?;
    let chat_agent = librarian_chat_agent_name(Some(&project));
    let _ = state
        .chat
        .append_message(owner, &chat_agent, ChatRole::User, form.question.clone());

    let result = if allow_edits && session.user.can_write(&project) {
        let action_result = execute_project_librarian_action(
            state,
            &project,
            form.question.clone(),
            options,
            &session.user,
        )
        .await?;
        json!({
            "ok": true,
            "answer": action_result.summary,
            "pending": action_result.requires_approval,
        })
    } else {
        let answer = answer_librarian_for_project(
            state,
            &project,
            form.question.clone(),
            options,
            librarian_actor_for_user(&session.user),
            Some(&session.user),
        )
        .await?;
        json!({
            "ok": true,
            "answer": answer.answer,
            "error": answer.error,
            "status": format!("{:?}", answer.status),
        })
    };

    if result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let answer_text = result
            .get("answer")
            .and_then(|v| v.as_str())
            .unwrap_or("No response.")
            .to_string();
        let _ = state
            .chat
            .append_message(owner, &chat_agent, ChatRole::Assistant, answer_text);
    } else {
        let error_text = result
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("request failed")
            .to_string();
        let _ = state
            .chat
            .append_message(owner, &chat_agent, ChatRole::Error, error_text);
    }

    Ok(result)
}

async fn librarian_chat_get_config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match librarian_chat_get_config_inner(&state, &headers) {
        Ok(value) => Json(value).into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}

fn librarian_chat_get_config_inner(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Value, LoreError> {
    let session = require_ui_session(state, headers)?;
    let config = state.librarian_config.load()?;
    let endpoints = state.endpoint_store.list()?;
    let status = state.librarian_provider_status.load().ok().flatten();

    let endpoint_options: Vec<Value> = endpoints
        .iter()
        .map(|ep| json!({ "id": ep.id, "name": ep.name, "model": ep.model }))
        .collect();

    Ok(json!({
        "endpoint_id": config.endpoint_id,
        "request_timeout_secs": config.request_timeout_secs,
        "max_concurrent_runs": config.max_concurrent_runs,
        "action_requires_approval": config.action_requires_approval,
        "is_configured": config.is_configured(),
        "endpoints": endpoint_options,
        "status": status.map(|s| s.detail),
        "is_admin": session.user.is_admin,
    }))
}

#[derive(Debug, Deserialize)]
struct LibrarianChatConfigForm {
    csrf_token: String,
    endpoint_id: Option<String>,
    request_timeout_secs: Option<u64>,
    max_concurrent_runs: Option<usize>,
    action_requires_approval: Option<String>,
}

async fn librarian_chat_save_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LibrarianChatConfigForm>,
) -> Response {
    match librarian_chat_save_config_inner(&state, &headers, form) {
        Ok(value) => Json(value).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

fn librarian_chat_save_config_inner(
    state: &AppState,
    headers: &HeaderMap,
    form: LibrarianChatConfigForm,
) -> Result<Value, LoreError> {
    let session = require_ui_session(state, headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    if !session.user.is_admin {
        return Err(LoreError::PermissionDenied);
    }
    let existing = state.librarian_config.load()?;
    state.librarian_config.update(
        form.endpoint_id.clone().filter(|s| !s.is_empty()),
        form.request_timeout_secs
            .unwrap_or(existing.request_timeout_secs),
        form.max_concurrent_runs
            .unwrap_or(existing.max_concurrent_runs),
        form.action_requires_approval.as_deref() == Some("true")
            || form.action_requires_approval.as_deref() == Some("1"),
    )?;
    Ok(json!({ "ok": true }))
}

#[derive(Debug, Deserialize)]
struct LibrarianActionForm {
    csrf_token: String,
}

async fn librarian_chat_approve_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<LibrarianActionForm>,
) -> Response {
    match librarian_chat_approve_inner(&state, &headers, &id, &form).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

async fn librarian_chat_approve_inner(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    form: &LibrarianActionForm,
) -> Result<Value, LoreError> {
    let session = require_ui_session(state, headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let all_pending = state.pending_librarian_actions.list_all(200)?;
    let pending = all_pending
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| LoreError::Validation("pending action does not exist".into()))?;
    let project = pending.project.clone();
    state.auth.authorize_write(&session.user, &project)?;
    approve_pending_project_librarian_action(state, &project, id, &session.user).await?;
    Ok(json!({ "ok": true }))
}

async fn librarian_chat_reject_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<LibrarianActionForm>,
) -> Response {
    match librarian_chat_reject_inner(&state, &headers, &id, &form) {
        Ok(value) => Json(value).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

fn librarian_chat_reject_inner(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    form: &LibrarianActionForm,
) -> Result<Value, LoreError> {
    let session = require_ui_session(state, headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let all_pending = state.pending_librarian_actions.list_all(200)?;
    let pending = all_pending
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| LoreError::Validation("pending action does not exist".into()))?;
    let project = pending.project.clone();
    state.auth.authorize_write(&session.user, &project)?;
    reject_pending_project_librarian_action(state, &project, id, &session.user)?;
    Ok(json!({ "ok": true }))
}

#[derive(Debug, Deserialize)]
struct LibrarianClearForm {
    csrf_token: String,
    #[serde(default)]
    project: Option<String>,
}

async fn librarian_chat_clear(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LibrarianClearForm>,
) -> Response {
    match librarian_chat_clear_inner(&state, &headers, &form) {
        Ok(value) => Json(value).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

fn librarian_chat_clear_inner(
    state: &AppState,
    headers: &HeaderMap,
    form: &LibrarianClearForm,
) -> Result<Value, LoreError> {
    let session = require_ui_session(state, headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let owner = session.user.username.as_str();
    if let Some(ref project_str) = form.project {
        if !project_str.is_empty() {
            let project = ProjectName::new(project_str)?;
            state.librarian_history.clear_project(&project)?;
            state
                .chat
                .clear_messages(owner, &librarian_chat_agent_name(Some(&project)))?;
        } else {
            state.librarian_history.clear_all()?;
            state.chat.clear_librarian_messages(owner)?;
        }
    } else {
        state.librarian_history.clear_all()?;
        state.chat.clear_librarian_messages(owner)?;
    }
    Ok(json!({ "ok": true }))
}

#[derive(Debug, Deserialize)]
struct ChatSendForm {
    csrf_token: String,
    message: String,
    client_message_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatExcludeMessageForm {
    csrf_token: String,
    message_id: u64,
    excluded: bool,
}

async fn chat_send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_name): Path<String>,
    Form(form): Form<ChatSendForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let owner = session.user.username.as_str();

    // Verify the user owns this agent
    let agents = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?;
    if !agents.iter().any(|a| a.name == agent_name) {
        return Err(LoreError::PermissionDenied.into());
    }

    let client_message_id = form
        .client_message_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let valid = value.len() <= 128
                && value
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'));
            if valid {
                Ok(value.to_string())
            } else {
                Err(LoreError::Validation("invalid client message id".into()))
            }
        })
        .transpose()?;

    let (msg, inserted) = state.chat.append_user_message_idempotent(
        owner,
        &agent_name,
        form.message.clone(),
        client_message_id.as_deref(),
    )?;
    if inserted {
        state
            .chat_audit
            .log(&agent_name, owner, "user", &form.message);

        // Push SSE event to the user
        push_chat_event(
            &state,
            owner,
            ChatEvent {
                event_type: "message".into(),
                agent: agent_name.clone(),
                owner: owner.to_string(),
                data: json!({ "id": msg.id, "role": "user", "content": msg.content }),
            },
        );

        // Notify the machine if it's polling
        let notifier_key = format!("{owner}_{agent_name}");
        if let Ok(notifiers) = state.chat_agent_notifiers.lock() {
            if let Some(notify) = notifiers.get(&notifier_key) {
                notify.notify_one();
            }
        }
    }

    Ok(Json(json!({
        "ok": true,
        "inserted": inserted,
        "message": {
            "id": msg.id,
            "role": "user",
            "content": msg.content,
        }
    }))
    .into_response())
}

async fn chat_update_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_name): Path<String>,
    Form(form): Form<ChatExcludeMessageForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let owner = session.user.username.as_str();

    let agents = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?;
    if !agents.iter().any(|a| a.name == agent_name) {
        return Err(LoreError::PermissionDenied.into());
    }

    let updated = state.chat.set_message_context_excluded(
        owner,
        &agent_name,
        form.message_id,
        form.excluded,
    )?;
    let conv = state.chat.load_conversation(owner, &agent_name)?;
    let last_message = conv
        .messages
        .iter()
        .rev()
        .find(|msg| !msg.excluded_from_context)
        .map(|msg| msg.content.chars().take(60).collect::<String>())
        .unwrap_or_default();
    let last_message_time = conv
        .messages
        .iter()
        .rev()
        .find(|msg| msg.role == ChatRole::User && !msg.excluded_from_context)
        .map(|msg| format_chat_time(msg.timestamp))
        .unwrap_or_default();

    Ok(Json(json!({
        "ok": true,
        "message": chat_message_json(&updated),
        "active_turn_user_id": conv.active_turn_user_id,
        "last_message": last_message,
        "last_message_time": last_message_time,
    }))
    .into_response())
}

async fn chat_sse_stream(State(state): State<AppState>, headers: HeaderMap) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    let owner = session.user.username.as_str().to_string();

    let rx = {
        let mut senders = state.chat_senders.lock().unwrap();
        let sender = senders.entry(owner.clone()).or_insert_with(|| {
            let (tx, _) = tokio::sync::broadcast::channel(64);
            tx
        });
        sender.subscribe()
    };

    let stream = async_stream::stream! {
        let mut rx = rx;
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        yield Ok::<_, std::convert::Infallible>(
                            format!("data: {json}\n\n")
                        );
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    let body = Body::from_stream(stream);
    Ok(Response::builder()
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(body)
        .unwrap())
}

// --- Agent-facing chat endpoints ---

#[derive(Debug, Deserialize)]
struct ChatRespondBody {
    text: Option<String>,
    message: Option<String>,
    tool_use: Option<String>,
    #[serde(alias = "done")]
    complete: Option<bool>,
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatStatusBody {
    status: String,
}

async fn chat_agent_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    // Track CLI version and machine name for update signaling
    let cli_version = headers
        .get("x-lore-version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let machine_name = headers
        .get("x-lore-machine")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| agent.machine_name.clone());
    if let (Some(mname), Some(ver)) = (&machine_name, &cli_version) {
        let _ = state.auth.update_machine_version(mname, owner, ver);
    }

    // Update cwd and git branch if provided
    let cwd_val = headers
        .get("x-lore-cwd")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let branch_val = headers
        .get("x-lore-git-branch")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Some(ref cwd) = cwd_val {
        let _ = state
            .chat
            .update_cwd(owner_str, &agent.name, cwd, branch_val.as_deref());
    }

    // Push current persisted status to the UI (include cwd/branch so UI updates live).
    // Polling is only a heartbeat and must not synthesize a completed state on its own.
    let loaded_conv = state.chat.load_conversation(owner_str, &agent.name).ok();
    let current_status = loaded_conv
        .as_ref()
        .map(|conv| match conv.agent_status {
            AgentChatStatus::Idle => "idle",
            AgentChatStatus::Thinking => "thinking",
            AgentChatStatus::Offline => "offline",
        })
        .unwrap_or("offline");
    let mut status_data = json!({
        "status": current_status,
        "active_turn_user_id": loaded_conv
            .as_ref()
            .map(|conv| conv.active_turn_user_id)
            .unwrap_or(0),
    });
    if let Some(ref cwd) = cwd_val {
        status_data["cwd"] = json!(cwd);
    }
    if let Some(ref branch) = branch_val {
        status_data["git_branch"] = json!(branch);
    }
    push_chat_event(
        &state,
        owner_str,
        ChatEvent {
            event_type: "status".into(),
            agent: agent.name.clone(),
            owner: owner_str.to_string(),
            data: status_data,
        },
    );

    // Check if machine has a pending update (transient, auto-expires after 3 min)
    let server_version = env!("CARGO_PKG_VERSION");
    let update_to = if let Some(mname) = machine_name.as_ref() {
        let machine_key = format!("{}_{}", owner, mname);
        let poll_key = format!("chat:{machine_key}:{}", agent.name);
        if should_emit_machine_update_signal(
            &state,
            &poll_key,
            machine_update_requested(&state, &machine_key, cli_version.as_deref())?,
        ) {
            Some(server_version.to_string())
        } else {
            None
        }
    } else {
        None
    };
    let update_config = if update_to.is_some() {
        state.auto_update_config.load().ok()
    } else {
        None
    };

    let poll_backend = agent.backend.to_string();
    let poll_endpoint_id = agent.endpoint_id.clone();
    let current_manage_requested = || -> Result<bool, ApiError> {
        Ok(state
            .chat
            .get_manage_config(owner_str, &agent.name)?
            .map(|mc| mc.enabled && mc.run_requested)
            .unwrap_or(false))
    };

    let build_poll_response = |msgs: Vec<Value>, manage_requested: bool| -> Json<Value> {
        let mut resp = json!({
            "messages": msgs,
            "backend": poll_backend,
            "manage_requested": manage_requested
        });
        if let Some(ref eid) = poll_endpoint_id {
            resp["endpoint_id"] = json!(eid);
        }
        if let Some(ref ver) = update_to {
            resp["update_to"] = json!(ver);
            if let Some(ref config) = update_config {
                resp["update_repo"] = json!(config.github_repo);
                resp["update_stream"] = json!(config.release_stream.as_str());
            }
        }
        Json(resp)
    };

    if take_chat_agent_stop_request(&state, owner_str, &agent.name) {
        return Ok(build_poll_response_with_stop(build_poll_response(
            vec![],
            current_manage_requested()?,
        )));
    }

    let _ = release_due_delayed_manager_message(&state, owner_str, &agent.name)?;

    // Claim unprocessed user messages. This uses a delivery cursor instead of
    // inferring pending state from the last assistant message, which breaks if
    // the user sends follow-up input while the agent is still thinking.
    let pending = state
        .chat
        .claim_pending_user_messages(owner_str, &agent.name)?;

    if !pending.is_empty() {
        let msgs: Vec<Value> = pending
            .iter()
            .map(|m| json!({ "id": m.id, "content": m.content, "timestamp": m.timestamp.format(&time::format_description::well_known::Rfc3339).unwrap_or_default() }))
            .collect();
        return Ok(build_poll_response(msgs, current_manage_requested()?));
    }

    // No messages — long-poll up to 30 seconds
    let notifier_key = format!("{owner_str}_{}", agent.name);
    let notify = {
        let mut notifiers = state.chat_agent_notifiers.lock().unwrap();
        notifiers
            .entry(notifier_key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Notify::new()))
            .clone()
    };

    let result = tokio::time::timeout(std::time::Duration::from_secs(30), notify.notified()).await;

    // Re-check for messages after waking
    if result.is_ok() {
        if take_chat_agent_stop_request(&state, owner_str, &agent.name) {
            return Ok(build_poll_response_with_stop(build_poll_response(
                vec![],
                current_manage_requested()?,
            )));
        }
        let _ = release_due_delayed_manager_message(&state, owner_str, &agent.name)?;
        let pending = state
            .chat
            .claim_pending_user_messages(owner_str, &agent.name)?;
        if !pending.is_empty() {
            let msgs: Vec<Value> = pending
                .iter()
                .map(|m| json!({ "id": m.id, "content": m.content, "timestamp": m.timestamp.format(&time::format_description::well_known::Rfc3339).unwrap_or_default() }))
                .collect();
            return Ok(build_poll_response(msgs, current_manage_requested()?));
        }
    }

    Ok(build_poll_response(vec![], current_manage_requested()?))
}

fn build_poll_response_with_stop(mut response: Json<Value>) -> Json<Value> {
    if let Some(obj) = response.0.as_object_mut() {
        obj.insert("stop_requested".to_string(), json!(true));
    }
    response
}

async fn chat_agent_take_stop_request(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    Ok(Json(json!({
        "stop_requested": take_chat_agent_stop_request(&state, owner.as_str(), &agent.name)
    })))
}

async fn chat_agent_respond(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChatRespondBody>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    if let Some(detail) = &body.tool_use {
        let _ = state
            .chat
            .append_or_extend_tool(owner_str, &agent.name, detail);
        state.chat_audit.log(&agent.name, owner_str, "tool", detail);
        push_chat_event(
            &state,
            owner_str,
            ChatEvent {
                event_type: "tool_use".into(),
                agent: agent.name.clone(),
                owner: owner_str.to_string(),
                data: json!({ "detail": detail }),
            },
        );
        record_tool_activity(&state, owner_str, &agent.name, detail);
    }

    if let Some(text) = &body.text {
        push_chat_event(
            &state,
            owner_str,
            ChatEvent {
                event_type: "chunk".into(),
                agent: agent.name.clone(),
                owner: owner_str.to_string(),
                data: json!({ "text": text }),
            },
        );
    }

    if let Some(content) = &body.message {
        let msg = state.chat.append_message(
            owner_str,
            &agent.name,
            ChatRole::Assistant,
            content.clone(),
        )?;
        state
            .chat_audit
            .log(&agent.name, owner_str, "agent", content);
        push_chat_event(
            &state,
            owner_str,
            ChatEvent {
                event_type: "message".into(),
                agent: agent.name.clone(),
                owner: owner_str.to_string(),
                data: json!({ "id": msg.id, "role": "assistant", "content": content }),
            },
        );
    }

    if body.complete.unwrap_or(false) {
        // Full response — store the message
        let content = body
            .content
            .clone()
            .or(body.text.clone())
            .unwrap_or_default();
        if !content.is_empty() {
            let msg = state.chat.append_message(
                owner_str,
                &agent.name,
                ChatRole::Assistant,
                content.clone(),
            )?;
            state
                .chat_audit
                .log(&agent.name, owner_str, "agent", &content);

            push_chat_event(
                &state,
                owner_str,
                ChatEvent {
                    event_type: "response_complete".into(),
                    agent: agent.name.clone(),
                    owner: owner_str.to_string(),
                    data: json!({ "id": msg.id, "content": content }),
                },
            );
        } else {
            push_chat_event(
                &state,
                owner_str,
                ChatEvent {
                    event_type: "response_complete".into(),
                    agent: agent.name.clone(),
                    owner: owner_str.to_string(),
                    data: json!({}),
                },
            );
        }

        finalize_agent_turn(&state, owner_str, &agent.name);

        // Auto-repeat: if set AND manage mode is not active, queue the auto_message
        let state2 = state.clone();
        let owner2 = owner_str.to_string();
        let agent_name2 = agent.name.clone();
        tokio::spawn(async move {
            let manage_active = state2
                .chat
                .get_manage_config(&owner2, &agent_name2)
                .ok()
                .flatten()
                .map(|mc| mc.enabled)
                .unwrap_or(false);
            if manage_active {
                return;
            }
            if let Ok(conv) = state2.chat.load_conversation(&owner2, &agent_name2) {
                if let Some(auto_msg) = &conv.auto_message {
                    if let Ok(auto_stored) = state2.chat.append_message(
                        &owner2,
                        &agent_name2,
                        ChatRole::User,
                        auto_msg.clone(),
                    ) {
                        state2
                            .chat_audit
                            .log(&agent_name2, &owner2, "auto", auto_msg);
                        push_chat_event(
                            &state2,
                            &owner2,
                            ChatEvent {
                                event_type: "auto_message".into(),
                                agent: agent_name2.clone(),
                                owner: owner2.clone(),
                                data: json!({ "id": auto_stored.id, "content": auto_stored.content }),
                            },
                        );
                        let notifier_key = format!("{}_{}", owner2, agent_name2);
                        if let Some(notify) = state2
                            .chat_agent_notifiers
                            .lock()
                            .unwrap()
                            .get(&notifier_key)
                        {
                            notify.notify_one();
                        }
                    }
                }
            }
        });
    }

    Ok(StatusCode::OK)
}

async fn chat_agent_update_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChatStatusBody>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    let status = match body.status.as_str() {
        "idle" => AgentChatStatus::Idle,
        "thinking" => AgentChatStatus::Thinking,
        _ => AgentChatStatus::Offline,
    };
    state
        .chat
        .update_agent_status(owner_str, &agent.name, status)?;
    let active_turn_user_id = state
        .chat
        .load_conversation(owner_str, &agent.name)
        .map(|conv| conv.active_turn_user_id)
        .unwrap_or(0);

    push_chat_event(
        &state,
        owner_str,
        ChatEvent {
            event_type: "status".into(),
            agent: agent.name.clone(),
            owner: owner_str.to_string(),
            data: json!({
                "status": body.status,
                "active_turn_user_id": active_turn_user_id,
            }),
        },
    );

    if matches!(status, AgentChatStatus::Thinking) {
        let backend_str = agent.backend.to_string();
        let (model, effort) = state
            .chat
            .get_backend_prefs(owner_str, &backend_str)
            .unwrap_or((None, None));
        push_chat_event(
            &state,
            owner_str,
            ChatEvent {
                event_type: "config_info".into(),
                agent: agent.name.clone(),
                owner: owner_str.to_string(),
                data: json!({
                    "backend": backend_str,
                    "model": model,
                    "effort": effort,
                }),
            },
        );
    }

    Ok(StatusCode::OK)
}

// --- Agent error reporting ---
//
// Machine-side errors (LLM API failures, CLI spawn/timeout, tool errors, parse errors)
// are reported here fire-and-forget. Persisted under:
//   <store_root>/errors/<owner>/<agent>/YYYY-MM-DD.jsonl
// Retention: 3 days (swept hourly).
// Caps: 8KB per entry, 10MB per daily file.

const SERVER_ERROR_ENTRY_MAX_BYTES: usize = 8 * 1024;
const SERVER_ERROR_FILE_MAX_BYTES: u64 = 10 * 1024 * 1024;
const SERVER_ERROR_RETENTION_DAYS: i64 = 3;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct AgentErrorReport {
    ts: String,
    category: String,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview_request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview_response: Option<String>,
}

fn errors_dir_for(state: &AppState) -> std::path::PathBuf {
    state.store.root().join("errors")
}

fn agent_error_reporting_config_path(state: &AppState) -> std::path::PathBuf {
    state
        .store
        .root()
        .join("config")
        .join("agent-error-reporting.json")
}

/// Whether agent-reported errors are accepted and persisted server-side.
/// Defaults to true (enabled) if the config file is absent or unreadable.
fn agent_error_reporting_enabled(state: &AppState) -> bool {
    let path = agent_error_reporting_config_path(state);
    let Ok(bytes) = std::fs::read(&path) else {
        return true;
    };
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(v) => v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(true),
        Err(_) => true,
    }
}

fn set_agent_error_reporting_enabled(state: &AppState, enabled: bool) -> Result<(), LoreError> {
    let path = agent_error_reporting_config_path(state);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(LoreError::Io)?;
    }
    let body = serde_json::json!({ "enabled": enabled });
    std::fs::write(&path, serde_json::to_vec_pretty(&body).unwrap_or_default())
        .map_err(LoreError::Io)?;
    Ok(())
}

fn truncate_error_preview(s: &str) -> String {
    truncate_head_tail_chars(s, 2730, 1366)
}

fn truncate_head_tail_chars(s: &str, head: usize, tail: usize) -> String {
    let total: usize = s.chars().count();
    if total <= head + tail {
        return s.to_string();
    }
    let head_part: String = s.chars().take(head).collect();
    let tail_part: String = s.chars().skip(total - tail).collect();
    let omitted = total - head - tail;
    format!("{head_part}\n\u{2026}[truncated {omitted} chars]\u{2026}\n{tail_part}")
}

fn today_utc_date_str() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        now.month() as u8,
        now.day()
    )
}

fn write_error_report_to_disk(
    root: &std::path::Path,
    owner: &str,
    agent: Option<&str>,
    report: &AgentErrorReport,
) {
    let mut dir = root.to_path_buf();
    dir.push(owner);
    if let Some(a) = agent {
        dir.push(a);
    }
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join(format!("{}.jsonl", today_utc_date_str()));
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() >= SERVER_ERROR_FILE_MAX_BYTES {
            return;
        }
    }
    let mut line = match serde_json::to_string(report) {
        Ok(s) => s,
        Err(_) => return,
    };
    if line.len() > SERVER_ERROR_ENTRY_MAX_BYTES {
        let mut trimmed = report.clone();
        trimmed.preview_response = trimmed
            .preview_response
            .map(|s| truncate_head_tail_chars(&s, 350, 150));
        trimmed.preview_request = trimmed
            .preview_request
            .map(|s| truncate_head_tail_chars(&s, 350, 150));
        line = serde_json::to_string(&trimmed).unwrap_or(line);
        if line.len() > SERVER_ERROR_ENTRY_MAX_BYTES {
            trimmed.preview_response = None;
            trimmed.preview_request = None;
            line = serde_json::to_string(&trimmed).unwrap_or(line);
        }
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{line}");
    }
}

pub fn sweep_agent_error_files(state: &AppState) {
    let root = errors_dir_for(state);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    let today = OffsetDateTime::now_utc().date();
    // Walk three levels: <owner>/<agent>/<date>.jsonl and <_server>/<date>.jsonl
    for owner_entry in entries.flatten() {
        let owner_path = owner_entry.path();
        if !owner_path.is_dir() {
            continue;
        }
        let Ok(subs) = std::fs::read_dir(&owner_path) else {
            continue;
        };
        for sub in subs.flatten() {
            let p = sub.path();
            if p.is_dir() {
                if let Ok(files) = std::fs::read_dir(&p) {
                    for f in files.flatten() {
                        remove_if_expired(&f.path(), today);
                    }
                }
            } else {
                remove_if_expired(&p, today);
            }
        }
    }
}

fn remove_if_expired(path: &std::path::Path, today: time::Date) {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let Some(date_part) = name.strip_suffix(".jsonl") else {
        return;
    };
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() != 3 {
        return;
    }
    let (Ok(y), Ok(m), Ok(d)) = (
        parts[0].parse::<i32>(),
        parts[1].parse::<u8>(),
        parts[2].parse::<u8>(),
    ) else {
        return;
    };
    let Some(month) = time::Month::try_from(m).ok() else {
        return;
    };
    let Ok(file_date) = time::Date::from_calendar_date(y, month, d) else {
        return;
    };
    if (today - file_date).whole_days() > SERVER_ERROR_RETENTION_DAYS {
        let _ = std::fs::remove_file(path);
    }
}

async fn chat_agent_errors_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<AgentErrorReport>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    // Admin can turn off server-side persistence of agent errors. When disabled
    // the agent still keeps a local copy in .lore/<agent>/error-YYYY-MM-DD.jsonl;
    // we just don't store or surface it here.
    if !agent_error_reporting_enabled(&state) {
        return Ok(StatusCode::NO_CONTENT);
    }

    // Backfill ts if missing.
    if body.ts.is_empty() {
        let now = OffsetDateTime::now_utc();
        body.ts = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
    }

    let root = errors_dir_for(&state);
    write_error_report_to_disk(&root, owner_str, Some(&agent.name), &body);

    // Persist a compact human-readable line as a chat message (role=error)
    // and notify live clients. Single line, truncated, prefixed by category.
    let display = format_error_chat_line(&body);
    state
        .chat_audit
        .log(&agent.name, owner_str, "error", &display);
    if let Ok(msg) = state
        .chat
        .append_or_extend_error(owner_str, &agent.name, &display)
    {
        push_chat_event(
            &state,
            owner_str,
            ChatEvent {
                event_type: "message".into(),
                agent: agent.name.clone(),
                owner: owner_str.to_string(),
                data: json!({ "id": msg.id, "role": "error", "content": msg.content }),
            },
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

fn record_server_error(
    state: &AppState,
    category: &str,
    detail: impl Into<String>,
    status_code: Option<u16>,
    endpoint_id: Option<String>,
    preview_request: Option<String>,
    preview_response: Option<String>,
) {
    let now = OffsetDateTime::now_utc();
    let ts = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let report = AgentErrorReport {
        ts,
        category: category.to_string(),
        detail: detail.into(),
        endpoint_id,
        status_code,
        duration_ms: None,
        preview_request: preview_request.map(|s| truncate_error_preview(&s)),
        preview_response: preview_response.map(|s| truncate_error_preview(&s)),
    };
    let root = errors_dir_for(state);
    write_error_report_to_disk(&root, "_server", None, &report);
    eprintln!(
        "[server-error] {} {}: {}",
        report.category,
        report
            .status_code
            .map(|c| c.to_string())
            .unwrap_or_default(),
        report.detail
    );
}

fn format_error_chat_line(r: &AgentErrorReport) -> String {
    let category_label = match r.category.as_str() {
        "llm_api" => "LLM API",
        "cli" => "CLI",
        "tool" => "Tool",
        "parse" => "Parse",
        "manager" => "Manager",
        other => other,
    };
    let status = r
        .status_code
        .map(|s| format!(" (HTTP {s})"))
        .unwrap_or_default();
    // Collapse whitespace, cap to ~200 chars.
    let detail = r.detail.split_whitespace().collect::<Vec<_>>().join(" ");
    let detail_short: String = if detail.chars().count() > 200 {
        let mut out: String = detail.chars().take(200).collect();
        out.push('\u{2026}');
        out
    } else {
        detail
    };
    format!("{category_label}{status}: {detail_short}")
}

async fn chat_errors_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = require_ui_session(&state, &headers)?;
    let owner_name = &session.user.username;
    let agents = state.auth.list_agent_tokens_for_user(owner_name)?;
    if !agents.iter().any(|a| a.name == agent_name) {
        return Err(ApiError::from(LoreError::PermissionDenied));
    }

    let root = errors_dir_for(&state);
    let records = read_recent_error_records(&root, owner_name.as_str(), Some(&agent_name), 200);
    Ok(Json(json!({ "records": records })))
}

fn read_recent_error_records(
    root: &std::path::Path,
    owner: &str,
    agent: Option<&str>,
    limit: usize,
) -> Vec<Value> {
    let mut dir = root.to_path_buf();
    dir.push(owner);
    if let Some(a) = agent {
        dir.push(a);
    }
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("jsonl"))
        .collect();
    files.sort();
    files.reverse();
    let mut out: Vec<Value> = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut lines: Vec<&str> = text.lines().collect();
        lines.reverse();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                out.push(v);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

fn collect_errors_for_librarian(
    state: &AppState,
    user: &crate::auth::AuthenticatedUser,
    limit: usize,
) -> Vec<Value> {
    let root = errors_dir_for(state);
    if user.is_admin {
        return read_all_error_records(&root, limit);
    }
    let owner = user.username.as_str();
    let owner_path = root.join(owner);
    let Ok(entries) = std::fs::read_dir(&owner_path) else {
        return Vec::new();
    };
    let mut all: Vec<(String, String, Option<String>, Value)> = Vec::new();
    for sub in entries.flatten() {
        let sub_path = sub.path();
        if sub_path.is_dir() {
            let agent_name = sub_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let Ok(files) = std::fs::read_dir(&sub_path) else {
                continue;
            };
            for f in files.flatten() {
                collect_file_records(&f.path(), owner, Some(&agent_name), &mut all);
            }
        } else {
            collect_file_records(&sub_path, owner, None, &mut all);
        }
    }
    all.sort_by(|a, b| b.0.cmp(&a.0));
    all.into_iter()
        .take(limit)
        .map(|(ts, owner, agent, v)| {
            let mut obj = v.as_object().cloned().unwrap_or_default();
            obj.insert("owner".to_string(), json!(owner));
            if let Some(a) = agent {
                obj.insert("agent".to_string(), json!(a));
            }
            if !obj.contains_key("ts") {
                obj.insert("ts".to_string(), json!(ts));
            }
            Value::Object(obj)
        })
        .collect()
}

fn format_errors_block_for_prompt(records: &[Value], max_chars: usize) -> String {
    if records.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for r in records {
        let ts = r.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let owner = r.get("owner").and_then(|v| v.as_str()).unwrap_or("");
        let agent = r.get("agent").and_then(|v| v.as_str()).unwrap_or("_server");
        let category = r.get("category").and_then(|v| v.as_str()).unwrap_or("");
        let status = r
            .get("status_code")
            .and_then(|v| v.as_u64())
            .map(|s| format!(" HTTP {s}"))
            .unwrap_or_default();
        let detail = r.get("detail").and_then(|v| v.as_str()).unwrap_or("");
        let detail_short: String = detail
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(240)
            .collect();
        let owner_label = if owner.is_empty() {
            String::new()
        } else {
            format!("{owner}/")
        };
        let line = format!("- [{ts}] {owner_label}{agent} [{category}{status}]: {detail_short}\n");
        if out.len() + line.len() > max_chars {
            break;
        }
        out.push_str(&line);
    }
    out
}

fn read_all_error_records(root: &std::path::Path, limit: usize) -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut all: Vec<(String, String, Option<String>, Value)> = Vec::new();
    for owner_entry in entries.flatten() {
        let owner_path = owner_entry.path();
        let owner_name = owner_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if owner_name.is_empty() {
            continue;
        }
        if !owner_path.is_dir() {
            continue;
        }
        let Ok(subs) = std::fs::read_dir(&owner_path) else {
            continue;
        };
        for sub in subs.flatten() {
            let sub_path = sub.path();
            if sub_path.is_dir() {
                let agent_name = sub_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                let Ok(files) = std::fs::read_dir(&sub_path) else {
                    continue;
                };
                for f in files.flatten() {
                    collect_file_records(&f.path(), &owner_name, Some(&agent_name), &mut all);
                }
            } else {
                collect_file_records(&sub_path, &owner_name, None, &mut all);
            }
        }
    }
    all.sort_by(|a, b| b.0.cmp(&a.0));
    all.into_iter()
        .take(limit)
        .map(|(ts, owner, agent, v)| {
            let mut obj = v.as_object().cloned().unwrap_or_default();
            obj.insert("owner".to_string(), json!(owner));
            if let Some(a) = agent {
                obj.insert("agent".to_string(), json!(a));
            }
            if !obj.contains_key("ts") {
                obj.insert("ts".to_string(), json!(ts));
            }
            Value::Object(obj)
        })
        .collect()
}

fn collect_file_records(
    path: &std::path::Path,
    owner: &str,
    agent: Option<&str>,
    out: &mut Vec<(String, String, Option<String>, Value)>,
) {
    if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let ts = v
            .get("ts")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        out.push((ts, owner.to_string(), agent.map(|s| s.to_string()), v));
    }
}

async fn admin_errors_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let _session = require_ui_admin(&state, &headers)?;
    let root = errors_dir_for(&state);
    let records = read_all_error_records(&root, 500);
    Ok(Json(json!({ "records": records })))
}

async fn admin_errors_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> UiResult<Html<String>> {
    let session = require_ui_admin(&state, &headers)?;
    let reporting_enabled = agent_error_reporting_enabled(&state);
    Ok(Html(render_admin_errors_page(
        resolved_theme(&session.user, &state.config.load()?),
        resolved_color_mode(&session.user),
        session.user.username.as_str(),
        &session.csrf_token,
        reporting_enabled,
    )))
}

async fn toggle_agent_error_reporting_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> ApiResult<axum::Json<serde_json::Value>> {
    let session = require_ui_admin(&state, &headers)?;
    let csrf = form.get("csrf_token").map(|s| s.as_str()).unwrap_or("");
    verify_csrf(&session, csrf)?;
    let enabled = form.get("enabled").map(|s| s == "true").unwrap_or(true);
    set_agent_error_reporting_enabled(&state, enabled)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        if enabled {
            "enable agent error reporting"
        } else {
            "disable agent error reporting"
        },
        None,
        None,
    )?;
    Ok(axum::Json(
        serde_json::json!({ "ok": true, "enabled": enabled }),
    ))
}

async fn chat_agent_history(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    let conv = state.chat.load_conversation(owner_str, &agent.name)?;
    let msgs: Vec<Value> = agent_context_messages(unsummarized_messages(&conv))
        .iter()
        .map(|m| chat_message_json(m))
        .collect();

    let backend_str = agent.backend.to_string();
    let (model, effort) = state
        .chat
        .get_backend_prefs(owner_str, &backend_str)
        .unwrap_or((None, None));
    let project_context = collect_project_context(&state, &agent.grants);

    let endpoint_info = agent
        .endpoint_id
        .as_deref()
        .and_then(|eid| state.endpoint_store.get(eid).ok().flatten());

    let git_ctx = collect_git_context(conv.cwd.as_deref());
    let activity = get_agent_recent_activity(&state, owner_str, &agent.name);

    let accessible: Vec<String> = agent
        .grants
        .iter()
        .map(|g| {
            let perm = if g.permission.allows_write() {
                "read-write"
            } else {
                "read"
            };
            format!("- {} ({})", g.project.as_str(), perm)
        })
        .collect();

    let mut resp = json!({
        "messages": msgs,
        "summary": conv.summary,
        "window_size": conv.window_size,
        "pins": conv.pins.iter().map(|p| json!({"id": p.id, "text": p.text})).collect::<Vec<_>>(),
        "pinned_context": conv.pinned_context,
        "project_context": project_context,
        "accessible_projects": accessible.join("\n"),
        "model": model,
        "effort": effort,
    });
    if !git_ctx.is_empty() {
        resp["git_context"] = json!(git_ctx);
    }
    if !activity.is_empty() {
        resp["recent_activity"] = json!(activity);
    }
    if let Some(ep) = endpoint_info {
        resp["endpoint"] = json!({
            "id": ep.id,
            "name": ep.name,
            "kind": ep.kind.to_string(),
            "url": ep.url,
            "model": ep.model,
        });
    }
    Ok(Json(resp))
}

// --- Agent compact endpoint ---

#[derive(Debug, Deserialize)]
struct ChatCompactBody {
    summary: String,
    keep_message_ids: Vec<u64>,
}

async fn chat_agent_compact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChatCompactBody>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    let conv = state.chat.load_conversation(owner_str, &agent.name)?;
    let unsummarized = unsummarized_messages(&conv);
    let summary_until_id = if body.keep_message_ids.is_empty() {
        unsummarized
            .last()
            .map(|m| m.id)
            .unwrap_or(conv.summary_until_id)
    } else {
        unsummarized
            .iter()
            .find(|m| body.keep_message_ids.contains(&m.id))
            .map(|m| m.id.saturating_sub(1))
            .unwrap_or_else(|| {
                unsummarized
                    .last()
                    .map(|m| m.id)
                    .unwrap_or(conv.summary_until_id)
            })
    };

    state.chat.set_compaction_state(
        owner_str,
        &agent.name,
        body.summary,
        summary_until_id.max(conv.summary_until_id),
    )?;
    Ok(StatusCode::OK)
}

async fn chat_agent_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let mut resp = serde_json::json!({
        "backend": agent.backend.to_string(),
    });
    if let Some(ref eid) = agent.endpoint_id {
        if let Ok(Some(ep)) = state.endpoint_store.get(eid) {
            resp["endpoint"] = json!({
                "id": ep.id,
                "name": ep.name,
                "kind": ep.kind.to_string(),
                "model": ep.model,
            });
        }
    }
    Ok(Json(resp))
}

async fn chat_agent_lore_tools(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let _agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let tools: Vec<Value> = mcp_tools().into_iter().map(|t| {
        json!({
            "type": "function",
            "function": {
                "name": t.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                "description": t.get("description").and_then(|d| d.as_str()).unwrap_or(""),
                "parameters": t.get("inputSchema").cloned().unwrap_or(json!({"type": "object"})),
            }
        })
    }).collect();
    Ok(Json(json!({ "tools": tools })))
}

async fn chat_agent_lore_tool_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let name = body["name"]
        .as_str()
        .ok_or_else(|| LoreError::Validation("name is required".into()))?;
    let args = body.get("arguments").cloned().unwrap_or(json!({}));
    let params = json!({ "name": name, "arguments": args });
    let result = call_mcp_tool(&state, &agent, Some(&params))?;
    let text = result["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or("");
    Ok(Json(json!({ "result": text })))
}

async fn chat_agent_get_manage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    let mc = state
        .chat
        .get_manage_config(owner_str, &agent.name)?
        .unwrap_or_default();

    if !mc.enabled {
        return Ok(Json(json!({ "enabled": false })));
    }

    let turn_in_cycle = mc.turn_counter % 5;
    let manager_prompt_config = state.manager_prompt_config.load()?;
    let system_prompt = build_manager_prompt(&mc, &manager_prompt_config, turn_in_cycle);

    let conv = state.chat.load_conversation(owner_str, &agent.name)?;
    let window_messages = agent_context_messages(unsummarized_messages(&conv));
    let boundaries = exchange_boundaries(&window_messages);
    let last_10_start = if boundaries.len() > 10 {
        boundaries[boundaries.len() - 10]
    } else {
        0
    };
    let recent_msgs: Vec<Value> = window_messages[last_10_start..]
        .iter()
        .map(|m| {
            json!({
                "role": match m.role { ChatRole::User => "user", ChatRole::Assistant => "assistant", ChatRole::Tool => "tool", ChatRole::Error => "error" },
                "content": m.content,
            })
        })
        .collect();

    let has_endpoint = !mc.endpoint_id.is_empty()
        && state
            .endpoint_store
            .get(&mc.endpoint_id)
            .ok()
            .flatten()
            .is_some();

    Ok(Json(json!({
        "enabled": true,
        "system_prompt": system_prompt,
        "messages": recent_msgs,
        "backend": mc.backend,
        "has_endpoint": has_endpoint,
        "turn_counter": mc.turn_counter,
    })))
}

#[derive(Debug, Deserialize)]
struct ManagerReportBody {
    content: String,
    #[serde(default)]
    stopped: bool,
    #[serde(default)]
    delay_seconds: Option<u64>,
}

async fn chat_agent_manager_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ManagerReportBody>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    state
        .chat_audit
        .log(&agent.name, owner_str, "manager", &body.content);

    let mut delayed_content = body.content.trim().to_string();
    let mut delayed_until_unix = None;
    if !body.stopped {
        if let Some(delay_seconds) = body.delay_seconds.filter(|secs| *secs > 0) {
            delayed_until_unix =
                Some(OffsetDateTime::now_utc().unix_timestamp() + delay_seconds as i64);
        } else {
            let (parsed_delay, stripped_content) = extract_manager_delay_prefix(&body.content);
            if let Some(delay_seconds) = parsed_delay {
                delayed_until_unix =
                    Some(OffsetDateTime::now_utc().unix_timestamp() + delay_seconds as i64);
                delayed_content = stripped_content;
            }
        }
    }

    let mut auto_disabled = false;
    let mut delayed_status = None;
    if let Ok(Some(mut mc)) = state.chat.get_manage_config(owner_str, &agent.name) {
        mc.turn_counter += 1;
        mc.run_requested = false;
        mc.request_announced = false;
        mc.delayed_message.clear();
        mc.delayed_until_unix = 0;
        if body.stopped {
            auto_disabled = mc.enabled;
            mc.enabled = false;
        } else if let Some(until) = delayed_until_unix {
            mc.delayed_message = delayed_content.clone();
            mc.delayed_until_unix = until;
            let delay_seconds = (until - OffsetDateTime::now_utc().unix_timestamp()).max(1) as u64;
            delayed_status = Some(describe_manager_delay(delay_seconds));
        }
        let _ = state.chat.save_manage_config(owner_str, &agent.name, &mc);
    }

    if let Some(status) = delayed_status {
        append_manager_chat_message(
            &state,
            owner_str,
            &agent.name,
            ChatRole::Assistant,
            &manager_chat_message_prefix(&status),
        );
    } else {
        let display = manager_chat_message_prefix(&delayed_content);
        append_manager_chat_message(&state, owner_str, &agent.name, ChatRole::User, &display);
    }
    if auto_disabled {
        append_manager_chat_message(
            &state,
            owner_str,
            &agent.name,
            ChatRole::Assistant,
            &manager_chat_message_prefix("Manager Disabled"),
        );
    }

    if !body.stopped && delayed_until_unix.is_none() {
        let notifier_key = format!("{}_{}", owner_str, agent.name);
        if let Some(notify) = state
            .chat_agent_notifiers
            .lock()
            .unwrap()
            .get(&notifier_key)
        {
            notify.notify_one();
        }
    }

    Ok(StatusCode::OK)
}

async fn chat_agent_manager_requested(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    if let Ok(Some(mut mc)) = state.chat.get_manage_config(owner_str, &agent.name) {
        if !mc.enabled || mc.request_announced {
            return Ok(StatusCode::OK);
        }

        append_manager_chat_message(
            &state,
            owner_str,
            &agent.name,
            ChatRole::Assistant,
            &manager_chat_message_prefix(&format!(
                "asking manager to {}",
                manager_request_summary(mc.turn_counter % 5)
            )),
        );
        mc.request_announced = true;
        let _ = state.chat.save_manage_config(owner_str, &agent.name, &mc);
    }

    Ok(StatusCode::OK)
}

async fn chat_manager_proxy_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::librarian::ProxyChatRequest>,
) -> Result<Json<Value>, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str();

    let mc = state
        .chat
        .get_manage_config(owner_str, &agent.name)?
        .ok_or_else(|| LoreError::Validation("no manage config".into()))?;
    let endpoint = state
        .endpoint_store
        .get(&mc.endpoint_id)?
        .ok_or_else(|| LoreError::Validation("manager endpoint not found".into()))?;

    let (url, body) = crate::librarian::build_proxy_request(&endpoint, &req, false);
    let result = crate::librarian::proxy_non_streaming_raw(
        &state.librarian_client_http,
        &endpoint,
        &url,
        &body,
        60,
    )
    .await;

    let body_preview = serde_json::to_string(&body).ok();
    match result {
        Ok((status, response)) if status.is_success() => Ok(Json(response)),
        Ok((status, response)) => {
            let err = crate::librarian::extract_provider_error(&response);
            record_server_error(
                &state,
                "llm_api",
                format!("manager proxy non-success: {err}"),
                Some(status.as_u16()),
                Some(endpoint.id.clone()),
                body_preview.clone(),
                Some(response.to_string()),
            );
            Err(ApiError(LoreError::Validation(format!(
                "Manager endpoint error: {err}"
            ))))
        }
        Err(e) => {
            record_server_error(
                &state,
                "llm_api",
                format!("manager proxy transport error: {e}"),
                None,
                Some(endpoint.id.clone()),
                body_preview,
                None,
            );
            Err(ApiError(LoreError::Validation(format!(
                "Manager request failed: {e}"
            ))))
        }
    }
}

// --- Exchange helpers ---
// An "exchange" = one user message + all following assistant messages until the next user message.
// This matches Snoot's MessagePair concept. Window size, compaction, and context
// management all count exchanges, not individual messages.

fn count_exchanges(messages: &[&ChatMessage]) -> usize {
    messages.iter().filter(|m| m.role == ChatRole::User).count()
}

fn agent_window_exchange_count(conv: &ChatConversation) -> usize {
    let messages = agent_context_messages(unsummarized_messages(conv));
    count_exchanges(&messages)
}

/// Returns the message index where each exchange starts (i.e. each User message index).
fn exchange_boundaries(messages: &[&ChatMessage]) -> Vec<usize> {
    messages
        .iter()
        .enumerate()
        .filter(|(_, m)| m.role == ChatRole::User)
        .map(|(i, _)| i)
        .collect()
}

const COMPACTION_SYSTEM_PROMPT: &str = "You are compacting conversation history for an LLM that \
will continue this work in a future session. The LLM cannot see these messages \u{2014} only your \
summary. Write high-signal notes that help it pick up where things left off.\n\n\
Write ONLY what a new session needs to know:\n\
- Decisions made and WHY (the reasoning matters more than the action)\n\
- What changed: \"refactored X from Y to Z\" not \"edited file.rs lines 200-350\"\n\
- Bugs found, root causes identified, fixes applied\n\
- Requirements or constraints the user stated\n\
- Work in progress or explicitly planned next steps\n\
- Anything surprising or non-obvious that was discovered\n\n\
Do NOT include:\n\
- Small talk, greetings, acknowledgments\n\
- Step-by-step narration of tool use (\"read file X, then edited Y\")\n\
- File contents or code snippets (the LLM can re-read files)\n\
- Things that are obvious from reading the current code\n\
- Alternatives that were discussed then rejected (unless the rejection reason is important)\n\n\
Keep it concise. A few dense paragraphs are better than an exhaustive log. If there is a current \
summary, integrate the new messages into it \u{2014} update or replace outdated information rather \
than appending.";

/// Exchange-based compaction. Returns Ok(message) on success, Err(message) on failure.
async fn do_exchange_compact(
    state: &AppState,
    endpoint_id: Option<&str>,
    owner: &str,
    agent_name: &str,
    aggressive: bool,
) -> Result<String, String> {
    let endpoint_id =
        endpoint_id.ok_or_else(|| "Compact failed: no endpoint configured.".to_string())?;
    let endpoint = state
        .endpoint_store
        .get(endpoint_id)
        .map_err(|e| format!("Compact failed: {e}"))?
        .ok_or_else(|| "Compact failed: endpoint not found.".to_string())?;
    let conv = state
        .chat
        .load_conversation(owner, agent_name)
        .map_err(|e| format!("Compact failed: {e}"))?;

    let unsummarized = agent_context_messages(unsummarized_messages(&conv));
    let exchanges = count_exchanges(&unsummarized);
    if exchanges <= 2 {
        return Err("Nothing to compact (2 or fewer exchanges).".to_string());
    }

    let target = if aggressive {
        conv.window_size / 2
    } else {
        conv.window_size / 2
    };

    let boundaries = exchange_boundaries(&unsummarized);
    let keep_count = target.min(exchanges - 1);
    let keep_from_exchange = boundaries.len().saturating_sub(keep_count);
    let split_idx = boundaries[keep_from_exchange];

    let to_summarize = &unsummarized[..split_idx];
    if to_summarize.is_empty() {
        return Err("Nothing to compact.".to_string());
    }
    let kept = &unsummarized[split_idx..];

    let mut conversation_text = String::new();
    if !conv.summary.is_empty() {
        conversation_text.push_str(&format!(
            "<current_summary>\n{}\n</current_summary>\n\n",
            conv.summary
        ));
    }
    conversation_text.push_str("<messages_to_compact>\n");
    for msg in to_summarize {
        let role = match msg.role {
            ChatRole::User => "User",
            ChatRole::Assistant => "Assistant",
            ChatRole::Tool => "Tool",
            ChatRole::Error => "Error",
        };
        let content: String = msg.content.chars().take(2000).collect();
        let content = if content.len() < msg.content.len() {
            format!("{content}...")
        } else {
            content
        };
        conversation_text.push_str(&format!("{role}: {content}\n"));
    }
    conversation_text.push_str("</messages_to_compact>");

    let summary_messages = vec![
        crate::librarian::ProxyChatMessage {
            role: "system".into(),
            content: Some(json!(COMPACTION_SYSTEM_PROMPT)),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        },
        crate::librarian::ProxyChatMessage {
            role: "user".into(),
            content: Some(json!(conversation_text)),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        },
    ];

    let req = crate::librarian::ProxyChatRequest {
        messages: summary_messages,
        model: None,
        stream: Some(false),
        tools: None,
        temperature: None,
        max_tokens: Some(4096),
        top_p: None,
        stop: None,
    };

    let (url, body) = crate::librarian::build_proxy_request(&endpoint, &req, false);
    let result = crate::librarian::proxy_non_streaming_raw(
        &state.librarian_client_http,
        &endpoint,
        &url,
        &body,
        60,
    )
    .await;

    let summary = match result {
        Ok((status, ref response)) if status.is_success() => response
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|c| c.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("(summary generation failed)")
            .to_string(),
        Ok((_, ref response)) => {
            let err = crate::librarian::extract_provider_error(response);
            return Err(format!("Compact failed: {err}"));
        }
        Err(e) => {
            return Err(format!("Compact failed: {e}"));
        }
    };

    let summarized_exchanges = keep_from_exchange;
    let kept_exchanges = count_exchanges(kept);
    let summary_until_id = to_summarize
        .last()
        .map(|msg| msg.id)
        .unwrap_or(conv.summary_until_id);

    state
        .chat
        .set_compaction_state(owner, agent_name, summary, summary_until_id)
        .map_err(|e| format!("Compact save failed: {e}"))?;

    Ok(format!(
        "Context compacted. {summarized_exchanges} exchanges summarized, {kept_exchanges} kept."
    ))
}

// --- Manager prompt ---

fn build_manager_prompt(
    mc: &ManageConfig,
    prompt_config: &ManagerPromptConfig,
    turn_in_cycle: u32,
) -> String {
    let base = format!(
        "You are a manager overseeing an AI agent working on a task. \
         Your role is to direct the agent's next action, catch problems early, and know when to stop.\n\n\
         GOALS:\n{}\n\nSTOPPING POINT:\n{}\n\nRED FLAGS:\n{}",
        mc.goals, mc.stopping_point, mc.red_flags
    );

    let sentinel = "\n\nCRITICAL SIGNAL TOKENS:\n\
                     The tokens STOPPING_POINT and RED_FLAG_POINT are control signals that halt the agent. \
                     They are NOT words to discuss, quote, explain, echo, or demonstrate. \
                     Any appearance of either token anywhere in your response is treated as a live signal and will stop the agent immediately.\n\n\
                     You MUST NOT write STOPPING_POINT or RED_FLAG_POINT under ANY of the following circumstances:\n\
                     - As examples, demonstrations, or illustrations of what the tokens look like\n\
                     - When summarizing, paraphrasing, or restating these instructions\n\
                     - Inside quotes, code blocks, backticks, or markdown\n\
                     - When describing the stopping point or red flag criteria in prose\n\
                     - In hypotheticals (\"if STOPPING_POINT were triggered...\")\n\
                     - In any other context whatsoever\n\n\
                     Write STOPPING_POINT ONLY when the stopping point criteria above are actually met right now and the agent should halt.\n\
                     Write RED_FLAG_POINT ONLY when a red flag above has actually triggered right now and the agent should halt.\n\
                     When referring to these concepts in guidance, use plain English (\"the stopping criteria\", \"a red flag\") \u{2014} never the literal token.\n\n\
                     RESPONSE RULES:\n\
                     - Write to the agent, not to the user\n\
                     - Give a concrete next instruction or decision\n\
                     - Do not ask the user for clarification, approval, or more input\n\
                     - Do not wait for the user unless the stated goals or stopping criteria require it\n\
                     - If the agent is on track, say so briefly and tell it what to do next\n\
                     - If the agent is waiting on a known long-running task, you may prefix your response with WAIT_FOR_SECONDS: <1-600> on the first line, then put the delayed instruction below it\n\
                     - Keep the response short and operational";

    let (stage, context) = match turn_in_cycle {
        0 | 1 | 2 => (ManagerPromptStage::ReviewLatestOutput, String::new()),
        3 => (
            ManagerPromptStage::RunPeriodicChecks,
            format!("PERIODIC CHECKS:\n{}\n\n", mc.periodic_checks),
        ),
        4 => (
            ManagerPromptStage::ValidatePeriodicChecks,
            format!("PERIODIC CHECKS:\n{}\n\n", mc.periodic_checks),
        ),
        _ => unreachable!(),
    };
    let stage_prompt = prompt_config.prompt_for_stage(stage);
    format!("{base}{sentinel}\n\n{context}{stage_prompt}")
}

fn manager_request_summary(turn_in_cycle: u32) -> &'static str {
    match turn_in_cycle {
        0 | 1 | 2 => "review the latest output",
        3 => "run periodic checks",
        4 => "validate the periodic check results",
        _ => unreachable!(),
    }
}

fn manager_chat_message_prefix(content: &str) -> String {
    format!("👔 {content}")
}

fn should_restart_agent_on_manage_enable(process_status: Option<&str>) -> bool {
    matches!(process_status, Some("restarting") | Some("offline"))
}

fn release_due_delayed_manager_message(
    state: &AppState,
    owner: &str,
    agent_name: &str,
) -> Result<bool, ApiError> {
    let Ok(Some(mut mc)) = state.chat.get_manage_config(owner, agent_name) else {
        return Ok(false);
    };
    if mc.delayed_message.trim().is_empty() || mc.delayed_until_unix <= 0 {
        return Ok(false);
    }
    if OffsetDateTime::now_utc().unix_timestamp() < mc.delayed_until_unix {
        return Ok(false);
    }

    let content = std::mem::take(&mut mc.delayed_message);
    mc.delayed_until_unix = 0;
    state.chat.save_manage_config(owner, agent_name, &mc)?;
    append_manager_chat_message(
        state,
        owner,
        agent_name,
        ChatRole::User,
        &manager_chat_message_prefix(content.trim()),
    );
    Ok(true)
}

fn append_manager_chat_message(
    state: &AppState,
    owner: &str,
    agent_name: &str,
    role: ChatRole,
    content: &str,
) {
    if let Ok(msg) = state
        .chat
        .append_message(owner, agent_name, role, content.to_string())
    {
        let audit_role = match role {
            ChatRole::User => "user",
            ChatRole::Assistant => "assistant",
            ChatRole::Tool => "tool",
            ChatRole::Error => "error",
        };
        state
            .chat_audit
            .log(agent_name, owner, audit_role, &msg.content);
        let event_role = match role {
            ChatRole::User => "user",
            ChatRole::Assistant => "assistant",
            ChatRole::Tool => "tool",
            ChatRole::Error => "error",
        };
        push_chat_event(
            state,
            owner,
            ChatEvent {
                event_type: "message".into(),
                agent: agent_name.to_string(),
                owner: owner.to_string(),
                data: json!({ "id": msg.id, "role": event_role, "content": msg.content }),
            },
        );
    }
}

// --- API agent helpers (used by btw) ---

const API_AGENT_TOOL_RESULT_CAP: usize = 30_000;
const API_AGENT_MAX_CONTEXT_CHARS: usize = 400_000;
const API_AGENT_TRIMMED_STUB: &str = "[Content trimmed to save context \u{2014} re-read if needed]";
const API_AGENT_TRIMMED_ASSISTANT: &str = "[Earlier analysis trimmed to save context]";

fn estimate_context_size(
    messages: &[crate::librarian::ProxyChatMessage],
    tool_count: usize,
) -> usize {
    let mut total = 0usize;
    for m in messages {
        if let Some(c) = &m.content {
            total += match c {
                Value::String(s) => s.len(),
                other => other.to_string().len(),
            };
        }
        if let Some(tcs) = &m.tool_calls {
            for tc in tcs {
                total += tc
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .and_then(|a| a.as_str())
                    .map(|s| s.len())
                    .unwrap_or(0);
                total += tc
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.len())
                    .unwrap_or(0);
            }
        }
    }
    total += tool_count * 500;
    total
}

fn trim_old_context(messages: &mut Vec<crate::librarian::ProxyChatMessage>, tool_count: usize) {
    let size = estimate_context_size(messages, tool_count);
    if size <= API_AGENT_MAX_CONTEXT_CHARS {
        return;
    }

    let last_assistant = messages
        .iter()
        .rposition(|m| m.role == "assistant")
        .unwrap_or(0);

    for i in 0..messages.len().min(last_assistant) {
        let m = &mut messages[i];
        if m.role == "tool" {
            if let Some(Value::String(s)) = &m.content {
                if s.len() > 200 {
                    m.content = Some(json!(API_AGENT_TRIMMED_STUB));
                }
            }
        }
        if m.role == "assistant" {
            if let Some(Value::String(s)) = &m.content {
                if s.len() > 1000 {
                    let preview = s.chars().take(200).collect::<String>();
                    m.content = Some(json!(format!("{preview}\n{API_AGENT_TRIMMED_ASSISTANT}")));
                }
            }
        }
    }
}

fn truncate_tool_result(tool_name: &str, text: &str) -> String {
    if text.len() <= API_AGENT_TOOL_RESULT_CAP {
        return text.to_string();
    }

    let mut cut_at = text[..API_AGENT_TOOL_RESULT_CAP]
        .rfind('\n')
        .unwrap_or(API_AGENT_TOOL_RESULT_CAP);
    if cut_at < API_AGENT_TOOL_RESULT_CAP / 2 {
        cut_at = API_AGENT_TOOL_RESULT_CAP;
    }

    let total_lines = text.matches('\n').count() + 1;
    let shown_lines = text[..cut_at].matches('\n').count() + 1;
    let hint = match tool_name {
        "read_block" | "read_blocks_around" | "read_document" => {
            "Use smaller reads or targeted grep."
        }
        "grep_blocks" => "Narrow your search query.",
        "list_blocks" | "list_projects" => "Results are large; consider targeted queries.",
        _ => "Consider a more targeted query to reduce output size.",
    };
    format!(
        "{}\n\n[Output truncated \u{2014} showing ~{shown_lines} of {total_lines} lines. {hint}]",
        &text[..cut_at]
    )
}

fn finish_api_agent(state: &AppState, owner: &str, agent_name: &str, content: &str) {
    let msg =
        state
            .chat
            .append_message(owner, agent_name, ChatRole::Assistant, content.to_string());
    state.chat_audit.log(agent_name, owner, "agent", content);

    if let Ok(msg) = msg {
        push_chat_event(
            state,
            owner,
            ChatEvent {
                event_type: "response_complete".into(),
                agent: agent_name.to_string(),
                owner: owner.to_string(),
                data: json!({ "id": msg.id, "content": content }),
            },
        );
    }

    finalize_agent_turn(state, owner, agent_name);
}

fn finalize_agent_turn(state: &AppState, owner: &str, agent_name: &str) {
    clear_chat_agent_stop_request(state, owner, agent_name);
    let _ = state.chat.complete_active_turn(owner, agent_name);
    let _ = state
        .chat
        .update_agent_status(owner, agent_name, AgentChatStatus::Idle);
    let active_turn_user_id = state
        .chat
        .load_conversation(owner, agent_name)
        .map(|conv| conv.active_turn_user_id)
        .unwrap_or(0);
    push_chat_event(
        state,
        owner,
        ChatEvent {
            event_type: "status".into(),
            agent: agent_name.to_string(),
            owner: owner.to_string(),
            data: json!({
                "status": "idle",
                "active_turn_user_id": active_turn_user_id,
            }),
        },
    );
}

fn chat_agent_stop_key(owner: &str, agent_name: &str) -> String {
    format!("{owner}_{agent_name}")
}

fn request_chat_agent_stop(state: &AppState, owner: &str, agent_name: &str) {
    state
        .chat_agent_stops
        .lock()
        .unwrap()
        .insert(chat_agent_stop_key(owner, agent_name));
}

fn take_chat_agent_stop_request(state: &AppState, owner: &str, agent_name: &str) -> bool {
    state
        .chat_agent_stops
        .lock()
        .unwrap()
        .remove(&chat_agent_stop_key(owner, agent_name))
}

fn clear_chat_agent_stop_request(state: &AppState, owner: &str, agent_name: &str) {
    state
        .chat_agent_stops
        .lock()
        .unwrap()
        .remove(&chat_agent_stop_key(owner, agent_name));
}

fn collect_git_context(cwd: Option<&str>) -> String {
    let dir = match cwd {
        Some(d) if !d.is_empty() => d,
        _ => return String::new(),
    };
    let git_dir = std::path::Path::new(dir).join(".git");
    if !git_dir.exists() {
        return String::new();
    }
    let mut parts = Vec::new();
    if let Ok(output) = std::process::Command::new("git")
        .args(["branch", "--show-current"])
        .current_dir(dir)
        .output()
    {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !branch.is_empty() {
            parts.push(format!("Branch: {branch}"));
        }
    }
    if let Ok(output) = std::process::Command::new("git")
        .args(["log", "--oneline", "-3"])
        .current_dir(dir)
        .output()
    {
        let log = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !log.is_empty() {
            parts.push(format!("Recent commits:\n{log}"));
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        parts.join("\n")
    }
}

fn get_agent_recent_activity(state: &AppState, owner: &str, agent: &str) -> String {
    let key = format!("{owner}_{agent}");
    let map = state.agent_recent_activity.lock().unwrap();
    match map.get(&key) {
        Some(activity) => activity.format_section(),
        None => String::new(),
    }
}

fn build_api_agent_system_prompt(
    state: &AppState,
    agent: &AuthenticatedAgent,
    conv: &crate::auth::ChatConversation,
) -> String {
    let mut parts = Vec::new();
    parts.push("You are a Lore knowledge base agent with tools to navigate projects, manage documents, and read/write content.\n\n\
        Lore organizes knowledge into projects and documents. Each project has an Overview, File Map, and Agent Context accessible via dedicated tools. Documents contain typed blocks (the content itself).\n\n\
        Guidelines:\n\
        - Be concise and direct. Provide clear answers.\n\
        - Use tools to fulfill user requests. Read before writing. Grep to find content.\n\
        - Use get_project_overview, get_file_map, get_agent_context for project-level info.\n\
        - Use list_documents to see the document tree, read_document to read the entire document as text, list_blocks for block structure, read_block for individual blocks.\n\
        - For broad document changes, use read_document then write_document. For surgical edits, use edit_block.\n\
        - Use edit_block for targeted changes within a block, update_block for full rewrites.\n\
        - For large blocks, use read_block with offset/limit to read chunks.\n\
        - When a tool result is truncated, use more targeted queries rather than re-reading the same large result.\n\
        - If you encounter an error, explain it clearly and suggest alternatives.\n\
        - Do not make up content. If you can't find something, say so.\n\
        - For multi-step tasks, plan before acting. Use fewer tool calls per turn when possible.\n\n\
        File Map maintenance:\n\
        - Each project has a File Map listing key project files. Use get_file_map to read it, update_file_map or edit_file_map to modify it.\n\
        - Keep this map current: add files you discover are important to the work, remove files that are deleted or no longer relevant.\n\
        - Only list files that are actionable for development. Do not list generated files, build artifacts, or files unlikely to need attention.\n\n\
        SVG output:\n\
        - You can output inline SVG to present quick reports, diagrams, tables, and visual summaries to the user.\n\
        - Use <svg xmlns=\"http://www.w3.org/2000/svg\" ...>...</svg> with a self-contained design. Keep SVGs simple and readable.\n\
        - Do NOT use <foreignObject> — use only native SVG elements (<text>, <rect>, <circle>, <line>, <path>, <g>, etc). Use &amp; not & in SVG text.".to_string());

    let project_context = collect_project_context(state, &agent.grants);
    if !project_context.is_empty() {
        parts.push(format!("\n## Project Context\n{project_context}"));
    }

    if !conv.pinned_context.is_empty() {
        parts.push(format!("\n## Pinned Context\n{}", conv.pinned_context));
    }

    let readable: Vec<String> = agent
        .grants
        .iter()
        .map(|g| {
            let perm = if g.permission.allows_write() {
                "read-write"
            } else {
                "read"
            };
            let name = state.store.read_project_meta(&g.project).display_name;
            format!("- {} ({})", name, perm)
        })
        .collect();
    if !readable.is_empty() {
        parts.push(format!("\n## Accessible Projects\n{}", readable.join("\n")));
    }

    let git_ctx = collect_git_context(conv.cwd.as_deref());
    if !git_ctx.is_empty() {
        parts.push(format!("\n## Git Repository\n{git_ctx}"));
    }

    let owner_str = agent.owner.as_ref().map(|u| u.as_str()).unwrap_or("");
    let activity = get_agent_recent_activity(state, owner_str, &agent.name);
    if !activity.is_empty() {
        parts.push(format!("\n## Recent Activity\n{activity}"));
    }

    parts.join("\n")
}

fn build_api_agent_tools() -> Vec<Value> {
    mcp_tools().into_iter().map(|t| {
        json!({
            "type": "function",
            "function": {
                "name": t.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                "description": t.get("description").and_then(|d| d.as_str()).unwrap_or(""),
                "parameters": t.get("inputSchema").cloned().unwrap_or(json!({"type": "object"})),
            }
        })
    }).collect()
}

fn format_api_tool_display(name: &str, args: &Value) -> String {
    let args_map = args.as_object();
    let get_str = |key: &str| -> &str {
        args_map
            .and_then(|m| m.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    };
    let short_id = |key: &str| -> String {
        let id = get_str(key);
        if id.starts_with('_') {
            id.to_string()
        } else if id.len() > 8 {
            id[..8].to_string()
        } else {
            id.to_string()
        }
    };
    match name {
        "list_projects" => "\u{1f4cb} list_projects".into(),
        "list_documents" => format!("\u{1f4c1} list_documents {}", get_str("project")),
        "create_document" => format!("\u{1f4c4} create_document \"{}\"", get_str("name")),
        "rename_document" => format!("\u{1f4c4} rename_document \"{}\"", get_str("name")),
        "delete_document" => format!(
            "\u{1f5d1}\u{fe0f} delete_document {}",
            short_id("document_id")
        ),
        "get_project_overview" => format!("\u{1f4d6} get_project_overview {}", get_str("project")),
        "get_file_map" => format!("\u{1f5fa}\u{fe0f} get_file_map {}", get_str("project")),
        "update_file_map" => format!("\u{270f}\u{fe0f} update_file_map {}", get_str("project")),
        "edit_file_map" => format!("\u{270f}\u{fe0f} edit_file_map {}", get_str("project")),
        "get_agent_context" => format!("\u{1f4d6} get_agent_context {}", get_str("project")),
        "list_blocks" => format!("\u{1f4cb} list_blocks {}", short_id("document_id")),
        "read_block" => format!("\u{1f4d6} read_block {}", short_id("block_id")),
        "update_block" => format!("\u{270f}\u{fe0f} update_block {}", short_id("block_id")),
        "edit_block" => format!("\u{270f}\u{fe0f} edit_block {}", short_id("block_id")),
        "create_block" => format!("\u{270f}\u{fe0f} create_block {}", short_id("document_id")),
        "delete_block" => format!("\u{1f5d1}\u{fe0f} delete_block {}", short_id("block_id")),
        "move_block" => format!("\u{1f4e6} move_block {}", short_id("block_id")),
        "split_block" => format!("\u{2702}\u{fe0f} split_block {}", short_id("block_id")),
        "combine_blocks" => format!("\u{1f517} combine_blocks"),
        "read_document" => format!("\u{1f4d6} read_document {}", short_id("document_id")),
        "write_document" => format!(
            "\u{270f}\u{fe0f} write_document {}",
            short_id("document_id")
        ),
        "grep_blocks" => format!("\u{1f50d} grep_blocks \"{}\"", get_str("query")),
        _ => format!("\u{1f527} {name}"),
    }
}

#[derive(Debug, Default, Clone)]
struct PendingStreamToolCall {
    name: String,
    arguments: String,
}

fn merge_pending_stream_tool_call(
    pending: &mut BTreeMap<i64, PendingStreamToolCall>,
    tool_call: &Value,
) {
    let index = tool_call
        .get("index")
        .and_then(|i| i.as_i64())
        .unwrap_or(pending.len() as i64);
    let entry = pending.entry(index).or_default();
    if let Some(name) = tool_call
        .get("function")
        .and_then(|f| f.get("name"))
        .and_then(|n| n.as_str())
        .filter(|name| !name.is_empty())
    {
        entry.name = name.to_string();
    }
    if let Some(arguments) = tool_call
        .get("function")
        .and_then(|f| f.get("arguments"))
        .and_then(|a| a.as_str())
        .filter(|arguments| !arguments.is_empty())
    {
        entry.arguments.push_str(arguments);
    }
}

fn finalize_pending_stream_tool_call(name: &str, raw_arguments: &str) -> (String, Option<Value>) {
    let trimmed = raw_arguments.trim();
    if trimmed.is_empty() {
        let args = json!({});
        return (format_api_tool_display(name, &args), Some(args));
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(args) => (format_api_tool_display(name, &args), Some(args)),
        Err(_) => (format!("\u{1f527} {name}"), None),
    }
}

fn flush_pending_stream_tool_calls(
    state: &AppState,
    owner: &str,
    agent: &str,
    pending: &mut BTreeMap<i64, PendingStreamToolCall>,
) {
    for (_, tool_call) in std::mem::take(pending) {
        if tool_call.name.is_empty() {
            continue;
        }
        let (detail, args) =
            finalize_pending_stream_tool_call(&tool_call.name, &tool_call.arguments);
        let _ = state.chat.append_or_extend_tool(owner, agent, &detail);
        state.chat_audit.log(agent, owner, "tool", &detail);
        push_chat_event(
            state,
            owner,
            ChatEvent {
                event_type: "tool_use".into(),
                agent: agent.to_string(),
                owner: owner.to_string(),
                data: json!({ "detail": detail }),
            },
        );
        if let Some(args) = args.as_ref() {
            record_api_tool_activity(state, owner, agent, &tool_call.name, args);
        }
    }
}

// --- API agent compact (delegates to do_exchange_compact) ---

async fn run_api_compact(
    state: &AppState,
    endpoint_id: Option<&str>,
    owner: &str,
    agent_name: &str,
) {
    match do_exchange_compact(state, endpoint_id, owner, agent_name, true).await {
        Ok(msg) | Err(msg) => finish_api_agent(state, owner, agent_name, &msg),
    }
}

// --- API agent btw ---

async fn run_api_btw(
    state: AppState,
    agent: AuthenticatedAgent,
    owner: String,
    agent_name: String,
    btw_message: String,
) {
    let endpoint_id = match agent.endpoint_id.as_deref() {
        Some(id) => id,
        None => return,
    };
    let endpoint = match state.endpoint_store.get(endpoint_id) {
        Ok(Some(ep)) => ep,
        _ => return,
    };
    let conv = match state.chat.load_conversation(&owner, &agent_name) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut system_parts = vec![
        "You are handling a side question (btw) for a Lore knowledge base agent. \
         You have full tool access but DO NOT create, update, move, or delete any content \
         unless the user's message explicitly asks you to make a change. \
         Read and search freely. Be concise."
            .to_string(),
    ];

    let project_context = collect_project_context(&state, &agent.grants);
    if !project_context.is_empty() {
        system_parts.push(format!("\n## Project Context\n{project_context}"));
    }
    if !conv.pinned_context.is_empty() {
        system_parts.push(format!("\n## Pinned Context\n{}", conv.pinned_context));
    }
    if !conv.summary.is_empty() {
        system_parts.push(format!("\n## Conversation Summary\n{}", conv.summary));
    }

    let accessible: Vec<String> = agent
        .grants
        .iter()
        .map(|g| {
            let perm = if g.permission.allows_write() {
                "read-write"
            } else {
                "read"
            };
            format!("- {} ({})", g.project.as_str(), perm)
        })
        .collect();
    if !accessible.is_empty() {
        system_parts.push(format!(
            "\n## Accessible Projects\n{}",
            accessible.join("\n")
        ));
    }

    let tools = build_api_agent_tools();
    let tool_count = tools.len();

    let mut messages = vec![
        crate::librarian::ProxyChatMessage {
            role: "system".into(),
            content: Some(json!(system_parts.join("\n"))),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        },
        crate::librarian::ProxyChatMessage {
            role: "user".into(),
            content: Some(json!(btw_message)),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        },
    ];

    let mut accumulated_text = String::new();
    const BTW_MAX_TURNS: usize = 250;
    const BTW_TURN_WARNINGS: &[usize] = &[150, 200, 237];

    for turn in 0..BTW_MAX_TURNS {
        trim_old_context(&mut messages, tool_count);

        let req = crate::librarian::ProxyChatRequest {
            messages: messages.clone(),
            model: None,
            stream: Some(false),
            tools: Some(tools.clone()),
            temperature: None,
            max_tokens: Some(16384),
            top_p: None,
            stop: None,
        };

        let (url, body) = crate::librarian::build_proxy_request(&endpoint, &req, false);
        let raw_result = crate::librarian::proxy_non_streaming_raw(
            &state.librarian_client_http,
            &endpoint,
            &url,
            &body,
            120,
        )
        .await;

        let response = match raw_result {
            Ok((status, resp)) => {
                if !status.is_success() {
                    let err = crate::librarian::extract_provider_error(&resp);
                    accumulated_text.push_str(&format!("\n\n[btw error: {err}]"));
                    break;
                }
                resp
            }
            Err(e) => {
                accumulated_text.push_str(&format!("\n\n[btw error: {e}]"));
                break;
            }
        };

        let choice = response
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|c| c.first());
        let message = choice.and_then(|c| c.get("message"));
        let content = message
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        let tool_calls = message
            .and_then(|m| m.get("tool_calls"))
            .and_then(|t| t.as_array())
            .cloned();

        accumulated_text.push_str(&content);

        if let Some(ref tcs) = tool_calls {
            if !tcs.is_empty() {
                messages.push(crate::librarian::ProxyChatMessage {
                    role: "assistant".into(),
                    content: if content.is_empty() {
                        None
                    } else {
                        Some(json!(content))
                    },
                    tool_calls: Some(tcs.clone()),
                    tool_call_id: None,
                    name: None,
                });

                for tc in tcs {
                    let tool_id = tc
                        .get("id")
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                        .to_string();
                    let func = tc.get("function");
                    let tool_name = func
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    let raw_args = func
                        .and_then(|f| f.get("arguments"))
                        .and_then(|a| a.as_str())
                        .unwrap_or("{}");
                    let tool_args: Value = serde_json::from_str(raw_args).unwrap_or(json!({}));

                    let detail = format_api_tool_display(tool_name, &tool_args);
                    let labeled_detail = format!("[btw] {detail}");
                    let _ = state
                        .chat
                        .append_or_extend_tool(&owner, &agent_name, &labeled_detail);
                    state
                        .chat_audit
                        .log(&agent_name, &owner, "tool", &labeled_detail);
                    push_chat_event(
                        &state,
                        &owner,
                        ChatEvent {
                            event_type: "tool_use".into(),
                            agent: agent_name.clone(),
                            owner: owner.clone(),
                            data: json!({"detail": labeled_detail}),
                        },
                    );
                    record_api_tool_activity(&state, &owner, &agent_name, tool_name, &tool_args);

                    let result_text = match call_mcp_tool(
                        &state,
                        &agent,
                        Some(&json!({
                            "name": tool_name,
                            "arguments": tool_args,
                        })),
                    ) {
                        Ok(val) => {
                            let text = val
                                .get("content")
                                .and_then(|c| c.as_array())
                                .and_then(|a| a.first())
                                .and_then(|t| t.get("text"))
                                .and_then(|t| t.as_str())
                                .unwrap_or("");
                            truncate_tool_result(tool_name, text)
                        }
                        Err(e) => format!("Error: {e}"),
                    };

                    messages.push(crate::librarian::ProxyChatMessage {
                        role: "tool".into(),
                        content: Some(json!(result_text)),
                        tool_calls: None,
                        tool_call_id: Some(tool_id),
                        name: Some(tool_name.to_string()),
                    });
                }
                if BTW_TURN_WARNINGS.contains(&turn) {
                    messages.push(crate::librarian::ProxyChatMessage {
                        role: "user".into(),
                        content: Some(json!(format!(
                            "You have used {turn} of {BTW_MAX_TURNS} tool-calling turns. \
                            You have {} turns remaining. Please wrap up your work and provide a final response soon.",
                            BTW_MAX_TURNS - turn
                        ))),
                        tool_calls: None,
                        tool_call_id: None,
                        name: None,
                    });
                }
                continue;
            }
        }
        break;
    }

    let final_content = if accumulated_text.trim().is_empty() {
        "[btw] (no response)".to_string()
    } else {
        format!("[btw] {}", accumulated_text.trim())
    };

    if let Ok(msg) = state.chat.append_message(
        &owner,
        &agent_name,
        ChatRole::Assistant,
        final_content.clone(),
    ) {
        state
            .chat_audit
            .log(&agent_name, &owner, "btw", &final_content);
        push_chat_event(
            &state,
            &owner,
            ChatEvent {
                event_type: "response_complete".into(),
                agent: agent_name.clone(),
                owner: owner.clone(),
                data: json!({"id": msg.id, "content": final_content}),
            },
        );
    }

    finalize_agent_turn(&state, &owner, &agent_name);
}

// --- Chat completions proxy ---

async fn chat_proxy_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::librarian::ProxyChatRequest>,
) -> Result<Response, ApiError> {
    let agent = authenticate_agent(&state, &headers)?.ok_or(LoreError::PermissionDenied)?;
    let endpoint_id = agent
        .endpoint_id
        .as_deref()
        .ok_or_else(|| LoreError::Validation("agent has no endpoint configured".into()))?;
    let endpoint = state
        .endpoint_store
        .get(endpoint_id)?
        .ok_or_else(|| LoreError::Validation("configured endpoint not found".into()))?;

    let streaming = req.stream.unwrap_or(false);
    let model = req.model.as_deref().unwrap_or(&endpoint.model).to_string();
    let (url, body) = crate::librarian::build_proxy_request(&endpoint, &req, streaming);
    let completion_id = format!("chatcmpl-{}", uuid::Uuid::new_v4());

    // Push tool_use events to the chat UI for visibility
    let owner = agent.owner.as_ref().ok_or(LoreError::PermissionDenied)?;
    let owner_str = owner.as_str().to_string();
    let agent_name = agent.name.clone();

    if streaming {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::librarian::ProxyStreamChunk>(256);
        let client = state.librarian_client_http.clone();
        let ep = endpoint.clone();
        let url_owned = url.clone();
        let body_owned = body.clone();
        tokio::spawn(async move {
            crate::librarian::proxy_streaming(&client, &ep, &url_owned, &body_owned, 300, tx).await;
        });

        let model_clone = model.clone();
        let cid = completion_id.clone();
        let state_clone = state.clone();
        let endpoint_id_for_stream = endpoint.id.clone();
        let body_preview = serde_json::to_string(&body).ok();
        let stream = async_stream::stream! {
            let mut pending_tool_calls: BTreeMap<i64, PendingStreamToolCall> = BTreeMap::new();
            while let Some(chunk) = rx.recv().await {
                if let crate::librarian::ProxyStreamChunk::Delta {
                    tool_calls: ref tc_opt,
                    finish_reason: ref finish_reason_opt,
                    ..
                } = chunk
                {
                    if let Some(tcs) = tc_opt {
                        for tc in tcs {
                            merge_pending_stream_tool_call(&mut pending_tool_calls, tc);
                        }
                    }
                    if finish_reason_opt.as_deref() == Some("tool_calls") {
                        flush_pending_stream_tool_calls(
                            &state_clone,
                            &owner_str,
                            &agent_name,
                            &mut pending_tool_calls,
                        );
                    }
                }
                if let crate::librarian::ProxyStreamChunk::Error(ref msg) = chunk {
                    record_server_error(
                        &state_clone,
                        "llm_api",
                        format!("chat proxy stream error: {msg}"),
                        None,
                        Some(endpoint_id_for_stream.clone()),
                        body_preview.clone(),
                        Some(msg.clone()),
                    );
                }
                if let Some(formatted) = crate::librarian::format_openai_stream_chunk(&chunk, &model_clone, &cid) {
                    yield Ok::<_, std::convert::Infallible>(formatted);
                }
                if matches!(chunk, crate::librarian::ProxyStreamChunk::Done) {
                    flush_pending_stream_tool_calls(
                        &state_clone,
                        &owner_str,
                        &agent_name,
                        &mut pending_tool_calls,
                    );
                    break;
                }
            }
        };

        let body = Body::from_stream(stream);
        Ok(Response::builder()
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .body(body)
            .unwrap())
    } else {
        let client = state.librarian_client_http.clone();
        let body_preview = serde_json::to_string(&body).ok();
        match crate::librarian::proxy_non_streaming(&client, &endpoint, &url, &body, 300).await {
            Ok(result) => Ok(Json(result).into_response()),
            Err(e) => {
                record_server_error(
                    &state,
                    "llm_api",
                    format!("chat proxy non-streaming error: {e}"),
                    None,
                    Some(endpoint.id.clone()),
                    body_preview,
                    None,
                );
                Err(e.into())
            }
        }
    }
}

// --- Slash command handler ---

#[derive(Debug, Deserialize)]
struct ChatCommandForm {
    csrf_token: String,
    command: String,
}

#[derive(Debug, Deserialize)]
struct ChatSaveConfigForm {
    csrf_token: String,
    backend: Option<String>,
    model: Option<String>,
    effort: Option<String>,
    pinned_context: Option<String>,
    endpoint_id: Option<String>,
}

async fn chat_get_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = require_ui_session(&state, &headers)?;
    let owner = session.user.username.as_str();

    let agents = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?;
    let agent = agents
        .iter()
        .find(|a| a.name == agent_name)
        .ok_or(LoreError::PermissionDenied)?;
    let backend_str = agent.backend.to_string();

    let mut all_prefs = serde_json::Map::new();
    for b in &["claude", "gemini", "codex", "openai"] {
        let (model, effort) = state
            .chat
            .get_backend_prefs(owner, b)
            .unwrap_or((None, None));
        all_prefs.insert(
            b.to_string(),
            serde_json::json!({
                "model": model,
                "effort": effort,
            }),
        );
    }

    let pinned_context = state.chat.get_pinned_context(owner, &agent_name)?;
    let project_context = collect_project_context(&state, &agent.grants);

    let endpoints: Vec<Value> = state.endpoint_store.list()?.iter().map(|ep| {
        json!({ "id": ep.id, "name": ep.name, "kind": ep.kind.to_string(), "model": ep.model })
    }).collect();

    Ok(Json(serde_json::json!({
        "backend": backend_str,
        "prefs": all_prefs,
        "pinned_context": pinned_context,
        "project_context": project_context,
        "endpoint_id": agent.endpoint_id,
        "endpoints": endpoints,
    })))
}

async fn chat_save_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_name): Path<String>,
    Form(form): Form<ChatSaveConfigForm>,
) -> Result<Json<Value>, ApiError> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let owner = session.user.username.as_str();

    let agents = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?;
    let agent = agents
        .iter()
        .find(|a| a.name == agent_name)
        .ok_or(LoreError::PermissionDenied)?;

    let backend_str = if let Some(ref new_backend) = form.backend {
        let parsed: crate::auth::AgentBackend = new_backend.parse()?;
        if parsed != agent.backend {
            state
                .auth
                .set_agent_backend(&agent_name, &session.user.username, parsed)?;
        }
        new_backend.clone()
    } else {
        agent.backend.to_string()
    };

    let model_val = form
        .model
        .as_deref()
        .filter(|m| !m.is_empty() && *m != "default");
    state
        .chat
        .set_backend_model(owner, &backend_str, model_val.map(|s| s.to_string()))?;

    let effort_val = form
        .effort
        .as_deref()
        .filter(|e| !e.is_empty() && *e != "default");
    state
        .chat
        .set_backend_effort(owner, &backend_str, effort_val.map(|s| s.to_string()))?;

    if let Some(ref pinned) = form.pinned_context {
        state.chat.set_pinned_context(owner, &agent_name, pinned)?;
    }

    if let Some(ref eid) = form.endpoint_id {
        let eid_opt = if eid.is_empty() {
            None
        } else {
            Some(eid.as_str())
        };
        state
            .auth
            .set_agent_endpoint_id(&agent_name, &session.user.username, eid_opt)?;
    }

    Ok(Json(serde_json::json!({"ok": true})))
}

async fn chat_get_manage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = require_ui_session(&state, &headers)?;
    let owner = session.user.username.as_str();
    let agents = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?;
    let _agent = agents
        .iter()
        .find(|a| a.name == agent_name)
        .ok_or(LoreError::PermissionDenied)?;

    let mc = state
        .chat
        .get_manage_config(owner, &agent_name)?
        .unwrap_or_default();

    let endpoints: Vec<Value> = state.endpoint_store.list()?.iter().map(|ep| {
        json!({ "id": ep.id, "name": ep.name, "kind": ep.kind.to_string(), "model": ep.model })
    }).collect();

    Ok(Json(json!({
        "backend": mc.backend,
        "endpoint_id": mc.endpoint_id,
        "goals": mc.goals,
        "stopping_point": mc.stopping_point,
        "periodic_checks": mc.periodic_checks,
        "red_flags": mc.red_flags,
        "enabled": mc.enabled,
        "turn_counter": mc.turn_counter,
        "endpoints": endpoints,
    })))
}

#[derive(Deserialize)]
struct ManageSaveForm {
    csrf_token: String,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    endpoint_id: Option<String>,
    #[serde(default)]
    goals: Option<String>,
    #[serde(default)]
    stopping_point: Option<String>,
    #[serde(default)]
    periodic_checks: Option<String>,
    #[serde(default)]
    red_flags: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn chat_save_manage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_name): Path<String>,
    Form(form): Form<ManageSaveForm>,
) -> Result<Json<Value>, ApiError> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let owner = session.user.username.as_str();
    let agents = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?;
    let agent = agents
        .iter()
        .find(|a| a.name == agent_name)
        .ok_or(LoreError::PermissionDenied)?;

    let mut mc = state
        .chat
        .get_manage_config(owner, &agent_name)?
        .unwrap_or_default();
    let was_enabled = mc.enabled;

    if let Some(b) = &form.backend {
        mc.backend = b.clone();
    }
    if let Some(eid) = &form.endpoint_id {
        mc.endpoint_id = eid.clone();
    }
    if let Some(g) = &form.goals {
        mc.goals = g.clone();
    }
    if let Some(sp) = &form.stopping_point {
        mc.stopping_point = sp.clone();
    }
    if let Some(pc) = &form.periodic_checks {
        mc.periodic_checks = pc.clone();
    }
    if let Some(rf) = &form.red_flags {
        mc.red_flags = rf.clone();
    }
    if let Some(en) = form.enabled {
        if en && !mc.enabled {
            mc.turn_counter = 0;
            mc.run_requested = true;
            mc.request_announced = false;
            mc.delayed_message.clear();
            mc.delayed_until_unix = 0;
        } else if !en {
            mc.run_requested = false;
            mc.request_announced = false;
            mc.delayed_message.clear();
            mc.delayed_until_unix = 0;
        }
        mc.enabled = en;
    }

    state.chat.save_manage_config(owner, &agent_name, &mc)?;
    if mc.enabled && !was_enabled {
        append_manager_chat_message(
            &state,
            owner,
            &agent_name,
            ChatRole::Assistant,
            &manager_chat_message_prefix("Manager Enabled"),
        );
        let state_clone = state.clone();
        let owner_clone = owner.to_string();
        let agent_name_clone = agent_name.clone();
        let machine_name = agent.machine_name.clone();
        let process_status =
            machine_agent_process_status(&state, owner, &agent_name, agent.machine_name.as_deref());
        tokio::spawn(async move {
            let notifier_key = format!("{}_{}", owner_clone, agent_name_clone);
            if let Some(notify) = state_clone
                .chat_agent_notifiers
                .lock()
                .unwrap()
                .get(&notifier_key)
            {
                notify.notify_one();
            }

            if should_restart_agent_on_manage_enable(process_status.as_deref()) {
                if let Some(machine_name) = machine_name {
                    let machine_key = format!("{}_{}", owner_clone, machine_name);
                    let _ = queue_machine_command_and_wait(
                        &state_clone,
                        &machine_key,
                        "restart_agent",
                        json!({ "agent_name": agent_name_clone }),
                    )
                    .await;
                }
            }
        });
    } else if !mc.enabled && was_enabled {
        append_manager_chat_message(
            &state,
            owner,
            &agent_name,
            ChatRole::Assistant,
            &manager_chat_message_prefix("Manager Disabled"),
        );
    }
    Ok(Json(json!({"ok": true, "enabled": mc.enabled})))
}

async fn chat_slash_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_name): Path<String>,
    Form(form): Form<ChatCommandForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let owner = session.user.username.as_str();

    // Verify the user owns this agent
    let agents = state
        .auth
        .list_agent_tokens_for_user(&session.user.username)?;
    if !agents.iter().any(|a| a.name == agent_name) {
        return Err(LoreError::PermissionDenied.into());
    }

    let trimmed = form.command.trim();
    let (cmd, args) = match trimmed.split_once(char::is_whitespace) {
        Some((c, a)) => (c.to_lowercase(), a.trim().to_string()),
        None => (trimmed.to_lowercase(), String::new()),
    };

    let response_text = match cmd.as_str() {
        "/help" => {
            "USER COMMANDS\n\n  STATUS\n    /help -- show this message\n    /status -- show current config\n    /prompt -- show full agent prompt and context\n    /context -- show message count and summary\n    /report -- status of all your agents\n\n  CONTEXT\n    /pin <text> -- add to pinned context\n    /pins -- show pinned context\n    /unpin <id> -- remove a pin by id\n    /window <n> -- set conversation window size\n    /compact -- force context compaction\n    /clear -- clear messages, keep context\n\n  MODEL\n    /model <name> -- switch model (process agents)\n    /effort <level> -- low/medium/high/max/default\n\nAGENT COMMANDS\n\n    /stop -- cancel current request\n    /restart -- restart the agent\n    /rename <name> -- change agent display name\n    /profile <url> -- set agent profile picture\n    /btw <message> -- side question (separate process)\n    /hi -- check if agent is working\n\nManage mode can be configured in the manage panel (people icon).".to_string()
        }
        "/status" => {
            let conv = state.chat.load_conversation(owner, &agent_name)?;
            let status_str = match conv.agent_status {
                AgentChatStatus::Idle => "idle",
                AgentChatStatus::Thinking => "thinking",
                AgentChatStatus::Offline => "offline",
            };
            let agent_token = agents.iter().find(|a| a.name == agent_name);
            let is_api = agent_token.map(|a| a.endpoint_id.is_some()).unwrap_or(false);
            if is_api {
                let ep_id = agent_token.and_then(|a| a.endpoint_id.as_deref()).unwrap_or("unknown");
                let (ep_name, ep_kind, ep_model) = state.endpoint_store.get(ep_id)
                    .ok().flatten()
                    .map(|ep| (ep.name.clone(), format!("{:?}", ep.kind), ep.model.clone()))
                    .unwrap_or_else(|| (ep_id.to_string(), "unknown".into(), "unknown".into()));
                let effort_key = format!("endpoint:{ep_id}");
                let (_, effort) = state.chat.get_backend_prefs(owner, &effort_key).unwrap_or((None, None));
                let effort_line = if ep_kind.contains("Anthropic") {
                    format!("\nEffort: {}", effort.as_deref().unwrap_or("default"))
                } else {
                    String::new()
                };
                let manage_line = match &conv.manage_config {
                    Some(mc) if mc.enabled => format!("\nManage: ON (turn {})", mc.turn_counter),
                    Some(_) => "\nManage: off".to_string(),
                    None => String::new(),
                };
                format!(
                    "Agent: {}\nStatus: {}\nMode: API\nEndpoint: {}\nProvider: {}\nModel: {}{}{}\nExchanges: {}\nPins: {}\nWindow: {} exchanges",
                    agent_name, status_str, ep_name, ep_kind, ep_model, effort_line, manage_line,
                    agent_window_exchange_count(&conv), conv.pins.len(), conv.window_size
                )
            } else {
                let backend = agent_token.map(|a| a.backend.clone()).unwrap_or_default();
                let (model, effort) = state.chat.get_backend_prefs(owner, &backend.to_string()).unwrap_or((None, None));
                let manage_line = match &conv.manage_config {
                    Some(mc) if mc.enabled => format!("\nManage: ON (turn {})", mc.turn_counter),
                    Some(_) => "\nManage: off".to_string(),
                    None => String::new(),
                };
                format!(
                    "Agent: {}\nStatus: {}\nMode: process ({})\nModel: {}\nEffort: {}{}\nExchanges: {}\nPins: {}\nWindow: {} exchanges",
                    agent_name, status_str, backend,
                    model.as_deref().unwrap_or("default"),
                    effort.as_deref().unwrap_or("default"),
                    manage_line,
                    agent_window_exchange_count(&conv), conv.pins.len(), conv.window_size
                )
            }
        }
        "/context" => {
            let conv = state.chat.load_conversation(owner, &agent_name)?;
            let mut parts = Vec::new();
            parts.push(format!(
                "{} exchanges in window (max {}).",
                agent_window_exchange_count(&conv),
                conv.window_size
            ));
            let git_ctx = collect_git_context(conv.cwd.as_deref());
            if !git_ctx.is_empty() {
                parts.push(format!("\nGit:\n{git_ctx}"));
            }
            let activity = get_agent_recent_activity(&state, owner, &agent_name);
            if !activity.is_empty() {
                parts.push(format!("\n{activity}"));
            }
            if conv.summary.is_empty() {
                parts.push("No conversation summary yet.".to_string());
            } else {
                parts.push(format!("\nSummary:\n{}", conv.summary));
            }
            parts.join("\n")
        }
        "/prompt" => {
            let conv = state.chat.load_conversation(owner, &agent_name)?;
            let agent_token = agents.iter().find(|a| a.name == agent_name);
            let is_api = agent_token.map(|a| a.endpoint_id.is_some()).unwrap_or(false);
            let mut parts = Vec::new();

            if is_api {
                let dummy_agent = AuthenticatedAgent {
                    token: String::new(),
                    name: agent_name.clone(),
                    owner: Some(session.user.username.clone()),
                    owner_is_admin: session.user.is_admin,
                    grants: agent_token.map(|a| a.grants.clone()).unwrap_or_default(),
                    backend: AgentBackend::default(),
                    endpoint_id: agent_token.and_then(|a| a.endpoint_id.clone()),
                    machine_name: None,
                };
                let prompt = build_api_agent_system_prompt(&state, &dummy_agent, &conv);
                parts.push("== System Prompt ==".to_string());
                parts.push(prompt);
            } else {
                parts.push("== Agent Context (process mode) ==".to_string());
                let project_context = collect_project_context(&state, &agent_token.map(|a| a.grants.clone()).unwrap_or_default());
                if !project_context.is_empty() {
                    parts.push(format!("\n-- Project Context --\n{project_context}"));
                }
                if !conv.pinned_context.is_empty() {
                    parts.push(format!("\n-- Pinned Context --\n{}", conv.pinned_context));
                }
                let readable: Vec<String> = agent_token.map(|a| &a.grants).unwrap_or(&vec![]).iter()
                    .map(|g| {
                        let perm = if g.permission.allows_write() { "read-write" } else { "read" };
                        format!("- {} ({})", g.project.as_str(), perm)
                    })
                    .collect();
                if !readable.is_empty() {
                    parts.push(format!("\n-- Accessible Projects --\n{}", readable.join("\n")));
                }
            }

            let git_ctx = collect_git_context(conv.cwd.as_deref());
            if !git_ctx.is_empty() {
                parts.push(format!("\n== Git Repository ==\n{git_ctx}"));
            }
            let activity = get_agent_recent_activity(&state, owner, &agent_name);
            if !activity.is_empty() {
                parts.push(format!("\n== Recent Activity ==\n{activity}"));
            }

            parts.push(format!(
                "\n== Conversation ==\n{} exchanges in window (max {}).",
                agent_window_exchange_count(&conv),
                conv.window_size
            ));
            if !conv.summary.is_empty() {
                parts.push(format!("\n-- Tail Summary --\n{}", conv.summary));
            }
            parts.join("\n")
        }
        "/pin" => {
            if args.is_empty() {
                "Usage: /pin <text to pin>".to_string()
            } else {
                let pin_text = format!("IMPORTANT: {args}");
                let mut conv = state.chat.load_conversation(owner, &agent_name)?;
                let pin = PinnedChatItem {
                    id: conv.next_id,
                    text: pin_text.clone(),
                    timestamp: OffsetDateTime::now_utc(),
                };
                conv.next_id += 1;
                conv.pins.push(pin);
                if !conv.pinned_context.is_empty() {
                    conv.pinned_context.push('\n');
                }
                conv.pinned_context.push_str(&pin_text);
                state.chat.save_conversation(owner, &agent_name, &conv)?;
                format!("Pinned: {pin_text}")
            }
        }
        "/pins" => {
            let conv = state.chat.load_conversation(owner, &agent_name)?;
            if conv.pinned_context.is_empty() {
                "No pinned context.".to_string()
            } else {
                let mut lines = vec!["Pinned context:".to_string(), conv.pinned_context.clone()];
                if !conv.pins.is_empty() {
                    lines.push(String::new());
                    lines.push("Tracked pins:".to_string());
                    for p in &conv.pins {
                        lines.push(format!("  #{}: {}", p.id, p.text));
                    }
                    lines.push(String::new());
                    lines.push("Use /unpin <id> to remove.".to_string());
                }
                lines.join("\n")
            }
        }
        "/unpin" => {
            let id: u64 = match args.parse() {
                Ok(n) => n,
                Err(_) => return Ok(Json(json!({"response": "Usage: /unpin <id>"})).into_response()),
            };
            let mut conv = state.chat.load_conversation(owner, &agent_name)?;
            let idx = conv.pins.iter().position(|p| p.id == id);
            match idx {
                Some(i) => {
                    let removed = conv.pins.remove(i);
                    let preview: String = removed.text.chars().take(80).collect();
                    if let Some(pos) = conv.pinned_context.find(&removed.text) {
                        let end = pos + removed.text.len();
                        let end = if end < conv.pinned_context.len() && conv.pinned_context.as_bytes()[end] == b'\n' {
                            end + 1
                        } else {
                            end
                        };
                        let start = if pos > 0 && conv.pinned_context.as_bytes()[pos - 1] == b'\n' {
                            pos - 1
                        } else {
                            pos
                        };
                        conv.pinned_context = format!(
                            "{}{}",
                            &conv.pinned_context[..start],
                            &conv.pinned_context[end..]
                        ).trim().to_string();
                    }
                    state.chat.save_conversation(owner, &agent_name, &conv)?;
                    format!("Removed pin #{id}: {preview}")
                }
                None => format!("Pin #{id} not found. Use /pins to see current pins."),
            }
        }
        "/window" => {
            if args.is_empty() {
                let conv = state.chat.load_conversation(owner, &agent_name)?;
                format!(
                    "Window: {} exchanges\nAuto-compact at: {} exchanges (down to {})\nCurrent: {} exchanges in window\n\nUsage: /window <n> (e.g. /window 22)",
                    conv.window_size,
                    conv.window_size,
                    conv.window_size / 2,
                    agent_window_exchange_count(&conv)
                )
            } else {
                match args.parse::<usize>() {
                    Ok(n) if n >= 3 => {
                        state.chat.update_window_size(owner, &agent_name, n)?;
                        format!("Window set to {n} exchanges. Auto-compact at {n} exchanges.")
                    }
                    _ => "Window size must be a number >= 3.".to_string(),
                }
            }
        }
        "/model" => {
            let agent_token = agents.iter().find(|a| a.name == agent_name);
            let is_api = agent_token.map(|a| a.endpoint_id.is_some()).unwrap_or(false);
            if is_api {
                let ep_id = agent_token.and_then(|a| a.endpoint_id.as_deref()).unwrap_or("");
                let ep_model = state.endpoint_store.get(ep_id).ok().flatten()
                    .map(|ep| ep.model.clone()).unwrap_or_else(|| "unknown".into());
                format!("Model is set by endpoint config: {ep_model}\nChange it in the admin panel under Endpoints.")
            } else {
                let backend = agent_token.map(|a| a.backend.to_string()).unwrap_or_default();
                let (current_model, _) = state.chat.get_backend_prefs(owner, &backend).unwrap_or((None, None));
                if args.is_empty() {
                    let current = current_model.as_deref().unwrap_or("default");
                    let options = match backend.as_str() {
                        "gemini" => format!(
                            "Current model: {current}\n\nOptions:\n  /model gemini-2.5-pro\n  /model gemini-2.5-flash\n  /model gemini-3-pro-preview\n  /model default"
                        ),
                        "claude" => format!(
                            "Current model: {current}\n\nOptions:\n  /model opus (claude-opus-4-6)\n  /model sonnet (claude-sonnet-4-6)\n  /model haiku (claude-haiku-4-5)\n  /model <full-model-id>\n  /model default"
                        ),
                        _ => format!(
                            "Current model: {current}\n\nUsage: /model <model-name>\n  /model default"
                        ),
                    };
                    options
                } else {
                    let lower = args.to_lowercase();
                    let new_model = if lower == "default" || lower == "off" || lower == "none" {
                        None
                    } else {
                        Some(args.clone())
                    };
                    if current_model == new_model {
                        format!("Already using {} model.", new_model.as_deref().unwrap_or("default"))
                    } else {
                        state.chat.set_backend_model(owner, &backend, new_model.clone())?;
                        let label = new_model.as_deref().unwrap_or("default");
                        format!("Model set to {label} for {backend}. Next message will use it.")
                    }
                }
            }
        }
        "/effort" => {
            let agent_token = agents.iter().find(|a| a.name == agent_name);
            let is_api = agent_token.map(|a| a.endpoint_id.is_some()).unwrap_or(false);
            let is_anthropic = if is_api {
                let ep_id = agent_token.and_then(|a| a.endpoint_id.as_deref()).unwrap_or("");
                state.endpoint_store.get(ep_id).ok().flatten()
                    .map(|ep| matches!(ep.kind, EndpointKind::Anthropic))
                    .unwrap_or(false)
            } else {
                agent_token.map(|a| a.backend.to_string() == "claude").unwrap_or(false)
            };
            if !is_anthropic {
                "Effort is only supported for Anthropic/Claude.".to_string()
            } else {
                let pref_key = if is_api {
                    format!("endpoint:{}", agent_token.and_then(|a| a.endpoint_id.as_deref()).unwrap_or(""))
                } else {
                    agent_token.map(|a| a.backend.to_string()).unwrap_or_default()
                };
                let (_, current_effort) = state.chat.get_backend_prefs(owner, &pref_key).unwrap_or((None, None));
                if args.is_empty() {
                    let current = current_effort.as_deref().unwrap_or("default");
                    format!(
                        "Current effort: {current}\n\nOptions:\n  /effort low -- minimal thinking\n  /effort medium -- balanced\n  /effort high -- deeper reasoning\n  /effort max -- maximum thinking\n  /effort default -- reset to default"
                    )
                } else {
                    let lower = args.to_lowercase();
                    if lower == "default" || lower == "off" || lower == "none" {
                        if current_effort.is_none() {
                            "Already using default effort.".to_string()
                        } else {
                            state.chat.set_backend_effort(owner, &pref_key, None)?;
                            "Effort reset to default. Next message will use it.".to_string()
                        }
                    } else if ["low", "medium", "high", "max"].contains(&lower.as_str()) {
                        if current_effort.as_deref() == Some(&lower) {
                            format!("Already using {lower} effort.")
                        } else {
                            state.chat.set_backend_effort(owner, &pref_key, Some(lower.clone()))?;
                            format!("Effort set to {lower}. Next message will use it.")
                        }
                    } else {
                        "Invalid effort level. Options: low, medium, high, max, default".to_string()
                    }
                }
            }
        }
        "/clear" => {
            state.chat.clear_messages(owner, &agent_name)?;
            return Ok(Json(json!({"action": "clear"})).into_response());
        }
        "/compact" => {
            let is_api = agents.iter().find(|a| a.name == agent_name)
                .map(|a| a.endpoint_id.is_some()).unwrap_or(false);
            if is_api {
                let endpoint_id = agents.iter().find(|a| a.name == agent_name)
                    .and_then(|a| a.endpoint_id.clone());
                let state_clone = state.clone();
                let owner_str = owner.to_string();
                let agent_name_clone = agent_name.clone();
                tokio::spawn(async move {
                    run_api_compact(&state_clone, endpoint_id.as_deref(), &owner_str, &agent_name_clone).await;
                });
                "Compacting context...".to_string()
            } else {
                let _ = state.chat.append_message(
                    owner, &agent_name, ChatRole::User, "/compact".to_string(),
                )?;
                let notifier_key = format!("{owner}_{agent_name}");
                if let Some(notify) = state.chat_agent_notifiers.lock().unwrap().get(&notifier_key) {
                    notify.notify_one();
                }
                "Compacting context...".to_string()
            }
        }
        "/stop" => {
            request_chat_agent_stop(&state, owner, &agent_name);
            let _ = state.chat.update_auto_message(owner, &agent_name, None);
            let notifier_key = format!("{owner}_{agent_name}");
            if let Some(notify) = state.chat_agent_notifiers.lock().unwrap().get(&notifier_key) {
                notify.notify_one();
            }
            "Stop requested. Auto-repeat cleared.".to_string()
        }
        "/restart" => {
            let _ = state.chat.append_message(
                owner,
                &agent_name,
                ChatRole::User,
                "/restart".to_string(),
            )?;
            let notifier_key = format!("{owner}_{agent_name}");
            if let Some(notify) = state.chat_agent_notifiers.lock().unwrap().get(&notifier_key) {
                notify.notify_one();
            }
            "Restart requested.".to_string()
        }
        "/rename" => {
            if args.is_empty() {
                "Usage: /rename <new display name>".to_string()
            } else {
                match state.auth.update_agent_display_name(
                    &agent_name,
                    &session.user.username,
                    &args,
                ) {
                    Ok(()) => format!("Agent renamed to \"{}\".", args),
                    Err(e) => format!("Rename failed: {e}"),
                }
            }
        }
        "/profile" => {
            if args.is_empty() {
                let conv = state.chat.load_conversation(owner, &agent_name)?;
                match &conv.profile_url {
                    Some(url) => format!("Current profile: {url}\n\nUsage: /profile <image-url>\n  /profile clear -- remove profile picture"),
                    None => "No profile picture set.\n\nUsage: /profile <image-url>".to_string(),
                }
            } else if args.to_lowercase() == "clear" || args.to_lowercase() == "none" {
                state.chat.update_profile_url(owner, &agent_name, None)?;
                "Profile picture cleared.".to_string()
            } else {
                state.chat.update_profile_url(owner, &agent_name, Some(args.clone()))?;
                "Profile picture set.".to_string()
            }
        }
        "/btw" => {
            if args.is_empty() {
                "Usage: /btw <message> -- side question (runs separately, won't interrupt agent)".to_string()
            } else {
                let content = format!("[btw] {args}");
                let _ = state.chat.append_message(
                    owner, &agent_name, ChatRole::User, content,
                )?;
                let is_api = agents.iter().find(|a| a.name == agent_name)
                    .map(|a| a.endpoint_id.is_some()).unwrap_or(false);
                if is_api {
                    let token = agents.iter().find(|a| a.name == agent_name).unwrap();
                    let agent_auth = AuthenticatedAgent {
                        token: format!("btw-{}", agent_name),
                        name: agent_name.clone(),
                        owner: Some(session.user.username.clone()),
                        owner_is_admin: session.user.is_admin,
                        grants: token.grants.clone(),
                        backend: token.backend,
                        endpoint_id: token.endpoint_id.clone(),
                        machine_name: None,
                    };
                    let state_clone = state.clone();
                    let owner_str = owner.to_string();
                    let agent_name_clone = agent_name.clone();
                    let btw_msg = args.clone();
                    tokio::spawn(async move {
                        run_api_btw(state_clone, agent_auth, owner_str, agent_name_clone, btw_msg).await;
                    });
                    format!("[btw] {args}")
                } else {
                    let notifier_key = format!("{owner}_{agent_name}");
                    if let Some(notify) = state.chat_agent_notifiers.lock().unwrap().get(&notifier_key) {
                        notify.notify_one();
                    }
                    format!("Sent: [btw] {args}")
                }
            }
        }
        "/hi" => {
            let conv = state.chat.load_conversation(owner, &agent_name)?;
            let display = agents.iter().find(|a| a.name == agent_name)
                .and_then(|a| a.display_name.as_deref())
                .unwrap_or(&agent_name);
            match conv.agent_status {
                AgentChatStatus::Thinking => {
                    let mut parts = vec![format!("{display} is processing a request.")];
                    if let Some(ref last) = conv.last_seen {
                        let elapsed = (time::OffsetDateTime::now_utc() - *last).whole_seconds();
                        let ago = if elapsed < 60 {
                            format!("{elapsed}s ago")
                        } else if elapsed < 3600 {
                            format!("{}m {}s ago", elapsed / 60, elapsed % 60)
                        } else {
                            format!("{}h {}m ago", elapsed / 3600, (elapsed % 3600) / 60)
                        };
                        parts.push(format!("Last activity: {ago}"));
                    }
                    parts.join("\n")
                }
                AgentChatStatus::Idle => format!("{display} is idle."),
                AgentChatStatus::Offline => format!("{display} is offline."),
            }
        }
        "/report" => {
            let all_agents = state.auth.list_agent_tokens_for_user(&session.user.username)?;
            let mut lines = Vec::new();
            for a in &all_agents {
                let conv = state.chat.load_conversation(owner, &a.name)?;
                let status_str = match conv.agent_status {
                    AgentChatStatus::Idle => "idle",
                    AgentChatStatus::Thinking => "thinking",
                    AgentChatStatus::Offline => "offline",
                };
                let display = a.display_name.as_deref().unwrap_or(&a.name);
                let exchange_count = agent_window_exchange_count(&conv);
                let auto_str = match &conv.auto_message {
                    Some(m) => format!(" auto=\"{}\"", m.chars().take(30).collect::<String>()),
                    None => String::new(),
                };
                let last = conv.last_seen.map(|t| format_chat_time(t)).unwrap_or_else(|| "never".to_string());
                lines.push(format!("{display}: {status_str}, {exchange_count} exchanges, seen {last}{auto_str}"));
            }
            if lines.is_empty() {
                "No agents found.".to_string()
            } else {
                lines.join("\n")
            }
        }
        _ => format!("Unknown command: {}. Type /help for available commands.", cmd),
    };

    state.chat_audit.log(&agent_name, owner, "command", trimmed);

    Ok(Json(json!({"response": response_text})).into_response())
}

fn push_chat_event(state: &AppState, owner: &str, event: ChatEvent) {
    if let Ok(senders) = state.chat_senders.lock() {
        if let Some(sender) = senders.get(owner) {
            let _ = sender.send(event);
        }
    }
}

fn format_chat_time(ts: OffsetDateTime) -> String {
    let now = OffsetDateTime::now_utc();
    let diff = now - ts;
    if diff.whole_minutes() < 1 {
        "just now".to_string()
    } else if diff.whole_minutes() < 60 {
        format!("{}m ago", diff.whole_minutes())
    } else if diff.whole_hours() < 24 {
        format!("{}h ago", diff.whole_hours())
    } else {
        format!("{}d ago", diff.whole_days())
    }
}

// --- Machine registration & agent provisioning ---

async fn register_machine(
    State(state): State<AppState>,
    Json(req): Json<RegisterMachineRequest>,
) -> Result<Json<Value>, ApiError> {
    let (token, machine) =
        state
            .auth
            .register_machine(&req.username, &req.password, &req.machine_name)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: req.username.clone(),
        },
        "register machine",
        Some(machine.name.clone()),
        None,
    )?;
    Ok(Json(serde_json::json!({
        "token": token,
        "machine_name": machine.name,
    })))
}

async fn provision_agent_with_body(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProvisionAgentRequest>,
) -> Result<Json<Value>, ApiError> {
    let machine_token = headers
        .get("x-lore-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let machine = state.auth.authenticate_machine_token(machine_token)?;

    // Track CLI version on the machine
    if let Some(version) = headers.get("x-lore-version").and_then(|v| v.to_str().ok()) {
        let _ = state.auth.update_machine_version(
            &machine.machine_name,
            &machine.user.username,
            version,
        );
    }

    let grants = match req.grants {
        Some(grants) => {
            let grants = grants
                .into_iter()
                .map(|grant| {
                    Ok(ProjectGrant {
                        project: ProjectName::new(grant.project)?,
                        permission: grant.permission,
                    })
                })
                .collect::<Result<Vec<_>, LoreError>>()?;
            validate_user_grants(&state, &machine.user, &grants)?;
            grants
        }
        None if req.inherit_owner_grants => build_user_all_grants(&state, &machine.user)?,
        None => Vec::new(),
    };

    let created = state.auth.provision_agent(
        &machine.user.username,
        &req.name,
        grants,
        req.backend.as_deref().and_then(|b| b.parse().ok()),
        Some(&machine.machine_name),
    )?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: machine.user.username.as_str().to_string(),
        },
        "provision agent",
        Some(created.stored.name.clone()),
        None,
    )?;
    Ok(Json(serde_json::json!({
        "token": created.token,
        "name": created.stored.name,
        "display_name": created.stored.display_name,
    })))
}

fn build_user_all_grants(
    state: &AppState,
    user: &AuthenticatedUser,
) -> std::result::Result<Vec<ProjectGrant>, LoreError> {
    let projects = state.store.list_projects()?;
    if user.is_admin {
        // Admin gets ReadWrite to all projects
        return Ok(projects
            .into_iter()
            .map(|project| ProjectGrant {
                project,
                permission: ProjectPermission::ReadWrite,
            })
            .collect());
    }
    // Regular user: collect grants from all their roles
    let mut grants_map = std::collections::BTreeMap::new();
    for role in &user.roles {
        for grant in &role.grants {
            let entry = grants_map
                .entry(grant.project.clone())
                .or_insert(grant.permission);
            if grant.permission.allows_write() {
                *entry = ProjectPermission::ReadWrite;
            }
        }
    }
    Ok(grants_map
        .into_iter()
        .map(|(project, permission)| ProjectGrant {
            project,
            permission,
        })
        .collect())
}

async fn revoke_machine_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.auth.revoke_machine(&name, &session.user.username)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "revoke machine",
        Some(name),
        None,
    )?;
    Ok(Redirect::to("/ui/agents?flash=Machine%20revoked").into_response())
}

async fn update_machine_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Response> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let machine_key = format!("{}_{}", session.user.username, name);
    set_machine_pending_update(&state, &machine_key);
    notify_machine_poll(&state, &machine_key);
    Ok(Redirect::to(
        "/ui/agents?flash=Update%20queued%20—%20machine%20will%20update%20on%20next%20poll",
    )
    .into_response())
}

async fn update_machine_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Json<Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let machine_key = format!("{}_{}", session.user.username, name);
    set_machine_pending_update(&state, &machine_key);
    notify_machine_poll(&state, &machine_key);
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn machine_status_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Json<Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let server_version = env!("CARGO_PKG_VERSION");
    if let Some(m) = state.auth.get_machine(&name, &session.user.username)? {
        let version = m.cli_version.as_deref().unwrap_or("unknown");
        let up_to_date = version.trim_start_matches('v') == server_version;
        let machine_key = format!("{}_{}", session.user.username, name);
        let pending = machine_update_requested(&state, &machine_key, m.cli_version.as_deref())?;
        Ok(Json(serde_json::json!({
            "version": version,
            "pending_update": pending,
            "up_to_date": up_to_date
        })))
    } else {
        Ok(Json(serde_json::json!({ "error": "machine not found" })))
    }
}

// --- Machine service poll/command infrastructure ---

#[derive(Deserialize, Default)]
struct MachinePollBody {
    #[serde(default)]
    agent_statuses: Option<Vec<Value>>,
}

async fn machine_service_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<MachinePollBody>>,
) -> Result<Json<Value>, ApiError> {
    let machine_token = headers
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let machine = state.auth.authenticate_machine_token(machine_token)?;
    let machine_key = format!("{}_{}", machine.user.username, machine.machine_name);

    // Report CLI version
    if let Some(version) = headers.get("x-lore-version").and_then(|v| v.to_str().ok()) {
        let _ = state.auth.update_machine_version(
            &machine.machine_name,
            &machine.user.username,
            version,
        );
    }

    // Store agent process statuses reported by the service
    if let Some(Json(ref poll_body)) = body {
        if let Some(ref statuses) = poll_body.agent_statuses {
            let mut agent_statuses = state.machine_agent_statuses.lock().unwrap();
            agent_statuses.insert(machine_key.clone(), statuses.clone());
        }
    }

    // Check if machine should self-update (transient, auto-expires after 3 min)
    let server_version = env!("CARGO_PKG_VERSION");
    let reported_version = headers.get("x-lore-version").and_then(|v| v.to_str().ok());
    let poll_key = format!("machine:{machine_key}");
    let update_to = if should_emit_machine_update_signal(
        &state,
        &poll_key,
        machine_update_requested(&state, &machine_key, reported_version)?,
    ) {
        Some(server_version.to_string())
    } else {
        None
    };
    let update_config = if update_to.is_some() {
        state.auto_update_config.load().ok()
    } else {
        None
    };

    let build_response = |commands: Vec<MachineCommand>| -> Json<Value> {
        let mut resp = json!({ "commands": commands });
        if let Some(ref ver) = update_to {
            resp["update_to"] = json!(ver);
            if let Some(ref config) = update_config {
                resp["update_repo"] = json!(config.github_repo);
                resp["update_stream"] = json!(config.release_stream.as_str());
            }
        }
        Json(resp)
    };

    // Check for pending commands
    {
        let mut cmds = state.machine_commands.lock().unwrap();
        if let Some(pending) = cmds.get_mut(&machine_key) {
            if !pending.is_empty() {
                let batch: Vec<MachineCommand> = pending.drain(..).collect();
                return Ok(build_response(batch));
            }
        }
    }

    // No commands — long-poll up to 10s.
    // The client re-polls immediately when a response took >5s, so the server
    // almost always has an open connection ready to push commands to instantly.
    let notify = {
        let mut notifiers = state.machine_poll_notifiers.lock().unwrap();
        notifiers
            .entry(machine_key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Notify::new()))
            .clone()
    };

    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), notify.notified()).await;

    // Re-check after waking
    let mut cmds = state.machine_commands.lock().unwrap();
    if let Some(pending) = cmds.get_mut(&machine_key) {
        if !pending.is_empty() {
            let batch: Vec<MachineCommand> = pending.drain(..).collect();
            return Ok(build_response(batch));
        }
    }

    Ok(build_response(vec![]))
}

async fn machine_service_ready(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let machine_token = headers
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let machine = state.auth.authenticate_machine_token(machine_token)?;
    let machine_key = format!("{}_{}", machine.user.username, machine.machine_name);
    let reported_version = headers.get("x-lore-version").and_then(|v| v.to_str().ok());

    if let Some(version) = reported_version {
        let _ = state.auth.update_machine_version(
            &machine.machine_name,
            &machine.user.username,
            version,
        );
    }

    let update_requested = machine_update_requested(&state, &machine_key, reported_version)?;
    Ok(Json(json!({
        "ok": true,
        "server_version": env!("CARGO_PKG_VERSION"),
        "update_requested": update_requested,
    })))
}

#[derive(Deserialize)]
struct MachineCommandResultBody {
    data: Value,
}

async fn machine_command_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<String>,
    Json(body): Json<MachineCommandResultBody>,
) -> Result<Json<Value>, ApiError> {
    let machine_token = headers
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let _machine = state.auth.authenticate_machine_token(machine_token)?;

    // Store result and notify waiting handler
    {
        let mut results = state.machine_command_results.lock().unwrap();
        results.insert(command_id.clone(), body.data);
    }
    {
        let notifiers = state.machine_result_notifiers.lock().unwrap();
        if let Some(notify) = notifiers.get(&command_id) {
            notify.notify_one();
        }
    }

    Ok(Json(json!({ "ok": true })))
}

/// Queue a command for a machine and wait for the result (long-poll).
async fn queue_machine_command_and_wait(
    state: &AppState,
    machine_key: &str,
    command_type: &str,
    params: Value,
) -> std::result::Result<Value, LoreError> {
    let command_id = Uuid::new_v4().to_string();
    let cmd = MachineCommand {
        id: command_id.clone(),
        command_type: command_type.to_string(),
        params,
    };

    // Set up the result notifier before queuing (avoid race)
    let notify = Arc::new(tokio::sync::Notify::new());
    {
        let mut notifiers = state.machine_result_notifiers.lock().unwrap();
        notifiers.insert(command_id.clone(), notify.clone());
    }

    // Queue the command
    {
        let mut cmds = state.machine_commands.lock().unwrap();
        cmds.entry(machine_key.to_string()).or_default().push(cmd);
    }

    // Wake the machine's poll
    notify_machine_poll(state, machine_key);

    // Wait for result
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(MACHINE_COMMAND_TIMEOUT_SECS),
        notify.notified(),
    )
    .await;

    // Clean up notifier
    {
        let mut notifiers = state.machine_result_notifiers.lock().unwrap();
        notifiers.remove(&command_id);
    }

    if result.is_err() {
        return Err(LoreError::Validation(
            "machine did not respond in time — is the Lore service running?".into(),
        ));
    }

    // Retrieve and remove the result
    let data = {
        let mut results = state.machine_command_results.lock().unwrap();
        results.remove(&command_id)
    };

    data.ok_or_else(|| LoreError::Validation("no result from machine".into()))
}

const MACHINE_UPDATE_TIMEOUT: Duration = Duration::from_secs(180);

fn machine_auto_update_rollout_active_for_current_version(
    state: &AppState,
) -> Result<bool, LoreError> {
    let config = state.auto_update_config.load()?;
    Ok(config.auto_update_machines
        && config.last_machine_rollout_version.as_deref() == Some(env!("CARGO_PKG_VERSION")))
}

fn machine_update_requested(
    state: &AppState,
    machine_key: &str,
    reported_version: Option<&str>,
) -> Result<bool, LoreError> {
    let server_version = env!("CARGO_PKG_VERSION");
    if reported_version
        .map(|v| v.trim_start_matches('v') == server_version)
        .unwrap_or(false)
    {
        clear_machine_pending_update(state, machine_key);
        return Ok(false);
    }
    if is_machine_pending_update(state, machine_key) {
        return Ok(true);
    }
    machine_auto_update_rollout_active_for_current_version(state)
}

fn should_emit_machine_update_signal(
    state: &AppState,
    poll_key: &str,
    update_requested: bool,
) -> bool {
    let mut map = state.machine_update_signal_state.lock().unwrap();
    if !update_requested {
        map.remove(poll_key);
        return false;
    }
    let emit = map.get(poll_key).copied().unwrap_or(true);
    map.insert(poll_key.to_string(), !emit);
    emit
}

fn maybe_mark_machine_auto_update_rollout(state: &AppState) -> Result<(), LoreError> {
    let config = state.auto_update_config.load()?;
    if !config.auto_update_machines {
        return Ok(());
    }
    let current_version = env!("CARGO_PKG_VERSION");
    if config.last_machine_rollout_version.as_deref() == Some(current_version) {
        return Ok(());
    }
    let _ = state
        .auto_update_config
        .set_last_machine_rollout_version(Some(current_version.to_string()))?;
    Ok(())
}

fn is_machine_pending_update(state: &AppState, machine_key: &str) -> bool {
    let mut map = state.machine_update_timestamps.lock().unwrap();
    if let Some(started) = map.get(machine_key) {
        if started.elapsed() < MACHINE_UPDATE_TIMEOUT {
            return true;
        }
        map.remove(machine_key);
    }
    false
}

fn set_machine_pending_update(state: &AppState, machine_key: &str) {
    state
        .machine_update_timestamps
        .lock()
        .unwrap()
        .insert(machine_key.to_string(), Instant::now());
}

fn clear_machine_pending_update(state: &AppState, machine_key: &str) {
    state
        .machine_update_timestamps
        .lock()
        .unwrap()
        .remove(machine_key);
}

fn notify_machine_poll(state: &AppState, machine_key: &str) {
    let notifiers = state.machine_poll_notifiers.lock().unwrap();
    if let Some(notify) = notifiers.get(machine_key) {
        notify.notify_one();
    }
}

fn notify_all_machine_polls(state: &AppState) {
    let notifiers = state.machine_poll_notifiers.lock().unwrap();
    for notify in notifiers.values() {
        notify.notify_one();
    }
}

async fn machine_binary_download_for_target(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(target): Path<String>,
) -> Result<Response, ApiError> {
    machine_binary_download_inner(&state, &headers, Some(target.as_str())).await
}

async fn machine_binary_download_inner(
    state: &AppState,
    headers: &HeaderMap,
    target: Option<&str>,
) -> Result<Response, ApiError> {
    let machine_token = headers
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state.auth.authenticate_machine_token(machine_token)?;

    let binary_path = match machine_binary_path(state, target) {
        Some(path) => path,
        None => return Ok(axum::http::StatusCode::NOT_FOUND.into_response()),
    };
    if !binary_path.exists() {
        return Ok(axum::http::StatusCode::NOT_FOUND.into_response());
    }
    let bytes = tokio::fs::read(&binary_path)
        .await
        .map_err(|e| ApiError(LoreError::Io(e)))?;
    let sha256 = hex_sha256(&bytes);
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-lore-binary-sha256"),
        HeaderValue::from_str(&sha256)
            .map_err(|e| ApiError(LoreError::Validation(e.to_string())))?,
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-lore-binary-version"),
        HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
    );
    Ok(response)
}

fn machine_binary_path(state: &AppState, target: Option<&str>) -> Option<std::path::PathBuf> {
    let updates_dir = state.store.root().join("updates");
    match target {
        Some(target) if SERVER_RELEASE_CLI_TARGETS.contains(&target) => {
            Some(updates_dir.join(format!("lore-{target}")))
        }
        _ => None,
    }
}

#[derive(Deserialize)]
struct MachineListDirRequest {
    csrf_token: String,
    path: Option<String>,
}

async fn machine_list_dir_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(machine_name): Path<String>,
    Json(req): Json<MachineListDirRequest>,
) -> UiResult<Json<Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &req.csrf_token)?;
    let machine_key = format!("{}_{}", session.user.username, machine_name);

    let params = json!({ "path": req.path });
    match queue_machine_command_and_wait(&state, &machine_key, "list_dir", params).await {
        Ok(data) => Ok(Json(data)),
        Err(e) => Ok(Json(json!({ "error": e.to_string() }))),
    }
}

#[derive(Deserialize)]
struct MachineCreateAgentRequest {
    csrf_token: String,
    agent_name: String,
    folder: String,
    backend: Option<String>,
    #[serde(default)]
    grants: String,
}

#[derive(Deserialize)]
struct MachineMkdirRequest {
    csrf_token: String,
    path: String,
    name: String,
}

async fn machine_create_agent_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(machine_name): Path<String>,
    Json(req): Json<MachineCreateAgentRequest>,
) -> UiResult<Json<Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &req.csrf_token)?;
    let machine_key = format!("{}_{}", session.user.username, machine_name);
    let grants = parse_agent_grants(&req.grants)?;
    validate_user_grants(&state, &session.user, &grants)?;

    let backend = req.backend.as_deref().unwrap_or("claude");
    let params = json!({
        "agent_name": req.agent_name,
        "folder": req.folder,
        "backend": backend,
        "grants": grants,
    });
    match queue_machine_command_and_wait(&state, &machine_key, "create_agent", params).await {
        Ok(data) => Ok(Json(data)),
        Err(e) => Ok(Json(json!({ "error": e.to_string() }))),
    }
}

async fn machine_mkdir_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(machine_name): Path<String>,
    Json(req): Json<MachineMkdirRequest>,
) -> UiResult<Json<Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &req.csrf_token)?;
    let machine_key = format!("{}_{}", session.user.username, machine_name);

    let params = json!({
        "path": req.path,
        "name": req.name,
    });
    match queue_machine_command_and_wait(&state, &machine_key, "mkdir", params).await {
        Ok(data) => Ok(Json(data)),
        Err(e) => Ok(Json(json!({ "error": e.to_string() }))),
    }
}

#[derive(Deserialize)]
struct MachineAgentCommandRequest {
    csrf_token: String,
    agent_name: String,
}

async fn machine_stop_agent_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(machine_name): Path<String>,
    Json(req): Json<MachineAgentCommandRequest>,
) -> UiResult<Json<Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &req.csrf_token)?;
    let machine_key = format!("{}_{}", session.user.username, machine_name);

    let params = json!({ "agent_name": req.agent_name });
    match queue_machine_command_and_wait(&state, &machine_key, "stop_agent", params).await {
        Ok(data) => Ok(Json(data)),
        Err(e) => Ok(Json(json!({ "error": e.to_string() }))),
    }
}

async fn machine_restart_agent_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(machine_name): Path<String>,
    Json(req): Json<MachineAgentCommandRequest>,
) -> UiResult<Json<Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &req.csrf_token)?;
    let machine_key = format!("{}_{}", session.user.username, machine_name);

    let params = json!({ "agent_name": req.agent_name });
    match queue_machine_command_and_wait(&state, &machine_key, "restart_agent", params).await {
        Ok(data) => Ok(Json(data)),
        Err(e) => Ok(Json(json!({ "error": e.to_string() }))),
    }
}

async fn machine_remove_agent_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(machine_name): Path<String>,
    Json(req): Json<MachineAgentCommandRequest>,
) -> UiResult<Json<Value>> {
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &req.csrf_token)?;
    let machine_key = format!("{}_{}", session.user.username, machine_name);

    let params = json!({ "agent_name": req.agent_name });
    match queue_machine_command_and_wait(&state, &machine_key, "remove_agent", params).await {
        Ok(data) => Ok(Json(data)),
        Err(e) => Ok(Json(json!({ "error": e.to_string() }))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AGENT_AUTH_RATE_LIMIT_ATTEMPTS, API_KEY_HEADER, GLOBAL_LIBRARIAN_RATE_LIMIT,
        LOGIN_RATE_LIMIT_ATTEMPTS, MCP_PROTOCOL_VERSION, build_app, build_app_with_librarian,
        build_chat_agents, constant_time_eq, enforce_agent_auth_rate_limit,
        enforce_global_librarian_rate_limit, parse_agent_grants, parse_role_grants,
        record_failed_agent_auth, session_cookie_value,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};
    use tower::util::ServiceExt;

    use super::{finalize_pending_stream_tool_call, merge_pending_stream_tool_call};
    use crate::auth::{AgentChatStatus, ChatConversation, ChatMessage, ChatRole, ManageConfig};
    use crate::librarian::{
        AnswerLibrarianClient, Endpoint, LibrarianAnswer, LibrarianConfig, LibrarianRequest,
        ProjectLibrarianOperation, ProjectLibrarianPlan, ProjectLibrarianRequest,
        ProviderCheckResult, RATE_LIMIT_REQUESTS,
    };
    use crate::manager::{ManagerPromptConfig, ManagerPromptOverride};
    use crate::store::FileBlockStore;
    use crate::updater::{AutoUpdateConfigStore, DEFAULT_UPDATE_REPO, ReleaseStream, hex_sha256};
    use crate::{
        AgentBackend, BlockType, LocalAuthStore, NewAgentToken, ProjectGrant, ProjectName,
        ProjectPermission, UserName,
    };

    #[test]
    fn parse_role_grants_skips_no_access_rows() {
        let grants = parse_role_grants(
            "alpha.docs:read_write\nbeta.docs:no access\ngamma.docs:none\ndelta.docs:no_access\n",
        )
        .unwrap();

        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].project.as_str(), "alpha.docs");
        assert_eq!(grants[0].permission, ProjectPermission::ReadWrite);
    }

    #[test]
    fn parse_role_grants_accepts_ui_permission_labels() {
        let grants = parse_role_grants(
            "alpha.docs:Read\nbeta.docs:read only\ngamma.docs:Read/Write\ndelta.docs:read-write\nepsilon.docs:No Access\n",
        )
        .unwrap();

        assert_eq!(grants.len(), 4);
        assert_eq!(grants[0].permission, ProjectPermission::Read);
        assert_eq!(grants[1].permission, ProjectPermission::Read);
        assert_eq!(grants[2].permission, ProjectPermission::ReadWrite);
        assert_eq!(grants[3].permission, ProjectPermission::ReadWrite);
    }

    #[test]
    fn parse_agent_grants_allows_empty_access() {
        let grants = parse_agent_grants("").unwrap();
        assert!(grants.is_empty());
    }

    #[test]
    fn chat_agents_sort_by_full_last_user_timestamp() {
        let dir = tempdir().unwrap();
        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        let owner = UserName::new("alice").unwrap();
        state
            .auth
            .bootstrap_admin(owner.clone(), "correct-horse-battery".into())
            .unwrap();

        for display_name in ["alpha", "bravo"] {
            state
                .auth
                .create_agent_token(NewAgentToken {
                    display_name: display_name.to_string(),
                    owner: owner.clone(),
                    grants: vec![ProjectGrant {
                        project: ProjectName::new("alpha.docs").unwrap(),
                        permission: ProjectPermission::ReadWrite,
                    }],
                    backend: AgentBackend::Claude,
                    endpoint_id: None,
                })
                .unwrap();
        }

        let base = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut alpha_conv = ChatConversation::default();
        alpha_conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "first".into(),
            timestamp: base + Duration::milliseconds(100),
            client_message_id: None,
            excluded_from_context: false,
        });
        alpha_conv.next_id = 2;
        state
            .chat
            .save_conversation(owner.as_str(), "alpha", &alpha_conv)
            .unwrap();

        let mut bravo_conv = ChatConversation::default();
        bravo_conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "second".into(),
            timestamp: base + Duration::milliseconds(900),
            client_message_id: None,
            excluded_from_context: false,
        });
        bravo_conv.next_id = 2;
        state
            .chat
            .save_conversation(owner.as_str(), "bravo", &bravo_conv)
            .unwrap();

        let agents = build_chat_agents(&state, &owner).unwrap();
        let ordered_names: Vec<&str> = agents.iter().map(|agent| agent.name.as_str()).collect();
        assert_eq!(ordered_names, vec!["bravo", "alpha"]);
    }

    #[test]
    fn chat_agents_ignore_assistant_timestamps_for_order_and_sidebar_time() {
        let dir = tempdir().unwrap();
        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        let owner = UserName::new("alice").unwrap();
        state
            .auth
            .bootstrap_admin(owner.clone(), "correct-horse-battery".into())
            .unwrap();

        for display_name in ["alpha", "bravo"] {
            state
                .auth
                .create_agent_token(NewAgentToken {
                    display_name: display_name.to_string(),
                    owner: owner.clone(),
                    grants: vec![ProjectGrant {
                        project: ProjectName::new("alpha.docs").unwrap(),
                        permission: ProjectPermission::ReadWrite,
                    }],
                    backend: AgentBackend::Claude,
                    endpoint_id: None,
                })
                .unwrap();
        }

        let base = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let alpha_user_at = base + Duration::minutes(2);
        let bravo_user_at = base + Duration::minutes(3);

        let mut alpha_conv = ChatConversation::default();
        alpha_conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "alpha user".into(),
            timestamp: alpha_user_at,
            client_message_id: None,
            excluded_from_context: false,
        });
        alpha_conv.messages.push(ChatMessage {
            id: 2,
            role: ChatRole::Assistant,
            content: "alpha assistant".into(),
            timestamp: base + Duration::minutes(10),
            client_message_id: None,
            excluded_from_context: false,
        });
        alpha_conv.next_id = 3;
        state
            .chat
            .save_conversation(owner.as_str(), "alpha", &alpha_conv)
            .unwrap();

        let mut bravo_conv = ChatConversation::default();
        bravo_conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "bravo user".into(),
            timestamp: bravo_user_at,
            client_message_id: None,
            excluded_from_context: false,
        });
        bravo_conv.messages.push(ChatMessage {
            id: 2,
            role: ChatRole::Assistant,
            content: "bravo assistant".into(),
            timestamp: base + Duration::minutes(4),
            client_message_id: None,
            excluded_from_context: false,
        });
        bravo_conv.next_id = 3;
        state
            .chat
            .save_conversation(owner.as_str(), "bravo", &bravo_conv)
            .unwrap();

        let agents = build_chat_agents(&state, &owner).unwrap();
        let ordered_names: Vec<&str> = agents.iter().map(|agent| agent.name.as_str()).collect();
        let expected_bravo_time = super::format_chat_time(bravo_user_at);
        let expected_alpha_time = super::format_chat_time(alpha_user_at);
        assert_eq!(ordered_names, vec!["bravo", "alpha"]);
        assert_eq!(
            agents[0].last_message_time.as_deref(),
            Some(expected_bravo_time.as_str())
        );
        assert_eq!(
            agents[1].last_message_time.as_deref(),
            Some(expected_alpha_time.as_str())
        );
    }

    #[tokio::test]
    async fn chat_panel_includes_selected_agent_status() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, _) = bootstrap_admin_session(&app, dir.path()).await;
        let _agent_token =
            issue_agent_token(&app, dir.path(), "agent-main", ProjectPermission::ReadWrite).await;

        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        state
            .chat
            .append_message(
                "admin",
                "agent-main",
                ChatRole::Assistant,
                "hello from agent".into(),
            )
            .unwrap();
        state
            .chat
            .update_agent_status("admin", "agent-main", AgentChatStatus::Idle)
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .uri("/ui/chat/panel?agent=agent-main")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["selected_agent"], "agent-main");
        assert_eq!(json["agent_status"], "idle");
        assert_eq!(json["messages"][0]["content"], "hello from agent");
        let agent_list_html = json["agent_list_html"].as_str().unwrap();
        assert!(agent_list_html.contains("agent-main"));
        assert!(agent_list_html.contains("hello from agent"));
        assert!(agent_list_html.contains("chat-status-running"));
    }

    #[tokio::test]
    async fn chat_send_returns_persisted_user_message() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let _agent_token =
            issue_agent_token(&app, dir.path(), "agent-main", ProjectPermission::ReadWrite).await;

        let request = Request::builder()
            .method("POST")
            .uri("/ui/chat/agent-main/send")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={}&message={}",
                urlencoding::encode(&csrf_token),
                urlencoding::encode("hello from user")
            )))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["message"]["role"], "user");
        assert_eq!(json["message"]["content"], "hello from user");
        assert!(json["message"]["id"].as_u64().unwrap_or(0) > 0);

        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        let conv = state.chat.load_conversation("admin", "agent-main").unwrap();
        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].role, ChatRole::User);
        assert_eq!(conv.messages[0].content, "hello from user");
    }

    #[tokio::test]
    async fn chat_update_message_toggles_message_context_exclusion() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let _agent_token =
            issue_agent_token(&app, dir.path(), "agent-main", ProjectPermission::ReadWrite).await;

        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        let base = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let conv = ChatConversation {
            messages: vec![
                ChatMessage {
                    id: 1,
                    role: ChatRole::User,
                    content: "remove me".into(),
                    timestamp: base,
                    client_message_id: None,
                    excluded_from_context: false,
                },
                ChatMessage {
                    id: 2,
                    role: ChatRole::Assistant,
                    content: "keep me".into(),
                    timestamp: base + Duration::seconds(1),
                    client_message_id: None,
                    excluded_from_context: false,
                },
            ],
            summary: "old summary".into(),
            summary_until_id: 2,
            next_id: 3,
            ..ChatConversation::default()
        };
        state
            .chat
            .save_conversation("admin", "agent-main", &conv)
            .unwrap();

        let exclude_request = Request::builder()
            .method("POST")
            .uri("/ui/chat/agent-main/message")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={}&message_id={}&excluded=true",
                urlencoding::encode(&csrf_token),
                1
            )))
            .unwrap();
        let exclude_response = app.clone().oneshot(exclude_request).await.unwrap();
        assert_eq!(exclude_response.status(), StatusCode::OK);
        let exclude_json: Value = serde_json::from_slice(
            &axum::body::to_bytes(exclude_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(exclude_json["ok"], true);
        assert_eq!(exclude_json["message"]["id"], 1);
        assert_eq!(exclude_json["message"]["excluded_from_context"], true);

        let saved = state.chat.load_conversation("admin", "agent-main").unwrap();
        assert_eq!(saved.summary, "");
        assert_eq!(saved.summary_until_id, 0);
        assert_eq!(saved.messages.len(), 2);
        assert!(saved.messages[0].excluded_from_context);
        assert_eq!(saved.messages[1].content, "keep me");

        let include_request = Request::builder()
            .method("POST")
            .uri("/ui/chat/agent-main/message")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={}&message_id={}&excluded=false",
                urlencoding::encode(&csrf_token),
                1
            )))
            .unwrap();
        let include_response = app.clone().oneshot(include_request).await.unwrap();
        assert_eq!(include_response.status(), StatusCode::OK);
        let include_json: Value = serde_json::from_slice(
            &axum::body::to_bytes(include_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(include_json["ok"], true);
        assert_eq!(include_json["message"]["excluded_from_context"], false);

        let saved = state.chat.load_conversation("admin", "agent-main").unwrap();
        assert!(!saved.messages[0].excluded_from_context);
    }

    #[tokio::test]
    async fn chat_stop_command_is_not_persisted_as_chat_message() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let _agent_token =
            issue_agent_token(&app, dir.path(), "agent-main", ProjectPermission::ReadWrite).await;

        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        state
            .chat
            .update_auto_message("admin", "agent-main", Some("repeat this".into()))
            .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/ui/chat/agent-main/command")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={}&command={}",
                urlencoding::encode(&csrf_token),
                urlencoding::encode("/stop")
            )))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["response"], "Stop requested. Auto-repeat cleared.");

        let conv = state.chat.load_conversation("admin", "agent-main").unwrap();
        assert!(conv.messages.is_empty());
        assert!(conv.auto_message.is_none());
    }

    #[tokio::test]
    async fn chat_send_retries_same_client_message_id_without_duplicates() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let _agent_token =
            issue_agent_token(&app, dir.path(), "agent-main", ProjectPermission::ReadWrite).await;
        let client_message_id = "retry_send_001";
        let body = format!(
            "csrf_token={}&message={}&client_message_id={}",
            urlencoding::encode(&csrf_token),
            urlencoding::encode("hello from user"),
            urlencoding::encode(client_message_id),
        );

        let request = || {
            Request::builder()
                .method("POST")
                .uri("/ui/chat/agent-main/send")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", &session_cookie)
                .body(Body::from(body.clone()))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_json: Value = serde_json::from_slice(
            &axum::body::to_bytes(first.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first_json["inserted"], true);

        let retry = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        let retry_json: Value = serde_json::from_slice(
            &axum::body::to_bytes(retry.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(retry_json["inserted"], false);
        assert_eq!(retry_json["message"]["id"], first_json["message"]["id"]);

        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        let conv = state.chat.load_conversation("admin", "agent-main").unwrap();
        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].content, "hello from user");
        assert_eq!(
            conv.messages[0].client_message_id.as_deref(),
            Some(client_message_id)
        );
    }

    #[tokio::test]
    async fn chat_poll_preserves_thinking_status() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token =
            issue_agent_token(&app, dir.path(), "agent-main", ProjectPermission::ReadWrite).await;

        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        state
            .chat
            .update_agent_status("admin", "agent-main", AgentChatStatus::Thinking)
            .unwrap();
        state
            .chat
            .append_message("admin", "agent-main", ChatRole::User, "follow-up".into())
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .uri("/v1/chat/poll")
            .header(API_KEY_HEADER, &agent_token)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let conv = state.chat.load_conversation("admin", "agent-main").unwrap();
        assert_eq!(conv.agent_status, AgentChatStatus::Thinking);
    }

    #[derive(Clone)]
    struct RecordingLibrarianClient {
        answer: String,
        operations: Vec<ProjectLibrarianOperation>,
        requests: Arc<Mutex<Vec<LibrarianRequest>>>,
    }

    impl RecordingLibrarianClient {
        fn new(answer: &str) -> Self {
            Self {
                answer: answer.to_string(),
                operations: Vec::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn with_operations(answer: &str, operations: Vec<ProjectLibrarianOperation>) -> Self {
            Self {
                answer: answer.to_string(),
                operations,
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl AnswerLibrarianClient for RecordingLibrarianClient {
        async fn answer(
            &self,
            endpoint: &Endpoint,
            _timeout_secs: u64,
            request: &LibrarianRequest,
        ) -> Result<LibrarianAnswer, crate::LoreError> {
            assert!(endpoint.is_configured());
            self.requests.lock().unwrap().push(request.clone());
            Ok(LibrarianAnswer {
                answer: self.answer.clone(),
            })
        }

        async fn answer_raw(
            &self,
            endpoint: &Endpoint,
            _timeout_secs: u64,
            _system: &str,
            _user_msg: &str,
        ) -> Result<LibrarianAnswer, crate::LoreError> {
            assert!(endpoint.is_configured());
            Ok(LibrarianAnswer {
                answer: self.answer.clone(),
            })
        }

        async fn healthcheck(
            &self,
            endpoint: &Endpoint,
            _timeout_secs: u64,
        ) -> Result<ProviderCheckResult, crate::LoreError> {
            assert!(endpoint.is_configured());
            Ok(ProviderCheckResult {
                ok: true,
                detail: "ok".into(),
                checked_at: time::OffsetDateTime::now_utc(),
            })
        }

        async fn plan_action(
            &self,
            endpoint: &Endpoint,
            _timeout_secs: u64,
            request: &ProjectLibrarianRequest,
        ) -> Result<ProjectLibrarianPlan, crate::LoreError> {
            assert!(endpoint.is_configured());
            self.requests.lock().unwrap().push(LibrarianRequest {
                project: request.project.clone(),
                question: request.instruction.clone(),
                context_blocks: request.context_blocks.clone(),
                context_errors: None,
            });
            Ok(ProjectLibrarianPlan {
                summary: self.answer.clone(),
                operations: self.operations.clone(),
            })
        }
    }

    #[tokio::test]
    async fn creates_and_lists_blocks() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token =
            issue_agent_token(&app, dir.path(), "agent-main", ProjectPermission::ReadWrite).await;

        let create = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"project":"alpha.docs","block_type":"markdown","content":"hello"}"#,
            ))
            .unwrap();

        let response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let list = Request::builder()
            .method("GET")
            .uri("/v1/blocks?project=alpha.docs")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(list).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["content"], "hello");
    }

    #[tokio::test]
    async fn rejects_missing_api_key_on_create() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));

        let request = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"project":"alpha.docs","block_type":"markdown","content":"hello"}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn searches_blocks() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-search",
            ProjectPermission::ReadWrite,
        )
        .await;

        let create = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"project":"alpha.docs","block_type":"markdown","content":"Decision log"}"#,
            ))
            .unwrap();

        let response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/search?project=alpha.docs&q=decision")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["content"], "Decision log");
    }

    #[tokio::test]
    async fn enforces_owner_on_delete() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let owner_token =
            issue_agent_token(&app, dir.path(), "owner-key", ProjectPermission::ReadWrite).await;
        let intruder_token = issue_agent_token(
            &app,
            dir.path(),
            "intruder-key",
            ProjectPermission::ReadWrite,
        )
        .await;

        let create = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &owner_token)
            .body(Body::from(
                r#"{"project":"alpha.docs","block_type":"markdown","content":"owned"}"#,
            ))
            .unwrap();

        let response = app.clone().oneshot(create).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let id = json["id"].as_str().unwrap();

        let delete = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/blocks/{id}?project=alpha.docs"))
            .header("x-lore-key", &intruder_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(delete).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn updates_block_via_api() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let owner_token = issue_agent_token(
            &app,
            dir.path(),
            "owner-update",
            ProjectPermission::ReadWrite,
        )
        .await;

        let create = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &owner_token)
            .body(Body::from(
                r#"{"project":"alpha.docs","block_type":"markdown","content":"owned"}"#,
            ))
            .unwrap();

        let response = app.clone().oneshot(create).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let id = json["id"].as_str().unwrap();

        let update = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/blocks/{id}"))
            .header("content-type", "application/json")
            .header("x-lore-key", &owner_token)
            .body(Body::from(
                r#"{"project":"alpha.docs","block_type":"html","content":"<p>edited</p>"}"#,
            ))
            .unwrap();

        let response = app.clone().oneshot(update).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let list = Request::builder()
            .method("GET")
            .uri("/v1/blocks?project=alpha.docs")
            .header("x-lore-key", &owner_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(list).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["content"], "<p>edited</p>");
        assert_eq!(json[0]["block_type"], "html");
    }

    #[tokio::test]
    async fn rejects_invalid_order_range() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-invalid-order",
            ProjectPermission::ReadWrite,
        )
        .await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{
                    "project":"alpha.docs",
                    "block_type":"markdown",
                    "content":"oops",
                    "left":"80000000",
                    "right":"40000000"
                }"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn renders_project_page() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, _) = bootstrap_admin_session(&app, dir.path()).await;
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-render",
            ProjectPermission::ReadWrite,
        )
        .await;

        // Create a document under the project
        let create_doc = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/documents")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from("{\"name\":\"Test Doc\"}"))
            .unwrap();
        let response = app.clone().oneshot(create_doc).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc_json: Value = serde_json::from_slice(&body).unwrap();
        let doc_id = doc_json["id"].as_str().unwrap().to_string();

        // Create a block in the document
        let create = Request::builder()
            .method("POST")
            .uri(format!("/v1/projects/alpha.docs/documents/{doc_id}/blocks"))
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                "{\"block_type\":\"markdown\",\"content\":\"# Hello\"}",
            ))
            .unwrap();
        let response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Check the project page shows reserved blocks and doc listing
        let request = Request::builder()
            .method("GET")
            .uri("/ui/alpha.docs")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("alpha.docs"));
        assert!(html.contains("Agent Context"));
        assert!(html.contains("Overview"));
        assert!(html.contains("File Map"));
        assert!(html.contains("Test Doc"));
        assert!(html.contains(">admin</span>"));

        // Check the document page shows the block
        let doc_page = Request::builder()
            .method("GET")
            .uri(format!("/ui/alpha.docs/doc/{doc_id}"))
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(doc_page).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("editline-plus"));
        assert!(html.contains("id=\"document\""));
        assert!(html.contains("title=\"Save\""));
        assert!(html.contains("class=\"block-header-btn danger\""));
    }

    #[tokio::test]
    async fn creates_block_from_form_and_redirects() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let boundary = "x-form-boundary";
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-form-create",
            ProjectPermission::ReadWrite,
        )
        .await;

        let request = Request::builder()
            .method("POST")
            .uri("/ui/alpha.docs/blocks")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("cookie", &session_cookie)
            .body(Body::from(multipart_body(
                boundary,
                &[
                    ("csrf_token", &csrf_token),
                    ("block_type", "markdown"),
                    ("content", "from form"),
                ],
                None,
            )))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/ui/alpha.docs?flash=Block%20created"
        );

        let list = Request::builder()
            .method("GET")
            .uri("/v1/blocks?project=alpha.docs")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(list).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["content"], "from form");
    }

    #[tokio::test]
    async fn updates_block_from_form_and_redirects() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let boundary = "x-form-boundary";
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-form-update",
            ProjectPermission::ReadWrite,
        )
        .await;

        let create = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                "{\"project\":\"alpha.docs\",\"block_type\":\"markdown\",\"content\":\"before\"}",
            ))
            .unwrap();

        let response = app.clone().oneshot(create).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let id = json["id"].as_str().unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/ui/alpha.docs/blocks/{id}/edit"))
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("cookie", &session_cookie)
            .body(Body::from(multipart_body(
                boundary,
                &[
                    ("csrf_token", &csrf_token),
                    ("block_type", "html"),
                    ("content", "<p>after</p>"),
                ],
                None,
            )))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/ui/alpha.docs?flash=Block%20updated"
        );

        let list = Request::builder()
            .method("GET")
            .uri("/v1/blocks?project=alpha.docs")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(list).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["content"], "<p>after</p>");
        assert_eq!(json[0]["block_type"], "html");
    }

    #[tokio::test]
    async fn repositions_block_via_api_update() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-reposition",
            ProjectPermission::ReadWrite,
        )
        .await;

        let first = create_block_for_test(&app, &agent_token, "first").await;
        let second = create_block_for_test(&app, &agent_token, "second").await;

        let update = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/blocks/{}", first["id"].as_str().unwrap()))
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(format!(
                "{{\"project\":\"alpha.docs\",\"block_type\":\"markdown\",\"content\":\"first\",\"left\":\"{}\"}}",
                second["order"].as_str().unwrap()
            )))
            .unwrap();

        let response = app.clone().oneshot(update).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let list = Request::builder()
            .method("GET")
            .uri("/v1/blocks?project=alpha.docs")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(list).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["content"], "second");
        assert_eq!(json[1]["content"], "first");
    }

    #[tokio::test]
    async fn uploads_image_from_form_and_serves_media() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let boundary = "x-image-boundary";
        let image_bytes = b"not-a-real-png";
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-image",
            ProjectPermission::ReadWrite,
        )
        .await;

        // Create a document first
        let create_doc = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/documents")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from("{\"name\":\"Image Doc\"}"))
            .unwrap();
        let response = app.clone().oneshot(create_doc).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc_json: Value = serde_json::from_slice(&body).unwrap();
        let doc_id = doc_json["id"].as_str().unwrap().to_string();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/ui/alpha.docs/doc/{doc_id}/blocks"))
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("cookie", &session_cookie)
            .body(Body::from(multipart_body(
                boundary,
                &[
                    ("csrf_token", &csrf_token),
                    ("block_type", "image"),
                    ("content", "diagram note"),
                ],
                Some(("image_file", "diagram.png", "image/png", image_bytes)),
            )))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let list = Request::builder()
            .method("GET")
            .uri(format!("/v1/projects/alpha.docs/documents/{doc_id}/blocks"))
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(list).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let id = json[0]["id"].as_str().unwrap();
        assert_eq!(json[0]["block_type"], "image");
        assert_eq!(json[0]["content"], "diagram note");
        assert_eq!(json[0]["media_type"], "image/png");

        let media = Request::builder()
            .method("GET")
            .uri(format!("/ui/alpha.docs/doc/{doc_id}/blocks/{id}/media"))
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(media).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "image/png");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), image_bytes);

        let page = Request::builder()
            .method("GET")
            .uri(format!("/ui/alpha.docs/doc/{doc_id}"))
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(page).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("alt=\"Image block\""));
        assert!(html.contains("diagram note"));
    }

    #[tokio::test]
    async fn lists_projects_via_agent_api() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token_multi_project(
            &app,
            dir.path(),
            "agent-project-list",
            &[
                ("alpha.docs", ProjectPermission::ReadWrite),
                ("beta.docs", ProjectPermission::ReadWrite),
            ],
        )
        .await;

        let create_alpha = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"block_type":"markdown","content":"alpha block"}"#,
            ))
            .unwrap();
        let create_beta = Request::builder()
            .method("POST")
            .uri("/v1/projects/beta.docs/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"block_type":"markdown","content":"beta block"}"#,
            ))
            .unwrap();

        assert_eq!(
            app.clone().oneshot(create_alpha).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(create_beta).await.unwrap().status(),
            StatusCode::OK
        );

        let request = Request::builder()
            .method("GET")
            .uri("/v1/projects")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["project"], "alpha.docs");
        assert_eq!(json[1]["project"], "beta.docs");
    }

    #[tokio::test]
    async fn reads_block_and_window_via_agent_api() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-read-window",
            ProjectPermission::ReadWrite,
        )
        .await;

        let first = create_block_for_test(&app, &agent_token, "first").await;
        let second = create_block_for_test(&app, &agent_token, "second").await;
        let _third = create_block_for_test(&app, &agent_token, "third").await;

        let read = Request::builder()
            .method("GET")
            .uri(format!(
                "/v1/projects/alpha.docs/blocks/{}",
                second["id"].as_str().unwrap()
            ))
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(read).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["content"], "second");

        let around = Request::builder()
            .method("GET")
            .uri(format!(
                "/v1/projects/alpha.docs/blocks/{}/around?before=1&after=1",
                second["id"].as_str().unwrap()
            ))
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(around).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["anchor"], second["id"]);
        assert_eq!(json["blocks"].as_array().unwrap().len(), 3);
        assert_eq!(json["blocks"][0]["id"], first["id"]);
        assert_eq!(json["blocks"][1]["id"], second["id"]);
    }

    #[tokio::test]
    async fn greps_with_preview_via_agent_api() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token =
            issue_agent_token(&app, dir.path(), "agent-grep", ProjectPermission::ReadWrite).await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"block_type":"markdown","content":"Investigated auth failure in staging"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );

        let grep = Request::builder()
            .method("GET")
            .uri("/v1/projects/alpha.docs/grep?q=auth")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(grep).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(
            json[0]["block"]["content"],
            "Investigated auth failure in staging"
        );
        assert!(json[0]["preview"].as_str().unwrap().contains("auth"));
    }

    #[tokio::test]
    async fn moves_block_via_agent_api() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token =
            issue_agent_token(&app, dir.path(), "agent-move", ProjectPermission::ReadWrite).await;

        let first = create_block_for_test(&app, &agent_token, "first").await;
        let second = create_block_for_test(&app, &agent_token, "second").await;
        let third = create_block_for_test(&app, &agent_token, "third").await;

        let move_request = Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/projects/alpha.docs/blocks/{}/move",
                first["id"].as_str().unwrap()
            ))
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(format!(
                "{{\"after_block_id\":\"{}\"}}",
                third["id"].as_str().unwrap()
            )))
            .unwrap();

        let response = app.clone().oneshot(move_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let list = Request::builder()
            .method("GET")
            .uri("/v1/projects/alpha.docs/blocks")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(list).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["id"], second["id"]);
        assert_eq!(json[1]["id"], third["id"]);
        assert_eq!(json[2]["id"], first["id"]);
    }

    #[tokio::test]
    async fn bootstrap_admin_and_manage_local_accounts() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        ensure_test_admin(dir.path());

        let create_role = Request::builder()
            .method("POST")
            .uri("/v1/admin/roles")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(
                r#"{
                    "name":"writers",
                    "grants":[{"project":"alpha.docs","permission":"read_write"}]
                }"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(create_role).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let create_user = Request::builder()
            .method("POST")
            .uri("/v1/admin/users")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(
                r#"{
                    "username":"alice",
                    "password":"very-secure-passphrase",
                    "roles":["writers"],
                    "is_admin":false
                }"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(create_user).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify password is hashed, not stored in plaintext
        let db_bytes = std::fs::read(dir.path().join("lore.db")).unwrap();
        let db_str = String::from_utf8_lossy(&db_bytes);
        assert!(!db_str.contains("very-secure-passphrase"));
    }

    #[tokio::test]
    async fn project_reader_can_read_but_not_write() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token =
            issue_agent_token(&app, dir.path(), "agent-seed", ProjectPermission::ReadWrite).await;

        create_block_for_test(&app, &agent_token, "seed").await;
        bootstrap_admin_with_role_and_user(
            &app,
            dir.path(),
            "readers",
            "reader",
            ProjectPermission::Read,
        )
        .await;

        let read = Request::builder()
            .method("GET")
            .uri("/v1/projects/alpha.docs/blocks")
            .header(
                "authorization",
                basic_auth("reader", "very-secure-passphrase"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(read).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let write = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/blocks")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("reader", "very-secure-passphrase"),
            )
            .body(Body::from(
                r#"{"block_type":"markdown","content":"should fail"}"#,
            ))
            .unwrap();
        let response = app.oneshot(write).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn project_writer_can_edit_agent_block() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-human-edit",
            ProjectPermission::ReadWrite,
        )
        .await;

        bootstrap_admin_with_role_and_user(
            &app,
            dir.path(),
            "writers",
            "writer",
            ProjectPermission::ReadWrite,
        )
        .await;

        let created = create_block_for_test(&app, &agent_token, "agent content").await;
        let id = created["id"].as_str().unwrap();

        let update = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/projects/alpha.docs/blocks/{id}"))
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("writer", "very-secure-passphrase"),
            )
            .body(Body::from(
                r#"{"block_type":"markdown","content":"human edit"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(update).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let read = Request::builder()
            .method("GET")
            .uri(format!("/v1/projects/alpha.docs/blocks/{id}"))
            .header(
                "authorization",
                basic_auth("writer", "very-secure-passphrase"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(read).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["content"], "human edit");
    }

    #[tokio::test]
    async fn setup_text_uses_saved_external_address() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;

        let update = Request::builder()
            .method("POST")
            .uri("/ui/admin/setup")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={csrf_token}&external_scheme=https&external_host=lore.example.com&external_port=443"
            )))
            .unwrap();
        let response = app.clone().oneshot(update).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let request = Request::builder()
            .method("GET")
            .uri("/setup.txt")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("https://lore.example.com/setup"));
        assert!(text.contains("https://lore.example.com"));
    }

    #[tokio::test]
    async fn admin_page_shows_network_section() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, _) = bootstrap_admin_session(&app, dir.path()).await;

        let request = Request::builder()
            .method("GET")
            .uri("/ui/admin")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Network"));
        assert!(html.contains("Users"));
    }

    #[tokio::test]
    async fn anonymous_pages_use_saved_default_theme() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;

        let update = Request::builder()
            .method("POST")
            .uri("/v1/admin/server-config")
            .header("content-type", "application/json")
            .header("authorization", "Basic YWRtaW46Y29ycmVjdC1ob3JzZS1iYXR0ZXJ5")
            .body(Body::from(r#"{"external_scheme":"http","external_host":"localhost","external_port":7043,"default_theme":"graphite"}"#))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::OK
        );

        let request = Request::builder()
            .method("GET")
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("--bg: #11161c;"));
        assert!(html.contains("color-scheme: dark;"));
    }

    #[tokio::test]
    async fn logged_in_user_can_override_theme_from_settings() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;

        let update = Request::builder()
            .method("POST")
            .uri("/ui/settings/theme")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!("csrf_token={csrf_token}&theme=signal")))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );

        let request = Request::builder()
            .method("GET")
            .uri("/ui")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("--accent: #0f8f6f;"));
        assert!(html.contains("Settings"));
    }

    #[tokio::test]
    async fn admin_can_create_agent_token_via_api() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));

        let token = issue_agent_token(
            &app,
            dir.path(),
            "worker-alpha",
            ProjectPermission::ReadWrite,
        )
        .await;
        assert!(token.starts_with("lore_at_"));

        let request = Request::builder()
            .method("GET")
            .uri("/v1/admin/agent-tokens")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["name"], "worker-alpha");
        assert_eq!(json[0]["grants"][0]["project"], "alpha.docs");
    }

    #[tokio::test]
    async fn machine_provision_without_grants_defaults_to_no_access() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        store.create_project("Alpha Docs", None).unwrap();
        store.create_project("Beta Docs", None).unwrap();
        let app = build_app(store);
        ensure_test_admin(dir.path());

        let register = Request::builder()
            .method("POST")
            .uri("/v1/machines/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery","machine_name":"desk"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(register).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let machine_token = json["token"].as_str().unwrap();

        let provision = Request::builder()
            .method("POST")
            .uri("/v1/agents/provision")
            .header("content-type", "application/json")
            .header("x-lore-key", machine_token)
            .body(Body::from(r#"{"name":"scoped-worker","backend":"claude"}"#))
            .unwrap();
        let response = app.clone().oneshot(provision).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let agent_token = json["token"].as_str().unwrap();

        let list_projects = Request::builder()
            .method("GET")
            .uri("/v1/projects")
            .header("x-lore-key", agent_token)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(list_projects).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let projects: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(projects, json!([]));

        let list_tokens = Request::builder()
            .method("GET")
            .uri("/v1/admin/agent-tokens")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(list_tokens).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let tokens: Value = serde_json::from_slice(&body).unwrap();
        let created = tokens
            .as_array()
            .unwrap()
            .iter()
            .find(|token| token["name"] == "scoped-worker")
            .unwrap();
        assert_eq!(created["grants"], json!([]));
    }

    #[tokio::test]
    async fn machine_binary_target_endpoint_serves_requested_artifact() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let machine_token = register_machine_token(&app, dir.path()).await;
        fs::create_dir_all(dir.path().join("updates")).unwrap();
        fs::write(
            dir.path().join("updates").join("lore-aarch64-apple-darwin"),
            b"mac-arm64",
        )
        .unwrap();

        let request = Request::builder()
            .method("GET")
            .uri("/v1/machines/binary/aarch64-apple-darwin")
            .header("x-lore-key", machine_token)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-lore-binary-version")
                .and_then(|value| value.to_str().ok()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            response
                .headers()
                .get("x-lore-binary-sha256")
                .and_then(|value| value.to_str().ok()),
            Some(hex_sha256(b"mac-arm64").as_str())
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"mac-arm64");
    }

    #[tokio::test]
    async fn machine_ready_reports_update_state_without_consuming_commands() {
        let dir = tempdir().unwrap();
        ensure_test_admin(dir.path());
        AutoUpdateConfigStore::new(dir.path())
            .update(
                false,
                DEFAULT_UPDATE_REPO.to_string(),
                ReleaseStream::Stable,
                true,
            )
            .unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let machine_token = register_machine_token(&app, dir.path()).await;

        let ready = Request::builder()
            .method("POST")
            .uri("/v1/machines/ready")
            .header(API_KEY_HEADER, &machine_token)
            .header("x-lore-version", "0.0.1")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(ready).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], json!(true));
        assert_eq!(json["update_requested"], json!(true));
    }

    #[tokio::test]
    async fn machine_provision_can_opt_into_owner_grants() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        store.create_project("Alpha Docs", None).unwrap();
        store.create_project("Beta Docs", None).unwrap();
        let app = build_app(store);
        ensure_test_admin(dir.path());

        let register = Request::builder()
            .method("POST")
            .uri("/v1/machines/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery","machine_name":"desk"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(register).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let machine_token = json["token"].as_str().unwrap();

        let provision = Request::builder()
            .method("POST")
            .uri("/v1/agents/provision")
            .header("content-type", "application/json")
            .header("x-lore-key", machine_token)
            .body(Body::from(
                r#"{"name":"legacy-worker","backend":"claude","inherit_owner_grants":true}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(provision).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let list_tokens = Request::builder()
            .method("GET")
            .uri("/v1/admin/agent-tokens")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(list_tokens).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let tokens: Value = serde_json::from_slice(&body).unwrap();
        let created = tokens
            .as_array()
            .unwrap()
            .iter()
            .find(|token| token["name"] == "legacy-worker")
            .unwrap();
        assert_eq!(
            created["grants"],
            json!([
                {"project":"alpha-docs","permission":"read_write"},
                {"project":"beta-docs","permission":"read_write"}
            ])
        );
    }

    #[tokio::test]
    async fn admin_can_configure_answer_librarian_via_api() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        ensure_test_admin(dir.path());

        let create_ep = Request::builder()
            .method("POST")
            .uri("/v1/admin/endpoints")
            .header("content-type", "application/json")
            .header("authorization", basic_auth("admin", "correct-horse-battery"))
            .body(Body::from(
                r#"{"name":"Test","kind":"openai","url":"https://api.example.com/v1/chat/completions","model":"gpt-5.4","api_key":"secret-key"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(create_ep).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ep_body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 64)
                .await
                .unwrap(),
        )
        .unwrap();
        let endpoint_id = ep_body["id"].as_str().unwrap();
        assert_eq!(ep_body["kind"], "openai");
        assert_eq!(ep_body["has_api_key"], true);

        let update = Request::builder()
            .method("POST")
            .uri("/v1/admin/librarian-config")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(format!(
                r#"{{"endpoint_id":"{}"}}"#,
                endpoint_id
            )))
            .unwrap();
        let response = app.clone().oneshot(update).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let get = Request::builder()
            .method("GET")
            .uri("/v1/admin/librarian-config")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(get).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["endpoint_id"], endpoint_id);
        assert_eq!(json["configured"], true);
    }

    #[tokio::test]
    async fn answer_librarian_api_is_grounded_to_one_project() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Grounded answer");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock.clone()));
        let agent_token = issue_agent_token_multi_project(
            &app,
            dir.path(),
            "agent-librarian",
            &[
                ("alpha.docs", ProjectPermission::ReadWrite),
                ("beta.docs", ProjectPermission::ReadWrite),
            ],
        )
        .await;

        configure_librarian(&app, dir.path()).await;
        create_block_in_project(&app, &agent_token, "alpha.docs", "alpha answer source").await;
        create_block_in_project(&app, &agent_token, "beta.docs", "beta secret").await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/librarian/answer")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(r#"{"question":"What does alpha say?"}"#))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["answer"], "Grounded answer");
        assert_eq!(json["project"], "alpha.docs");

        let requests = mock.requests.lock().unwrap();
        let recorded = requests.last().unwrap();
        assert_eq!(recorded.project.as_str(), "alpha.docs");
        assert!(
            recorded
                .context_blocks
                .iter()
                .any(|block| block.content == "alpha answer source")
        );
        assert!(
            recorded
                .context_blocks
                .iter()
                .all(|block| block.project.as_str() == "alpha.docs")
        );
        assert!(
            recorded
                .context_blocks
                .iter()
                .all(|block| !block.content.contains("beta secret"))
        );
    }

    #[tokio::test]
    async fn project_ui_can_ask_answer_librarian() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Summary from librarian");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-ui-librarian",
            ProjectPermission::ReadWrite,
        )
        .await;

        configure_librarian(&app, dir.path()).await;
        create_block_in_project(&app, &agent_token, "alpha.docs", "UI context block").await;

        let request = Request::builder()
            .method("POST")
            .uri("/ui/alpha.docs/librarian")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={csrf_token}&question=Summarise+this+project"
            )))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let history = Request::builder()
            .method("GET")
            .uri("/ui/chat/librarian/history?project=alpha.docs")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(history).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();
        assert!(messages.len() >= 2);
        assert!(messages.iter().any(|m| {
            m["content"]
                .as_str()
                .unwrap_or("")
                .contains("Summary from librarian")
        }));
    }

    #[tokio::test]
    async fn project_page_shows_persisted_librarian_history() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Persisted librarian answer");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-history",
            ProjectPermission::ReadWrite,
        )
        .await;

        configure_librarian(&app, dir.path()).await;
        create_block_in_project(&app, &agent_token, "alpha.docs", "history source block").await;

        let ask = Request::builder()
            .method("POST")
            .uri("/ui/alpha.docs/librarian")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={csrf_token}&question=What+is+the+history"
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(ask).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );

        let history = Request::builder()
            .method("GET")
            .uri("/ui/chat/librarian/history?project=alpha.docs")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(history).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();
        assert!(messages.iter().any(|m| {
            m["content"]
                .as_str()
                .unwrap_or("")
                .contains("Persisted librarian answer")
        }));
        assert!(messages.iter().all(|m| m.get("timestamp").is_some()));
    }

    #[tokio::test]
    async fn librarian_chat_history_reads_project_scoped_conversation_messages() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Scoped librarian answer");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-scoped-history",
            ProjectPermission::ReadWrite,
        )
        .await;

        configure_librarian(&app, dir.path()).await;
        create_block_in_project(&app, &agent_token, "alpha.docs", "scoped source block").await;

        let ask = Request::builder()
            .method("POST")
            .uri("/ui/chat/librarian/ask")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={csrf_token}&project=alpha.docs&question=Explain+alpha"
            )))
            .unwrap();
        let response = app.clone().oneshot(ask).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let history = Request::builder()
            .method("GET")
            .uri("/ui/chat/librarian/history?project=alpha.docs")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(history).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();
        assert!(messages.iter().any(|m| m["content"] == "Explain alpha"));
        assert!(
            messages
                .iter()
                .any(|m| m["content"] == "Scoped librarian answer")
        );
    }

    #[tokio::test]
    async fn librarian_chat_history_reads_all_projects_conversation_messages() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Combined librarian answer");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let agent_token = issue_agent_token_multi_project(
            &app,
            dir.path(),
            "agent-all-history",
            &[
                ("alpha.docs", ProjectPermission::ReadWrite),
                ("beta.docs", ProjectPermission::ReadWrite),
            ],
        )
        .await;

        configure_librarian(&app, dir.path()).await;
        create_block_in_project(&app, &agent_token, "alpha.docs", "alpha source block").await;
        create_block_in_project(&app, &agent_token, "beta.docs", "beta source block").await;

        let ask = Request::builder()
            .method("POST")
            .uri("/ui/chat/librarian/ask")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={csrf_token}&project=&question=Summarise+everything"
            )))
            .unwrap();
        let response = app.clone().oneshot(ask).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let history = Request::builder()
            .method("GET")
            .uri("/ui/chat/librarian/history?project=")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(history).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();
        assert!(
            messages
                .iter()
                .any(|m| m["content"] == "Summarise everything")
        );
        assert!(
            messages
                .iter()
                .any(|m| m["content"] == "Combined librarian answer")
        );
    }

    #[tokio::test]
    async fn admin_can_test_saved_librarian_provider_via_api() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Provider ok");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));

        configure_librarian(&app, dir.path()).await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/admin/librarian-config/test")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert!(
            dir.path()
                .join("config/librarian-provider-status.json")
                .exists()
        );
    }

    #[tokio::test]
    async fn project_librarian_action_executes_scoped_operations_and_records_audit() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::with_operations(
            "Created a concise summary block.",
            vec![ProjectLibrarianOperation::CreateBlock {
                block_type: BlockType::Markdown,
                content: "Project summary from librarian".into(),
                after_block_id: None,
            }],
        );
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let seed_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-project-action",
            ProjectPermission::ReadWrite,
        )
        .await;
        configure_librarian(&app, dir.path()).await;
        create_block_in_project(&app, &seed_token, "alpha.docs", "seed context").await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/librarian/action")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(
                r#"{"instruction":"Add a concise summary block for this project"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["summary"], "Created a concise summary block.");
        assert_eq!(json["operations"][0]["operation_type"], "create_block");

        let read = Request::builder()
            .method("GET")
            .uri("/v1/projects/alpha.docs/blocks")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(read).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.as_array()
                .unwrap()
                .iter()
                .any(|block| block["content"] == "Project summary from librarian")
        );

        let history_path = dir.path().join("config/librarian-history/alpha.docs.json");
        let history_json = std::fs::read_to_string(history_path).unwrap();
        assert!(history_json.contains("action_request"));
        assert!(history_json.contains("project_action"));
        assert!(history_json.contains("Project summary from librarian"));
    }

    #[tokio::test]
    async fn project_librarian_action_can_require_approval_before_execution() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::with_operations(
            "Prepared a summary block.",
            vec![ProjectLibrarianOperation::CreateBlock {
                block_type: BlockType::Markdown,
                content: "Approval-gated summary".into(),
                after_block_id: None,
            }],
        );
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let seed_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-approval",
            ProjectPermission::ReadWrite,
        )
        .await;
        configure_librarian_with_approval(&app, dir.path(), true).await;
        create_block_in_project(&app, &seed_token, "alpha.docs", "seed context").await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/librarian/action")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(
                r#"{"instruction":"Add a concise summary block for this project"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["requires_approval"], true);
        let pending_id = json["pending_action_id"].as_str().unwrap();

        let read = Request::builder()
            .method("GET")
            .uri("/v1/projects/alpha.docs/blocks")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(read).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            !json
                .as_array()
                .unwrap()
                .iter()
                .any(|block| block["content"] == "Approval-gated summary")
        );

        let approve = Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/projects/alpha.docs/librarian/action/{pending_id}/approve"
            ))
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(approve).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let read = Request::builder()
            .method("GET")
            .uri("/v1/projects/alpha.docs/blocks")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(read).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.as_array()
                .unwrap()
                .iter()
                .any(|block| block["content"] == "Approval-gated summary")
        );
    }

    #[tokio::test]
    async fn answer_librarian_enforces_rate_limit_per_actor_and_project() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Grounded answer");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-rate-limit",
            ProjectPermission::ReadWrite,
        )
        .await;

        configure_librarian(&app, dir.path()).await;
        create_block_in_project(&app, &agent_token, "alpha.docs", "rate limit source").await;

        for _ in 0..RATE_LIMIT_REQUESTS {
            let request = Request::builder()
                .method("POST")
                .uri("/v1/projects/alpha.docs/librarian/answer")
                .header("content-type", "application/json")
                .header("x-lore-key", &agent_token)
                .body(Body::from(r#"{"question":"Summarise alpha"}"#))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let request = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/librarian/answer")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(r#"{"question":"Summarise alpha"}"#))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("librarian rate limit exceeded")
        );

        let history_path = dir.path().join("config/librarian-history/alpha.docs.json");
        let history_json = std::fs::read_to_string(history_path).unwrap();
        assert!(history_json.contains("rate_limited"));
    }

    #[tokio::test]
    async fn mcp_initialize_lists_tools_and_calls_list_projects() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token_multi_project(
            &app,
            dir.path(),
            "mcp-agent",
            &[("alpha.docs", ProjectPermission::ReadWrite)],
        )
        .await;

        let seed = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"block_type":"markdown","content":"hello from mcp"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(seed).await.unwrap().status(),
            StatusCode::OK
        );

        let initialize = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", format!("Bearer {agent_token}"))
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(initialize).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["result"]["protocolVersion"], "2025-06-18");

        let tools = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-session-id", &session_id)
            .header("mcp-protocol-version", "2025-06-18")
            .header("authorization", format!("Bearer {agent_token}"))
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(tools).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == "grep_blocks")
        );

        let call = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-session-id", &session_id)
            .header("mcp-protocol-version", "2025-06-18")
            .header("authorization", format!("Bearer {agent_token}"))
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_projects","arguments":{}}}"#,
            ))
            .unwrap();
        let response = app.oneshot(call).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["result"]["structuredContent"]["projects"][0]["project"],
            "alpha.docs"
        );
    }

    #[tokio::test]
    async fn admin_can_rotate_agent_token_and_old_token_stops_working() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let token = issue_agent_token(
            &app,
            dir.path(),
            "worker-rotate",
            ProjectPermission::ReadWrite,
        )
        .await;

        let rotate = Request::builder()
            .method("POST")
            .uri("/v1/admin/agent-tokens/worker-rotate/rotate")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(rotate).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let rotated = json["token"].as_str().unwrap();
        assert_ne!(token, rotated);

        let old_request = Request::builder()
            .method("GET")
            .uri("/v1/projects")
            .header("x-lore-key", &token)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(old_request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let new_request = Request::builder()
            .method("GET")
            .uri("/v1/projects")
            .header("x-lore-key", rotated)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(new_request).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn disabling_user_revokes_existing_ui_session() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        bootstrap_admin_with_role_and_user(
            &app,
            dir.path(),
            "writers",
            "writer",
            ProjectPermission::ReadWrite,
        )
        .await;

        let login = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                "username=writer&password=very-secure-passphrase",
            ))
            .unwrap();
        let response = app.clone().oneshot(login).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let session_cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let disable = Request::builder()
            .method("POST")
            .uri("/v1/admin/users/writer/disable")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(disable).await.unwrap().status(),
            StatusCode::OK
        );

        let request = Request::builder()
            .method("GET")
            .uri("/ui")
            .header("cookie", session_cookie)
            .body(Body::empty())
            .unwrap();
        // UI routes redirect to /login when session is invalid
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
    }

    #[tokio::test]
    async fn librarian_request_filters_context_by_type_and_author() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Filtered answer");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock.clone()));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-filter",
            ProjectPermission::ReadWrite,
        )
        .await;

        configure_librarian(&app, dir.path()).await;
        let alpha_markdown =
            create_block_in_project(&app, &agent_token, "alpha.docs", "alpha plan").await;
        let alpha_id = alpha_markdown["id"].as_str().unwrap().to_string();

        let update = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/projects/alpha.docs/blocks/{alpha_id}"))
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"block_type":"html","content":"<p>html block</p>"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::OK
        );

        let request = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/librarian/answer")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"question":"What changed?","block_type":"html"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );

        let requests = mock.requests.lock().unwrap();
        let recorded = requests.last().unwrap();
        assert!(!recorded.context_blocks.is_empty());
        assert!(
            recorded
                .context_blocks
                .iter()
                .all(|block| block.block_type == BlockType::Html)
        );
    }

    #[tokio::test]
    async fn mcp_rejects_missing_session_on_tools_calls() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get("mcp-protocol-version").unwrap(),
            MCP_PROTOCOL_VERSION
        );
    }

    #[tokio::test]
    async fn external_auth_headers_can_sign_in_existing_user() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        bootstrap_admin_with_role_and_user(
            &app,
            dir.path(),
            "writers",
            "writer",
            ProjectPermission::ReadWrite,
        )
        .await;
        configure_external_auth(&app, dir.path()).await;

        let request = Request::builder()
            .method("POST")
            .uri("/login/external")
            .header("x-forwarded-user", "writer")
            .header("x-lore-proxy-auth", "proxy-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let page = Request::builder()
            .method("GET")
            .uri("/ui")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(page).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_audit_page_shows_pending_actions() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::with_operations(
            "Prepared a summary block.",
            vec![ProjectLibrarianOperation::CreateBlock {
                block_type: BlockType::Markdown,
                content: "Audit pending summary".into(),
                after_block_id: None,
            }],
        );
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let (session_cookie, _) = bootstrap_admin_session(&app, dir.path()).await;
        let seed_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-audit-pending",
            ProjectPermission::ReadWrite,
        )
        .await;
        configure_librarian_with_approval(&app, dir.path(), true).await;
        create_block_in_project(&app, &seed_token, "alpha.docs", "seed context").await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/librarian/action")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(
                r#"{"instruction":"Add a concise summary block for this project"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );

        let page = Request::builder()
            .method("GET")
            .uri("/ui/admin/audit")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(page).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Pending action"));
        assert!(html.contains("Audit pending summary"));
    }

    #[tokio::test]
    async fn project_history_records_and_reverts_block_updates() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-history",
            ProjectPermission::ReadWrite,
        )
        .await;

        let create = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"block_type":"markdown","content":"first note","after_block_id":null}"#,
            ))
            .unwrap();
        let create_response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: Value = serde_json::from_slice(&create_body).unwrap();
        let block_id = created["id"].as_str().unwrap().to_string();

        let update = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/projects/alpha.docs/blocks/{block_id}"))
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                r#"{"block_type":"markdown","content":"edited note","after_block_id":null}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::OK
        );

        let history = Request::builder()
            .method("GET")
            .uri("/v1/projects/alpha.docs/history")
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();
        let history_response = app.clone().oneshot(history).await.unwrap();
        assert_eq!(history_response.status(), StatusCode::OK);
        let history_body = axum::body::to_bytes(history_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let history_json: Value = serde_json::from_slice(&history_body).unwrap();
        let versions = history_json["versions"].as_array().unwrap();
        let update_version_id = versions
            .iter()
            .find(|entry| entry["summary"] == "Update block")
            .and_then(|entry| entry["id"].as_str())
            .unwrap()
            .to_string();

        let revert = Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/projects/alpha.docs/history/{update_version_id}/revert"
            ))
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(revert).await.unwrap().status(),
            StatusCode::OK
        );

        let read = Request::builder()
            .method("GET")
            .uri(format!("/v1/projects/alpha.docs/blocks/{block_id}"))
            .header("x-lore-key", &agent_token)
            .body(Body::empty())
            .unwrap();
        let read_response = app.oneshot(read).await.unwrap();
        assert_eq!(read_response.status(), StatusCode::OK);
        let read_body = axum::body::to_bytes(read_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let block_json: Value = serde_json::from_slice(&read_body).unwrap();
        assert_eq!(block_json["content"], "first note");
    }

    #[tokio::test]
    async fn admin_can_configure_and_run_git_export() {
        let dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "--bare"])
                .arg(remote_dir.path())
                .status()
                .unwrap()
                .success()
        );

        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-export",
            ProjectPermission::ReadWrite,
        )
        .await;
        create_block_in_project(&app, &agent_token, "alpha.docs", "export me").await;
        configure_admin_and_git_export(
            &app,
            dir.path(),
            &format!("file://{}", remote_dir.path().display()),
        )
        .await;

        let sync = Request::builder()
            .method("POST")
            .uri("/v1/admin/git-export/sync")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(sync).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let clone_dir = tempdir().unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["clone", "--branch", "main"])
                .arg(remote_dir.path())
                .arg(clone_dir.path())
                .status()
                .unwrap()
                .success()
        );
        let projects_dir = clone_dir.path().join("projects/alpha.docs/blocks");
        let exported_file = std::fs::read_dir(projects_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let exported = std::fs::read_to_string(exported_file).unwrap();
        assert!(exported.contains("alpha.docs"));
    }

    async fn create_block_for_test<S>(app: &S, agent_token: &str, content: &str) -> Value
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        let create = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", agent_token)
            .body(Body::from(format!(
                "{{\"project\":\"alpha.docs\",\"block_type\":\"markdown\",\"content\":\"{content}\"}}"
            )))
            .unwrap();

        let response = app.clone().oneshot(create).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn create_block_in_project<S>(
        app: &S,
        agent_token: &str,
        project: &str,
        content: &str,
    ) -> Value
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        let create = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", agent_token)
            .body(Body::from(format!(
                "{{\"project\":\"{project}\",\"block_type\":\"markdown\",\"content\":\"{content}\"}}"
            )))
            .unwrap();

        let response = app.clone().oneshot(create).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn issue_agent_token<S>(
        app: &S,
        dir: &std::path::Path,
        name: &str,
        permission: ProjectPermission,
    ) -> String
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        issue_agent_token_multi_project(app, dir, name, &[("alpha.docs", permission)]).await
    }

    async fn issue_agent_token_multi_project<S>(
        app: &S,
        dir: &std::path::Path,
        name: &str,
        grants: &[(&str, ProjectPermission)],
    ) -> String
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        ensure_test_admin(dir);

        let grants_json = grants
            .iter()
            .map(|(project, permission)| {
                let permission = match permission {
                    ProjectPermission::Read => "read",
                    ProjectPermission::ReadWrite => "read_write",
                };
                format!(r#"{{"project":"{project}","permission":"{permission}"}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        let request = Request::builder()
            .method("POST")
            .uri("/v1/admin/agent-tokens")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(format!(
                r#"{{"name":"{name}","owner":"admin","grants":[{grants_json}]}}"#
            )))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        json["token"].as_str().unwrap().to_string()
    }

    async fn register_machine_token<S>(app: &S, dir: &std::path::Path) -> String
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        ensure_test_admin(dir);
        let register = Request::builder()
            .method("POST")
            .uri("/v1/machines/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery","machine_name":"desk"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(register).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        json["token"].as_str().unwrap().to_string()
    }

    async fn bootstrap_admin_with_role_and_user<S>(
        app: &S,
        dir: &std::path::Path,
        role_name: &str,
        username: &str,
        permission: ProjectPermission,
    ) where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        ensure_test_admin(dir);

        let permission = match permission {
            ProjectPermission::Read => "read",
            ProjectPermission::ReadWrite => "read_write",
        };
        let create_role = Request::builder()
            .method("POST")
            .uri("/v1/admin/roles")
            .header("content-type", "application/json")
            .header("authorization", basic_auth("admin", "correct-horse-battery"))
            .body(Body::from(format!(
                "{{\"name\":\"{role_name}\",\"grants\":[{{\"project\":\"alpha.docs\",\"permission\":\"{permission}\"}}]}}"
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(create_role).await.unwrap().status(),
            StatusCode::OK
        );

        let create_user = Request::builder()
            .method("POST")
            .uri("/v1/admin/users")
            .header("content-type", "application/json")
            .header("authorization", basic_auth("admin", "correct-horse-battery"))
            .body(Body::from(format!(
                "{{\"username\":\"{username}\",\"password\":\"very-secure-passphrase\",\"roles\":[\"{role_name}\"],\"is_admin\":false}}"
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(create_user).await.unwrap().status(),
            StatusCode::OK
        );
    }

    async fn configure_librarian<S>(app: &S, dir: &std::path::Path)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        configure_librarian_with_approval(app, dir, false).await;
    }

    async fn configure_librarian_with_approval<S>(
        app: &S,
        dir: &std::path::Path,
        action_requires_approval: bool,
    ) where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        ensure_test_admin(dir);

        let create_ep = Request::builder()
            .method("POST")
            .uri("/v1/admin/endpoints")
            .header("content-type", "application/json")
            .header("authorization", basic_auth("admin", "correct-horse-battery"))
            .body(Body::from(
                r#"{"name":"Test","kind":"openai","url":"https://api.example.com/v1/chat/completions","model":"gpt-5.4","api_key":"secret-key"}"#,
            ))
            .unwrap();
        let ep_response = app.clone().oneshot(create_ep).await.unwrap();
        assert_eq!(ep_response.status(), StatusCode::OK);
        let ep_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ep_response.into_body(), 1024 * 64)
                .await
                .unwrap(),
        )
        .unwrap();
        let endpoint_id = ep_body["id"].as_str().unwrap();

        let update = Request::builder()
            .method("POST")
            .uri("/v1/admin/librarian-config")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(format!(
                r#"{{"endpoint_id":"{}","action_requires_approval":{}}}"#,
                endpoint_id,
                if action_requires_approval {
                    "true"
                } else {
                    "false"
                }
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::OK
        );
    }

    async fn configure_external_auth<S>(app: &S, dir: &std::path::Path)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        ensure_test_admin(dir);

        let update = Request::builder()
            .method("POST")
            .uri("/v1/admin/external-auth-config")
            .header("content-type", "application/json")
            .header("authorization", basic_auth("admin", "correct-horse-battery"))
            .body(Body::from(
                r#"{"enabled":true,"username_header":"x-forwarded-user","secret_header":"x-lore-proxy-auth","secret_value":"proxy-secret"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::OK
        );
    }

    async fn configure_admin_and_git_export<S>(app: &S, dir: &std::path::Path, remote_url: &str)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        ensure_test_admin(dir);

        let update = Request::builder()
            .method("POST")
            .uri("/v1/admin/git-export-config")
            .header("content-type", "application/json")
            .header("authorization", basic_auth("admin", "correct-horse-battery"))
            .body(Body::from(format!(
                r#"{{"enabled":true,"remote_url":"{remote_url}","branch":"main","author_name":"Lore","author_email":"lore@example.com","auto_export":false}}"#
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::OK
        );
    }

    async fn bootstrap_admin_session<S>(app: &S, dir: &std::path::Path) -> (String, String)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        ensure_test_admin(dir);
        let login = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("username=admin&password=correct-horse-battery"))
            .unwrap();
        let response = app.clone().oneshot(login).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let page = Request::builder()
            .method("GET")
            .uri("/ui")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(page).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        let csrf = extract_hidden_value(&html, "csrf_token").unwrap();
        (cookie, csrf)
    }

    fn ensure_test_admin(dir: &std::path::Path) {
        let auth = LocalAuthStore::new(dir.to_path_buf());
        if !auth.has_users().unwrap() {
            auth.bootstrap_admin(
                UserName::new("admin".to_string()).unwrap(),
                "correct-horse-battery".to_string(),
            )
            .unwrap();
        }
    }

    fn basic_auth(username: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
        )
    }

    fn extract_hidden_value(html: &str, name: &str) -> Option<String> {
        let needle = format!("name=\"{name}\" value=\"");
        let start = html.find(&needle)? + needle.len();
        let rest = &html[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }

    fn multipart_body(
        boundary: &str,
        text_fields: &[(&str, &str)],
        file_field: Option<(&str, &str, &str, &[u8])>,
    ) -> Vec<u8> {
        let mut body = Vec::new();

        for (name, value) in text_fields {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }

        if let Some((name, filename, media_type, bytes)) = file_field {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {media_type}\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }

        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    #[tokio::test]
    async fn auto_update_repo_change_requires_password() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let _token =
            issue_agent_token(&app, dir.path(), "agent-upd", ProjectPermission::ReadWrite).await;

        // Save initial config (same default repo) without password - should succeed
        let request = Request::builder()
            .method("POST")
            .uri("/v1/admin/auto-update-config")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(format!(
                r#"{{"enabled":true,"github_repo":"{}"}}"#,
                crate::updater::DEFAULT_UPDATE_REPO
            )))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Change repo without password - should fail
        let request = Request::builder()
            .method("POST")
            .uri("/v1/admin/auto-update-config")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(r#"{"enabled":true,"github_repo":"evil/repo"}"#))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Change repo with wrong password - should fail
        let request = Request::builder()
            .method("POST")
            .uri("/v1/admin/auto-update-config")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(
                r#"{"enabled":true,"github_repo":"evil/repo","confirm_password":"wrong"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Change repo with correct password - should succeed
        let request = Request::builder()
            .method("POST")
            .uri("/v1/admin/auto-update-config")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(
                r#"{"enabled":true,"github_repo":"other/repo","confirm_password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auto_update_config_api_exposes_machine_rollout_settings() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        ensure_test_admin(dir.path());

        let request = Request::builder()
            .method("POST")
            .uri("/v1/admin/auto-update-config")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(format!(
                r#"{{"enabled":true,"github_repo":"{}","release_stream":"prerelease","auto_update_machines":true}}"#,
                crate::updater::DEFAULT_UPDATE_REPO
            )))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["auto_update_machines"], json!(true));
        assert_eq!(json["release_stream"], json!("prerelease"));
        assert_eq!(json["last_machine_rollout_version"], Value::Null);
    }

    #[tokio::test]
    async fn machine_poll_uses_global_auto_update_rollout_for_current_server_version() {
        let dir = tempdir().unwrap();
        ensure_test_admin(dir.path());
        AutoUpdateConfigStore::new(dir.path())
            .update(
                false,
                DEFAULT_UPDATE_REPO.to_string(),
                ReleaseStream::Stable,
                true,
            )
            .unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));

        let register = Request::builder()
            .method("POST")
            .uri("/v1/machines/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery","machine_name":"desk"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(register).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let machine_token = json["token"].as_str().unwrap();

        let poll = Request::builder()
            .method("POST")
            .uri("/v1/machines/poll")
            .header("content-type", "application/json")
            .header(API_KEY_HEADER, machine_token)
            .header("x-lore-version", "0.0.1")
            .body(Body::from("{}"))
            .unwrap();
        let response = app.clone().oneshot(poll).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["update_to"], json!(env!("CARGO_PKG_VERSION")));
        assert_eq!(json["update_repo"], json!(DEFAULT_UPDATE_REPO));
        assert_eq!(json["update_stream"], json!("stable"));

        let config = AutoUpdateConfigStore::new(dir.path()).load().unwrap();
        assert_eq!(
            config.last_machine_rollout_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[tokio::test]
    async fn machine_poll_only_includes_update_every_other_poll() {
        let dir = tempdir().unwrap();
        ensure_test_admin(dir.path());
        AutoUpdateConfigStore::new(dir.path())
            .update(
                false,
                DEFAULT_UPDATE_REPO.to_string(),
                ReleaseStream::Stable,
                true,
            )
            .unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let machine_token = register_machine_token(&app, dir.path()).await;

        for expected_update in [true, false, true, false] {
            let poll = Request::builder()
                .method("POST")
                .uri("/v1/machines/poll")
                .header("content-type", "application/json")
                .header(API_KEY_HEADER, &machine_token)
                .header("x-lore-version", "0.0.1")
                .body(Body::from("{}"))
                .unwrap();
            let response = app.clone().oneshot(poll).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json.get("update_to").is_some(), expected_update);
        }
    }

    #[tokio::test]
    async fn chat_poll_only_includes_update_every_other_poll() {
        let dir = tempdir().unwrap();
        ensure_test_admin(dir.path());
        AutoUpdateConfigStore::new(dir.path())
            .update(
                false,
                DEFAULT_UPDATE_REPO.to_string(),
                ReleaseStream::Stable,
                true,
            )
            .unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app, dir.path()).await;
        let _machine_token = register_machine_token(&app, dir.path()).await;
        let agent_token =
            issue_agent_token(&app, dir.path(), "agent-upd", ProjectPermission::ReadWrite).await;

        for (idx, expected_update) in [true, false, true, false].into_iter().enumerate() {
            let send = Request::builder()
                .method("POST")
                .uri("/ui/chat/agent-upd/send")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", &session_cookie)
                .body(Body::from(format!(
                    "csrf_token={}&message={}",
                    urlencoding::encode(&csrf_token),
                    urlencoding::encode(&format!("poll message {idx}"))
                )))
                .unwrap();
            let response = app.clone().oneshot(send).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let poll = Request::builder()
                .method("GET")
                .uri("/v1/chat/poll")
                .header(API_KEY_HEADER, &agent_token)
                .header("x-lore-machine", "desk")
                .header("x-lore-version", "0.0.1")
                .body(Body::empty())
                .unwrap();
            let response = app.clone().oneshot(poll).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json.get("update_to").is_some(), expected_update);
        }
    }

    #[test]
    fn git_branch_rejects_leading_dash() {
        use crate::versioning::GitExportConfig;
        let mut config = GitExportConfig::default();
        config.enabled = true;
        config.remote_url = "https://github.com/example/repo.git".to_string();
        config.branch = "--upload-pack=evil".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn git_branch_accepts_normal_names() {
        use crate::versioning::GitExportConfig;
        let mut config = GitExportConfig::default();
        config.enabled = true;
        config.remote_url = "https://github.com/example/repo.git".to_string();
        config.branch = "feature/my-branch".to_string();
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn api_basic_auth_rate_limited() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        ensure_test_admin(dir.path());

        for _ in 0..LOGIN_RATE_LIMIT_ATTEMPTS {
            let req = Request::builder()
                .method("GET")
                .uri("/v1/projects")
                .header("authorization", basic_auth("admin", "wrong-password"))
                .body(Body::empty())
                .unwrap();
            let _ = app.clone().oneshot(req).await.unwrap();
        }

        let req = Request::builder()
            .method("GET")
            .uri("/v1/projects")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn mcp_session_rejects_wrong_bearer_token() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token_multi_project(
            &app,
            dir.path(),
            "mcp-bound",
            &[("alpha.docs", ProjectPermission::ReadWrite)],
        )
        .await;

        let initialize = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", format!("Bearer {agent_token}"))
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(initialize).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let tools_wrong_token = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-session-id", &session_id)
            .header("mcp-protocol-version", "2025-06-18")
            .header("authorization", "Bearer fake-token-value")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(tools_wrong_token).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let tools_no_token = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-session-id", &session_id)
            .header("mcp-protocol-version", "2025-06-18")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(tools_no_token).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn secure_cookie_flag_when_https() {
        let cookie = session_cookie_value("test-token", true);
        assert!(cookie.contains("; Secure"));
        let cookie = session_cookie_value("test-token", false);
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[tokio::test]
    async fn agent_token_auth_rate_limited_after_failures() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let valid_token = issue_agent_token_multi_project(
            &app,
            dir.path(),
            "rate-test",
            &[("alpha.docs", ProjectPermission::Read)],
        )
        .await;

        for _ in 0..AGENT_AUTH_RATE_LIMIT_ATTEMPTS {
            let req = Request::builder()
                .method("GET")
                .uri("/v1/projects")
                .header(API_KEY_HEADER, "completely-wrong-token")
                .body(Body::empty())
                .unwrap();
            let _ = app.clone().oneshot(req).await.unwrap();
        }

        // Valid token should now be rate-limited too
        let req = Request::builder()
            .method("GET")
            .uri("/v1/projects")
            .header(API_KEY_HEADER, &valid_token)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn global_librarian_rate_limit_caps_total_requests() {
        let dir = tempdir().unwrap();
        let state = super::AppState::new(FileBlockStore::new(dir.path()));

        for _ in 0..GLOBAL_LIBRARIAN_RATE_LIMIT {
            enforce_global_librarian_rate_limit(&state).unwrap();
        }

        let err = enforce_global_librarian_rate_limit(&state).unwrap_err();
        assert!(err.to_string().contains("server-wide librarian rate limit"));
    }

    #[test]
    fn agent_auth_rate_limit_tracks_failures() {
        let dir = tempdir().unwrap();
        let state = super::AppState::new(FileBlockStore::new(dir.path()));

        enforce_agent_auth_rate_limit(&state).unwrap();

        for _ in 0..AGENT_AUTH_RATE_LIMIT_ATTEMPTS {
            record_failed_agent_auth(&state);
        }

        let err = enforce_agent_auth_rate_limit(&state).unwrap_err();
        assert!(
            err.to_string()
                .contains("too many failed agent authentication")
        );
    }

    #[test]
    fn streamed_tool_call_deltas_accumulate_into_formatted_file_read() {
        let mut pending = BTreeMap::new();
        merge_pending_stream_tool_call(
            &mut pending,
            &json!({
                "index": 0,
                "function": {
                    "name": "read_document",
                    "arguments": ""
                }
            }),
        );
        merge_pending_stream_tool_call(
            &mut pending,
            &json!({
                "index": 0,
                "function": {
                    "arguments": "{\"document_id\":\"abcdefghi\"}"
                }
            }),
        );
        let call = pending.remove(&0).unwrap();
        let (detail, args) = finalize_pending_stream_tool_call(&call.name, &call.arguments);
        let args = args.unwrap();
        assert_eq!(detail, "\u{1f4d6} read_document abcdefgh");
        assert_eq!(
            args.get("document_id").and_then(|v| v.as_str()),
            Some("abcdefghi")
        );
    }

    #[test]
    fn streamed_tool_call_deltas_accumulate_into_formatted_file_edit() {
        let mut pending = BTreeMap::new();
        merge_pending_stream_tool_call(
            &mut pending,
            &json!({
                "index": 2,
                "function": {
                    "name": "update_block",
                    "arguments": "{\"block_id\":\"_block123\""
                }
            }),
        );
        merge_pending_stream_tool_call(
            &mut pending,
            &json!({
                "index": 2,
                "function": {
                    "arguments": "}"
                }
            }),
        );
        let call = pending.remove(&2).unwrap();
        let (detail, args) = finalize_pending_stream_tool_call(&call.name, &call.arguments);
        let args = args.unwrap();
        assert_eq!(detail, "\u{270f}\u{fe0f} update_block _block123");
        assert_eq!(
            args.get("block_id").and_then(|v| v.as_str()),
            Some("_block123")
        );
    }

    #[test]
    fn chat_panel_appends_finished_message_for_idle_completed_turn() {
        let mut conv = ChatConversation {
            agent_status: AgentChatStatus::Idle,
            active_turn_user_id: 1,
            last_delivered_user_id: 1,
            ..Default::default()
        };
        conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "hello".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });
        conv.messages.push(ChatMessage {
            id: 2,
            role: ChatRole::Assistant,
            content: "done".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });

        let messages = super::chat_messages_value_for_panel(&conv);
        let last = messages.last().unwrap();
        assert_eq!(last["role"].as_str(), Some("system"));
        assert_eq!(last["content"].as_str(), Some("✅ Finished"));
    }

    #[test]
    fn chat_panel_skips_finished_message_without_completed_turn_marker() {
        let mut conv = ChatConversation {
            agent_status: AgentChatStatus::Idle,
            ..Default::default()
        };
        conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "hello".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });
        conv.messages.push(ChatMessage {
            id: 2,
            role: ChatRole::Assistant,
            content: "done".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });

        let messages = super::chat_messages_value_for_panel(&conv);
        assert_eq!(messages.len(), 2);
        assert_ne!(
            messages.last().unwrap()["content"].as_str(),
            Some("✅ Finished")
        );
    }

    #[test]
    fn chat_panel_skips_finished_message_while_agent_is_thinking() {
        let mut conv = ChatConversation {
            agent_status: AgentChatStatus::Thinking,
            active_turn_user_id: 1,
            last_delivered_user_id: 1,
            ..Default::default()
        };
        conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "hello".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });
        conv.messages.push(ChatMessage {
            id: 2,
            role: ChatRole::Assistant,
            content: "partial".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });

        let messages = super::chat_messages_value_for_panel(&conv);
        assert_eq!(messages.len(), 2);
        assert_ne!(
            messages.last().unwrap()["content"].as_str(),
            Some("✅ Finished")
        );
    }

    #[test]
    fn chat_panel_moves_follow_up_user_messages_after_active_turn_output() {
        let mut conv = ChatConversation {
            agent_status: AgentChatStatus::Thinking,
            active_turn_user_id: 1,
            last_delivered_user_id: 0,
            ..Default::default()
        };
        conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "first".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });
        conv.messages.push(ChatMessage {
            id: 2,
            role: ChatRole::Assistant,
            content: "working".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });
        conv.messages.push(ChatMessage {
            id: 3,
            role: ChatRole::User,
            content: "follow-up".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });
        conv.messages.push(ChatMessage {
            id: 4,
            role: ChatRole::Tool,
            content: "tool step".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });

        let messages = super::chat_messages_value_for_panel(&conv);
        let contents: Vec<&str> = messages
            .iter()
            .map(|msg| msg["content"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(contents, vec!["first", "working", "tool step", "follow-up"]);
    }

    #[test]
    fn chat_panel_places_finished_marker_before_pending_follow_up_messages() {
        let mut conv = ChatConversation {
            agent_status: AgentChatStatus::Idle,
            active_turn_user_id: 1,
            last_delivered_user_id: 1,
            ..Default::default()
        };
        conv.messages.push(ChatMessage {
            id: 1,
            role: ChatRole::User,
            content: "first".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });
        conv.messages.push(ChatMessage {
            id: 2,
            role: ChatRole::Assistant,
            content: "done".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });
        conv.messages.push(ChatMessage {
            id: 3,
            role: ChatRole::User,
            content: "follow-up".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            client_message_id: None,
            excluded_from_context: false,
        });

        let messages = super::chat_messages_value_for_panel(&conv);
        let contents: Vec<&str> = messages
            .iter()
            .map(|msg| msg["content"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(contents, vec!["first", "done", "✅ Finished", "follow-up"]);
    }

    #[test]
    fn chat_panel_keeps_last_fifty_exchanges_verbatim() {
        let mut conv = ChatConversation {
            active_turn_user_id: 119,
            last_delivered_user_id: 119,
            ..Default::default()
        };
        for i in 1..=60u64 {
            conv.messages.push(ChatMessage {
                id: (i * 2) - 1,
                role: ChatRole::User,
                content: format!("user-{i}"),
                timestamp: OffsetDateTime::UNIX_EPOCH,
                client_message_id: None,
                excluded_from_context: false,
            });
            conv.messages.push(ChatMessage {
                id: i * 2,
                role: ChatRole::Assistant,
                content: format!("assistant-{i}"),
                timestamp: OffsetDateTime::UNIX_EPOCH,
                client_message_id: None,
                excluded_from_context: false,
            });
        }
        conv.summary_until_id = 100;

        let messages = super::chat_messages_value_for_panel(&conv);
        assert_eq!(messages.len(), 100);
        assert_eq!(
            messages.first().unwrap()["content"].as_str(),
            Some("user-11")
        );
        assert_eq!(
            messages.last().unwrap()["content"].as_str(),
            Some("assistant-60")
        );
    }

    #[test]
    fn unsummarized_messages_hide_compacted_prefix_from_agent_window() {
        let mut conv = ChatConversation::default();
        for i in 1..=6u64 {
            conv.messages.push(ChatMessage {
                id: (i * 2) - 1,
                role: ChatRole::User,
                content: format!("user-{i}"),
                timestamp: OffsetDateTime::UNIX_EPOCH,
                client_message_id: None,
                excluded_from_context: false,
            });
            conv.messages.push(ChatMessage {
                id: i * 2,
                role: ChatRole::Assistant,
                content: format!("assistant-{i}"),
                timestamp: OffsetDateTime::UNIX_EPOCH,
                client_message_id: None,
                excluded_from_context: false,
            });
        }
        conv.summary_until_id = 6;

        let remaining = super::unsummarized_messages(&conv);
        let context_remaining = super::agent_context_messages(remaining);
        assert_eq!(super::count_exchanges(&context_remaining), 3);
        assert_eq!(remaining.first().unwrap().content, "user-4");
        assert_eq!(remaining.last().unwrap().content, "assistant-6");
    }

    #[test]
    fn finish_api_agent_preserves_only_follow_up_message_as_pending() {
        let dir = tempdir().unwrap();
        let state = super::AppState::new(FileBlockStore::new(dir.path()));

        let first = state
            .chat
            .append_message("admin", "agent-main", ChatRole::User, "first".into())
            .unwrap();
        let claimed = state
            .chat
            .claim_pending_user_messages("admin", "agent-main")
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, first.id);

        let second = state
            .chat
            .append_message("admin", "agent-main", ChatRole::User, "second".into())
            .unwrap();

        super::finish_api_agent(&state, "admin", "agent-main", "done");

        let pending = state
            .chat
            .claim_pending_user_messages("admin", "agent-main")
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, second.id);
        assert_eq!(pending[0].content, "second");
    }

    #[test]
    fn chat_agent_stop_request_is_one_shot() {
        let dir = tempdir().unwrap();
        let state = super::AppState::new(FileBlockStore::new(dir.path()));

        super::request_chat_agent_stop(&state, "admin", "agent-main");

        assert!(super::take_chat_agent_stop_request(
            &state,
            "admin",
            "agent-main"
        ));
        assert!(!super::take_chat_agent_stop_request(
            &state,
            "admin",
            "agent-main"
        ));
    }

    #[test]
    fn finalize_agent_turn_clears_pending_stop_request() {
        let dir = tempdir().unwrap();
        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        let _ = state
            .chat
            .append_message("admin", "agent-main", ChatRole::User, "first".into())
            .unwrap();
        let _ = state
            .chat
            .claim_pending_user_messages("admin", "agent-main")
            .unwrap();

        super::request_chat_agent_stop(&state, "admin", "agent-main");
        super::finalize_agent_turn(&state, "admin", "agent-main");

        assert!(!super::take_chat_agent_stop_request(
            &state,
            "admin",
            "agent-main"
        ));
    }

    #[test]
    fn chat_respond_body_accepts_legacy_done_flag() {
        let body: super::ChatRespondBody = serde_json::from_value(json!({
            "text": "fallback",
            "done": true
        }))
        .unwrap();

        assert_eq!(body.text.as_deref(), Some("fallback"));
        assert_eq!(body.complete, Some(true));
    }

    #[test]
    fn manager_request_summary_matches_turn_cycle() {
        assert_eq!(
            super::manager_request_summary(0),
            "review the latest output"
        );
        assert_eq!(
            super::manager_request_summary(1),
            "review the latest output"
        );
        assert_eq!(
            super::manager_request_summary(2),
            "review the latest output"
        );
        assert_eq!(super::manager_request_summary(3), "run periodic checks");
        assert_eq!(
            super::manager_request_summary(4),
            "validate the periodic check results"
        );
    }

    #[test]
    fn manager_chat_messages_use_emoji_prefix() {
        assert_eq!(
            super::manager_chat_message_prefix("asking manager to review the latest output"),
            "👔 asking manager to review the latest output"
        );
        assert_eq!(
            super::manager_chat_message_prefix("keep going"),
            "👔 keep going"
        );
    }

    #[test]
    fn manager_prompts_direct_the_agent_without_waiting_for_user_input() {
        let mc = ManageConfig {
            goals: "Ship the fix".into(),
            stopping_point: "The bug is fixed".into(),
            periodic_checks: "Run the smoke test".into(),
            red_flags: "Data loss".into(),
            ..Default::default()
        };
        let prompt_config = ManagerPromptConfig::default();

        let review = super::build_manager_prompt(&mc, &prompt_config, 0);
        assert!(review.contains("direct instructions to the agent"));
        assert!(review.contains("Do not ask the user for input"));
        assert!(review.contains("WAIT_FOR_SECONDS: <1-600>"));

        let periodic = super::build_manager_prompt(&mc, &prompt_config, 3);
        assert!(periodic.contains("direct instructions to the agent"));
        assert!(periodic.contains("Do not ask the user for input"));
        assert!(periodic.contains("WAIT_FOR_SECONDS: <1-600>"));

        let validate = super::build_manager_prompt(&mc, &prompt_config, 4);
        assert!(validate.contains("tell the agent exactly what to do next"));
        assert!(validate.contains("Do not ask the user for input"));
        assert!(validate.contains("WAIT_FOR_SECONDS: <1-600>"));
    }

    #[test]
    fn manager_prompt_builder_uses_admin_stage_override_when_enabled() {
        let mc = ManageConfig {
            goals: "Ship the fix".into(),
            stopping_point: "The bug is fixed".into(),
            periodic_checks: "Run the smoke test".into(),
            red_flags: "Data loss".into(),
            ..Default::default()
        };
        let prompt_config = ManagerPromptConfig::new(
            ManagerPromptOverride {
                enabled: true,
                text: "Tell the agent to inspect the latest diff and then continue.".into(),
            },
            ManagerPromptOverride::default(),
            ManagerPromptOverride::default(),
        );

        let review = super::build_manager_prompt(&mc, &prompt_config, 1);
        assert!(review.contains("Tell the agent to inspect the latest diff and then continue."));
        assert!(!review.contains(
            "Review the agent's latest output and decide the next thing the agent should do."
        ));
    }

    #[test]
    fn manage_enable_restart_policy_matches_agent_state() {
        assert!(super::should_restart_agent_on_manage_enable(Some(
            "restarting"
        )));
        assert!(super::should_restart_agent_on_manage_enable(Some(
            "offline"
        )));
        assert!(!super::should_restart_agent_on_manage_enable(Some(
            "running"
        )));
        assert!(!super::should_restart_agent_on_manage_enable(None));
    }

    #[test]
    fn due_delayed_manager_message_is_released_to_pending_user_queue() {
        let dir = tempdir().unwrap();
        let state = super::AppState::new(FileBlockStore::new(dir.path()));
        let owner = "alice";
        let agent = "agent-main";
        state
            .chat
            .save_manage_config(
                owner,
                agent,
                &ManageConfig {
                    enabled: true,
                    delayed_message: "Check whether the build finished, then continue.".into(),
                    delayed_until_unix: OffsetDateTime::now_utc().unix_timestamp() - 1,
                    ..Default::default()
                },
            )
            .unwrap();

        let released = super::release_due_delayed_manager_message(&state, owner, agent);
        assert!(matches!(released, Ok(true)));

        let pending = state
            .chat
            .claim_pending_user_messages(owner, agent)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].content,
            "👔 Check whether the build finished, then continue."
        );

        let saved = state.chat.get_manage_config(owner, agent).unwrap().unwrap();
        assert!(saved.delayed_message.is_empty());
        assert_eq!(saved.delayed_until_unix, 0);
    }

    #[tokio::test]
    async fn csp_header_on_html_responses() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path().to_path_buf());
        let app = build_app(store);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let csp = resp
            .headers()
            .get("content-security-policy")
            .expect("CSP header should be present")
            .to_str()
            .unwrap();
        assert!(csp.contains("script-src 'unsafe-inline'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("img-src 'self' data: https:"));

        let xcto = resp
            .headers()
            .get("x-content-type-options")
            .expect("X-Content-Type-Options should be present")
            .to_str()
            .unwrap();
        assert_eq!(xcto, "nosniff");

        let xfo = resp
            .headers()
            .get("x-frame-options")
            .expect("X-Frame-Options should be present")
            .to_str()
            .unwrap();
        assert_eq!(xfo, "DENY");
    }

    #[test]
    fn svg_sanitization_strips_dangerous_elements() {
        use crate::ui::sanitize_svg;

        // Script tags removed, safe elements preserved
        let malicious = r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect width="10" height="10"/></svg>"#;
        let clean = sanitize_svg(malicious);
        assert!(!clean.contains("<script"), "script tag should be stripped");
        assert!(clean.contains("rect"), "safe elements should be preserved");

        // Event handlers stripped, element kept
        let with_event = r#"<svg><rect onclick="alert(1)" width="10"/></svg>"#;
        let clean = sanitize_svg(with_event);
        assert!(
            !clean.contains("onclick"),
            "event handlers should be stripped"
        );
        assert!(clean.contains("rect"), "element should remain");

        // foreignObject and its children removed
        let with_foreign =
            r#"<svg><foreignObject><div>xss</div></foreignObject><circle r="5"/></svg>"#;
        let clean = sanitize_svg(with_foreign);
        assert!(!clean.contains("foreignObject"), "foreignObject stripped");
        assert!(
            !clean.contains("div"),
            "children of blocked elements stripped"
        );
        assert!(clean.contains("circle"), "safe elements should remain");

        // Safe SVG passes through unchanged
        let safe = r#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="50" fill="blue"/><text x="10" y="30">Hello</text></svg>"#;
        let clean = sanitize_svg(safe);
        assert_eq!(clean, safe, "safe SVG should pass through unchanged");

        // Mixed-case bypass attempt
        let upper = r#"<svg><SCRIPT>alert(1)</SCRIPT><rect width="5"/></svg>"#;
        let clean = sanitize_svg(upper);
        assert!(!clean.contains("SCRIPT"), "mixed-case script stripped");
        assert!(clean.contains("rect"));

        // External use href blocked, local ref preserved
        let ext_use = r#"<svg><use href="http://evil.com/x.svg#a"/></svg>"#;
        let clean = sanitize_svg(ext_use);
        assert!(!clean.contains("evil.com"), "external use href blocked");
        let local_use = r##"<svg><use href="#mySymbol"/></svg>"##;
        let clean = sanitize_svg(local_use);
        assert!(clean.contains("#mySymbol"), "local use href preserved");

        // Image: external URL blocked, data URI preserved
        let ext_img = r#"<svg><image href="http://evil.com/track.png"/></svg>"#;
        let clean = sanitize_svg(ext_img);
        assert!(!clean.contains("evil.com"), "external image href blocked");
        let data_img = r#"<svg><image href="data:image/png;base64,abc"/></svg>"#;
        let clean = sanitize_svg(data_img);
        assert!(clean.contains("data:image/png"), "data URI image preserved");

        // Style attribute: safe properties kept, dangerous values stripped
        let safe_style = r#"<svg><rect style="fill:red;opacity:0.5"/></svg>"#;
        let clean = sanitize_svg(safe_style);
        assert!(clean.contains("fill:red"), "safe style kept");
        assert!(clean.contains("opacity:0.5"), "safe style kept");
        let bad_style =
            r#"<svg><rect style="fill:red;background:url(javascript:alert(1))"/></svg>"#;
        let clean = sanitize_svg(bad_style);
        assert!(clean.contains("fill:red"), "safe part of style kept");
        assert!(
            !clean.contains("javascript"),
            "dangerous style value stripped"
        );

        // Malformed XML returns empty string
        let broken = r#"<svg><rect width="10""#;
        let clean = sanitize_svg(broken);
        assert!(clean.is_empty(), "malformed XML returns empty");

        // iframe, embed, object all blocked
        let iframe = r#"<svg><iframe src="http://evil.com"/><rect width="5"/></svg>"#;
        let clean = sanitize_svg(iframe);
        assert!(!clean.contains("iframe"), "iframe stripped");
        assert!(clean.contains("rect"));
    }

    #[tokio::test]
    async fn project_librarian_action_rejects_foreign_block_ids() {
        let dir = tempdir().unwrap();
        let fake_block_id =
            crate::model::BlockId::from_string("00000000-0000-0000-0000-000000000099".into())
                .unwrap();
        let mock = RecordingLibrarianClient::with_operations(
            "Update the block.",
            vec![ProjectLibrarianOperation::UpdateBlock {
                block_id: fake_block_id,
                block_type: None,
                content: Some("injected".into()),
                after_block_id: None,
            }],
        );
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let seed_token = issue_agent_token(
            &app,
            dir.path(),
            "agent-scope-test",
            ProjectPermission::ReadWrite,
        )
        .await;
        configure_librarian(&app, dir.path()).await;
        create_block_in_project(&app, &seed_token, "alpha.docs", "real block").await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/projects/alpha.docs/librarian/action")
            .header("content-type", "application/json")
            .header(
                "authorization",
                basic_auth("admin", "correct-horse-battery"),
            )
            .body(Body::from(r#"{"instruction":"Update the block"}"#))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "should reject plan referencing block IDs not in project"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("does not belong to project"),
            "error should mention project scope: {text}"
        );
    }
}
