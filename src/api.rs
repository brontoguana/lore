use crate::audit::{AuditActor, AuditActorKind, AuditStore, StoredAuditEvent};
use crate::auth::{
    AuthenticatedAgent, AuthenticatedUser, CreatedAgentToken, LocalAuthStore, NewAgentToken,
    NewRole, NewSession, NewUser, ProjectGrant, ProjectPermission, RoleName, StoredAgentToken,
    UserName, hash_agent_token,
};
use crate::config::{
    ExternalAuthSecretUpdate, ExternalAuthStore, ExternalScheme, OidcConfig, OidcConfigStore,
    OidcLoginStateStore, OidcSecretUpdate, OidcUsernameClaim, ServerConfig, ServerConfigStore,
    StoredOidcLoginState, UiTheme,
};
use crate::error::LoreError;
use crate::librarian::{
    AnswerLibrarianClient, ApiKeyUpdate, HttpLibrarianClient, LibrarianActor, LibrarianActorKind,
    LibrarianAnswer, LibrarianConfigStore, LibrarianHistoryStore, LibrarianProviderStatusStore,
    LibrarianRequest, LibrarianRunKind, LibrarianRunStatus, MAX_CONTEXT_BLOCKS,
    MAX_PROJECT_ACTION_OPERATIONS, MAX_PROMPT_CHARS, PendingLibrarianAction,
    PendingLibrarianActionStore, ProjectLibrarianOperation, ProjectLibrarianRequest,
    ProviderCheckResult, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECS, StoredLibrarianOperation,
    build_action_prompt, build_prompt,
};
use crate::model::{
    Block, BlockId, BlockType, ImageUpload, NewBlock, OrderKey, ProjectName, UpdateBlock,
};
use crate::store::FileBlockStore;
use crate::ui::{
    AgentTokenSummary, ProjectListEntry, UiAdminTokenDisplay, UiAuditEvent, UiDiffLine,
    UiDiffLineKind, UiLibrarianAnswer, UiPendingLibrarianAction, UiProjectVersion,
    UiProjectVersionOperation, UiUserSummary, render_admin_audit_page, render_admin_page,
    render_login_page, render_project_audit_page, render_project_history_page, render_project_page,
    render_projects_page, render_settings_page, render_setup_page,
};
use crate::updater::{
    AutoUpdateConfig, AutoUpdateConfigStore, AutoUpdateStatus, AutoUpdateStatusStore,
    check_for_update, maybe_apply_self_update,
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
use axum::routing::{delete, get, post};
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
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
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

#[derive(Clone)]
pub struct AppState {
    store: Arc<FileBlockStore>,
    auth: Arc<LocalAuthStore>,
    auth_audit: Arc<AuditStore>,
    config: Arc<ServerConfigStore>,
    external_auth: Arc<ExternalAuthStore>,
    oidc: Arc<OidcConfigStore>,
    oidc_states: Arc<OidcLoginStateStore>,
    librarian_config: Arc<LibrarianConfigStore>,
    librarian_history: Arc<LibrarianHistoryStore>,
    project_history: Arc<ProjectHistoryStore>,
    git_export_config: Arc<GitExportConfigStore>,
    git_export_status: Arc<GitExportStatusStore>,
    pending_librarian_actions: Arc<PendingLibrarianActionStore>,
    librarian_provider_status: Arc<LibrarianProviderStatusStore>,
    auto_update_config: Arc<AutoUpdateConfigStore>,
    auto_update_status: Arc<AutoUpdateStatusStore>,
    librarian_client: Arc<dyn AnswerLibrarianClient>,
    librarian_rate_limits: Arc<Mutex<HashMap<String, Vec<OffsetDateTime>>>>,
    librarian_inflight_runs: Arc<Mutex<usize>>,
    login_rate_limits: Arc<Mutex<HashMap<String, Vec<OffsetDateTime>>>>,
    agent_auth_rate_limits: Arc<Mutex<Vec<OffsetDateTime>>>,
    global_librarian_rate_limits: Arc<Mutex<Vec<OffsetDateTime>>>,
    mcp_sessions: Arc<Mutex<HashMap<String, McpSessionEntry>>>,
}

#[derive(Debug, Clone)]
struct McpSessionEntry {
    agent: AuthenticatedAgent,
    token_hash: String,
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
        let auth = LocalAuthStore::new(root.clone());
        let config = ServerConfigStore::new(root.clone(), default_port);
        Self {
            store: Arc::new(store),
            auth: Arc::new(auth),
            auth_audit: Arc::new(AuditStore::new(root.clone())),
            config: Arc::new(config),
            external_auth: Arc::new(ExternalAuthStore::new(root.clone())),
            oidc: Arc::new(OidcConfigStore::new(root.clone())),
            oidc_states: Arc::new(OidcLoginStateStore::new(root.clone())),
            librarian_config: Arc::new(LibrarianConfigStore::new(root.clone())),
            librarian_history: Arc::new(LibrarianHistoryStore::new(root.clone())),
            project_history: Arc::new(ProjectHistoryStore::new(root.clone())),
            git_export_config: Arc::new(GitExportConfigStore::new(root.clone())),
            git_export_status: Arc::new(GitExportStatusStore::new(root)),
            pending_librarian_actions: Arc::new(PendingLibrarianActionStore::new(
                provider_status_root.clone(),
            )),
            librarian_provider_status: Arc::new(LibrarianProviderStatusStore::new(
                provider_status_root,
            )),
            auto_update_config: Arc::new(AutoUpdateConfigStore::new(auto_update_root.clone())),
            auto_update_status: Arc::new(AutoUpdateStatusStore::new(auto_update_root)),
            librarian_client,
            librarian_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            librarian_inflight_runs: Arc::new(Mutex::new(0)),
            login_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            agent_auth_rate_limits: Arc::new(Mutex::new(Vec::new())),
            global_librarian_rate_limits: Arc::new(Mutex::new(Vec::new())),
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub fn build_app(store: FileBlockStore) -> Router {
    build_app_with_librarian(store, Arc::new(HttpLibrarianClient::new()))
}

fn build_app_with_librarian(
    store: FileBlockStore,
    librarian_client: Arc<dyn AnswerLibrarianClient>,
) -> Router {
    Router::new()
        .route("/", get(root_redirect))
        .route("/login", get(login_page).post(login_submit))
        .route("/login/oidc", get(oidc_login_start))
        .route("/login/oidc/callback", get(oidc_login_callback))
        .route("/login/external", post(external_login_submit))
        .route("/login/bootstrap", post(bootstrap_submit))
        .route("/logout", post(logout_submit))
        .route("/setup", get(setup_page))
        .route("/setup.txt", get(setup_text))
        .route("/mcp", get(mcp_get).post(mcp_post).delete(mcp_delete))
        .route("/v1/blocks", post(create_block).get(list_blocks))
        .route("/v1/search", axum::routing::get(search_blocks))
        .route("/v1/blocks/{id}", delete(delete_block).patch(update_block))
        .route("/v1/admin/bootstrap", post(bootstrap_admin))
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
            "/v1/admin/librarian-config",
            get(get_librarian_config).post(update_librarian_config),
        )
        .route(
            "/v1/admin/librarian-config/test",
            post(test_librarian_config),
        )
        .route(
            "/v1/admin/librarian-config/rotate-key",
            post(rotate_librarian_api_key),
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
        .route("/ui/settings", get(settings_page))
        .route("/ui/settings/theme", post(update_theme_from_ui))
        .route("/ui/admin", get(admin_page))
        .route("/ui/admin/audit", get(admin_audit_page))
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
        .route("/ui/admin/agent-tokens", post(create_agent_token_from_ui))
        .route(
            "/ui/admin/agent-tokens/{name}/rotate",
            post(rotate_agent_token_from_ui),
        )
        .route(
            "/ui/admin/agent-tokens/{name}/delete",
            post(delete_agent_token_from_ui),
        )
        .route("/ui/admin/setup", post(update_setup_from_ui))
        .route("/ui/admin/librarian", post(update_librarian_from_ui))
        .route("/ui/admin/librarian/test", post(test_librarian_from_ui))
        .route(
            "/ui/admin/librarian/rotate-key",
            post(rotate_librarian_key_from_ui),
        )
        .route("/ui/admin/git-export", post(update_git_export_from_ui))
        .route("/ui/admin/git-export/sync", post(sync_git_export_from_ui))
        .route(
            "/ui/admin/external-auth",
            post(update_external_auth_from_ui),
        )
        .route("/ui/admin/oidc", post(update_oidc_from_ui))
        .route("/ui/admin/auto-update", post(update_auto_update_from_ui))
        .route(
            "/ui/admin/auto-update/check",
            post(check_auto_update_from_ui),
        )
        .route(
            "/ui/admin/auto-update/apply",
            post(apply_auto_update_from_ui),
        )
        .route("/ui/{project}", axum::routing::get(project_page))
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
        .layer(axum::middleware::map_response(add_security_headers))
        .with_state(AppState::with_librarian(store, librarian_client))
}

async fn add_security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
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
}

#[derive(Debug, Deserialize)]
struct ProjectPageQuery {
    flash: Option<String>,
    q: Option<String>,
    block_type: Option<String>,
    author: Option<String>,
    since_days: Option<u32>,
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
    block_type: BlockType,
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
struct BootstrapAdminRequest {
    username: String,
    password: String,
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
struct CreateAgentTokenUiForm {
    csrf_token: String,
    name: String,
    grants: String,
}

#[derive(Debug, Deserialize)]
struct DeleteAgentTokenUiForm {
    csrf_token: String,
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
    default_theme: String,
}

#[derive(Debug, Deserialize)]
struct UpdateThemeUiForm {
    csrf_token: String,
    theme: String,
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
    endpoint_url: String,
    model: String,
    api_key: Option<String>,
    clear_api_key: Option<bool>,
    request_timeout_secs: Option<u64>,
    max_concurrent_runs: Option<usize>,
    action_requires_approval: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateLibrarianUiForm {
    csrf_token: String,
    endpoint_url: String,
    model: String,
    api_key: String,
    clear_api_key: Option<String>,
    request_timeout_secs: Option<u64>,
    max_concurrent_runs: Option<usize>,
    action_requires_approval: Option<String>,
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
    max_sources: Option<usize>,
    around: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RotateLibrarianApiKeyRequest {
    api_key: String,
}

#[derive(Debug, Deserialize)]
struct LibrarianProviderTestUiForm {
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct RotateLibrarianKeyUiForm {
    csrf_token: String,
    api_key: String,
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
    confirm_password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateAutoUpdateUiForm {
    csrf_token: String,
    enabled: Option<String>,
    github_repo: String,
    confirm_password: Option<String>,
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
    max_sources: Option<usize>,
    around: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug, Serialize)]
struct ProjectSummary {
    project: ProjectName,
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
    endpoint_url: String,
    model: String,
    has_api_key: bool,
    configured: bool,
    request_timeout_secs: u64,
    max_concurrent_runs: usize,
    action_requires_approval: bool,
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

async fn bootstrap_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> UiResult<Response> {
    enforce_login_rate_limit(&state, &form.username)?;
    let password = form.password;
    let user = state
        .auth
        .bootstrap_admin(UserName::new(form.username)?, password.clone())?;
    let session = state
        .auth
        .create_session(user.username.as_str(), &password)?;
    clear_login_rate_limit(&state, user.username.as_str());
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::System,
            name: "bootstrap".into(),
        },
        "bootstrap admin",
        Some(user.username.as_str().to_string()),
        None,
    )?;
    Ok(session_redirect_response(
        &state,
        &session,
        Redirect::to("/ui/admin?flash=Admin%20account%20created"),
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
    let projects = state.store.list_projects()?;
    let visible_projects = filter_projects_for_actor(&actor, &projects);
    let projects = visible_projects
        .into_iter()
        .map(|project| ProjectSummary { project })
        .collect();
    Ok(Json(projects))
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

async fn bootstrap_admin(
    State(state): State<AppState>,
    Json(payload): Json<BootstrapAdminRequest>,
) -> ApiResult<Json<UserSummary>> {
    let user = state
        .auth
        .bootstrap_admin(UserName::new(payload.username)?, payload.password)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::System,
            name: "bootstrap".into(),
        },
        "bootstrap admin",
        Some(user.username.as_str().to_string()),
        Some("api".into()),
    )?;
    Ok(Json(user_summary(&state, user)?))
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
        .map(agent_token_summary)
        .collect();
    Ok(Json(tokens))
}

async fn create_agent_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAgentTokenRequest>,
) -> ApiResult<Json<Value>> {
    let admin = require_admin(&state, &headers)?;
    let created = state.auth.create_agent_token(NewAgentToken {
        name: payload.name,
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
        "create agent token",
        Some(created.stored.name.clone()),
        Some("api".into()),
    )?;
    Ok(Json(json!({
        "token": created.token,
        "summary": agent_token_summary(created.stored),
    })))
}

async fn delete_agent_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    let admin = require_admin(&state, &headers)?;
    state.auth.revoke_agent_token(&name)?;
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
    let created = state.auth.rotate_agent_token(&name)?;
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
        "summary": agent_token_summary(created.stored),
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
        payload.endpoint_url,
        payload.model,
        api_key_update_from_request(payload.api_key.as_deref(), payload.clear_api_key),
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
    let config = state.librarian_config.load()?;
    let status = state.librarian_client.healthcheck(&config).await?;
    state.librarian_provider_status.save(&status)?;
    Ok(Json(provider_status_summary(status)))
}

async fn rotate_librarian_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RotateLibrarianApiKeyRequest>,
) -> ApiResult<Json<LibrarianConfigSummary>> {
    let admin = require_admin(&state, &headers)?;
    let config = state.librarian_config.rotate_api_key(&payload.api_key)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: admin.username.as_str().to_string(),
        },
        "rotate librarian api key",
        None,
        Some("api".into()),
    )?;
    Ok(Json(librarian_config_summary(&config)))
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
    let config = state
        .auto_update_config
        .update(payload.enabled, payload.github_repo)?;
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
            "enabled={} repo={}",
            config.enabled, config.github_repo
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
        schedule_server_restart();
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
    let projects = state.store.list_projects()?;
    let visible = filter_projects_for_user(&session.user, &projects)
        .into_iter()
        .map(|project| ProjectListEntry {
            can_write: session.user.can_write(&project),
            project,
        })
        .collect::<Vec<_>>();
    Ok(Html(render_projects_page(
        resolved_theme(&session.user, &server_config),
        session.user.username.as_str(),
        session.user.is_admin,
        &visible,
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
    let librarian_config = state.librarian_config.load()?;
    let git_export_config = state.git_export_config.load()?;
    let setup_instruction = build_agent_setup_instruction(&config, None);
    let librarian_audit = state.librarian_history.list_recent_all(12)?;
    let pending_actions = state.pending_librarian_actions.list_all(12)?;
    let auth_audit = state.auth_audit.list_recent(12)?;
    let projects = state.store.list_projects()?;
    Ok(Html(render_admin_page(
        resolved_theme(&session.user, &config),
        session.user.username.as_str(),
        &session.csrf_token,
        &state.auth.list_roles()?,
        &state
            .auth
            .list_users()?
            .into_iter()
            .map(|user| ui_user_summary(&state, user))
            .collect::<Result<Vec<_>, LoreError>>()?,
        &state
            .auth
            .list_agent_tokens()?
            .into_iter()
            .map(agent_token_summary)
            .collect::<Vec<_>>(),
        &config,
        &external_auth_config,
        &oidc_config,
        &auto_update_config,
        &librarian_config,
        &git_export_config,
        state.auto_update_status.load()?.as_ref(),
        state.librarian_provider_status.load()?,
        state.git_export_status.load()?.as_ref(),
        &setup_instruction,
        &ui_librarian_answers_from_history_all(&state.store, librarian_audit)?,
        &ui_pending_librarian_actions_all(&state.store, pending_actions)?,
        &ui_auth_audit_events(auth_audit),
        &projects,
        None,
        query.flash.as_deref(),
        query.section.as_deref().unwrap_or("users"),
    )))
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
    let theme = preview_theme.unwrap_or_else(|| resolved_theme(&session.user, &config));
    Ok(Html(render_settings_page(
        theme,
        session.user.username.as_str(),
        &session.csrf_token,
        session.user.theme,
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
    let project = ProjectName::new(form.project_name)?;
    // Creating a block implicitly creates the project directory
    let (left, right) = state.store.resolve_after_block(&project, None, None)?;
    state.store.ensure_layout(&project)?;
    Ok(Redirect::to(&format!(
        "/ui/project/{}?flash=Project%20{}%20created",
        project.as_str(),
        project.as_str()
    )))
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
    Ok(Redirect::to("/ui/admin?flash=Role%20created"))
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
    Ok(Redirect::to("/ui/admin?flash=Role%20updated"))
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

async fn create_agent_token_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateAgentTokenUiForm>,
) -> UiResult<Html<String>> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let created = state.auth.create_agent_token(NewAgentToken {
        name: form.name,
        grants: parse_role_grants(&form.grants)?,
    })?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "create agent token",
        Some(created.stored.name.clone()),
        None,
    )?;
    let config = state.config.load()?;
    let external_auth_config = state.external_auth.load()?;
    let oidc_config = state.oidc.load()?;
    let auto_update_config = state.auto_update_config.load()?;
    let librarian_config = state.librarian_config.load()?;
    let git_export_config = state.git_export_config.load()?;
    let token_display = build_ui_admin_token_display(&config, created);
    let projects = state.store.list_projects()?;
    Ok(Html(render_admin_page(
        resolved_theme(&session.user, &config),
        session.user.username.as_str(),
        &session.csrf_token,
        &state.auth.list_roles()?,
        &state
            .auth
            .list_users()?
            .into_iter()
            .map(|user| ui_user_summary(&state, user))
            .collect::<Result<Vec<_>, LoreError>>()?,
        &state
            .auth
            .list_agent_tokens()?
            .into_iter()
            .map(agent_token_summary)
            .collect::<Vec<_>>(),
        &config,
        &external_auth_config,
        &oidc_config,
        &auto_update_config,
        &librarian_config,
        &git_export_config,
        state.auto_update_status.load()?.as_ref(),
        state.librarian_provider_status.load()?,
        state.git_export_status.load()?.as_ref(),
        &build_agent_setup_instruction(&config, None),
        &ui_librarian_answers_from_history_all(
            &state.store,
            state.librarian_history.list_recent_all(12)?,
        )?,
        &ui_pending_librarian_actions_all(
            &state.store,
            state.pending_librarian_actions.list_all(12)?,
        )?,
        &ui_auth_audit_events(state.auth_audit.list_recent(12)?),
        &projects,
        Some(&token_display),
        Some("Agent token created. Copy it now; the raw token will not be shown again."),
        "agent-tokens",
    )))
}

async fn rotate_agent_token_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<UserActionUiForm>,
) -> UiResult<Html<String>> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let created = state.auth.rotate_agent_token(&name)?;
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
    let config = state.config.load()?;
    let external_auth_config = state.external_auth.load()?;
    let oidc_config = state.oidc.load()?;
    let auto_update_config = state.auto_update_config.load()?;
    let librarian_config = state.librarian_config.load()?;
    let git_export_config = state.git_export_config.load()?;
    let token_display = build_ui_admin_token_display(&config, created);
    let projects = state.store.list_projects()?;
    Ok(Html(render_admin_page(
        resolved_theme(&session.user, &config),
        session.user.username.as_str(),
        &session.csrf_token,
        &state.auth.list_roles()?,
        &state
            .auth
            .list_users()?
            .into_iter()
            .map(|user| ui_user_summary(&state, user))
            .collect::<Result<Vec<_>, LoreError>>()?,
        &state
            .auth
            .list_agent_tokens()?
            .into_iter()
            .map(agent_token_summary)
            .collect::<Vec<_>>(),
        &config,
        &external_auth_config,
        &oidc_config,
        &auto_update_config,
        &librarian_config,
        &git_export_config,
        state.auto_update_status.load()?.as_ref(),
        state.librarian_provider_status.load()?,
        state.git_export_status.load()?.as_ref(),
        &build_agent_setup_instruction(&config, None),
        &ui_librarian_answers_from_history_all(
            &state.store,
            state.librarian_history.list_recent_all(12)?,
        )?,
        &ui_pending_librarian_actions_all(
            &state.store,
            state.pending_librarian_actions.list_all(12)?,
        )?,
        &ui_auth_audit_events(state.auth_audit.list_recent(12)?),
        &projects,
        Some(&token_display),
        Some("Agent token rotated. Copy the new raw token now."),
        "agent-tokens",
    )))
}

async fn delete_agent_token_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<DeleteAgentTokenUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.auth.revoke_agent_token(&name)?;
    append_audit_event(
        &state,
        AuditActor {
            kind: AuditActorKind::User,
            name: session.user.username.as_str().to_string(),
        },
        "revoke agent token",
        Some(name),
        None,
    )?;
    Ok(Redirect::to("/ui/admin?flash=Agent%20token%20revoked"))
}

async fn update_setup_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateSetupUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.config.update(
        ExternalScheme::parse(&form.external_scheme)?,
        form.external_host,
        form.external_port,
        UiTheme::parse(&form.default_theme)?,
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
    state
        .auth
        .update_user_theme(&session.user.username, theme)?;
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
    state.librarian_config.update(
        form.endpoint_url,
        form.model,
        api_key_update_from_form(&form.api_key, form.clear_api_key.as_deref()),
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
    Ok(Redirect::to("/ui/admin?flash=Answer%20librarian%20saved"))
}

async fn test_librarian_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LibrarianProviderTestUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let config = state.librarian_config.load()?;
    let status = state.librarian_client.healthcheck(&config).await?;
    let ok = status.ok;
    state.librarian_provider_status.save(&status)?;
    let flash = if ok {
        "Librarian%20provider%20test%20succeeded"
    } else {
        "Librarian%20provider%20test%20failed"
    };
    Ok(Redirect::to(&format!("/ui/admin?flash={flash}")))
}

async fn rotate_librarian_key_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RotateLibrarianKeyUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    state.librarian_config.rotate_api_key(&form.api_key)?;
    Ok(Redirect::to(
        "/ui/admin?flash=Librarian%20API%20key%20rotated",
    ))
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

async fn update_auto_update_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateAutoUpdateUiForm>,
) -> UiResult<Redirect> {
    let session = require_ui_admin(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let current_config = state.auto_update_config.load()?;
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
    let config = state
        .auto_update_config
        .update(form.enabled.as_deref() == Some("true"), form.github_repo)?;
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
            "enabled={} repo={}",
            config.enabled, config.github_repo
        )),
    )?;
    Ok(Redirect::to("/ui/admin?flash=Auto%20update%20saved"))
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
        schedule_server_restart();
        "Update%20applied%20—%20server%20restarting"
    } else {
        "Already%20up%20to%20date"
    };
    Ok(Redirect::to(&format!("/ui/admin?flash={flash}")))
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
    let all_blocks = state.store.list_blocks(&project)?;
    let filters = block_filters_from_parts(
        query.block_type.as_deref(),
        query.author.as_deref(),
        query.since_days,
    )?;
    let blocks = if let Some(search) = query.q.as_deref() {
        state
            .store
            .search_blocks(&project, search)?
            .into_iter()
            .filter(|block| block_matches_filters(block, &filters))
            .collect::<Vec<_>>()
    } else {
        all_blocks
            .clone()
            .into_iter()
            .filter(|block| block_matches_filters(block, &filters))
            .collect::<Vec<_>>()
    };
    let librarian_history = state.librarian_history.list_recent_project(&project, 8)?;
    let pending_actions = state.pending_librarian_actions.list_project(&project, 8)?;
    let server_config = state.config.load()?;
    let page = render_project_page(
        resolved_theme(&session.user, &server_config),
        &project,
        &blocks,
        &all_blocks,
        query.flash.as_deref(),
        query.q.as_deref(),
        query.block_type.as_deref(),
        query.author.as_deref(),
        query.since_days,
        session.user.username.as_str(),
        session.user.can_write(&project),
        session.user.is_admin,
        &session.csrf_token,
        None,
        &ui_librarian_answers_from_history(&state.store, &project, librarian_history)?,
        &ui_pending_librarian_actions(&state.store, &project, pending_actions)?,
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
        &project,
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
    let versions = ui_project_versions(state.project_history.list_recent_project(&project, 100)?);
    Ok(Html(render_project_history_page(
        resolved_theme(&session.user, &state.config.load()?),
        &project,
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
    let answer = answer_librarian_for_project(
        &state,
        &project,
        payload.question,
        options,
        librarian_actor_for_request_actor(&actor),
    )
    .await?;
    Ok(Json(answer))
}

async fn answer_librarian_from_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Form(form): Form<AskLibrarianForm>,
) -> UiResult<Html<String>> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    state.auth.authorize_read(&session.user, &project)?;
    verify_csrf(&session, &form.csrf_token)?;
    let options = librarian_options_from_form(&form)?;
    let librarian_answer = answer_librarian_for_project(
        &state,
        &project,
        form.question,
        options,
        librarian_actor_for_user(&session.user),
    )
    .await?;
    let all_blocks = state.store.list_blocks(&project)?;
    let librarian_history = state.librarian_history.list_recent_project(&project, 8)?;
    let current_answer = UiLibrarianAnswer::from(librarian_answer);
    let history_answers =
        ui_librarian_answers_from_history(&state.store, &project, librarian_history)?;
    let server_config = state.config.load()?;
    let page = render_project_page(
        resolved_theme(&session.user, &server_config),
        &project,
        &all_blocks,
        &all_blocks,
        Some("Answer librarian responded"),
        None,
        None,
        None,
        None,
        session.user.username.as_str(),
        session.user.can_write(&project),
        session.user.is_admin,
        &session.csrf_token,
        Some(&current_answer),
        &history_answers,
        &ui_pending_librarian_actions(
            &state.store,
            &project,
            state.pending_librarian_actions.list_project(&project, 8)?,
        )?,
    );
    Ok(Html(page))
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
) -> UiResult<Html<String>> {
    let project = ProjectName::new(project)?;
    let session = require_ui_session(&state, &headers)?;
    verify_csrf(&session, &form.csrf_token)?;
    let options = action_librarian_options_from_form(&form)?;
    let action = execute_project_librarian_action(
        &state,
        &project,
        form.instruction,
        options,
        &session.user,
    )
    .await?;
    let all_blocks = state.store.list_blocks(&project)?;
    let librarian_history = state.librarian_history.list_recent_project(&project, 8)?;
    let current_answer = UiLibrarianAnswer::from(action);
    let history_answers =
        ui_librarian_answers_from_history(&state.store, &project, librarian_history)?;
    let pending_actions = ui_pending_librarian_actions(
        &state.store,
        &project,
        state.pending_librarian_actions.list_project(&project, 8)?,
    )?;
    let server_config = state.config.load()?;
    let page = render_project_page(
        resolved_theme(&session.user, &server_config),
        &project,
        &all_blocks,
        &all_blocks,
        Some(
            if current_answer.status == LibrarianRunStatus::PendingApproval {
                "Project librarian action planned and queued for approval"
            } else {
                "Project librarian action completed"
            },
        ),
        None,
        None,
        None,
        None,
        session.user.username.as_str(),
        session.user.can_write(&project),
        session.user.is_admin,
        &session.csrf_token,
        Some(&current_answer),
        &history_answers,
        &pending_actions,
    );
    Ok(Html(page))
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
    let after_block_id = form.after_block_id.map(BlockId::from_string).transpose()?;
    let (left, right) =
        state
            .store
            .resolve_after_block(&project, after_block_id.as_ref(), Some(&block_id))?;
    let update = UpdateBlock {
        project: project.clone(),
        block_id: block_id.clone(),
        block_type: form.block_type,
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
        }],
    )?;
    Ok(Redirect::to(&format!(
        "/ui/{}?flash=Block%20deleted",
        project.as_str()
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

fn filter_projects_for_user(
    user: &AuthenticatedUser,
    projects: &[ProjectName],
) -> Vec<ProjectName> {
    if user.is_admin {
        return projects.to_vec();
    }
    projects
        .iter()
        .filter(|project| user.can_read(project))
        .cloned()
        .collect()
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

fn build_http_auth_example(config: &ServerConfig, token: &str) -> String {
    format!(
        "curl -H 'Authorization: Bearer {token}' '{}/v1/projects'",
        config.base_url()
    )
}

fn build_mcp_config_example(config: &ServerConfig, token: &str) -> String {
    serde_json::to_string_pretty(&json!({
        "transport": "streamable_http",
        "url": config.mcp_url(),
        "headers": {
            "Authorization": format!("Bearer {token}"),
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION
        }
    }))
    .unwrap_or_else(|_| config.mcp_url())
}

fn resolved_theme(user: &AuthenticatedUser, config: &ServerConfig) -> UiTheme {
    user.theme.unwrap_or(config.default_theme)
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

fn agent_token_summary(token: StoredAgentToken) -> AgentTokenSummary {
    AgentTokenSummary {
        name: token.name,
        grants: token.grants,
        created_at: token.created_at,
    }
}

fn build_ui_admin_token_display(
    config: &ServerConfig,
    created: CreatedAgentToken,
) -> UiAdminTokenDisplay {
    let summary = agent_token_summary(created.stored);
    UiAdminTokenDisplay {
        setup_instruction: build_agent_setup_instruction(config, Some(&created.token)),
        http_example: build_http_auth_example(config, &created.token),
        mcp_example: build_mcp_config_example(config, &created.token),
        token: created.token,
        summary,
    }
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
        endpoint_url: config.endpoint_url.clone(),
        model: config.model.clone(),
        has_api_key: config.has_api_key(),
        configured: config.is_configured(),
        request_timeout_secs: config.request_timeout_secs,
        max_concurrent_runs: config.max_concurrent_runs,
        action_requires_approval: config.action_requires_approval,
        updated_at: config.updated_at,
    }
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
        configured: !config.github_repo.trim().is_empty(),
        updated_at: config.updated_at,
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
    let config = state.auto_update_config.load()?;
    let client = reqwest::Client::new();
    let check = check_for_update(
        &client,
        "lore-server",
        env!("CARGO_PKG_VERSION"),
        &config.github_repo,
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
    Ok(status)
}

async fn run_auto_update_apply(state: &AppState) -> Result<AutoUpdateStatus, LoreError> {
    let config = state.auto_update_config.load()?;
    let executable_path = std::env::current_exe().map_err(LoreError::Io)?;
    let client = reqwest::Client::new();
    match maybe_apply_self_update(
        &client,
        "lore-server",
        env!("CARGO_PKG_VERSION"),
        &config.github_repo,
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

fn schedule_server_restart() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let executable_path = match std::env::current_exe() {
            Ok(path) => path,
            Err(_) => std::process::exit(1),
        };
        let args = std::env::args_os().skip(1).collect::<Vec<_>>();
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
) -> Result<LibrarianAnswerBody, LoreError> {
    let created_at = OffsetDateTime::now_utc();
    let mut source_blocks = Vec::new();
    let config = state.librarian_config.load()?;
    let _guard = acquire_librarian_slot(state, &config)?;
    let result = async {
        enforce_librarian_rate_limit(state, &actor, project)?;
        enforce_global_librarian_rate_limit(state)?;
        let request = build_librarian_request(&state.store, project, &question, &options)?;
        source_blocks = request.context_blocks.clone();
        let LibrarianAnswer { answer } = state.librarian_client.answer(&config, &request).await?;
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

    let audit = librarian_audit_entry(
        project,
        actor,
        created_at,
        &config.endpoint_url,
        &config.model,
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
    let config = state.librarian_config.load()?;
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
        provider_endpoint_url: config.endpoint_url.clone(),
        provider_model: config.model.clone(),
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
            .plan_action(&config, &request)
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
                provider_endpoint_url: config.endpoint_url.clone(),
                provider_model: config.model.clone(),
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
        &config.endpoint_url,
        &config.model,
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
    let all_blocks = store
        .list_blocks(project)?
        .into_iter()
        .filter(|block| block_matches_filters(block, &options.filters))
        .collect::<Vec<_>>();
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
    for block_id in anchor_ids {
        for block in store.read_blocks_around(project, &block_id, options.around, options.around)? {
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
    let project_blocks = state.store.list_blocks(project)?;
    let valid_ids: std::collections::HashSet<&str> =
        project_blocks.iter().map(|b| b.id.as_str()).collect();
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
            ProjectLibrarianOperation::UpdateBlock {
                block_id,
                block_type,
                content,
                after_block_id,
            } => {
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
            ProjectLibrarianOperation::MoveBlock {
                block_id,
                after_block_id,
            } => {
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
            ProjectLibrarianOperation::DeleteBlock { block_id } => {
                let before = state.store.snapshot_block(project, block_id)?;
                state
                    .store
                    .delete_block_as_project_writer(project, block_id)?;
                recorded.push(StoredProjectVersionOperation {
                    operation_type: ProjectVersionOperationType::DeleteBlock,
                    block_id: block_id.clone(),
                    before: Some(before),
                    after: None,
                });
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
        match operation.operation_type {
            ProjectVersionOperationType::CreateBlock => {
                state
                    .store
                    .delete_block_as_project_writer(project, &operation.block_id)?;
            }
            ProjectVersionOperationType::UpdateBlock | ProjectVersionOperationType::MoveBlock => {
                let before = operation.before.as_ref().ok_or_else(|| {
                    LoreError::Validation("recorded version is missing a before snapshot".into())
                })?;
                state.store.restore_block_snapshot(before)?;
            }
            ProjectVersionOperationType::DeleteBlock => {
                let before = operation.before.as_ref().ok_or_else(|| {
                    LoreError::Validation("recorded version is missing a deleted snapshot".into())
                })?;
                state.store.restore_block_snapshot(before)?;
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
        match operation.operation_type {
            ProjectVersionOperationType::CreateBlock
            | ProjectVersionOperationType::UpdateBlock
            | ProjectVersionOperationType::MoveBlock => {
                let after = operation.after.as_ref().ok_or_else(|| {
                    LoreError::Validation("recorded version is missing an after snapshot".into())
                })?;
                if !state.store.block_matches_snapshot(
                    &version.project,
                    &operation.block_id,
                    after,
                )? {
                    return Err(LoreError::Validation(
                        "this version can no longer be reverted cleanly because later changes touched the same block".into(),
                    ));
                }
            }
            ProjectVersionOperationType::DeleteBlock => {
                if state
                    .store
                    .get_block(&version.project, &operation.block_id)
                    .is_ok()
                {
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
            let projects = state
                .store
                .list_projects()?
                .into_iter()
                .filter(|project| agent.can_read(project))
                .map(|project| json!({ "project": project.as_str() }))
                .collect::<Vec<_>>();
            json!({ "projects": projects })
        }
        "list_blocks" => {
            let project = required_project(&args, "project")?;
            authorize_agent_read(agent, &project)?;
            json!({ "blocks": state.store.list_blocks(&project)? })
        }
        "read_block" => {
            let project = required_project(&args, "project")?;
            authorize_agent_read(agent, &project)?;
            let block_id = required_block_id(&args, "block_id")?;
            json!({ "block": state.store.get_block(&project, &block_id)? })
        }
        "read_blocks_around" => {
            let project = required_project(&args, "project")?;
            authorize_agent_read(agent, &project)?;
            let block_id = required_block_id(&args, "block_id")?;
            let before = optional_usize(&args, "before").unwrap_or(2);
            let after = optional_usize(&args, "after").unwrap_or(2);
            json!({
                "anchor": block_id.as_str(),
                "blocks": state.store.read_blocks_around(&project, &block_id, before, after)?
            })
        }
        "grep_blocks" => {
            let project = required_project(&args, "project")?;
            authorize_agent_read(agent, &project)?;
            let query = required_string(&args, "query")?;
            let matches = state
                .store
                .search_blocks(&project, &query)?
                .into_iter()
                .map(|block| {
                    json!({
                        "block": block.clone(),
                        "preview": grep_preview(&block.content, &query),
                    })
                })
                .collect::<Vec<_>>();
            json!({ "matches": matches })
        }
        "create_block" => {
            let project = required_project(&args, "project")?;
            authorize_agent_write(agent, &project)?;
            let after_block_id = optional_block_id(&args, "after_block_id")?;
            let (left, right) =
                state
                    .store
                    .resolve_after_block(&project, after_block_id.as_ref(), None)?;
            let block = state.store.create_block(NewBlock {
                project,
                block_type: required_block_type(&args, "block_type")?,
                content: required_string(&args, "content")?,
                author_key: agent.token.clone(),
                left,
                right,
                image_upload: None,
            })?;
            json!({ "block": block })
        }
        "update_block" => {
            let project = required_project(&args, "project")?;
            authorize_agent_write(agent, &project)?;
            let block_id = required_block_id(&args, "block_id")?;
            let existing = state.store.get_block(&project, &block_id)?;
            let after_block_id = optional_block_id(&args, "after_block_id")?;
            let (left, right) = if args.contains_key("after_block_id") {
                state.store.resolve_after_block(
                    &project,
                    after_block_id.as_ref(),
                    Some(&block_id),
                )?
            } else {
                (None, None)
            };
            let block = state.store.update_block(UpdateBlock {
                project,
                block_id,
                block_type: optional_block_type(&args, "block_type")?
                    .unwrap_or(existing.block_type),
                content: optional_string(&args, "content").unwrap_or(existing.content),
                author_key: agent.token.clone(),
                left,
                right,
                image_upload: None,
            })?;
            json!({ "block": block })
        }
        "move_block" => {
            let project = required_project(&args, "project")?;
            authorize_agent_write(agent, &project)?;
            let block_id = required_block_id(&args, "block_id")?;
            let after_block_id = optional_block_id(&args, "after_block_id")?;
            let block = state.store.move_block_after(
                &project,
                &block_id,
                after_block_id.as_ref(),
                &agent.token,
            )?;
            json!({ "block": block })
        }
        "delete_block" => {
            let project = required_project(&args, "project")?;
            authorize_agent_write(agent, &project)?;
            let block_id = required_block_id(&args, "block_id")?;
            state
                .store
                .delete_block(&project, &block_id, &agent.token)?;
            json!({ "deleted": true, "block_id": block_id.as_str() })
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
) -> Result<ProjectName, LoreError> {
    ProjectName::new(required_string(args, key)?)
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

fn required_block_type(
    args: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<BlockType, LoreError> {
    parse_block_type(&required_string(args, key)?)
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
            "description": "List projects visible to the connected agent token.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "list_blocks",
            "title": "List Blocks",
            "description": "List ordered blocks in a project.",
            "inputSchema": schema_with_required_property("project", "string", "Lore project name")
        }),
        json!({
            "name": "read_block",
            "title": "Read Block",
            "description": "Read a single block by id.",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("block_id", "string", "Block UUID")
            ])
        }),
        json!({
            "name": "read_blocks_around",
            "title": "Read Blocks Around",
            "description": "Read an anchor block with neighboring context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Lore project name" },
                    "block_id": { "type": "string", "description": "Block UUID" },
                    "before": { "type": "integer", "minimum": 0 },
                    "after": { "type": "integer", "minimum": 0 }
                },
                "required": ["project", "block_id"]
            }
        }),
        json!({
            "name": "grep_blocks",
            "title": "Grep Blocks",
            "description": "Search a project and return matching blocks with previews.",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("query", "string", "Search query")
            ])
        }),
        json!({
            "name": "create_block",
            "title": "Create Block",
            "description": "Create a new block after an optional anchor block.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string" },
                    "block_type": { "type": "string", "enum": ["markdown", "html", "svg", "image"] },
                    "content": { "type": "string" },
                    "after_block_id": { "type": ["string", "null"] }
                },
                "required": ["project", "block_type", "content"]
            }
        }),
        json!({
            "name": "update_block",
            "title": "Update Block",
            "description": "Update block content, type, and optional placement.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string" },
                    "block_id": { "type": "string" },
                    "block_type": { "type": ["string", "null"], "enum": ["markdown", "html", "svg", "image", null] },
                    "content": { "type": ["string", "null"] },
                    "after_block_id": { "type": ["string", "null"] }
                },
                "required": ["project", "block_id"]
            }
        }),
        json!({
            "name": "move_block",
            "title": "Move Block",
            "description": "Move a block after another block.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string" },
                    "block_id": { "type": "string" },
                    "after_block_id": { "type": ["string", "null"] }
                },
                "required": ["project", "block_id"]
            }
        }),
        json!({
            "name": "delete_block",
            "title": "Delete Block",
            "description": "Delete a block the connected agent owns.",
            "inputSchema": schema_with_required_properties(&[
                ("project", "string", "Lore project name"),
                ("block_id", "string", "Block UUID")
            ])
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
            LoreError::PermissionDenied => StatusCode::FORBIDDEN,
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
        block_type: block_type
            .ok_or_else(|| LoreError::Validation("block type is required".into()))?,
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
    let mut grants = Vec::new();
    for line in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (project, permission) = line.split_once(':').ok_or_else(|| {
            LoreError::Validation("grants must use one project:permission pair per line".into())
        })?;
        let permission = match permission.trim() {
            "read" => ProjectPermission::Read,
            "read_write" => ProjectPermission::ReadWrite,
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
    if grants.is_empty() {
        return Err(LoreError::Validation(
            "role must grant at least one project permission".into(),
        ));
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

#[cfg(test)]
mod tests {
    use super::{
        AGENT_AUTH_RATE_LIMIT_ATTEMPTS, API_KEY_HEADER, GLOBAL_LIBRARIAN_RATE_LIMIT,
        LOGIN_RATE_LIMIT_ATTEMPTS, MCP_PROTOCOL_VERSION, build_app, build_app_with_librarian,
        constant_time_eq, enforce_agent_auth_rate_limit, enforce_global_librarian_rate_limit,
        record_failed_agent_auth, session_cookie_value,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tower::util::ServiceExt;

    use crate::librarian::{
        AnswerLibrarianClient, LibrarianAnswer, LibrarianConfig, LibrarianRequest,
        ProjectLibrarianOperation, ProjectLibrarianPlan, ProjectLibrarianRequest,
        ProviderCheckResult, RATE_LIMIT_REQUESTS,
    };
    use crate::store::FileBlockStore;
    use crate::{BlockType, ProjectPermission};

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
            config: &LibrarianConfig,
            request: &LibrarianRequest,
        ) -> Result<LibrarianAnswer, crate::LoreError> {
            assert!(config.is_configured());
            self.requests.lock().unwrap().push(request.clone());
            Ok(LibrarianAnswer {
                answer: self.answer.clone(),
            })
        }

        async fn healthcheck(
            &self,
            config: &LibrarianConfig,
        ) -> Result<ProviderCheckResult, crate::LoreError> {
            assert!(config.is_configured());
            Ok(ProviderCheckResult {
                ok: true,
                detail: "ok".into(),
                checked_at: time::OffsetDateTime::now_utc(),
            })
        }

        async fn plan_action(
            &self,
            config: &LibrarianConfig,
            request: &ProjectLibrarianRequest,
        ) -> Result<ProjectLibrarianPlan, crate::LoreError> {
            assert!(config.is_configured());
            self.requests.lock().unwrap().push(LibrarianRequest {
                project: request.project.clone(),
                question: request.instruction.clone(),
                context_blocks: request.context_blocks.clone(),
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
        let agent_token = issue_agent_token(&app, "agent-main", ProjectPermission::ReadWrite).await;

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
        let agent_token =
            issue_agent_token(&app, "agent-search", ProjectPermission::ReadWrite).await;

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
        let owner_token = issue_agent_token(&app, "owner-key", ProjectPermission::ReadWrite).await;
        let intruder_token =
            issue_agent_token(&app, "intruder-key", ProjectPermission::ReadWrite).await;

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
        let owner_token =
            issue_agent_token(&app, "owner-update", ProjectPermission::ReadWrite).await;

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
        let agent_token =
            issue_agent_token(&app, "agent-invalid-order", ProjectPermission::ReadWrite).await;

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
        let (session_cookie, _) = bootstrap_admin_session(&app).await;
        let agent_token =
            issue_agent_token(&app, "agent-render", ProjectPermission::ReadWrite).await;

        let create = Request::builder()
            .method("POST")
            .uri("/v1/blocks")
            .header("content-type", "application/json")
            .header("x-lore-key", &agent_token)
            .body(Body::from(
                "{\"project\":\"alpha.docs\",\"block_type\":\"markdown\",\"content\":\"# Hello\"}",
            ))
            .unwrap();

        let response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let request = Request::builder()
            .method("GET")
            .uri("/ui/alpha.docs")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("alpha.docs"));
        assert!(html.contains("Add block"));
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("width=device-width, initial-scale=1"));
        assert!(html.contains(">admin</span>"));
        assert!(html.contains("id=\"document\""));
        assert!(html.contains("Edit block"));
        assert!(html.contains("Delete block"));
    }

    #[tokio::test]
    async fn creates_block_from_form_and_redirects() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let boundary = "x-form-boundary";
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app).await;
        let agent_token =
            issue_agent_token(&app, "agent-form-create", ProjectPermission::ReadWrite).await;

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
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app).await;
        let agent_token =
            issue_agent_token(&app, "agent-form-update", ProjectPermission::ReadWrite).await;

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
        let agent_token =
            issue_agent_token(&app, "agent-reposition", ProjectPermission::ReadWrite).await;

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
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app).await;
        let agent_token =
            issue_agent_token(&app, "agent-image", ProjectPermission::ReadWrite).await;

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
            .uri("/v1/blocks?project=alpha.docs")
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
            .uri(format!("/ui/alpha.docs/blocks/{id}/media"))
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
            .uri("/ui/alpha.docs")
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
        let agent_token =
            issue_agent_token(&app, "agent-read-window", ProjectPermission::ReadWrite).await;

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
        let agent_token = issue_agent_token(&app, "agent-grep", ProjectPermission::ReadWrite).await;

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
        let agent_token = issue_agent_token(&app, "agent-move", ProjectPermission::ReadWrite).await;

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

        let bootstrap = Request::builder()
            .method("POST")
            .uri("/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        let response = app.clone().oneshot(bootstrap).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

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

        let users_path = dir.path().join("auth/users.json");
        let users_json = std::fs::read_to_string(users_path).unwrap();
        assert!(!users_json.contains("very-secure-passphrase"));
        assert!(users_json.contains("$argon2"));
    }

    #[tokio::test]
    async fn project_reader_can_read_but_not_write() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let agent_token = issue_agent_token(&app, "agent-seed", ProjectPermission::ReadWrite).await;

        create_block_for_test(&app, &agent_token, "seed").await;
        bootstrap_admin_with_role_and_user(&app, "readers", "reader", ProjectPermission::Read)
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
        let agent_token =
            issue_agent_token(&app, "agent-human-edit", ProjectPermission::ReadWrite).await;

        bootstrap_admin_with_role_and_user(&app, "writers", "writer", ProjectPermission::ReadWrite)
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
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app).await;

        let update = Request::builder()
            .method("POST")
            .uri("/ui/admin/setup")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={csrf_token}&external_scheme=https&external_host=lore.example.com&external_port=443&default_theme=parchment"
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
    async fn admin_page_shows_copy_paste_setup_instruction() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, _) = bootstrap_admin_session(&app).await;

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
        assert!(html.contains("Agent setup"));
        assert!(html.contains("Copy-paste for an agent"));
        assert!(html.contains("/setup"));
        assert!(html.contains("Visit this URL first:"));
    }

    #[tokio::test]
    async fn anonymous_pages_use_saved_default_theme() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app).await;

        let update = Request::builder()
            .method("POST")
            .uri("/ui/admin/setup")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &session_cookie)
            .body(Body::from(format!(
                "csrf_token={csrf_token}&external_scheme=http&external_host=localhost&external_port=7043&default_theme=graphite"
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::SEE_OTHER
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
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app).await;

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

        let token = issue_agent_token(&app, "worker-alpha", ProjectPermission::ReadWrite).await;
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
    async fn admin_can_configure_answer_librarian_via_api() {
        let dir = tempdir().unwrap();
        let app = build_app(FileBlockStore::new(dir.path()));

        let bootstrap = Request::builder()
            .method("POST")
            .uri("/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(bootstrap).await.unwrap().status(),
            StatusCode::OK
        );

        let update = Request::builder()
            .method("POST")
            .uri("/v1/admin/librarian-config")
            .header("content-type", "application/json")
            .header("authorization", basic_auth("admin", "correct-horse-battery"))
            .body(Body::from(
                r#"{"endpoint_url":"https://api.example.com/v1/chat/completions","model":"gpt-5.4","api_key":"secret-key"}"#,
            ))
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
        assert_eq!(
            json["endpoint_url"],
            "https://api.example.com/v1/chat/completions"
        );
        assert_eq!(json["model"], "gpt-5.4");
        assert_eq!(json["has_api_key"], true);
        assert_eq!(json["configured"], true);
    }

    #[tokio::test]
    async fn answer_librarian_api_is_grounded_to_one_project() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Grounded answer");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock.clone()));
        let agent_token = issue_agent_token_multi_project(
            &app,
            "agent-librarian",
            &[
                ("alpha.docs", ProjectPermission::ReadWrite),
                ("beta.docs", ProjectPermission::ReadWrite),
            ],
        )
        .await;

        configure_librarian(&app).await;
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
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app).await;
        let agent_token =
            issue_agent_token(&app, "agent-ui-librarian", ProjectPermission::ReadWrite).await;

        configure_librarian(&app).await;
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
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Answer librarian"));
        assert!(html.contains("Summary from librarian"));
        assert!(html.contains("Grounded with these blocks"));
        assert!(html.contains("UI context block"));
        assert!(html.contains("Recent project-only librarian history"));
        assert!(html.contains("Ask again"));
    }

    #[tokio::test]
    async fn project_page_shows_persisted_librarian_history() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Persisted librarian answer");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));
        let (session_cookie, csrf_token) = bootstrap_admin_session(&app).await;
        let agent_token =
            issue_agent_token(&app, "agent-history", ProjectPermission::ReadWrite).await;

        configure_librarian(&app).await;
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
            StatusCode::OK
        );

        let view = Request::builder()
            .method("GET")
            .uri("/ui/alpha.docs")
            .header("cookie", &session_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(view).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Persisted librarian answer"));
        assert!(html.contains("history source block"));
        assert!(html.contains("Ask again"));
    }

    #[tokio::test]
    async fn admin_can_test_saved_librarian_provider_via_api() {
        let dir = tempdir().unwrap();
        let mock = RecordingLibrarianClient::new("Provider ok");
        let app = build_app_with_librarian(FileBlockStore::new(dir.path()), Arc::new(mock));

        configure_librarian(&app).await;

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
        let seed_token =
            issue_agent_token(&app, "agent-project-action", ProjectPermission::ReadWrite).await;
        configure_librarian(&app).await;
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
        let seed_token =
            issue_agent_token(&app, "agent-approval", ProjectPermission::ReadWrite).await;
        configure_librarian_with_approval(&app, true).await;
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
        let agent_token =
            issue_agent_token(&app, "agent-rate-limit", ProjectPermission::ReadWrite).await;

        configure_librarian(&app).await;
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
        let token = issue_agent_token(&app, "worker-rotate", ProjectPermission::ReadWrite).await;

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
        bootstrap_admin_with_role_and_user(&app, "writers", "writer", ProjectPermission::ReadWrite)
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
        let agent_token =
            issue_agent_token(&app, "agent-filter", ProjectPermission::ReadWrite).await;

        configure_librarian(&app).await;
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
        bootstrap_admin_with_role_and_user(&app, "writers", "writer", ProjectPermission::ReadWrite)
            .await;
        configure_external_auth(&app).await;

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
        let (session_cookie, _) = bootstrap_admin_session(&app).await;
        let seed_token =
            issue_agent_token(&app, "agent-audit-pending", ProjectPermission::ReadWrite).await;
        configure_librarian_with_approval(&app, true).await;
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
        let agent_token =
            issue_agent_token(&app, "agent-history", ProjectPermission::ReadWrite).await;

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
        let agent_token =
            issue_agent_token(&app, "agent-export", ProjectPermission::ReadWrite).await;
        create_block_in_project(&app, &agent_token, "alpha.docs", "export me").await;
        configure_admin_and_git_export(&app, &format!("file://{}", remote_dir.path().display()))
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

    async fn issue_agent_token<S>(app: &S, name: &str, permission: ProjectPermission) -> String
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        issue_agent_token_multi_project(app, name, &[("alpha.docs", permission)]).await
    }

    async fn issue_agent_token_multi_project<S>(
        app: &S,
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
        let bootstrap = Request::builder()
            .method("POST")
            .uri("/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        let bootstrap_status = app.clone().oneshot(bootstrap).await.unwrap().status();
        assert!(matches!(
            bootstrap_status,
            StatusCode::OK | StatusCode::FORBIDDEN
        ));

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
                r#"{{"name":"{name}","grants":[{grants_json}]}}"#
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

    async fn bootstrap_admin_with_role_and_user<S>(
        app: &S,
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
        let bootstrap = Request::builder()
            .method("POST")
            .uri("/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        let bootstrap_status = app.clone().oneshot(bootstrap).await.unwrap().status();
        assert!(matches!(
            bootstrap_status,
            StatusCode::OK | StatusCode::FORBIDDEN
        ));

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

    async fn configure_librarian<S>(app: &S)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        configure_librarian_with_approval(app, false).await;
    }

    async fn configure_librarian_with_approval<S>(app: &S, action_requires_approval: bool)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        let bootstrap = Request::builder()
            .method("POST")
            .uri("/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        let bootstrap_status = app.clone().oneshot(bootstrap).await.unwrap().status();
        assert!(matches!(
            bootstrap_status,
            StatusCode::OK | StatusCode::FORBIDDEN
        ));

        let update = Request::builder()
            .method("POST")
            .uri("/v1/admin/librarian-config")
            .header("content-type", "application/json")
            .header("authorization", basic_auth("admin", "correct-horse-battery"))
            .body(Body::from(format!(
                r#"{{"endpoint_url":"https://api.example.com/v1/chat/completions","model":"gpt-5.4","api_key":"secret-key","action_requires_approval":{}}}"#,
                if action_requires_approval { "true" } else { "false" }
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(update).await.unwrap().status(),
            StatusCode::OK
        );
    }

    async fn configure_external_auth<S>(app: &S)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        let bootstrap = Request::builder()
            .method("POST")
            .uri("/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        let bootstrap_status = app.clone().oneshot(bootstrap).await.unwrap().status();
        assert!(matches!(
            bootstrap_status,
            StatusCode::OK | StatusCode::FORBIDDEN
        ));

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

    async fn configure_admin_and_git_export<S>(app: &S, remote_url: &str)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        let bootstrap = Request::builder()
            .method("POST")
            .uri("/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        let bootstrap_status = app.clone().oneshot(bootstrap).await.unwrap().status();
        assert!(matches!(
            bootstrap_status,
            StatusCode::OK | StatusCode::FORBIDDEN
        ));

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

    async fn bootstrap_admin_session<S>(app: &S) -> (String, String)
    where
        S: tower::Service<
                Request<Body>,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Clone,
        S::Future: Send,
    {
        let bootstrap = Request::builder()
            .method("POST")
            .uri("/login/bootstrap")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("username=admin&password=correct-horse-battery"))
            .unwrap();
        let response = app.clone().oneshot(bootstrap).await.unwrap();
        let response = if response.status() == StatusCode::SEE_OTHER {
            response
        } else {
            let login = Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("username=admin&password=correct-horse-battery"))
                .unwrap();
            let login_response = app.clone().oneshot(login).await.unwrap();
            assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
            login_response
        };
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
        let _token = issue_agent_token(&app, "agent-upd", ProjectPermission::ReadWrite).await;

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
        let bootstrap = Request::builder()
            .method("POST")
            .uri("/v1/admin/bootstrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"username":"admin","password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(bootstrap).await.unwrap().status(),
            StatusCode::OK
        );

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
        assert!(csp.contains("img-src 'self' data:"));

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

        let malicious = r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect width="10" height="10"/></svg>"#;
        let clean = sanitize_svg(malicious);
        assert!(!clean.contains("script"), "script tag should be stripped");
        assert!(clean.contains("rect"), "safe elements should be preserved");

        let with_event = r#"<svg><rect onclick="alert(1)" width="10"/></svg>"#;
        let clean = sanitize_svg(with_event);
        assert!(
            !clean.contains("onclick"),
            "event handlers should be stripped"
        );
        assert!(clean.contains("rect"), "element should remain");

        let with_foreign =
            r#"<svg><foreignObject><div>xss</div></foreignObject><circle r="5"/></svg>"#;
        let clean = sanitize_svg(with_foreign);
        assert!(
            !clean.contains("foreignObject"),
            "foreignObject should be stripped"
        );
        assert!(clean.contains("circle"), "safe elements should remain");

        let safe = r#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="50" fill="blue"/><text x="10" y="30">Hello</text></svg>"#;
        let clean = sanitize_svg(safe);
        assert_eq!(clean, safe, "safe SVG should pass through unchanged");
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
        let seed_token =
            issue_agent_token(&app, "agent-scope-test", ProjectPermission::ReadWrite).await;
        configure_librarian(&app).await;
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
