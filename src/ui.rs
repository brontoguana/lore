use crate::audit::{AuditActor, AuditActorKind};
use crate::auth::{ProjectGrant, ProjectPermission, StoredRole};
use crate::config::{ExternalAuthConfig, ExternalScheme, OidcConfig, ServerConfig, UiTheme};
use crate::librarian::{
    LibrarianActor, LibrarianActorKind, LibrarianConfig, LibrarianRunKind, LibrarianRunStatus,
    ProjectLibrarianOperationType, ProviderCheckResult, StoredLibrarianOperation,
};
use crate::model::{Block, BlockType, ProjectName};
use crate::updater::{AutoUpdateConfig, AutoUpdateStatus, DEFAULT_UPDATE_REPO};
use crate::versioning::{
    GitExportConfig, GitExportStatus, ProjectVersionActor, ProjectVersionActorKind,
    ProjectVersionOperationType,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use pulldown_cmark::{Options, Parser, html};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;

pub struct ProjectListEntry {
    pub project: ProjectName,
    pub can_write: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentTokenSummary {
    pub name: String,
    pub grants: Vec<ProjectGrant>,
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiUserSummary {
    pub username: String,
    pub role_names: Vec<String>,
    pub is_admin: bool,
    pub disabled: bool,
    pub active_sessions: usize,
    pub created_at: time::OffsetDateTime,
}

pub struct UiAdminTokenDisplay {
    pub summary: AgentTokenSummary,
    pub token: String,
    pub setup_instruction: String,
    pub http_example: String,
    pub mcp_example: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiLibrarianAnswer {
    pub id: String,
    pub project: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub kind: LibrarianRunKind,
    pub parent_run_id: Option<String>,
    pub question: String,
    pub answer: Option<String>,
    pub status: LibrarianRunStatus,
    pub error: Option<String>,
    pub actor: Option<LibrarianActor>,
    pub context_blocks: Vec<Block>,
    pub operations: Vec<StoredLibrarianOperation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiPendingLibrarianAction {
    pub id: String,
    pub project: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub actor: LibrarianActor,
    pub parent_run_id: String,
    pub pending_run_id: String,
    pub instruction: String,
    pub summary: String,
    pub context_blocks: Vec<Block>,
    pub operations: Vec<StoredLibrarianOperation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiAuditEvent {
    pub id: String,
    pub created_at: time::OffsetDateTime,
    pub actor: AuditActor,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiDiffLine {
    pub kind: UiDiffLineKind,
    pub text: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiDiffLineKind {
    Context,
    Added,
    Removed,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiProjectVersionOperation {
    pub operation_type: ProjectVersionOperationType,
    pub block_id: String,
    pub before_preview: Option<String>,
    pub after_preview: Option<String>,
    pub changed_fields: Vec<String>,
    pub diff_lines: Vec<UiDiffLine>,
    pub before_order: Option<String>,
    pub after_order: Option<String>,
    pub before_block_type: Option<String>,
    pub after_block_type: Option<String>,
    pub before_media_type: Option<String>,
    pub after_media_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiProjectVersion {
    pub id: String,
    pub created_at: time::OffsetDateTime,
    pub actor: ProjectVersionActor,
    pub summary: String,
    pub operations: Vec<UiProjectVersionOperation>,
    pub git_commit: Option<String>,
    pub git_export_error: Option<String>,
    pub reverted_from_version_id: Option<String>,
    pub reverted_by_version_id: Option<String>,
}

pub fn render_login_page(
    theme: UiTheme,
    has_users: bool,
    external_auth_enabled: bool,
    oidc_enabled: bool,
    flash: Option<&str>,
) -> String {
    let title = if has_users {
        "Sign in to Lore"
    } else {
        "Create the first admin account"
    };
    let subtitle = if has_users {
        "Use a local Lore account. Browser sessions are cookie-backed, HttpOnly, and protected by a per-session CSRF token."
    } else {
        "Lore has no human accounts yet. Create the initial local administrator to unlock the UI."
    };
    let action = if has_users {
        "/login"
    } else {
        "/login/bootstrap"
    };
    let button = if has_users { "Sign in" } else { "Create admin" };
    let flash_html = flash_message(flash);
    let external_auth_html = if has_users && external_auth_enabled {
        r#"<form method="post" action="/login/external">
        <button type="submit">Sign in with external auth</button>
      </form>
      <p class="hint">Use this only when Lore is behind the configured reverse proxy that injects the trusted auth headers.</p>"#
            .to_string()
    } else {
        String::new()
    };
    let oidc_html = if has_users && oidc_enabled {
        r#"<form method="get" action="/login/oidc">
        <button type="submit">Sign in with OIDC</button>
      </form>
      <p class="hint">Use this when Lore is configured against an OpenID Connect provider. Successful sign-in still maps onto an existing Lore user and role set.</p>"#
            .to_string()
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell auth-shell">
    <section class="panel auth-panel">
      <p class="eyebrow">Lore</p>
      <h1>{title}</h1>
      <p class="subtitle">{subtitle}</p>
      {flash_html}
      <form method="post" action="{action}">
        <label>
          Username
          <input type="text" name="username" autocomplete="username" required>
        </label>
        <label>
          Password
          <input type="password" name="password" autocomplete="{autocomplete}" required>
        </label>
        <button type="submit">{button}</button>
      </form>
      {oidc_html}
      {external_auth_html}
    </section>
  </main>
</body>
</html>"#,
        title = escape_text(title),
        subtitle = escape_text(subtitle),
        action = action,
        button = escape_text(button),
        autocomplete = if has_users {
            "current-password"
        } else {
            "new-password"
        },
        flash_html = flash_html,
        oidc_html = oidc_html,
        external_auth_html = external_auth_html,
        styles = shared_styles(theme),
    )
}

pub fn render_projects_page(
    theme: UiTheme,
    username: &str,
    is_admin: bool,
    projects: &[ProjectListEntry],
    csrf_token: &str,
    flash: Option<&str>,
) -> String {
    let flash_html = flash_message(flash);
    let admin_link = if is_admin {
        r#"<a href="/ui/admin">Admin</a>"#.to_string()
    } else {
        String::new()
    };
    let project_cards = if projects.is_empty() {
        r#"<section class="empty-state"><h2>No visible projects</h2><p>You do not currently have access to any projects, or no project data exists yet.</p></section>"#.to_string()
    } else {
        projects
            .iter()
            .map(|entry| {
                format!(
                    r#"<article class="project-card">
  <div>
    <p class="eyebrow">Project</p>
    <h2>{}</h2>
    <p class="subtitle">{}</p>
  </div>
  <a class="button-link" href="/ui/{}">Open</a>
</article>"#,
                    escape_text(entry.project.as_str()),
                    if entry.can_write {
                        "Read and write access"
                    } else {
                        "Read-only access"
                    },
                    escape_attribute(entry.project.as_str())
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lore projects</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Lore workspace</p>
      <h1>Projects</h1>
      <p class="subtitle">Signed in as {username}. Open a project document, or move to admin if you manage access.</p>
      <div class="hero-actions">
        <a href="/ui/settings">Settings</a>
        {admin_link}
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Sign out</button>
        </form>
      </div>
      {flash_html}
    </section>
    <section class="project-grid">{project_cards}</section>
  </main>
</body>
</html>"#,
        styles = shared_styles(theme),
        username = escape_text(username),
        admin_link = admin_link,
        csrf_token = escape_attribute(csrf_token),
        flash_html = flash_html,
        project_cards = project_cards,
    )
}

pub fn render_admin_page(
    theme: UiTheme,
    username: &str,
    csrf_token: &str,
    roles: &[StoredRole],
    users: &[UiUserSummary],
    agent_tokens: &[AgentTokenSummary],
    server_config: &ServerConfig,
    external_auth_config: &ExternalAuthConfig,
    oidc_config: &OidcConfig,
    auto_update_config: &AutoUpdateConfig,
    librarian_config: &LibrarianConfig,
    git_export_config: &GitExportConfig,
    auto_update_status: Option<&AutoUpdateStatus>,
    provider_status: Option<ProviderCheckResult>,
    git_export_status: Option<&GitExportStatus>,
    setup_instruction: &str,
    librarian_audit: &[UiLibrarianAnswer],
    pending_actions: &[UiPendingLibrarianAction],
    auth_audit: &[UiAuditEvent],
    latest_agent_token: Option<&UiAdminTokenDisplay>,
    flash: Option<&str>,
) -> String {
    let flash_html = flash_message(flash);
    let roles_html = if roles.is_empty() {
        "<p class=\"hint padded\">No roles exist yet.</p>".to_string()
    } else {
        roles
            .iter()
            .map(|role| render_role_card(role, csrf_token))
            .collect::<Vec<_>>()
            .join("")
    };
    let users_html = if users.is_empty() {
        "<p class=\"hint padded\">No users exist yet.</p>".to_string()
    } else {
        users
            .iter()
            .map(|user| render_user_card(user, csrf_token))
            .collect::<Vec<_>>()
            .join("")
    };
    let agent_tokens_html = if agent_tokens.is_empty() {
        "<p class=\"hint padded\">No agent tokens exist yet.</p>".to_string()
    } else {
        agent_tokens
            .iter()
            .map(|token| render_agent_token_card(token, csrf_token))
            .collect::<Vec<_>>()
            .join("")
    };
    let latest_agent_token_html = latest_agent_token
        .map(|token| render_latest_agent_token(token))
        .unwrap_or_default();
    let pending_actions_html = if pending_actions.is_empty() {
        "<p class=\"hint padded\">No pending project librarian actions.</p>".to_string()
    } else {
        pending_actions
            .iter()
            .map(|action| render_pending_librarian_action(action, None, csrf_token, false))
            .collect::<Vec<_>>()
            .join("")
    };
    let provider_status_html = provider_status
        .map(|status| {
            let label = if status.ok { "Healthy" } else { "Failed" };
            format!(
                "<p><strong>Provider test</strong><br>{label} at {}<br>{}</p>",
                escape_text(&format_timestamp(status.checked_at)),
                escape_text(&status.detail),
            )
        })
        .unwrap_or_else(|| "<p><strong>Provider test</strong><br>Not run yet.</p>".to_string());
    let audit_html = if librarian_audit.is_empty() {
        "<p class=\"hint padded\">No librarian runs recorded yet.</p>".to_string()
    } else {
        librarian_audit
            .iter()
            .map(render_librarian_answer)
            .collect::<Vec<_>>()
            .join("")
    };
    let auth_audit_html = if auth_audit.is_empty() {
        "<p class=\"hint padded\">No auth or admin events recorded yet.</p>".to_string()
    } else {
        auth_audit
            .iter()
            .map(render_audit_event)
            .collect::<Vec<_>>()
            .join("")
    };
    let git_export_status_html = git_export_status
        .map(|status| {
            format!(
                "<p><strong>Last sync</strong><br>{}<br>{}<br>{}</p>",
                if status.ok { "Succeeded" } else { "Failed" },
                escape_text(&format_timestamp(status.created_at)),
                escape_text(&status.detail),
            )
        })
        .unwrap_or_else(|| "<p><strong>Last sync</strong><br>Not run yet.</p>".to_string());
    let auto_update_status_html = auto_update_status
        .map(|status| {
            let latest = status.latest_version.as_deref().unwrap_or("unknown");
            let current = &status.current_version;
            let update_available = status.ok
                && !status.applied
                && status.latest_version.as_deref().is_some_and(|v| v != current);
            let apply_button = if update_available {
                format!(
                    r#"<form method="post" action="/ui/admin/auto-update/apply" class="inline-form" style="margin-top:0.5rem">
                      <input type="hidden" name="csrf_token" value="{csrf_token}">
                      <button type="submit">Apply update to {latest}</button>
                    </form>"#,
                    csrf_token = csrf_token,
                    latest = escape_attribute(latest),
                )
            } else {
                String::new()
            };
            format!(
                "<p><strong>Last check</strong><br>{}<br>Current {}<br>Latest {}<br>{}</p>{}",
                escape_text(&format_timestamp(status.checked_at)),
                escape_text(current),
                escape_text(latest),
                escape_text(&status.detail),
                apply_button,
            )
        })
        .unwrap_or_else(|| "<p><strong>Last check</strong><br>Not run yet.</p>".to_string());

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lore admin</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Lore admin</p>
      <h1>Users and roles</h1>
      <p class="subtitle">Signed in as {username}. Local browser sessions use a server-side token store, and role grants apply at whole-project scope for human users.</p>
      <div class="hero-actions">
        <a class="primary" href="/ui">Projects</a>
        <a href="/ui/settings">Settings</a>
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Sign out</button>
        </form>
      </div>
      {flash_html}
    </section>

    <section class="layout admin-layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Agent setup</h2>
          <p>Set the externally reachable Lore address once, then hand agents the generated setup URL instead of writing custom instructions yourself.</p>
        </div>
        <form method="post" action="/ui/admin/setup">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            External scheme
            <select name="external_scheme">
              <option value="http"{http_selected}>http</option>
              <option value="https"{https_selected}>https</option>
            </select>
          </label>
          <label>
            External domain
            <input type="text" name="external_host" value="{external_host}" placeholder="lore.example.com" required>
          </label>
          <label>
            External port
            <input type="number" name="external_port" min="1" max="65535" value="{external_port}" required>
          </label>
          <label>
            Default theme
            <select name="default_theme">
              {theme_options}
            </select>
          </label>
          <button type="submit">Save setup address</button>
        </form>
        <div class="meta-stack">
          <p><strong>Setup page</strong><br>{setup_url}</p>
          <p><strong>Plain text page</strong><br>{setup_text_url}</p>
        </div>
        <label>
          Copy-paste for an agent
          <textarea readonly>{setup_instruction}</textarea>
        </label>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Answer librarian</h2>
          <p>Configure one OpenAI-compatible chat completions endpoint for the read-only answer librarian and the narrow project librarian. The secret is stored on disk with the same restricted file permissions as other Lore server secrets and is never shown again after save.</p>
        </div>
        <form method="post" action="/ui/admin/librarian">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Endpoint URL
            <input type="url" name="endpoint_url" value="{librarian_endpoint_url}" placeholder="https://api.example.com/v1/chat/completions">
          </label>
          <label>
            Model
            <input type="text" name="model" value="{librarian_model}" placeholder="gpt-5.4">
          </label>
          <label>
            API key
            <input type="password" name="api_key" placeholder="{librarian_key_placeholder}">
          </label>
          <label>
            Provider timeout seconds
            <input type="number" name="request_timeout_secs" min="1" max="120" value="{request_timeout_secs}">
          </label>
          <label>
            Max concurrent runs
            <input type="number" name="max_concurrent_runs" min="1" max="32" value="{max_concurrent_runs}">
          </label>
          <label class="toggle">
            <input type="checkbox" name="action_requires_approval" value="true"{action_requires_approval_checked}>
            <span>Require admin or project-writer approval before executing project librarian actions</span>
          </label>
          <label class="toggle">
            <input type="checkbox" name="clear_api_key" value="true">
            <span>Clear saved API key</span>
          </label>
          <button type="submit">Save librarian config</button>
        </form>
        <form method="post" action="/ui/admin/librarian/test" class="inline-form">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Test saved provider config</button>
        </form>
        <form method="post" action="/ui/admin/librarian/rotate-key">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Rotate API key
            <input type="password" name="api_key" placeholder="Paste new provider secret" required>
          </label>
          <button type="submit">Rotate saved API key</button>
        </form>
        <div class="meta-stack">
          <p><strong>Status</strong><br>{librarian_status}</p>
          <p><strong>Scope</strong><br>Read-only, one project per request, Lore-native context only.</p>
          <p><strong>Limits</strong><br>{request_timeout_secs}s timeout, {max_concurrent_runs} concurrent runs max.</p>
          {provider_status_html}
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Git export</h2>
          <p>Export Lore’s native project files and recorded project history into a Git branch. This gives you off-server history and familiar recovery workflows without making Git the live storage engine.</p>
        </div>
        <form method="post" action="/ui/admin/git-export">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label class="toggle">
            <input type="checkbox" name="enabled" value="true"{git_export_enabled_checked}>
            <span>Enable Git export</span>
          </label>
          <label>
            Remote URL
            <input type="url" name="remote_url" value="{git_export_remote_url}" placeholder="https://github.com/org/repo.git">
          </label>
          <label>
            Branch
            <input type="text" name="branch" value="{git_export_branch}" placeholder="main">
          </label>
          <label>
            Token
            <input type="password" name="token" placeholder="{git_export_token_placeholder}">
          </label>
          <label>
            Commit author name
            <input type="text" name="author_name" value="{git_export_author_name}" placeholder="Lore">
          </label>
          <label>
            Commit author email
            <input type="email" name="author_email" value="{git_export_author_email}" placeholder="lore@example.com">
          </label>
          <label class="toggle">
            <input type="checkbox" name="auto_export" value="true"{git_export_auto_checked}>
            <span>Automatically export after project mutations</span>
          </label>
          <label class="toggle">
            <input type="checkbox" name="clear_token" value="true">
            <span>Clear saved token</span>
          </label>
          <button type="submit">Save Git export</button>
        </form>
        <form method="post" action="/ui/admin/git-export/sync" class="inline-form">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Run export now</button>
        </form>
        <div class="meta-stack">
          <p><strong>Status</strong><br>{git_export_state}</p>
          <p><strong>Mode</strong><br>{git_export_mode}</p>
          <p><strong>Remote</strong><br>{git_export_remote_label}</p>
          {git_export_status_html}
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Agent tokens</h2>
          <p>Create scoped agent tokens with per-project read or read_write access. Raw tokens are shown once and then only their hashes remain on disk.</p>
        </div>
        {latest_agent_token_html}
        <form method="post" action="/ui/admin/agent-tokens">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Token name
            <input type="text" name="name" placeholder="worker-alpha" required>
          </label>
          <label>
            Grants
            <textarea name="grants" placeholder="alpha.docs:read_write&#10;beta.docs:read"></textarea>
          </label>
          <button type="submit">Create agent token</button>
        </form>
        <div class="timeline">{agent_tokens_html}</div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>OIDC</h2>
          <p>Configure an OpenID Connect login flow that redirects the browser to your identity provider and then maps the returned identity onto an existing Lore user. Roles and admin flags still come from Lore.</p>
        </div>
        <form method="post" action="/ui/admin/oidc">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label class="toggle">
            <input type="checkbox" name="enabled" value="true"{oidc_enabled_checked}>
            <span>Enable OIDC login</span>
          </label>
          <label>
            Issuer URL
            <input type="url" name="issuer_url" value="{oidc_issuer_url}" placeholder="https://accounts.example.com">
          </label>
          <label>
            Client ID
            <input type="text" name="client_id" value="{oidc_client_id}" placeholder="lore-web">
          </label>
          <label>
            Client secret
            <input type="password" name="client_secret" placeholder="{oidc_secret_placeholder}">
          </label>
          <label>
            Callback path
            <input type="text" name="callback_path" value="{oidc_callback_path}" placeholder="/login/oidc/callback">
          </label>
          <label>
            Username claim
            <select name="username_claim">
              <option value="preferred_username"{oidc_preferred_username_selected}>preferred_username</option>
              <option value="email"{oidc_email_selected}>email</option>
              <option value="sub"{oidc_subject_selected}>sub</option>
            </select>
          </label>
          <label class="toggle">
            <input type="checkbox" name="clear_client_secret" value="true">
            <span>Clear saved OIDC client secret</span>
          </label>
          <button type="submit">Save OIDC config</button>
        </form>
        <div class="meta-stack">
          <p><strong>Status</strong><br>{oidc_status}</p>
          <p><strong>Redirect URI</strong><br>{oidc_redirect_uri}</p>
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Server updates</h2>
          <p>Check for new Lore server releases and apply updates. When automatic updates are enabled, Lore also checks on startup. You can always check and apply manually from here.</p>
        </div>
        <form method="post" action="/ui/admin/auto-update">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label class="toggle">
            <input type="checkbox" name="enabled" value="true"{auto_update_enabled_checked}>
            <span>Enable automatic server self-update on restart</span>
          </label>
          <label>
            GitHub repo
            <input type="text" name="github_repo" value="{auto_update_repo}" placeholder="{default_update_repo}" required>
          </label>
          <label>
            Confirm password (required when changing repo)
            <input type="password" name="confirm_password" autocomplete="current-password">
          </label>
          <button type="submit">Save auto update</button>
        </form>
        <form method="post" action="/ui/admin/auto-update/check" class="inline-form">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Check latest release now</button>
        </form>
        <div class="meta-stack">
          <p><strong>Status</strong><br>{auto_update_state}</p>
          <p><strong>Mode</strong><br>Updates replace the server binary and restart automatically. Can be applied here or on startup when enabled.</p>
          {auto_update_status_html}
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>External auth</h2>
          <p>Enable trusted reverse-proxy header auth to map an upstream authenticated username onto an existing local Lore user and role set. Keep this behind a proxy that strips and rewrites these headers.</p>
        </div>
        <form method="post" action="/ui/admin/external-auth">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label class="toggle">
            <input type="checkbox" name="enabled" value="true"{external_auth_enabled_checked}>
            <span>Enable trusted header auth</span>
          </label>
          <label>
            Username header
            <input type="text" name="username_header" value="{external_auth_username_header}" placeholder="x-forwarded-user" required>
          </label>
          <label>
            Shared secret header
            <input type="text" name="secret_header" value="{external_auth_secret_header}" placeholder="x-lore-proxy-auth" required>
          </label>
          <label>
            Shared secret value
            <input type="password" name="secret_value" placeholder="{external_auth_secret_placeholder}">
          </label>
          <label class="toggle">
            <input type="checkbox" name="clear_secret" value="true">
            <span>Clear saved external auth secret</span>
          </label>
          <button type="submit">Save external auth</button>
        </form>
        <div class="meta-stack">
          <p><strong>Status</strong><br>{external_auth_status}</p>
          <p><strong>Scope</strong><br>Maps a trusted proxy username onto an existing local Lore user. Roles and admin flags still come from Lore.</p>
        </div>
      </section>
    </section>

    <section class="layout admin-layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Create role</h2>
          <p>Enter one grant per line using project:permission where permission is read or read_write.</p>
        </div>
        <form method="post" action="/ui/admin/roles">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Role name
            <input type="text" name="name" placeholder="engineering-writers" required>
          </label>
          <label>
            Grants
            <textarea name="grants" placeholder="alpha.docs:read_write&#10;beta.docs:read"></textarea>
          </label>
          <button type="submit">Create role</button>
        </form>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Create user</h2>
          <p>Assign comma-separated role names. Admins can see everything and manage access.</p>
        </div>
        <form method="post" action="/ui/admin/users">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Username
            <input type="text" name="username" autocomplete="username" required>
          </label>
          <label>
            Password
            <input type="password" name="password" autocomplete="new-password" required>
          </label>
          <label>
            Roles
            <input type="text" name="roles" placeholder="engineering-writers,product-readers">
          </label>
          <label class="toggle">
            <input type="checkbox" name="is_admin" value="true">
            <span>Grant full admin access</span>
          </label>
          <button type="submit">Create user</button>
        </form>
      </section>
    </section>

    <section class="layout admin-layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Roles</h2>
          <p>These grants define project-level visibility and editing for human users.</p>
        </div>
        <div class="timeline">{roles_html}</div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Users</h2>
          <p>Passwords are stored as Argon2 hashes on disk, never as plaintext.</p>
        </div>
        <div class="timeline">{users_html}</div>
      </section>
    </section>

    <section class="layout admin-layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Librarian audit</h2>
          <p>Recent grounded runs across projects, including actor, status, source blocks, and pending approvals. <a href="/ui/admin/audit">Open full audit</a>.</p>
        </div>
        <div class="timeline">{pending_actions_html}</div>
        <div class="timeline">{audit_html}</div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Auth and admin audit</h2>
          <p>Recent sign-in, sign-out, configuration, and access-management changes. <a href="/ui/admin/audit">Open full audit</a>.</p>
        </div>
        <div class="timeline">{auth_audit_html}</div>
      </section>
    </section>
  </main>
</body>
</html>"#,
        styles = shared_styles(theme),
        username = escape_text(username),
        csrf_token = escape_attribute(csrf_token),
        flash_html = flash_html,
        http_selected = if matches!(server_config.external_scheme, ExternalScheme::Http) {
            " selected"
        } else {
            ""
        },
        https_selected = if matches!(server_config.external_scheme, ExternalScheme::Https) {
            " selected"
        } else {
            ""
        },
        theme_options = render_theme_options(Some(server_config.default_theme), false),
        external_host = escape_attribute(&server_config.external_host),
        external_port = server_config.external_port,
        setup_url = escape_text(&server_config.setup_url()),
        setup_text_url = escape_text(&server_config.setup_text_url()),
        setup_instruction = escape_text(setup_instruction),
        librarian_endpoint_url = escape_attribute(&librarian_config.endpoint_url),
        librarian_model = escape_attribute(&librarian_config.model),
        librarian_key_placeholder = if librarian_config.has_api_key() {
            "Stored. Leave blank to preserve."
        } else {
            "Paste a provider secret"
        },
        request_timeout_secs = librarian_config.request_timeout_secs,
        max_concurrent_runs = librarian_config.max_concurrent_runs,
        action_requires_approval_checked = if librarian_config.action_requires_approval {
            " checked"
        } else {
            ""
        },
        librarian_status = if librarian_config.is_configured() {
            "Configured"
        } else {
            "Not configured"
        },
        git_export_enabled_checked = if git_export_config.enabled {
            " checked"
        } else {
            ""
        },
        git_export_remote_url = escape_attribute(&git_export_config.remote_url),
        git_export_branch = escape_attribute(&git_export_config.branch),
        git_export_author_name = escape_attribute(&git_export_config.author_name),
        git_export_author_email = escape_attribute(&git_export_config.author_email),
        git_export_token_placeholder = if git_export_config.has_token() {
            "Stored. Leave blank to preserve."
        } else {
            "Paste a GitHub or Git token"
        },
        git_export_auto_checked = if git_export_config.auto_export {
            " checked"
        } else {
            ""
        },
        git_export_state = if git_export_config.is_configured() {
            "Configured"
        } else if git_export_config.enabled {
            "Enabled but incomplete"
        } else {
            "Disabled"
        },
        git_export_mode = if git_export_config.auto_export {
            "Automatic after writes, plus manual sync"
        } else {
            "Manual sync only"
        },
        git_export_remote_label = if git_export_config.remote_url.trim().is_empty() {
            "Not configured".to_string()
        } else {
            escape_text(&git_export_config.remote_url)
        },
        git_export_status_html = git_export_status_html,
        external_auth_enabled_checked = if external_auth_config.enabled {
            " checked"
        } else {
            ""
        },
        external_auth_username_header = escape_attribute(&external_auth_config.username_header),
        external_auth_secret_header = escape_attribute(&external_auth_config.secret_header),
        external_auth_secret_placeholder = if external_auth_config.has_secret() {
            "Stored. Leave blank to preserve."
        } else {
            "Paste proxy shared secret"
        },
        external_auth_status = if external_auth_config.is_configured() {
            "Configured"
        } else if external_auth_config.enabled {
            "Enabled but incomplete"
        } else {
            "Disabled"
        },
        oidc_enabled_checked = if oidc_config.enabled { " checked" } else { "" },
        oidc_issuer_url = escape_attribute(&oidc_config.issuer_url),
        oidc_client_id = escape_attribute(&oidc_config.client_id),
        oidc_callback_path = escape_attribute(&oidc_config.callback_path),
        oidc_secret_placeholder = if oidc_config.has_client_secret() {
            "Stored. Leave blank to preserve."
        } else {
            "Paste OIDC client secret"
        },
        oidc_preferred_username_selected =
            if oidc_config.username_claim.as_str() == "preferred_username" {
                " selected"
            } else {
                ""
            },
        oidc_email_selected = if oidc_config.username_claim.as_str() == "email" {
            " selected"
        } else {
            ""
        },
        oidc_subject_selected = if oidc_config.username_claim.as_str() == "sub" {
            " selected"
        } else {
            ""
        },
        oidc_status = if oidc_config.is_configured() {
            "Configured"
        } else if oidc_config.enabled {
            "Enabled but incomplete"
        } else {
            "Disabled"
        },
        oidc_redirect_uri = escape_text(&format!(
            "{}{}",
            server_config.base_url(),
            oidc_config.callback_path
        )),
        auto_update_enabled_checked = if auto_update_config.enabled {
            " checked"
        } else {
            ""
        },
        auto_update_repo = escape_attribute(&auto_update_config.github_repo),
        default_update_repo = escape_attribute(DEFAULT_UPDATE_REPO),
        auto_update_state = if auto_update_config.enabled {
            "Enabled on startup"
        } else {
            "Disabled"
        },
        auto_update_status_html = auto_update_status_html,
        provider_status_html = provider_status_html,
        latest_agent_token_html = latest_agent_token_html,
        agent_tokens_html = agent_tokens_html,
        roles_html = roles_html,
        users_html = users_html,
        pending_actions_html = pending_actions_html,
        audit_html = audit_html,
        auth_audit_html = auth_audit_html,
    )
}

pub fn render_setup_page(config: &ServerConfig, setup_instruction: &str) -> String {
    let base_url = config.base_url();
    let setup_text_url = config.setup_text_url();
    let mcp_url = config.mcp_url();
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lore setup</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Lore setup</p>
      <h1>Agent integration instructions</h1>
      <p class="subtitle">This page is generated by Lore using the external address configured by the administrator. Use it to decide whether your agent should integrate over HTTP or Lore's native MCP endpoint for this runtime.</p>
    </section>

    <section class="layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Server address</h2>
          <p>Lore expects agents to treat this server as the shared project memory endpoint.</p>
        </div>
        <div class="timeline">
          <article class="block">
            <div class="block-meta">
              <span class="pill">Base URL</span>
            </div>
            <div class="block-body"><pre>{base_url}</pre></div>
          </article>
          <article class="block">
            <div class="block-meta">
              <span class="pill">Plain text setup</span>
            </div>
            <div class="block-body"><pre>{setup_text_url}</pre></div>
          </article>
          <article class="block">
            <div class="block-meta">
              <span class="pill">MCP endpoint</span>
            </div>
            <div class="block-body"><pre>{mcp_url}</pre></div>
          </article>
        </div>
      </section>

      <aside class="stack">
        <section class="panel">
          <div class="panel-header">
            <h2>When to use HTTP</h2>
            <p>Choose HTTP if the agent runs as a command, shell wrapper, CI task, cron job, or any runtime that can make ordinary web requests but does not mount MCP servers cleanly.</p>
          </div>
        </section>
        <section class="panel">
          <div class="panel-header">
            <h2>When to use MCP</h2>
            <p>Choose MCP when the host runtime natively supports MCP tool servers and you want Lore to appear as a discoverable tool server. Lore exposes familiar grep, read, edit, move, and delete tools over the MCP endpoint.</p>
          </div>
        </section>
      </aside>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2>Copy-paste for your agent</h2>
        <p>Give the block below to the agent, or tell it to open the plain-text setup URL directly.</p>
      </div>
      <textarea readonly>{setup_instruction}</textarea>
    </section>
  </main>
</body>
</html>"#,
        styles = shared_styles(config.default_theme),
        base_url = escape_text(&base_url),
        setup_text_url = escape_text(&setup_text_url),
        mcp_url = escape_text(&mcp_url),
        setup_instruction = escape_text(setup_instruction),
    )
}

pub fn render_settings_page(
    theme: UiTheme,
    username: &str,
    csrf_token: &str,
    selected_theme: Option<UiTheme>,
    server_default_theme: UiTheme,
    is_admin: bool,
    flash: Option<&str>,
) -> String {
    let flash_html = flash_message(flash);
    let admin_link = if is_admin {
        r#"<a href="/ui/admin">Admin</a>"#.to_string()
    } else {
        String::new()
    };
    let current_label = selected_theme
        .unwrap_or(server_default_theme)
        .display_name();
    let preference_label = selected_theme
        .map(UiTheme::display_name)
        .unwrap_or("Use server default");
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lore settings</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Lore settings</p>
      <h1>Appearance</h1>
      <p class="subtitle">Signed in as {username}. Choose a personal theme override, or fall back to the server default for shared pages like login and setup.</p>
      <div class="hero-actions">
        <a class="primary" href="/ui">Projects</a>
        {admin_link}
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Sign out</button>
        </form>
      </div>
      {flash_html}
    </section>

    <section class="layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Theme preference</h2>
          <p>Your current effective theme is {current_label}. The server default is {server_default_label}.</p>
        </div>
        <form method="post" action="/ui/settings/theme">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Theme
            <select name="theme">
              {theme_options}
            </select>
          </label>
          <button type="submit">Save theme</button>
        </form>
        <div class="meta-stack">
          <p><strong>Saved preference</strong><br>{preference_label}</p>
          <p><strong>Server default</strong><br>{server_default_label}</p>
        </div>
      </section>
      <section class="panel">
        <div class="panel-header">
          <h2>Built-in themes</h2>
          <p>Parchment is warm and editorial. Graphite is low-glare and dense. Signal is crisper and more technical.</p>
        </div>
        <div class="timeline">
          {theme_preview_cards}
        </div>
      </section>
    </section>
  </main>
</body>
</html>"#,
        styles = shared_styles(theme),
        username = escape_text(username),
        admin_link = admin_link,
        csrf_token = escape_attribute(csrf_token),
        flash_html = flash_html,
        current_label = escape_text(current_label),
        preference_label = escape_text(preference_label),
        server_default_label = escape_text(server_default_theme.display_name()),
        theme_options = render_theme_options(selected_theme, true),
        theme_preview_cards = render_theme_preview_cards(selected_theme, server_default_theme),
    )
}

pub fn render_admin_audit_page(
    theme: UiTheme,
    username: &str,
    csrf_token: &str,
    runs: &[UiLibrarianAnswer],
    pending_actions: &[UiPendingLibrarianAction],
    auth_audit: &[UiAuditEvent],
) -> String {
    let runs_html = if runs.is_empty() {
        "<p class=\"hint padded\">No librarian runs recorded yet.</p>".to_string()
    } else {
        runs.iter()
            .map(render_librarian_answer)
            .collect::<Vec<_>>()
            .join("")
    };
    let pending_html = if pending_actions.is_empty() {
        "<p class=\"hint padded\">No pending project librarian actions.</p>".to_string()
    } else {
        pending_actions
            .iter()
            .map(|action| render_pending_librarian_action(action, None, csrf_token, false))
            .collect::<Vec<_>>()
            .join("")
    };
    let auth_html = if auth_audit.is_empty() {
        "<p class=\"hint padded\">No auth or admin audit events recorded yet.</p>".to_string()
    } else {
        auth_audit
            .iter()
            .map(render_audit_event)
            .collect::<Vec<_>>()
            .join("")
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lore admin audit</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Lore admin audit</p>
      <h1>Librarian audit</h1>
      <p class="subtitle">Signed in as {username}. Review pending actions, completed runs, errors, and approval chains across projects.</p>
      <div class="hero-actions">
        <a class="primary" href="/ui/admin">Admin</a>
        <a href="/ui">Projects</a>
        <a href="/ui/settings">Settings</a>
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Sign out</button>
        </form>
      </div>
    </section>
    <section class="layout admin-layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Pending actions</h2>
          <p>These plans are waiting for explicit project-writer approval.</p>
        </div>
        <div class="timeline">{pending_html}</div>
      </section>
      <section class="panel">
        <div class="panel-header">
          <h2>Recorded runs</h2>
          <p>Runs include answers, action requests, executed project actions, rate limits, and rejections.</p>
        </div>
        <div class="timeline">{runs_html}</div>
      </section>
      <section class="panel">
        <div class="panel-header">
          <h2>Auth and admin events</h2>
          <p>Sign-in, sign-out, configuration, token, role, and user-management changes.</p>
        </div>
        <div class="timeline">{auth_html}</div>
      </section>
    </section>
  </main>
</body>
</html>"#,
        styles = shared_styles(theme),
        username = escape_text(username),
        csrf_token = escape_attribute(csrf_token),
        pending_html = pending_html,
        runs_html = runs_html,
        auth_html = auth_html,
    )
}

pub fn render_project_audit_page(
    theme: UiTheme,
    project: &ProjectName,
    username: &str,
    is_admin: bool,
    can_write: bool,
    csrf_token: &str,
    runs: &[UiLibrarianAnswer],
    pending_actions: &[UiPendingLibrarianAction],
) -> String {
    let admin_link = if is_admin {
        r#"<a href="/ui/admin">Admin</a>"#.to_string()
    } else {
        String::new()
    };
    let runs_html = if runs.is_empty() {
        "<p class=\"hint padded\">No librarian runs recorded for this project yet.</p>".to_string()
    } else {
        runs.iter()
            .map(render_librarian_answer)
            .collect::<Vec<_>>()
            .join("")
    };
    let pending_html = if pending_actions.is_empty() {
        "<p class=\"hint padded\">No pending project librarian actions.</p>".to_string()
    } else {
        pending_actions
            .iter()
            .map(|action| {
                render_pending_librarian_action(action, Some(project), csrf_token, can_write)
            })
            .collect::<Vec<_>>()
            .join("")
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lore audit · {project}</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Lore project audit</p>
      <h1>{project}</h1>
      <p class="subtitle">Signed in as {username}. Review grounded answer runs, project-action chains, and pending approvals for this project.</p>
      <div class="hero-actions">
        <a class="primary" href="/ui/{project}">Back to project</a>
        <a href="/ui/settings">Settings</a>
        {admin_link}
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Sign out</button>
        </form>
      </div>
    </section>
    <section class="layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Pending actions</h2>
          <p>When approval is enabled, actions stay here until a project writer approves or rejects them.</p>
        </div>
        <div class="timeline">{pending_html}</div>
      </section>
      <section class="panel">
        <div class="panel-header">
          <h2>Recorded runs</h2>
          <p>This includes answer runs, action requests, approvals, rejections, and execution results.</p>
        </div>
        <div class="timeline">{runs_html}</div>
      </section>
    </section>
  </main>
</body>
</html>"#,
        styles = shared_styles(theme),
        project = escape_text(project.as_str()),
        username = escape_text(username),
        admin_link = admin_link,
        csrf_token = escape_attribute(csrf_token),
        pending_html = pending_html,
        runs_html = runs_html,
    )
}

pub fn render_project_history_page(
    theme: UiTheme,
    project: &ProjectName,
    username: &str,
    is_admin: bool,
    can_write: bool,
    csrf_token: &str,
    versions: &[UiProjectVersion],
) -> String {
    let admin_link = if is_admin {
        r#"<a href="/ui/admin">Admin</a>"#.to_string()
    } else {
        String::new()
    };
    let history_html = if versions.is_empty() {
        "<p class=\"hint padded\">No project versions recorded yet.</p>".to_string()
    } else {
        versions
            .iter()
            .map(|version| render_project_version(project, csrf_token, can_write, version))
            .collect::<Vec<_>>()
            .join("")
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lore history · {project}</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Lore project history</p>
      <h1>{project}</h1>
      <p class="subtitle">Signed in as {username}. Review reversible project mutations, including librarian edits and API writes, in the order they were recorded.</p>
      <div class="hero-actions">
        <a class="primary" href="/ui/{project}">Back to project</a>
        <a href="/ui/{project}/audit">Audit</a>
        <a href="/ui/settings">Settings</a>
        {admin_link}
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Sign out</button>
        </form>
      </div>
    </section>
    <section class="panel">
      <div class="panel-header">
        <h2>Version history</h2>
        <p>Each recorded version captures exact before/after block snapshots. Revert creates a new version rather than silently deleting history.</p>
      </div>
      <div class="timeline">{history_html}</div>
    </section>
  </main>
</body>
</html>"#,
        styles = shared_styles(theme),
        project = escape_text(project.as_str()),
        username = escape_text(username),
        admin_link = admin_link,
        csrf_token = escape_attribute(csrf_token),
        history_html = history_html,
    )
}

pub fn render_project_page(
    theme: UiTheme,
    project: &ProjectName,
    blocks: &[Block],
    all_blocks: &[Block],
    flash: Option<&str>,
    search: Option<&str>,
    search_block_type: Option<&str>,
    search_author: Option<&str>,
    search_since_days: Option<u32>,
    username: &str,
    can_write: bool,
    is_admin: bool,
    csrf_token: &str,
    librarian_answer: Option<&UiLibrarianAnswer>,
    librarian_history: &[UiLibrarianAnswer],
    pending_actions: &[UiPendingLibrarianAction],
) -> String {
    let flash_html = flash_message(flash);
    let search_value = search.unwrap_or_default();
    let results_label = if search_value.is_empty() {
        format!(
            "{} block{} in sorted order.",
            blocks.len(),
            if blocks.len() == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "{} result{} for “{}”.",
            blocks.len(),
            if blocks.len() == 1 { "" } else { "s" },
            escape_text(search_value)
        )
    };
    let placement_options = render_after_options(all_blocks, None, None);
    let blocks_html = if blocks.is_empty() {
        r#"<section class="empty-state"><h2>No blocks yet</h2><p>Add the first block below to start the shared document.</p></section>"#.to_string()
    } else {
        blocks
            .iter()
            .map(|block| render_block(project, block, all_blocks, can_write, csrf_token))
            .collect::<Vec<_>>()
            .join("")
    };
    let admin_link = if is_admin {
        r#"<a href="/ui/admin">Admin</a>"#.to_string()
    } else {
        String::new()
    };
    let librarian_panel = render_librarian_panel(
        project,
        csrf_token,
        can_write,
        librarian_answer,
        librarian_history,
        pending_actions,
    );
    let composer = if can_write {
        format!(
            r#"<section class="panel composer" id="composer">
  <div class="panel-header">
    <h2>Add block</h2>
    <p>You can write anywhere in this project because your role grants project-level write access.</p>
  </div>
  <form method="post" action="/ui/{project}/blocks" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <label>
      Type
      <select name="block_type">
        <option value="markdown">Markdown</option>
        <option value="svg">SVG</option>
        <option value="html">HTML</option>
        <option value="image">Image</option>
      </select>
    </label>
    <label>
      Place after
      <select name="after_block_id">
        {placement_options}
      </select>
    </label>
    <label>
      Content or note
      <textarea name="content" placeholder="Write markdown, paste an SVG, provide an image URL, or add a note for an uploaded image."></textarea>
    </label>
    <label>
      Upload image
      <input type="file" name="image_file" accept="image/*">
    </label>
    <button type="submit">Add block</button>
  </form>
  <p class="hint">HTML is displayed as escaped source for now. Uploaded images are stored on disk and served from Lore only to authenticated users with project access.</p>
</section>"#,
            project = escape_attribute(project.as_str()),
            csrf_token = escape_attribute(csrf_token),
            placement_options = placement_options,
        )
    } else {
        r#"<section class="panel composer"><div class="panel-header"><h2>Read-only access</h2><p>Your role allows viewing this project but not creating, editing, moving, or deleting blocks.</p></div></section>"#.to_string()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lore · {project}</title>
  <style>{styles}</style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Lore project</p>
      <h1>{project}</h1>
      <p class="subtitle">Signed in as {username}. Human access is project-scoped; agent ownership remains a separate rule at the API layer.</p>
      <div class="hero-actions">
        <a class="primary" href="/ui">Projects</a>
        <a href="/ui/settings">Settings</a>
        {admin_link}
        <a href="/ui/{project}/audit">Audit</a>
        <a href="/ui/{project}/history">History</a>
        <form method="post" action="/logout">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit">Sign out</button>
        </form>
      </div>
      <form class="searchbar" method="get" action="/ui/{project}">
        <input type="search" name="q" value="{search_value}" placeholder="Search content, author, type, or order">
        <select name="block_type">
          <option value=""{search_any_type}>Any type</option>
          <option value="markdown"{search_markdown}>Markdown</option>
          <option value="svg"{search_svg}>SVG</option>
          <option value="html"{search_html}>HTML</option>
          <option value="image"{search_image}>Image</option>
        </select>
        <input type="search" name="author" value="{search_author}" placeholder="Author contains">
        <input type="number" name="since_days" min="1" value="{search_since_days}" placeholder="Days">
        <button type="submit">Search</button>
      </form>
      {flash_html}
    </section>

    <section class="layout">
      <section class="panel" id="document">
        <div class="panel-header">
          <h2>Document</h2>
          <p>{results_label}</p>
        </div>
        <div class="timeline">{blocks_html}</div>
      </section>
      <aside class="stack">{librarian_panel}{composer}</aside>
    </section>
  </main>
</body>
</html>"#,
        styles = shared_styles(theme),
        project = escape_text(project.as_str()),
        username = escape_text(username),
        admin_link = admin_link,
        csrf_token = escape_attribute(csrf_token),
        search_value = escape_attribute(search_value),
        search_any_type = if search_block_type.is_none() {
            " selected"
        } else {
            ""
        },
        search_markdown = selected(search_block_type, "markdown"),
        search_svg = selected(search_block_type, "svg"),
        search_html = selected(search_block_type, "html"),
        search_image = selected(search_block_type, "image"),
        search_author = escape_attribute(search_author.unwrap_or_default()),
        search_since_days = search_since_days.map(|v| v.to_string()).unwrap_or_default(),
        flash_html = flash_html,
        results_label = results_label,
        blocks_html = blocks_html,
        librarian_panel = librarian_panel,
        composer = composer,
    )
}

fn render_librarian_panel(
    project: &ProjectName,
    csrf_token: &str,
    can_write: bool,
    librarian_answer: Option<&UiLibrarianAnswer>,
    librarian_history: &[UiLibrarianAnswer],
    pending_actions: &[UiPendingLibrarianAction],
) -> String {
    let answer_html = librarian_answer
        .map(render_librarian_answer)
        .unwrap_or_else(|| {
            "<p class=\"hint\">Ask for a summary, explanation, or grounded answer about this project. Lore sends only this project's retrieved blocks to the configured answer librarian.</p>".to_string()
        });
    let question_value = librarian_answer
        .map(|answer| escape_attribute(&answer.question))
        .unwrap_or_default();
    let history_html = if librarian_history.is_empty() {
        "<p class=\"hint\">No previous librarian answers for this project yet.</p>".to_string()
    } else {
        librarian_history
            .iter()
            .map(|answer| render_librarian_history_item(project, csrf_token, answer))
            .collect::<Vec<_>>()
            .join("")
    };
    let pending_html = if pending_actions.is_empty() {
        "<p class=\"hint\">No pending project librarian actions.</p>".to_string()
    } else {
        pending_actions
            .iter()
            .map(|action| {
                render_pending_librarian_action(action, Some(project), csrf_token, can_write)
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let action_form = if can_write {
        format!(
            r#"<form method="post" action="/ui/{project}/librarian/action">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <label>
      Project action
      <textarea name="instruction" placeholder="Reorganise the release notes into a summary block after the current introduction." required></textarea>
    </label>
    <label>
      Limit to block type
      <select name="block_type">
        <option value="">Any type</option>
        <option value="markdown">Markdown</option>
        <option value="svg">SVG</option>
        <option value="html">HTML</option>
        <option value="image">Image</option>
      </select>
    </label>
    <label>
      Author contains
      <input type="text" name="author" placeholder="agent-alpha or alice">
    </label>
    <label>
      Only last N days
      <input type="number" name="since_days" min="1" placeholder="30">
    </label>
    <label>
      Max source blocks
      <input type="number" name="max_sources" min="1" max="10" placeholder="10">
    </label>
    <label>
      Context radius
      <input type="number" name="around" min="0" max="4" placeholder="2">
    </label>
    <button type="submit">Run project librarian action</button>
  </form>"#,
            project = escape_attribute(project.as_str()),
            csrf_token = escape_attribute(csrf_token),
        )
    } else {
        "<p class=\"hint\">Project librarian actions require project write access.</p>".to_string()
    };

    format!(
        r#"<section class="panel composer">
  <div class="panel-header">
    <h2>Answer librarian</h2>
    <p>Single-project, read-only, and grounded only in Lore blocks from this project.</p>
  </div>
  <form method="post" action="/ui/{project}/librarian">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <label>
      Question
      <textarea name="question" placeholder="Summarise the current decisions in this project." required>{question_value}</textarea>
    </label>
    <label>
      Limit to block type
      <select name="block_type">
        <option value="">Any type</option>
        <option value="markdown">Markdown</option>
        <option value="svg">SVG</option>
        <option value="html">HTML</option>
        <option value="image">Image</option>
      </select>
    </label>
    <label>
      Author contains
      <input type="text" name="author" placeholder="agent-alpha or alice">
    </label>
    <label>
      Only last N days
      <input type="number" name="since_days" min="1" placeholder="30">
    </label>
    <label>
      Max source blocks
      <input type="number" name="max_sources" min="1" max="10" placeholder="10">
    </label>
    <label>
      Context radius
      <input type="number" name="around" min="0" max="4" placeholder="2">
    </label>
    <button type="submit">Ask librarian</button>
  </form>
  <div class="stack">
    <p class="hint">Project librarian actions are explicit, single-project, and limited to Lore block operations only.</p>
    {action_form}
  </div>
  {answer_html}
  <div class="stack">
    <p class="hint">Recent project-only librarian history</p>
    {history_html}
  </div>
  <div class="stack">
    <p class="hint">Pending project librarian actions</p>
    {pending_html}
  </div>
</section>"#,
        project = escape_attribute(project.as_str()),
        csrf_token = escape_attribute(csrf_token),
        question_value = question_value,
        action_form = action_form,
        answer_html = answer_html,
        history_html = history_html,
        pending_html = pending_html,
    )
}

fn render_librarian_answer(answer: &UiLibrarianAnswer) -> String {
    let kind = match answer.kind {
        LibrarianRunKind::Answer => "Answer librarian",
        LibrarianRunKind::ActionRequest => "Action request",
        LibrarianRunKind::ProjectAction => "Project librarian action",
    };
    let status = match answer.status {
        LibrarianRunStatus::Success => "success",
        LibrarianRunStatus::Error => "error",
        LibrarianRunStatus::RateLimited => "rate limited",
        LibrarianRunStatus::PendingApproval => "pending approval",
        LibrarianRunStatus::Rejected => "rejected",
    };
    let answer_body = answer
        .answer
        .as_deref()
        .map(render_markdown)
        .unwrap_or_else(|| {
            format!(
                "<p>{}</p>",
                escape_text(answer.error.as_deref().unwrap_or("No answer returned."))
            )
        });
    let context_html = if answer.context_blocks.is_empty() {
        "<p class=\"hint\">No project blocks were available to ground this answer.</p>".to_string()
    } else {
        let items = answer
            .context_blocks
            .iter()
            .map(|block| {
                format!(
                    r#"<li><span class="meta-code">{}</span> {}</li>"#,
                    escape_text(block.id.as_str()),
                    escape_text(&truncate_single_line(&block.content, 64))
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(r#"<ul class="grant-list">{items}</ul>"#)
    };
    let operations_html = if answer.operations.is_empty() {
        String::new()
    } else {
        let items = answer
            .operations
            .iter()
            .map(|operation| {
                let label = match operation.operation_type {
                    ProjectLibrarianOperationType::CreateBlock => "create",
                    ProjectLibrarianOperationType::UpdateBlock => "update",
                    ProjectLibrarianOperationType::MoveBlock => "move",
                    ProjectLibrarianOperationType::DeleteBlock => "delete",
                };
                let target = operation
                    .block_id
                    .as_ref()
                    .map(|id| id.as_str().to_string())
                    .unwrap_or_else(|| "new block".to_string());
                let detail = operation
                    .content_preview
                    .as_deref()
                    .map(escape_text)
                    .unwrap_or_default();
                format!(
                    r#"<li><span class="meta-code">{}</span> {} {}</li>"#,
                    escape_text(label),
                    escape_text(&target),
                    detail
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(r#"<p class="hint">Executed operations:</p><ul class="grant-list">{items}</ul>"#)
    };
    let parent_html = answer
        .parent_run_id
        .as_deref()
        .map(|id| format!("<p class=\"hint\">Parent run: {}</p>", escape_text(id)))
        .unwrap_or_default();
    let run_meta = format!("<p class=\"hint\">Run id: {}</p>", escape_text(&answer.id));
    let project_html = answer
        .project
        .as_deref()
        .map(|project| format!("<p class=\"hint\">Project: {}</p>", escape_text(project)))
        .unwrap_or_default();

    format!(
        r#"<div class="callout">
  <p><strong>{kind}</strong><br>{question}</p>
  <p class="hint">Grounded only in this project. Status: {status}. Asked {created_at}.</p>
  {project_html}
  {run_meta}
  <div class="block-body">{answer_body}</div>
  {operations_html}
  <p class="hint">Grounded with these blocks:</p>
  {context_html}
  {parent_html}
</div>"#,
        kind = escape_text(kind),
        question = escape_text(&answer.question),
        status = escape_text(status),
        created_at = escape_text(&format_timestamp(answer.created_at)),
        project_html = project_html,
        run_meta = run_meta,
        answer_body = answer_body,
        operations_html = operations_html,
        context_html = context_html,
        parent_html = parent_html,
    )
}

fn render_pending_librarian_action(
    action: &UiPendingLibrarianAction,
    project: Option<&ProjectName>,
    csrf_token: &str,
    can_write: bool,
) -> String {
    let actor_label = match action.actor.kind {
        LibrarianActorKind::User => "user",
        LibrarianActorKind::Agent => "agent",
    };
    let operations_html = if action.operations.is_empty() {
        "<p class=\"hint\">No operations proposed.</p>".to_string()
    } else {
        let items = action
            .operations
            .iter()
            .map(|operation| {
                let label = match operation.operation_type {
                    ProjectLibrarianOperationType::CreateBlock => "create",
                    ProjectLibrarianOperationType::UpdateBlock => "update",
                    ProjectLibrarianOperationType::MoveBlock => "move",
                    ProjectLibrarianOperationType::DeleteBlock => "delete",
                };
                let target = operation
                    .block_id
                    .as_ref()
                    .map(|id| id.as_str().to_string())
                    .unwrap_or_else(|| "new block".to_string());
                format!(
                    r#"<li><span class="meta-code">{}</span> {}</li>"#,
                    escape_text(label),
                    escape_text(&target)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(r#"<ul class="grant-list">{items}</ul>"#)
    };
    let sources_html = if action.context_blocks.is_empty() {
        "<p class=\"hint\">No source blocks captured.</p>".to_string()
    } else {
        let items = action
            .context_blocks
            .iter()
            .map(|block| {
                format!(
                    r#"<li><span class="meta-code">{}</span> {}</li>"#,
                    escape_text(block.id.as_str()),
                    escape_text(&truncate_single_line(&block.content, 64))
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(r#"<ul class="grant-list">{items}</ul>"#)
    };
    let actions_html = if let Some(project) = project {
        if can_write {
            format!(
                r#"<div class="inline-form">
  <form method="post" action="/ui/{project}/librarian/action/{id}/approve">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <button type="submit">Approve and execute</button>
  </form>
  <form method="post" action="/ui/{project}/librarian/action/{id}/reject">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <button class="danger" type="submit">Reject</button>
  </form>
</div>"#,
                project = escape_attribute(project.as_str()),
                id = escape_attribute(&action.id),
                csrf_token = escape_attribute(csrf_token),
            )
        } else {
            "<p class=\"hint\">You can view this pending action, but only project writers can approve or reject it.</p>".to_string()
        }
    } else {
        String::new()
    };
    let project_html = action
        .project
        .as_deref()
        .map(|project| format!("<p class=\"hint\">Project: {}</p>", escape_text(project)))
        .unwrap_or_default();
    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">Pending action</span>
    <span>{created_at}</span>
    <span>{actor_label} {actor_name}</span>
  </div>
  {project_html}
  <p><strong>{instruction}</strong></p>
  <p>{summary}</p>
  <p class="hint">Pending id: {pending_id}. Parent run: {parent_run}. Pending run: {pending_run}.</p>
  <p class="hint">Proposed operations:</p>
  {operations_html}
  <p class="hint">Grounded with these blocks:</p>
  {sources_html}
  {actions_html}
</article>"#,
        created_at = escape_text(&format_timestamp(action.created_at)),
        actor_label = escape_text(actor_label),
        actor_name = escape_text(action.actor.name.as_str()),
        project_html = project_html,
        instruction = escape_text(&action.instruction),
        summary = escape_text(&action.summary),
        pending_id = escape_text(&action.id),
        parent_run = escape_text(&action.parent_run_id),
        pending_run = escape_text(&action.pending_run_id),
        operations_html = operations_html,
        sources_html = sources_html,
        actions_html = actions_html,
    )
}

fn render_audit_event(event: &UiAuditEvent) -> String {
    let actor_kind = match event.actor.kind {
        AuditActorKind::User => "user",
        AuditActorKind::ExternalAuth => "external auth",
        AuditActorKind::Oidc => "oidc",
        AuditActorKind::System => "system",
    };
    let target_html = event
        .target
        .as_deref()
        .map(|value| format!("<p><strong>Target:</strong> {}</p>", escape_text(value)))
        .unwrap_or_default();
    let detail_html = event
        .detail
        .as_deref()
        .map(|value| format!("<p>{}</p>", escape_text(value)))
        .unwrap_or_default();
    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">{actor_kind}</span>
    <span>{created_at}</span>
  </div>
  <div class="block-body">
    <p><strong>{action}</strong></p>
    <p><strong>Actor:</strong> {actor}</p>
    {target_html}
    {detail_html}
  </div>
</article>"#,
        actor_kind = escape_text(actor_kind),
        created_at = escape_text(&format_timestamp(event.created_at)),
        action = escape_text(&event.action),
        actor = escape_text(&event.actor.name),
        target_html = target_html,
        detail_html = detail_html,
    )
}

fn render_project_version(
    project: &ProjectName,
    csrf_token: &str,
    can_write: bool,
    version: &UiProjectVersion,
) -> String {
    let actor_label = match version.actor.kind {
        ProjectVersionActorKind::User => "user",
        ProjectVersionActorKind::Agent => "agent",
        ProjectVersionActorKind::System => "system",
    };
    let operations_html = if version.operations.is_empty() {
        "<p class=\"hint\">No block operations recorded.</p>".to_string()
    } else {
        version
            .operations
            .iter()
            .map(render_project_version_operation)
            .collect::<Vec<_>>()
            .join("")
    };
    let git_html = version
        .git_commit
        .as_deref()
        .map(|commit| {
            format!(
                "<p class=\"hint\">Git commit: <span class=\"meta-code\">{}</span></p>",
                escape_text(commit)
            )
        })
        .unwrap_or_default();
    let export_error_html = version
        .git_export_error
        .as_deref()
        .map(|error| {
            format!(
                "<p class=\"hint\">Git export error: {}</p>",
                escape_text(error)
            )
        })
        .unwrap_or_default();
    let revert_html = if can_write && version.reverted_by_version_id.is_none() {
        format!(
            r#"<form method="post" action="/ui/{project}/history/{id}/revert">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <button type="submit">Revert this version</button>
</form>"#,
            project = escape_attribute(project.as_str()),
            id = escape_attribute(&version.id),
            csrf_token = escape_attribute(csrf_token),
        )
    } else if let Some(reverted_by) = &version.reverted_by_version_id {
        format!(
            "<p class=\"hint\">Already reverted by version <span class=\"meta-code\">{}</span>.</p>",
            escape_text(reverted_by)
        )
    } else {
        "<p class=\"hint\">You can view history, but only project writers can revert versions.</p>"
            .to_string()
    };
    let reverted_from_html = version
        .reverted_from_version_id
        .as_deref()
        .map(|id| {
            format!(
                "<p class=\"hint\">This version is a revert of <span class=\"meta-code\">{}</span>.</p>",
                escape_text(id)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">Version</span>
    <span>{created_at}</span>
    <span>{actor_label} {actor_name}</span>
  </div>
  <div class="block-body">
    <p><strong>{summary}</strong></p>
    <p class="hint">Version id: <span class="meta-code">{id}</span></p>
    {reverted_from_html}
    <div class="stack">{operations_html}</div>
    {git_html}
    {export_error_html}
    {revert_html}
  </div>
</article>"#,
        created_at = escape_text(&format_timestamp(version.created_at)),
        actor_label = escape_text(actor_label),
        actor_name = escape_text(&version.actor.name),
        summary = escape_text(&version.summary),
        id = escape_text(&version.id),
        reverted_from_html = reverted_from_html,
        operations_html = operations_html,
        git_html = git_html,
        export_error_html = export_error_html,
        revert_html = revert_html,
    )
}

fn render_project_version_operation(operation: &UiProjectVersionOperation) -> String {
    let label = match operation.operation_type {
        ProjectVersionOperationType::CreateBlock => "create",
        ProjectVersionOperationType::UpdateBlock => "update",
        ProjectVersionOperationType::MoveBlock => "move",
        ProjectVersionOperationType::DeleteBlock => "delete",
    };
    let fields_html = if operation.changed_fields.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"hint\">Changed: {}</p>",
            operation
                .changed_fields
                .iter()
                .map(|field| format!(r#"<span class="pill small">{}</span>"#, escape_text(field)))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    let metadata_html = render_project_version_metadata(operation);
    let previews_html = render_project_version_previews(operation);
    let diff_html = render_project_version_diff(operation);
    format!(
        r#"<section class="callout version-op">
  <div class="block-meta">
    <span class="pill small">{label}</span>
    <span class="meta-code">{block_id}</span>
  </div>
  {fields_html}
  {metadata_html}
  {previews_html}
  {diff_html}
</section>"#,
        label = escape_text(label),
        block_id = escape_text(&operation.block_id),
        fields_html = fields_html,
        metadata_html = metadata_html,
        previews_html = previews_html,
        diff_html = diff_html,
    )
}

fn render_project_version_metadata(operation: &UiProjectVersionOperation) -> String {
    let mut rows = Vec::new();
    push_version_metadata_row(
        &mut rows,
        "Type",
        operation.before_block_type.as_deref(),
        operation.after_block_type.as_deref(),
    );
    push_version_metadata_row(
        &mut rows,
        "Order",
        operation.before_order.as_deref(),
        operation.after_order.as_deref(),
    );
    push_version_metadata_row(
        &mut rows,
        "Media",
        operation.before_media_type.as_deref(),
        operation.after_media_type.as_deref(),
    );
    if rows.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="version-meta">{}</div>"#, rows.join(""))
    }
}

fn push_version_metadata_row(
    rows: &mut Vec<String>,
    label: &str,
    before: Option<&str>,
    after: Option<&str>,
) {
    let value = match (before, after) {
        (Some(left), Some(right)) if left != right => {
            format!(
                "{} <span class=\"meta-separator\">→</span> {}",
                escape_text(left),
                escape_text(right)
            )
        }
        (None, Some(right)) => format!(
            "(none) <span class=\"meta-separator\">→</span> {}",
            escape_text(right)
        ),
        (Some(left), None) => format!(
            "{} <span class=\"meta-separator\">→</span> (none)",
            escape_text(left)
        ),
        _ => return,
    };
    rows.push(format!(
        r#"<p><strong>{}</strong> {}</p>"#,
        escape_text(label),
        value
    ));
}

fn render_project_version_previews(operation: &UiProjectVersionOperation) -> String {
    let mut previews = Vec::new();
    if let Some(value) = operation.before_preview.as_deref() {
        previews.push(format!(
            r#"<p class="hint"><strong>Before:</strong> {}</p>"#,
            escape_text(value)
        ));
    }
    if let Some(value) = operation.after_preview.as_deref() {
        previews.push(format!(
            r#"<p class="hint"><strong>After:</strong> {}</p>"#,
            escape_text(value)
        ));
    }
    previews.join("")
}

fn render_project_version_diff(operation: &UiProjectVersionOperation) -> String {
    if operation.diff_lines.is_empty() {
        return String::new();
    }
    let lines = operation
        .diff_lines
        .iter()
        .map(|line| {
            let (class_name, prefix) = match line.kind {
                UiDiffLineKind::Added => ("diff-added", "+"),
                UiDiffLineKind::Removed => ("diff-removed", "-"),
                UiDiffLineKind::Context => ("diff-context", " "),
            };
            format!(
                r#"<div class="diff-line {}"><span class="diff-prefix">{}</span><span>{}</span></div>"#,
                class_name,
                escape_text(prefix),
                escape_text(&line.text)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<div class="diff-list"><p class="hint"><strong>Diff:</strong></p>{}</div>"#,
        lines
    )
}

fn render_librarian_history_item(
    project: &ProjectName,
    csrf_token: &str,
    answer: &UiLibrarianAnswer,
) -> String {
    let actor_html = answer
        .actor
        .as_ref()
        .map(|actor| {
            let label = match actor.kind {
                LibrarianActorKind::User => "user",
                LibrarianActorKind::Agent => "agent",
            };
            format!(
                "{} {}",
                escape_text(label),
                escape_text(actor.name.as_str())
            )
        })
        .unwrap_or_else(|| "unknown actor".to_string());
    let retry_form = format!(
        r#"<form method="post" action="/ui/{project}/{route}">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <input type="hidden" name="{field_name}" value="{question}">
  <button type="submit">{button_label}</button>
</form>"#,
        project = escape_attribute(project.as_str()),
        route = if matches!(answer.kind, LibrarianRunKind::ProjectAction) {
            "librarian/action"
        } else {
            "librarian"
        },
        csrf_token = escape_attribute(csrf_token),
        field_name = if matches!(answer.kind, LibrarianRunKind::ProjectAction) {
            "instruction"
        } else {
            "question"
        },
        question = escape_attribute(&answer.question),
        button_label = if matches!(answer.kind, LibrarianRunKind::ProjectAction) {
            "Run again"
        } else {
            "Ask again"
        },
    );

    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">Librarian</span>
    <span>{created_at}</span>
    <span>{actor}</span>
  </div>
  {answer_html}
  {retry_form}
</article>"#,
        created_at = escape_text(&format_timestamp(answer.created_at)),
        actor = actor_html,
        answer_html = render_librarian_answer(answer),
        retry_form = retry_form,
    )
}

fn render_role_card(role: &StoredRole, csrf_token: &str) -> String {
    let grants = role
        .grants
        .iter()
        .map(|grant| {
            format!(
                r#"<li><span class="meta-code">{}</span> <span class="pill small">{}</span></li>"#,
                escape_text(grant.project.as_str()),
                escape_text(match grant.permission {
                    ProjectPermission::Read => "read",
                    ProjectPermission::ReadWrite => "read_write",
                })
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">{}</span>
    <span>{}</span>
  </div>
  <ul class="grant-list">{}</ul>
  <details>
    <summary>Edit role</summary>
    <form method="post" action="/ui/admin/roles/{}">
      <input type="hidden" name="csrf_token" value="{}">
      <label>
        Grants
        <textarea name="grants">{}</textarea>
      </label>
      <button type="submit">Update role</button>
    </form>
  </details>
</article>"#,
        escape_text(role.name.as_str()),
        escape_text(&format_timestamp(role.created_at)),
        grants,
        escape_attribute(role.name.as_str()),
        escape_attribute(csrf_token),
        escape_text(
            &role
                .grants
                .iter()
                .map(|grant| format!(
                    "{}:{}",
                    grant.project.as_str(),
                    match grant.permission {
                        ProjectPermission::Read => "read",
                        ProjectPermission::ReadWrite => "read_write",
                    }
                ))
                .collect::<Vec<_>>()
                .join("\n")
        )
    )
}

fn render_user_card(user: &UiUserSummary, csrf_token: &str) -> String {
    let roles = if user.role_names.is_empty() {
        "<li>No assigned roles</li>".to_string()
    } else {
        user.role_names
            .iter()
            .map(|role| format!(r#"<li class="meta-code">{}</li>"#, escape_text(role)))
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">{}</span>
    <span>{}</span>
    <span class="meta-separator">•</span>
    <span>{}</span>
    <span class="meta-separator">•</span>
    <span>{}</span>
  </div>
  <ul class="grant-list">{}</ul>
  <div class="inline-form">
    <form method="post" action="/ui/admin/users/{}/password">
      <input type="hidden" name="csrf_token" value="{}">
      <input type="password" name="password" placeholder="New password" autocomplete="new-password" required>
      <button type="submit">Reset password</button>
    </form>
  </div>
  <div class="inline-form">
    <form method="post" action="/ui/admin/users/{}/sessions/revoke">
      <input type="hidden" name="csrf_token" value="{}">
      <button type="submit">Revoke sessions</button>
    </form>
    <form method="post" action="/ui/admin/users/{}/{}">
      <input type="hidden" name="csrf_token" value="{}">
      <button class="danger" type="submit">{}</button>
    </form>
  </div>
</article>"#,
        escape_text(&user.username),
        escape_text(if user.is_admin { "admin" } else { "user" }),
        escape_text(&format_timestamp(user.created_at)),
        escape_text(&format!("{} active sessions", user.active_sessions)),
        roles,
        escape_attribute(&user.username),
        escape_attribute(csrf_token),
        escape_attribute(&user.username),
        escape_attribute(csrf_token),
        escape_attribute(&user.username),
        if user.disabled { "enable" } else { "disable" },
        escape_attribute(csrf_token),
        if user.disabled {
            "Enable user"
        } else {
            "Disable user"
        }
    )
}

fn render_agent_token_card(token: &AgentTokenSummary, csrf_token: &str) -> String {
    let grants = token
        .grants
        .iter()
        .map(|grant| {
            format!(
                r#"<li><span class="meta-code">{}</span> <span class="pill small">{}</span></li>"#,
                escape_text(grant.project.as_str()),
                escape_text(match grant.permission {
                    ProjectPermission::Read => "read",
                    ProjectPermission::ReadWrite => "read_write",
                })
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">{}</span>
    <span>{}</span>
  </div>
  <ul class="grant-list">{}</ul>
  <form method="post" action="/ui/admin/agent-tokens/{}/delete" class="inline-form">
    <input type="hidden" name="csrf_token" value="{}">
    <button class="danger" type="submit">Revoke token</button>
  </form>
  <form method="post" action="/ui/admin/agent-tokens/{}/rotate" class="inline-form">
    <input type="hidden" name="csrf_token" value="{}">
    <button type="submit">Rotate token</button>
  </form>
</article>"#,
        escape_text(&token.name),
        escape_text(&format_timestamp(token.created_at)),
        grants,
        escape_attribute(&token.name),
        escape_attribute(csrf_token),
        escape_attribute(&token.name),
        escape_attribute(csrf_token),
    )
}

fn render_latest_agent_token(token: &UiAdminTokenDisplay) -> String {
    format!(
        r#"<div class="callout">
  <p><strong>New token for {name}</strong><br>Copy it now. Lore stores only the hash after this response.</p>
  <label>
    Raw token
    <textarea readonly>{raw_token}</textarea>
  </label>
  <label>
    HTTP header
    <textarea readonly>{http_example}</textarea>
  </label>
  <label>
    MCP config
    <textarea readonly>{mcp_example}</textarea>
  </label>
  <label>
    Agent instruction
    <textarea readonly>{setup_instruction}</textarea>
  </label>
</div>"#,
        name = escape_text(&token.summary.name),
        raw_token = escape_text(&token.token),
        http_example = escape_text(&token.http_example),
        mcp_example = escape_text(&token.mcp_example),
        setup_instruction = escape_text(&token.setup_instruction),
    )
}

fn render_after_options(
    blocks: &[Block],
    exclude_block_id: Option<&str>,
    selected_after_block_id: Option<&str>,
) -> String {
    let mut options = vec![format!(
        r#"<option value=""{}>Place at top</option>"#,
        if selected_after_block_id.is_none() {
            " selected"
        } else {
            ""
        }
    )];
    options.extend(
        blocks
            .iter()
            .filter(|block| {
                exclude_block_id
                    .map(|exclude_block_id| block.id.as_str() != exclude_block_id)
                    .unwrap_or(true)
            })
            .map(|block| {
                format!(
                    r#"<option value="{}"{}>After {} · {} · {}</option>"#,
                    escape_attribute(block.id.as_str()),
                    if selected_after_block_id == Some(block.id.as_str()) {
                        " selected"
                    } else {
                        ""
                    },
                    escape_text(block_type_label(block.block_type)),
                    escape_text(short_fingerprint(block.author.as_str())),
                    escape_text(&truncate_single_line(&block.content, 42))
                )
            }),
    );
    options.join("")
}

fn selected(current: Option<&str>, value: &str) -> &'static str {
    if current == Some(value) {
        " selected"
    } else {
        ""
    }
}

fn render_block(
    project: &ProjectName,
    block: &Block,
    all_blocks: &[Block],
    can_write: bool,
    csrf_token: &str,
) -> String {
    let selected_after_block_id = all_blocks
        .iter()
        .take_while(|candidate| candidate.id != block.id)
        .last()
        .map(|candidate| candidate.id.as_str());
    let placement_options =
        render_after_options(all_blocks, Some(block.id.as_str()), selected_after_block_id);
    let actions = if can_write {
        format!(
            r#"<div class="block-actions">
  <details>
    <summary>Edit block</summary>
    <form method="post" action="/ui/{}/blocks/{}/edit" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{}">
      <label>
        Type
        <select name="block_type">
          {}
        </select>
      </label>
      <label>
        Place after
        <select name="after_block_id">
          {}
        </select>
      </label>
      <label>
        Content or note
        <textarea name="content">{}</textarea>
      </label>
      <label>
        Replace image
        <input type="file" name="image_file" accept="image/*">
      </label>
      <button type="submit">Save changes</button>
    </form>
  </details>
  <details>
    <summary>Delete block</summary>
    <div class="danger-panel">
      <p>Project writers can delete any block in this project. This is permanent.</p>
      <form method="post" action="/ui/{}/blocks/{}/delete">
        <input type="hidden" name="csrf_token" value="{}">
        <button class="danger" type="submit">Delete block</button>
      </form>
    </div>
  </details>
</div>"#,
            escape_attribute(project.as_str()),
            escape_attribute(block.id.as_str()),
            escape_attribute(csrf_token),
            render_block_type_options(block.block_type),
            placement_options,
            escape_text(&block.content),
            escape_attribute(project.as_str()),
            escape_attribute(block.id.as_str()),
            escape_attribute(csrf_token),
        )
    } else {
        String::new()
    };

    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">{}</span>
    <span>{}</span>
    <span class="meta-separator">•</span>
    <span class="meta-code">author {}</span>
    <span class="meta-separator">•</span>
    <span class="meta-code">order {}</span>
  </div>
  <div class="block-body">{}</div>
  {}
</article>"#,
        escape_text(block_type_label(block.block_type)),
        escape_text(&format_timestamp(block.created_at)),
        escape_text(short_fingerprint(block.author.as_str())),
        escape_text(block.order.as_str()),
        render_block_body(block),
        actions
    )
}

pub fn render_block_body(block: &Block) -> String {
    match block.block_type {
        BlockType::Markdown => render_markdown(&block.content),
        BlockType::Html => format!(
            r#"<pre class="raw-content">{}</pre>"#,
            escape_text(&block.content)
        ),
        BlockType::Svg => render_data_image("image/svg+xml", &block.content, "SVG block"),
        BlockType::Image => render_image_block(block),
    }
}

fn render_markdown(content: &str) -> String {
    let escaped = escape_text(content);
    let mut html_output = String::new();
    let parser = Parser::new_ext(
        &escaped,
        Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES | Options::ENABLE_TASKLISTS,
    );
    html::push_html(&mut html_output, parser);
    html_output
}

fn render_image_block(block: &Block) -> String {
    let src = if block.media_type.is_some() {
        format!(
            "/ui/{}/blocks/{}/media",
            escape_attribute(block.project.as_str()),
            escape_attribute(block.id.as_str())
        )
    } else {
        let trimmed = block.content.trim();
        if trimmed.starts_with("data:image/")
            || trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
        {
            trimmed.to_string()
        } else {
            format!("data:image/*;base64,{}", BASE64.encode(trimmed.as_bytes()))
        }
    };
    let caption = if block.media_type.is_some() && !block.content.trim().is_empty() {
        format!(
            r#"<figcaption class="hint">{}</figcaption>"#,
            escape_text(block.content.trim())
        )
    } else {
        String::new()
    };

    format!(
        r#"<figure class="media-frame"><img src="{}" alt="Image block">{}</figure>"#,
        escape_attribute(&src),
        caption
    )
}

fn render_data_image(mime: &str, content: &str, alt: &str) -> String {
    let safe_content = if mime.contains("svg") {
        sanitize_svg(content)
    } else {
        content.to_string()
    };
    let encoded = BASE64.encode(safe_content.as_bytes());
    let src = format!("data:{mime};base64,{encoded}");
    format!(
        r#"<figure class="media-frame"><img src="{}" alt="{}"></figure>"#,
        escape_attribute(&src),
        escape_attribute(alt)
    )
}

pub fn sanitize_svg(input: &str) -> String {
    use regex::Regex;
    let dangerous_tags = Regex::new(
        r#"(?i)<\s*/?\s*(script|foreignObject|iframe|embed|object|applet|meta|link|base)\b[^>]*>"#,
    )
    .unwrap();
    let event_handlers = Regex::new(r#"(?i)\s+on\w+\s*=\s*["'][^"']*["']"#).unwrap();
    let event_handlers_unquoted = Regex::new(r"(?i)\s+on\w+\s*=\s*\S+").unwrap();
    let external_use =
        Regex::new(r#"(?i)<\s*use\b[^>]*href\s*=\s*["']https?://[^"']*["'][^>]*>"#).unwrap();

    let result = dangerous_tags.replace_all(input, "");
    let result = event_handlers.replace_all(&result, "");
    let result = event_handlers_unquoted.replace_all(&result, "");
    let result = external_use.replace_all(&result, "");
    result.into_owned()
}

fn render_block_type_options(selected: BlockType) -> String {
    [
        BlockType::Markdown,
        BlockType::Svg,
        BlockType::Html,
        BlockType::Image,
    ]
    .into_iter()
    .map(|block_type| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            block_type_value(block_type),
            if block_type == selected {
                " selected"
            } else {
                ""
            },
            escape_text(block_type_label(block_type))
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn block_type_label(block_type: BlockType) -> &'static str {
    match block_type {
        BlockType::Markdown => "Markdown",
        BlockType::Html => "HTML",
        BlockType::Svg => "SVG",
        BlockType::Image => "Image",
    }
}

fn block_type_value(block_type: BlockType) -> &'static str {
    match block_type {
        BlockType::Markdown => "markdown",
        BlockType::Html => "html",
        BlockType::Svg => "svg",
        BlockType::Image => "image",
    }
}

fn truncate_single_line(content: &str, max_chars: usize) -> String {
    let single_line = content.split_whitespace().collect::<Vec<_>>().join(" ");
    if single_line.chars().count() <= max_chars {
        single_line
    } else {
        let mut truncated = single_line.chars().take(max_chars).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

fn short_fingerprint(value: &str) -> &str {
    let len = value.len().min(12);
    &value[..len]
}

fn format_timestamp(value: time::OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| value.unix_timestamp().to_string())
}

fn flash_message(flash: Option<&str>) -> String {
    flash
        .map(|message| format!(r#"<p class="flash">{}</p>"#, escape_text(message)))
        .unwrap_or_default()
}

fn escape_text(value: &str) -> String {
    v_htmlescape::escape(value).to_string()
}

fn escape_attribute(value: &str) -> String {
    escape_text(value)
}

struct ThemePalette {
    color_scheme: &'static str,
    bg: &'static str,
    panel: &'static str,
    panel_strong: &'static str,
    ink: &'static str,
    muted: &'static str,
    line: &'static str,
    accent: &'static str,
    accent_soft: &'static str,
    shadow: &'static str,
    radius: &'static str,
    font_sans: &'static str,
    font_mono: &'static str,
    body_background: &'static str,
    button_background: &'static str,
    button_text: &'static str,
    hero_button_background: &'static str,
    hero_button_text: &'static str,
    flash_background: &'static str,
    flash_text: &'static str,
    flash_border: &'static str,
    callout_background: &'static str,
    code_background: &'static str,
    code_text: &'static str,
    media_background: &'static str,
    media_image_background: &'static str,
    empty_background: &'static str,
    details_background: &'static str,
}

fn theme_palette(theme: UiTheme) -> ThemePalette {
    match theme {
        UiTheme::Parchment => ThemePalette {
            color_scheme: "light",
            bg: "#f4efe7",
            panel: "rgba(255,255,255,0.88)",
            panel_strong: "#fffaf3",
            ink: "#1f1a17",
            muted: "#6d6258",
            line: "rgba(78, 55, 36, 0.14)",
            accent: "#b55233",
            accent_soft: "rgba(181, 82, 51, 0.12)",
            shadow: "0 20px 60px rgba(71, 46, 31, 0.12)",
            radius: "22px",
            font_sans: "\"Iowan Old Style\", \"Palatino Linotype\", \"Book Antiqua\", Georgia, serif",
            font_mono: "\"SFMono-Regular\", \"Cascadia Mono\", \"Liberation Mono\", monospace",
            body_background: "radial-gradient(circle at top left, rgba(214, 139, 96, 0.24), transparent 28rem), radial-gradient(circle at top right, rgba(96, 138, 173, 0.14), transparent 22rem), linear-gradient(180deg, #f7f2ea 0%, var(--bg) 100%)",
            button_background: "linear-gradient(135deg, #1f1a17, #7b3622)",
            button_text: "#fff8f2",
            hero_button_background: "linear-gradient(135deg, #1f1a17, #7b3622)",
            hero_button_text: "#fff8f2",
            flash_background: "rgba(62, 140, 93, 0.12)",
            flash_text: "#234c31",
            flash_border: "rgba(62, 140, 93, 0.2)",
            callout_background: "rgba(181, 82, 51, 0.08)",
            code_background: "#201814",
            code_text: "#f9f3ec",
            media_background: "#fff",
            media_image_background: "linear-gradient(180deg, #fffdf9, #f5eee3)",
            empty_background: "rgba(255,255,255,0.62)",
            details_background: "rgba(255,255,255,0.62)",
        },
        UiTheme::Graphite => ThemePalette {
            color_scheme: "dark",
            bg: "#11161c",
            panel: "rgba(20,27,35,0.9)",
            panel_strong: "#1a222c",
            ink: "#edf2f7",
            muted: "#97a7b8",
            line: "rgba(166, 184, 204, 0.18)",
            accent: "#7dd3fc",
            accent_soft: "rgba(125, 211, 252, 0.16)",
            shadow: "0 20px 60px rgba(2, 8, 18, 0.45)",
            radius: "20px",
            font_sans: "\"Avenir Next\", \"Segoe UI\", \"Helvetica Neue\", sans-serif",
            font_mono: "\"SFMono-Regular\", \"Cascadia Code\", \"Liberation Mono\", monospace",
            body_background: "radial-gradient(circle at top left, rgba(46, 93, 131, 0.32), transparent 28rem), radial-gradient(circle at top right, rgba(125, 211, 252, 0.12), transparent 22rem), linear-gradient(180deg, #0c1117 0%, var(--bg) 100%)",
            button_background: "linear-gradient(135deg, #2563eb, #0f766e)",
            button_text: "#f8fbff",
            hero_button_background: "linear-gradient(135deg, #2563eb, #0f766e)",
            hero_button_text: "#f8fbff",
            flash_background: "rgba(45, 212, 191, 0.14)",
            flash_text: "#c7fff1",
            flash_border: "rgba(45, 212, 191, 0.26)",
            callout_background: "rgba(125, 211, 252, 0.1)",
            code_background: "#091017",
            code_text: "#d9ecff",
            media_background: "#0e151d",
            media_image_background: "linear-gradient(180deg, #18222d, #0f1820)",
            empty_background: "rgba(20,27,35,0.68)",
            details_background: "rgba(20,27,35,0.72)",
        },
        UiTheme::Signal => ThemePalette {
            color_scheme: "light",
            bg: "#e7f0ec",
            panel: "rgba(248,252,250,0.9)",
            panel_strong: "#ffffff",
            ink: "#0f1f1b",
            muted: "#536965",
            line: "rgba(31, 73, 63, 0.16)",
            accent: "#0f8f6f",
            accent_soft: "rgba(15, 143, 111, 0.14)",
            shadow: "0 18px 54px rgba(18, 74, 63, 0.16)",
            radius: "18px",
            font_sans: "\"Gill Sans\", \"Avenir Next Condensed\", \"Trebuchet MS\", sans-serif",
            font_mono: "\"IBM Plex Mono\", \"Cascadia Mono\", monospace",
            body_background: "radial-gradient(circle at top left, rgba(15, 143, 111, 0.18), transparent 28rem), radial-gradient(circle at top right, rgba(244, 114, 182, 0.12), transparent 22rem), linear-gradient(180deg, #f2f8f5 0%, var(--bg) 100%)",
            button_background: "linear-gradient(135deg, #0f8f6f, #1768ac)",
            button_text: "#f6fffc",
            hero_button_background: "linear-gradient(135deg, #0f8f6f, #1768ac)",
            hero_button_text: "#f6fffc",
            flash_background: "rgba(22, 163, 74, 0.12)",
            flash_text: "#14532d",
            flash_border: "rgba(22, 163, 74, 0.22)",
            callout_background: "rgba(15, 143, 111, 0.08)",
            code_background: "#10221e",
            code_text: "#dcfff8",
            media_background: "#ffffff",
            media_image_background: "linear-gradient(180deg, #fbfffe, #edf7f4)",
            empty_background: "rgba(255,255,255,0.66)",
            details_background: "rgba(255,255,255,0.72)",
        },
    }
}

fn render_theme_options(selected_theme: Option<UiTheme>, allow_default: bool) -> String {
    let mut options = Vec::new();
    if allow_default {
        options.push(format!(
            r#"<option value=""{}>Use server default</option>"#,
            if selected_theme.is_none() {
                " selected"
            } else {
                ""
            }
        ));
    }
    options.extend(UiTheme::all().into_iter().map(|theme| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            theme.as_str(),
            if selected_theme == Some(theme) {
                " selected"
            } else {
                ""
            },
            escape_text(theme.display_name())
        )
    }));
    options.join("")
}

fn render_theme_preview_cards(
    selected_theme: Option<UiTheme>,
    server_default_theme: UiTheme,
) -> String {
    UiTheme::all()
        .into_iter()
        .map(|theme| {
            let label = if selected_theme == Some(theme) {
                "Your preference"
            } else if selected_theme.is_none() && server_default_theme == theme {
                "Server default"
            } else {
                "Available"
            };
            format!(
                r#"<article class="block">
  <div class="block-meta">
    <span class="pill">{}</span>
    <span>{}</span>
  </div>
  <div class="theme-preview theme-preview-{}">
    <span></span><span></span><span></span>
  </div>
</article>"#,
                escape_text(theme.display_name()),
                escape_text(label),
                escape_attribute(theme.as_str()),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn shared_styles(theme: UiTheme) -> String {
    let palette = theme_palette(theme);
    let root = format!(
        r#"
    :root {{
      color-scheme: {};
      --bg: {};
      --panel: {};
      --panel-strong: {};
      --ink: {};
      --muted: {};
      --line: {};
      --accent: {};
      --accent-soft: {};
      --shadow: {};
      --radius: {};
      --font-sans: {};
      --font-mono: {};
      --button-bg: {};
      --button-ink: {};
      --hero-button-bg: {};
      --hero-button-ink: {};
      --flash-bg: {};
      --flash-ink: {};
      --flash-line: {};
      --callout-bg: {};
      --code-bg: {};
      --code-ink: {};
      --media-bg: {};
      --media-image-bg: {};
      --empty-bg: {};
      --details-bg: {};
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      font-family: var(--font-sans);
      color: var(--ink);
      background: {};
      min-height: 100vh;
    }}
"#,
        palette.color_scheme,
        palette.bg,
        palette.panel,
        palette.panel_strong,
        palette.ink,
        palette.muted,
        palette.line,
        palette.accent,
        palette.accent_soft,
        palette.shadow,
        palette.radius,
        palette.font_sans,
        palette.font_mono,
        palette.button_background,
        palette.button_text,
        palette.hero_button_background,
        palette.hero_button_text,
        palette.flash_background,
        palette.flash_text,
        palette.flash_border,
        palette.callout_background,
        palette.code_background,
        palette.code_text,
        palette.media_background,
        palette.media_image_background,
        palette.empty_background,
        palette.details_background,
        palette.body_background,
    );
    let rest = r#"

    .shell {
      width: min(1080px, calc(100vw - 24px));
      margin: 0 auto;
      padding: 20px 0 48px;
    }

    .auth-shell {
      min-height: 100vh;
      display: grid;
      align-items: center;
    }

    .hero,
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(8px);
    }

    .hero {
      padding: 22px;
      display: grid;
      gap: 10px;
    }

    .auth-panel {
      max-width: 32rem;
      margin: 0 auto;
      padding: 22px;
    }

    .eyebrow {
      margin: 0;
      color: var(--muted);
      font-size: 0.88rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    h1,
    h2 {
      margin: 0;
    }

    h1 {
      font-size: clamp(1.9rem, 5vw, 3.2rem);
      line-height: 0.95;
    }

    .subtitle,
    .hint,
    .danger-panel p {
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }

    .flash {{
      margin: 6px 0 0;
      padding: 12px 14px;
      border-radius: 14px;
      background: var(--flash-bg);
      color: var(--flash-ink);
      border: 1px solid var(--flash-line);
    }}

    .hero-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 6px;
      align-items: center;
    }

    .hero-actions form {
      padding: 0;
      display: block;
    }

    .hero-actions a,
    .button-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 10px 14px;
      border-radius: 999px;
      text-decoration: none;
      border: 1px solid var(--line);
      color: var(--ink);
      background: rgba(255,255,255,0.68);
      font-weight: 700;
    }

    .hero-actions a.primary,
    .button-link {
      background: var(--hero-button-bg);
      border-color: transparent;
      color: var(--hero-button-ink);
    }

    .layout {
      display: grid;
      gap: 18px;
      margin-top: 18px;
      grid-template-columns: minmax(0, 1.6fr) minmax(280px, 0.95fr);
      align-items: start;
    }

    .admin-layout {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .project-grid,
    .stack,
    .timeline {
      display: grid;
      gap: 14px;
      margin-top: 18px;
    }

    .timeline {
      padding: 16px;
      margin-top: 0;
    }

    .project-card,
    .block {
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: linear-gradient(180deg, var(--panel-strong), rgba(255,255,255,0.76));
    }

    .project-card {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
    }

    .panel-header {
      padding: 16px 18px 0;
      display: grid;
      gap: 6px;
    }

    .composer {
      position: sticky;
      top: 14px;
    }

    form {
      display: grid;
      gap: 12px;
      padding: 16px;
    }

    label {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 0.92rem;
    }

    .toggle {
      grid-template-columns: auto 1fr;
      align-items: center;
      gap: 10px;
    }

    .toggle input {
      width: auto;
      margin: 0;
    }

    input,
    select,
    textarea,
    button {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 12px 13px;
      font-size: 16px;
      background: rgba(255,255,255,0.92);
      color: var(--ink);
      font-family: var(--font-mono);
    }

    textarea {
      min-height: 13rem;
      resize: vertical;
    }

    .callout {
      display: grid;
      gap: 12px;
      margin: 16px;
      padding: 16px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: var(--callout-bg);
    }

    .callout p {
      margin: 0;
    }

    button {
      border: 0;
      background: var(--button-bg);
      color: var(--button-ink);
      font-weight: 700;
      letter-spacing: 0.01em;
      cursor: pointer;
    }

    .searchbar {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      margin-top: 6px;
    }

    .block-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin-bottom: 12px;
      color: var(--muted);
      font-size: 0.85rem;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      padding: 5px 9px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-weight: 700;
      letter-spacing: 0.01em;
    }

    .pill.small {
      padding: 3px 7px;
      font-size: 0.8rem;
    }

    .meta-code {
      font-family: var(--font-mono);
      font-size: 0.8rem;
      word-break: break-all;
    }

    .meta-separator {
      color: rgba(109, 98, 88, 0.6);
    }

    .block-body {
      font-size: 1rem;
      line-height: 1.65;
      overflow-wrap: anywhere;
    }

    .block-body > :first-child,
    .grant-list > :first-child {
      margin-top: 0;
    }

    .block-body > :last-child,
    .grant-list > :last-child {
      margin-bottom: 0;
    }

    .block-body pre,
    .block-body code,
    .raw-content {
      font-family: var(--font-mono);
    }

    .block-body pre,
    .raw-content {
      margin: 0;
      padding: 14px;
      border-radius: 14px;
      background: var(--code-bg);
      color: var(--code-ink);
      overflow-x: auto;
      font-size: 0.9rem;
    }

    .media-frame {
      margin: 0;
      border: 1px solid var(--line);
      border-radius: 16px;
      overflow: hidden;
      background: var(--media-bg);
    }

    .media-frame img {
      display: block;
      width: 100%;
      height: auto;
      max-height: 26rem;
      object-fit: contain;
      background: var(--media-image-bg);
    }

    .block-actions {
      display: grid;
      gap: 10px;
      margin-top: 14px;
      padding-top: 14px;
      border-top: 1px solid var(--line);
    }

    details {
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--details-bg);
      overflow: hidden;
    }

    summary {
      list-style: none;
      cursor: pointer;
      padding: 12px 14px;
      font-weight: 700;
    }

    summary::-webkit-details-marker {
      display: none;
    }

    .danger {
      background: linear-gradient(135deg, #6f1f19, #a5332a);
    }

    .danger-panel {
      padding: 16px;
      display: grid;
      gap: 12px;
    }

    .empty-state,
    .padded {
      padding: 24px;
    }

    .empty-state {
      border: 1px dashed rgba(78, 55, 36, 0.22);
      border-radius: 18px;
      background: var(--empty-bg);
      text-align: center;
    }

    .theme-preview {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      min-height: 72px;
      margin-top: 8px;
    }

    .theme-preview span {
      border-radius: 14px;
      border: 1px solid var(--line);
    }

    .theme-preview-parchment span:nth-child(1) { background: #fff8ef; }
    .theme-preview-parchment span:nth-child(2) { background: #d36a45; }
    .theme-preview-parchment span:nth-child(3) { background: #c7d9e2; }
    .theme-preview-graphite span:nth-child(1) { background: #1a222c; }
    .theme-preview-graphite span:nth-child(2) { background: #2563eb; }
    .theme-preview-graphite span:nth-child(3) { background: #7dd3fc; }
    .theme-preview-signal span:nth-child(1) { background: #f6fffc; }
    .theme-preview-signal span:nth-child(2) { background: #0f8f6f; }
    .theme-preview-signal span:nth-child(3) { background: #1768ac; }

    .grant-list {
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
    }

    .version-op {
      margin: 0;
    }

    .version-meta {
      display: grid;
      gap: 6px;
      margin: 12px 0;
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.5);
      border: 1px solid var(--line);
    }

    .version-meta p,
    .diff-list p {
      margin: 0;
    }

    .diff-list {
      display: grid;
      gap: 1px;
      margin-top: 12px;
      border: 1px solid var(--line);
      border-radius: 14px;
      overflow: hidden;
      background: var(--line);
    }

    .diff-line {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 10px;
      padding: 10px 12px;
      font-family: var(--font-mono);
      font-size: 0.88rem;
      background: rgba(255, 255, 255, 0.9);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }

    .diff-prefix {
      font-weight: 700;
      color: var(--muted);
    }

    .diff-added {
      background: rgba(47, 122, 97, 0.12);
    }

    .diff-added .diff-prefix {
      color: #1d7257;
    }

    .diff-removed {
      background: rgba(181, 82, 51, 0.12);
    }

    .diff-removed .diff-prefix {
      color: #a33a1d;
    }

    .diff-context {
      background: rgba(255, 255, 255, 0.94);
    }

    .inline-form {
      margin-top: 14px;
      padding: 0;
    }

    @media (max-width: 860px) {
      .shell {
        width: min(100vw - 16px, 1080px);
        padding-top: max(8px, env(safe-area-inset-top));
        padding-bottom: calc(28px + env(safe-area-inset-bottom));
      }

      .layout,
      .admin-layout,
      .searchbar {
        grid-template-columns: 1fr;
      }

      .composer {
        position: static;
      }

      .project-card {
        display: grid;
      }

      .block-meta {
        display: grid;
        grid-template-columns: 1fr;
        gap: 6px;
        align-items: start;
      }

      .meta-separator {
        display: none;
      }
    }
    "#;
    format!("{root}{rest}")
}
