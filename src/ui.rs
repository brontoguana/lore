use crate::audit::{AuditActor, AuditActorKind};
use crate::auth::{ProjectGrant, ProjectPermission, StoredRole};
use crate::config::{ExternalAuthConfig, ExternalScheme, OidcConfig, ServerConfig, UiTheme};
use crate::librarian::{
    LibrarianActor, LibrarianActorKind, LibrarianConfig, LibrarianRunKind, LibrarianRunStatus,
    ProjectLibrarianOperationType, ProviderCheckResult, StoredLibrarianOperation,
};
use crate::model::{Block, BlockId, BlockType, ProjectName};
use crate::store::ProjectInfo;
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

pub struct PageShell<'a> {
    pub title: &'a str,
    pub username: Option<&'a str>,
    pub is_admin: bool,
    pub theme: UiTheme,
    pub csrf_token: Option<&'a str>,
    pub flash: Option<&'a str>,
}

pub fn render_shell(shell: PageShell, content: String) -> String {
    let flash_html = flash_message(shell.flash);
    let nav_html = if let Some(username) = shell.username {
        let admin_link = if shell.is_admin {
            r#"<a href="/ui/admin">Admin</a>"#.to_string()
        } else {
            String::new()
        };
        let csrf_input = shell
            .csrf_token
            .map(|t| format!(r#"<input type="hidden" name="csrf_token" value="{}">"#, t))
            .unwrap_or_default();

        format!(
            r#"<nav class="top-nav">
  <div class="top-nav-inner">
    <div style="display:flex; align-items:center; gap:var(--s-4);">
      <a href="/ui" class="logo">Lore</a>
      <span class="eyebrow" style="margin-top:2px;">{username}</span>
    </div>
    <div class="top-nav-links">
      <a href="/ui">Projects</a>
      {admin_link}
      <a href="/ui/settings">Settings</a>
      <form method="post" action="/logout">
        {csrf_input}
        <button type="submit">Sign out</button>
      </form>
    </div>
  </div>
</nav>"#,
            username = escape_text(username),
            admin_link = admin_link,
            csrf_input = csrf_input,
        )
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
  {nav_html}
  <main class="shell">
    {flash_html}
    {content}
  </main>
  <script>
  function showInserterForm(btn, type) {{
    var expand = btn.closest('.inserter-expand');
    var forms = expand.querySelectorAll('.inserter-form');
    for (var i = 0; i < forms.length; i++) forms[i].style.display = 'none';
    var btns = expand.querySelectorAll('.inserter-type-btn');
    for (var i = 0; i < btns.length; i++) btns[i].classList.remove('active');
    var target = expand.querySelector('.inserter-form-' + type);
    if (target) {{ target.style.display = ''; }}
    btn.classList.add('active');
    var ta = target && target.querySelector('textarea');
    if (ta) ta.focus();
  }}
  </script>
</body>
</html>"#,
        title = escape_text(shell.title),
        styles = shared_styles(shell.theme),
        nav_html = nav_html,
        flash_html = flash_html,
        content = content,
    )
}

pub struct ProjectListEntry {
    pub project: ProjectName,
    pub display_name: String,
    pub parent: Option<String>,
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

    let content = format!(
        r#"<section class="panel auth-panel">
      <p class="eyebrow">Lore</p>
      <h1>{title}</h1>
      <p class="subtitle">{subtitle}</p>
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
    </section>"#,
        title = escape_text(title),
        subtitle = escape_text(subtitle),
        action = action,
        button = escape_text(button),
        autocomplete = if has_users {
            "current-password"
        } else {
            "new-password"
        },
        oidc_html = oidc_html,
        external_auth_html = external_auth_html,
    );

    render_shell(
        PageShell {
            title,
            username: None,
            is_admin: false,
            theme,
            csrf_token: None,
            flash,
        },
        content,
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
    let tree_html = if projects.is_empty() {
        r#"<div class="empty-state"><p>No projects yet.</p></div>"#.to_string()
    } else {
        render_project_tree(projects, is_admin, csrf_token)
    };

    let root_create = if is_admin {
        format!(
            r#"<div class="tree-create-root">
  <button type="button" class="tree-add-btn" onclick="addSiblingRow(this, '')">+ New project</button>
</div>"#,
        )
    } else {
        String::new()
    };

    let content = format!(
        r#"<h1 class="page-title">Projects</h1>
    <section class="project-tree-panel panel">
      {tree_html}
      {root_create}
    </section>
    <script>
    var csrfToken = '{csrf_token}';
    function addSiblingRow(btn, parentSlug) {{
      // Remove any existing inline create rows
      document.querySelectorAll('.tree-inline-create').forEach(function(el) {{ el.remove(); }});

      var li = document.createElement('li');
      li.className = 'tree-node tree-inline-create';
      li.innerHTML = '<form class="tree-node-row tree-create-row" method="post" action="/ui/projects">'
        + '<input type="hidden" name="csrf_token" value="' + csrfToken + '">'
        + '<input type="hidden" name="parent" value="' + parentSlug + '">'
        + '<input type="text" name="project_name" class="tree-inline-input" placeholder="Project name" required>'
        + '<div class="tree-row-right">'
        + '<span class="tree-perm">read/write</span>'
        + '<button type="submit" class="tree-add-child">Save</button>'
        + '<button type="button" class="tree-add-child" onclick="this.closest(\'.tree-inline-create\').remove()">Cancel</button>'
        + '</div></form>';

      // Insert after the current tree-node (sibling), or at end of the tree list
      var node = btn.closest('.tree-node');
      if (node) {{
        node.after(li);
      }} else {{
        // Clicked from root "New project" button
        var list = document.querySelector('.project-tree-panel .tree-list');
        if (list) {{
          list.appendChild(li);
        }} else {{
          // No tree-list yet (empty state) -- create one
          var panel = document.querySelector('.project-tree-panel');
          var empty = panel.querySelector('.empty-state');
          if (empty) empty.remove();
          var ul = document.createElement('ul');
          ul.className = 'tree-list';
          ul.appendChild(li);
          panel.insertBefore(ul, panel.querySelector('.tree-create-root'));
        }}
      }}
      li.querySelector('input[name="project_name"]').focus();
    }}
    </script>"#,
        tree_html = tree_html,
        root_create = root_create,
        csrf_token = escape_attribute(csrf_token),
    );

    render_shell(
        PageShell {
            title: "Lore projects",
            username: Some(username),
            is_admin,
            theme,
            csrf_token: Some(csrf_token),
            flash,
        },
        content,
    )
}

fn render_project_tree(projects: &[ProjectListEntry], is_admin: bool, csrf_token: &str) -> String {
    // Build tree structure: root nodes have parent == None
    // Children have parent == Some(slug)
    fn render_children(
        parent: Option<&str>,
        projects: &[ProjectListEntry],
        is_admin: bool,
        csrf_token: &str,
        depth: usize,
    ) -> String {
        let children: Vec<&ProjectListEntry> = projects
            .iter()
            .filter(|e| e.parent.as_deref() == parent)
            .collect();

        if children.is_empty() {
            return String::new();
        }

        let parent_slug = parent.unwrap_or("");
        let items: Vec<String> = children
            .iter()
            .map(|entry| {
                let slug = entry.project.as_str();
                let display = escape_text(&entry.display_name);
                let perm = if entry.can_write { "read/write" } else { "read-only" };
                let sub = render_children(
                    Some(slug),
                    projects,
                    is_admin,
                    csrf_token,
                    depth + 1,
                );

                let add_btn = if is_admin {
                    format!(
                        r#"<button type="button" class="tree-add-child" onclick="addSiblingRow(this, '{parent}')">+</button>"#,
                        parent = escape_attribute(parent_slug),
                    )
                } else {
                    String::new()
                };

                format!(
                    r#"<li class="tree-node">
  <div class="tree-node-row">
    <a href="/ui/{slug}" class="tree-link">{display}</a>
    <div class="tree-row-right">
      <span class="tree-perm">{perm}</span>
      {add_btn}
    </div>
  </div>
  {sub}
</li>"#,
                    slug = escape_attribute(slug),
                    display = display,
                    perm = perm,
                    add_btn = add_btn,
                    sub = sub,
                )
            })
            .collect();

        format!(r#"<ul class="tree-list">{}</ul>"#, items.join(""))
    }

    render_children(None, projects, is_admin, csrf_token, 0)
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
    projects: &[ProjectInfo],
    latest_agent_token: Option<&UiAdminTokenDisplay>,
    flash: Option<&str>,
    active_section: &str,
) -> String {
    let roles_html = if roles.is_empty() {
        "<p class=\"hint padded\">No roles exist yet.</p>".to_string()
    } else {
        roles
            .iter()
            .map(|role| render_role_card(role, csrf_token, projects))
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
    let role_grants_html = if projects.is_empty() {
        "<p class=\"hint\">No projects exist yet. Create a project first, then come back to assign grants.</p>".to_string()
    } else {
        let rows: Vec<String> = projects
            .iter()
            .map(|p| {
                format!(
                    r#"<div class="grant-row" data-project-grant="{}">
                      <span class="grant-project-name">{}</span>
                      <select>
                        <option value="">No access</option>
                        <option value="read">Read</option>
                        <option value="read_write">Read/Write</option>
                      </select>
                    </div>"#,
                    escape_attribute(p.slug.as_str()),
                    escape_text(&p.display_name),
                )
            })
            .collect();
        format!(
            r#"<fieldset class="grant-fieldset"><legend>Project access</legend>{}</fieldset>"#,
            rows.join("")
        )
    };
    let project_grants_html = if projects.is_empty() {
        "<p class=\"hint\">No projects exist yet. Create a project first, then come back to grant access.</p>".to_string()
    } else {
        let rows: Vec<String> = projects
            .iter()
            .map(|p| {
                format!(
                    r#"<div class="grant-row" data-project-grant="{}">
                      <span class="grant-project-name">{}</span>
                      <select>
                        <option value="">No access</option>
                        <option value="read">Read</option>
                        <option value="read_write">Read/Write</option>
                      </select>
                    </div>"#,
                    escape_attribute(p.slug.as_str()),
                    escape_text(&p.display_name),
                )
            })
            .collect();
        format!(
            r#"<fieldset class="grant-fieldset"><legend>Project access</legend>{}</fieldset>"#,
            rows.join("")
        )
    };
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

    let sections = [
        "users",
        "roles",
        "agent-tokens",
        "agent-setup",
        "librarian",
        "git-export",
        "oidc",
        "external-auth",
        "updates",
        "audit",
    ];
    let section_labels = [
        "Users",
        "Roles",
        "Agent tokens",
        "Agent setup",
        "Librarian",
        "Git export",
        "OIDC",
        "External auth",
        "Updates",
        "Audit",
    ];
    let active = if sections.contains(&active_section) {
        active_section
    } else {
        "users"
    };
    let nav_items: String = sections
        .iter()
        .zip(section_labels.iter())
        .map(|(id, label)| {
            let cls = if *id == active {
                r#" class="active""#
            } else {
                ""
            };
            format!(r#"<a href="/ui/admin?section={id}"{cls} data-section="{id}">{label}</a>"#)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let hidden = |id: &str| -> &str {
        if id == active {
            ""
        } else {
            r#" style="display:none""#
        }
    };

    let content = format!(
        r#"<h1 class="page-title">Admin</h1>

    <div class="admin-sidebar-layout">
      <nav class="admin-nav" id="admin-nav">
        {nav_items}
      </nav>
      <div id="admin-panels">

      <section class="panel" data-panel="users"{users_display}>
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
        <div class="panel-header"><h2>Users</h2><p>Passwords are stored as Argon2 hashes on disk.</p></div>
        <div class="timeline">{users_html}</div>
      </section>

      <section class="panel" data-panel="roles"{roles_display}>
        <div class="panel-header">
          <h2>Create role</h2>
          <p>Select project-level permissions for this role.</p>
        </div>
        <form method="post" action="/ui/admin/roles" id="create-role-form">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Role name
            <input type="text" name="name" placeholder="engineering-writers" required>
          </label>
          {role_grants_html}
          <textarea name="grants" style="display:none" id="role-grants-field"></textarea>
          <button type="submit">Create role</button>
        </form>
        <script>
        (function() {{
          var form = document.getElementById('create-role-form');
          form.addEventListener('submit', function() {{
            var rows = form.querySelectorAll('[data-project-grant]');
            var lines = [];
            rows.forEach(function(row) {{
              var sel = row.querySelector('select');
              if (sel && sel.value) {{
                lines.push(row.getAttribute('data-project-grant') + ':' + sel.value);
              }}
            }});
            document.getElementById('role-grants-field').value = lines.join('\\n');
          }});
        }})();
        </script>
        <div class="panel-header"><h2>Roles</h2><p>Grants define project-level visibility and editing.</p></div>
        <div class="timeline">{roles_html}</div>
      </section>

      <section class="panel" data-panel="agent-tokens"{agent_tokens_display}>
        <div class="panel-header">
          <h2>Agent tokens</h2>
          <p>Create scoped agent tokens with per-project read or read/write access.</p>
        </div>
        {latest_agent_token_html}
        <form method="post" action="/ui/admin/agent-tokens" id="agent-token-form">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Token name
            <input type="text" name="name" placeholder="worker-alpha" required>
          </label>
          {project_grants_html}
          <textarea name="grants" style="display:none" id="agent-grants-field"></textarea>
          <button type="submit">Create agent token</button>
        </form>
        <script>
        (function() {{
          var form = document.getElementById('agent-token-form');
          form.addEventListener('submit', function() {{
            var rows = form.querySelectorAll('[data-project-grant]');
            var lines = [];
            rows.forEach(function(row) {{
              var sel = row.querySelector('select');
              if (sel && sel.value) {{
                lines.push(row.getAttribute('data-project-grant') + ':' + sel.value);
              }}
            }});
            document.getElementById('agent-grants-field').value = lines.join('\\n');
          }});
        }})();
        </script>
        <div class="timeline">{agent_tokens_html}</div>
      </section>

      <section class="panel" data-panel="agent-setup"{agent_setup_display}>
        <div class="panel-header">
          <h2>Agent setup</h2>
          <p>Set the externally reachable Lore address.</p>
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
        <div class="meta-stack padded">
          <p><strong>Setup page</strong><br>{setup_url}</p>
          <p><strong>Plain text page</strong><br>{setup_text_url}</p>
        </div>
        <div class="padded">
          <label>
            Copy-paste for an agent
            <textarea readonly style="min-height: 6rem;">{setup_instruction}</textarea>
          </label>
        </div>
      </section>

      <section class="panel" data-panel="librarian"{librarian_display}>
        <div class="panel-header">
          <h2>Librarian</h2>
          <p>Configure an OpenAI-compatible chat completions endpoint.</p>
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
            <span>Require approval before project librarian actions</span>
          </label>
          <button type="submit">Save librarian config</button>
        </form>
        <div class="meta-stack padded">
          <p><strong>Status</strong><br>{librarian_status}</p>
          {provider_status_html}
        </div>
      </section>

      <section class="panel" data-panel="git-export"{git_export_display}>
        <div class="panel-header">
          <h2>Git export</h2>
          <p>Export project files and history into a Git branch.</p>
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
          <button type="submit">Save Git export</button>
        </form>
        <div class="meta-stack padded">
          <p><strong>Status</strong><br>{git_export_state}</p>
          {git_export_status_html}
        </div>
      </section>

      <section class="panel" data-panel="oidc"{oidc_display}>
        <div class="panel-header">
          <h2>OIDC</h2>
          <p>Configure an OpenID Connect login flow.</p>
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
          <button type="submit">Save OIDC config</button>
        </form>
        <div class="meta-stack padded">
          <p><strong>Status</strong><br>{oidc_status}</p>
          <p><strong>Redirect URI</strong><br>{oidc_redirect_uri}</p>
        </div>
      </section>

      <section class="panel" data-panel="external-auth"{external_auth_display}>
        <div class="panel-header">
          <h2>External auth</h2>
          <p>Enable trusted reverse-proxy header auth.</p>
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
          <button type="submit">Save external auth</button>
        </form>
        <div class="meta-stack padded">
          <p><strong>Status</strong><br>{external_auth_status}</p>
        </div>
      </section>

      <section class="panel" data-panel="updates"{updates_display}>
        <div class="panel-header">
          <h2>Server updates</h2>
          <p>Check for new Lore server releases and apply updates.</p>
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
          <button type="submit">Save auto update</button>
        </form>
        <div class="meta-stack padded">
          <p><strong>Status</strong><br>{auto_update_state}</p>
          {auto_update_status_html}
        </div>
      </section>

      <section class="panel" data-panel="audit"{audit_display}>
        <div class="panel-header">
          <h2>Audit</h2>
          <p>Recent runs and events. <a href="/ui/admin/audit">Open full audit</a>.</p>
        </div>
        <div class="timeline">{pending_actions_html}</div>
        <div class="timeline">{audit_html}</div>
        <div class="panel-header"><h2>Auth events</h2></div>
        <div class="timeline">{auth_audit_html}</div>
      </section>

      </div>
    </div>

    <script>
    (function() {{
      var nav = document.getElementById(‘admin-nav’);
      var panels = document.getElementById(‘admin-panels’);
      var links = nav.querySelectorAll(‘a[data-section]’);
      var sections = panels.querySelectorAll(‘[data-panel]’);
      function show(id) {{
        sections.forEach(function(s) {{ s.style.display = s.getAttribute(‘data-panel’) === id ? ‘’ : ‘none’; }});
        links.forEach(function(a) {{ a.classList.toggle(‘active’, a.getAttribute(‘data-section’) === id); }});
      }}
      var params = new URLSearchParams(window.location.search);
      var initial = params.get(‘section’) || ‘users’;
      show(initial);
      links.forEach(function(a) {{
        a.addEventListener(‘click’, function(e) {{
          e.preventDefault();
          var id = a.getAttribute(‘data-section’);
          show(id);
          history.replaceState(null, ‘’, ‘/ui/admin?section=’ + id);
        }});
      }});
    }})();
    </script>"#,
        nav_items = nav_items,
        csrf_token = escape_attribute(csrf_token),
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
        git_export_status_html = git_export_status_html,
        oidc_enabled_checked = if oidc_config.enabled { " checked" } else { "" },
        oidc_issuer_url = escape_attribute(&oidc_config.issuer_url),
        oidc_client_id = escape_attribute(&oidc_config.client_id),
        oidc_secret_placeholder = if oidc_config.has_client_secret() {
            "Stored. Leave blank to preserve."
        } else {
            "Paste OIDC client secret"
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
        provider_status_html = provider_status_html,
        latest_agent_token_html = latest_agent_token_html,
        agent_tokens_html = agent_tokens_html,
        project_grants_html = project_grants_html,
        role_grants_html = role_grants_html,
        roles_html = roles_html,
        users_html = users_html,
        pending_actions_html = pending_actions_html,
        audit_html = audit_html,
        auth_audit_html = auth_audit_html,
        users_display = hidden("users"),
        roles_display = hidden("roles"),
        agent_tokens_display = hidden("agent-tokens"),
        agent_setup_display = hidden("agent-setup"),
        librarian_display = hidden("librarian"),
        git_export_display = hidden("git-export"),
        oidc_display = hidden("oidc"),
        external_auth_display = hidden("external-auth"),
        updates_display = hidden("updates"),
        audit_display = hidden("audit"),
    );

    render_shell(
        PageShell {
            title: "Lore admin",
            username: Some(username),
            is_admin: true,
            theme,
            csrf_token: Some(csrf_token),
            flash,
        },
        content,
    )
}

pub fn render_setup_page(config: &ServerConfig, setup_instruction: &str) -> String {
    let base_url = config.base_url();
    let setup_text_url = config.setup_text_url();
    let mcp_url = config.mcp_url();
    let content = format!(
        r#"<h1 class="page-title">Agent setup</h1>

    <div class="layout">
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
            <p>Choose HTTP if the agent runs as a command, shell wrapper, CI task, or any runtime that can make web requests but does not mount MCP servers.</p>
          </div>
        </section>
        <section class="panel">
          <div class="panel-header">
            <h2>When to use MCP</h2>
            <p>Choose MCP when the host runtime natively supports MCP tool servers and you want Lore to appear as a discoverable tool server.</p>
          </div>
        </section>
      </aside>
    </div>

    <section class="panel" style="margin-top: var(--s-6);">
      <div class="panel-header">
        <h2>Copy-paste for your agent</h2>
        <p>Give the block below to the agent, or tell it to open the plain-text setup URL directly.</p>
      </div>
      <div class="padded">
        <textarea readonly style="min-height: 12rem;">{setup_instruction}</textarea>
      </div>
    </section>"#,
        base_url = escape_text(&base_url),
        setup_text_url = escape_text(&setup_text_url),
        mcp_url = escape_text(&mcp_url),
        setup_instruction = escape_text(setup_instruction),
    );

    render_shell(
        PageShell {
            title: "Lore setup",
            username: None,
            is_admin: false,
            theme: config.default_theme,
            csrf_token: None,
            flash: None,
        },
        content,
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
    let preference_label = selected_theme
        .map(UiTheme::display_name)
        .unwrap_or("Use server default");

    let content = format!(
        r#"<h1 class="page-title">Settings</h1>

    <div class="layout">
      <section class="panel">
        <div class="panel-header">
          <h2>Theme</h2>
          <p>Select a theme to preview it. Click Save to keep it.</p>
        </div>
        <form method="post" action="/ui/settings/theme" id="theme-form">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="theme" id="theme-input" value="{current_theme_value}">
          <button type="submit" id="save-theme-btn" disabled>Save theme</button>
        </form>
        <div class="theme-selector padded">
          {theme_selector_cards}
        </div>
      </section>
      <section class="panel">
        <div class="panel-header">
          <h2>Current</h2>
        </div>
        <div class="meta-stack padded">
          <p><strong>Saved preference</strong><br>{preference_label}</p>
          <p><strong>Server default</strong><br>{server_default_label}</p>
        </div>
      </section>
    </div>
    <script>
    (function() {{
      var cards = document.querySelectorAll('.theme-card[data-theme]');
      var input = document.getElementById('theme-input');
      var btn = document.getElementById('save-theme-btn');
      var saved = '{current_theme_value}';
      var params = new URLSearchParams(window.location.search);
      var preview = params.get('preview');
      if (preview && preview !== saved) {{
        btn.disabled = false;
        input.value = preview;
      }}
      cards.forEach(function(card) {{
        card.addEventListener('click', function() {{
          cards.forEach(function(c) {{ c.classList.remove('selected'); }});
          card.classList.add('selected');
          var theme = card.getAttribute('data-theme');
          input.value = theme;
          btn.disabled = (theme === saved);
          window.location.href = '/ui/settings?preview=' + encodeURIComponent(theme);
        }});
      }});
    }})();
    </script>"#,
        csrf_token = escape_attribute(csrf_token),
        current_theme_value = escape_attribute(selected_theme.map(|t| t.as_str()).unwrap_or("")),
        preference_label = escape_text(preference_label),
        server_default_label = escape_text(server_default_theme.display_name()),
        theme_selector_cards =
            render_theme_selector_cards(selected_theme, server_default_theme, theme),
    );

    render_shell(
        PageShell {
            title: "Lore settings",
            username: Some(username),
            is_admin,
            theme,
            csrf_token: Some(csrf_token),
            flash,
        },
        content,
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

    let content = format!(
        r#"<h1 class="page-title">Audit</h1>
    <div class="layout admin-layout">
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
    </div>"#,
        pending_html = pending_html,
        runs_html = runs_html,
        auth_html = auth_html,
    );

    render_shell(
        PageShell {
            title: "Lore admin audit",
            username: Some(username),
            is_admin: true,
            theme,
            csrf_token: Some(csrf_token),
            flash: None,
        },
        content,
    )
}

pub fn render_project_audit_page(
    theme: UiTheme,
    project: &ProjectName,
    display_name: &str,
    username: &str,
    is_admin: bool,
    can_write: bool,
    csrf_token: &str,
    runs: &[UiLibrarianAnswer],
    pending_actions: &[UiPendingLibrarianAction],
) -> String {
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

    let content = format!(
        r#"<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--s-3);">
      <h1 class="page-title" style="margin:0;">{display_name} &mdash; Audit</h1>
      <a class="button-link" href="/ui/{project_slug}">Back to project</a>
    </div>
    <div class="layout">
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
    </div>"#,
        display_name = escape_text(display_name),
        project_slug = escape_attribute(project.as_str()),
        pending_html = pending_html,
        runs_html = runs_html,
    );

    render_shell(
        PageShell {
            title: &format!("Lore audit · {}", display_name),
            username: Some(username),
            is_admin,
            theme,
            csrf_token: Some(csrf_token),
            flash: None,
        },
        content,
    )
}

pub fn render_project_history_page(
    theme: UiTheme,
    project: &ProjectName,
    display_name: &str,
    username: &str,
    is_admin: bool,
    can_write: bool,
    csrf_token: &str,
    versions: &[UiProjectVersion],
) -> String {
    let history_html = if versions.is_empty() {
        "<p class=\"hint padded\">No project versions recorded yet.</p>".to_string()
    } else {
        versions
            .iter()
            .map(|version| render_project_version(project, csrf_token, can_write, version))
            .collect::<Vec<_>>()
            .join("")
    };

    let content = format!(
        r#"<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--s-3);">
      <h1 class="page-title" style="margin:0;">{display_name} &mdash; History</h1>
      <div style="display:flex; gap:var(--s-3);">
        <a class="button-link" href="/ui/{project_slug}">Back to project</a>
        <a class="button-link" href="/ui/{project_slug}/audit">Audit</a>
      </div>
    </div>
    <section class="panel">
      <div class="panel-header">
        <h2>Version history</h2>
        <p>Each recorded version captures exact before/after block snapshots. Revert creates a new version rather than silently deleting history.</p>
      </div>
      <div class="timeline">{history_html}</div>
    </section>"#,
        display_name = escape_text(display_name),
        project_slug = escape_attribute(project.as_str()),
        history_html = history_html,
    );

    render_shell(
        PageShell {
            title: &format!("Lore history · {}", display_name),
            username: Some(username),
            is_admin,
            theme,
            csrf_token: Some(csrf_token),
            flash: None,
        },
        content,
    )
}

pub fn render_project_page(
    theme: UiTheme,
    project: &ProjectName,
    display_name: &str,
    blocks: &[Block],
    all_blocks: &[Block],
    flash: Option<&str>,
    search: Option<&str>,
    search_block_type: Option<&str>,
    search_author: Option<&str>,
    search_include_history: bool,
    username: &str,
    can_write: bool,
    is_admin: bool,
    csrf_token: &str,
    librarian_answer: Option<&UiLibrarianAnswer>,
    librarian_history: &[UiLibrarianAnswer],
    pending_actions: &[UiPendingLibrarianAction],
) -> String {
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
    let blocks_html = if blocks.is_empty() && can_write {
        format!(
            r#"<section class="empty-state"><h2>No blocks yet</h2><p>Click the button below to add the first block.</p></section>{}"#,
            render_block_inserter(project, None, csrf_token),
        )
    } else if blocks.is_empty() {
        r#"<section class="empty-state"><h2>No blocks yet</h2></section>"#.to_string()
    } else {
        let mut html = String::new();
        if can_write {
            html.push_str(&render_block_inserter(project, None, csrf_token));
        }
        for block in blocks {
            html.push_str(&render_block(
                project, block, all_blocks, can_write, csrf_token,
            ));
            if can_write {
                html.push_str(&render_block_inserter(project, Some(&block.id), csrf_token));
            }
        }
        html
    };
    let librarian_panel = render_librarian_panel(
        project,
        csrf_token,
        can_write,
        librarian_answer,
        librarian_history,
        pending_actions,
    );
    let read_only_notice = if !can_write {
        r#"<section class="panel composer"><div class="panel-header"><h2>Read-only access</h2><p>Viewing only.</p></div></section>"#
    } else {
        ""
    };

    let rename_html = if can_write && is_admin {
        format!(
            r#"<h1 class="page-title editable-title" style="margin:0;" id="project-title"
                title="Click to rename" onclick="document.getElementById('rename-form').style.display='flex'; this.style.display='none';"
            >{display_name}</h1>
            <form id="rename-form" method="post" action="/ui/{project_slug}/rename"
                  style="display:none; align-items:center; gap:var(--s-3); margin:0;">
              <input type="hidden" name="csrf_token" value="{csrf_token}">
              <input type="text" name="display_name" value="{display_name_attr}" class="rename-input"
                     autofocus onfocus="this.select()">
              <button type="submit" class="button-link">Save</button>
              <button type="button" class="button-link" onclick="this.closest('form').style.display='none'; document.getElementById('project-title').style.display='';">Cancel</button>
            </form>"#,
            display_name = escape_text(display_name),
            display_name_attr = escape_attribute(display_name),
            project_slug = escape_attribute(project.as_str()),
            csrf_token = escape_attribute(csrf_token),
        )
    } else {
        format!(
            r#"<h1 class="page-title" style="margin:0;">{display_name}</h1>"#,
            display_name = escape_text(display_name),
        )
    };

    let content = format!(
        r#"<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--s-3);">
      {rename_html}
      <div style="display:flex; gap:var(--s-3);">
        <a class="button-link" href="/ui/{project_slug}/audit">Audit</a>
        <a class="button-link" href="/ui/{project_slug}/history">History</a>
      </div>
    </div>
    <form class="searchbar" method="get" action="/ui/{project_slug}">
      <input type="search" name="q" value="{search_value}" placeholder="Search content...">
      <select name="block_type">
        <option value=""{search_any_type}>Any type</option>
        <option value="markdown"{search_markdown}>Markdown</option>
        <option value="svg"{search_svg}>SVG</option>
        <option value="html"{search_html}>HTML</option>
        <option value="image"{search_image}>Image</option>
      </select>
      <input type="search" name="author" value="{search_author}" placeholder="Author...">
      <label class="toggle"><input type="checkbox" name="include_history" value="1"{search_history_checked}> <span>Search document history</span></label>
      <button type="submit">Search</button>
    </form>

    <div class="layout">
      <section class="panel" id="document">
        <div class="panel-header">
          <h2>Document</h2>
          <p>{results_label}</p>
        </div>
        <div class="timeline">{blocks_html}</div>
      </section>
      <aside class="stack">{librarian_panel}{read_only_notice}</aside>
    </div>"#,
        rename_html = rename_html,
        project_slug = escape_attribute(project.as_str()),
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
        search_history_checked = if search_include_history {
            " checked"
        } else {
            ""
        },
        results_label = results_label,
        blocks_html = blocks_html,
        librarian_panel = librarian_panel,
        read_only_notice = read_only_notice,
    );

    render_shell(
        PageShell {
            title: &format!("Lore · {}", display_name),
            username: Some(username),
            is_admin,
            theme,
            csrf_token: Some(csrf_token),
            flash,
        },
        content,
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
            "<p class=\"hint\">Ask for a summary, explanation, or grounded answer about this project.</p>".to_string()
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
    <label class="toggle"><input type="checkbox" name="include_history" value="1"> <span>Search document history</span></label>
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
    <h2>Librarian</h2>
  </div>
  <form method="post" action="/ui/{project}/librarian">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <label>
      Question
      <textarea name="question" placeholder="Summarise the current decisions in this project." required>{question_value}</textarea>
    </label>
    <label class="toggle"><input type="checkbox" name="include_history" value="1"> <span>Search document history</span></label>
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
        LibrarianRunKind::Answer => "Librarian",
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

fn render_role_card(role: &StoredRole, csrf_token: &str, projects: &[ProjectInfo]) -> String {
    let grants = role
        .grants
        .iter()
        .map(|grant| {
            let display = projects
                .iter()
                .find(|p| p.slug == grant.project)
                .map(|p| p.display_name.as_str())
                .unwrap_or(grant.project.as_str());
            format!(
                r#"<li><span class="meta-code">{}</span> <span class="pill small">{}</span></li>"#,
                escape_text(display),
                escape_text(match grant.permission {
                    ProjectPermission::Read => "read",
                    ProjectPermission::ReadWrite => "read_write",
                })
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let form_id = format!("edit-role-{}", role.name.as_str().replace('.', "-"));
    let grants_field_id = format!("{}-grants", form_id);

    let edit_grants_html = if projects.is_empty() {
        "<p class=\"hint\">No projects exist yet.</p>".to_string()
    } else {
        let rows: Vec<String> = projects
            .iter()
            .map(|p| {
                let current = role.grants.iter().find(|g| g.project == p.slug);
                let (no_sel, r_sel, rw_sel) = match current {
                    Some(g) => match g.permission {
                        ProjectPermission::Read => ("", " selected", ""),
                        ProjectPermission::ReadWrite => ("", "", " selected"),
                    },
                    None => ("", "", ""),
                };
                format!(
                    r#"<div class="grant-row" data-project-grant="{}">
                      <span class="grant-project-name">{}</span>
                      <select>
                        <option value=""{}>No access</option>
                        <option value="read"{}>Read</option>
                        <option value="read_write"{}>Read/Write</option>
                      </select>
                    </div>"#,
                    escape_attribute(p.slug.as_str()),
                    escape_text(&p.display_name),
                    no_sel,
                    r_sel,
                    rw_sel,
                )
            })
            .collect();
        format!(
            r#"<fieldset class="grant-fieldset"><legend>Project access</legend>{}</fieldset>"#,
            rows.join("")
        )
    };

    format!(
        r#"<article class="block">
  <div class="block-meta">
    <span class="pill">{name}</span>
    <span>{created_at}</span>
  </div>
  <ul class="grant-list">{grants}</ul>
  <details>
    <summary>Edit role</summary>
    <form method="post" action="/ui/admin/roles/{action_name}" id="{form_id}">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      {edit_grants_html}
      <textarea name="grants" style="display:none" id="{grants_field_id}"></textarea>
      <button type="submit">Update role</button>
    </form>
    <script>
    (function() {{
      var form = document.getElementById('{form_id}');
      form.addEventListener('submit', function() {{
        var rows = form.querySelectorAll('[data-project-grant]');
        var lines = [];
        rows.forEach(function(row) {{
          var sel = row.querySelector('select');
          if (sel && sel.value) {{
            lines.push(row.getAttribute('data-project-grant') + ':' + sel.value);
          }}
        }});
        document.getElementById('{grants_field_id}').value = lines.join('\\n');
      }});
    }})();
    </script>
  </details>
</article>"#,
        name = escape_text(role.name.as_str()),
        created_at = escape_text(&format_timestamp(role.created_at)),
        grants = grants,
        action_name = escape_attribute(role.name.as_str()),
        form_id = form_id,
        csrf_token = escape_attribute(csrf_token),
        edit_grants_html = edit_grants_html,
        grants_field_id = grants_field_id,
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

fn render_block_inserter(
    project: &ProjectName,
    after_block_id: Option<&BlockId>,
    csrf_token: &str,
) -> String {
    let after_value = after_block_id
        .map(|id| escape_attribute(id.as_str()).to_string())
        .unwrap_or_default();
    let project_attr = escape_attribute(project.as_str());
    let csrf_attr = escape_attribute(csrf_token);
    format!(
        r#"<div class="block-inserter">
  <button type="button" class="inserter-btn" onclick="
    var p=this.parentNode;
    var ex=p.querySelector('.inserter-expand');
    if(ex.style.display==='none'){{ex.style.display='';this.textContent='\u{{2212}}'}}
    else{{ex.style.display='none';this.textContent='+'}}
  ">+</button>
  <div class="inserter-expand" style="display:none">
    <div class="inserter-types">
      <button type="button" class="inserter-type-btn" onclick="showInserterForm(this,'md')">Markdown</button>
      <button type="button" class="inserter-type-btn" onclick="showInserterForm(this,'svg')">SVG</button>
      <button type="button" class="inserter-type-btn" onclick="showInserterForm(this,'image')">Image</button>
    </div>
    <form class="inserter-form inserter-form-md" style="display:none" method="post" action="/ui/{project_attr}/blocks" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{csrf_attr}">
      <input type="hidden" name="block_type" value="markdown">
      <input type="hidden" name="after_block_id" value="{after_value}">
      <textarea name="content" placeholder="Write markdown..." rows="6"></textarea>
      <button type="submit">Add markdown</button>
    </form>
    <form class="inserter-form inserter-form-svg" style="display:none" method="post" action="/ui/{project_attr}/blocks" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{csrf_attr}">
      <input type="hidden" name="block_type" value="svg">
      <input type="hidden" name="after_block_id" value="{after_value}">
      <textarea name="content" placeholder="Paste SVG markup or describe what you want..." rows="6"></textarea>
      <label>Or upload an SVG file
        <input type="file" name="image_file" accept=".svg,image/svg+xml">
      </label>
      <button type="submit">Add SVG</button>
    </form>
    <form class="inserter-form inserter-form-image" style="display:none" method="post" action="/ui/{project_attr}/blocks" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{csrf_attr}">
      <input type="hidden" name="block_type" value="image">
      <input type="hidden" name="after_block_id" value="{after_value}">
      <label>Upload image
        <input type="file" name="image_file" accept="image/*">
      </label>
      <textarea name="content" placeholder="Optional caption or note..." rows="2"></textarea>
      <button type="submit">Add image</button>
    </form>
  </div>
</div>"#,
        project_attr = project_attr,
        csrf_attr = csrf_attr,
        after_value = after_value,
    )
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
        .map(|message| {
            let class = if message.starts_with("Incorrect")
                || message.starts_with("Error")
                || message.starts_with("too many")
            {
                "flash flash-error"
            } else {
                "flash"
            };
            format!(
                r#"<p class="{class}" id="flash-msg">{msg}</p>
<script>(function(){{ var f=document.getElementById('flash-msg'); if(f){{ setTimeout(function(){{ f.classList.add('fade-out'); }}, 2000); setTimeout(function(){{ f.remove(); }}, 2500); }} }})()</script>"#,
                class = class,
                msg = escape_text(message),
            )
        })
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
    input_background: &'static str,
    surface_hover: &'static str,
    diff_context_background: &'static str,
    diff_added_background: &'static str,
    diff_added_prefix: &'static str,
    diff_removed_background: &'static str,
    diff_removed_prefix: &'static str,
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
            font_sans: "Inter, -apple-system, system-ui, sans-serif",
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
            input_background: "rgba(255,255,255,0.92)",
            surface_hover: "rgba(255,255,255,0.9)",
            diff_context_background: "rgba(255,255,255,0.94)",
            diff_added_background: "rgba(47, 122, 97, 0.12)",
            diff_added_prefix: "#1d7257",
            diff_removed_background: "rgba(181, 82, 51, 0.12)",
            diff_removed_prefix: "#a33a1d",
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
            input_background: "rgba(255,255,255,0.08)",
            surface_hover: "rgba(255,255,255,0.12)",
            diff_context_background: "rgba(255,255,255,0.04)",
            diff_added_background: "rgba(45, 212, 191, 0.12)",
            diff_added_prefix: "#5eead4",
            diff_removed_background: "rgba(248, 113, 113, 0.14)",
            diff_removed_prefix: "#fca5a5",
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
            font_sans: "Inter, -apple-system, system-ui, sans-serif",
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
            input_background: "rgba(255,255,255,0.92)",
            surface_hover: "rgba(255,255,255,0.9)",
            diff_context_background: "rgba(255,255,255,0.94)",
            diff_added_background: "rgba(47, 122, 97, 0.12)",
            diff_added_prefix: "#1d7257",
            diff_removed_background: "rgba(181, 82, 51, 0.12)",
            diff_removed_prefix: "#a33a1d",
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

fn render_theme_selector_cards(
    selected_theme: Option<UiTheme>,
    server_default_theme: UiTheme,
    active_preview: UiTheme,
) -> String {
    UiTheme::all()
        .into_iter()
        .map(|theme| {
            let is_selected = theme == active_preview;
            let label = if selected_theme == Some(theme) {
                "Saved"
            } else if selected_theme.is_none() && server_default_theme == theme {
                "Default"
            } else {
                ""
            };
            let pill = if !label.is_empty() {
                format!(r#"<span class="pill">{}</span>"#, label)
            } else {
                String::new()
            };
            format!(
                r#"<div class="theme-card{}" data-theme="{}">
  <div class="theme-card-label">
    <strong>{}</strong>
    {}
  </div>
  <div class="theme-preview theme-preview-{}">
    <span></span><span></span><span></span>
  </div>
</div>"#,
                if is_selected { " selected" } else { "" },
                escape_attribute(theme.as_str()),
                escape_text(theme.display_name()),
                pill,
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
      --input-bg: {};
      --surface-hover: {};
      --diff-ctx-bg: {};
      --diff-add-bg: {};
      --diff-add-prefix: {};
      --diff-rm-bg: {};
      --diff-rm-prefix: {};

      --s-1: 4px;
      --s-2: 8px;
      --s-3: 12px;
      --s-4: 16px;
      --s-5: 24px;
      --s-6: 32px;
      --s-7: 48px;
      --s-8: 64px;
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      font-family: var(--font-sans);
      color: var(--ink);
      background: {};
      min-height: 100vh;
      line-height: 1.5;
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
        palette.input_background,
        palette.surface_hover,
        palette.diff_context_background,
        palette.diff_added_background,
        palette.diff_added_prefix,
        palette.diff_removed_background,
        palette.diff_removed_prefix,
        palette.body_background,
    );
    let rest = r#"
    .shell {
      width: min(1080px, calc(100vw - var(--s-6)));
      margin: 0 auto;
      padding: var(--s-5) 0 var(--s-8);
    }

    .top-nav {
      position: sticky;
      top: 0;
      z-index: 100;
      background: var(--panel);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--line);
      margin-bottom: var(--s-6);
    }

    .top-nav-inner {
      width: min(1080px, calc(100vw - var(--s-6)));
      margin: 0 auto;
      height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .top-nav .logo {
      font-weight: 800;
      font-size: 1.25rem;
      text-decoration: none;
      color: var(--ink);
      letter-spacing: -0.02em;
    }

    .top-nav-links {
      display: flex;
      align-items: center;
      gap: var(--s-4);
    }

    .top-nav-links a {
      text-decoration: none;
      color: var(--muted);
      font-weight: 600;
      font-size: 0.95rem;
      transition: color 0.2s;
    }

    .top-nav-links a:hover,
    .top-nav-links a.active {
      color: var(--ink);
    }

    .top-nav-links form {
      padding: 0;
      margin: 0;
    }

    .top-nav-links button {
      background: none;
      color: var(--muted);
      padding: 0;
      font-size: 0.95rem;
      min-height: auto;
      width: auto;
    }

    .top-nav-links button:hover {
      color: var(--ink);
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
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(8px);
    }

    .hero {
      padding: var(--s-6);
      display: grid;
      gap: var(--s-2);
    }

    .auth-panel {
      max-width: 32rem;
      margin: 0 auto;
      padding: var(--s-6);
    }

    .eyebrow {
      margin: 0;
      color: var(--muted);
      font-size: 0.85rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    h1, h2, h3 { margin: 0; }

    h1 {
      font-size: clamp(2.2rem, 5vw, 3.6rem);
      line-height: 1.1;
      letter-spacing: -0.03em;
      font-weight: 800;
    }

    .page-title {
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin: 0 0 var(--s-5) 0;
    }

    .editable-title {
      cursor: pointer;
      border-radius: 4px;
      padding: 2px 6px;
      margin-left: -6px;
      transition: background 0.15s, box-shadow 0.15s;
    }
    .editable-title:hover {
      background: var(--surface-hover);
      box-shadow: 0 0 0 2px var(--line);
    }

    .rename-input {
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      padding: 2px 6px;
      border: 2px solid var(--accent);
      border-radius: 4px;
      background: var(--input-bg);
      color: var(--ink);
      font-family: inherit;
      min-width: 12rem;
    }

    h2 {
      font-size: 1.5rem;
      letter-spacing: -0.02em;
      font-weight: 700;
    }

    .subtitle, .hint, .danger-panel p {
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
    }

    .flash {
      position: fixed;
      top: 80px;
      left: 50%;
      transform: translateX(-50%);
      z-index: 200;
      padding: var(--s-3) var(--s-5);
      border-radius: var(--s-3);
      background: var(--flash-bg);
      color: var(--flash-ink);
      border: 1px solid var(--flash-line);
      font-weight: 600;
      box-shadow: 0 4px 16px rgba(0,0,0,0.12);
      opacity: 1;
      transition: opacity 0.4s ease;
      pointer-events: none;
    }

    .flash.fade-out {
      opacity: 0;
    }

    .flash-error {
      background: rgba(220, 38, 38, 0.10);
      color: #991b1b;
      border-color: rgba(220, 38, 38, 0.25);
    }

    .hero-actions {
      display: flex;
      flex-wrap: wrap;
      gap: var(--s-3);
      margin-top: var(--s-4);
      align-items: center;
    }

    .hero-actions a,
    .button-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 0 var(--s-5);
      border-radius: 999px;
      text-decoration: none;
      border: 1px solid var(--line);
      color: var(--ink);
      background: var(--input-bg);
      font-weight: 700;
      font-size: 0.95rem;
      transition: all 0.2s;
    }

    .hero-actions a:hover,
    .button-link:hover {
      background: var(--surface-hover);
      transform: translateY(-1px);
    }

    .hero-actions a.primary,
    .button-link {
      background: var(--hero-button-bg);
      border-color: transparent;
      color: var(--hero-button-ink);
    }

    .hero-actions a.primary:hover,
    .button-link:hover {
      opacity: 0.9;
    }

    .layout {
      display: grid;
      gap: var(--s-5);
      margin-top: var(--s-6);
      grid-template-columns: minmax(0, 1.6fr) minmax(300px, 0.95fr);
      align-items: start;
    }

    @media (max-width: 800px) {
      .layout {
        grid-template-columns: 1fr;
      }
    }

    .admin-layout {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .stack, .timeline {
      display: grid;
      gap: var(--s-4);
    }

    .project-tree-panel {
      padding: var(--s-5);
    }

    .tree-list {
      list-style: none;
      margin: 0;
      padding: 0;
    }

    .tree-list .tree-list {
      padding-left: var(--s-5);
      border-left: 1px solid var(--line);
      margin-left: var(--s-3);
    }

    .tree-node {
      margin: var(--s-2) 0;
    }

    .tree-node-row {
      display: flex;
      align-items: center;
      gap: var(--s-3);
      padding: var(--s-2) var(--s-3);
      border-radius: var(--radius);
      transition: background 0.15s;
    }

    .tree-node-row:hover {
      background: var(--surface-hover);
    }

    .tree-link {
      font-weight: 600;
      font-size: 1rem;
      color: var(--ink);
      text-decoration: none;
      flex: 1;
      min-width: 0;
    }

    .tree-link:hover {
      color: var(--accent);
    }

    .tree-row-right {
      display: flex;
      align-items: center;
      gap: var(--s-3);
      margin-left: auto;
      flex-shrink: 0;
    }

    .tree-perm {
      font-size: 0.8rem;
      color: var(--muted);
      white-space: nowrap;
    }

    .tree-add-child,
    .tree-add-btn {
      background: none;
      border: 1px solid var(--line);
      color: var(--muted);
      border-radius: var(--radius);
      cursor: pointer;
      font-size: 0.85rem;
      padding: 2px 8px;
      min-height: auto;
    }

    .tree-add-child:hover,
    .tree-add-btn:hover {
      background: var(--surface-hover);
      color: var(--ink);
    }

    .tree-create-root {
      margin-top: var(--s-4);
      padding-top: var(--s-4);
      border-top: 1px solid var(--line);
    }

    .tree-create-row {
      margin: 0;
    }

    .tree-inline-input {
      flex: 1;
      min-width: 0;
      font-size: 1rem;
      font-weight: 600;
      padding: var(--s-1) var(--s-2);
      border: 1px solid var(--accent);
      border-radius: var(--radius);
      background: var(--input-bg);
      color: var(--ink);
      outline: none;
    }

    .tree-create-form button {
      min-height: auto;
      padding: var(--s-2) var(--s-4);
    }

    .timeline {
      padding: var(--s-5);
    }

    .block {
      padding: var(--s-5);
      border: 1px solid var(--line);
      border-radius: var(--s-5);
      background: var(--panel-strong);
      transition: border-color 0.2s;
    }

    .block-inserter {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: var(--s-2) 0;
    }

    .inserter-btn {
      width: 32px;
      height: 32px;
      min-height: auto;
      border-radius: 50%;
      border: 2px dashed var(--line);
      background: transparent;
      color: var(--muted);
      font-size: 1.2rem;
      line-height: 1;
      cursor: pointer;
      padding: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
    }

    .inserter-btn:hover {
      border-color: var(--accent);
      color: var(--accent);
      background: var(--accent-soft);
    }

    .inserter-expand {
      width: 100%;
      margin-top: var(--s-3);
    }

    .inserter-types {
      display: flex;
      gap: var(--s-2);
      justify-content: center;
      margin-bottom: var(--s-3);
    }

    .inserter-type-btn {
      min-height: auto;
      padding: var(--s-2) var(--s-4);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--input-bg);
      color: var(--muted);
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 600;
      width: auto;
      transition: border-color 0.2s, color 0.2s;
    }

    .inserter-type-btn:hover,
    .inserter-type-btn.active {
      border-color: var(--accent);
      color: var(--accent);
    }

    .inserter-form {
      border: 1px solid var(--line);
      border-radius: var(--s-4);
      background: var(--panel-strong);
    }

    .inserter-form textarea {
      min-height: 6rem;
    }

    .panel-header {
      padding: var(--s-5) var(--s-5) 0;
      display: grid;
      gap: var(--s-2);
    }

    .composer {
      position: sticky;
      top: 84px;
      padding: var(--s-5);
    }

    form {
      display: grid;
      gap: var(--s-4);
      padding: var(--s-5);
    }

    label {
      display: grid;
      gap: var(--s-2);
      color: var(--muted);
      font-size: 0.9rem;
      font-weight: 600;
    }

    label.toggle {
      display: flex;
      align-items: center;
      gap: var(--s-3);
      cursor: pointer;
    }

    label.toggle input[type="checkbox"] {
      width: auto;
      margin: 0;
      cursor: pointer;
    }

    input:not([type="checkbox"]), select, textarea, button {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: var(--s-3);
      padding: var(--s-3) var(--s-4);
      font-size: 16px;
      background: var(--input-bg);
      color: var(--ink);
      font-family: inherit;
    }

    input:not([type="checkbox"]):focus, select:focus, textarea:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-soft);
    }

    textarea {
      min-height: 10rem;
      resize: vertical;
      font-family: var(--font-mono);
      font-size: 0.9rem;
    }

    button {
      border: 0;
      background: var(--button-bg);
      color: var(--button-ink);
      font-weight: 700;
      cursor: pointer;
      min-height: 48px;
    }

    button:hover {
      opacity: 0.9;
    }

    button:disabled {
      opacity: 0.4;
      cursor: default;
    }

    button:disabled:hover {
      opacity: 0.4;
    }

    .callout {
      display: grid;
      gap: var(--s-3);
      margin: var(--s-5);
      padding: var(--s-5);
      border-radius: var(--s-4);
      border: 1px solid var(--line);
      background: var(--callout-bg);
    }

    .searchbar {
      display: flex;
      flex-wrap: wrap;
      gap: var(--s-2);
      margin-top: var(--s-4);
    }

    .searchbar input, .searchbar select {
      flex: 1;
      min-width: 120px;
    }

    .searchbar button {
      width: auto;
      padding: 0 var(--s-6);
    }

    .block-meta {
      display: flex;
      flex-wrap: wrap;
      gap: var(--s-2);
      align-items: center;
      margin-bottom: var(--s-4);
      color: var(--muted);
      font-size: 0.85rem;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-weight: 700;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.02em;
    }

    .meta-code {
      font-family: var(--font-mono);
      font-size: 0.8rem;
      background: var(--code-bg);
      color: var(--code-ink);
      padding: 2px 6px;
      border-radius: 6px;
    }

    .block-body {
      font-size: 1.05rem;
      line-height: 1.7;
    }

    .block-body pre {
      margin: var(--s-4) 0;
      padding: var(--s-4);
      border-radius: var(--s-3);
      background: var(--code-bg);
      color: var(--code-ink);
      overflow-x: auto;
      font-size: 0.9rem;
    }

    .media-frame {
      margin: var(--s-4) 0;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      overflow: hidden;
      background: var(--media-bg);
    }

    .media-frame img {
      display: block;
      width: 100%;
      height: auto;
      max-height: 40rem;
      object-fit: contain;
    }

    .block-actions {
      display: flex;
      gap: var(--s-3);
      margin-top: var(--s-5);
      padding-top: var(--s-5);
      border-top: 1px solid var(--line);
    }

    .block-actions button, .block-actions a {
      flex: 1;
    }

    .empty-state {
      padding: var(--s-8) var(--s-5);
      border: 2px dashed var(--line);
      border-radius: var(--radius);
      text-align: center;
      color: var(--muted);
    }

    .theme-preview {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: var(--s-3);
      min-height: 72px;
      margin-top: var(--s-2);
    }

    .theme-preview span {
      border-radius: var(--s-3);
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

    .meta-stack {
      display: grid;
      gap: var(--s-3);
    }

    .padded {
      padding: var(--s-4) var(--s-5);
    }

    .grant-list {
      margin: 0;
      padding-left: var(--s-5);
      color: var(--muted);
    }

    .grant-fieldset {
      border: 1px solid var(--line);
      border-radius: var(--s-3);
      padding: var(--s-3) var(--s-4);
      margin: var(--s-3) 0;
    }
    .grant-fieldset legend {
      font-weight: 600;
      font-size: 0.875rem;
      padding: 0 var(--s-2);
    }
    .grant-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: var(--s-2) 0;
      border-bottom: 1px solid var(--line);
    }
    .grant-row:last-child {
      border-bottom: none;
    }
    .grant-project-name {
      font-family: monospace;
      font-size: 0.875rem;
    }
    .grant-row select {
      width: auto;
      min-width: 8rem;
    }

    .version-meta {
      display: grid;
      gap: var(--s-2);
      margin: var(--s-4) 0;
      padding: var(--s-4);
      border-radius: var(--s-4);
      background: var(--empty-bg);
      border: 1px solid var(--line);
    }

    .diff-list {
      display: grid;
      gap: 1px;
      margin-top: var(--s-3);
      border: 1px solid var(--line);
      border-radius: var(--s-4);
      overflow: hidden;
      background: var(--line);
    }

    .diff-line {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: var(--s-3);
      padding: var(--s-2) var(--s-3);
      font-family: var(--font-mono);
      font-size: 0.88rem;
      background: var(--diff-ctx-bg);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }

    .diff-prefix {
      font-weight: 700;
      color: var(--muted);
    }

    .diff-added { background: var(--diff-add-bg); }
    .diff-added .diff-prefix { color: var(--diff-add-prefix); }
    .diff-removed { background: var(--diff-rm-bg); }
    .diff-removed .diff-prefix { color: var(--diff-rm-prefix); }
    .diff-context { background: var(--diff-ctx-bg); }

    .admin-sidebar-layout {
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr);
      gap: var(--s-5);
      margin-top: var(--s-5);
      align-items: start;
    }

    .admin-nav {
      display: grid;
      gap: 2px;
    }

    .admin-nav a {
      display: block;
      padding: var(--s-3) var(--s-4);
      text-decoration: none;
      color: var(--muted);
      font-weight: 600;
      font-size: 0.92rem;
      border-radius: var(--s-2);
      transition: background 0.15s, color 0.15s;
    }

    .admin-nav a:hover {
      background: var(--accent-soft);
      color: var(--ink);
    }

    .admin-nav a.active {
      background: var(--accent-soft);
      color: var(--accent);
    }

    @media (max-width: 700px) {
      .admin-sidebar-layout {
        grid-template-columns: 1fr;
      }
      .admin-nav {
        grid-auto-flow: column;
        overflow-x: auto;
      }
    }

    .theme-selector {
      display: grid;
      gap: var(--s-4);
    }

    .theme-card {
      padding: var(--s-4);
      border: 2px solid var(--line);
      border-radius: var(--s-4);
      cursor: pointer;
      transition: border-color 0.15s, box-shadow 0.15s;
      background: var(--panel-strong);
    }

    .theme-card:hover {
      border-color: var(--accent);
    }

    .theme-card.selected {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-soft);
    }

    .theme-card-label {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: var(--s-2);
    }

    .theme-card-label strong {
      font-size: 0.95rem;
    }

    .theme-card-label .pill {
      font-size: 0.7rem;
    }

    .inline-form {
      margin-top: var(--s-4);
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
