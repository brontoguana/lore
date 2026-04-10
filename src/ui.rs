use crate::audit::{AuditActor, AuditActorKind};
use crate::auth::{ProjectGrant, ProjectPermission, StoredMachine, StoredRole};
use crate::config::{ColorMode, ExternalAuthConfig, ExternalScheme, OidcConfig, ServerConfig, UiTheme};
use crate::librarian::{
    LibrarianActor, LibrarianActorKind, LibrarianConfig, LibrarianRunKind, LibrarianRunStatus,
    ProjectLibrarianOperationType, ProviderCheckResult, StoredLibrarianOperation,
};
use crate::model::{Block, BlockId, BlockType, ProjectName};
use crate::store::{FileBlockStore, ProjectInfo};
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
    pub color_mode: ColorMode,
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
    <button class="burger-btn" onclick="toggleBurger()" aria-label="Menu">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
    </button>
    <div class="top-nav-links" id="top-nav-links">
      <a href="/ui">Projects</a>
      <a href="/ui/agents">Agents</a>
      <a href="/ui/chat">Chat</a>
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
  function toggleBurger() {{
    var links = document.getElementById('top-nav-links');
    if (links) links.classList.toggle('burger-open');
  }}
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
  function toggleBlockEdit(blockId) {{
    var body = document.getElementById('body-' + blockId);
    var edit = document.getElementById('edit-' + blockId);
    var meta = document.getElementById('meta-' + blockId);
    var article = document.getElementById('block-' + blockId);
    if (!body || !edit) return;
    var row = article.closest('.editline-row');
    var band = row ? row.querySelector('.editline-band') : null;
    if (edit.style.display === 'none') {{
      body.style.display = 'none';
      edit.style.display = '';
      if (meta) meta.style.display = '';
      if (band) band.classList.add('editline-band-active');
      article.classList.add('editing');
      var ta = edit.querySelector('textarea');
      if (ta) {{
        edit.dataset.origContent = ta.value;
        ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length);
      }}
    }} else {{
      body.style.display = '';
      edit.style.display = 'none';
      if (meta) meta.style.display = 'none';
      if (band) band.classList.remove('editline-band-active');
      article.classList.remove('editing');
    }}
  }}
  function cancelBlockEdit(blockId) {{
    var editPanel = document.getElementById('edit-' + blockId);
    if (editPanel) {{
      var ta = editPanel.querySelector('textarea');
      var orig = editPanel.dataset.origContent || '';
      if (ta && ta.value !== orig) {{
        if (!confirm('You have unsaved changes. Discard?')) return;
      }}
    }}
    toggleBlockEdit(blockId);
  }}
  function toggleAgentContext() {{
    var preview = document.getElementById('agent-context-preview');
    var full = document.getElementById('agent-context-full');
    var form = document.getElementById('agent-context-form');
    var band = document.querySelector('.agent-context-band');
    if (!form) return;
    if (form.style.display === 'none') {{
      if (preview) preview.style.display = 'none';
      if (full) full.style.display = 'none';
      form.style.display = '';
      if (band) band.classList.add('editline-band-active');
      var ta = form.querySelector('textarea');
      if (ta) {{ ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); }}
    }} else {{
      if (preview) preview.style.display = '';
      if (full) full.style.display = 'none';
      form.style.display = 'none';
      if (band) band.classList.remove('editline-band-active');
    }}
  }}
  function toggleEditlineInserter(btn) {{
    var row = btn.closest('.editline-gap-row');
    var ins = row ? row.querySelector('.block-inserter') : null;
    if (!ins) return;
    var ex = ins.querySelector('.inserter-expand');
    if (!ex) return;
    if (ex.style.display === 'none') {{
      ex.style.display = '';
      btn.textContent = '\u{{2212}}';
      ins.classList.add('expanded');
    }} else {{
      ex.style.display = 'none';
      btn.textContent = '+';
      ins.classList.remove('expanded');
    }}
  }}
  document.addEventListener('keydown', function(e) {{
    if (e.key !== 'Escape') return;
    // Check for an open edit panel
    var editPanel = document.querySelector('.block-edit-panel[style=""],.block-edit-panel:not([style*="display:none"])');
    if (editPanel && editPanel.style.display !== 'none') {{
      var blockId = editPanel.id.replace('edit-', '');
      cancelBlockEdit(blockId);
      e.preventDefault();
      return;
    }}
    // Check for an open inserter
    var openIns = document.querySelector('.block-inserter.expanded');
    if (openIns) {{
      var ta = openIns.querySelector('textarea');
      var hasContent = false;
      openIns.querySelectorAll('textarea').forEach(function(t) {{ if (t.value.trim()) hasContent = true; }});
      if (hasContent) {{
        if (!confirm('You have unsaved content. Discard?')) return;
        openIns.querySelectorAll('textarea').forEach(function(t) {{ t.value = ''; }});
      }}
      var plusBtn = openIns.closest('.editline-gap-row').querySelector('.editline-plus');
      if (plusBtn) toggleEditlineInserter(plusBtn);
      e.preventDefault();
    }}
  }});
  var _dragBlockId = null;
  function bandDragStart(e) {{
    _dragBlockId = e.currentTarget.dataset.blockId;
    e.currentTarget.classList.add('editline-band-dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', _dragBlockId);
    document.querySelectorAll('.editline-gap').forEach(function(g) {{
      g.classList.add('editline-gap-drop-ready');
    }});
  }}
  function bandDragEnd(e) {{
    _dragBlockId = null;
    e.currentTarget.classList.remove('editline-band-dragging');
    document.querySelectorAll('.editline-gap').forEach(function(g) {{
      g.classList.remove('editline-gap-drop-ready', 'editline-gap-drop-hover');
    }});
  }}
  function gapDragOver(e) {{
    if (!_dragBlockId) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    e.currentTarget.classList.add('editline-gap-drop-hover');
  }}
  function gapDragLeave(e) {{
    e.currentTarget.classList.remove('editline-gap-drop-hover');
  }}
  function gapDrop(e) {{
    e.preventDefault();
    var gap = e.currentTarget;
    gap.classList.remove('editline-gap-drop-hover');
    var afterId = gap.dataset.after || '';
    var blockId = _dragBlockId;
    if (!blockId) return;
    var project = window.location.pathname.split('/ui/')[1];
    if (project) project = project.split('?')[0].split('#')[0];
    if (!project) return;
    var csrf = document.querySelector('input[name="csrf_token"]');
    if (!csrf) return;
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/ui/' + project + '/blocks/' + blockId + '/move';
    form.style.display = 'none';
    var csrfIn = document.createElement('input');
    csrfIn.name = 'csrf_token'; csrfIn.value = csrf.value; form.appendChild(csrfIn);
    var afterIn = document.createElement('input');
    afterIn.name = 'after_block_id'; afterIn.value = afterId; form.appendChild(afterIn);
    document.body.appendChild(form);
    form.submit();
  }}
  function insertDocLink(btn) {{
    var picker = btn.closest('.doc-link-picker');
    var sel = picker.querySelector('.doc-link-select');
    if (!sel.value) return;
    var name = sel.options[sel.selectedIndex].getAttribute('data-name');
    var md = '[' + name + '](lore://' + sel.value + ')';
    var form = picker.closest('form');
    var ta = form.querySelector('textarea[name="content"]');
    if (!ta) return;
    var start = ta.selectionStart;
    var end = ta.selectionEnd;
    var val = ta.value;
    ta.value = val.substring(0, start) + md + val.substring(end);
    ta.selectionStart = ta.selectionEnd = start + md.length;
    ta.focus();
    sel.selectedIndex = 0;
  }}
  function copyLoreLink(uuid) {{
    var md = '[link](lore://' + uuid + ')';
    if (navigator.clipboard) {{
      navigator.clipboard.writeText(md).then(function() {{
        showCopyToast('Link copied');
      }});
    }} else {{
      var ta = document.createElement('textarea');
      ta.value = md; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showCopyToast('Link copied');
    }}
  }}
  function showCopyToast(msg) {{
    var t = document.createElement('div');
    t.textContent = msg;
    t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--panel-strong);color:var(--ink);padding:6px 16px;border-radius:var(--radius);box-shadow:0 2px 8px var(--shadow);z-index:9999;font-size:0.85rem;';
    document.body.appendChild(t);
    setTimeout(function() {{ t.remove(); }}, 2000);
  }}
  </script>
</body>
</html>"#,
        title = escape_text(shell.title),
        styles = shared_styles(shell.theme, shell.color_mode),
        nav_html = nav_html,
        flash_html = flash_html,
        content = content,
    )
}

pub struct ProjectListEntry {
    pub project: ProjectName,
    pub display_name: String,
    pub parent: Option<String>,
    pub sort_order: u64,
    pub can_write: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentTokenSummary {
    pub name: String,
    pub display_name: String,
    pub owner: Option<String>,
    pub grants: Vec<ProjectGrant>,
    pub backend: String,
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
    color_mode: ColorMode,
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
        ""
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
      {subtitle_html}
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
        subtitle_html = if subtitle.is_empty() { String::new() } else { format!("<p class=\"subtitle\">{}</p>", escape_text(subtitle)) },
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
            color_mode,
            csrf_token: None,
            flash,
        },
        content,
    )
}

pub fn render_projects_page(
    theme: UiTheme,
    color_mode: ColorMode,
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
    var dragSlug = null;

    function createRow(parentSlug) {{
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
      return li;
    }}
    function addChildRow(btn, parentSlug) {{
      document.querySelectorAll('.tree-inline-create').forEach(function(el) {{ el.remove(); }});
      var li = createRow(parentSlug);
      var node = btn.closest('.tree-node');
      var childList = node.querySelector(':scope > .tree-list');
      if (!childList) {{
        childList = document.createElement('ul');
        childList.className = 'tree-list';
        node.appendChild(childList);
      }}
      childList.appendChild(li);
      li.querySelector('input[name="project_name"]').focus();
    }}
    function addSiblingRow(btn, parentSlug) {{
      document.querySelectorAll('.tree-inline-create').forEach(function(el) {{ el.remove(); }});
      var li = createRow(parentSlug);
      var list = document.querySelector('.project-tree-panel .tree-list');
      if (list) {{
        list.appendChild(li);
      }} else {{
        var panel = document.querySelector('.project-tree-panel');
        var empty = panel.querySelector('.empty-state');
        if (empty) empty.remove();
        var ul = document.createElement('ul');
        ul.className = 'tree-list';
        ul.appendChild(li);
        panel.insertBefore(ul, panel.querySelector('.tree-create-root'));
      }}
      li.querySelector('input[name="project_name"]').focus();
    }}

    /* --- Drag and drop --- */
    function onHandleDragStart(e) {{
      e.stopPropagation();
      var node = e.target.closest('.tree-node');
      dragSlug = node.getAttribute('data-slug');
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', dragSlug);
      node.classList.add('tree-dragging');
      // Show all drop zones
      setTimeout(function() {{
        document.querySelectorAll('.tree-drop-zone').forEach(function(z) {{
          z.classList.add('tree-drop-visible');
        }});
        document.querySelectorAll('.tree-node-row').forEach(function(r) {{
          r.classList.add('tree-drop-target-ready');
        }});
      }}, 0);
    }}
    function onDragEnd(e) {{
      dragSlug = null;
      document.querySelectorAll('.tree-dragging').forEach(function(el) {{ el.classList.remove('tree-dragging'); }});
      document.querySelectorAll('.tree-drop-visible').forEach(function(el) {{ el.classList.remove('tree-drop-visible'); }});
      document.querySelectorAll('.tree-drop-hover').forEach(function(el) {{ el.classList.remove('tree-drop-hover'); }});
      document.querySelectorAll('.tree-drop-target-ready').forEach(function(el) {{ el.classList.remove('tree-drop-target-ready'); }});
      document.querySelectorAll('.tree-node-drop-hover').forEach(function(el) {{ el.classList.remove('tree-node-drop-hover'); }});
    }}

    /* Drop between items (reorder as sibling) */
    function onDragOver(e) {{
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      e.target.closest('.tree-drop-zone').classList.add('tree-drop-hover');
    }}
    function onDragLeave(e) {{
      e.target.closest('.tree-drop-zone').classList.remove('tree-drop-hover');
    }}
    function onDrop(e) {{
      e.preventDefault();
      var zone = e.target.closest('.tree-drop-zone');
      var newParent = zone.getAttribute('data-parent');
      var after = zone.getAttribute('data-after');
      submitMove(dragSlug, newParent, after);
    }}

    /* Drop onto a node (make it a child) */
    function onNodeDragOver(e) {{
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      var node = e.target.closest('.tree-node');
      if (node && node.getAttribute('data-slug') !== dragSlug) {{
        e.target.closest('.tree-node-row').classList.add('tree-node-drop-hover');
      }}
    }}
    function onNodeDragLeave(e) {{
      e.target.closest('.tree-node-row').classList.remove('tree-node-drop-hover');
    }}
    function onNodeDrop(e) {{
      e.preventDefault();
      var row = e.target.closest('.tree-node-row');
      row.classList.remove('tree-node-drop-hover');
      var node = row.closest('.tree-node');
      var targetSlug = node.getAttribute('data-slug');
      if (targetSlug === dragSlug) return;
      // Make it the last child of the target
      submitMove(dragSlug, targetSlug, '');
    }}

    function submitMove(slug, newParent, after) {{
      var form = document.createElement('form');
      form.method = 'POST';
      form.action = '/ui/' + encodeURIComponent(slug) + '/move';
      form.innerHTML = '<input type="hidden" name="csrf_token" value="' + csrfToken + '">'
        + '<input type="hidden" name="new_parent" value="' + (newParent || '') + '">'
        + '<input type="hidden" name="after" value="' + (after || '') + '">';
      document.body.appendChild(form);
      form.submit();
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
            color_mode,
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

        let items: Vec<String> = children
            .iter()
            .map(|entry| {
                let slug = entry.project.as_str();
                let display = escape_text(&entry.display_name);
                let perm = if entry.can_write { "read/write" } else { "read-only" };
                let parent_attr = entry.parent.as_deref().unwrap_or("");
                let sub = render_children(
                    Some(slug),
                    projects,
                    is_admin,
                    csrf_token,
                    depth + 1,
                );

                let admin_btns = if is_admin {
                    format!(
                        r#"<button type="button" class="tree-add-child" onclick="event.stopPropagation(); addChildRow(this, '{slug_attr}')">+</button><button type="button" class="tree-drag-handle" draggable="true" ondragstart="onHandleDragStart(event)" ondragend="onDragEnd(event)" title="Drag to move"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/></svg></button>"#,
                        slug_attr = escape_attribute(slug),
                    )
                } else {
                    String::new()
                };

                let drop_zone = if is_admin {
                    format!(
                        r#"<div class="tree-drop-zone" data-parent="{parent_attr}" data-after="{slug}" ondragover="onDragOver(event)" ondragleave="onDragLeave(event)" ondrop="onDrop(event)"></div>"#,
                        parent_attr = escape_attribute(parent_attr),
                        slug = escape_attribute(slug),
                    )
                } else {
                    String::new()
                };

                format!(
                    r#"<li class="tree-node" data-slug="{slug}" data-parent="{parent_attr}">
  <div class="tree-node-row" ondragover="onNodeDragOver(event)" ondragleave="onNodeDragLeave(event)" ondrop="onNodeDrop(event)">
    <a href="/ui/{slug}" class="tree-link">{display}</a>
    <div class="tree-row-right">
      <span class="tree-perm">{perm}</span>
      {admin_btns}
    </div>
  </div>
  {sub}
  {drop_zone}
</li>"#,
                    slug = escape_attribute(slug),
                    parent_attr = escape_attribute(parent_attr),
                    display = display,
                    perm = perm,
                    admin_btns = admin_btns,
                    sub = sub,
                    drop_zone = drop_zone,
                )
            })
            .collect();

        let list_parent = parent.unwrap_or("");
        let top_drop = if is_admin {
            format!(
                r#"<div class="tree-drop-zone tree-drop-zone-top" data-parent="{lp}" data-after="" ondragover="onDragOver(event)" ondragleave="onDragLeave(event)" ondrop="onDrop(event)"></div>"#,
                lp = escape_attribute(list_parent),
            )
        } else {
            String::new()
        };

        format!(r#"<ul class="tree-list" data-parent="{lp}">{top_drop}{items}</ul>"#,
            lp = escape_attribute(list_parent),
            top_drop = top_drop,
            items = items.join(""),
        )
    }

    render_children(None, projects, is_admin, csrf_token, 0)
}

pub fn render_admin_page(
    theme: UiTheme,
    color_mode: ColorMode,
    username: &str,
    csrf_token: &str,
    roles: &[StoredRole],
    users: &[UiUserSummary],
    user_agents: &std::collections::HashMap<String, Vec<AgentTokenSummary>>,
    user_machines: &std::collections::HashMap<String, Vec<StoredMachine>>,
    server_config: &ServerConfig,
    external_auth_config: &ExternalAuthConfig,
    oidc_config: &OidcConfig,
    auto_update_config: &AutoUpdateConfig,
    librarian_config: &LibrarianConfig,
    git_export_config: &GitExportConfig,
    auto_update_status: Option<&AutoUpdateStatus>,
    provider_status: Option<ProviderCheckResult>,
    git_export_status: Option<&GitExportStatus>,
    librarian_audit: &[UiLibrarianAnswer],
    pending_actions: &[UiPendingLibrarianAction],
    auth_audit: &[UiAuditEvent],
    projects: &[ProjectInfo],
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
    let users_list_html = if users.is_empty() {
        "<p class=\"hint padded\">No users exist yet.</p>".to_string()
    } else {
        let items: Vec<String> = users
            .iter()
            .map(|user| {
                let badge = if user.is_admin { "admin" } else { "user" };
                let disabled_badge = if user.disabled { r#" <span class="pill" style="background:var(--danger);color:#fff;font-size:0.7rem;">disabled</span>"# } else { "" };
                format!(
                    r#"<div class="user-list-item" data-username="{username_attr}">
                      <span class="user-list-name">{username}</span>
                      <span class="user-list-meta"><span class="pill">{badge}</span>{disabled} &middot; {sessions} sessions</span>
                    </div>"#,
                    username_attr = escape_attribute(&user.username),
                    username = escape_text(&user.username),
                    badge = badge,
                    disabled = disabled_badge,
                    sessions = user.active_sessions,
                )
            })
            .collect();
        format!(r#"<div class="user-list">{}</div>"#, items.join(""))
    };
    let users_detail_html: String = users
        .iter()
        .map(|user| {
            let agents = user_agents.get(&user.username);
            let machines = user_machines.get(&user.username);
            render_user_detail(
                user,
                agents.map(|v| v.as_slice()).unwrap_or(&[]),
                machines.map(|v| v.as_slice()).unwrap_or(&[]),
                csrf_token,
            )
        })
        .collect::<Vec<_>>()
        .join("");
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
    let pending_actions_html = if pending_actions.is_empty() {
        "<p class=\"hint padded\">No pending librarian actions.</p>".to_string()
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
    let current_version = env!("CARGO_PKG_VERSION");
    let update_now_button = format!(
        r#"<button type="button" id="update-btn" data-csrf="{csrf_token}" data-state="check">Check for updates</button>"#,
        csrf_token = csrf_token,
    );
    let _ = auto_update_status; // no longer rendered

    let sections = [
        "users",
        "roles",
        "network",
        "librarian",
        "git-export",
        "oidc",
        "external-auth",
        "updates",
        "audit",
    ];
    let section_labels = [
        "Users",
        "User Roles",
        "Network",
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
        <div class="panel-header"><h2>Users</h2></div>
        {users_list_html}
        <div id="user-detail-container">{users_detail_html}</div>
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
        <div class="panel-header"><h2>User Roles</h2><p>Grants define project-level visibility and editing.</p></div>
        <div class="timeline">{roles_html}</div>
      </section>

      <section class="panel" data-panel="network"{network_display}>
        <div class="panel-header">
          <h2>Network</h2>
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
          <button type="submit">Save setup address</button>
        </form>
        <div class="meta-stack padded">
          <p><strong>Setup page</strong><br>{setup_url}</p>
          <p><strong>Plain text page</strong><br>{setup_text_url}</p>
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
            <span>Require approval before librarian edit actions</span>
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
          <h2>Server Update</h2>
          <p>Current version: v{current_version}</p>
        </div>
        <div style="padding:0 var(--s-5)">
          {update_now_button}
        </div>

        <div class="panel-header" style="margin-top:var(--s-5)">
          <h2>Auto Update</h2>
          <p>Configure automatic updates on server restart.</p>
        </div>
        <label class="toggle" style="padding:var(--s-5);">
          <input type="checkbox" id="auto-update-toggle" data-csrf="{csrf_token}"{auto_update_enabled_checked}>
          <span>Enable automatic server self-update on restart</span>
        </label>
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
      var nav = document.getElementById('admin-nav');
      var panels = document.getElementById('admin-panels');
      var links = nav.querySelectorAll('a[data-section]');
      var sections = panels.querySelectorAll('[data-panel]');
      function show(id) {{
        sections.forEach(function(s) {{ s.style.display = s.getAttribute('data-panel') === id ? '' : 'none'; }});
        links.forEach(function(a) {{ a.classList.toggle('active', a.getAttribute('data-section') === id); }});
      }}
      var params = new URLSearchParams(window.location.search);
      var initial = params.get('section') || 'users';
      show(initial);
      links.forEach(function(a) {{
        a.addEventListener('click', function(e) {{
          e.preventDefault();
          var id = a.getAttribute('data-section');
          show(id);
          history.replaceState(null, '', '/ui/admin?section=' + id);
        }});
      }});

      var ubtn = document.getElementById('update-btn');
      if (ubtn) {{
        function resetBtn() {{
          ubtn.textContent = 'Check for updates';
          ubtn.setAttribute('data-state', 'check');
          ubtn.disabled = false;
        }}
        ubtn.addEventListener('click', function() {{
          var state = ubtn.getAttribute('data-state');
          var csrf = ubtn.getAttribute('data-csrf');
          if (state === 'check') {{
            ubtn.disabled = true;
            ubtn.textContent = 'Checking\u2026';
            var ac = new AbortController();
            setTimeout(function() {{ ac.abort(); }}, 20000);
            fetch('/ui/admin/auto-update/check-json', {{
              method: 'POST',
              headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
              body: 'csrf_token=' + encodeURIComponent(csrf),
              signal: ac.signal
            }}).then(function(r) {{
              if (!r.ok) throw new Error('server returned ' + r.status);
              return r.json();
            }}).then(function(d) {{
              if (d.latest_version && d.latest_version !== d.current_version) {{
                ubtn.textContent = 'Update to v' + d.latest_version;
                ubtn.setAttribute('data-state', 'apply');
                ubtn.disabled = false;
              }} else {{
                ubtn.textContent = 'Up to date (v' + d.current_version + ')';
                ubtn.disabled = true;
                setTimeout(resetBtn, 4000);
              }}
            }}).catch(function(e) {{
              ubtn.textContent = 'Check failed';
              console.error('update check:', e);
              setTimeout(resetBtn, 3000);
            }});
          }} else if (state === 'apply') {{
            ubtn.disabled = true;
            ubtn.textContent = 'Applying update\u2026';
            var ac2 = new AbortController();
            setTimeout(function() {{ ac2.abort(); }}, 30000);
            fetch('/ui/admin/auto-update/apply-json', {{
              method: 'POST',
              headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
              body: 'csrf_token=' + encodeURIComponent(csrf),
              signal: ac2.signal
            }}).then(function(r) {{
              if (!r.ok) throw new Error('server returned ' + r.status);
              return r.json();
            }}).then(function(d) {{
              if (d.applied) {{
                ubtn.textContent = 'Restarting\u2026';
              }} else {{
                ubtn.textContent = 'Up to date (v' + d.current_version + ')';
                ubtn.disabled = true;
                setTimeout(resetBtn, 4000);
              }}
            }}).catch(function() {{
              ubtn.textContent = 'Update failed';
              setTimeout(resetBtn, 3000);
            }});
          }}
        }});
      }}

      var autoCb = document.getElementById('auto-update-toggle');
      if (autoCb) {{
        autoCb.addEventListener('change', function() {{
          var csrf = autoCb.getAttribute('data-csrf');
          fetch('/ui/admin/auto-update/toggle-json', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
            body: 'csrf_token=' + encodeURIComponent(csrf) + '&enabled=' + autoCb.checked
          }});
        }});
      }}

      var userItems = document.querySelectorAll('.user-list-item');
      var userDetails = document.querySelectorAll('.user-detail');
      userItems.forEach(function(item) {{
        item.addEventListener('click', function() {{
          var name = item.getAttribute('data-username');
          var wasActive = item.classList.contains('active');
          userItems.forEach(function(i) {{ i.classList.remove('active'); }});
          userDetails.forEach(function(d) {{ d.style.display = 'none'; }});
          if (!wasActive) {{
            item.classList.add('active');
            var detail = document.querySelector('.user-detail[data-user-detail="' + name + '"]');
            if (detail) detail.style.display = '';
          }}
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
        external_host = escape_attribute(&server_config.external_host),
        external_port = server_config.external_port,
        setup_url = escape_text(&server_config.setup_url()),
        setup_text_url = escape_text(&server_config.setup_text_url()),
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
        current_version = current_version,
        update_now_button = update_now_button,
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
        role_grants_html = role_grants_html,
        roles_html = roles_html,
        users_list_html = users_list_html,
        users_detail_html = users_detail_html,
        pending_actions_html = pending_actions_html,
        audit_html = audit_html,
        auth_audit_html = auth_audit_html,
        users_display = hidden("users"),
        roles_display = hidden("roles"),
        network_display = hidden("network"),
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
            color_mode,
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
            color_mode: ColorMode::System,
            csrf_token: None,
            flash: None,
        },
        content,
    )
}

pub struct UserProjectAccess {
    pub slug: String,
    pub display_name: String,
    pub max_permission: ProjectPermission,
}

pub fn render_agents_page(
    config: &ServerConfig,
    username: &str,
    is_admin: bool,
    theme: UiTheme,
    color_mode: ColorMode,
    csrf_token: &str,
    agents: &[AgentTokenSummary],
    machines: &[StoredMachine],
    user_projects: &[UserProjectAccess],
    selected_agent: Option<&str>,
    flash: Option<&str>,
) -> String {
    let base_url = config.base_url();
    let mcp_url = config.mcp_url();
    let install_script_url =
        "https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-cli.sh";
    let install_ps1_url =
        "https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-cli.ps1";

    // Agent list
    let agent_list_html = if agents.is_empty() {
        r#"<p class="hint padded">No agents yet. Use <code>lore setup</code> and <code>lore agent</code> from the CLI to create one.</p>"#.to_string()
    } else {
        agents
            .iter()
            .map(|agent| {
                let active = selected_agent == Some(agent.name.as_str());
                let cls = if active { " active" } else { "" };
                let grant_count = agent.grants.len();
                let grant_label = if grant_count == 1 {
                    "1 project".to_string()
                } else {
                    format!("{grant_count} projects")
                };
                format!(
                    r#"<a href="/ui/agents?selected={}" class="agent-list-item{}">
                      <span class="agent-list-name">{}</span>
                      <span class="agent-list-meta">{} &middot; {}</span>
                    </a>"#,
                    escape_attribute(&agent.name),
                    cls,
                    escape_text(&agent.display_name),
                    escape_text(&grant_label),
                    escape_text(&agent.backend),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    // Machines list
    let machines_html = if machines.is_empty() {
        r#"<p class="hint padded">No machines registered.</p>"#.to_string()
    } else {
        machines
            .iter()
            .map(|m| {
                format!(
                    r#"<div class="agent-list-item" style="display:flex; justify-content:space-between; align-items:center;">
                      <span class="agent-list-name">{}</span>
                      <form method="post" action="/ui/agents/machines/{}/revoke" class="inline-form" style="margin:0;">
                        <input type="hidden" name="csrf_token" value="{}">
                        <button class="danger" type="submit" style="font-size:0.8rem; padding:var(--s-1) var(--s-2);">Revoke</button>
                      </form>
                    </div>"#,
                    escape_text(&m.name),
                    escape_attribute(&m.name),
                    escape_attribute(csrf_token),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    // Selected agent detail
    let detail_html = if let Some(sel_name) = selected_agent {
        if let Some(agent) = agents.iter().find(|a| a.name == sel_name) {
            let setup_instruction = build_agent_setup_instruction_text(
                &base_url,
                &mcp_url,
                install_script_url,
                install_ps1_url,
                "YOUR_TOKEN",
            );
            let mcp_config_text = format!(
                r#"{{"transport": "streamable_http","url": "{}","headers": {{"Authorization": "Bearer YOUR_TOKEN","Accept": "application/json, text/event-stream","MCP-Protocol-Version": "2025-06-18"}}}}"#,
                escape_text(&mcp_url),
            );
            // Grants editor
            let edit_grants_html = if user_projects.is_empty() {
                "<p class=\"hint\">No projects available.</p>".to_string()
            } else {
                let rows: Vec<String> = user_projects
                    .iter()
                    .map(|p| {
                        let current = agent.grants.iter().find(|g| g.project.as_str() == p.slug);
                        let no_sel = if current.is_none() { " selected" } else { "" };
                        let r_sel = if current
                            .map(|g| g.permission == ProjectPermission::Read)
                            .unwrap_or(false)
                        {
                            " selected"
                        } else {
                            ""
                        };
                        let rw_sel = if current
                            .map(|g| g.permission == ProjectPermission::ReadWrite)
                            .unwrap_or(false)
                        {
                            " selected"
                        } else {
                            ""
                        };
                        let rw_option = if p.max_permission.allows_write() {
                            format!(r#"<option value="read_write"{rw_sel}>Read/Write</option>"#)
                        } else {
                            String::new()
                        };
                        format!(
                            r#"<div class="grant-row" data-project-grant="{}">
                              <span class="grant-project-name">{}</span>
                              <select>
                                <option value=""{no_sel}>No access</option>
                                <option value="read"{r_sel}>Read</option>
                                {rw_option}
                              </select>
                            </div>"#,
                            escape_attribute(&p.slug),
                            escape_text(&p.display_name),
                        )
                    })
                    .collect();
                format!(
                    r#"<fieldset class="grant-fieldset"><legend>Project access</legend>{}</fieldset>"#,
                    rows.join("")
                )
            };

            format!(
                r##"<section class="panel" style="margin-top: var(--s-5);">
                <div class="panel-header"><h2>{display_name}</h2><p>{owner}-{slug} &middot; {backend}</p></div>

                <div class="panel-header"><h3>Configuration</h3></div>
                <form method="post" action="/ui/agents/{name_attr}/grants" id="edit-grants-form">
                  <input type="hidden" name="csrf_token" value="{csrf_token}">
                  {edit_grants_html}
                  <textarea name="grants" style="display:none" id="edit-grants-field"></textarea>
                  <button type="submit">Save</button>
                </form>
                <script>
                (function() {{
                  var form = document.getElementById('edit-grants-form');
                  form.addEventListener('submit', function() {{
                    var rows = form.querySelectorAll('[data-project-grant]');
                    var lines = [];
                    rows.forEach(function(row) {{
                      var sel = row.querySelector('select');
                      if (sel && sel.value) {{
                        lines.push(row.getAttribute('data-project-grant') + ':' + sel.value);
                      }}
                    }});
                    document.getElementById('edit-grants-field').value = lines.join('\n');
                  }});
                }})();
                </script>

                <div class="panel-header"><h3>Setup instructions</h3><p>Copy and give to your agent.</p></div>
                <div class="padded">
                  <textarea readonly id="agent-instruction" style="min-height: 8rem; font-family: var(--font-mono); font-size: 0.85rem;">{setup_instruction}</textarea>
                  <div style="margin-top: var(--s-3); text-align: right;">
                    <button type="button" class="button-link" onclick="copyField('agent-instruction')">Copy</button>
                  </div>
                </div>

                <div class="panel-header"><h3>MCP config</h3></div>
                <div class="padded">
                  <textarea readonly id="mcp-config" style="min-height:8rem; font-family:var(--font-mono); font-size:0.85rem;">{mcp_config_text}</textarea>
                  <div style="margin-top: var(--s-2); text-align: right;">
                    <button type="button" class="button-link" onclick="copyField('mcp-config')">Copy</button>
                  </div>
                </div>

                <div class="padded" style="border-top: 1px solid var(--line); margin-top: var(--s-4); padding-top: var(--s-4);">
                  <form method="post" action="/ui/agents/{name_attr}/delete" class="inline-form">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <button class="danger" type="submit">Delete agent</button>
                  </form>
                </div>
              </section>"##,
                display_name = escape_text(&agent.display_name),
                slug = escape_text(&agent.name),
                owner = escape_text(username),
                backend = escape_text(&agent.backend),
                name_attr = escape_attribute(&agent.name),
                csrf_token = escape_attribute(csrf_token),
                edit_grants_html = edit_grants_html,
                setup_instruction = escape_text(&setup_instruction),
                mcp_config_text = escape_text(&mcp_config_text),
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let content = format!(
        r##"<h1 class="page-title">My Agents</h1>

    <section class="panel">
      <div class="panel-header">
        <h2>Machines</h2>
        <p>Registered machines that can provision agents for your account. <a href="/ui/agents/guide">Setup guide</a></p>
      </div>
      <div class="agent-list">{machines_html}</div>
    </section>

    <section class="panel" style="margin-top: var(--s-5);">
      <div class="panel-header">
        <h2>Agents</h2>
        <p>Each agent gets its own scoped token and project access.</p>
      </div>
      <div class="agent-list">{agent_list_html}</div>
    </section>

    {detail_html}

    <script>
    function copyField(id) {{
      var el = document.getElementById(id);
      if (!el) return;
      navigator.clipboard.writeText(el.value).then(function() {{
        var btn = event && event.target && event.target.closest('button');
        if (btn) {{ var orig = btn.textContent; btn.textContent = 'Copied'; setTimeout(function(){{ btn.textContent = orig; }}, 1500); }}
      }});
    }}
    </script>"##,
        agent_list_html = agent_list_html,
        machines_html = machines_html,
        detail_html = detail_html,
    );

    render_shell(
        PageShell {
            title: "Lore agents",
            username: Some(username),
            is_admin,
            theme,
            color_mode,
            csrf_token: None,
            flash,
        },
        content,
    )
}

fn build_agent_setup_instruction_text(
    base_url: &str,
    mcp_url: &str,
    install_script_url: &str,
    install_ps1_url: &str,
    token: &str,
) -> String {
    format!(
        r#"# Lore — shared project knowledge base

Lore is a structured knowledge base your team uses to store and retrieve project documentation, decisions, and context. You can read and write project documents made up of ordered blocks (markdown, SVG, or images).

## Server

Base URL: {base_url}
MCP endpoint: {mcp_url}

## Authentication

All requests require an agent token. Include it as:
  Authorization: Bearer {token}

## How to connect

### Option 1 — Lore CLI (recommended for code agents)

Install (Linux/macOS):
  curl -fsSL {install_script_url} | sh

Install (Windows PowerShell):
  irm {install_ps1_url} | iex

Configure (registers this machine and saves credentials):
  lore setup {base_url}

Commands:
  lore projects                     — list projects
  lore blocks list <project>        — list blocks in a project
  lore blocks read <project>        — read all block content
  lore grep <project> -q "query"    — search blocks
  lore add <project> --type markdown --content "..."  — add a block
  lore update <block-id> --content "..."              — update a block
  lore delete <block-id>            — delete a block
  lore history list <project>       — view project history
  lore librarian answer <project> -q "question"       — ask the librarian

### Option 2 — MCP (for MCP-native hosts)

Add this to your MCP client config (Claude Desktop, Cursor, etc.):

{{
  "transport": "streamable_http",
  "url": "{mcp_url}",
  "headers": {{
    "Authorization": "Bearer {token}",
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-06-18"
  }}
}}

Available MCP tools: list_projects, list_blocks, read_block, read_blocks_around, grep_blocks, create_block, update_block, move_block, delete_block.

## Add to your persistent config

Add the following to your memory or config file (CLAUDE.md, AGENTS.md, GEMINI.md, or equivalent):

- Use Lore for project information, tracking, and updates.
- If the Lore MCP server is available, use it (server URL: {mcp_url}). Otherwise use the Lore CLI — run `lore help` for usage details.

## Usage guidance

- Read existing blocks before creating new ones to avoid duplicating content
- Use markdown blocks for text content
- Use the librarian to ask questions about project context
- Link between documents using lore:// links in standard markdown format"#,
    )
}

pub fn render_settings_page(
    theme: UiTheme,
    color_mode: ColorMode,
    username: &str,
    csrf_token: &str,
    selected_theme: Option<UiTheme>,
    selected_color_mode: Option<ColorMode>,
    server_default_theme: UiTheme,
    is_admin: bool,
    flash: Option<&str>,
) -> String {
    let preference_label = selected_theme
        .map(UiTheme::display_name)
        .unwrap_or("Use server default");

    let mode_label = selected_color_mode
        .map(ColorMode::display_name)
        .unwrap_or("Follow system");

    let mode_options: String = ColorMode::all()
        .into_iter()
        .map(|m| {
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                m.as_str(),
                if selected_color_mode == Some(m) {
                    " selected"
                } else if selected_color_mode.is_none() && m == ColorMode::System {
                    " selected"
                } else {
                    ""
                },
                escape_text(m.display_name())
            )
        })
        .collect();

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
          <input type="hidden" name="color_mode" id="mode-input" value="{current_mode_value}">
          <button type="submit" id="save-theme-btn" disabled>Save theme</button>
        </form>
        <div class="theme-selector padded">
          {theme_selector_cards}
        </div>
        <div class="padded" style="padding-top:0;">
          <label style="font-weight:600; font-size:0.85rem; margin-bottom:var(--s-1); display:block;">Appearance</label>
          <select id="mode-select" style="max-width:200px;">
            {mode_options}
          </select>
        </div>
      </section>
      <section class="panel">
        <div class="panel-header">
          <h2>Current</h2>
        </div>
        <div class="meta-stack padded">
          <p><strong>Theme</strong><br>{preference_label}</p>
          <p><strong>Appearance</strong><br>{mode_label}</p>
          <p><strong>Server default</strong><br>{server_default_label}</p>
          <p><strong>Server version</strong><br>v{server_version}</p>
        </div>
      </section>
    </div>
    <script>
    (function() {{
      var cards = document.querySelectorAll('.theme-card[data-theme]');
      var themeInput = document.getElementById('theme-input');
      var modeInput = document.getElementById('mode-input');
      var modeSelect = document.getElementById('mode-select');
      var btn = document.getElementById('save-theme-btn');
      var savedTheme = '{current_theme_value}';
      var savedMode = '{current_mode_value}';
      var params = new URLSearchParams(window.location.search);
      var preview = params.get('preview');
      var previewMode = params.get('mode');
      if (preview && preview !== savedTheme) {{
        btn.disabled = false;
        themeInput.value = preview;
      }}
      if (previewMode) {{
        modeSelect.value = previewMode;
        modeInput.value = previewMode;
        if (previewMode !== savedMode) btn.disabled = false;
      }}
      function checkDirty() {{
        btn.disabled = (themeInput.value === savedTheme && modeInput.value === savedMode);
      }}
      cards.forEach(function(card) {{
        card.addEventListener('click', function() {{
          cards.forEach(function(c) {{ c.classList.remove('selected'); }});
          card.classList.add('selected');
          var theme = card.getAttribute('data-theme');
          themeInput.value = theme;
          var url = '/ui/settings?preview=' + encodeURIComponent(theme) + '&mode=' + encodeURIComponent(modeInput.value);
          window.location.href = url;
        }});
      }});
      modeSelect.addEventListener('change', function() {{
        modeInput.value = modeSelect.value;
        var url = '/ui/settings?preview=' + encodeURIComponent(themeInput.value) + '&mode=' + encodeURIComponent(modeSelect.value);
        window.location.href = url;
      }});
    }})();
    </script>"#,
        csrf_token = escape_attribute(csrf_token),
        current_theme_value = escape_attribute(selected_theme.map(|t| t.as_str()).unwrap_or("")),
        current_mode_value = escape_attribute(
            selected_color_mode
                .map(|m| m.as_str())
                .unwrap_or("system")
        ),
        preference_label = escape_text(preference_label),
        mode_label = escape_text(mode_label),
        server_default_label = escape_text(server_default_theme.display_name()),
        theme_selector_cards =
            render_theme_selector_cards(selected_theme, server_default_theme, theme),
        mode_options = mode_options,
        server_version = env!("CARGO_PKG_VERSION"),
    );

    render_shell(
        PageShell {
            title: "Lore settings",
            username: Some(username),
            is_admin,
            theme,
            color_mode,
            csrf_token: Some(csrf_token),
            flash,
        },
        content,
    )
}

#[derive(Debug, Clone)]
pub struct ChatAgentSummary {
    pub name: String,
    pub display_name: String,
    pub owner: String,
    pub status: String,
    pub last_message: Option<String>,
    pub last_message_time: Option<String>,
    pub profile_url: Option<String>,
}

pub fn render_agent_guide_page(
    config: &ServerConfig,
    theme: UiTheme,
    color_mode: ColorMode,
    username: &str,
    is_admin: bool,
    csrf_token: &str,
) -> String {
    let base_url = config.base_url();
    let install_script_url =
        "https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-cli.sh";
    let install_ps1_url =
        "https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-cli.ps1";

    let content = format!(
        r#"<h1 class="page-title">Machine &amp; Agent Setup</h1>

    <section class="panel">
      <div class="panel-header">
        <h2>1. Install the Lore CLI</h2>
        <p>Run this on the machine where you want agents to operate.</p>
      </div>
      <div class="padded">
        <p class="hint" style="margin-bottom:var(--s-2);"><strong>Linux / macOS</strong></p>
        <div style="display:flex; align-items:stretch; gap:var(--s-2);">
          <code style="flex:1; min-width:0; padding:var(--s-2) var(--s-3); background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); font-size:0.85rem; overflow-x:auto; white-space:nowrap; display:flex; align-items:center;">curl -fsSL {install_script_url} | sh</code>
          <button class="button-link" onclick="navigator.clipboard.writeText('curl -fsSL {install_script_url} | sh')" title="Copy" style="aspect-ratio:1; width:auto; padding:0; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
        <p class="hint" style="margin-top:var(--s-4); margin-bottom:var(--s-2);"><strong>Windows</strong> (PowerShell)</p>
        <div style="display:flex; align-items:stretch; gap:var(--s-2);">
          <code style="flex:1; min-width:0; padding:var(--s-2) var(--s-3); background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); font-size:0.85rem; overflow-x:auto; white-space:nowrap; display:flex; align-items:center;">irm {install_ps1_url} | iex</code>
          <button class="button-link" onclick="navigator.clipboard.writeText('irm {install_ps1_url} | iex')" title="Copy" style="aspect-ratio:1; width:auto; padding:0; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      </div>
    </section>

    <section class="panel" style="margin-top: var(--s-5);">
      <div class="panel-header">
        <h2>2. Register this machine</h2>
        <p>This links the machine to your Lore account so it can create agents.</p>
      </div>
      <div class="padded">
        <div style="display:flex; align-items:stretch; gap:var(--s-2);">
          <code style="flex:1; min-width:0; padding:var(--s-2) var(--s-3); background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); font-size:0.85rem; overflow-x:auto; white-space:nowrap; display:flex; align-items:center;">lore setup {base_url}</code>
          <button class="button-link" onclick="navigator.clipboard.writeText('lore setup {base_url}')" title="Copy" style="aspect-ratio:1; width:auto; padding:0; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
        <p class="hint" style="margin-top:var(--s-3);">You will be prompted to log in with your Lore username and password, then asked to name this machine.</p>
      </div>
    </section>

    <section class="panel" style="margin-top: var(--s-5);">
      <div class="panel-header">
        <h2>3. Start an agent</h2>
        <p>Create and run an agent on this machine.</p>
      </div>
      <div class="padded">
        <div style="display:flex; align-items:stretch; gap:var(--s-2);">
          <code style="flex:1; min-width:0; padding:var(--s-2) var(--s-3); background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); font-size:0.85rem; overflow-x:auto; white-space:nowrap; display:flex; align-items:center;">lore agent my-agent-name</code>
          <button class="button-link" onclick="navigator.clipboard.writeText('lore agent my-agent-name')" title="Copy" style="aspect-ratio:1; width:auto; padding:0; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
        <p class="hint" style="margin-top:var(--s-3);">The agent is automatically provisioned on the server and starts polling for messages. Use the Chat tab to talk to it.</p>
        <p class="hint" style="margin-top:var(--s-2);">Options: <code>--backend gemini</code> or <code>--backend codex</code> to use a different backend (default is Claude).</p>
      </div>
    </section>

    <p style="margin-top:var(--s-5);"><a href="/ui/agents">&larr; Back to Agents</a></p>"#,
        install_script_url = escape_attribute(install_script_url),
        base_url = escape_text(&base_url),
    );

    render_shell(
        PageShell {
            title: "Lore setup guide",
            username: Some(username),
            is_admin,
            theme,
            color_mode: ColorMode::System,
            csrf_token: Some(csrf_token),
            flash: None,
        },
        content,
    )
}

pub fn render_chat_page(
    theme: UiTheme,
    color_mode: ColorMode,
    username: &str,
    csrf_token: &str,
    is_admin: bool,
    agents: &[ChatAgentSummary],
    selected_agent: Option<&str>,
    messages_json: &str,
    flash: Option<&str>,
) -> String {
    let agent_list_html: String = agents
        .iter()
        .map(|agent| {
            let active_class = if selected_agent == Some(agent.name.as_str()) {
                " chat-agent-active"
            } else {
                ""
            };
            let status_class = match agent.status.as_str() {
                "idle" => "chat-status-online",
                "thinking" => "chat-status-thinking",
                _ => "chat-status-offline",
            };
            let snippet = agent
                .last_message
                .as_deref()
                .unwrap_or("No messages yet");
            let snippet_escaped = escape_text(
                &snippet.chars().take(60).collect::<String>(),
            );
            let time_str = agent
                .last_message_time
                .as_deref()
                .unwrap_or("");
            let avatar_html = if let Some(ref url) = agent.profile_url {
                format!(
                    r#"<img class="chat-avatar-sm" src="{}" alt="">"#,
                    escape_attribute(url)
                )
            } else {
                String::new()
            };
            format!(
                r#"<div class="chat-agent-item{active_class}" data-agent="{name}" onclick="selectAgent('{name}')">
  <div class="chat-agent-header">
    {avatar_html}<span class="chat-agent-name">{display_name}</span>
    <span class="chat-status-dot {status_class}"></span>
  </div>
  <div class="chat-agent-snippet">{snippet_escaped}</div>
  <div class="chat-agent-time">{time_str}</div>
</div>"#,
                active_class = active_class,
                name = escape_attribute(&agent.name),
                avatar_html = avatar_html,
                display_name = escape_text(&agent.display_name),
                status_class = status_class,
                snippet_escaped = snippet_escaped,
                time_str = escape_text(time_str),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let chat_area_html = if let Some(agent_name) = selected_agent {
        let selected_agent_data = agents
            .iter()
            .find(|a| a.name == agent_name);
        let display = selected_agent_data
            .map(|a| a.display_name.as_str())
            .unwrap_or(agent_name);
        let header_avatar = selected_agent_data
            .and_then(|a| a.profile_url.as_ref())
            .map(|url| format!(
                r#"<img class="chat-avatar-header" src="{}" alt="">"#,
                escape_attribute(url)
            ))
            .unwrap_or_default();
        format!(
            r#"<div class="chat-header">
  <button class="chat-back-btn" onclick="showAgentList()">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
  </button>
  {header_avatar}<span class="chat-header-name">{display_name}</span>
  <span class="chat-header-status" id="chat-agent-status"></span>
</div>
<div class="chat-messages" id="chat-messages"></div>
<form class="chat-input-form" id="chat-input-form" onsubmit="return sendMessage(event)">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <textarea class="chat-input" id="chat-input" placeholder="Type a message..." rows="1" onkeydown="return handleChatKey(event)"></textarea>
  <button type="submit" class="chat-send-btn">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
  </button>
</form>"#,
            header_avatar = header_avatar,
            display_name = escape_text(display),
            csrf_token = escape_attribute(csrf_token),
        )
    } else {
        r#"<div class="chat-empty">
  <div class="chat-empty-text">Select an agent to start chatting</div>
</div>"#
            .to_string()
    };

    let selected_agent_js = selected_agent
        .map(|a| format!("'{}'", escape_attribute(a)))
        .unwrap_or_else(|| "null".to_string());

    let profile_url_js = selected_agent
        .and_then(|name| agents.iter().find(|a| a.name == name))
        .and_then(|a| a.profile_url.as_ref())
        .map(|url| format!("'{}'", escape_attribute(url)))
        .unwrap_or_else(|| "null".to_string());

    let layout_class = if selected_agent.is_some() {
        "chat-layout chat-has-agent"
    } else {
        "chat-layout"
    };

    let content = format!(
        r#"<div class="{layout_class}">
  <div class="chat-sidebar" id="chat-sidebar">
    <div class="chat-sidebar-header">
      <span class="heading-3">Agents</span>
    </div>
    <div class="chat-agent-list">
      {agent_list_html}
    </div>
  </div>
  <div class="chat-main" id="chat-main">
    {chat_area_html}
  </div>
</div>
<script>
var currentAgent = {selected_agent_js};
var csrfToken = '{csrf_token}';
var chatMessages = {messages_json};
var agentProfileUrl = {profile_url_js};
var eventSource = null;
var streamingContent = '';

function selectAgent(name) {{
  window.location.href = '/ui/chat?agent=' + encodeURIComponent(name);
}}

function showAgentList() {{
  var layout = document.querySelector('.chat-layout');
  if (layout) layout.classList.add('chat-sidebar-show');
}}

function renderMessages() {{
  var container = document.getElementById('chat-messages');
  if (!container) return;
  var html = '';
  for (var i = 0; i < chatMessages.length; i++) {{
    var msg = chatMessages[i];
    var cls = msg.role === 'user' ? 'chat-msg-user' : msg.role === 'system' ? 'chat-msg-system' : 'chat-msg-assistant';
    html += '<div class="chat-msg ' + cls + '">';
    if (msg.role === 'assistant' && agentProfileUrl) {{
      html += '<img class="chat-avatar-msg" src="' + escapeHtmlRaw(agentProfileUrl) + '" alt="">';
    }}
    if (msg.role === 'assistant') {{
      html += '<div class="chat-msg-content">' + renderMarkdown(msg.content) + '</div>';
    }} else {{
      html += '<div class="chat-msg-content">' + escapeHtml(msg.content) + '</div>';
    }}
    html += '</div>';
  }}
  container.innerHTML = html;
  container.scrollTop = container.scrollHeight;
}}

function escapeHtml(text) {{
  var d = document.createElement('div');
  d.textContent = text;
  return d.innerHTML.replace(/\n/g, '<br>');
}}

function escapeHtmlRaw(text) {{
  var d = document.createElement('div');
  d.textContent = text;
  return d.innerHTML;
}}

function renderMarkdown(text) {{
  if (!text) return '';
  var svgs = [];
  text = text.replace(/<svg[\s\S]*?<\/svg>/gi, function(m) {{
    svgs.push(m);
    return '__SVG_' + (svgs.length - 1) + '__';
  }});
  var codeBlocks = [];
  text = text.replace(/```(\w*)\n([\s\S]*?)```/g, function(m, lang, code) {{
    codeBlocks.push('<pre><code>' + escapeHtmlRaw(code.replace(/\n$/, '')) + '</code></pre>');
    return '\n__CODE_' + (codeBlocks.length - 1) + '__\n';
  }});
  var lines = text.split('\n');
  var html = '';
  var inList = null;
  var inBq = false;
  var inTable = false;
  var tableHead = true;
  var tableSep = false;
  for (var i = 0; i < lines.length; i++) {{
    var line = lines[i];
    var cm = line.match(/^__CODE_(\d+)__$/);
    if (cm) {{
      if (inList) {{ html += '</' + inList + '>'; inList = null; }}
      if (inBq) {{ html += '</blockquote>'; inBq = false; }}
      if (inTable) {{ html += '</table></div>'; inTable = false; tableHead = false; tableSep = false; }}
      html += codeBlocks[parseInt(cm[1])];
      continue;
    }}
    var sm = line.match(/^__SVG_(\d+)__$/);
    if (sm) {{
      if (inList) {{ html += '</' + inList + '>'; inList = null; }}
      if (inBq) {{ html += '</blockquote>'; inBq = false; }}
      if (inTable) {{ html += '</table></div>'; inTable = false; tableHead = false; tableSep = false; }}
      html += '<div class="chat-svg-wrap" onclick="expandSvg(this)">' + svgs[parseInt(sm[1])] + '<div class="chat-svg-hint">Click to expand</div></div>';
      continue;
    }}
    line = escapeHtmlRaw(line);
    var hm = line.match(/^(#{{1,6}})\s+(.+)$/);
    if (hm) {{
      if (inList) {{ html += '</' + inList + '>'; inList = null; }}
      if (inBq) {{ html += '</blockquote>'; inBq = false; }}
      var lvl = hm[1].length;
      html += '<h' + lvl + '>' + inlineMd(hm[2]) + '</h' + lvl + '>';
      continue;
    }}
    if (/^-{{3,}}$/.test(line) || /^\*{{3,}}$/.test(line)) {{
      if (inList) {{ html += '</' + inList + '>'; inList = null; }}
      if (inBq) {{ html += '</blockquote>'; inBq = false; }}
      html += '<hr>';
      continue;
    }}
    var bm = line.match(/^&gt;\s?(.*)$/);
    if (bm) {{
      if (inList) {{ html += '</' + inList + '>'; inList = null; }}
      if (!inBq) {{ html += '<blockquote>'; inBq = true; }}
      html += inlineMd(bm[1]) + '<br>';
      continue;
    }} else if (inBq) {{
      html += '</blockquote>'; inBq = false;
    }}
    var ul = line.match(/^[-*]\s+(.+)$/);
    if (ul) {{
      if (inBq) {{ html += '</blockquote>'; inBq = false; }}
      if (inList !== 'ul') {{
        if (inList) html += '</' + inList + '>';
        html += '<ul>'; inList = 'ul';
      }}
      html += '<li>' + inlineMd(ul[1]) + '</li>';
      continue;
    }}
    var ol = line.match(/^\d+\.\s+(.+)$/);
    if (ol) {{
      if (inBq) {{ html += '</blockquote>'; inBq = false; }}
      if (inList !== 'ol') {{
        if (inList) html += '</' + inList + '>';
        html += '<ol>'; inList = 'ol';
      }}
      html += '<li>' + inlineMd(ol[1]) + '</li>';
      continue;
    }}
    if (inList) {{ html += '</' + inList + '>'; inList = null; }}
    var tm = line.match(/^\|(.+)\|$/);
    if (tm) {{
      if (!inTable) {{
        if (inList) {{ html += '</' + inList + '>'; inList = null; }}
        if (inBq) {{ html += '</blockquote>'; inBq = false; }}
        html += '<div class="chat-table-wrap"><table>';
        inTable = true; tableHead = true; tableSep = false;
      }}
      if (/^\|[\s\-:|]+\|$/.test(line)) {{
        tableSep = true;
        continue;
      }}
      var cells = tm[1].split('|').map(function(c) {{ return c.trim(); }});
      var tag = (tableHead && !tableSep) ? 'th' : 'td';
      html += '<tr>';
      for (var ci = 0; ci < cells.length; ci++) {{
        html += '<' + tag + '>' + inlineMd(cells[ci]) + '</' + tag + '>';
      }}
      html += '</tr>';
      if (tableSep) tableHead = false;
      continue;
    }}
    if (inTable) {{ html += '</table></div>'; inTable = false; tableHead = false; tableSep = false; }}
    if (line.trim() === '') continue;
    html += '<p>' + inlineMd(line) + '</p>';
  }}
  if (inList) html += '</' + inList + '>';
  if (inBq) html += '</blockquote>';
  if (inTable) html += '</table></div>';
  return html;
}}

function inlineMd(t) {{
  var codes = [];
  t = t.replace(/`([^`]+)`/g, function(m, c) {{
    codes.push('<code>' + c + '</code>');
    return '__IC_' + (codes.length - 1) + '__';
  }});
  t = t.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  t = t.replace(/\*(.+?)\*/g, '<em>$1</em>');
  t = t.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  for (var i = 0; i < codes.length; i++) {{
    t = t.replace('__IC_' + i + '__', codes[i]);
  }}
  return t;
}}

function expandSvg(container) {{
  var svg = container.querySelector('svg');
  if (!svg) return;
  var overlay = document.createElement('div');
  overlay.className = 'svg-overlay';
  overlay.onclick = function() {{ overlay.remove(); }};
  var close = document.createElement('button');
  close.className = 'svg-overlay-close';
  close.innerHTML = '&#x2715;';
  close.onclick = function(e) {{ e.stopPropagation(); overlay.remove(); }};
  overlay.appendChild(close);
  var wrapper = document.createElement('div');
  wrapper.innerHTML = svg.outerHTML;
  wrapper.onclick = function(e) {{ e.stopPropagation(); }};
  var bigSvg = wrapper.querySelector('svg');
  if (bigSvg) {{
    bigSvg.removeAttribute('width');
    bigSvg.removeAttribute('height');
    bigSvg.style.maxWidth = '90vw';
    bigSvg.style.maxHeight = '90vh';
  }}
  overlay.appendChild(wrapper);
  document.body.appendChild(overlay);
}}

document.addEventListener('keydown', function(e) {{
  if (e.key === 'Escape') {{
    var ov = document.querySelector('.svg-overlay');
    if (ov) ov.remove();
  }}
}});

function handleChatKey(e) {{
  if (e.key === 'Enter' && !e.shiftKey) {{
    e.preventDefault();
    sendMessage(e);
    return false;
  }}
  return true;
}}

function sendMessage(e) {{
  e.preventDefault();
  var input = document.getElementById('chat-input');
  var text = input.value.trim();
  if (!text) return false;
  input.value = '';

  // Slash commands go to the command endpoint
  if (text.startsWith('/')) {{
    chatMessages.push({{ role: 'user', content: text }});
    renderMessages();
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/ui/chat/' + encodeURIComponent(currentAgent) + '/command');
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {{
      try {{
        var resp = JSON.parse(xhr.responseText);
        if (resp.response) {{
          chatMessages.push({{ role: 'system', content: resp.response }});
          renderMessages();
        }}
      }} catch(err) {{}}
    }};
    xhr.send('csrf_token=' + encodeURIComponent(csrfToken) + '&command=' + encodeURIComponent(text));
    return false;
  }}

  chatMessages.push({{ role: 'user', content: text }});
  renderMessages();

  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/ui/chat/' + encodeURIComponent(currentAgent) + '/send');
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onerror = function() {{
    chatMessages.push({{ role: 'system', content: 'Failed to send message (network error)' }});
    renderMessages();
  }};
  xhr.onload = function() {{
    if (xhr.status !== 200) {{
      chatMessages.push({{ role: 'system', content: 'Failed to send message (HTTP ' + xhr.status + ')' }});
      renderMessages();
    }}
  }};
  xhr.send('csrf_token=' + encodeURIComponent(csrfToken) + '&message=' + encodeURIComponent(text));
  return false;
}}

function connectSSE() {{
  if (eventSource) eventSource.close();
  eventSource = new EventSource('/ui/chat/stream');
  eventSource.onmessage = function(e) {{
    try {{
      var evt = JSON.parse(e.data);
      if (evt.agent !== currentAgent) return;
      if (evt.event_type === 'chunk') {{
        streamingContent += evt.data.text;
        var lastMsg = chatMessages[chatMessages.length - 1];
        if (lastMsg && lastMsg.role === 'assistant' && lastMsg.streaming) {{
          lastMsg.content = streamingContent;
        }} else {{
          chatMessages.push({{ role: 'assistant', content: streamingContent, streaming: true }});
        }}
        renderMessages();
      }} else if (evt.event_type === 'response_complete') {{
        var lastMsg = chatMessages[chatMessages.length - 1];
        if (lastMsg && lastMsg.streaming) {{
          lastMsg.streaming = false;
          lastMsg.content = evt.data.content || lastMsg.content;
        }}
        streamingContent = '';
        renderMessages();
      }} else if (evt.event_type === 'auto_message') {{
        chatMessages.push({{ role: 'user', content: evt.data.content }});
        renderMessages();
      }} else if (evt.event_type === 'command_response') {{
        chatMessages.push({{ role: 'system', content: evt.data.response }});
        renderMessages();
      }} else if (evt.event_type === 'status') {{
        var el = document.getElementById('chat-agent-status');
        if (el) el.textContent = evt.data.status || '';
      }}
    }} catch(err) {{}}
  }};
  eventSource.onerror = function() {{
    setTimeout(connectSSE, 3000);
  }};
}}

// Mobile swipe: right to show agent list, left to show chat
(function() {{
  var touchStartX = 0;
  var touchStartY = 0;
  document.addEventListener('touchstart', function(e) {{
    touchStartX = e.touches[0].clientX;
    touchStartY = e.touches[0].clientY;
  }}, {{ passive: true }});
  document.addEventListener('touchend', function(e) {{
    var dx = e.changedTouches[0].clientX - touchStartX;
    var dy = e.changedTouches[0].clientY - touchStartY;
    if (Math.abs(dx) < 60 || Math.abs(dy) > Math.abs(dx)) return;
    var layout = document.querySelector('.chat-layout');
    if (!layout) return;
    if (dx > 0) {{
      // Swipe right: show agent list
      layout.classList.add('chat-sidebar-show');
    }} else {{
      // Swipe left: show chat
      layout.classList.remove('chat-sidebar-show');
    }}
  }}, {{ passive: true }});
}})();

if (currentAgent) {{
  renderMessages();
  connectSSE();
}}
</script>"#,
        layout_class = layout_class,
        agent_list_html = agent_list_html,
        chat_area_html = chat_area_html,
        selected_agent_js = selected_agent_js,
        csrf_token = escape_attribute(csrf_token),
        messages_json = messages_json,
        profile_url_js = profile_url_js,
    );

    render_shell(
        PageShell {
            title: "Lore chat",
            username: Some(username),
            is_admin,
            theme,
            color_mode,
            csrf_token: Some(csrf_token),
            flash,
        },
        content,
    )
}

pub fn render_admin_audit_page(
    theme: UiTheme,
    color_mode: ColorMode,
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
        "<p class=\"hint padded\">No pending librarian actions.</p>".to_string()
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
            color_mode,
            csrf_token: Some(csrf_token),
            flash: None,
        },
        content,
    )
}

pub fn render_project_audit_page(
    theme: UiTheme,
    color_mode: ColorMode,
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
        "<p class=\"hint padded\">No librarian history for this project yet.</p>".to_string()
    } else {
        runs.iter()
            .map(render_librarian_answer)
            .collect::<Vec<_>>()
            .join("")
    };
    let pending_html = if pending_actions.is_empty() {
        "<p class=\"hint padded\">No pending librarian actions.</p>".to_string()
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
            color_mode,
            csrf_token: Some(csrf_token),
            flash: None,
        },
        content,
    )
}

pub fn render_project_history_page(
    theme: UiTheme,
    color_mode: ColorMode,
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
            color_mode,
            csrf_token: Some(csrf_token),
            flash: None,
        },
        content,
    )
}

pub fn render_project_page(
    theme: UiTheme,
    color_mode: ColorMode,
    project: &ProjectName,
    display_name: &str,
    project_uuid: &str,
    agent_context: Option<&str>,
    blocks: &[Block],
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
    store: &FileBlockStore,
) -> String {
    let project_infos = store.list_project_infos().unwrap_or_default();
    let search_value = search.unwrap_or_default();
    let results_label = if !search_value.is_empty() {
        format!(
            "<p>{} result{} for \"{}\". </p>",
            blocks.len(),
            if blocks.len() == 1 { "" } else { "s" },
            escape_text(search_value)
        )
    } else {
        String::new()
    };
    let blocks_html = if blocks.is_empty() && can_write {
        format!(
            r#"<section class="empty-state"><h2>No blocks yet</h2><p>Click the button below to add the first block.</p></section>{}"#,
            render_block_inserter(project, None, csrf_token, &project_infos),
        )
    } else if blocks.is_empty() {
        r#"<section class="empty-state"><h2>No blocks yet</h2></section>"#.to_string()
    } else {
        let mut html = String::new();
        if can_write {
            html.push_str(&render_block_inserter(project, None, csrf_token, &project_infos));
        }
        for (i, block) in blocks.iter().enumerate() {
            html.push_str(&render_block(
                project, block, can_write, &project_infos, csrf_token, i,
            ));
            if can_write {
                html.push_str(&render_block_inserter(project, Some(&block.id), csrf_token, &project_infos));
            }
        }
        html
    };
    let blocks_html = resolve_lore_links_in_html(&blocks_html, store);
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

    let delete_project_html = if is_admin {
        format!(
            r#"<div class="delete-project-section">
              <form method="post" action="/ui/{project_slug}/delete"
                    onsubmit="return confirm('Are you sure you want to delete this project? This cannot be undone.');">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <button type="submit" class="delete-project-btn">Delete project</button>
              </form>
            </div>"#,
            project_slug = escape_attribute(project.as_str()),
            csrf_token = escape_attribute(csrf_token),
        )
    } else {
        String::new()
    };

    let copy_project_link_btn = format!(
        r##"<button type="button" class="block-header-btn" title="Copy link to this project" onclick="copyLoreLink('{project_uuid}')" style="margin-left:var(--s-3);">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
  </button>"##,
        project_uuid = escape_attribute(project_uuid),
    );

    let rename_html = if can_write && is_admin {
        format!(
            r#"<div style="display:flex; align-items:center;">
            <h1 class="page-title editable-title" style="margin:0;" id="project-title"
                title="Click to rename" onclick="document.getElementById('rename-form').style.display='flex'; this.style.display='none';"
            >{display_name}</h1>{copy_project_link_btn}</div>
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
            copy_project_link_btn = copy_project_link_btn,
        )
    } else {
        format!(
            r#"<div style="display:flex; align-items:center;"><h1 class="page-title" style="margin:0;">{display_name}</h1>{copy_project_link_btn}</div>"#,
            display_name = escape_text(display_name),
            copy_project_link_btn = copy_project_link_btn,
        )
    };

    let search_active = !search_value.is_empty()
        || search_block_type.is_some()
        || !search_author.unwrap_or_default().is_empty()
        || search_include_history;
    let search_strip_style = if search_active {
        ""
    } else {
        " style=\"display:none\""
    };
    let search_btn_class = if search_active { " active" } else { "" };

    let context_text = agent_context.unwrap_or_default();
    let context_lines: Vec<&str> = context_text.lines().collect();
    let context_truncated = context_lines.len() > 8;
    let context_preview: String = if context_truncated {
        let mut preview = context_lines[..8].join("\n");
        preview.push_str("\n...");
        preview
    } else {
        context_text.to_string()
    };
    let agent_context_html = {
        let edit_form = if can_write {
            format!(
                r#"<form id="agent-context-form" method="post" action="/ui/{project_slug}/context" style="display:none;">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <textarea name="agent_context" class="agent-context-textarea">{content_escaped}</textarea>
    <div style="display:flex; gap:var(--s-3); margin-top:var(--s-2);">
      <button type="submit" class="button-link">Save</button>
      <button type="button" class="button-link" onclick="toggleAgentContext()">Cancel</button>
    </div>
  </form>"#,
                project_slug = escape_attribute(project.as_str()),
                csrf = escape_attribute(csrf_token),
                content_escaped = escape_text(context_text),
            )
        } else {
            String::new()
        };
        let band_html = if can_write {
            r#"<div class="editline-band editline-band-even agent-context-band" onclick="toggleAgentContext()" title="Click to edit agent context"></div>"#
        } else {
            ""
        };
        format!(
            r#"<div class="agent-context-section">
  <div class="section-tag">Agent Context</div>
  <div class="agent-context-panel">
    <div class="agent-context-content">
      <pre class="agent-context-preview" id="agent-context-preview">{preview}</pre>
      <div class="agent-context-full" id="agent-context-full" style="display:none;">
        <pre class="agent-context-full-text">{full_text}</pre>
      </div>
      {edit_form}
    </div>{band_html}
  </div>
</div>"#,
            preview = if context_preview.is_empty() {
                "<span class=\"hint\">No agent context set</span>".to_string()
            } else {
                escape_text(&context_preview)
            },
            full_text = escape_text(context_text),
            edit_form = edit_form,
            band_html = band_html,
        )
    };

    let content = format!(
        r#"<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--s-3);">
      {rename_html}
      <div style="display:flex; gap:var(--s-3);">
        <button type="button" class="button-link{search_btn_class}" onclick="var s=document.getElementById('search-strip'); if(s.style.display==='none'){{s.style.display='';this.classList.add('active');}}else{{s.style.display='none';this.classList.remove('active');}}">Search</button>
        <a class="button-link" href="/ui/{project_slug}/audit">Audit</a>
        <a class="button-link" href="/ui/{project_slug}/history">History</a>
      </div>
    </div>
    <form class="searchbar" id="search-strip" method="get" action="/ui/{project_slug}"{search_strip_style}>
      <input type="search" name="q" value="{search_value}" placeholder="Search content...">
      <select name="block_type">
        <option value=""{search_any_type}>Any type</option>
        <option value="markdown"{search_markdown}>Markdown</option>
        <option value="svg"{search_svg}>SVG</option>
        <option value="html"{search_html}>HTML</option>
        <option value="image"{search_image}>Image</option>
      </select>
      <input type="search" name="author" value="{search_author}" placeholder="Author...">
      <select name="include_history">
        <option value=""{search_history_current}>Current</option>
        <option value="1"{search_history_history}>History</option>
      </select>
      <button type="submit">Search</button>
    </form>

    <div class="layout">
      <div class="main-column">
        {agent_context_html}
        <div class="section-tag">Document</div>
        <section class="panel" id="document">
          {results_label}
          <div class="timeline">{blocks_html}</div>
        </section>
      </div>
      <aside class="stack">{librarian_panel}{read_only_notice}</aside>
    </div>
    {delete_project_html}"#,
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
        search_strip_style = search_strip_style,
        search_btn_class = search_btn_class,
        search_history_current = if !search_include_history {
            " selected"
        } else {
            ""
        },
        search_history_history = if search_include_history {
            " selected"
        } else {
            ""
        },
        agent_context_html = agent_context_html,
        results_label = results_label,
        blocks_html = blocks_html,
        librarian_panel = librarian_panel,
        read_only_notice = read_only_notice,
        delete_project_html = delete_project_html,
    );

    render_shell(
        PageShell {
            title: &format!("Lore · {}", display_name),
            username: Some(username),
            is_admin,
            theme,
            color_mode,
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
        "<p class=\"hint\">No previous answers.</p>".to_string()
    } else {
        librarian_history
            .iter()
            .map(|answer| render_librarian_history_item(project, csrf_token, answer))
            .collect::<Vec<_>>()
            .join("")
    };
    let pending_html = if pending_actions.is_empty() {
        "<p class=\"hint\">No pending actions.</p>".to_string()
    } else {
        pending_actions
            .iter()
            .map(|action| {
                render_pending_librarian_action(action, Some(project), csrf_token, can_write)
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let allow_edits_html = if can_write {
        r#"<label class="toggle"><input type="checkbox" name="allow_edits" value="1"> <span>Allow edits</span></label>"#
    } else {
        ""
    };
    let compact_html = if can_write {
        format!(
            r#"<div class="stack">
    <h3 class="panel-subheading">Tools</h3>
    <form method="post" action="/ui/{project}/compact" onsubmit="return confirm('Merge all consecutive markdown blocks into single blocks?')">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <button type="submit" class="button-link" title="Merge consecutive markdown blocks into single blocks">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12h16"/><path d="M4 6h16"/><path d="m7 9-3 3 3 3"/><path d="m17 9 3 3-3 3"/></svg>
        Compact
      </button>
    </form>
  </div>"#,
            project = escape_attribute(project.as_str()),
            csrf_token = escape_attribute(csrf_token),
        )
    } else {
        String::new()
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
    {allow_edits_html}
    <button type="submit">Ask</button>
  </form>
  {answer_html}
  <div class="stack">
    <h3 class="panel-subheading">Recent history</h3>
    {history_html}
  </div>
  <div class="stack">
    <h3 class="panel-subheading">Pending actions</h3>
    {pending_html}
  </div>
  {compact_html}
</section>"#,
        project = escape_attribute(project.as_str()),
        csrf_token = escape_attribute(csrf_token),
        question_value = question_value,
        allow_edits_html = allow_edits_html,
        answer_html = answer_html,
        history_html = history_html,
        pending_html = pending_html,
        compact_html = compact_html,
    )
}

fn render_librarian_answer(answer: &UiLibrarianAnswer) -> String {
    let kind = match answer.kind {
        LibrarianRunKind::Answer => "Librarian",
        LibrarianRunKind::ActionRequest => "Action request",
        LibrarianRunKind::ProjectAction => "Librarian action",
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
    let allow_edits_field = if matches!(answer.kind, LibrarianRunKind::ProjectAction) {
        r#"<input type="hidden" name="allow_edits" value="1">"#
    } else {
        ""
    };
    let retry_form = format!(
        r#"<form method="post" action="/ui/{project}/librarian">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <input type="hidden" name="question" value="{question}">
  {allow_edits_field}
  <button type="submit">Ask again</button>
</form>"#,
        project = escape_attribute(project.as_str()),
        csrf_token = escape_attribute(csrf_token),
        question = escape_attribute(&answer.question),
        allow_edits_field = allow_edits_field,
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

fn render_user_detail(user: &UiUserSummary, agents: &[AgentTokenSummary], machines: &[StoredMachine], csrf_token: &str) -> String {
    let roles = if user.role_names.is_empty() {
        "<li>No assigned roles</li>".to_string()
    } else {
        user.role_names
            .iter()
            .map(|role| format!(r#"<li class="meta-code">{}</li>"#, escape_text(role)))
            .collect::<Vec<_>>()
            .join("")
    };

    let agents_html = if agents.is_empty() {
        r#"<p style="font-size:0.85rem; color:var(--fg-muted); margin:0;">No agents</p>"#.to_string()
    } else {
        let items: Vec<String> = agents
            .iter()
            .map(|agent| {
                let grants = agent
                    .grants
                    .iter()
                    .map(|g| {
                        format!(
                            "{} ({})",
                            g.project.as_str(),
                            if g.permission.allows_write() { "rw" } else { "r" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    r#"<li><span class="meta-code">{}</span> <span style="font-size:0.82rem; color:var(--fg-muted);">{}</span></li>"#,
                    escape_text(&agent.display_name),
                    escape_text(&grants),
                )
            })
            .collect();
        items.join("")
    };

    let machines_html = if machines.is_empty() {
        r#"<p style="font-size:0.85rem; color:var(--fg-muted); margin:0;">No machines</p>"#.to_string()
    } else {
        let items: Vec<String> = machines
            .iter()
            .map(|m| {
                format!(
                    r#"<li><span class="meta-code">{}</span> <span style="font-size:0.82rem; color:var(--fg-muted);">{}</span></li>"#,
                    escape_text(&m.name),
                    escape_text(&format_timestamp(m.created_at)),
                )
            })
            .collect();
        items.join("")
    };

    format!(
        r#"<div class="user-detail" data-user-detail="{username_attr}" style="display:none;">
  <div class="block-meta">
    <span class="pill">{badge}</span>
    <span>{created}</span>
    <span class="meta-separator">&middot;</span>
    <span>{sessions}</span>
  </div>
  <div style="padding:0 var(--s-4);">
    <strong style="font-size:0.85rem;">Roles</strong>
    <ul class="grant-list" style="margin-top:var(--s-1);">{roles}</ul>
  </div>
  <div style="margin-top:var(--s-3); padding:0 var(--s-4);">
    <strong style="font-size:0.85rem;">Agents</strong>
    <ul class="grant-list" style="margin-top:var(--s-1);">{agents_html}</ul>
  </div>
  <div style="margin-top:var(--s-3); padding:0 var(--s-4);">
    <strong style="font-size:0.85rem;">Machines</strong>
    <ul class="grant-list" style="margin-top:var(--s-1);">{machines_html}</ul>
  </div>
  <div class="inline-form">
    <form method="post" action="/ui/admin/users/{username_attr}/password">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="password" name="password" placeholder="New password" autocomplete="new-password" required>
      <button type="submit">Reset password</button>
    </form>
  </div>
  <div class="inline-form">
    <form method="post" action="/ui/admin/users/{username_attr}/sessions/revoke">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button type="submit">Revoke sessions</button>
    </form>
    <form method="post" action="/ui/admin/users/{username_attr}/{action}">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button class="danger" type="submit">{action_label}</button>
    </form>
  </div>
</div>"#,
        username_attr = escape_attribute(&user.username),
        badge = escape_text(if user.is_admin { "admin" } else { "user" }),
        created = escape_text(&format_timestamp(user.created_at)),
        sessions = escape_text(&format!("{} active sessions", user.active_sessions)),
        roles = roles,
        agents_html = agents_html,
        machines_html = machines_html,
        csrf = escape_attribute(csrf_token),
        action = if user.disabled { "enable" } else { "disable" },
        action_label = if user.disabled { "Enable user" } else { "Disable user" },
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

fn render_doc_link_picker(project_infos: &[ProjectInfo]) -> String {
    if project_infos.is_empty() {
        return String::new();
    }
    let options: String = project_infos
        .iter()
        .map(|info| {
            format!(
                r#"<option value="{id}" data-name="{name}">{display}</option>"#,
                id = escape_attribute(&info.id),
                name = escape_attribute(&info.display_name),
                display = escape_text(&info.display_name),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<div class="doc-link-picker">
      <select class="doc-link-select">
        <option value="">Link to document...</option>
        {options}
      </select>
      <button type="button" class="copy-btn" onclick="insertDocLink(this)" title="Insert link">&#x1F517;</button>
    </div>"#,
        options = options,
    )
}

fn render_block_inserter(
    project: &ProjectName,
    after_block_id: Option<&BlockId>,
    csrf_token: &str,
    project_infos: &[ProjectInfo],
) -> String {
    let after_value = after_block_id
        .map(|id| escape_attribute(id.as_str()).to_string())
        .unwrap_or_default();
    let project_attr = escape_attribute(project.as_str());
    let csrf_attr = escape_attribute(csrf_token);
    format!(
        r#"<div class="editline-row editline-gap-row">
  <div class="block-inserter" data-after="{after_value}">
    <div class="inserter-expand" style="display:none">
      <div class="inserter-types">
        <button type="button" class="inserter-type-btn" onclick="showInserterForm(this,'md')">Markdown</button>
        <button type="button" class="inserter-type-btn" onclick="showInserterForm(this,'svg')">SVG</button>
        <button type="button" class="inserter-type-btn" onclick="showInserterForm(this,'image')">Image</button>
        <button type="button" class="cancel-circle" onclick="toggleEditlineInserter(this.closest('.editline-gap-row').querySelector('.editline-plus'))" title="Cancel"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
      </div>
      <form class="inserter-form inserter-form-md" style="display:none" method="post" action="/ui/{project_attr}/blocks" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{csrf_attr}">
        <input type="hidden" name="block_type" value="markdown">
        <input type="hidden" name="after_block_id" value="{after_value}">
        <textarea name="content" placeholder="Write markdown..." rows="6"></textarea>
        {doc_link_picker}
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
  </div>
  <div class="editline-gap" data-after="{after_value}" ondragover="gapDragOver(event)" ondragleave="gapDragLeave(event)" ondrop="gapDrop(event)"><button type="button" class="editline-plus" onclick="toggleEditlineInserter(this)">+</button></div>
</div>"#,
        project_attr = project_attr,
        csrf_attr = csrf_attr,
        after_value = after_value,
        doc_link_picker = render_doc_link_picker(project_infos),
    )
}

fn render_block(
    project: &ProjectName,
    block: &Block,
    can_write: bool,
    project_infos: &[ProjectInfo],
    csrf_token: &str,
    block_index: usize,
) -> String {
    let block_id = escape_attribute(block.id.as_str());
    let project_slug = escape_attribute(project.as_str());
    let csrf = escape_attribute(csrf_token);

    let copy_link_btn = format!(
        r##"<button type="button" class="block-header-btn" title="Copy link" onclick="copyLoreLink('{block_id}')">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
  </button>"##,
        block_id = block_id,
    );

    let pin_title = if block.pinned {
        "Unpin (allow agent edits)"
    } else {
        "Pin (block agent edits)"
    };
    let pin_class = if block.pinned {
        "block-header-btn pinned"
    } else {
        "block-header-btn"
    };

    let header_actions = if can_write {
        format!(
            r##"<div class="block-header-actions">
  <button type="button" class="block-header-btn danger" title="Delete" onclick="if(confirm('Delete this block? This cannot be undone.')){{document.getElementById('del-{block_id}').submit();}}">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
  </button>
  {copy_link_btn}
  <button type="button" class="{pin_class}" title="{pin_title}" onclick="document.getElementById('pin-{block_id}').submit();">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>
  </button>
  <button type="button" class="block-header-btn" title="Save" onclick="document.querySelector('#edit-{block_id} form').submit();">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
  </button>
  <button type="button" class="block-header-btn" title="Cancel" onclick="cancelBlockEdit('{block_id}')">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
  </button>
  <form id="del-{block_id}" method="post" action="/ui/{project_slug}/blocks/{block_id}/delete" style="display:none;">
    <input type="hidden" name="csrf_token" value="{csrf}">
  </form>
  <form id="pin-{block_id}" method="post" action="/ui/{project_slug}/blocks/{block_id}/pin" style="display:none;">
    <input type="hidden" name="csrf_token" value="{csrf}">
  </form>
</div>"##,
            copy_link_btn = copy_link_btn,
            block_id = block_id,
            project_slug = project_slug,
            csrf = csrf,
            pin_class = pin_class,
            pin_title = pin_title,
        )
    } else {
        // Read-only users still get the copy link button
        format!(
            r##"<div class="block-header-actions">
  {copy_link_btn}
</div>"##,
            copy_link_btn = copy_link_btn,
        )
    };

    let edit_doc_link_picker = render_doc_link_picker(project_infos);
    let edit_form = if can_write {
        format!(
            r#"<form method="post" action="/ui/{project_slug}/blocks/{block_id}/edit" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <textarea name="content" class="block-edit-textarea">{content}</textarea>
    {edit_doc_link_picker}
    {image_replace}
  </form>"#,
            block_id = block_id,
            project_slug = project_slug,
            csrf = csrf,
            content = escape_text(&block.content),
            edit_doc_link_picker = edit_doc_link_picker,
            image_replace = if block.block_type == crate::model::BlockType::Image {
                r#"<div class="block-edit-extras">
      <label>
        Replace image
        <input type="file" name="image_file" accept="image/*">
      </label>
    </div>"#
            } else {
                ""
            },
        )
    } else {
        String::new()
    };

    let band_class = if block_index % 2 == 0 {
        "editline-band-even"
    } else {
        "editline-band-odd"
    };
    let band_pinned = if block.pinned { " editline-band-pinned" } else { "" };

    let band_html = if can_write {
        format!(
            r#"<div class="editline-band {band_class}{band_pinned}" data-block-id="{block_id}" draggable="true" ondragstart="bandDragStart(event)" ondragend="bandDragEnd(event)" onclick="toggleBlockEdit('{block_id}')" title="Click to edit · Drag to reorder"></div>"#,
            band_class = band_class,
            band_pinned = band_pinned,
            block_id = block_id,
        )
    } else {
        format!(
            r#"<div class="editline-band {band_class}{band_pinned}"></div>"#,
            band_class = band_class,
            band_pinned = band_pinned,
        )
    };

    format!(
        r#"<div class="editline-row"><article class="block" id="block-{block_id}" data-block-id="{block_id}">
  <div class="block-meta" id="meta-{block_id}" style="display:none;">
    <span class="pill">{type_label}</span>
    {header_actions}
  </div>
  <div class="block-body" id="body-{block_id}">{body}</div>
  <div class="block-edit-panel" id="edit-{block_id}" style="display:none;">{edit_form}</div>
</article>{band_html}</div>"#,
        block_id = block_id,
        type_label = escape_text(block_type_label(block.block_type)),
        header_actions = header_actions,
        body = render_block_body(block),
        edit_form = edit_form,
        band_html = band_html,
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

/// Post-process rendered HTML to resolve lore:// links into real URLs.
/// Replaces href="lore://UUID" with the correct /ui/... path.
/// Unresolvable links get a broken-link style.
fn resolve_lore_links_in_html(html: &str, store: &FileBlockStore) -> String {
    use crate::store::LoreLinkTarget;
    let re = regex::Regex::new(r#"href="lore://([0-9a-fA-F-]+)""#).unwrap();
    re.replace_all(html, |caps: &regex::Captures| {
        let uuid = &caps[1];
        match store.resolve_lore_link(uuid) {
            Some(LoreLinkTarget::Project(slug, _display)) => {
                format!(
                    r#"href="/ui/{}" class="lore-link lore-link-project""#,
                    escape_attribute(slug.as_str())
                )
            }
            Some(LoreLinkTarget::Block(slug, block_id, _bt, _preview)) => {
                format!(
                    r#"href="/ui/{}#block-{}" class="lore-link lore-link-block""#,
                    escape_attribute(slug.as_str()),
                    escape_attribute(block_id.as_str()),
                )
            }
            None => {
                format!(
                    r##"href="#" class="lore-link lore-link-broken" title="Link target not found ({})" onclick="return false""##,
                    escape_attribute(uuid)
                )
            }
        }
    })
    .into_owned()
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

/// Allowlist-based SVG sanitizer. Parses the input as XML, keeps only
/// elements and attributes on an explicit allowlist, and rebuilds the
/// output. Anything not on the lists is silently dropped. Returns an
/// empty string for malformed XML.
pub fn sanitize_svg(input: &str) -> String {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(false);
    let mut out = String::with_capacity(input.len());
    let mut skip_depth: usize = 0;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let qn = e.name();
                let name = std::str::from_utf8(qn.as_ref()).unwrap_or("");
                let lower = name.to_ascii_lowercase();
                if skip_depth > 0 {
                    skip_depth += 1;
                    continue;
                }
                if !is_allowed_svg_element(&lower) {
                    skip_depth = 1;
                    continue;
                }
                svg_write_open_tag(&mut out, e, name, &lower, false);
            }
            Ok(Event::End(ref e)) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                    continue;
                }
                let qn = e.name();
                let name = std::str::from_utf8(qn.as_ref()).unwrap_or("");
                out.push_str("</");
                out.push_str(name);
                out.push('>');
            }
            Ok(Event::Empty(ref e)) => {
                if skip_depth > 0 {
                    continue;
                }
                let qn = e.name();
                let name = std::str::from_utf8(qn.as_ref()).unwrap_or("");
                let lower = name.to_ascii_lowercase();
                if !is_allowed_svg_element(&lower) {
                    continue;
                }
                svg_write_open_tag(&mut out, e, name, &lower, true);
            }
            Ok(Event::Text(ref e)) => {
                if skip_depth > 0 {
                    continue;
                }
                if let Ok(s) = std::str::from_utf8(e.as_ref()) {
                    out.push_str(s);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {} // drop comments, PIs, doctypes, CDATA
            Err(_) => return String::new(),
        }
    }
    out
}

fn svg_write_open_tag(
    out: &mut String,
    elem: &quick_xml::events::BytesStart<'_>,
    tag: &str,
    lower_tag: &str,
    self_close: bool,
) {
    out.push('<');
    out.push_str(tag);
    for attr in elem.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        let lower_key = key.to_ascii_lowercase();
        if !is_allowed_svg_attribute(&lower_key) {
            continue;
        }
        let raw_val = std::str::from_utf8(&attr.value).unwrap_or("");

        // href / xlink:href — local refs only, data:image/ for <image>
        if lower_key == "href" || lower_key == "xlink:href" {
            let decoded = attr.unescape_value().unwrap_or_default();
            if lower_tag == "image" {
                if !decoded.starts_with("data:image/") && !decoded.starts_with('#') {
                    continue;
                }
            } else if !decoded.starts_with('#') {
                continue;
            }
        }

        // style — sanitize individual CSS declarations
        if lower_key == "style" {
            let decoded = attr.unescape_value().unwrap_or_default();
            let safe = sanitize_svg_style(&decoded);
            if safe.is_empty() {
                continue;
            }
            out.push(' ');
            out.push_str(key);
            out.push_str("=\"");
            svg_push_escaped_attr(out, &safe);
            out.push('"');
            continue;
        }

        // Pass through with raw (already-escaped) value; only re-escape
        // double-quotes in case the original used single-quote delimiters.
        out.push(' ');
        out.push_str(key);
        out.push_str("=\"");
        svg_push_raw_attr_val(out, raw_val);
        out.push('"');
    }
    if self_close {
        out.push_str("/>");
    } else {
        out.push('>');
    }
}

fn is_allowed_svg_element(lower: &str) -> bool {
    matches!(
        lower,
        "svg"
            | "g"
            | "defs"
            | "symbol"
            | "use"
            | "clippath"
            | "mask"
            | "pattern"
            | "lineargradient"
            | "radialgradient"
            | "stop"
            | "filter"
            | "fegaussianblur"
            | "feoffset"
            | "femerge"
            | "femergenode"
            | "feflood"
            | "fecomposite"
            | "feblend"
            | "fecolormatrix"
            | "rect"
            | "circle"
            | "ellipse"
            | "line"
            | "polyline"
            | "polygon"
            | "path"
            | "text"
            | "tspan"
            | "textpath"
            | "image"
            | "title"
            | "desc"
            | "marker"
            | "animate"
            | "animatetransform"
            | "animatemotion"
            | "set"
    )
}

fn is_allowed_svg_attribute(lower: &str) -> bool {
    matches!(
        lower,
        "id"
            | "class"
            | "style"
            | "x"
            | "y"
            | "x1"
            | "y1"
            | "x2"
            | "y2"
            | "cx"
            | "cy"
            | "r"
            | "rx"
            | "ry"
            | "width"
            | "height"
            | "viewbox"
            | "xmlns"
            | "xmlns:xlink"
            | "fill"
            | "stroke"
            | "stroke-width"
            | "stroke-linecap"
            | "stroke-linejoin"
            | "stroke-dasharray"
            | "stroke-dashoffset"
            | "opacity"
            | "fill-opacity"
            | "stroke-opacity"
            | "transform"
            | "d"
            | "points"
            | "font-family"
            | "font-size"
            | "font-weight"
            | "font-style"
            | "text-anchor"
            | "dominant-baseline"
            | "dx"
            | "dy"
            | "rotate"
            | "letter-spacing"
            | "text-decoration"
            | "clip-path"
            | "clip-rule"
            | "mask"
            | "filter"
            | "marker-start"
            | "marker-mid"
            | "marker-end"
            | "preserveaspectratio"
            | "color"
            | "display"
            | "visibility"
            | "overflow"
            | "gradientunits"
            | "gradienttransform"
            | "spreadmethod"
            | "offset"
            | "stop-color"
            | "stop-opacity"
            | "patternunits"
            | "patterntransform"
            | "href"
            | "xlink:href"
            | "dur"
            | "begin"
            | "end"
            | "repeatcount"
            | "from"
            | "to"
            | "values"
            | "keytimes"
            | "calcmode"
            | "attributename"
            | "type"
            | "result"
            | "in"
            | "in2"
            | "stddeviation"
            | "flood-color"
            | "flood-opacity"
            | "mode"
            | "fill-rule"
            | "xml:space"
            | "version"
            | "markerwidth"
            | "markerheight"
            | "orient"
            | "refx"
            | "refy"
            | "markerunits"
            | "patterncontentunits"
            | "alignment-baseline"
            | "baseline-shift"
    )
}

fn sanitize_svg_style(style: &str) -> String {
    style
        .split(';')
        .filter_map(|decl| {
            let decl = decl.trim();
            if decl.is_empty() {
                return None;
            }
            let (prop, val) = decl.split_once(':')?;
            let prop = prop.trim();
            let val = val.trim();
            if !is_safe_svg_css_property(&prop.to_ascii_lowercase()) {
                return None;
            }
            let lower_val = val.to_ascii_lowercase();
            if lower_val.contains("url(")
                || lower_val.contains("expression(")
                || lower_val.contains("javascript:")
                || lower_val.contains("-moz-binding")
                || lower_val.contains("behavior")
            {
                return None;
            }
            Some(format!("{}:{}", prop, val))
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn is_safe_svg_css_property(lower: &str) -> bool {
    matches!(
        lower,
        "color"
            | "fill"
            | "stroke"
            | "stroke-width"
            | "stroke-linecap"
            | "stroke-linejoin"
            | "stroke-dasharray"
            | "stroke-dashoffset"
            | "opacity"
            | "fill-opacity"
            | "stroke-opacity"
            | "font-family"
            | "font-size"
            | "font-weight"
            | "font-style"
            | "text-anchor"
            | "dominant-baseline"
            | "text-decoration"
            | "letter-spacing"
            | "display"
            | "visibility"
            | "overflow"
            | "transform"
            | "stop-color"
            | "stop-opacity"
            | "fill-rule"
            | "clip-rule"
    )
}

/// Escape a decoded value for use inside a double-quoted XML attribute.
fn svg_push_escaped_attr(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
}

/// Push a raw (already entity-escaped) attribute value, only re-escaping
/// double-quotes that may appear when the original used single-quote
/// delimiters.
fn svg_push_raw_attr_val(out: &mut String, raw: &str) {
    for c in raw.chars() {
        if c == '"' {
            out.push_str("&quot;");
        } else {
            out.push(c);
        }
    }
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

fn theme_palette(theme: UiTheme, dark: bool) -> ThemePalette {
    match (theme, dark) {
        (UiTheme::Parchment, false) => ThemePalette {
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
            font_mono: "\"IBM Plex Mono\", \"Cascadia Mono\", monospace",
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
        (UiTheme::Parchment, true) => ThemePalette {
            color_scheme: "dark",
            bg: "#1e1914",
            panel: "rgba(35,28,22,0.9)",
            panel_strong: "#2a221a",
            ink: "#ede5d8",
            muted: "#a3957f",
            line: "rgba(200, 170, 130, 0.18)",
            accent: "#e07050",
            accent_soft: "rgba(224, 112, 80, 0.16)",
            shadow: "0 20px 60px rgba(10, 5, 0, 0.5)",
            radius: "22px",
            font_sans: "Inter, -apple-system, system-ui, sans-serif",
            font_mono: "\"IBM Plex Mono\", \"Cascadia Mono\", monospace",
            body_background: "radial-gradient(circle at top left, rgba(160, 90, 50, 0.2), transparent 28rem), radial-gradient(circle at top right, rgba(80, 110, 140, 0.12), transparent 22rem), linear-gradient(180deg, #1a1510 0%, var(--bg) 100%)",
            button_background: "linear-gradient(135deg, #c45a30, #8b3a18)",
            button_text: "#fff8f2",
            hero_button_background: "linear-gradient(135deg, #c45a30, #8b3a18)",
            hero_button_text: "#fff8f2",
            flash_background: "rgba(62, 180, 110, 0.14)",
            flash_text: "#b8f0d0",
            flash_border: "rgba(62, 180, 110, 0.24)",
            callout_background: "rgba(224, 112, 80, 0.1)",
            code_background: "#120e0a",
            code_text: "#f0e6d8",
            media_background: "#1a1510",
            media_image_background: "linear-gradient(180deg, #251e16, #1a1510)",
            empty_background: "rgba(35,28,22,0.68)",
            details_background: "rgba(35,28,22,0.72)",
            input_background: "rgba(255,255,255,0.08)",
            surface_hover: "rgba(255,255,255,0.1)",
            diff_context_background: "rgba(255,255,255,0.04)",
            diff_added_background: "rgba(62, 180, 110, 0.14)",
            diff_added_prefix: "#6dd8a0",
            diff_removed_background: "rgba(224, 112, 80, 0.14)",
            diff_removed_prefix: "#f0a090",
        },
        (UiTheme::Graphite, true) => ThemePalette {
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
            font_sans: "Inter, -apple-system, system-ui, sans-serif",
            font_mono: "\"IBM Plex Mono\", \"Cascadia Mono\", monospace",
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
        (UiTheme::Graphite, false) => ThemePalette {
            color_scheme: "light",
            bg: "#edf1f7",
            panel: "rgba(255,255,255,0.9)",
            panel_strong: "#ffffff",
            ink: "#1a2233",
            muted: "#637088",
            line: "rgba(30, 50, 80, 0.14)",
            accent: "#3b82f6",
            accent_soft: "rgba(59, 130, 246, 0.12)",
            shadow: "0 20px 60px rgba(20, 40, 70, 0.1)",
            radius: "20px",
            font_sans: "Inter, -apple-system, system-ui, sans-serif",
            font_mono: "\"IBM Plex Mono\", \"Cascadia Mono\", monospace",
            body_background: "radial-gradient(circle at top left, rgba(59, 130, 246, 0.14), transparent 28rem), radial-gradient(circle at top right, rgba(99, 200, 220, 0.1), transparent 22rem), linear-gradient(180deg, #f3f6fb 0%, var(--bg) 100%)",
            button_background: "linear-gradient(135deg, #2563eb, #0f766e)",
            button_text: "#f8fbff",
            hero_button_background: "linear-gradient(135deg, #2563eb, #0f766e)",
            hero_button_text: "#f8fbff",
            flash_background: "rgba(16, 185, 129, 0.12)",
            flash_text: "#065f46",
            flash_border: "rgba(16, 185, 129, 0.2)",
            callout_background: "rgba(59, 130, 246, 0.08)",
            code_background: "#1a2233",
            code_text: "#dce5f0",
            media_background: "#ffffff",
            media_image_background: "linear-gradient(180deg, #fafbfe, #edf1f7)",
            empty_background: "rgba(255,255,255,0.66)",
            details_background: "rgba(255,255,255,0.66)",
            input_background: "rgba(255,255,255,0.92)",
            surface_hover: "rgba(255,255,255,0.9)",
            diff_context_background: "rgba(255,255,255,0.94)",
            diff_added_background: "rgba(16, 185, 129, 0.12)",
            diff_added_prefix: "#047857",
            diff_removed_background: "rgba(239, 68, 68, 0.1)",
            diff_removed_prefix: "#dc2626",
        },
        (UiTheme::Signal, false) => ThemePalette {
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
        (UiTheme::Signal, true) => ThemePalette {
            color_scheme: "dark",
            bg: "#0e1a16",
            panel: "rgba(18,32,27,0.9)",
            panel_strong: "#152520",
            ink: "#e2f0ea",
            muted: "#7fa99a",
            line: "rgba(120, 200, 170, 0.18)",
            accent: "#20c997",
            accent_soft: "rgba(32, 201, 151, 0.16)",
            shadow: "0 18px 54px rgba(5, 20, 15, 0.5)",
            radius: "18px",
            font_sans: "Inter, -apple-system, system-ui, sans-serif",
            font_mono: "\"IBM Plex Mono\", \"Cascadia Mono\", monospace",
            body_background: "radial-gradient(circle at top left, rgba(15, 143, 111, 0.2), transparent 28rem), radial-gradient(circle at top right, rgba(200, 100, 160, 0.1), transparent 22rem), linear-gradient(180deg, #0a1510 0%, var(--bg) 100%)",
            button_background: "linear-gradient(135deg, #20c997, #1768ac)",
            button_text: "#f0fff8",
            hero_button_background: "linear-gradient(135deg, #20c997, #1768ac)",
            hero_button_text: "#f0fff8",
            flash_background: "rgba(32, 201, 151, 0.14)",
            flash_text: "#b0f0d8",
            flash_border: "rgba(32, 201, 151, 0.24)",
            callout_background: "rgba(32, 201, 151, 0.1)",
            code_background: "#08120e",
            code_text: "#d0f8e8",
            media_background: "#0e1a16",
            media_image_background: "linear-gradient(180deg, #1a2e26, #0e1a16)",
            empty_background: "rgba(18,32,27,0.68)",
            details_background: "rgba(18,32,27,0.72)",
            input_background: "rgba(255,255,255,0.08)",
            surface_hover: "rgba(255,255,255,0.1)",
            diff_context_background: "rgba(255,255,255,0.04)",
            diff_added_background: "rgba(32, 201, 151, 0.14)",
            diff_added_prefix: "#5ee8c0",
            diff_removed_background: "rgba(248, 113, 113, 0.14)",
            diff_removed_prefix: "#fca5a5",
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

fn palette_css_vars(p: &ThemePalette) -> String {
    format!(
        r#"color-scheme: {color_scheme};
      --bg: {bg};
      --panel: {panel};
      --panel-strong: {panel_strong};
      --ink: {ink};
      --muted: {muted};
      --line: {line};
      --accent: {accent};
      --accent-soft: {accent_soft};
      --shadow: {shadow};
      --radius: {radius};
      --font-sans: {font_sans};
      --font-mono: {font_mono};
      --button-bg: {button_bg};
      --button-ink: {button_ink};
      --hero-button-bg: {hero_button_bg};
      --hero-button-ink: {hero_button_ink};
      --flash-bg: {flash_bg};
      --flash-ink: {flash_ink};
      --flash-line: {flash_line};
      --callout-bg: {callout_bg};
      --code-bg: {code_bg};
      --code-ink: {code_ink};
      --media-bg: {media_bg};
      --media-image-bg: {media_image_bg};
      --empty-bg: {empty_bg};
      --details-bg: {details_bg};
      --input-bg: {input_bg};
      --surface-hover: {surface_hover};
      --diff-ctx-bg: {diff_ctx_bg};
      --diff-add-bg: {diff_add_bg};
      --diff-add-prefix: {diff_add_prefix};
      --diff-rm-bg: {diff_rm_bg};
      --diff-rm-prefix: {diff_rm_prefix};
      --body-bg: {body_bg};"#,
        color_scheme = p.color_scheme,
        bg = p.bg,
        panel = p.panel,
        panel_strong = p.panel_strong,
        ink = p.ink,
        muted = p.muted,
        line = p.line,
        accent = p.accent,
        accent_soft = p.accent_soft,
        shadow = p.shadow,
        radius = p.radius,
        font_sans = p.font_sans,
        font_mono = p.font_mono,
        button_bg = p.button_background,
        button_ink = p.button_text,
        hero_button_bg = p.hero_button_background,
        hero_button_ink = p.hero_button_text,
        flash_bg = p.flash_background,
        flash_ink = p.flash_text,
        flash_line = p.flash_border,
        callout_bg = p.callout_background,
        code_bg = p.code_background,
        code_ink = p.code_text,
        media_bg = p.media_background,
        media_image_bg = p.media_image_background,
        empty_bg = p.empty_background,
        details_bg = p.details_background,
        input_bg = p.input_background,
        surface_hover = p.surface_hover,
        diff_ctx_bg = p.diff_context_background,
        diff_add_bg = p.diff_added_background,
        diff_add_prefix = p.diff_added_prefix,
        diff_rm_bg = p.diff_removed_background,
        diff_rm_prefix = p.diff_removed_prefix,
        body_bg = p.body_background,
    )
}

fn shared_styles(theme: UiTheme, mode: ColorMode) -> String {
    let root = match mode {
        ColorMode::Light => {
            let p = theme_palette(theme, false);
            format!(
                "    :root {{\n      {vars}\n\n      --s-1: 4px;\n      --s-2: 8px;\n      --s-3: 12px;\n      --s-4: 16px;\n      --s-5: 24px;\n      --s-6: 32px;\n      --s-7: 48px;\n      --s-8: 64px;\n    }}",
                vars = palette_css_vars(&p)
            )
        }
        ColorMode::Dark => {
            let p = theme_palette(theme, true);
            format!(
                "    :root {{\n      {vars}\n\n      --s-1: 4px;\n      --s-2: 8px;\n      --s-3: 12px;\n      --s-4: 16px;\n      --s-5: 24px;\n      --s-6: 32px;\n      --s-7: 48px;\n      --s-8: 64px;\n    }}",
                vars = palette_css_vars(&p)
            )
        }
        ColorMode::System => {
            let light = theme_palette(theme, false);
            let dark = theme_palette(theme, true);
            format!(
                "    :root {{\n      {light_vars}\n\n      --s-1: 4px;\n      --s-2: 8px;\n      --s-3: 12px;\n      --s-4: 16px;\n      --s-5: 24px;\n      --s-6: 32px;\n      --s-7: 48px;\n      --s-8: 64px;\n    }}\n    @media (prefers-color-scheme: dark) {{\n      :root {{\n        {dark_vars}\n      }}\n    }}",
                light_vars = palette_css_vars(&light),
                dark_vars = palette_css_vars(&dark)
            )
        }
    };
    let base = r#"

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: var(--font-sans);
      color: var(--ink);
      background: var(--body-bg);
      min-height: 100vh;
      line-height: 1.5;
    }
"#;
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

    .burger-btn {
      display: none;
      background: none;
      border: none;
      color: var(--muted);
      cursor: pointer;
      padding: var(--s-2);
      min-height: auto;
      width: auto;
    }
    .burger-btn:hover {
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

    .delete-project-section {
      margin-top: var(--s-6);
      padding-top: var(--s-5);
      border-top: 1px solid var(--line);
      display: flex;
      justify-content: flex-end;
    }

    .delete-project-btn {
      background: none;
      border: 1px solid var(--danger, #c53030);
      color: var(--danger, #c53030);
      padding: var(--s-2) var(--s-4);
      border-radius: var(--radius);
      cursor: pointer;
      font-size: 0.85rem;
      min-height: auto;
    }

    .delete-project-btn:hover {
      background: var(--danger, #c53030);
      color: #fff;
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

    .hero-actions a:hover {
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
      transform: translateY(-1px);
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

    .agents-options {
      display: flex;
      flex-direction: column;
      gap: var(--s-5);
      margin-top: var(--s-6);
    }

    .agent-list {
      display: flex;
      flex-direction: column;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      margin: var(--s-3) var(--s-5) var(--s-5);
      overflow: hidden;
    }

    .agent-list-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: var(--s-3) var(--s-4);
      border-bottom: 1px solid var(--line);
      text-decoration: none;
      color: var(--fg);
      transition: background 0.1s;
    }

    .agent-list-item:last-child {
      border-bottom: none;
    }

    .agent-list-item:hover {
      background: var(--bg-hover);
    }

    .agent-list-item.active {
      background: var(--bg-hover);
      border-left: 3px solid var(--accent);
    }

    .agent-list-name {
      font-weight: 600;
      font-family: var(--font-mono);
      font-size: 0.9rem;
    }

    .agent-list-meta {
      font-size: 0.82rem;
      color: var(--fg-muted);
    }

    .user-list {
      display: flex;
      flex-direction: column;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      margin: var(--s-3) var(--s-5) 0;
      overflow: hidden;
    }

    .user-list-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: var(--s-3) var(--s-4);
      border-bottom: 1px solid var(--line);
      cursor: pointer;
      transition: background 0.1s;
    }

    .user-list-item:last-child {
      border-bottom: none;
    }

    .user-list-item:hover {
      background: var(--bg-hover);
    }

    .user-list-item.active {
      background: var(--bg-hover);
      border-left: 3px solid var(--accent);
    }

    .user-list-name {
      font-weight: 600;
      font-family: var(--font-mono);
      font-size: 0.9rem;
    }

    .user-list-meta {
      font-size: 0.82rem;
      color: var(--fg-muted);
      display: flex;
      align-items: center;
      gap: var(--s-2);
    }

    .user-detail {
      border: 1px solid var(--line);
      border-top: none;
      border-radius: 0 0 var(--radius) var(--radius);
      margin: 0 var(--s-5) var(--s-5);
      padding: var(--s-4) 0;
    }

    /* Chat — full-viewport layout, no page scroll */
    body:has(.chat-layout) { overflow: hidden; }
    .shell:has(.chat-layout) {
      width: 100%;
      max-width: 100%;
      padding: 0;
      margin: 0;
      overflow: hidden;
    }
    .top-nav:has(~ .shell .chat-layout) { margin-bottom: 0; }
    .chat-layout {
      display: flex;
      height: calc(100vh - 65px);
      overflow: hidden;
    }
    .chat-sidebar {
      width: 280px;
      min-width: 280px;
      border-right: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      overflow-y: auto;
    }
    .chat-sidebar-header {
      padding: var(--s-4);
      border-bottom: 1px solid var(--line);
    }
    .chat-agent-list {
      flex: 1;
      overflow-y: auto;
    }
    .chat-agent-item {
      padding: var(--s-3) var(--s-4);
      border-bottom: 1px solid var(--line);
      cursor: pointer;
    }
    .chat-agent-item:hover {
      background: var(--bg-hover);
    }
    .chat-agent-active {
      background: var(--bg-hover);
      border-left: 3px solid var(--accent);
    }
    .chat-agent-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .chat-agent-name {
      font-weight: 600;
      font-size: 0.9rem;
    }
    .chat-status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
    }
    .chat-status-online { background: #22c55e; }
    .chat-status-thinking { background: #eab308; }
    .chat-status-offline { background: var(--fg-muted); }
    .chat-agent-snippet {
      font-size: 0.82rem;
      color: var(--fg-muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      margin-top: 2px;
    }
    .chat-agent-time {
      font-size: 0.75rem;
      color: var(--fg-muted);
    }
    .chat-main {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .chat-header {
      padding: var(--s-3) var(--s-4);
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      gap: var(--s-3);
    }
    .chat-header-name {
      font-weight: 600;
      font-size: 1rem;
    }
    .chat-header-status {
      font-size: 0.82rem;
      color: var(--fg-muted);
    }
    .chat-avatar-sm {
      width: 24px;
      height: 24px;
      border-radius: 4px;
      object-fit: cover;
      flex-shrink: 0;
      margin-right: var(--s-2);
    }
    .chat-avatar-header {
      width: 28px;
      height: 28px;
      border-radius: 5px;
      object-fit: cover;
      flex-shrink: 0;
    }
    .chat-avatar-msg {
      width: 26px;
      height: 26px;
      border-radius: 4px;
      object-fit: cover;
      flex-shrink: 0;
      margin-top: 2px;
    }
    .chat-back-btn {
      display: none;
      background: none;
      border: none;
      color: var(--fg);
      cursor: pointer;
      padding: var(--s-2);
    }
    .chat-messages {
      flex: 1;
      overflow-y: auto;
      padding: var(--s-4);
      display: flex;
      flex-direction: column;
      gap: var(--s-3);
    }
    .chat-msg {
      max-width: 80%;
      padding: var(--s-3) var(--s-4);
      border-radius: 8px;
      font-size: 0.92rem;
      line-height: 1.5;
      word-wrap: break-word;
    }
    .chat-msg-user {
      align-self: flex-end;
      background: var(--accent);
      color: #fff;
    }
    .chat-msg-assistant {
      align-self: flex-start;
      background: var(--bg-hover);
      color: var(--fg);
      display: flex;
      gap: var(--s-2);
      align-items: flex-start;
    }
    .chat-msg-system {
      align-self: center;
      background: var(--bg);
      color: var(--fg-muted);
      border: 1px solid var(--line);
      font-size: 0.85rem;
      max-width: 90%;
      font-family: var(--font-mono);
    }
    .chat-msg-user .chat-msg-content,
    .chat-msg-system .chat-msg-content { white-space: pre-wrap; }
    .chat-msg-assistant .chat-msg-content p { margin: 0.3em 0; }
    .chat-msg-assistant .chat-msg-content p:first-child { margin-top: 0; }
    .chat-msg-assistant .chat-msg-content p:last-child { margin-bottom: 0; }
    .chat-msg-assistant .chat-msg-content h1,
    .chat-msg-assistant .chat-msg-content h2,
    .chat-msg-assistant .chat-msg-content h3,
    .chat-msg-assistant .chat-msg-content h4 {
      margin: 0.6em 0 0.3em;
      line-height: 1.3;
    }
    .chat-msg-assistant .chat-msg-content h1 { font-size: 1.15em; }
    .chat-msg-assistant .chat-msg-content h2 { font-size: 1.05em; }
    .chat-msg-assistant .chat-msg-content h3 { font-size: 1em; font-weight: 600; }
    .chat-msg-assistant .chat-msg-content h4 { font-size: 0.95em; font-weight: 600; }
    .chat-msg-assistant .chat-msg-content ul,
    .chat-msg-assistant .chat-msg-content ol {
      margin: 0.3em 0;
      padding-left: 1.4em;
    }
    .chat-msg-assistant .chat-msg-content li { margin: 0.15em 0; }
    .chat-msg-assistant .chat-msg-content blockquote {
      border-left: 3px solid var(--accent);
      margin: 0.3em 0;
      padding: 0.15em 0.7em;
      color: var(--muted);
    }
    .chat-msg-assistant .chat-msg-content hr {
      border: none;
      border-top: 1px solid var(--line);
      margin: 0.5em 0;
    }
    .chat-msg-assistant .chat-msg-content pre {
      background: var(--code-bg);
      color: var(--code-ink);
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 0.5em 0.7em;
      overflow-x: auto;
      font-family: var(--font-mono);
      font-size: 0.85em;
      margin: 0.4em 0;
      white-space: pre;
    }
    .chat-msg-assistant .chat-msg-content code {
      font-family: var(--font-mono);
      font-size: 0.88em;
    }
    .chat-msg-assistant .chat-msg-content :not(pre) > code {
      background: var(--code-bg);
      color: var(--code-ink);
      border-radius: 3px;
      padding: 0.1em 0.3em;
    }
    .chat-msg-assistant .chat-msg-content a {
      color: var(--accent);
      text-decoration: underline;
    }
    .chat-table-wrap {
      overflow-x: auto;
      margin: 0.4em 0;
    }
    .chat-table-wrap table {
      border-collapse: collapse;
      width: 100%;
      font-size: 0.88em;
    }
    .chat-table-wrap th, .chat-table-wrap td {
      border: 1px solid var(--line);
      padding: 0.35em 0.6em;
      text-align: left;
    }
    .chat-table-wrap th {
      background: var(--surface);
      font-weight: 600;
    }
    .chat-svg-wrap {
      cursor: pointer;
      margin: 0.4em 0;
      max-width: 100%;
      border-radius: 4px;
      border: 1px solid var(--line);
      padding: 0.5em;
      position: relative;
    }
    .chat-svg-wrap svg { max-width: 100%; height: auto; display: block; }
    .chat-svg-wrap:hover { border-color: var(--accent); }
    .chat-svg-hint {
      font-size: 0.72em;
      color: var(--muted);
      text-align: center;
      margin-top: 0.3em;
    }
    .svg-overlay {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      background: rgba(0,0,0,0.85);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 9999;
      cursor: pointer;
      padding: 2rem;
      box-sizing: border-box;
    }
    .svg-overlay svg {
      max-width: 90vw;
      max-height: 90vh;
      border-radius: 8px;
      padding: 1rem;
    }
    .svg-overlay-close {
      position: fixed;
      top: 1rem; right: 1rem;
      background: rgba(255,255,255,0.15);
      border: none;
      color: #fff;
      font-size: 1.5rem;
      cursor: pointer;
      z-index: 10000;
      width: 36px; height: 36px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 50%;
    }
    .svg-overlay-close:hover { background: rgba(255,255,255,0.3); }
    .chat-input-form {
      display: flex;
      gap: var(--s-2);
      padding: var(--s-3) var(--s-4);
      border-top: 1px solid var(--line);
      align-items: flex-end;
    }
    .chat-input {
      flex: 1;
      padding: var(--s-3);
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--bg);
      color: var(--fg);
      font-family: var(--font-sans);
      font-size: 0.92rem;
      resize: none;
      min-height: 38px;
      max-height: 120px;
    }
    .chat-send-btn {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 6px;
      width: 38px;
      height: 38px;
      min-width: 38px;
      padding: 0;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .chat-send-btn:hover { opacity: 0.85; }
    .chat-empty {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .chat-empty-text {
      color: var(--fg-muted);
      font-size: 1rem;
    }

    .stack {
      display: grid;
      gap: var(--s-4);
    }

    .timeline {
      display: grid;
      gap: 6px;
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
    .tree-add-btn,
    .tree-drag-handle {
      background: none;
      border: 1px solid var(--line);
      color: var(--muted);
      border-radius: var(--radius);
      cursor: pointer;
      font-size: 0.85rem;
      padding: 2px 8px;
      min-height: auto;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }

    .tree-add-child:hover,
    .tree-add-btn:hover {
      background: var(--surface-hover);
      color: var(--ink);
    }

    .tree-drag-handle {
      cursor: grab;
    }
    .tree-drag-handle:active {
      cursor: grabbing;
    }
    .tree-drag-handle:hover {
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

    /* Drag and drop */
    .tree-dragging {
      opacity: 0.4;
    }
    .tree-drop-zone {
      height: 0;
      transition: height 0.15s, background 0.15s;
      border-radius: var(--radius);
      margin: 0 var(--s-3);
    }
    .tree-drop-zone.tree-drop-visible {
      height: 6px;
    }
    .tree-drop-zone.tree-drop-hover {
      height: 6px;
      background: var(--accent);
    }
    .tree-node-row.tree-node-drop-hover {
      outline: 2px solid var(--accent);
      outline-offset: -2px;
      border-radius: var(--radius);
      background: var(--surface-hover);
    }

    .timeline {
      padding: var(--s-5);
    }

    /* Edit-line paradigm: seamless document with vertical band indicator */
    .editline-row {
      display: flex;
      align-items: stretch;
    }

    .editline-row > .block {
      flex: 1;
      min-width: 0;
    }

    .main-column {
      display: flex;
      flex-direction: column;
      gap: var(--s-3);
      min-width: 0;
    }

    .section-tag {
      text-align: right;
      font-size: 0.75em;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--fg);
      opacity: 0.35;
      margin-bottom: var(--s-1);
    }

    .agent-context-section {
      margin-bottom: 0;
    }

    .agent-context-panel {
      display: flex;
      align-items: stretch;
      background: var(--surface-hover);
      border-radius: var(--radius);
      padding: var(--s-3) 0 var(--s-3) var(--s-4);
      overflow: hidden;
    }

    .agent-context-content {
      flex: 1;
      min-width: 0;
      padding-right: var(--s-4);
    }

    .agent-context-preview,
    .agent-context-full-text {
      margin: 0;
      font-size: 0.85em;
      white-space: pre-wrap;
      word-break: break-word;
      color: var(--fg);
      opacity: 0.8;
    }

    .agent-context-textarea {
      width: 100%;
      min-height: 120px;
      max-height: 400px;
      font-family: var(--font-mono);
      font-size: 0.85em;
      padding: var(--s-3);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--bg);
      color: var(--fg);
      resize: vertical;
    }

    .agent-context-band {
      align-self: stretch;
    }

    .block {
      padding: var(--s-3) 0;
      border: none;
      border-radius: 0;
      background: transparent;
      transition: background 0.15s;
    }

    .block.editing {
      background: var(--surface-hover);
      border-radius: var(--radius);
      padding: var(--s-3) var(--s-4);
    }

    .editline-band {
      width: 7px;
      flex-shrink: 0;
      cursor: pointer;
      transition: background 0.15s, width 0.15s;
      border-radius: 2px;
      margin-left: var(--s-3);
    }

    .editline-band-even {
      background: var(--accent-soft);
    }

    .editline-band-odd {
      background: var(--line);
    }

    .editline-band:hover {
      background: var(--accent);
      width: 9px;
    }

    .editline-band-active {
      background: var(--accent) !important;
      width: 9px;
    }

    .editline-band-pinned {
      background: var(--accent) !important;
      opacity: 0.6;
    }

    .editline-band-pinned:hover {
      opacity: 1;
    }

    .editline-band-dragging {
      background: var(--accent) !important;
      width: 9px;
      opacity: 0.5;
    }

    .editline-gap-drop-ready {
      min-height: 12px;
      background: var(--accent-soft);
      border-radius: 2px;
      transition: min-height 0.15s, background 0.15s;
    }

    .editline-gap-drop-hover {
      min-height: 20px;
      background: var(--accent) !important;
    }

    /* Edit-line gap rows (inserters) */
    .editline-gap-row {
      min-height: 4px;
      position: relative;
    }

    .editline-gap-row > .block-inserter {
      flex: 1;
      min-width: 0;
    }

    .editline-gap {
      width: 7px;
      flex-shrink: 0;
      margin-left: var(--s-3);
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
    }

    .editline-plus {
      position: absolute;
      left: 50%;
      top: 50%;
      transform: translate(-50%, -50%);
      width: 20px;
      height: 20px;
      min-height: auto;
      border-radius: 50%;
      border: 2px solid var(--line);
      background: var(--panel-strong);
      color: var(--muted);
      font-size: 0.85rem;
      font-weight: bold;
      line-height: 1;
      cursor: pointer;
      padding: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      opacity: 0;
      transition: opacity 0.15s, border-color 0.2s, color 0.2s, background 0.2s;
      z-index: 6;
      box-shadow: 0 1px 4px rgba(0,0,0,0.15);
    }

    .editline-gap-row:hover .editline-plus {
      opacity: 1;
    }

    .editline-plus:hover {
      border-color: var(--accent);
      color: var(--accent);
      background: var(--accent-soft);
    }

    /* Cancel circle button (X) for edit/insert forms */
    .cancel-circle {
      width: 24px;
      height: 24px;
      min-height: auto;
      border-radius: 50%;
      border: 2px solid var(--line);
      background: var(--panel-strong);
      color: var(--muted);
      cursor: pointer;
      padding: 0;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
      flex-shrink: 0;
    }
    .cancel-circle:hover {
      border-color: var(--danger);
      color: var(--danger);
      background: #fff0f0;
    }


    .block-inserter {
      display: flex;
      flex-direction: column;
      align-items: stretch;
    }

    .block-inserter.expanded {
      margin: var(--s-2) 0;
    }

    .inserter-expand {
      width: 100%;
      margin-top: var(--s-3);
      position: relative;
      z-index: 4;
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

    .panel-subheading {
      font-size: 0.85em;
      font-weight: 600;
      color: var(--muted);
      margin: 0;
      padding: 0;
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
      align-items: center;
      justify-content: space-between;
      margin-bottom: var(--s-3);
      color: var(--muted);
      font-size: 0.85rem;
    }

    .block-header-actions {
      display: flex;
      gap: var(--s-1);
      align-items: center;
    }

    .block-header-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      min-height: auto;
      padding: 0;
      border-radius: 6px;
      border: 1px solid transparent;
      background: transparent;
      color: var(--muted);
      cursor: pointer;
      transition: background 0.15s, color 0.15s, border-color 0.15s;
    }

    .block-header-btn:hover {
      background: var(--accent-soft);
      border-color: var(--accent);
      color: var(--accent);
    }

    .block-header-btn.danger:hover {
      background: #fef2f2;
      border-color: #dc2626;
      color: #dc2626;
    }

    .block-header-btn.pinned {
      background: var(--accent-soft);
      border-color: var(--accent);
      color: var(--accent);
    }

    .block-edit-panel {
    }

    .block-edit-textarea {
      min-height: 8rem;
      font-family: var(--font-mono);
      font-size: 0.9rem;
    }

    .block-edit-extras {
      display: grid;
      gap: var(--s-3);
      padding-top: var(--s-3);
      border-top: 1px solid var(--line);
      margin-top: var(--s-2);
    }

    .block-edit-actions {
      display: flex;
      gap: var(--s-2);
    }

    .block-edit-actions button {
      width: auto;
      padding: var(--s-2) var(--s-5);
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

    a.lore-link {
      text-decoration-style: dotted;
    }
    a.lore-link-project::before {
      content: "\1F4C4  ";
      font-size: 0.85em;
    }
    a.lore-link-block::before {
      content: "\1F517  ";
      font-size: 0.85em;
    }
    .doc-link-picker {
      display: flex;
      align-items: center;
      gap: var(--s-3);
    }
    .doc-link-picker select {
      flex: 1;
      min-width: 0;
    }
    a.lore-link-broken {
      color: #dc2626;
      text-decoration: line-through;
      cursor: not-allowed;
    }

    .block-edit-panel form {
      display: grid;
      gap: var(--s-4);
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

    .agents-cmd-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }

    .agents-cmd-table td {
      padding: var(--s-2) var(--s-3);
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }

    .agents-cmd-table td:first-child {
      white-space: nowrap;
      font-family: var(--font-mono);
      font-size: 0.82rem;
      color: var(--accent);
    }

    .agents-cmd-table tr:last-child td {
      border-bottom: none;
    }

    .copy-btn {
      background: var(--panel);
      color: var(--muted);
      border: 1px solid var(--line);
      border-radius: var(--s-2);
      padding: var(--s-1) var(--s-3);
      font-size: 0.8rem;
      cursor: pointer;
      min-height: auto;
      width: auto;
    }

    .copy-btn:hover {
      color: var(--ink);
      border-color: var(--muted);
    }

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
        grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
        overflow-x: visible;
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

      .block-header-btn {
        width: 28px;
        height: 28px;
      }

      /* Burger menu */
      .burger-btn {
        display: block;
      }

      .top-nav-links {
        display: none;
        position: absolute;
        top: 64px;
        right: 0;
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: var(--s-2);
        padding: var(--s-3);
        flex-direction: column;
        gap: var(--s-3);
        min-width: 160px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.12);
        z-index: 200;
      }

      .top-nav-links.burger-open {
        display: flex;
      }

      .top-nav-inner {
        position: relative;
      }

      /* Admin nav buttons: wrap on mobile */
      .admin-nav {
        grid-auto-flow: row;
        grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
        overflow-x: visible;
      }

      /* Mobile: hide edit line by default, show pencil toggle */
      #document {
        position: relative;
      }

      /* Chat mobile */
      .chat-layout { flex-direction: column; }
      .chat-sidebar {
        width: 100%;
        min-width: 100%;
        border-right: none;
        max-height: none;
      }
      .chat-main { display: none; }
      .chat-has-agent .chat-sidebar { display: none; }
      .chat-has-agent .chat-main { display: flex; flex: 1; }
      .chat-sidebar-show .chat-sidebar { display: flex !important; }
      .chat-sidebar-show .chat-main { display: none !important; }
      .chat-back-btn { display: flex; }
      .chat-msg { max-width: 90%; }

    }
    "#;
    format!("{root}{base}{rest}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BlockType, NewBlock};
    use crate::store::FileBlockStore;
    use tempfile::tempdir;

    #[test]
    fn lore_links_resolve_in_rendered_markdown() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let info = store.create_project("My Docs", None).unwrap();
        let block = store
            .create_block(NewBlock {
                project: info.slug.clone(),
                block_type: BlockType::Markdown,
                content: "Hello world".into(),
                author_key: "key-a".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        // Project link resolves
        let html = format!(r#"<a href="lore://{}">My Docs</a>"#, info.id);
        let resolved = resolve_lore_links_in_html(&html, &store);
        assert!(resolved.contains(&format!(r#"href="/ui/{}""#, info.slug.as_str())));
        assert!(resolved.contains("lore-link-project"));

        // Block link resolves
        let html = format!(r#"<a href="lore://{}">a block</a>"#, block.id.as_str());
        let resolved = resolve_lore_links_in_html(&html, &store);
        assert!(resolved.contains(&format!("block-{}", block.id.as_str())));
        assert!(resolved.contains("lore-link-block"));

        // Unknown UUID gets broken link
        let html = r#"<a href="lore://00000000-0000-0000-0000-000000000000">gone</a>"#;
        let resolved = resolve_lore_links_in_html(html, &store);
        assert!(resolved.contains("lore-link-broken"));
    }
}
