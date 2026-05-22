use crate::audit::{AuditActor, AuditActorKind};
use crate::auth::{ProjectGrant, ProjectPermission, StoredMachine, StoredRole};
use crate::config::{
    ColorMode, ExternalAuthConfig, ExternalScheme, OidcConfig, ServerConfig, UiTheme,
};
use crate::librarian::{
    Endpoint, LibrarianActor, LibrarianActorKind, LibrarianConfig, LibrarianRunKind,
    LibrarianRunStatus, ProjectLibrarianOperationType, ProviderCheckResult,
    StoredLibrarianOperation,
};
use crate::manager::{ManagerPromptConfig, ManagerPromptStage};
use crate::model::{
    Block, BlockId, BlockType, ProjectName, RESERVED_AGENT_CONTEXT, RESERVED_MAP, RESERVED_OVERVIEW,
};
use crate::store::{DocumentInfo, FileBlockStore, ProjectInfo};
use crate::updater::{AutoUpdateConfig, AutoUpdateStatus, ReleaseStream};
use crate::versioning::{
    GitExportConfig, GitExportStatus, ProjectVersionActor, ProjectVersionActorKind,
    ProjectVersionOperationType,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use pulldown_cmark::{Options, Parser, html};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;

// Lucide-style SVG icons for agent controls (14x14)
const ICON_STOP: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>"#;
const ICON_RESTART: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>"#;
const ICON_CHECK: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>"#;
const ICON_CLOSE: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>"#;
const ICON_SETTINGS: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>"#;
const ICON_MANAGER: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>"#;
const ICON_STATUS_DONE: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m9 12 2 2 4-4"/></svg>"#;
const ICON_STATUS_WORKING: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.3-3.3a6 6 0 0 1-7.9 7.9l-6.8 6.8a2 2 0 1 1-2.8-2.8l6.8-6.8a6 6 0 0 1 7.9-7.9z"/></svg>"#;
const ICON_STATUS_STOPPED: &str = r#"<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6"/><path d="M15 9l-6 6"/></svg>"#;

fn chat_status_indicator(status: &str) -> (&'static str, &'static str, &'static str) {
    match status {
        "idle" => ("chat-status-running", "Finished", ICON_STATUS_DONE),
        "thinking" => ("chat-status-working", "Working", ICON_STATUS_WORKING),
        "restarting" => ("chat-status-restarting", "Restarting", ICON_RESTART),
        _ => ("chat-status-stopped", "Stopped", ICON_STATUS_STOPPED),
    }
}

pub struct PageShell<'a> {
    pub title: &'a str,
    pub username: Option<&'a str>,
    pub is_admin: bool,
    pub theme: UiTheme,
    pub color_mode: ColorMode,
    pub csrf_token: Option<&'a str>,
    pub flash: Option<&'a str>,
}

fn shell_color_scheme_meta(mode: ColorMode) -> &'static str {
    match mode {
        ColorMode::System => "light dark",
        ColorMode::Light => "light",
        ColorMode::Dark => "dark",
    }
}

fn shell_root_attrs(mode: ColorMode) -> String {
    let mut attrs = format!(r#" data-color-mode="{}""#, mode.as_str());
    if mode != ColorMode::System {
        attrs.push_str(&format!(r#" data-resolved-color-mode="{}""#, mode.as_str()));
    }
    attrs
}

fn shell_theme_bootstrap(mode: ColorMode) -> String {
    format!(
        r#"(function() {{
  var root = document.documentElement;
  var mode = '{mode}';
  function setResolvedMode(resolved) {{
    root.setAttribute('data-resolved-color-mode', resolved);
  }}
  root.setAttribute('data-color-mode', mode);
  if (mode === 'system') {{
    root.removeAttribute('data-resolved-color-mode');
    root.style.colorScheme = 'light dark';
    return;
  }}
  setResolvedMode(mode);
  root.style.colorScheme = mode;
}})();"#,
        mode = mode.as_str()
    )
}

pub fn render_shell(shell: PageShell, content: String) -> String {
    let flash_html = flash_message(shell.flash);
    let csrf_hidden = shell
        .csrf_token
        .map(|t| format!(r#"<input type="hidden" name="csrf_token" value="{}">"#, t))
        .unwrap_or_default();
    let color_scheme_meta = shell_color_scheme_meta(shell.color_mode);
    let root_attrs = shell_root_attrs(shell.color_mode);
    let theme_bootstrap = shell_theme_bootstrap(shell.color_mode);
    let nav_html = if let Some(username) = shell.username {
        let admin_link = if shell.is_admin {
            r#"<a href="/ui/admin">Admin</a>"#.to_string()
        } else {
            String::new()
        };
        format!(
            r#"<nav class="top-nav">
  <div class="top-nav-inner">
    <div style="display:flex; align-items:baseline; gap:var(--s-4);">
      <a href="/ui" class="logo">Lore</a>
      <span class="eyebrow">{username}</span>
    </div>
    <div class="nav-right-btns">
      <a href="/ui" class="nav-projects-btn" aria-label="Projects">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z"/></svg>
      </a>
      <a href="/ui/chat" class="nav-chat-btn" aria-label="Chat">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      </a>
      <button class="burger-btn" onclick="toggleBurger()" aria-label="Menu">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
      </button>
    </div>
    <div class="top-nav-links" id="top-nav-links">
      <a href="/ui" class="nav-link-projects">Projects</a>
      <a href="/ui/chat" class="nav-link-chat">Chat</a>
      <a href="/ui/agents">Agents</a>
      {admin_link}
      <a href="/ui/settings">Settings</a>
    </div>
  </div>
</nav>"#,
            username = escape_text(username),
            admin_link = admin_link,
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en"{root_attrs}>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="color-scheme" content="{color_scheme_meta}">
  <title>{title}</title>
  <script>{theme_bootstrap}</script>
  <style>{styles}</style>
</head>
<body>
  {nav_html}
  {csrf_hidden}
  <script>
  var expandedTextEditorState = null;
  var expandedTextEditorScrollY = 0;
  function syncExpandedTextEditorViewport() {{
    var overlay = document.getElementById('expanded-text-editor');
    var shell = overlay ? overlay.querySelector('.expanded-editor-shell') : null;
    if (!overlay) return;
    overlay.style.top = '';
    overlay.style.right = '';
    overlay.style.bottom = '';
    overlay.style.left = '';
    overlay.style.width = '';
    overlay.style.height = '';
    if (!shell) return;
    if (!document.body.classList.contains('expanded-editor-open')) {{
      shell.style.top = '';
      shell.style.right = '';
      shell.style.bottom = '';
      shell.style.left = '';
      shell.style.width = '';
      shell.style.height = '';
      return;
    }}
    if (window.visualViewport) {{
      shell.style.top = Math.max(0, Math.round(window.visualViewport.offsetTop)) + 'px';
      shell.style.right = 'auto';
      shell.style.bottom = 'auto';
      shell.style.left = Math.max(0, Math.round(window.visualViewport.offsetLeft)) + 'px';
      shell.style.width = Math.max(0, Math.round(window.visualViewport.width)) + 'px';
      shell.style.height = Math.max(0, Math.round(window.visualViewport.height)) + 'px';
    }} else {{
      shell.style.top = '';
      shell.style.right = '';
      shell.style.bottom = '';
      shell.style.left = '';
      shell.style.width = '';
      shell.style.height = '';
    }}
  }}
  function scheduleExpandedTextEditorViewportSync() {{
    syncExpandedTextEditorViewport();
    requestAnimationFrame(function() {{
      syncExpandedTextEditorViewport();
      setTimeout(syncExpandedTextEditorViewport, 60);
      setTimeout(syncExpandedTextEditorViewport, 180);
    }});
  }}
  function setExpandedTextEditorOpen(open) {{
    var overlay = document.getElementById('expanded-text-editor');
    var wasOpen = document.body.classList.contains('expanded-editor-open');
    if (open && !wasOpen) {{
      expandedTextEditorScrollY = window.scrollY || document.documentElement.scrollTop || 0;
      document.documentElement.style.overflow = 'hidden';
      document.body.style.position = 'fixed';
      document.body.style.top = '-' + expandedTextEditorScrollY + 'px';
      document.body.style.left = '0';
      document.body.style.right = '0';
      document.body.style.width = '100%';
    }}
    if (overlay) overlay.style.display = open ? 'flex' : 'none';
    document.body.classList.toggle('expanded-editor-open', !!open);
    syncExpandedTextEditorViewport();
    if (!open && wasOpen) {{
      var restoreY = expandedTextEditorScrollY;
      document.documentElement.style.overflow = '';
      document.body.style.position = '';
      document.body.style.top = '';
      document.body.style.left = '';
      document.body.style.right = '';
      document.body.style.width = '';
      expandedTextEditorScrollY = 0;
      window.scrollTo(0, restoreY);
    }}
  }}
  function openExpandedTextEditor(sourceId) {{
    var source = document.getElementById(sourceId);
    var overlay = document.getElementById('expanded-text-editor');
    var input = document.getElementById('expanded-editor-input');
    var title = document.getElementById('expanded-editor-title');
    if (!source || !overlay || !input || !title || source.disabled) return false;
    expandedTextEditorState = {{
      sourceId: sourceId,
      saveKind: source.getAttribute('data-editor-save') || ''
    }};
    title.textContent = source.getAttribute('data-editor-label') || 'Edit';
    input.value = source.value || '';
    input.placeholder = source.getAttribute('placeholder') || '';
    setExpandedTextEditorOpen(true);
    window.setTimeout(function() {{
      scheduleExpandedTextEditorViewportSync();
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    }}, 0);
    return false;
  }}
  function syncExpandedEditorPreview(sourceId) {{
    var source = document.getElementById(sourceId);
    var preview = document.querySelector('[data-expanded-editor-preview-for="' + sourceId + '"]');
    if (!source || !preview) return;
    var value = source.value || '';
    var placeholder = source.getAttribute('placeholder') || '';
    if (value.trim()) {{
      preview.textContent = value;
      preview.classList.remove('is-placeholder');
    }} else {{
      preview.textContent = placeholder;
      preview.classList.add('is-placeholder');
    }}
  }}
  function cancelExpandedTextEditor() {{
    expandedTextEditorState = null;
    setExpandedTextEditorOpen(false);
    return false;
  }}
  function saveExpandedTextEditor() {{
    if (!expandedTextEditorState) return false;
    var source = document.getElementById(expandedTextEditorState.sourceId);
    var input = document.getElementById('expanded-editor-input');
    if (!source || !input) {{
      cancelExpandedTextEditor();
      return false;
    }}
    source.value = input.value;
    syncExpandedEditorPreview(source.id);
    var saveKind = expandedTextEditorState.saveKind;
    cancelExpandedTextEditor();
    if (saveKind === 'pinned') {{
      if (typeof pinnedSaveTimer !== 'undefined' && pinnedSaveTimer) clearTimeout(pinnedSaveTimer);
      if (typeof savePinnedContext === 'function') savePinnedContext();
    }} else if (saveKind === 'manage') {{
      if (typeof manageSaveTimer !== 'undefined' && manageSaveTimer) clearTimeout(manageSaveTimer);
      if (typeof saveManageConfig === 'function') saveManageConfig();
    }} else if (saveKind === 'block') {{
      var action = source.getAttribute('data-editor-action') || '';
      var blockType = source.getAttribute('data-editor-block-type') || 'markdown';
      var csrf = document.querySelector('input[name="csrf_token"]');
      if (!action || !csrf) return false;
      var formData = new FormData();
      formData.append('csrf_token', csrf.value);
      formData.append('block_type', blockType);
      formData.append('content', input.value);
      fetch(action, {{
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      }}).then(function(response) {{
        if (!response.ok) throw new Error('Block save failed');
        if (response.redirected && response.url) {{
          window.location.assign(response.url);
        }} else {{
          window.location.reload();
        }}
      }}).catch(function(err) {{
        alert(err && err.message ? err.message : 'Failed to save block');
      }});
      return false;
    }} else if (saveKind === 'reserved') {{
      var action = source.getAttribute('data-editor-action') || '';
      var csrf = document.querySelector('input[name="csrf_token"]');
      if (!action || !csrf) return false;
      var formData = new URLSearchParams();
      formData.set('csrf_token', csrf.value);
      formData.set('content', input.value);
      fetch(action, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
        body: formData,
        credentials: 'same-origin'
      }}).then(function(response) {{
        if (!response.ok) throw new Error('Section save failed');
        if (response.redirected && response.url) {{
          window.location.assign(response.url);
        }} else {{
          window.location.reload();
        }}
      }}).catch(function(err) {{
        alert(err && err.message ? err.message : 'Failed to save section');
      }});
      return false;
    }} else {{
      source.dispatchEvent(new Event('input', {{ bubbles: true }}));
    }}
    return false;
  }}
  if (window.visualViewport) {{
    window.visualViewport.addEventListener('resize', function() {{
      syncExpandedTextEditorViewport();
    }});
    window.visualViewport.addEventListener('scroll', function() {{
      syncExpandedTextEditorViewport();
    }});
  }}
  document.addEventListener('focusin', function(e) {{
    if (e.target && e.target.id === 'expanded-editor-input') {{
      scheduleExpandedTextEditorViewportSync();
    }}
  }});
  document.addEventListener('focusout', function(e) {{
    if (e.target && e.target.id === 'expanded-editor-input') {{
      setTimeout(syncExpandedTextEditorViewport, 0);
      setTimeout(syncExpandedTextEditorViewport, 120);
    }}
  }});
  document.addEventListener('DOMContentLoaded', function() {{
    document.querySelectorAll('.expanded-editor-source').forEach(function(source) {{
      if (source.id) syncExpandedEditorPreview(source.id);
    }});
  }});
  </script>
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
    var directSource = document.getElementById('block-edit-content-' + blockId);
    var meta = document.getElementById('meta-' + blockId);
    var article = document.getElementById('block-' + blockId);
    if (directSource && directSource.getAttribute('data-editor-save') === 'block') {{
      openExpandedTextEditor(directSource.id);
      return;
    }}
    if (!body || !edit) return;
    var expandedSource = edit.querySelector('textarea[data-editor-save="block"]');
    if (edit.style.display === 'none' && expandedSource && expandedSource.id) {{
      openExpandedTextEditor(expandedSource.id);
      return;
    }}
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
    var body = document.getElementById('agent-context-body');
    var editPanel = document.getElementById('agent-context-edit');
    var band = document.querySelector('.agent-context-band');
    var block = document.querySelector('.agent-context-block');
    if (!editPanel) return;
    if (editPanel.style.display === 'none') {{
      if (body) body.style.display = 'none';
      editPanel.style.display = '';
      if (band) band.classList.add('editline-band-active');
      if (block) block.classList.add('editing');
      var ta = editPanel.querySelector('textarea');
      if (ta) {{ ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); }}
    }} else {{
      if (body) body.style.display = '';
      editPanel.style.display = 'none';
      if (band) band.classList.remove('editline-band-active');
      if (block) block.classList.remove('editing');
    }}
  }}
  function toggleReservedEdit(safeId) {{
    var source = document.getElementById('reserved-' + safeId + '-content');
    if (source) {{
      openExpandedTextEditor(source.id);
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
    if (document.body.classList.contains('expanded-editor-open')) {{
      cancelExpandedTextEditor();
      e.preventDefault();
      return;
    }}
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
        color_scheme_meta = color_scheme_meta,
        root_attrs = root_attrs,
        theme_bootstrap = theme_bootstrap,
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
    pub endpoint_id: Option<String>,
    pub machine_name: Option<String>,
    pub process_status: Option<String>,
    pub status: String,
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
    let title = if has_users { "Sign in to Lore" } else { "Lore" };
    let subtitle = if has_users { "" } else { "" };
    let action = "/login";
    let button = "Sign in";
    let no_users_html = if !has_users {
        r#"<p class="hint" style="margin-top:var(--s-4)">No admin account exists yet. Create one on the server console:<br><code style="display:inline-block;margin-top:var(--s-2);padding:var(--s-1) var(--s-2);background:var(--bg-2);border-radius:4px">lore-server create-admin</code></p>"#
            .to_string()
    } else {
        String::new()
    };
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

    let form_html = if has_users {
        format!(
            r#"<form method="post" action="{action}">
        <label>
          Username
          <input type="text" name="username" autocomplete="username" required>
        </label>
        <label>
          Password
          <input type="password" name="password" autocomplete="current-password" required>
        </label>
        <button type="submit">{button}</button>
      </form>
      {oidc_html}
      {external_auth_html}"#,
            action = action,
            button = escape_text(button),
            oidc_html = oidc_html,
            external_auth_html = external_auth_html,
        )
    } else {
        no_users_html.clone()
    };

    let content = format!(
        r#"<section class="panel auth-panel">
      <p class="eyebrow">Lore</p>
      <h1>{title}</h1>
      {subtitle_html}
      {form_html}
    </section>"#,
        title = escape_text(title),
        subtitle_html = if subtitle.is_empty() {
            String::new()
        } else {
            format!("<p class=\"subtitle\">{}</p>", escape_text(subtitle))
        },
        form_html = form_html,
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
    project_docs: &std::collections::HashMap<String, Vec<DocumentInfo>>,
    csrf_token: &str,
    flash: Option<&str>,
) -> String {
    let tree_html = if projects.is_empty() {
        r#"<div class="empty-state"><p>No projects yet.</p></div>"#.to_string()
    } else {
        render_project_tree(projects, project_docs, is_admin, csrf_token)
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
    var treeUser = '{username}';
    var dragSlug = null;

    function treeStateKey() {{ return 'lore-tree-' + treeUser; }}
    function saveTreeState() {{
      var expanded = [];
      document.querySelectorAll('.tree-node').forEach(function(node) {{
        var btn = node.querySelector(':scope > .tree-node-row > .tree-expand-btn');
        if (btn && btn.classList.contains('tree-expand-open')) {{
          expanded.push(node.getAttribute('data-slug'));
        }}
      }});
      try {{ localStorage.setItem(treeStateKey(), JSON.stringify(expanded)); }} catch(e) {{}}
    }}
    function restoreTreeState() {{
      var expanded;
      try {{ expanded = JSON.parse(localStorage.getItem(treeStateKey())); }} catch(e) {{ return; }}
      if (!expanded || !expanded.length) return;
      expanded.forEach(function(slug) {{
        var node = document.querySelector('.tree-node[data-slug="' + slug + '"]');
        if (!node) return;
        var btn = node.querySelector(':scope > .tree-node-row > .tree-expand-btn');
        if (btn && !btn.classList.contains('tree-expand-open')) {{
          toggleProjectDocs(btn);
        }}
      }});
    }}

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
    function toggleProjectDocs(btn) {{
      var node = btn.closest('.tree-node');
      var docList = node.querySelector(':scope > .tree-doc-list');
      if (!docList) return;
      if (docList.style.display === 'none') {{
        docList.style.display = '';
        btn.innerHTML = '&#9660;';
        btn.classList.add('tree-expand-open');
      }} else {{
        docList.style.display = 'none';
        btn.innerHTML = '&#9654;';
        btn.classList.remove('tree-expand-open');
      }}
      saveTreeState();
    }}
    function addDocRow(btn, projectSlug, parentDocId) {{
      document.querySelectorAll('.tree-doc-inline-create').forEach(function(el) {{ el.remove(); }});
      var li = document.createElement('li');
      li.className = 'tree-doc-node tree-doc-inline-create';
      var indent = 20;
      var node = btn.closest('.tree-doc-node');
      if (parentDocId && node) {{
        var parentRow = node.querySelector(':scope > .tree-doc-row');
        if (parentRow) indent = (parseInt(parentRow.style.paddingLeft) || 0) + 20;
      }}
      li.innerHTML = '<form class="tree-doc-row" style="padding-left:' + indent + 'px" method="post" action="/ui/' + projectSlug + '/documents">'
        + '<input type="hidden" name="csrf_token" value="' + csrfToken + '">'
        + (parentDocId ? '<input type="hidden" name="parent_document_id" value="' + parentDocId + '">' : '')
        + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>'
        + '<input type="text" name="name" class="tree-inline-input" placeholder="Document name" required style="font-size:0.9rem;font-weight:normal">'
        + '<button type="submit" class="tree-add-child">Save</button>'
        + '<button type="button" class="tree-add-child" onclick="this.closest(\'.tree-doc-inline-create\').remove()">Cancel</button>'
        + '</form>';
      var node = btn.closest('.tree-node') || btn.closest('.tree-doc-node');
      if (parentDocId) {{
        node.appendChild(li);
      }} else {{
        var docList = node.querySelector(':scope > .tree-doc-list');
        if (!docList) {{
          docList = document.createElement('ul');
          docList.className = 'tree-doc-list';
          node.appendChild(docList);
          var expandBtn = node.querySelector('.tree-expand-btn');
          if (expandBtn) {{
            expandBtn.innerHTML = '&#9660;';
            expandBtn.classList.add('tree-expand-open');
          }}
        }}
        docList.style.display = '';
        docList.appendChild(li);
      }}
      li.querySelector('input[name="name"]').focus();
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
    restoreTreeState();
    </script>"#,
        tree_html = tree_html,
        root_create = root_create,
        csrf_token = escape_attribute(csrf_token),
        username = escape_attribute(username),
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

fn render_project_tree(
    projects: &[ProjectListEntry],
    project_docs: &std::collections::HashMap<String, Vec<DocumentInfo>>,
    is_admin: bool,
    csrf_token: &str,
) -> String {
    fn render_doc_subtree(
        project_slug: &str,
        docs: &[DocumentInfo],
        depth: usize,
        can_write: bool,
    ) -> String {
        docs.iter()
            .map(|doc| {
                let doc_id = escape_attribute(doc.id.as_str());
                let name = escape_text(&doc.display_name);
                let indent = format!("padding-left:{}px", (depth + 1) * 20);
                let children = render_doc_subtree(project_slug, &doc.children, depth + 1, can_write);
                let add_child_doc_btn = if can_write {
                    format!(
                        r#"<button type="button" class="tree-add-child tree-doc-add" onclick="event.stopPropagation(); event.preventDefault(); addDocRow(this, '{project_slug}', '{doc_id}')" title="New sub-document"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg></button>"#,
                        project_slug = escape_attribute(project_slug),
                        doc_id = doc_id,
                    )
                } else {
                    String::new()
                };
                format!(
                    r#"<li class="tree-doc-node">
  <div class="tree-doc-row" style="{indent}">
    <a href="/ui/{project_slug}/doc/{doc_id}" class="tree-doc-link">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
      <span>{name}</span>
    </a>
    {add_child_doc_btn}
  </div>
</li>{children}"#,
                    indent = indent,
                    project_slug = escape_attribute(project_slug),
                    doc_id = doc_id,
                    name = name,
                    add_child_doc_btn = add_child_doc_btn,
                    children = children,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn render_children(
        parent: Option<&str>,
        projects: &[ProjectListEntry],
        project_docs: &std::collections::HashMap<String, Vec<DocumentInfo>>,
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
                    project_docs,
                    is_admin,
                    csrf_token,
                    depth + 1,
                );

                let docs = project_docs.get(slug);
                let has_docs = docs.map_or(false, |d| !d.is_empty());
                let expand_btn = if has_docs {
                    r#"<button type="button" class="tree-expand-btn" onclick="event.stopPropagation(); toggleProjectDocs(this)" title="Show documents">&#9654;</button>"#.to_string()
                } else {
                    String::new()
                };

                let doc_tree_html = if let Some(docs) = docs {
                    if !docs.is_empty() {
                        let doc_items = render_doc_subtree(slug, docs, 0, entry.can_write);
                        format!(
                            r#"<ul class="tree-doc-list" style="display:none;">{doc_items}</ul>"#,
                        )
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                let add_doc_btn = if entry.can_write {
                    format!(
                        r#"<button type="button" class="tree-add-child" onclick="event.stopPropagation(); addDocRow(this, '{slug_attr}', '')" title="New document"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg></button>"#,
                        slug_attr = escape_attribute(slug),
                    )
                } else {
                    String::new()
                };

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
    {expand_btn}
    <a href="/ui/{slug}" class="tree-link">{display}</a>
    <div class="tree-row-right">
      <span class="tree-perm">{perm}</span>
      {add_doc_btn}
      {admin_btns}
    </div>
  </div>
  {doc_tree_html}
  {sub}
  {drop_zone}
</li>"#,
                    slug = escape_attribute(slug),
                    parent_attr = escape_attribute(parent_attr),
                    expand_btn = expand_btn,
                    display = display,
                    perm = perm,
                    add_doc_btn = add_doc_btn,
                    admin_btns = admin_btns,
                    doc_tree_html = doc_tree_html,
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

        format!(
            r#"<ul class="tree-list" data-parent="{lp}">{top_drop}{items}</ul>"#,
            lp = escape_attribute(list_parent),
            top_drop = top_drop,
            items = items.join(""),
        )
    }

    render_children(None, projects, project_docs, is_admin, csrf_token, 0)
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
    manager_prompt_config: &ManagerPromptConfig,
    librarian_config: &LibrarianConfig,
    endpoints: &[crate::librarian::Endpoint],
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
                    r#"<div class="sel-item" data-sel-id="{username_attr}">
                      <span class="sel-item-name">{username}</span>
                      <span class="sel-item-meta"><span class="pill">{badge}</span>{disabled} &middot; {sessions} sessions</span>
                    </div>"#,
                    username_attr = escape_attribute(&user.username),
                    username = escape_text(&user.username),
                    badge = badge,
                    disabled = disabled_badge,
                    sessions = user.active_sessions,
                )
            })
            .collect();
        format!(r#"<div class="sel-list">{}</div>"#, items.join(""))
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
    let endpoints_list_html = if endpoints.is_empty() {
        "<p class=\"hint padded\">No endpoints configured yet.</p>".to_string()
    } else {
        let items: Vec<String> = endpoints
            .iter()
            .map(|ep| {
                let status = if ep.is_configured() && ep.has_api_key() {
                    "configured"
                } else {
                    "incomplete"
                };
                format!(
                    r#"<div class="sel-item" data-sel-id="{id}">
                      <span class="sel-item-name">{name}</span>
                      <span class="sel-item-meta"><span class="pill">{kind}</span> &middot; {status}</span>
                    </div>"#,
                    id = escape_attribute(&ep.id),
                    name = escape_text(&ep.name),
                    kind = ep.kind,
                    status = status,
                )
            })
            .collect();
        format!(r#"<div class="sel-list">{}</div>"#, items.join(""))
    };
    let endpoints_detail_html: String = endpoints
        .iter()
        .map(|ep| {
            let key_placeholder = if ep.has_api_key() {
                "Stored. Leave blank to preserve."
            } else {
                "Paste a provider secret"
            };
            format!(
                r#"<div class="sel-detail" data-sel-id="{id}" style="display:none">
                  <form method="post" action="/ui/admin/endpoints/{id}">
                    <input type="hidden" name="csrf_token" value="{csrf}">
                    <label>Name<input type="text" name="name" value="{name}" required></label>
                    <label>URL<input type="url" name="url" value="{url}" placeholder="https://api.example.com/..."></label>
                    <label>API key<input type="password" name="api_key" placeholder="{key_placeholder}"></label>
                    <label>Model
                      <div style="display:flex;gap:var(--s-1);align-items:center">
                        <input type="text" name="model" value="{model}" required style="flex:1;margin:0">
                        <button type="button" class="btn-sm" title="Fetch available models" onclick="fetchModels(this)"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 21h5v-5"/></svg></button>
                      </div>
                    </label>
                    <div style="display:flex;gap:var(--s-2);flex-wrap:wrap">
                      <button type="submit">Save endpoint</button>
                    </div>
                  </form>
                  <div style="display:flex;gap:var(--s-2);margin-top:var(--s-3);flex-wrap:wrap">
                    <form method="post" action="/ui/admin/endpoints/{id}/test" style="margin:0">
                      <input type="hidden" name="csrf_token" value="{csrf}">
                      <button type="submit" style="width:auto">Test</button>
                    </form>
                    <form method="post" action="/ui/admin/endpoints/{id}/delete" style="margin:0"
                          onsubmit="return confirm('Delete this endpoint?')">
                      <input type="hidden" name="csrf_token" value="{csrf}">
                      <button type="submit" style="width:auto;background:var(--danger);color:#fff">Delete</button>
                    </form>
                  </div>
                </div>"#,
                id = escape_attribute(&ep.id),
                csrf = escape_attribute(csrf_token),
                name = escape_attribute(&ep.name),
                url = escape_attribute(&ep.url),
                model = escape_attribute(&ep.model),
                key_placeholder = key_placeholder,
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let librarian_endpoint_options: String = {
        let none_selected = if librarian_config.endpoint_id.is_none() {
            " selected"
        } else {
            ""
        };
        let mut opts = format!(r#"<option value=""{none_selected}>-- none --</option>"#);
        for ep in endpoints {
            let sel = if librarian_config.endpoint_id.as_deref() == Some(&ep.id) {
                " selected"
            } else {
                ""
            };
            opts.push_str(&format!(
                r#"<option value="{id}"{sel}>{name} ({kind})</option>"#,
                id = escape_attribute(&ep.id),
                name = escape_text(&ep.name),
                kind = ep.kind,
                sel = sel,
            ));
        }
        opts
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
    let stable_selected = if auto_update_config.release_stream == ReleaseStream::Stable {
        " selected"
    } else {
        ""
    };
    let prerelease_selected = if auto_update_config.release_stream == ReleaseStream::Prerelease {
        " selected"
    } else {
        ""
    };
    let manager_review_enabled_checked = if manager_prompt_config.review_latest_output.enabled {
        " checked"
    } else {
        ""
    };
    let manager_periodic_enabled_checked = if manager_prompt_config.run_periodic_checks.enabled {
        " checked"
    } else {
        ""
    };
    let manager_validate_enabled_checked = if manager_prompt_config.validate_periodic_checks.enabled
    {
        " checked"
    } else {
        ""
    };
    let manager_review_text = if manager_prompt_config.review_latest_output.enabled {
        manager_prompt_config.review_latest_output.text.as_str()
    } else {
        ManagerPromptStage::ReviewLatestOutput.default_text()
    };
    let manager_periodic_text = if manager_prompt_config.run_periodic_checks.enabled {
        manager_prompt_config.run_periodic_checks.text.as_str()
    } else {
        ManagerPromptStage::RunPeriodicChecks.default_text()
    };
    let manager_validate_text = if manager_prompt_config.validate_periodic_checks.enabled {
        manager_prompt_config.validate_periodic_checks.text.as_str()
    } else {
        ManagerPromptStage::ValidatePeriodicChecks.default_text()
    };
    let _ = auto_update_status; // no longer rendered

    let sections = [
        "users",
        "roles",
        "network",
        "endpoints",
        "librarian",
        "git-export",
        "oidc",
        "external-auth",
        "updates",
        "manager",
        "audit",
    ];
    let section_labels = [
        "Users",
        "User Roles",
        "Network",
        "Endpoints",
        "Librarian",
        "Git export",
        "OIDC",
        "External auth",
        "Updates",
        "Manager",
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
        r#"<div class="admin-page-header">
      <h1 class="page-title">Admin</h1>
      <p class="admin-version">Lore v{current_version}</p>
    </div>

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

      <section class="panel" data-panel="endpoints"{endpoints_display}>
        <div class="panel-header">
          <h2>Add endpoint</h2>
          <p>Configure Anthropic, Gemini, or OpenAI provider endpoints.</p>
        </div>
        <form method="post" action="/ui/admin/endpoints">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>Name<input type="text" name="name" placeholder="Production Anthropic" required></label>
          <label>URL<input type="url" name="url" placeholder="https://api.anthropic.com/v1/messages" required></label>
          <label>API key<input type="password" name="api_key"></label>
          <label>Model
            <div style="display:flex;gap:var(--s-1);align-items:center">
              <input type="text" name="model" placeholder="claude-sonnet-4-20250514" required style="flex:1;margin:0">
              <button type="button" class="btn-sm" title="Fetch available models" onclick="fetchModels(this)"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 21h5v-5"/></svg></button>
            </div>
          </label>
          <button type="submit">Add endpoint</button>
        </form>
        <div class="panel-header"><h2>Endpoints</h2></div>
        {endpoints_list_html}
        <div id="endpoint-detail-container">{endpoints_detail_html}</div>
      </section>

      <section class="panel" data-panel="librarian"{librarian_display}>
        <div class="panel-header">
          <h2>Librarian</h2>
          <p>Select which endpoint the librarian uses for AI requests.</p>
        </div>
        <form method="post" action="/ui/admin/librarian">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Endpoint
            <select name="endpoint_id">{librarian_endpoint_options}</select>
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
          <h2>Connected Machines</h2>
          <p>Signal all connected CLI machines to update on their next poll.</p>
        </div>
        <div style="padding:0 var(--s-5) var(--s-5)">
          <button type="button" id="update-all-machines-btn" data-csrf="{csrf_token}">Update all machines</button>
        </div>
        <label class="toggle" style="padding:0 var(--s-5) var(--s-5);">
          <input type="checkbox" id="auto-update-machines-toggle" data-csrf="{csrf_token}"{auto_update_machines_checked}>
          <span>Automatically update machines when the server comes online on a new version</span>
        </label>

        <div class="panel-header" style="margin-top:var(--s-5)">
          <h2>Auto Update</h2>
          <p>Configure automatic updates on server restart.</p>
        </div>
        <label class="toggle" style="padding:var(--s-5);">
          <input type="checkbox" id="auto-update-toggle" data-csrf="{csrf_token}"{auto_update_enabled_checked}>
          <span>Enable automatic server self-update on restart</span>
        </label>
        <div class="panel-header" style="margin-top:var(--s-5)">
          <h2>Release Stream</h2>
          <p>Machine-triggered CLI updates follow the server's selected stream.</p>
        </div>
        <div style="padding:0 var(--s-5) var(--s-5)">
          <select id="auto-update-stream" data-csrf="{csrf_token}">
            <option value="stable"{stable_selected}>Stable</option>
            <option value="prerelease"{prerelease_selected}>Prerelease</option>
          </select>
        </div>
      </section>

      <section class="panel" data-panel="manager"{manager_display}>
        <div class="panel-header">
          <h2>Manager</h2>
          <p>Review the stage-specific prompts sent to the manager. Goals, stopping rules, red flags, and safety instructions are still added automatically.</p>
        </div>
        <form method="post" action="/ui/admin/manager-prompts">
          <input type="hidden" name="csrf_token" value="{csrf_token}">

          <div class="panel-header" style="margin-top:0">
            <h2>Review Latest Output</h2>
            <p>Used on the normal manager turns between periodic checks.</p>
          </div>
          <label class="toggle" style="padding:0 var(--s-5) var(--s-3);">
            <input
              type="checkbox"
              name="review_latest_output_enabled"
              value="true"
              data-manager-prompt-toggle
              data-manager-target="manager-review-prompt"
              {manager_review_enabled_checked}>
            <span>Edit this prompt</span>
          </label>
          <div style="padding:0 var(--s-5) var(--s-5);">
            <label class="chat-config-label" for="manager-review-prompt">Prompt</label>
            <div
              class="chat-config-textarea expanded-editor-preview"
              data-expanded-editor-preview-for="manager-review-prompt"
              onclick="return openManagerPromptEditor('manager-review-prompt')"></div>
            <textarea
              id="manager-review-prompt"
              name="review_latest_output_text"
              class="chat-config-textarea expanded-editor-source"
              data-editor-label="Review Latest Output Prompt"
              data-manager-default="{manager_review_default}"
              placeholder="Used on normal manager turns between periodic checks."
              readonly
              onclick="return openExpandedTextEditor('manager-review-prompt')"
              style="display:none;"{manager_review_disabled}>{manager_review_text}</textarea>
          </div>

          <div class="panel-header">
            <h2>Run Periodic Checks</h2>
            <p>Used when the manager should tell the agent to run its periodic verification checklist.</p>
          </div>
          <label class="toggle" style="padding:0 var(--s-5) var(--s-3);">
            <input
              type="checkbox"
              name="run_periodic_checks_enabled"
              value="true"
              data-manager-prompt-toggle
              data-manager-target="manager-periodic-prompt"
              {manager_periodic_enabled_checked}>
            <span>Edit this prompt</span>
          </label>
          <div style="padding:0 var(--s-5) var(--s-5);">
            <label class="chat-config-label" for="manager-periodic-prompt">Prompt</label>
            <div
              class="chat-config-textarea expanded-editor-preview"
              data-expanded-editor-preview-for="manager-periodic-prompt"
              onclick="return openManagerPromptEditor('manager-periodic-prompt')"></div>
            <textarea
              id="manager-periodic-prompt"
              name="run_periodic_checks_text"
              class="chat-config-textarea expanded-editor-source"
              data-editor-label="Run Periodic Checks Prompt"
              data-manager-default="{manager_periodic_default}"
              placeholder="Used when the manager should ask the agent to run periodic verification."
              readonly
              onclick="return openExpandedTextEditor('manager-periodic-prompt')"
              style="display:none;"{manager_periodic_disabled}>{manager_periodic_text}</textarea>
          </div>

          <div class="panel-header">
            <h2>Validate Periodic Check Results</h2>
            <p>Used after the agent reports back from a periodic-check turn.</p>
          </div>
          <label class="toggle" style="padding:0 var(--s-5) var(--s-3);">
            <input
              type="checkbox"
              name="validate_periodic_checks_enabled"
              value="true"
              data-manager-prompt-toggle
              data-manager-target="manager-validate-prompt"
              {manager_validate_enabled_checked}>
            <span>Edit this prompt</span>
          </label>
          <div style="padding:0 var(--s-5) var(--s-5);">
            <label class="chat-config-label" for="manager-validate-prompt">Prompt</label>
            <div
              class="chat-config-textarea expanded-editor-preview"
              data-expanded-editor-preview-for="manager-validate-prompt"
              onclick="return openManagerPromptEditor('manager-validate-prompt')"></div>
            <textarea
              id="manager-validate-prompt"
              name="validate_periodic_checks_text"
              class="chat-config-textarea expanded-editor-source"
              data-editor-label="Validate Periodic Check Results Prompt"
              data-manager-default="{manager_validate_default}"
              placeholder="Used after the agent reports back from a periodic-check turn."
              readonly
              onclick="return openExpandedTextEditor('manager-validate-prompt')"
              style="display:none;"{manager_validate_disabled}>{manager_validate_text}</textarea>
          </div>

          <div style="padding:0 var(--s-5) var(--s-5);">
            <button type="submit" class="btn-lg">Save manager prompts</button>
          </div>
        </form>
      </section>

      <section class="panel" data-panel="audit"{audit_display}>
        <div class="panel-header">
          <h2>Audit</h2>
          <p>Recent runs and events. <a href="/ui/admin/audit">Open full audit</a> &middot; <a href="/ui/admin/errors">Open error log</a>.</p>
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
                var oldVer = d.current_version;
                ubtn.textContent = 'Restarting\u2026';
                (function pollRestart() {{
                  var dots = 0;
                  var iv = setInterval(function() {{
                    dots = (dots + 1) % 4;
                    ubtn.textContent = 'Restarting' + '.'.repeat(dots || 1);
                  }}, 400);
                  function tryReach() {{
                    fetch('/v1/health', {{method: 'GET', cache: 'no-store'}}).then(function(r) {{
                      if (!r.ok) {{ setTimeout(tryReach, 1500); return; }}
                      return r.json();
                    }}).then(function(h) {{
                      if (!h) return;
                      if (h.version && h.version !== oldVer) {{
                        clearInterval(iv);
                        ubtn.textContent = 'Updated to v' + h.version + '! Reloading\u2026';
                        setTimeout(function() {{ location.reload(); }}, 500);
                      }} else {{
                        setTimeout(tryReach, 1500);
                      }}
                    }}).catch(function() {{
                      setTimeout(tryReach, 1500);
                    }});
                  }}
                  setTimeout(tryReach, 2000);
                }})();
              }} else {{
                ubtn.textContent = 'Up to date (v' + d.current_version + ')';
                ubtn.disabled = true;
                setTimeout(resetBtn, 4000);
              }}
            }}).catch(function() {{
              ubtn.textContent = 'Restarting\u2026';
              ubtn.disabled = true;
              var oldVer2 = '{current_version}';
              (function pollAfterCrash() {{
                var dots = 0;
                var iv = setInterval(function() {{
                  dots = (dots + 1) % 4;
                  ubtn.textContent = 'Restarting' + '.'.repeat(dots || 1);
                }}, 400);
                function tryReach() {{
                  fetch('/v1/health', {{method: 'GET', cache: 'no-store'}}).then(function(r) {{
                    if (!r.ok) {{ setTimeout(tryReach, 1500); return; }}
                    return r.json();
                  }}).then(function(h) {{
                    if (!h) return;
                    if (h.version && h.version !== oldVer2) {{
                      clearInterval(iv);
                      ubtn.textContent = 'Updated to v' + h.version + '! Reloading\u2026';
                      setTimeout(function() {{ location.reload(); }}, 500);
                    }} else {{
                      setTimeout(tryReach, 1500);
                    }}
                  }}).catch(function() {{
                    setTimeout(tryReach, 1500);
                  }});
                }}
                setTimeout(tryReach, 2000);
              }})();
            }});
          }}
        }});
      }}

      var autoCb = document.getElementById('auto-update-toggle');
      var autoStream = document.getElementById('auto-update-stream');
      var autoMachinesCb = document.getElementById('auto-update-machines-toggle');
      function saveAutoUpdateSettings() {{
        var source = autoCb || autoMachinesCb;
        if (!source) return;
        var csrf = source.getAttribute('data-csrf');
        var stream = autoStream ? autoStream.value : 'stable';
        fetch('/ui/admin/auto-update/toggle-json', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
          body: 'csrf_token=' + encodeURIComponent(csrf)
            + '&enabled=' + encodeURIComponent(autoCb ? String(autoCb.checked) : 'false')
            + '&release_stream=' + encodeURIComponent(stream)
            + '&auto_update_machines=' + encodeURIComponent(autoMachinesCb ? String(autoMachinesCb.checked) : 'false')
        }});
      }}
      if (autoCb) {{
        autoCb.addEventListener('change', function() {{
          saveAutoUpdateSettings();
        }});
      }}
      if (autoStream) {{
        autoStream.addEventListener('change', function() {{
          saveAutoUpdateSettings();
        }});
      }}
      if (autoMachinesCb) {{
        autoMachinesCb.addEventListener('change', function() {{
          saveAutoUpdateSettings();
        }});
      }}

      function pollMachineStatus(btn, name, csrf) {{
        fetch('/ui/agents/machines/' + encodeURIComponent(name) + '/status-json', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
          body: 'csrf_token=' + encodeURIComponent(csrf)
        }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
          if (d.up_to_date) {{
            btn.style.display = 'none';
          }} else if (d.pending_update) {{
            setTimeout(function() {{ pollMachineStatus(btn, name, csrf); }}, 3000);
          }} else {{
            btn.textContent = 'Update';
            btn.disabled = false;
            btn.style.opacity = '';
          }}
        }}).catch(function() {{
          setTimeout(function() {{ pollMachineStatus(btn, name, csrf); }}, 5000);
        }});
      }}

      function updateMachine(btn, name) {{
        var csrf = btn.getAttribute('data-csrf');
        btn.disabled = true;
        btn.textContent = 'Queuing\u2026';
        fetch('/ui/agents/machines/' + encodeURIComponent(name) + '/update-json', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
          body: 'csrf_token=' + encodeURIComponent(csrf)
        }}).then(function(r) {{
          if (!r.ok) throw new Error('server returned ' + r.status);
          return r.json();
        }}).then(function() {{
          btn.textContent = 'Updating\u2026';
          setTimeout(function() {{ pollMachineStatus(btn, name, csrf); }}, 3000);
        }}).catch(function() {{
          btn.textContent = 'Failed';
          btn.disabled = false;
          setTimeout(function() {{ btn.textContent = 'Update'; }}, 3000);
        }});
      }}

      var uamBtn = document.getElementById('update-all-machines-btn');
      if (uamBtn) {{
        uamBtn.addEventListener('click', function() {{
          var csrf = uamBtn.getAttribute('data-csrf');
          uamBtn.disabled = true;
          uamBtn.textContent = 'Queuing\u2026';
          fetch('/ui/admin/update-all-machines-json', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
            body: 'csrf_token=' + encodeURIComponent(csrf)
          }}).then(function(r) {{
            if (!r.ok) throw new Error('server returned ' + r.status);
            return r.json();
          }}).then(function(d) {{
            uamBtn.textContent = d.count + ' machine' + (d.count === 1 ? '' : 's') + ' queued';
            setTimeout(function() {{
              uamBtn.textContent = 'Update all machines';
              uamBtn.disabled = false;
            }}, 3000);
          }}).catch(function() {{
            uamBtn.textContent = 'Failed';
            setTimeout(function() {{
              uamBtn.textContent = 'Update all machines';
              uamBtn.disabled = false;
            }}, 3000);
          }});
        }});
      }}

      function syncManagerPromptEditor(toggle) {{
        var targetId = toggle.getAttribute('data-manager-target');
        if (!targetId) return;
        var textarea = document.getElementById(targetId);
        var preview = document.querySelector('[data-expanded-editor-preview-for="' + targetId + '"]');
        if (!textarea) return;
        if (toggle.checked) {{
          textarea.disabled = false;
          textarea.removeAttribute('disabled');
          if (preview) preview.classList.remove('is-disabled');
        }} else {{
          textarea.value = textarea.getAttribute('data-manager-default') || '';
          textarea.disabled = true;
          textarea.setAttribute('disabled', 'disabled');
          if (preview) preview.classList.add('is-disabled');
        }}
        syncExpandedEditorPreview(targetId);
      }}
      window.openManagerPromptEditor = function(targetId) {{
        var toggle = document.querySelector('[data-manager-prompt-toggle][data-manager-target="' + targetId + '"]');
        if (!toggle || !toggle.checked) return false;
        syncManagerPromptEditor(toggle);
        var textarea = document.getElementById(targetId);
        if (textarea) {{
          textarea.disabled = false;
          textarea.removeAttribute('disabled');
        }}
        return openExpandedTextEditor(targetId);
      }};
      document.querySelectorAll('[data-manager-prompt-toggle]').forEach(function(toggle) {{
        syncManagerPromptEditor(toggle);
        toggle.addEventListener('change', function() {{
          syncManagerPromptEditor(toggle);
        }});
      }});

      function initSelList(scope) {{
        var items = scope.querySelectorAll('.sel-list .sel-item');
        var details = scope.querySelectorAll('.sel-detail');
        items.forEach(function(item) {{
          item.addEventListener('click', function() {{
            var id = item.getAttribute('data-sel-id');
            var wasActive = item.classList.contains('active');
            items.forEach(function(i) {{ i.classList.remove('active'); }});
            details.forEach(function(d) {{ d.style.display = 'none'; }});
            if (!wasActive) {{
              item.classList.add('active');
              var detail = scope.querySelector('.sel-detail[data-sel-id="' + id + '"]');
              if (detail) detail.style.display = '';
            }}
          }});
        }});
      }}
      document.querySelectorAll('[data-panel]').forEach(function(p) {{ initSelList(p); }});

      window.fetchModels = function(btn) {{
        var form = btn.closest('form');
        var urlInput = form.querySelector('input[name="url"]');
        var keyInput = form.querySelector('input[name="api_key"]');
        var modelField = form.querySelector('[name="model"]');
        var currentModel = modelField.value;
        var detailDiv = form.closest('.sel-detail');
        var endpointId = detailDiv ? detailDiv.getAttribute('data-sel-id') : null;
        var body = {{}};
        if (endpointId) body.endpoint_id = endpointId;
        if (urlInput && urlInput.value) body.url = urlInput.value;
        if (keyInput && keyInput.value) body.api_key = keyInput.value;
        if (!body.url && !body.endpoint_id) return;
        btn.disabled = true;
        btn.style.opacity = '0.5';
        fetch('/ui/admin/endpoints/list-models', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify(body)
        }})
        .then(function(r) {{ if (!r.ok) throw new Error('failed'); return r.json(); }})
        .then(function(data) {{
          if (!data.models || !data.models.length) throw new Error('empty');
          var sel = document.createElement('select');
          sel.name = 'model';
          sel.required = true;
          sel.style.flex = '1';
          sel.style.margin = '0';
          data.models.forEach(function(m) {{
            var opt = document.createElement('option');
            opt.value = m;
            opt.textContent = m;
            if (m === currentModel) opt.selected = true;
            sel.appendChild(opt);
          }});
          modelField.replaceWith(sel);
        }})
        .catch(function() {{ btn.style.background = 'var(--danger)'; btn.style.color = '#fff';
          setTimeout(function() {{ btn.style.background = ''; btn.style.color = ''; }}, 1200);
        }})
        .finally(function() {{ btn.disabled = false; btn.style.opacity = ''; }});
      }};
    }})();

    document.querySelectorAll('[data-machine-update]').forEach(function(btn) {{
      var name = btn.getAttribute('data-machine-update');
      var csrf = btn.getAttribute('data-csrf');
      pollMachineStatus(btn, name, csrf);
    }});
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
        endpoints_list_html = endpoints_list_html,
        endpoints_detail_html = endpoints_detail_html,
        librarian_endpoint_options = librarian_endpoint_options,
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
        auto_update_machines_checked = if auto_update_config.auto_update_machines {
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
        endpoints_display = hidden("endpoints"),
        librarian_display = hidden("librarian"),
        git_export_display = hidden("git-export"),
        oidc_display = hidden("oidc"),
        external_auth_display = hidden("external-auth"),
        updates_display = hidden("updates"),
        manager_display = hidden("manager"),
        audit_display = hidden("audit"),
        manager_review_default =
            escape_attribute(ManagerPromptStage::ReviewLatestOutput.default_text()),
        manager_periodic_default =
            escape_attribute(ManagerPromptStage::RunPeriodicChecks.default_text()),
        manager_validate_default =
            escape_attribute(ManagerPromptStage::ValidatePeriodicChecks.default_text()),
        manager_review_disabled = if manager_prompt_config.review_latest_output.enabled {
            ""
        } else {
            " disabled"
        },
        manager_periodic_disabled = if manager_prompt_config.run_periodic_checks.enabled {
            ""
        } else {
            " disabled"
        },
        manager_validate_disabled = if manager_prompt_config.validate_periodic_checks.enabled {
            ""
        } else {
            " disabled"
        },
        manager_review_text = escape_text(manager_review_text),
        manager_periodic_text = escape_text(manager_periodic_text),
        manager_validate_text = escape_text(manager_validate_text),
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
    endpoints: &[Endpoint],
    selected_agent: Option<&str>,
    flash: Option<&str>,
    created_token: Option<&str>,
) -> String {
    let base_url = config.base_url();
    let mcp_url = config.mcp_url();
    let install_script_url = format!("{}/install-cli.sh", base_url.trim_end_matches('/'));
    let install_ps1_url = format!("{}/install-cli.ps1", base_url.trim_end_matches('/'));

    let agent_list_html = if agents.is_empty() {
        r#"<p class="hint padded">No agents yet. Create an external agent here, or use the Create button on a machine for a Lore-managed worker.</p>"#.to_string()
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
                let (status_class, status_title, status_icon) =
                    chat_status_indicator(&agent.status);
                let machine_controls = if agent.machine_name.is_some() && agent.process_status.is_some() {
                    let mname = agent.machine_name.as_deref().unwrap_or("");
                    let is_running = agent.process_status.as_deref() == Some("running");
                    let stop_btn = if is_running {
                        format!(
                            r#"<button type="button" class="btn-sm button-link" onclick="event.preventDefault(); event.stopPropagation(); agentCommand('stop', '{}', '{}')" title="Stop">{}</button>"#,
                            escape_attribute(&agent.name),
                            escape_attribute(mname),
                            ICON_STOP,
                        )
                    } else { String::new() };
                    let restart_btn = format!(
                        r#"<button type="button" class="btn-sm button-link" onclick="event.preventDefault(); event.stopPropagation(); agentCommand('restart', '{}', '{}')" title="Restart">{}</button>"#,
                        escape_attribute(&agent.name),
                        escape_attribute(mname),
                        ICON_RESTART,
                    );
                    format!(r#"<span class="sel-item-actions">{stop_btn}{restart_btn}</span>"#)
                } else {
                    String::new()
                };
                let token_kind = if agent.machine_name.is_some() {
                    "machine agent"
                } else if agent.endpoint_id.is_some() {
                    "API agent"
                } else {
                    "external agent"
                };
                format!(
                    r#"<a href="/ui/agents?selected={}" class="sel-item{}">
                      <div style="display:flex; align-items:center; gap:var(--s-2); min-width:0;">
                        <span class="chat-status-glyph {status_class}" title="{status_title}">{status_icon}</span>
                        <div style="min-width:0;">
                          <span class="sel-item-name">{}</span>
                          <span class="sel-item-meta">{} &middot; {}</span>
                        </div>
                      </div>
                      {machine_controls}
                    </a>"#,
                    escape_attribute(&agent.name),
                    cls,
                    escape_text(&agent.display_name),
                    escape_text(&grant_label),
                    escape_text(token_kind),
                    status_class = status_class,
                    status_title = status_title,
                    status_icon = status_icon,
                    machine_controls = machine_controls,
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let external_grants_html = if user_projects.is_empty() {
        "<p class=\"hint\" style=\"margin-top:var(--s-3);\">No projects available yet.</p>"
            .to_string()
    } else {
        let rows = user_projects
            .iter()
            .map(|p| {
                let rw_option = if p.max_permission.allows_write() {
                    r#"<option value="read_write">Read/write</option>"#
                } else {
                    ""
                };
                format!(
                    r#"<div class="grant-row" data-external-project-grant="{}">
                      <span class="grant-project-name">{}</span>
                      <select>
                        <option value="" selected>No access</option>
                        <option value="read">Read</option>
                        {rw_option}
                      </select>
                    </div>"#,
                    escape_attribute(&p.slug),
                    escape_text(&p.display_name),
                )
            })
            .collect::<Vec<_>>();
        format!(
            r#"<fieldset class="grant-fieldset"><legend>Project access</legend>{}</fieldset>"#,
            rows.join("")
        )
    };

    // Machines list
    let server_version = env!("CARGO_PKG_VERSION");
    let machines_html = if machines.is_empty() {
        r#"<p class="hint padded">No machines registered.</p>"#.to_string()
    } else {
        machines
            .iter()
            .map(|m| {
                let create_grants_html = if user_projects.is_empty() {
                    "<p class=\"hint\" style=\"margin-top:var(--s-3);\">No projects available yet.</p>".to_string()
                } else {
                    let rows = user_projects
                        .iter()
                        .map(|p| {
                            let rw_option = if p.max_permission.allows_write() {
                                r#"<option value="read_write">Read/write</option>"#
                            } else {
                                ""
                            };
                            format!(
                                r#"<div class="grant-row" data-create-project-grant="{}">
                                  <span class="grant-project-name">{}</span>
                                  <select>
                                    <option value="" selected>No access</option>
                                    <option value="read">Read</option>
                                    {rw_option}
                                  </select>
                                </div>"#,
                                escape_attribute(&p.slug),
                                escape_text(&p.display_name),
                            )
                        })
                        .collect::<Vec<_>>();
                    format!(
                        r#"<fieldset class="grant-fieldset create-agent-grants"><legend>Project access</legend>{}</fieldset>"#,
                        rows.join("")
                    )
                };
                let version_display = m.cli_version.as_deref().unwrap_or("unknown");
                let is_outdated = m.cli_version.as_deref().map(|v| v.trim_start_matches('v') != server_version).unwrap_or(true);
                let update_btn = if is_outdated && !m.pending_update {
                    format!(
                        r#"<button type="button" onclick="updateMachine(this, '{}')" data-csrf="{}" style="font-size:0.8rem; padding:var(--s-1) var(--s-2);">Update</button>"#,
                        escape_attribute(&m.name),
                        escape_attribute(csrf_token),
                    )
                } else if m.pending_update {
                    format!(
                        r#"<button type="button" disabled data-machine-update="{}" data-csrf="{}" style="font-size:0.8rem; padding:var(--s-1) var(--s-2);">Updating&hellip;</button>"#,
                        escape_attribute(&m.name),
                        escape_attribute(csrf_token),
                    )
                } else {
                    String::new()
                };
                let version_class = if is_outdated { r#" style="color:var(--danger)""# } else { "" };
                format!(
                    r#"<div class="machine-item" data-machine="{name_attr}">
                      <div class="sel-item" style="display:flex; justify-content:space-between; align-items:center; gap:var(--s-2);">
                        <div style="min-width:0;">
                          <span class="sel-item-name">{name}</span>
                          <span class="sel-item-meta"{version_class}>v{version}</span>
                        </div>
                        <div style="display:flex; gap:var(--s-2); align-items:center; flex-shrink:0;">
                          {update_btn}
                          <button type="button" onclick="toggleCreateAgent(this, '{name_attr}')" data-csrf="{csrf}" style="font-size:0.8rem; padding:var(--s-1) var(--s-2);">Create</button>
                          <form method="post" action="/ui/agents/machines/{name_attr}/revoke" class="inline-form" style="margin:0;">
                            <input type="hidden" name="csrf_token" value="{csrf}">
                            <button class="danger" type="submit" style="font-size:0.8rem; padding:var(--s-1) var(--s-2);">Revoke</button>
                          </form>
                        </div>
                      </div>
                      <div class="create-agent-panel" id="create-panel-{name_attr}" style="display:none; padding:var(--s-3); border-top:1px solid var(--line);">
                        <div style="display:flex; gap:var(--s-3); flex-wrap:wrap; align-items:end;">
                          <label style="flex:1; min-width:150px;">
                            <span style="font-size:0.8rem; color:var(--fg-2);">Agent name</span>
                            <input type="text" id="create-name-{name_attr}" placeholder="my-agent" style="width:100%; margin-top:var(--s-1);">
                          </label>
                          <div style="display:flex; flex-direction:column; gap:var(--s-1);">
                            <span style="font-size:0.8rem; color:var(--fg-2);">Backend</span>
                            <div class="create-agent-backend-row">
                              <select id="create-backend-{name_attr}">
                                <option value="claude">Claude</option>
                                <option value="agy">Antigravity</option>
                                <option value="codex">Codex</option>
                              </select>
                              <button type="button" class="btn-sm create-folder-toggle" onclick="toggleMkdir('{name_attr}')" title="Create folder" aria-label="Create folder">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                  <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                                  <path d="M12 11v6"/>
                                  <path d="M9 14h6"/>
                                </svg>
                              </button>
                            </div>
                          </div>
                        </div>
                        <div id="create-mkdir-row-{name_attr}" style="display:none; margin-top:var(--s-3);">
                          <div style="display:flex; gap:var(--s-2); align-items:center;">
                            <input type="text" id="create-mkdir-name-{name_attr}" placeholder="new-folder" style="flex:1; min-width:0;">
                            <button type="button" onclick="createFolder('{name_attr}')" style="font-size:0.8rem; padding:var(--s-1) var(--s-3);">Create</button>
                          </div>
                          <div id="create-mkdir-status-{name_attr}" class="hint" style="margin-top:var(--s-1); font-size:0.8rem;"></div>
                        </div>
                        <div style="margin-top:var(--s-3);">
                          <span style="font-size:0.8rem; color:var(--fg-2);">Agent folder</span>
                          <div id="create-folder-{name_attr}" class="folder-browser" style="margin-top:var(--s-1); border:1px solid var(--line); border-radius:var(--radius); max-height:240px; overflow-y:auto;">
                            <div class="folder-loading hint" style="padding:var(--s-2);">Loading...</div>
                          </div>
                          <div style="margin-top:var(--s-2); display:flex; flex-direction:column; gap:var(--s-1);">
                            <span style="font-size:0.75rem; color:var(--fg-2);">The folder shown above is the folder this agent will use.</span>
                            <div id="create-path-display-{name_attr}" style="font-size:0.85rem; font-family:var(--font-mono); word-break:break-all;"></div>
                            <input type="hidden" id="create-path-{name_attr}">
                            <input type="hidden" id="create-home-{name_attr}">
                          </div>
                        </div>
                        <div style="margin-top:var(--s-3);">
                          {create_grants_html}
                        </div>
                        <div style="margin-top:var(--s-3); display:flex; gap:var(--s-2);">
                          <button type="button" class="btn-lg" onclick="submitCreateAgent('{name_attr}')">Create Agent</button>
                          <span id="create-status-{name_attr}" class="hint" style="font-size:0.8rem; align-self:center;"></span>
                        </div>
                      </div>
                    </div>"#,
                    name = escape_text(&m.name),
                    version = escape_text(version_display),
                    version_class = version_class,
                    update_btn = update_btn,
                    name_attr = escape_attribute(&m.name),
                    csrf = escape_attribute(csrf_token),
                    create_grants_html = create_grants_html,
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    // Selected agent detail
    let detail_html = if let Some(sel_name) = selected_agent {
        if let Some(agent) = agents.iter().find(|a| a.name == sel_name) {
            let setup_token = created_token.unwrap_or("YOUR_TOKEN");
            let is_external_agent = agent.machine_name.is_none() && agent.endpoint_id.is_none();
            let setup_instruction = build_agent_setup_instruction_text(
                &base_url,
                &mcp_url,
                &install_script_url,
                &install_ps1_url,
                setup_token,
                server_version,
            );
            let mcp_config_text = format!(
                r#"{{"transport": "streamable_http","url": "{}","headers": {{"Authorization": "Bearer {}","Accept": "application/json, text/event-stream","MCP-Protocol-Version": "2025-06-18"}}}}"#,
                escape_text(&mcp_url),
                escape_text(setup_token),
            );
            let created_token_html = created_token.map(|token| {
                format!(
                    r##"<div class="padded" style="border:1px solid var(--line); border-radius:var(--radius); margin-bottom:var(--s-4);">
                  <div class="hint" style="margin-bottom:var(--s-2);">Copy this token now. Lore only shows it once.</div>
                  <textarea readonly id="created-token" style="min-height:4rem; font-family:var(--font-mono); font-size:0.85rem;">{}</textarea>
                  <div style="margin-top:var(--s-3); text-align:right;">
                    <button type="button" class="btn-lg button-link" onclick="copyField('created-token')">Copy token</button>
                  </div>
                </div>"##,
                    escape_text(token),
                )
            }).unwrap_or_default();
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

            let backend_section_html = if is_external_agent {
                r#"<div class="panel-header"><h3>Runtime</h3><p>External agents use this token from their own machine and do not appear in chat.</p></div>"#.to_string()
            } else {
                let cli_backends = [
                    ("claude", "Claude"),
                    ("agy", "Antigravity"),
                    ("codex", "Codex"),
                ];
                let mut cli_opts = String::new();
                for (b, label) in &cli_backends {
                    let sel = if agent.endpoint_id.is_none() && agent.backend.to_string() == *b {
                        " selected"
                    } else {
                        ""
                    };
                    cli_opts.push_str(&format!(r#"<option value="cli:{b}"{sel}>{label}</option>"#));
                }
                let mut ep_opts = String::new();
                for ep in endpoints {
                    let sel = if agent.endpoint_id.as_deref() == Some(&ep.id) {
                        " selected"
                    } else {
                        ""
                    };
                    ep_opts.push_str(&format!(
                        r#"<option value="ep:{}"{}>{} ({})</option>"#,
                        escape_attribute(&ep.id),
                        sel,
                        escape_text(&ep.name),
                        escape_text(&ep.model),
                    ));
                }
                let ep_group = if !ep_opts.is_empty() {
                    format!(r#"<optgroup label="Endpoints">{ep_opts}</optgroup>"#)
                } else {
                    String::new()
                };
                let backend_options =
                    format!(r#"<optgroup label="CLI">{cli_opts}</optgroup>{ep_group}"#);
                format!(
                    r#"<div class="panel-header"><h3>Backend</h3><p>Choose a CLI backend or a configured endpoint.</p></div>
                <div class="padded">
                  <select id="agent-backend-select" style="width:100%;" onchange="saveAgentBackend('{name_attr}')">{backend_options}</select>
                </div>"#,
                    name_attr = escape_attribute(&agent.name),
                    backend_options = backend_options,
                )
            };

            format!(
                r##"<section class="panel" style="margin-top: var(--s-5);">
                <div class="panel-header"><h2>{display_name}</h2><p>{owner}-{slug}</p></div>

                {created_token_html}

                <div class="panel-header"><h3>Permissions</h3></div>
                <form method="post" action="/ui/agents/{name_attr}/grants" id="edit-grants-form">
                  <input type="hidden" name="csrf_token" value="{csrf_token}">
                  {edit_grants_html}
                  <textarea name="grants" style="display:none" id="edit-grants-field"></textarea>
                  <button type="submit" class="btn-lg">Save</button>
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

                {backend_section_html}

                <div class="panel-header"><h3>Setup instructions</h3><p>Copy and give to your agent.</p></div>
                <div class="padded">
                  <textarea readonly id="agent-instruction" style="min-height: 8rem; font-family: var(--font-mono); font-size: 0.85rem;">{setup_instruction}</textarea>
                  <div style="margin-top: var(--s-3); text-align: right;">
                    <form method="post" action="/ui/agents/{name_attr}/rotate" class="inline-form" style="margin-right:var(--s-2);">
                      <input type="hidden" name="csrf_token" value="{csrf_token}">
                      <button type="submit" class="btn-lg">Regenerate token</button>
                    </form>
                    <button type="button" class="btn-lg button-link" onclick="copyField('agent-instruction')">Copy setup</button>
                  </div>
                </div>

                <div class="panel-header"><h3>MCP config</h3></div>
                <div class="padded">
                  <textarea readonly id="mcp-config" style="min-height:8rem; font-family:var(--font-mono); font-size:0.85rem;">{mcp_config_text}</textarea>
                  <div style="margin-top: var(--s-2); text-align: right;">
                    <button type="button" class="btn-lg button-link" onclick="copyField('mcp-config')">Copy MCP config</button>
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
                name_attr = escape_attribute(&agent.name),
                csrf_token = escape_attribute(csrf_token),
                edit_grants_html = edit_grants_html,
                backend_section_html = backend_section_html,
                setup_instruction = escape_text(&setup_instruction),
                mcp_config_text = escape_text(&mcp_config_text),
                created_token_html = created_token_html,
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
      <div class="sel-list">{machines_html}</div>
    </section>

    <section class="panel" style="margin-top: var(--s-5);">
      <div class="panel-header">
        <h2>Agents</h2>
        <p>Machine and API agents appear in chat. External agents use Lore from their own CLI and only receive scoped project access.</p>
      </div>
      <form method="post" action="/ui/agents/external-agent" id="create-external-agent-form" style="margin-bottom:var(--s-4);">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <label>
          <span style="font-size:0.8rem; color:var(--fg-2);">External agent name</span>
          <input type="text" name="token_name" placeholder="codex-laptop" style="width:100%; margin-top:var(--s-1);">
        </label>
        <div style="margin-top:var(--s-3);">{external_grants_html}</div>
        <textarea name="grants" id="external-grants-field" style="display:none"></textarea>
        <button type="submit" class="btn-lg" style="margin-top:var(--s-3);">Create External Agent</button>
      </form>
      <div class="sel-list">{agent_list_html}</div>
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

    var externalAgentForm = document.getElementById('create-external-agent-form');
    if (externalAgentForm) {{
      externalAgentForm.addEventListener('submit', function() {{
        var lines = [];
        externalAgentForm.querySelectorAll('[data-external-project-grant]').forEach(function(row) {{
          var sel = row.querySelector('select');
          if (sel && sel.value) {{
            lines.push(row.getAttribute('data-external-project-grant') + ':' + sel.value);
          }}
        }});
        var field = document.getElementById('external-grants-field');
        if (field) field.value = lines.join('\n');
      }});
    }}

    function saveAgentBackend(agentName) {{
      var sel = document.getElementById('agent-backend-select');
      if (!sel) return;
      var val = sel.value;
      var csrf = document.querySelector('input[name="csrf_token"]');
      var body;
      if (val.indexOf('ep:') === 0) {{
        body = 'csrf_token=' + encodeURIComponent(csrf ? csrf.value : '')
          + '&endpoint_id=' + encodeURIComponent(val.substring(3));
      }} else {{
        var cli = val.indexOf('cli:') === 0 ? val.substring(4) : val;
        body = 'csrf_token=' + encodeURIComponent(csrf ? csrf.value : '')
          + '&backend=' + encodeURIComponent(cli)
          + '&endpoint_id=';
      }}
      fetch('/ui/chat/' + encodeURIComponent(agentName) + '/config', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
        body: body
      }});
    }}

    function toggleCreateAgent(btn, machine) {{
      var panel = document.getElementById('create-panel-' + machine);
      if (!panel) return;
      if (panel.style.display === 'none') {{
        panel.style.display = 'block';
        loadFolder(machine, '~');
      }} else {{
        panel.style.display = 'none';
      }}
    }}

    function getCsrf(machine) {{
      var item = document.querySelector('.machine-item[data-machine="' + machine + '"]');
      if (!item) return '';
      var btn = item.querySelector('[data-csrf]');
      return btn ? btn.getAttribute('data-csrf') : '';
    }}

    function setTextStatus(id, text, isError) {{
      var el = document.getElementById(id);
      if (!el) return;
      el.textContent = text || '';
      el.style.color = isError ? 'var(--danger)' : '';
    }}

    function setCreateFolderPath(machine, path) {{
      var pathInput = document.getElementById('create-path-' + machine);
      var pathDisplay = document.getElementById('create-path-display-' + machine);
      if (pathInput) pathInput.value = path || '';
      if (pathDisplay) pathDisplay.textContent = path || '';
    }}

    function toggleMkdir(machine) {{
      var row = document.getElementById('create-mkdir-row-' + machine);
      var input = document.getElementById('create-mkdir-name-' + machine);
      if (!row) return;
      var show = row.style.display === 'none';
      row.style.display = show ? 'block' : 'none';
      if (!show) {{
        setTextStatus('create-mkdir-status-' + machine, '', false);
      }}
      if (show && input) input.focus();
    }}

    function loadFolder(machine, path) {{
      var browser = document.getElementById('create-folder-' + machine);
      var homeInput = document.getElementById('create-home-' + machine);
      if (!browser) return;
      browser.innerHTML = '<div class="hint" style="padding:var(--s-2);">Loading\u2026</div>';
      fetch('/ui/agents/machines/' + encodeURIComponent(machine) + '/list-dir', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ csrf_token: getCsrf(machine), path: path }})
      }}).then(readJsonResponse).then(function(data) {{
        if (data.error) {{
          browser.innerHTML = '<div class="hint" style="padding:var(--s-2); color:var(--danger);">' + escapeHtml(data.error) + '</div>';
          return;
        }}
        var currentPath = data.path || path;
        var homePath = data.home || currentPath;
        setCreateFolderPath(machine, currentPath);
        if (homeInput) homeInput.value = homePath;
        var html = '';
        // Parent directory link
        if (currentPath !== homePath) {{
          var parts = currentPath.replace(/\/+$/, '').split('/');
          parts.pop();
          var parent = parts.join('/') || homePath;
          html += '<div class="folder-entry" onclick="loadFolder(\'' + machine + '\', \'' + escapeAttr(parent) + '\')" style="padding:var(--s-1) var(--s-2); cursor:pointer; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:var(--s-2);">';
          html += '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>';
          html += '<span style="font-family:var(--font-mono); font-size:0.85rem;">..</span></div>';
        }}
        var entries = data.entries || [];
        for (var i = 0; i < entries.length; i++) {{
          var e = entries[i];
          if (!e.is_dir) continue;
          var fullPath = currentPath === '/' ? '/' + e.name : currentPath + '/' + e.name;
          html += '<div class="folder-entry" onclick="loadFolder(\'' + machine + '\', \'' + escapeAttr(fullPath) + '\')" style="padding:var(--s-1) var(--s-2); cursor:pointer; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:var(--s-2);">';
          html += '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
          html += '<span style="font-family:var(--font-mono); font-size:0.85rem;">' + escapeHtml(e.name) + '</span></div>';
        }}
        if (!html) html = '<div class="hint" style="padding:var(--s-2);">Empty directory</div>';
        browser.innerHTML = html;
      }}).catch(function(err) {{
        browser.innerHTML = '<div class="hint" style="padding:var(--s-2); color:var(--danger);">Failed to list directory</div>';
      }});
    }}

    function escapeHtml(s) {{
      var d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }}

    function escapeAttr(s) {{
      return s.replace(/\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
    }}

    function readJsonResponse(response) {{
      return response.text().then(function(text) {{
        var data = null;
        if (text) {{
          try {{ data = JSON.parse(text); }} catch (err) {{}}
        }}
        if (!data) {{
          return {{ error: text || ('Request failed: HTTP ' + response.status) }};
        }}
        if (!response.ok && !data.error) {{
          data.error = 'Request failed: HTTP ' + response.status;
        }}
        return data;
      }});
    }}

    function createFolder(machine) {{
      var pathInput = document.getElementById('create-path-' + machine);
      var nameInput = document.getElementById('create-mkdir-name-' + machine);
      var statusId = 'create-mkdir-status-' + machine;
      var currentPath = pathInput ? pathInput.value : '';
      var name = nameInput ? nameInput.value.trim() : '';
      if (!name) {{
        setTextStatus(statusId, 'Enter a folder name', true);
        return;
      }}
      if (name.indexOf('/') !== -1 || name.indexOf('\\\\') !== -1 || name === '.' || name === '..') {{
        setTextStatus(statusId, 'Invalid folder name', true);
        return;
      }}
      setTextStatus(statusId, 'Creating\u2026', false);
      fetch('/ui/agents/machines/' + encodeURIComponent(machine) + '/mkdir', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ csrf_token: getCsrf(machine), path: currentPath, name: name }})
      }}).then(readJsonResponse).then(function(data) {{
        if (data.error) {{
          setTextStatus(statusId, data.error, true);
          return;
        }}
        if (nameInput) nameInput.value = '';
        setTextStatus(statusId, '', false);
        loadFolder(machine, data.path || currentPath);
      }}).catch(function(err) {{
        setTextStatus(statusId, 'Failed to create folder', true);
      }});
    }}

    function pollMachineStatus(btn, name, csrf) {{
      fetch('/ui/agents/machines/' + encodeURIComponent(name) + '/status-json', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
        body: 'csrf_token=' + encodeURIComponent(csrf)
      }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
        if (d.up_to_date) {{
          btn.style.display = 'none';
          var verSpan = btn.closest('.sel-item').querySelector('.sel-item-meta');
          if (verSpan) {{
            verSpan.textContent = 'v' + d.version;
            verSpan.style.color = '';
          }}
        }} else if (d.pending_update) {{
          setTimeout(function() {{ pollMachineStatus(btn, name, csrf); }}, 3000);
        }} else {{
          btn.textContent = 'Update';
          btn.disabled = false;
          btn.style.opacity = '';
        }}
      }}).catch(function() {{
        setTimeout(function() {{ pollMachineStatus(btn, name, csrf); }}, 5000);
      }});
    }}

    function updateMachine(btn, name) {{
      var csrf = btn.getAttribute('data-csrf');
      btn.disabled = true;
      btn.textContent = 'Queuing\u2026';
      fetch('/ui/agents/machines/' + encodeURIComponent(name) + '/update-json', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
        body: 'csrf_token=' + encodeURIComponent(csrf)
      }}).then(function(r) {{
        if (!r.ok) throw new Error('server returned ' + r.status);
        return r.json();
      }}).then(function() {{
        btn.textContent = 'Updating\u2026';
        setTimeout(function() {{ pollMachineStatus(btn, name, csrf); }}, 3000);
      }}).catch(function() {{
        btn.textContent = 'Failed';
        btn.disabled = false;
        setTimeout(function() {{ btn.textContent = 'Update'; }}, 3000);
      }});
    }}

    function agentCommand(action, agentName, machine) {{
      var btn = event && event.target && event.target.closest('button');
      if (btn) btn.disabled = true;
      var csrf = getCsrf(machine);
      fetch('/ui/agents/machines/' + encodeURIComponent(machine) + '/' + action + '-agent', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ csrf_token: csrf, agent_name: agentName }})
      }}).then(readJsonResponse).then(function(data) {{
        if (data.error) {{
          alert(data.error);
          if (btn) btn.disabled = false;
        }} else {{
          setTimeout(function() {{ window.location.reload(); }}, 1000);
        }}
      }}).catch(function(err) {{
        alert('Failed: ' + err);
        if (btn) btn.disabled = false;
      }});
    }}

    function submitCreateAgent(machine) {{
      var nameInput = document.getElementById('create-name-' + machine);
      var pathInput = document.getElementById('create-path-' + machine);
      var backendSelect = document.getElementById('create-backend-' + machine);
      var panel = document.getElementById('create-panel-' + machine);
      var statusEl = document.getElementById('create-status-' + machine);
      var agentName = nameInput ? nameInput.value.trim() : '';
      var folder = pathInput ? pathInput.value.trim() : '';
      var backend = backendSelect ? backendSelect.value : 'claude';
      var grants = [];
      if (panel) {{
        var rows = panel.querySelectorAll('[data-create-project-grant]');
        rows.forEach(function(row) {{
          var sel = row.querySelector('select');
          if (sel && sel.value) {{
            grants.push(row.getAttribute('data-create-project-grant') + ':' + sel.value);
          }}
        }});
      }}
      if (!agentName) {{
        if (statusEl) {{ statusEl.textContent = 'Enter an agent name'; statusEl.style.color = 'var(--danger)'; }}
        return;
      }}
      if (!folder) {{
        if (statusEl) {{ statusEl.textContent = 'Select a folder'; statusEl.style.color = 'var(--danger)'; }}
        return;
      }}
      if (statusEl) {{ statusEl.textContent = 'Creating\u2026'; statusEl.style.color = ''; }}
      fetch('/ui/agents/machines/' + encodeURIComponent(machine) + '/create-agent', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{
          csrf_token: getCsrf(machine),
          agent_name: agentName,
          folder: folder,
          backend: backend,
          grants: grants.join('\n')
        }})
      }}).then(readJsonResponse).then(function(data) {{
        if (data.error) {{
          if (statusEl) {{ statusEl.textContent = data.error; statusEl.style.color = 'var(--danger)'; }}
        }} else {{
          if (statusEl) {{ statusEl.textContent = 'Agent created!'; statusEl.style.color = 'var(--success, green)'; }}
          setTimeout(function() {{ window.location.reload(); }}, 1500);
        }}
      }}).catch(function(err) {{
        if (statusEl) {{ statusEl.textContent = 'Failed to create agent'; statusEl.style.color = 'var(--danger)'; }}
      }});
    }}

    document.querySelectorAll('[data-machine-update]').forEach(function(btn) {{
      var name = btn.getAttribute('data-machine-update');
      var csrf = btn.getAttribute('data-csrf');
      pollMachineStatus(btn, name, csrf);
    }});

    </script>"##,
        agent_list_html = agent_list_html,
        machines_html = machines_html,
        detail_html = detail_html,
        csrf_token = escape_attribute(csrf_token),
        external_grants_html = external_grants_html,
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
    server_version: &str,
) -> String {
    format!(
        r#"# Lore - shared project knowledge base

Lore is a structured knowledge base your team uses to store and retrieve project documentation, decisions, and context. You can read and write project documents made up of ordered blocks.

## Server

Base URL: {base_url}
MCP endpoint: {mcp_url}

## Authentication

All requests require an agent token. Include it as:
  Authorization: Bearer {token}

## How to connect

### Option 1 - Lore CLI (recommended for code agents)

Install (Linux/macOS):
  LORE_VERSION=v{server_version} curl -fsSL {install_script_url} | sh

Install (Windows PowerShell):
  $env:LORE_VERSION='v{server_version}'; irm {install_ps1_url} | iex

Configure this machine for the external agent. This does not register a machine or start a Lore-managed agent service:
  lore setup-external {base_url} --token {token}

Set the project for the current repo:
  lore project set-local <project-slug>

Commands:
  lore projects                     - list projects
  lore overview                     - read the current project overview
  lore file-map read                - read the current project file map
  lore context                      - read agent context
  lore docs list                    - list documents
  lore docs read <doc-id>           - read a document
  lore blocks list --doc <doc-id>   - list document blocks
  lore grep "query"                 - search blocks
  lore librarian answer "question"  - ask the librarian

### Option 2 - MCP (for MCP-native hosts)

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

Available MCP tools: list_projects, list_documents, list_blocks, read_block, read_blocks_around, grep_blocks, create_block, update_block, edit_block, move_block, delete_block, create_document, rename_document, delete_document.

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
    <section class="panel" style="margin-top:var(--s-6);">
      <div class="panel-header">
        <h2>Account</h2>
      </div>
      <div class="padded meta-stack">
        <p><strong>Signed in as</strong><br>{signed_in_username}</p>
        <form method="post" action="/ui/settings/password">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <label>
            Current password
            <input type="password" name="current_password" autocomplete="current-password" required>
          </label>
          <label>
            New password
            <input type="password" name="password" autocomplete="new-password" required>
          </label>
          <label>
            Confirm new password
            <input type="password" name="confirm_password" autocomplete="new-password" required>
          </label>
          <button type="submit" class="btn-lg">Change password</button>
        </form>
        <form method="post" action="/logout" style="margin-top:var(--s-5);">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <button type="submit" class="btn-lg" style="background:var(--danger, #c53030); color:#fff;">Sign out</button>
        </form>
      </div>
    </section>
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
        current_mode_value =
            escape_attribute(selected_color_mode.map(|m| m.as_str()).unwrap_or("system")),
        preference_label = escape_text(preference_label),
        mode_label = escape_text(mode_label),
        server_default_label = escape_text(server_default_theme.display_name()),
        signed_in_username = escape_text(username),
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
    pub manage_enabled: bool,
    pub last_message: Option<String>,
    pub last_message_time: Option<String>,
    pub profile_url: Option<String>,
    pub cwd: Option<String>,
    pub git_branch: Option<String>,
}

fn chat_folder_name(cwd: &str) -> String {
    cwd.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or("")
        .to_string()
}

fn chat_agent_status_indicator(
    status: &str,
    manage_enabled: bool,
) -> (&'static str, &'static str, &'static str) {
    let (status_class, status_title, status_icon) = chat_status_indicator(status);
    if manage_enabled && status == "thinking" {
        (status_class, status_title, ICON_MANAGER)
    } else {
        (status_class, status_title, status_icon)
    }
}

fn render_expanded_text_editor_shell() -> String {
    format!(
        r#"<div class="expanded-editor-overlay" id="expanded-text-editor" style="display:none;">
  <div class="expanded-editor-shell">
    <div class="expanded-editor-header">
      <div class="expanded-editor-kicker">Editing</div>
      <h2 class="expanded-editor-title" id="expanded-editor-title">Edit</h2>
    </div>
    <textarea id="expanded-editor-input" class="expanded-editor-input" spellcheck="false"></textarea>
    <div class="expanded-editor-footer">
      <div class="expanded-editor-actions expanded-editor-actions-desktop">
        <button type="button" class="btn-lg" onclick="return cancelExpandedTextEditor()">Cancel</button>
        <button type="button" class="btn-lg button-link" onclick="return saveExpandedTextEditor()">Save</button>
      </div>
      <div class="expanded-editor-actions expanded-editor-actions-mobile">
        <button type="button" class="btn-sm" onclick="return cancelExpandedTextEditor()" title="Cancel">{close_icon}</button>
        <button type="button" class="btn-sm button-link" onclick="return saveExpandedTextEditor()" title="Save">{check_icon}</button>
      </div>
    </div>
  </div>
</div>"#,
        close_icon = ICON_CLOSE,
        check_icon = ICON_CHECK,
    )
}

pub fn render_chat_main_panel(
    agents: &[ChatAgentSummary],
    selected_agent: Option<&str>,
    csrf_token: &str,
    projects: &[(String, String)],
) -> String {
    let is_librarian = selected_agent == Some("librarian");

    if is_librarian {
        let project_options: String = projects
            .iter()
            .map(|(slug, display_name)| {
                format!(
                    r#"<option value="{}">{}</option>"#,
                    escape_attribute(slug),
                    escape_text(display_name),
                )
            })
            .collect::<Vec<_>>()
            .join("");
        return format!(
            r#"<div class="chat-header">
  <button class="chat-back-btn" onclick="showAgentList()">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
  </button>
  <span class="chat-header-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20"/></svg></span>
  <span class="chat-header-name">Librarian</span>
  <select id="lib-project" class="chat-config-select" style="margin-left:var(--s-3);max-width:200px;" onchange="onLibProjectChange()">
    <option value="">All Projects</option>
    {project_options}
  </select>
  <button type="button" class="btn-sm button-link lib-toggle" id="lib-toggle-history" style="margin-left:auto;" onclick="toggleLibOption('history')" title="Include history"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></button>
  <button type="button" class="btn-sm button-link lib-toggle" id="lib-toggle-edits" style="margin-left:var(--s-1);" onclick="toggleLibOption('edits')" title="Allow edits"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
</div>
<div class="chat-messages-wrap" id="chat-messages-wrap">
  <div class="chat-messages" id="chat-messages"></div>
  <button type="button" class="btn-lg chat-jump-btn" id="chat-jump-btn" onclick="return jumpToChatLatest()">Jump to end</button>
</div>
<form class="chat-input-form" id="chat-input-form" onsubmit="return sendLibrarianMessage(event)">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <textarea class="chat-input" id="chat-input" placeholder="Ask the librarian..." rows="1" onkeydown="return handleChatKey(event)"></textarea>
  <button type="submit" class="chat-send-btn">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
  </button>
</form>"#,
            csrf_token = escape_attribute(csrf_token),
            project_options = project_options,
        );
    }

    if let Some(agent_name) = selected_agent {
        let selected_agent_data = agents.iter().find(|a| a.name == agent_name);
        let display = selected_agent_data
            .map(|a| a.display_name.as_str())
            .unwrap_or(agent_name);
        let header_avatar = selected_agent_data
            .and_then(|a| a.profile_url.as_ref())
            .map(|url| {
                format!(
                    r#"<img class="chat-avatar-header" src="{}" alt="">"#,
                    escape_attribute(url)
                )
            })
            .unwrap_or_default();
        let metadata_html = {
            let folder = selected_agent_data
                .and_then(|a| a.cwd.as_ref())
                .map(|cwd| chat_folder_name(cwd))
                .unwrap_or_default();
            format!(
                r#"<span class="chat-header-cwd" id="chat-agent-cwd" data-folder="{}">{}</span>"#,
                escape_attribute(&folder),
                escape_text(&folder)
            )
        };
        return format!(
            r#"<div class="chat-header">
  <button class="chat-back-btn" onclick="showAgentList()">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
  </button>
  {header_avatar}<span class="chat-header-name">{display_name}</span>
  {metadata_html}
  <div class="chat-header-actions">
    <span class="chat-header-status" id="chat-agent-status"></span>
    <button type="button" class="btn-sm button-link" id="chat-manage-btn" onclick="toggleManagePanel()" title="Manage">{ICON_MANAGER}</button>
    <button type="button" class="btn-sm button-link" id="chat-config-btn" onclick="toggleChatConfig()" title="Configure">{settings_icon}</button>
  </div>
</div>
<div class="chat-messages-wrap" id="chat-messages-wrap">
  <div class="chat-messages" id="chat-messages"></div>
  <button type="button" class="btn-lg chat-jump-btn" id="chat-jump-btn" onclick="return jumpToChatLatest()">Jump to end</button>
</div>
<div class="chat-config-panel" id="chat-config-panel" style="display:none;">
  <div class="chat-config-inner">
    <div class="chat-config-field">
      <label class="chat-config-label">Backend</label>
      <select id="cfg-backend" class="chat-config-select" onchange="onBackendChange()"></select>
    </div>
    <div class="chat-config-field">
      <label class="chat-config-label">Model</label>
      <select id="cfg-model" class="chat-config-select" onchange="onConfigChange()"></select>
    </div>
    <div class="chat-config-field" id="cfg-effort-field">
      <label class="chat-config-label">Effort</label>
      <select id="cfg-effort" class="chat-config-select" onchange="onConfigChange()"></select>
    </div>
    <div class="chat-config-field chat-config-field-wide">
      <label class="chat-config-label" for="cfg-pinned-context">Pinned Context</label>
      <textarea id="cfg-pinned-context" class="chat-config-textarea expanded-editor-source" data-editor-label="Pinned Context" data-editor-save="pinned" placeholder="Context sent with every message to this agent..." readonly onclick="return openExpandedTextEditor('cfg-pinned-context')"></textarea>
    </div>
    <div class="chat-config-field chat-config-field-wide" id="cfg-project-context-field" style="display:none;">
      <label class="chat-config-label">Project Context</label>
      <textarea id="cfg-project-context" class="chat-config-textarea" readonly placeholder="No project context set."></textarea>
    </div>
    <div class="chat-config-field chat-config-field-wide" id="cfg-errors-field">
      <label class="chat-config-label">Error Log <span id="cfg-errors-count" style="color:var(--fg-muted);font-weight:normal;"></span></label>
      <div id="cfg-errors-list" class="chat-errors-list"></div>
    </div>
  </div>
</div>
<div class="chat-config-panel" id="chat-manage-panel" style="display:none;">
  <div class="chat-config-inner">
    <div class="chat-config-field">
      <button type="button" class="btn-lg" id="mgr-toggle" onclick="toggleManageMode()">Enable</button>
      <span id="mgr-status" style="margin-left:var(--s-2);font-size:0.85em;color:var(--fg-muted);"></span>
    </div>
    <div class="chat-config-field">
      <label class="chat-config-label">Manager Backend</label>
      <select id="mgr-backend" class="chat-config-select" onchange="onManageChange()"></select>
    </div>
    <div class="chat-config-field chat-config-field-wide">
      <label class="chat-config-label" for="mgr-goals">Goals</label>
      <textarea id="mgr-goals" class="chat-config-textarea expanded-editor-source" data-editor-label="Goals" data-editor-save="manage" placeholder="What should the agent accomplish?" readonly onclick="return openExpandedTextEditor('mgr-goals')"></textarea>
    </div>
    <div class="chat-config-field chat-config-field-wide">
      <label class="chat-config-label" for="mgr-stopping">Stopping Point</label>
      <textarea id="mgr-stopping" class="chat-config-textarea expanded-editor-source" data-editor-label="Stopping Point" data-editor-save="manage" placeholder="When should the manager stop the agent?" readonly onclick="return openExpandedTextEditor('mgr-stopping')"></textarea>
    </div>
    <div class="chat-config-field chat-config-field-wide">
      <label class="chat-config-label" for="mgr-checks">Periodic Checks</label>
      <textarea id="mgr-checks" class="chat-config-textarea expanded-editor-source" data-editor-label="Periodic Checks" data-editor-save="manage" placeholder="What should the agent verify every few turns?" readonly onclick="return openExpandedTextEditor('mgr-checks')"></textarea>
    </div>
    <div class="chat-config-field chat-config-field-wide">
      <label class="chat-config-label" for="mgr-redflags">Red Flags</label>
      <textarea id="mgr-redflags" class="chat-config-textarea expanded-editor-source" data-editor-label="Red Flags" data-editor-save="manage" placeholder="What should cause the manager to halt the agent?" readonly onclick="return openExpandedTextEditor('mgr-redflags')"></textarea>
    </div>
  </div>
</div>
<form class="chat-input-form" id="chat-input-form" onsubmit="return sendMessage(event)">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <textarea class="chat-input" id="chat-input" placeholder="Type a message..." rows="1" onkeydown="return handleChatKey(event)"></textarea>
  <button type="submit" class="chat-send-btn">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
  </button>
</form>
<div class="expanded-editor-overlay" id="expanded-text-editor" style="display:none;">
  <div class="expanded-editor-shell">
    <div class="expanded-editor-header">
      <div class="expanded-editor-kicker">Editing</div>
      <h2 class="expanded-editor-title" id="expanded-editor-title">Edit</h2>
    </div>
    <textarea id="expanded-editor-input" class="expanded-editor-input" spellcheck="false"></textarea>
    <div class="expanded-editor-footer">
      <div class="expanded-editor-actions expanded-editor-actions-desktop">
        <button type="button" class="btn-lg" onclick="return cancelExpandedTextEditor()">Cancel</button>
        <button type="button" class="btn-lg button-link" onclick="return saveExpandedTextEditor()">Save</button>
      </div>
      <div class="expanded-editor-actions expanded-editor-actions-mobile">
        <button type="button" class="btn-sm" onclick="return cancelExpandedTextEditor()" title="Cancel">{close_icon}</button>
        <button type="button" class="btn-sm button-link" onclick="return saveExpandedTextEditor()" title="Save">{check_icon}</button>
      </div>
    </div>
  </div>
</div>
"#,
            header_avatar = header_avatar,
            display_name = escape_text(display),
            metadata_html = metadata_html,
            settings_icon = ICON_SETTINGS,
            close_icon = ICON_CLOSE,
            check_icon = ICON_CHECK,
            csrf_token = escape_attribute(csrf_token),
        );
    }

    r#"<div class="chat-empty">
  <div class="chat-empty-text">Select an agent to start chatting</div>
</div>"#
        .to_string()
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
    let install_script_url = format!("{}/install-cli.sh", base_url.trim_end_matches('/'));
    let install_ps1_url = format!("{}/install-cli.ps1", base_url.trim_end_matches('/'));

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
          <code style="flex:1; min-width:0; padding:var(--s-2) var(--s-3); background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); font-size:0.85rem; overflow-x:auto; white-space:nowrap; display:flex; align-items:center;">LORE_VERSION=v{server_version} curl -fsSL {install_script_url} | sh</code>
          <button class="button-link" onclick="navigator.clipboard.writeText('LORE_VERSION=v{server_version} curl -fsSL {install_script_url} | sh')" title="Copy" style="aspect-ratio:1; width:auto; padding:0; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
        <p class="hint" style="margin-top:var(--s-4); margin-bottom:var(--s-2);"><strong>Windows</strong> (PowerShell)</p>
        <div style="display:flex; align-items:stretch; gap:var(--s-2);">
          <code style="flex:1; min-width:0; padding:var(--s-2) var(--s-3); background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); font-size:0.85rem; overflow-x:auto; white-space:nowrap; display:flex; align-items:center;">$env:LORE_VERSION='v{server_version}'; irm {install_ps1_url} | iex</code>
          <button class="button-link" onclick="navigator.clipboard.writeText(&quot;$env:LORE_VERSION=&apos;v{server_version}&apos;; irm {install_ps1_url} | iex&quot;)" title="Copy" style="aspect-ratio:1; width:auto; padding:0; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
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
          <code style="flex:1; min-width:0; padding:var(--s-2) var(--s-3); background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); font-size:0.85rem; overflow-x:auto; white-space:nowrap; display:flex; align-items:center;">lore setup-machine {base_url}</code>
          <button class="button-link" onclick="navigator.clipboard.writeText('lore setup-machine {base_url}')" title="Copy" style="aspect-ratio:1; width:auto; padding:0; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
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
        <p class="hint" style="margin-top:var(--s-2);">Options: <code>--backend agy</code> or <code>--backend codex</code> to use a different backend (default is Claude).</p>
      </div>
    </section>

    <section class="panel" style="margin-top: var(--s-5);">
      <div class="panel-header">
        <h2>Optional: Start the machine service</h2>
        <p>The machine service lets you create and manage agents remotely from the Lore web UI.</p>
      </div>
      <div class="padded">
        <div style="display:flex; align-items:stretch; gap:var(--s-2);">
          <code style="flex:1; min-width:0; padding:var(--s-2) var(--s-3); background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); font-size:0.85rem; overflow-x:auto; white-space:nowrap; display:flex; align-items:center;">lore service</code>
          <button class="button-link" onclick="navigator.clipboard.writeText('lore service')" title="Copy" style="aspect-ratio:1; width:auto; padding:0; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
        <p class="hint" style="margin-top:var(--s-3);">Once running, use the Create button next to machines on the Agents tab to create agents remotely and browse folders on the machine.</p>
        <p class="hint" style="margin-top:var(--s-2);">Use <code>--fg</code> to run in the foreground instead of daemonizing.</p>
      </div>
    </section>

    <p style="margin-top:var(--s-5);"><a href="/ui/agents">&larr; Back to Agents</a></p>"#,
        install_script_url = escape_attribute(&install_script_url),
        install_ps1_url = escape_attribute(&install_ps1_url),
        base_url = escape_text(&base_url),
        server_version = env!("CARGO_PKG_VERSION"),
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
    active_turn_user_id: u64,
    flash: Option<&str>,
    projects: &[(String, String)],
) -> String {
    let agent_list_html = render_chat_agent_list(agents, selected_agent);
    let selected_agent_status_js = selected_agent
        .and_then(|name| agents.iter().find(|agent| agent.name == name))
        .map(|agent| format!("'{}'", escape_attribute(&agent.status)))
        .unwrap_or_else(|| "''".to_string());
    let chat_area_html = render_chat_main_panel(agents, selected_agent, csrf_token, projects);
    let selected_agent_js = selected_agent
        .map(|a| format!("'{}'", escape_attribute(a)))
        .unwrap_or_else(|| "null".to_string());
    let profile_url_js = selected_agent
        .and_then(|name| agents.iter().find(|a| a.name == name))
        .and_then(|a| a.profile_url.as_ref())
        .map(|url| format!("'{}'", escape_attribute(url)))
        .unwrap_or_else(|| "null".to_string());
    render_chat_page_with_agent_list_html(
        theme,
        color_mode,
        username,
        csrf_token,
        is_admin,
        &agent_list_html,
        selected_agent.is_some(),
        selected_agent_js,
        selected_agent_status_js,
        messages_json,
        profile_url_js,
        active_turn_user_id,
        flash,
        chat_area_html,
    )
}

pub fn render_chat_agent_list(agents: &[ChatAgentSummary], selected_agent: Option<&str>) -> String {
    let is_librarian = selected_agent == Some("librarian");
    let librarian_active_class = if is_librarian {
        " chat-agent-active"
    } else {
        ""
    };
    let (librarian_status_class, librarian_status_title, librarian_status_icon) =
        chat_agent_status_indicator("idle", false);
    let librarian_entry = format!(
        r#"<div class="chat-agent-item{active_class}" data-agent="librarian" onclick="selectAgent('librarian')">
  <div class="chat-agent-header">
    <div class="chat-avatar-sm-wrap chat-avatar-empty chat-avatar-librarian"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20"/></svg></div>
    <span class="chat-agent-name">Librarian</span>
    <span class="chat-status-glyph {status_class}" title="{status_title}">{status_icon}</span>
  </div>
  <div class="chat-agent-snippet">Ask questions about your projects</div>
  <div class="chat-agent-time"></div>
</div>"#,
        active_class = librarian_active_class,
        status_class = librarian_status_class,
        status_title = librarian_status_title,
        status_icon = librarian_status_icon,
    );

    let agent_list_html: String = agents
        .iter()
        .map(|agent| {
            let active_class = if selected_agent == Some(agent.name.as_str()) {
                " chat-agent-active"
            } else {
                ""
            };
            let (status_class, status_title, status_icon) =
                chat_agent_status_indicator(&agent.status, agent.manage_enabled);
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
                    r#"<div class="chat-avatar-sm-wrap" data-agent="{}" onclick="event.stopPropagation(); openProfilePic(this)" title="Change profile picture"><img class="chat-avatar-sm" src="{}" alt=""></div>"#,
                    escape_attribute(&agent.name),
                    escape_attribute(url)
                )
            } else {
                format!(
                    r#"<div class="chat-avatar-sm-wrap chat-avatar-empty" data-agent="{}" onclick="event.stopPropagation(); openProfilePic(this)" title="Set profile picture"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.4"><circle cx="12" cy="8" r="4"/><path d="M5.5 21a7.5 7.5 0 0 1 13 0"/></svg></div>"#,
                    escape_attribute(&agent.name)
                )
            };
            format!(
                r#"<div class="chat-agent-item{active_class}" data-agent="{name}" data-manage-enabled="{manage_enabled}" onclick="selectAgent('{name}')">
  <div class="chat-agent-header">
    {avatar_html}<span class="chat-agent-name">{display_name}</span>
    <span class="chat-status-glyph {status_class}" title="{status_title}">{status_icon}</span>
  </div>
  <div class="chat-agent-snippet">{snippet_escaped}</div>
  <div class="chat-agent-time">{time_str}</div>
</div>"#,
                active_class = active_class,
                name = escape_attribute(&agent.name),
                manage_enabled = if agent.manage_enabled { "true" } else { "false" },
                avatar_html = avatar_html,
                display_name = escape_text(&agent.display_name),
                status_class = status_class,
                status_title = status_title,
                status_icon = status_icon,
                snippet_escaped = snippet_escaped,
                time_str = escape_text(time_str),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{}\n{}", librarian_entry, agent_list_html)
}

fn render_chat_page_with_agent_list_html(
    theme: UiTheme,
    color_mode: ColorMode,
    username: &str,
    csrf_token: &str,
    is_admin: bool,
    agent_list_html: &str,
    has_selected_agent: bool,
    selected_agent_js: String,
    selected_agent_status_js: String,
    messages_json: &str,
    profile_url_js: String,
    active_turn_user_id: u64,
    flash: Option<&str>,
    chat_area_html: String,
) -> String {
    let username_js = escape_attribute(username);
    let messages_json = escape_json_for_inline_script(messages_json);

    let layout_class = if has_selected_agent {
        "chat-layout chat-has-agent"
    } else {
        "chat-layout"
    };

    let content = format!(
        r#"<div class="{layout_class}">
  <div class="chat-sidebar" id="chat-sidebar">
    <div class="chat-sidebar-header">
      <span class="chat-header-name">Agents</span>
    </div>
    <div class="chat-agent-list" id="chat-agent-list">
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
var chatDraftUser = '{username_js}';
var chatMessages = {messages_json};
var agentProfileUrl = {profile_url_js};
var eventSource = null;
var streamingContent = '';
var agentConfig = {{ backend: '', model: '', effort: '' }};
var agentStatus = {selected_agent_status_js};
var activeTurnUserId = {active_turn_user_id};
var isLibrarian = currentAgent === 'librarian';
var libProject = '';
var chatFollowScroll = true;
var chatViewportResizeRestorePending = false;
var chatViewportResizeRestoreSeq = 0;
var chatResumeRefreshInFlight = false;
var chatResumeRefreshTimer = null;
var chatResumeRefreshSeq = 0;
var chatLastResumeRefreshAt = 0;
var chatLastStreamEventAt = Date.now();
var chatLastFullPanelRefreshAt = Date.now();
var chatWasBackgrounded = false;
var chatSendInFlight = false;
var chatSendMaxAttempts = 3;
var chatRestoreInFlight = false;
var chatPanelRequestSeq = 0;
var chatPanelRefreshScrollSnapshot = null;
var CHAT_PANEL_CACHE_LIMIT = 100;
var CHAT_PANEL_FETCH_TIMEOUT_MS = 15000;
var CHAT_RESUME_STALE_AFTER_MS = 10000;
var CHAT_WAKE_ACTIVITY_REFRESH_AFTER_MS = 60000;
var CHAT_FOREGROUND_RECONCILE_AFTER_MS = 300000;
var CHAT_FOREGROUND_RECONCILE_INTERVAL_MS = 30000;
var chatPanelCache = {{}};
var chatPanelCacheOrder = [];

function isMobileChatLayout() {{
  return !!(window.matchMedia && window.matchMedia('(max-width: 860px)').matches);
}}

function currentChatUrl(agent) {{
  return agent ? ('/ui/chat?agent=' + encodeURIComponent(agent)) : '/ui/chat';
}}

function chatDraftStorageKey() {{
  return 'lore.chat.drafts:' + chatDraftUser;
}}

function chatSendTokenStorageKey() {{
  return 'lore.chat.send-tokens:' + chatDraftUser;
}}

function readChatDraftStore() {{
  try {{
    var raw = localStorage.getItem(chatDraftStorageKey());
    if (!raw) return {{}};
    var parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {{}};
  }} catch (e) {{
    return {{}};
  }}
}}

function writeChatDraftStore(store) {{
  try {{
    var nextStore = store || {{}};
    if (Object.keys(nextStore).length === 0) {{
      localStorage.removeItem(chatDraftStorageKey());
      return;
    }}
    localStorage.setItem(chatDraftStorageKey(), JSON.stringify(nextStore));
  }} catch (e) {{}}
}}

function readChatSendTokenStore() {{
  try {{
    var raw = localStorage.getItem(chatSendTokenStorageKey());
    if (!raw) return {{}};
    var parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {{}};
  }} catch (e) {{
    return {{}};
  }}
}}

function writeChatSendTokenStore(store) {{
  try {{
    var nextStore = store || {{}};
    if (Object.keys(nextStore).length === 0) {{
      localStorage.removeItem(chatSendTokenStorageKey());
      return;
    }}
    localStorage.setItem(chatSendTokenStorageKey(), JSON.stringify(nextStore));
  }} catch (e) {{}}
}}

function getChatDraft(agent) {{
  if (!agent) return '';
  var store = readChatDraftStore();
  return typeof store[agent] === 'string' ? store[agent] : '';
}}

function setChatDraft(agent, value) {{
  if (!agent) return;
  var store = readChatDraftStore();
  if (value) {{
    store[agent] = value;
  }} else {{
    delete store[agent];
  }}
  writeChatDraftStore(store);
}}

function getChatSendTokenEntry(agent) {{
  if (!agent) return null;
  var store = readChatSendTokenStore();
  var entry = store[agent];
  if (!entry || typeof entry !== 'object') return null;
  if (typeof entry.text !== 'string' || typeof entry.token !== 'string' || !entry.token) return null;
  return entry;
}}

function setChatSendTokenEntry(agent, text, token) {{
  if (!agent) return;
  var store = readChatSendTokenStore();
  if (text && token) {{
    store[agent] = {{ text: text, token: token }};
  }} else {{
    delete store[agent];
  }}
  writeChatSendTokenStore(store);
}}

function clearChatSendToken(agent) {{
  setChatSendTokenEntry(agent, '', '');
}}

function syncChatSendToken(agent, text) {{
  var entry = getChatSendTokenEntry(agent);
  if (!entry) return;
  if (!text || entry.text !== text) clearChatSendToken(agent);
}}

function generateChatSendToken() {{
  if (window.crypto && typeof window.crypto.randomUUID === 'function') {{
    return window.crypto.randomUUID().replace(/[^A-Za-z0-9_-]/g, '_');
  }}
  return 'chat_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
}}

function resolveChatSendToken(agent, text) {{
  var entry = getChatSendTokenEntry(agent);
  if (entry && entry.text === text) return entry.token;
  var token = generateChatSendToken();
  setChatSendTokenEntry(agent, text, token);
  return token;
}}

function persistCurrentChatDraft() {{
  var input = document.getElementById('chat-input');
  if (!input || !currentAgent) return;
  setChatDraft(currentAgent, input.value || '');
  syncChatSendToken(currentAgent, input.value || '');
}}

function captureChatComposerState() {{
  var input = document.getElementById('chat-input');
  if (!input) return null;
  return {{
    agent: currentAgent,
    focused: input === document.activeElement,
    value: input.value || '',
    selectionStart: typeof input.selectionStart === 'number' ? input.selectionStart : null,
    selectionEnd: typeof input.selectionEnd === 'number' ? input.selectionEnd : null,
    scrollTop: input.scrollTop || 0
  }};
}}

function restoreChatComposerState(snapshot) {{
  if (!snapshot || snapshot.agent !== currentAgent) return;
  var input = document.getElementById('chat-input');
  if (!input) return;
  if (input.value !== snapshot.value) {{
    input.value = snapshot.value || '';
    setChatDraft(currentAgent, input.value);
    syncChatSendToken(currentAgent, input.value);
  }}
  resizeChatInput();
  input.scrollTop = snapshot.scrollTop || 0;
  if (snapshot.focused) {{
    try {{
      input.focus({{ preventScroll: true }});
    }} catch (_err) {{
      input.focus();
    }}
    if (snapshot.selectionStart !== null && snapshot.selectionEnd !== null && input.setSelectionRange) {{
      try {{
        input.setSelectionRange(snapshot.selectionStart, snapshot.selectionEnd);
      }} catch (_err) {{}}
    }}
  }}
}}

function shouldApplyChatRefreshWithoutPanelReplace(selectedAgent) {{
  if (!selectedAgent || selectedAgent !== currentAgent) return false;
  if (chatConfigOpen || chatManageOpen || expandedTextEditorState) return true;
  return chatInputIsFocused();
}}

function clearActiveAgentInList() {{
  document.querySelectorAll('.chat-agent-item.chat-agent-active').forEach(function(item) {{
    item.classList.remove('chat-agent-active');
  }});
}}

function setActiveAgentInList(agent) {{
  clearActiveAgentInList();
  if (!agent) return;
  var item = document.querySelector('.chat-agent-item[data-agent="' + CSS.escape(agent) + '"]');
  if (item) item.classList.add('chat-agent-active');
}}

function moveAgentItemToTop(agent) {{
  if (!agent || agent === 'librarian') return;
  var list = document.querySelector('.chat-agent-list');
  var item = document.querySelector('.chat-agent-item[data-agent="' + CSS.escape(agent) + '"]');
  if (!list || !item) return;
  var librarian = list.querySelector('.chat-agent-item[data-agent="librarian"]');
  if (librarian) {{
    list.insertBefore(item, librarian.nextSibling);
  }} else {{
    list.insertBefore(item, list.firstChild);
  }}
}}

function sidebarTimeNow() {{
  return new Date().toLocaleTimeString([], {{ hour: 'numeric', minute: '2-digit' }});
}}

function updateAgentListPreview(agent, content, timeText) {{
  if (!agent || agent === 'librarian') return;
  var item = document.querySelector('.chat-agent-item[data-agent="' + CSS.escape(agent) + '"]');
  if (!item) return;
  var snippetEl = item.querySelector('.chat-agent-snippet');
  var timeEl = item.querySelector('.chat-agent-time');
  if (snippetEl && typeof content === 'string') {{
    var normalized = content.replace(/\s+/g, ' ').trim();
    snippetEl.textContent = normalized ? normalized.slice(0, 60) : 'No messages yet';
  }}
  if (timeEl && typeof timeText === 'string') {{
    timeEl.textContent = timeText;
  }}
}}

function touchChatPanelCache(agent) {{
  if (!agent || agent === 'librarian') return;
  chatPanelCacheOrder = chatPanelCacheOrder.filter(function(name) {{ return name !== agent; }});
  chatPanelCacheOrder.push(agent);
  while (chatPanelCacheOrder.length > CHAT_PANEL_CACHE_LIMIT) {{
    var evict = chatPanelCacheOrder.shift();
    if (evict && evict !== currentAgent) {{
      delete chatPanelCache[evict];
    }} else if (evict) {{
      chatPanelCacheOrder.push(evict);
      break;
    }}
  }}
}}

function cacheChatPanelState(agent, state) {{
  if (!agent || agent === 'librarian' || !state) return;
  var existing = chatPanelCache[agent] || {{}};
  chatPanelCache[agent] = Object.assign(existing, {{
    selected_agent: agent,
    panel_html: typeof state.panel_html === 'string' ? state.panel_html : existing.panel_html || '',
    messages: Array.isArray(state.messages) ? state.messages : existing.messages || [],
    agent_status: typeof state.agent_status === 'string' ? state.agent_status : existing.agent_status || '',
    active_turn_user_id: state.active_turn_user_id || 0,
    profile_url: state.profile_url || null,
    cached_at: Date.now()
  }});
  touchChatPanelCache(agent);
}}

function cacheCurrentChatPanelState(includePanelHtml) {{
  if (!currentAgent || isLibrarian) return;
  var main = document.getElementById('chat-main');
  cacheChatPanelState(currentAgent, {{
    panel_html: includePanelHtml && main ? main.innerHTML : undefined,
    messages: chatMessages || [],
    agent_status: agentStatus || '',
    active_turn_user_id: activeTurnUserId || 0,
    profile_url: agentProfileUrl || null
  }});
}}

function cacheChatPanelResponse(data) {{
  if (!data || !data.ok || !data.selected_agent || data.selected_agent === 'librarian') return;
  var incomingMessages = Array.isArray(data.messages) ? data.messages : [];
  var cached = chatPanelCache[data.selected_agent];
  if (cached && Array.isArray(cached.messages) && cached.messages.length) {{
    incomingMessages = mergeChatMessagesPreservingVisibleOrder(cached.messages, incomingMessages);
  }}
  cacheChatPanelState(data.selected_agent, {{
    panel_html: data.panel_html || '',
    messages: incomingMessages,
    agent_status: data.agent_status || '',
    active_turn_user_id: data.active_turn_user_id || 0,
    profile_url: data.profile_url || null
  }});
}}

function fetchChatJson(url, options, timeoutMs) {{
  var fetchOptions = Object.assign({{}}, options || {{}});
  var timer = null;
  var controller = null;
  if (typeof AbortController !== 'undefined' && timeoutMs > 0) {{
    controller = new AbortController();
    fetchOptions.signal = controller.signal;
    timer = setTimeout(function() {{ controller.abort(); }}, timeoutMs);
  }}
  var request = fetch(url, fetchOptions);
  if (!timer) return request;
  return request.finally(function() {{ clearTimeout(timer); }});
}}

function applyCachedChatPanel(agent, pushHistory) {{
  var cached = agent && chatPanelCache[agent];
  if (!cached || !cached.panel_html) return false;
  applyChatPanelResponse({{
    ok: true,
    selected_agent: agent,
    panel_html: cached.panel_html,
    messages: cached.messages || [],
    agent_status: cached.agent_status || '',
    active_turn_user_id: cached.active_turn_user_id || 0,
    profile_url: cached.profile_url || null
  }}, pushHistory, true);
  return true;
}}

function initializeChatPanel() {{
  isLibrarian = currentAgent === 'librarian';
  streamingContent = '';
  agentConfig = {{ backend: '', model: '', effort: '' }};
  if (isLibrarian || !currentAgent) agentStatus = '';
  chatFollowScroll = true;
  clearChatMessageSwipeGesture();
  chatMessageEditPending = false;
  expandedTextEditorState = null;
  setExpandedTextEditorOpen(false);
  closeAllPanels();
  setActiveAgentInList(currentAgent);
  if (eventSource) {{
    eventSource.close();
    eventSource = null;
  }}
  connectSSE();
  initChatComposer();
  bindChatScrollState();
  bindChatMessageMutationGestures();

  if (isLibrarian) {{
    var params = new URLSearchParams(window.location.search);
    var qProject = params.get('project');
    var saved = localStorage.getItem('libProject');
    var projSel = document.getElementById('lib-project');
    if (qProject && projSel) {{
      projSel.value = qProject;
      libProject = qProject;
    }} else if (saved && projSel) {{
      projSel.value = saved;
      libProject = saved;
      if (!projSel.value) {{ libProject = ''; }}
    }} else {{
      libProject = '';
    }}
    loadLibrarianHistory();
    return;
  }}

  if (!currentAgent) {{
    renderMessages();
    return;
  }}

  renderMessages();
  var configAgent = currentAgent;
  fetch('/ui/chat/' + encodeURIComponent(configAgent) + '/config', {{ cache: 'no-store' }})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      if (currentAgent !== configAgent) return;
      if (data.endpoint_id && data.endpoints) {{
        var ep = data.endpoints.find(function(e) {{ return e.id === data.endpoint_id; }});
        if (ep) {{
          agentConfig.backend = ep.name;
          agentConfig.model = ep.model;
          agentConfig.effort = '';
          updateHeaderStatus();
          return;
        }}
      }}
      agentConfig.backend = data.backend || '';
      var prefs = data.prefs && data.prefs[data.backend];
      agentConfig.model = (prefs && prefs.model) || '';
      agentConfig.effort = (prefs && prefs.effort) || '';
      updateHeaderStatus();
    }});
}}

function applyChatPanelResponse(data, pushHistory, fromCache) {{
  if (!data || !data.ok) return;
  var main = document.getElementById('chat-main');
  if (!main) return;
  var selectedAgent = data.selected_agent || null;
  var incomingMessages = Array.isArray(data.messages) ? data.messages : [];
  if (selectedAgent && selectedAgent === currentAgent && Array.isArray(chatMessages) && chatMessages.length) {{
    incomingMessages = mergeChatMessagesPreservingVisibleOrder(chatMessages, incomingMessages);
  }}
  var list = document.getElementById('chat-agent-list');
  if (!fromCache && list && typeof data.agent_list_html === 'string') {{
    list.innerHTML = data.agent_list_html;
  }}
  if (!fromCache && shouldApplyChatRefreshWithoutPanelReplace(selectedAgent)) {{
    currentAgent = selectedAgent;
    chatMessages = incomingMessages;
    agentStatus = data.agent_status || '';
    activeTurnUserId = data.active_turn_user_id || 0;
    agentProfileUrl = data.profile_url || null;
    if (currentAgent) localStorage.setItem('lastChatAgent', currentAgent);
    var activeSnapshot = chatPanelRefreshScrollSnapshot || captureChatResizeScrollSnapshot();
    chatPanelRefreshScrollSnapshot = null;
    renderMessages();
    updateHeaderStatus();
    setActiveAgentInList(currentAgent);
    applyChatViewportFix();
    scheduleChatResizeScrollRestore(activeSnapshot);
    return;
  }}
  var composerSnapshot = captureChatComposerState();
  var scrollSnapshot = chatPanelRefreshScrollSnapshot || captureChatResizeScrollSnapshot();
  chatPanelRefreshScrollSnapshot = null;
  main.innerHTML = data.panel_html || '';
  currentAgent = selectedAgent;
  chatMessages = incomingMessages;
  agentStatus = data.agent_status || '';
  activeTurnUserId = data.active_turn_user_id || 0;
  agentProfileUrl = data.profile_url || null;
  if (currentAgent) {{
    localStorage.setItem('lastChatAgent', currentAgent);
  }} else {{
    localStorage.removeItem('lastChatAgent');
  }}
  if (pushHistory === 'replace') {{
    history.replaceState({{ agent: currentAgent }}, '', currentChatUrl(currentAgent));
  }} else if (pushHistory) {{
    history.pushState({{ agent: currentAgent }}, '', currentChatUrl(currentAgent));
  }}
  if (!fromCache) cacheChatPanelResponse(data);
  initializeChatPanel();
  restoreChatComposerState(composerSnapshot);
  scheduleChatResizeScrollRestore(scrollSnapshot);
  applyChatViewportFix();
}}

function fetchDesktopChatPanel(agent, pushHistory, applyMode, requestSeq) {{
  var requestedAgent = agent || null;
  var url = '/ui/chat/panel';
  if (agent) url += '?agent=' + encodeURIComponent(agent);
  var panelRefreshScrollSnapshot = requestedAgent === currentAgent
    ? captureChatResizeScrollSnapshot()
    : null;
  return fetchChatJson(url, {{ cache: 'no-store' }}, CHAT_PANEL_FETCH_TIMEOUT_MS)
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      if (data && data.ok) chatLastFullPanelRefreshAt = Date.now();
      cacheChatPanelResponse(data);
      if (!data || !data.ok) return data;
      if (applyMode === 'background' && currentAgent !== requestedAgent) return data;
      if (requestSeq && requestSeq !== chatPanelRequestSeq) return data;
      if (applyMode === 'background' && (chatConfigOpen || chatManageOpen || expandedTextEditorState)) return data;
      persistCurrentChatDraft();
      chatPanelRefreshScrollSnapshot = panelRefreshScrollSnapshot;
      applyChatPanelResponse(data, applyMode === 'cached' ? false : pushHistory, false);
      return data;
    }});
}}

function loadDesktopChatPanel(agent, pushHistory) {{
  persistCurrentChatDraft();
  cacheCurrentChatPanelState(true);
  var requestSeq = ++chatPanelRequestSeq;
  var usedCache = false;
  if (agent && !isMobileChatLayout()) {{
    usedCache = applyCachedChatPanel(agent, pushHistory);
  }}
  return fetchDesktopChatPanel(agent, pushHistory, usedCache ? 'background' : 'normal', requestSeq);
}}

function readLastChatAgent() {{
  try {{
    return localStorage.getItem('lastChatAgent') || '';
  }} catch (e) {{
    return '';
  }}
}}

function canRestoreChatAgent(agent) {{
  if (!agent) return false;
  return !!document.querySelector('.chat-agent-item[data-agent="' + CSS.escape(agent) + '"]');
}}

function restorePersistedChatAgentSelection(historyMode) {{
  if (currentAgent || isMobileChatLayout()) return false;
  if (chatRestoreInFlight) return true;
  var savedAgent = readLastChatAgent();
  if (!savedAgent) return false;
  if (!canRestoreChatAgent(savedAgent)) {{
    try {{ localStorage.removeItem('lastChatAgent'); }} catch (e) {{}}
    return false;
  }}
  chatRestoreInFlight = true;
  loadDesktopChatPanel(savedAgent, historyMode || false)
    .catch(function() {{}})
    .finally(function() {{ chatRestoreInFlight = false; }});
  return true;
}}

function markChatStreamAlive() {{
  chatLastStreamEventAt = Date.now();
}}

function shouldRefreshChatOnResume(force) {{
  if (document.visibilityState && document.visibilityState === 'hidden') return false;
  if (chatResumeRefreshInFlight) return false;
  var now = Date.now();
  if (!force && now - chatLastResumeRefreshAt < 1000) return false;
  if (force || chatWasBackgrounded) return true;
  if (!eventSource) return true;
  if (typeof EventSource !== 'undefined' && eventSource.readyState === EventSource.CLOSED) return true;
  return (now - Math.max(chatLastStreamEventAt, chatLastFullPanelRefreshAt)) > CHAT_RESUME_STALE_AFTER_MS;
}}

function reconnectChatStreamForResume() {{
  if (eventSource) {{
    eventSource.close();
    eventSource = null;
  }}
  connectSSE();
}}

function finishChatResumeRefresh(resumeSeq) {{
  if (resumeSeq && resumeSeq !== chatResumeRefreshSeq) return;
  if (chatResumeRefreshTimer) {{
    clearTimeout(chatResumeRefreshTimer);
    chatResumeRefreshTimer = null;
  }}
  chatResumeRefreshInFlight = false;
}}

function refreshChatOnResume(force) {{
  if (!shouldRefreshChatOnResume(force)) return;
  chatWasBackgrounded = false;
  chatResumeRefreshInFlight = true;
  chatLastResumeRefreshAt = Date.now();
  reconnectChatStreamForResume();
  var resumeSeq = ++chatResumeRefreshSeq;
  var refreshAgent = currentAgent;
  var requestSeq = ++chatPanelRequestSeq;
  if (chatResumeRefreshTimer) clearTimeout(chatResumeRefreshTimer);
  chatResumeRefreshTimer = setTimeout(function() {{
    if (resumeSeq !== chatResumeRefreshSeq) return;
    chatResumeRefreshInFlight = false;
    chatResumeRefreshTimer = null;
    reconnectChatStreamForResume();
  }}, CHAT_PANEL_FETCH_TIMEOUT_MS + 5000);
  fetchDesktopChatPanel(refreshAgent, false, 'normal', requestSeq)
    .catch(function() {{
      reconnectChatStreamForResume();
    }})
    .finally(function() {{
      finishChatResumeRefresh(resumeSeq);
    }});
}}

function shouldRefreshChatAfterWakeActivity() {{
  if (!currentAgent || isLibrarian) return false;
  if (document.visibilityState && document.visibilityState === 'hidden') return false;
  if (chatResumeRefreshInFlight) return false;
  var now = Date.now();
  if (chatWasBackgrounded) return true;
  if (!eventSource) return true;
  if (typeof EventSource !== 'undefined' && eventSource.readyState === EventSource.CLOSED) return true;
  if (now - chatLastFullPanelRefreshAt > CHAT_WAKE_ACTIVITY_REFRESH_AFTER_MS) return true;
  return (now - Math.max(chatLastStreamEventAt, chatLastResumeRefreshAt)) > CHAT_WAKE_ACTIVITY_REFRESH_AFTER_MS;
}}

function refreshChatAfterWakeActivity() {{
  if (!shouldRefreshChatAfterWakeActivity()) return;
  refreshChatOnResume(true);
}}

function reconcileVisibleChatIfStale() {{
  if (!currentAgent || isLibrarian) return;
  if (document.visibilityState && document.visibilityState === 'hidden') return;
  if (chatResumeRefreshInFlight) return;
  var now = Date.now();
  if (now - chatLastFullPanelRefreshAt > CHAT_FOREGROUND_RECONCILE_AFTER_MS) {{
    refreshChatOnResume(true);
  }}
}}

if (currentAgent) {{
  localStorage.setItem('lastChatAgent', currentAgent);
}}

function selectAgent(name) {{
  persistCurrentChatDraft();
  localStorage.setItem('lastChatAgent', name);
  if (isMobileChatLayout()) {{
    window.location.href = currentChatUrl(name);
    return;
  }}
  if (currentAgent === name) {{
    setActiveAgentInList(name);
    return;
  }}
  loadDesktopChatPanel(name, true);
}}

function showAgentList() {{
  persistCurrentChatDraft();
  localStorage.removeItem('lastChatAgent');
  if (isMobileChatLayout()) {{
    window.location.href = '/ui/chat';
    return;
  }}
  loadDesktopChatPanel(null, true);
}}

/* Fix mobile keyboard: on dismiss, browser sometimes leaves page scrolled
   so chat-header hides behind the sticky top-nav. On first keyboard open,
   iOS may not recalculate fixed layout in time, so drive the shell inset
   from the visual viewport and keep nudging the composer into view. */
function chatInputIsFocused() {{
  var ci = document.getElementById('chat-input');
  return !!(ci && ci === document.activeElement);
}}

function currentKeyboardInset() {{
  if (!window.visualViewport) return 0;
  var visibleBottom = window.visualViewport.height + window.visualViewport.offsetTop;
  return Math.max(0, Math.round(window.innerHeight - visibleBottom));
}}

function applyChatViewportFix() {{
  var shell = document.querySelector('.shell');
  var form = document.getElementById('chat-input-form');
  var input = document.getElementById('chat-input');
  var messages = document.getElementById('chat-messages');
  var hasFocus = chatInputIsFocused();
  var inset = currentKeyboardInset();

  if (shell) {{
    if (inset > 0 || hasFocus) {{
      shell.style.bottom = inset > 0 ? (inset + 'px') : '0px';
    }} else {{
      shell.style.bottom = '';
    }}
  }}

  if (!window.visualViewport) {{
    if (!hasFocus) window.scrollTo(0, 0);
    return;
  }}

  if (!hasFocus || !form || !messages || !input) {{
    if (!hasFocus && inset === 0) window.scrollTo(0, 0);
    return;
  }}

  var viewportBottom = window.visualViewport.offsetTop + window.visualViewport.height;
  var formRect = form.getBoundingClientRect();
  var inputRect = input.getBoundingClientRect();
  var targetBottom = viewportBottom - 12;
  var overlap = Math.max(formRect.bottom - targetBottom, inputRect.bottom - targetBottom);
  if (overlap > 0 && chatShouldFollow(messages, chatFollowScroll)) {{
    messages.scrollTop += overlap;
  }}
}}

function scheduleChatViewportFix() {{
  applyChatViewportFix();
  requestAnimationFrame(function() {{
    applyChatViewportFix();
    requestAnimationFrame(function() {{
      applyChatViewportFix();
      setTimeout(applyChatViewportFix, 60);
      setTimeout(applyChatViewportFix, 180);
    }});
  }});
}}

function measureChatInputContentHeight(input, isBorderBox, borderY, useClone) {{
  if (!useClone) return input.scrollHeight + (isBorderBox ? borderY : 0);
  var clone = input.cloneNode(false);
  var rect = input.getBoundingClientRect();
  clone.removeAttribute('id');
  clone.removeAttribute('name');
  clone.setAttribute('aria-hidden', 'true');
  clone.tabIndex = -1;
  clone.value = input.value || '';
  clone.style.position = 'absolute';
  clone.style.visibility = 'hidden';
  clone.style.pointerEvents = 'none';
  clone.style.left = '-10000px';
  clone.style.top = '0';
  clone.style.zIndex = '-1';
  clone.style.width = Math.max(1, Math.round(rect.width || input.offsetWidth || 1)) + 'px';
  clone.style.height = 'auto';
  clone.style.minHeight = '0';
  clone.style.maxHeight = 'none';
  clone.style.overflowY = 'hidden';
  document.body.appendChild(clone);
  var measuredHeight = clone.scrollHeight + (isBorderBox ? borderY : 0);
  clone.remove();
  return measuredHeight;
}}

function resizeChatInput() {{
  var input = document.getElementById('chat-input');
  if (!input) return false;
  var form = document.getElementById('chat-input-form');
  var sendBtn = document.querySelector('#chat-input-form .chat-send-btn');
  var header = document.querySelector('.chat-header');
  var messages = document.getElementById('chat-messages');
  var viewportHeight = window.visualViewport ? window.visualViewport.height : window.innerHeight;
  var headerBottom = 0;
  var prevHeight = input.offsetHeight;
  var prevOverflow = input.style.overflowY;
  var valueLength = (input.value || '').length;
  var prevValueLength = parseInt(input.dataset.chatComposerValueLength || '0', 10);
  var wasFollowing = chatShouldFollow(messages, chatFollowScroll);
  if (header) {{
    var headerRect = header.getBoundingClientRect();
    headerBottom = Math.max(0, headerRect.bottom);
  }}
  var computed = window.getComputedStyle ? window.getComputedStyle(input) : null;
  var borderY = computed
    ? (parseFloat(computed.borderTopWidth) || 0) + (parseFloat(computed.borderBottomWidth) || 0)
    : 0;
  var isBorderBox = !computed || computed.boxSizing === 'border-box';
  var needsShrinkProbe = !!input.style.height && valueLength <= prevValueLength;
  var formChrome = form ? Math.max(0, form.offsetHeight - input.offsetHeight) : 0;
  var minHeight = 38;
  var maxHeight = Math.max(120, Math.floor(viewportHeight - headerBottom - formChrome - 16));
  var measuredHeight = measureChatInputContentHeight(input, isBorderBox, borderY, needsShrinkProbe);
  var nextHeight = Math.max(minHeight, Math.min(measuredHeight, maxHeight));
  var nextOverflow = measuredHeight > maxHeight ? 'auto' : 'hidden';
  if (Math.abs(nextHeight - prevHeight) > 1) {{
    input.style.height = nextHeight + 'px';
  }} else if (!input.style.height) {{
    input.style.height = prevHeight + 'px';
  }}
  input.style.overflowY = nextOverflow;
  input.dataset.chatComposerValueLength = String(valueLength);
  if (sendBtn) {{
    // Match the textarea's real rendered box, not just the requested height,
    // so the button stays flush when browser text metrics round differently.
    var renderedHeight = Math.max(minHeight, input.offsetHeight || nextHeight);
    sendBtn.style.height = renderedHeight + 'px';
  }}
  var changed = Math.abs(nextHeight - prevHeight) > 1 || prevOverflow !== nextOverflow;
  if (changed && messages && wasFollowing) {{
    chatFollowScroll = true;
    messages.scrollTop = messages.scrollHeight;
  }}
  if (changed) updateChatJumpButton();
  return changed;
}}

function initChatComposer() {{
  var input = document.getElementById('chat-input');
  if (!input) return;
  input.value = getChatDraft(currentAgent);
  syncChatSendToken(currentAgent, input.value || '');
  if (input.dataset.chatComposerBound !== '1') {{
    input.dataset.chatComposerBound = '1';
    input.addEventListener('input', function() {{
      setChatDraft(currentAgent, input.value || '');
      syncChatSendToken(currentAgent, input.value || '');
      if (resizeChatInput()) {{
        scheduleChatViewportFix();
      }}
    }});
  }}
  resizeChatInput();
}}

if (window.visualViewport) {{
  var _lastVVH = window.visualViewport.height;
  window.visualViewport.addEventListener('resize', function() {{
    var snapshot = captureChatResizeScrollSnapshot();
    var h = window.visualViewport.height;
    if (h > _lastVVH) {{
      window.scrollTo(0, 0);
    }}
    resizeChatInput();
    applyChatViewportFix();
    scheduleChatResizeScrollRestore(snapshot);
    _lastVVH = h;
  }});
  window.visualViewport.addEventListener('scroll', function() {{
    var snapshot = captureChatResizeScrollSnapshot();
    resizeChatInput();
    applyChatViewportFix();
    scheduleChatResizeScrollRestore(snapshot);
  }});
}}

window.addEventListener('resize', function() {{
  var snapshot = captureChatResizeScrollSnapshot();
  resizeChatInput();
  applyChatViewportFix();
  scheduleChatResizeScrollRestore(snapshot);
}});
window.addEventListener('orientationchange', function() {{
  var snapshot = captureChatResizeScrollSnapshot();
  scheduleChatResizeScrollRestore(snapshot);
}});

document.addEventListener('focusin', function(e) {{
  if (e.target && e.target.id === 'chat-input') {{
    resizeChatInput();
    scheduleChatViewportFix();
  }}
}});

document.addEventListener('focusout', function(e) {{
  if (e.target && e.target.id === 'chat-input') {{
    resizeChatInput();
    setTimeout(applyChatViewportFix, 0);
    setTimeout(applyChatViewportFix, 120);
  }}
}});

function openProfilePic(el) {{
  var agent = el.getAttribute('data-agent');
  var inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = 'image/*';
  inp.style.display = 'none';
  inp.addEventListener('change', function() {{
    if (!inp.files || !inp.files[0]) return;
    resizeAndUpload(inp.files[0], agent, el);
  }});
  document.body.appendChild(inp);
  inp.click();
  setTimeout(function() {{ document.body.removeChild(inp); }}, 60000);
}}

function resizeAndUpload(file, agent, el) {{
  var reader = new FileReader();
  reader.onload = function(e) {{
    var img = new Image();
    img.onload = function() {{
      var sz = 96;
      var c = document.createElement('canvas');
      c.width = sz; c.height = sz;
      var ctx = c.getContext('2d');
      var side = Math.min(img.width, img.height);
      var sx = (img.width - side) / 2;
      var sy = (img.height - side) / 2;
      ctx.drawImage(img, sx, sy, side, side, 0, 0, sz, sz);
      var dataUrl = c.toDataURL('image/png');
      fetch('/ui/chat/' + encodeURIComponent(agent) + '/profile-pic', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
        body: 'csrf_token=' + encodeURIComponent(csrfToken) + '&data_url=' + encodeURIComponent(dataUrl)
      }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
        if (d.ok) {{
          el.classList.remove('chat-avatar-empty');
          el.innerHTML = '<img class="chat-avatar-sm" src="' + escapeHtmlRaw(dataUrl) + '" alt="">';
          if (agent === currentAgent) {{
            agentProfileUrl = dataUrl;
            var hdr = document.querySelector('.chat-avatar-header');
            if (hdr) hdr.src = dataUrl;
            else {{
              var nameEl = document.querySelector('.chat-header-name');
              if (nameEl) {{
                var img2 = document.createElement('img');
                img2.className = 'chat-avatar-header';
                img2.src = dataUrl;
                nameEl.parentNode.insertBefore(img2, nameEl);
              }}
            }}
            renderMessages();
          }}
        }}
      }});
    }};
    img.src = e.target.result;
  }};
  reader.readAsDataURL(file);
}}

function renderMessages() {{
  var container = document.getElementById('chat-messages');
  if (!container) return;
  normalizeChatMessageOrder();
  var anchor = null;
  var preservedScrollTop = container.scrollTop;
  var shouldFollow = chatShouldFollow(container, chatFollowScroll);
  if (!shouldFollow) {{
    anchor = captureChatViewportAnchor(container);
  }}
  var html = '';
  for (var i = 0; i < chatMessages.length; i++) {{
    var msg = chatMessages[i];
    var kind = msg.role === 'user' ? 'user' : msg.role === 'system' ? 'system' : msg.role === 'config' ? 'config' : msg.role === 'tool' ? 'tool' : msg.role === 'error' ? 'error' : 'assistant';
    var cls = kind === 'user' ? 'chat-msg-user' : kind === 'system' ? 'chat-msg-system' : kind === 'config' ? 'chat-msg-config' : kind === 'tool' ? 'chat-msg-tool' : kind === 'error' ? 'chat-msg-error' : 'chat-msg-assistant';
    if (msg._thinking) cls += ' chat-msg-thinking';
    if (msg.excluded_from_context) cls += ' chat-msg-excluded';
    var messageId = chatMessageId(msg);
    var canMutate = chatMessageCanMutate(msg);
    html += '<div class="chat-msg-row chat-msg-row-' + kind + (canMutate ? ' chat-msg-row-mutable' : '') + (msg.excluded_from_context ? ' chat-msg-row-excluded' : '') + '" data-chat-idx="' + i + '"' + (canMutate ? ' data-chat-msg-id="' + messageId + '"' : '') + '>';
    var timestamp = formatChatTimestamp(msg.timestamp);
    if (timestamp) {{
      html += '<div class="chat-msg-timestamp">' + escapeHtmlRaw(timestamp) + '</div>';
    }}
    if (canMutate) {{
      var toggleExcluded = msg.excluded_from_context ? 'false' : 'true';
      var toggleTitle = msg.excluded_from_context ? 'Include in agent context' : 'Exclude from agent context';
      var actionClass = 'btn-sm chat-msg-swipe-action' + (msg.excluded_from_context ? ' chat-msg-swipe-action-active' : '');
      html += '<div class="chat-msg-swipe-shell">';
      html += '<button type="button" class="' + actionClass + '" title="' + toggleTitle + '" aria-label="' + toggleTitle + '" onclick="event.stopPropagation(); return toggleChatMessageContextExclusion(' + messageId + ', ' + toggleExcluded + ');"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg></button>';
    }}
    html += '<div class="chat-msg ' + cls + '">';
    if (msg.excluded_from_context) {{
      html += '<div class="chat-msg-excluded-prefix" title="Excluded from agent context">&#128465;</div>';
    }}
    if (msg.role === 'assistant' || msg.role === 'user') {{
      html += '<div class="chat-msg-content">' + renderMarkdown(msg.content) + '</div>';
    }} else if (msg.role === 'error') {{
      html += '<div class="chat-msg-content chat-msg-error-content"><svg class="chat-msg-error-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>' + escapeHtml(msg.content) + '</span></div>';
    }} else if (msg.role === 'tool') {{
      html += renderToolMessage(msg, i);
    }} else {{
      html += '<div class="chat-msg-content">' + escapeHtml(msg.content) + '</div>';
    }}
    html += '</div>';
    if (canMutate) {{
      html += '</div>';
    }}
    html += '</div>';
  }}
  container.innerHTML = html;
  if (shouldFollow) {{
    chatFollowScroll = true;
    container.scrollTop = container.scrollHeight;
  }} else {{
    chatFollowScroll = false;
    restoreChatViewportAnchor(container, anchor, preservedScrollTop);
  }}
  updateChatJumpButton();
  cacheCurrentChatPanelState(false);
}}

function chatToolLines(msg) {{
  if (!msg || typeof msg.content !== 'string' || !msg.content) return [];
  return msg.content.split('\n').filter(function(line) {{ return !!line; }});
}}

function renderToolMessage(msg, index) {{
  var lines = chatToolLines(msg);
  if (!lines.length) {{
    return '<div class="chat-msg-content"></div>';
  }}
  var latest = lines[lines.length - 1];
  var expanded = !!msg.tool_expanded;
  var html = '<div class="chat-msg-content">';
  html += '<div class="chat-tool-summary">';
  if (lines.length > 1) {{
    var title = expanded ? 'Collapse tool runs' : 'Expand tool runs';
    var ariaLabel = expanded ? 'Collapse tool runs' : 'Expand tool runs';
    var icon = expanded
      ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>'
      : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"/></svg>';
    html += '<button type="button" class="btn-sm chat-tool-toggle" onclick="toggleToolMessage(' + index + '); return false;" title="' + title + '" aria-label="' + ariaLabel + '">' + icon + '</button>';
  }}
  html += '<span class="chat-tool-line">' + escapeHtml(latest) + '</span>';
  if (lines.length > 1) {{
    html += '<span class="chat-tool-count">' + lines.length + ' runs</span>';
  }}
  html += '</div>';
  if (expanded && lines.length > 1) {{
    html += '<div class="chat-tool-lines">' + escapeHtml(lines.join('\n')) + '</div>';
  }}
  html += '</div>';
  return html;
}}

function toggleToolMessage(index) {{
  var msg = chatMessages[index];
  if (!msg || msg.role !== 'tool') return false;
  if (chatToolLines(msg).length < 2) return false;
  msg.tool_expanded = !msg.tool_expanded;
  renderMessages();
  return false;
}}

function chatDistanceFromBottom(container) {{
  if (!container) return true;
  return Math.max(0, container.scrollHeight - container.clientHeight - container.scrollTop);
}}

function chatIsNearBottom(container, threshold) {{
  if (!container) return true;
  return chatDistanceFromBottom(container) <= (threshold || 0);
}}

function chatShouldFollow(container, wasFollowing) {{
  if (!container) return true;
  return chatIsNearBottom(container, wasFollowing ? 72 : 16);
}}

function captureChatViewportAnchor(container) {{
  if (!container) return null;
  var containerTop = container.getBoundingClientRect().top;
  var children = container.children;
  for (var i = 0; i < children.length; i++) {{
    var child = children[i];
    var rect = child.getBoundingClientRect();
    if (rect.bottom > containerTop) {{
      return {{
        index: child.getAttribute('data-chat-idx'),
        offset: rect.top - containerTop
      }};
    }}
  }}
  return null;
}}

function restoreChatViewportAnchor(container, anchor, fallbackScrollTop) {{
  if (!container) return;
  if (anchor && anchor.index !== null) {{
    var selector = '[data-chat-idx="' + anchor.index + '"]';
    var child = container.querySelector(selector);
    if (child) {{
      var containerTop = container.getBoundingClientRect().top;
      var rect = child.getBoundingClientRect();
      container.scrollTop += rect.top - containerTop - anchor.offset;
      return;
    }}
  }}
  container.scrollTop = Math.max(0, fallbackScrollTop);
}}

function updateChatJumpButton() {{
  var button = document.getElementById('chat-jump-btn');
  var container = document.getElementById('chat-messages');
  if (!button) return;
  if (!container || chatConfigOpen || chatManageOpen) {{
    button.style.display = 'none';
    return;
  }}
  var hasOverflow = container.scrollHeight > container.clientHeight + 8;
  button.style.display = (!chatIsNearBottom(container, 16) && hasOverflow) ? 'inline-flex' : 'none';
}}

function bindChatScrollState() {{
  var container = document.getElementById('chat-messages');
  if (!container) return;
  if (container.dataset.scrollBound !== '1') {{
    container.dataset.scrollBound = '1';
    container.addEventListener('scroll', function() {{
      if (chatViewportResizeRestorePending) {{
        updateChatJumpButton();
        return;
      }}
      chatFollowScroll = chatShouldFollow(container, chatFollowScroll);
      updateChatJumpButton();
    }});
  }}
  chatFollowScroll = chatShouldFollow(container, chatFollowScroll);
  updateChatJumpButton();
}}

function jumpToChatLatest() {{
  var container = document.getElementById('chat-messages');
  if (!container) return false;
  chatFollowScroll = true;
  container.scrollTop = container.scrollHeight;
  updateChatJumpButton();
  return false;
}}

function captureChatResizeScrollSnapshot() {{
  var container = document.getElementById('chat-messages');
  if (!container) return null;
  return {{
    follow: !!chatFollowScroll || chatIsNearBottom(container, 96),
    anchor: captureChatViewportAnchor(container),
    scrollTop: container.scrollTop
  }};
}}

function restoreChatResizeScrollSnapshot(snapshot) {{
  var container = document.getElementById('chat-messages');
  if (!container || !snapshot) return;
  if (snapshot.follow) {{
    chatFollowScroll = true;
    container.scrollTop = container.scrollHeight;
  }} else {{
    chatFollowScroll = false;
    restoreChatViewportAnchor(container, snapshot.anchor, snapshot.scrollTop || 0);
  }}
  updateChatJumpButton();
}}

function scheduleChatResizeScrollRestore(snapshot) {{
  if (!snapshot) return;
  var restoreSeq = ++chatViewportResizeRestoreSeq;
  chatViewportResizeRestorePending = true;
  var restore = function() {{
    restoreChatResizeScrollSnapshot(snapshot);
  }};
  restore();
  requestAnimationFrame(function() {{
    restore();
    requestAnimationFrame(function() {{
      restore();
      setTimeout(restore, 80);
      setTimeout(function() {{
        restore();
        if (restoreSeq === chatViewportResizeRestoreSeq) {{
          chatViewportResizeRestorePending = false;
        }}
      }}, 220);
    }});
  }});
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

function parseChatTimestamp(value) {{
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') {{
    return new Date(value * 1000);
  }}
  if (typeof value === 'string' && /^\d+$/.test(value)) {{
    return new Date(parseInt(value, 10) * 1000);
  }}
  var parsed = new Date(value);
  return isNaN(parsed.getTime()) ? null : parsed;
}}

function formatChatTimestamp(value) {{
  var parsed = parseChatTimestamp(value);
  if (!parsed) return '';
  var now = new Date();
  var sameDay = parsed.getFullYear() === now.getFullYear()
    && parsed.getMonth() === now.getMonth()
    && parsed.getDate() === now.getDate();
  if (sameDay) {{
    return parsed.toLocaleTimeString([], {{ hour: 'numeric', minute: '2-digit' }});
  }}
  var sameYear = parsed.getFullYear() === now.getFullYear();
  return parsed.toLocaleString([], sameYear
    ? {{ month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }}
    : {{ year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }});
}}

function renderMarkdown(text) {{
  if (!text) return '';
  var svgs = [];
  text = text.replace(/<svg[\s\S]*?<\/svg>/gi, function(m) {{
    svgs.push(m);
    return '__SVG_' + (svgs.length - 1) + '__';
  }});
  text = text.replace(/```\w*\n\s*(__SVG_\d+__)\s*\n?```/g, '$1');
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
  var bigSvg = svg.cloneNode(true);
  bigSvg.removeAttribute('width');
  bigSvg.removeAttribute('height');
  bigSvg.onclick = function(e) {{ e.stopPropagation(); }};
  overlay.appendChild(bigSvg);
  document.body.appendChild(overlay);
}}

document.addEventListener('keydown', function(e) {{
  if (e.key === 'Escape') {{
    if (expandedTextEditorState) {{
      cancelExpandedTextEditor();
      return;
    }}
    var ov = document.querySelector('.svg-overlay');
    if (ov) ov.remove();
  }}
}});

function handleChatKey(e) {{
  if (!e || e.key !== 'Enter') return true;
  if (e.shiftKey || e.isComposing || e.keyCode === 229) return true;
  if (isMobileChatLayout()) return true;
  e.preventDefault();
  var form = e.target && e.target.form;
  if (form) {{
    if (typeof form.requestSubmit === 'function') {{
      form.requestSubmit();
    }} else {{
      form.dispatchEvent(new Event('submit', {{ bubbles: true, cancelable: true }}));
    }}
  }}
  return false;
}}

function applyExcludedChatMessage(data, messageId) {{
  if (!data) return;
  if (data.message) {{
    for (var i = 0; i < chatMessages.length; i++) {{
      if (chatMessageId(chatMessages[i]) === data.message.id) {{
        chatMessages[i].excluded_from_context = !!data.message.excluded_from_context;
        break;
      }}
    }}
  }}
  activeTurnUserId = data.active_turn_user_id || 0;
  syncQueuedFollowUpFlags(false);
  renderMessages();
  updateAgentListPreview(currentAgent, data.last_message || '', data.last_message_time || '');
}}

function toggleChatMessageContextExclusion(messageId, excluded) {{
  if (!messageId || chatMessageEditPending || !currentAgent) return false;
  var msg = findChatMessageById(messageId);
  if (!chatMessageCanMutate(msg)) return false;
  chatMessageEditPending = true;
  fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/message', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: 'csrf_token=' + encodeURIComponent(csrfToken)
      + '&message_id=' + encodeURIComponent(messageId)
      + '&excluded=' + encodeURIComponent(excluded ? 'true' : 'false')
  }})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      chatMessageEditPending = false;
      if (!data || !data.ok) throw new Error((data && data.error) || 'Failed to update message exclusion');
      applyExcludedChatMessage(data, messageId);
    }})
    .catch(function(err) {{
      chatMessageEditPending = false;
      alert(err && err.message ? err.message : 'Failed to update message exclusion');
    }});
  return false;
}}

function setChatMessageSwipeOffset(row, offset) {{
  if (!row) return;
  var clamped = Math.max(0, Math.min(CHAT_MESSAGE_SWIPE_REVEAL, offset || 0));
  row.style.setProperty('--chat-msg-swipe-offset', clamped + 'px');
  row.classList.toggle('chat-msg-row-swipe-visible', clamped > 0);
  row.classList.toggle('chat-msg-row-swipe-open', clamped >= CHAT_MESSAGE_SWIPE_REVEAL - 1);
}}

function closeChatSwipeRow(row) {{
  setChatMessageSwipeOffset(row, 0);
}}

function closeAllChatSwipeRows(exceptRow) {{
  var container = document.getElementById('chat-messages');
  if (!container) return;
  var rows = container.querySelectorAll('.chat-msg-row-swipe-visible[data-chat-msg-id]');
  rows.forEach(function(row) {{
    if (exceptRow && row === exceptRow) return;
    closeChatSwipeRow(row);
  }});
}}

function openChatSwipeRow(row) {{
  if (!row) return;
  closeAllChatSwipeRows(row);
  setChatMessageSwipeOffset(row, CHAT_MESSAGE_SWIPE_REVEAL);
}}

function clearChatMessageSwipeGesture() {{
  chatMessageSwipeGesture = null;
}}

function bindChatMessageMutationGestures() {{
  var container = document.getElementById('chat-messages');
  if (!container || container.dataset.messageMutationBound === '1') return;
  container.dataset.messageMutationBound = '1';

  container.addEventListener('contextmenu', function(e) {{
    var row = e.target && e.target.closest ? e.target.closest('.chat-msg-row[data-chat-msg-id]') : null;
    if (!row) return;
    e.preventDefault();
    var messageId = parseInt(row.getAttribute('data-chat-msg-id'), 10) || 0;
    var msg = findChatMessageById(messageId);
    if (!chatMessageCanMutate(msg)) return;
    toggleChatMessageContextExclusion(messageId, !msg.excluded_from_context);
  }});

  container.addEventListener('click', function(e) {{
    if (e.target && e.target.closest && e.target.closest('.chat-msg-swipe-action')) return;
    var row = e.target && e.target.closest ? e.target.closest('.chat-msg-row[data-chat-msg-id]') : null;
    if (!row || !row.classList.contains('chat-msg-row-swipe-open')) {{
      closeAllChatSwipeRows(null);
    }}
  }});

  container.addEventListener('pointerdown', function(e) {{
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    if (e.target && e.target.closest && e.target.closest('.chat-msg-swipe-action')) return;
    var row = e.target && e.target.closest ? e.target.closest('.chat-msg-row[data-chat-msg-id]') : null;
    if (!row) return;
    var messageId = parseInt(row.getAttribute('data-chat-msg-id'), 10) || 0;
    var msg = findChatMessageById(messageId);
    if (!chatMessageCanMutate(msg)) return;
    closeAllChatSwipeRows(row);
    chatMessageSwipeGesture = {{
      pointerId: e.pointerId,
      row: row,
      messageId: messageId,
      startX: e.clientX,
      startY: e.clientY,
      startOffset: row.classList.contains('chat-msg-row-swipe-open') ? CHAT_MESSAGE_SWIPE_REVEAL : 0,
      horizontal: false
    }};
    if (row.setPointerCapture) {{
      try {{ row.setPointerCapture(e.pointerId); }} catch (_err) {{}}
    }}
  }});

  container.addEventListener('pointermove', function(e) {{
    if (!chatMessageSwipeGesture || chatMessageSwipeGesture.pointerId !== e.pointerId) return;
    var dx = e.clientX - chatMessageSwipeGesture.startX;
    var dy = e.clientY - chatMessageSwipeGesture.startY;
    if (!chatMessageSwipeGesture.horizontal) {{
      if (Math.abs(dx) < 8 && Math.abs(dy) < 8) return;
      if (Math.abs(dy) >= Math.abs(dx)) {{
        closeChatSwipeRow(chatMessageSwipeGesture.row);
        clearChatMessageSwipeGesture();
        return;
      }}
      chatMessageSwipeGesture.horizontal = true;
    }}
    var nextOffset = chatMessageSwipeGesture.startOffset - dx;
    setChatMessageSwipeOffset(chatMessageSwipeGesture.row, nextOffset);
    e.preventDefault();
  }});

  function finishChatMessageSwipe(e, cancelled) {{
    if (!chatMessageSwipeGesture) return;
    if (e && chatMessageSwipeGesture.pointerId !== e.pointerId) return;
    var gesture = chatMessageSwipeGesture;
    clearChatMessageSwipeGesture();
    if (gesture.row && gesture.row.releasePointerCapture && e) {{
      try {{ gesture.row.releasePointerCapture(e.pointerId); }} catch (_err) {{}}
    }}
    if (cancelled || !gesture.horizontal) {{
      if (!gesture.row.classList.contains('chat-msg-row-swipe-open')) {{
        closeChatSwipeRow(gesture.row);
      }}
      return;
    }}
    var msg = findChatMessageById(gesture.messageId);
    var offsetValue = parseFloat((gesture.row.style.getPropertyValue('--chat-msg-swipe-offset') || '0').replace('px', '')) || 0;
    if (offsetValue >= CHAT_MESSAGE_SWIPE_TOGGLE_THRESHOLD && msg) {{
      closeChatSwipeRow(gesture.row);
      toggleChatMessageContextExclusion(gesture.messageId, !msg.excluded_from_context);
      return;
    }}
    if (offsetValue >= CHAT_MESSAGE_SWIPE_OPEN_THRESHOLD) {{
      openChatSwipeRow(gesture.row);
    }} else {{
      closeChatSwipeRow(gesture.row);
    }}
  }}

  container.addEventListener('pointerup', function(e) {{
    finishChatMessageSwipe(e, false);
  }});
  container.addEventListener('pointercancel', function(e) {{
    finishChatMessageSwipe(e, true);
  }});
  container.addEventListener('scroll', function() {{
    closeAllChatSwipeRows(null);
    clearChatMessageSwipeGesture();
  }}, {{ passive: true }});
}}

function setChatSendPending(pending) {{
  chatSendInFlight = !!pending;
  var input = document.getElementById('chat-input');
  var sendBtn = document.querySelector('#chat-input-form .chat-send-btn');
  if (input) input.disabled = chatSendInFlight;
  if (sendBtn) sendBtn.disabled = chatSendInFlight;
}}

function shouldRetryChatSendStatus(status) {{
  return status === 408 || status === 425 || status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}}

function insertOrReconcileConfirmedUserMessage(message) {{
  if (!message || !message.id) return;
  for (var i = chatMessages.length - 1; i >= 0; i--) {{
    var userMsg = chatMessages[i];
    if (!userMsg || userMsg.role !== 'user') continue;
    if (chatMessageId(userMsg) === message.id) {{
      userMsg.content = message.content || '';
      userMsg.queued_follow_up = message.id > activeTurnUserId;
      return;
    }}
    if (!chatMessageId(userMsg) && userMsg.content === (message.content || '')) {{
      userMsg._id = message.id;
      userMsg.content = message.content || '';
      userMsg.queued_follow_up = message.id > activeTurnUserId;
      return;
    }}
  }}
  insertChatMessage({{
    role: 'user',
    content: message.content || '',
    _id: message.id,
    queued_follow_up: message.id > activeTurnUserId
  }});
}}

function handleChatSendSuccess(agentName, text, message) {{
  setChatSendPending(false);
  setChatDraft(agentName, '');
  clearChatSendToken(agentName);
  moveAgentItemToTop(agentName);
  updateAgentListPreview(agentName, text);
  if (currentAgent === agentName) {{
    var input = document.getElementById('chat-input');
    if (input) {{
      input.value = '';
      resizeChatInput();
    }}
    insertOrReconcileConfirmedUserMessage(message);
    renderMessages();
  }}
}}

function handleChatSendFailure(agentName, text, errorMessage) {{
  setChatSendPending(false);
  setChatDraft(agentName, text);
  if (currentAgent === agentName) {{
    var input = document.getElementById('chat-input');
    if (input && input.value !== text) {{
      input.value = text;
      resizeChatInput();
    }}
    insertChatMessage({{ role: 'system', content: errorMessage }});
    renderMessages();
  }}
}}

function sendMessageRequest(agentName, text, clientMessageId, attempt) {{
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/ui/chat/' + encodeURIComponent(agentName) + '/send');
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.timeout = 15000;
  xhr.onerror = function() {{
    if (attempt < chatSendMaxAttempts) {{
      window.setTimeout(function() {{
        sendMessageRequest(agentName, text, clientMessageId, attempt + 1);
      }}, attempt * 800);
      return;
    }}
    handleChatSendFailure(agentName, text, 'Failed to send message after retrying (network error)');
  }};
  xhr.ontimeout = function() {{
    if (attempt < chatSendMaxAttempts) {{
      window.setTimeout(function() {{
        sendMessageRequest(agentName, text, clientMessageId, attempt + 1);
      }}, attempt * 800);
      return;
    }}
    handleChatSendFailure(agentName, text, 'Failed to send message after retrying (request timed out)');
  }};
  xhr.onload = function() {{
    if (xhr.status !== 200) {{
      if (attempt < chatSendMaxAttempts && shouldRetryChatSendStatus(xhr.status)) {{
        window.setTimeout(function() {{
          sendMessageRequest(agentName, text, clientMessageId, attempt + 1);
        }}, attempt * 800);
        return;
      }}
      handleChatSendFailure(agentName, text, 'Failed to send message (HTTP ' + xhr.status + ')');
      return;
    }}
    var message = null;
    try {{
      var resp = JSON.parse(xhr.responseText);
      if (resp && resp.message) message = resp.message;
    }} catch (err) {{}}
    handleChatSendSuccess(agentName, text, message);
  }};
  xhr.send(
    'csrf_token=' + encodeURIComponent(csrfToken) +
    '&message=' + encodeURIComponent(text) +
    '&client_message_id=' + encodeURIComponent(clientMessageId)
  );
}}

function sendMessage(e) {{
  e.preventDefault();
  if (chatSendInFlight) return false;
  var agentName = currentAgent;
  var input = document.getElementById('chat-input');
  if (!input) return false;
  var text = input.value.trim();
  if (!text) return false;

  // Slash commands go to the command endpoint
  if (text.startsWith('/')) {{
    setChatDraft(currentAgent, '');
    input.value = '';
    resizeChatInput();
    chatFollowScroll = true;
    moveAgentItemToTop(currentAgent);
    updateAgentListPreview(currentAgent, text);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/ui/chat/' + encodeURIComponent(currentAgent) + '/command');
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {{
      try {{
        var resp = JSON.parse(xhr.responseText);
        if (resp.action === 'clear') {{
          chatMessages = [];
          renderMessages();
        }} else if (resp.response) {{
          insertChatMessage({{ role: 'system', content: resp.response }});
          renderMessages();
        }}
      }} catch(err) {{}}
    }};
    xhr.send('csrf_token=' + encodeURIComponent(csrfToken) + '&command=' + encodeURIComponent(text));
    return false;
  }}

  chatFollowScroll = true;
  setChatSendPending(true);
  sendMessageRequest(agentName, text, resolveChatSendToken(agentName, text), 1);
  return false;
}}

function updateHeaderStatus() {{
  var statusEl = document.getElementById('chat-agent-status');
  var metaEl = document.getElementById('chat-agent-cwd');
  if (!statusEl && !metaEl) return;
  var parts = [];
  if (agentConfig.backend) {{
    parts.push(agentConfig.backend);
    parts.push(agentConfig.model || 'default');
    if (backendEfforts[agentConfig.backend] && backendEfforts[agentConfig.backend].length > 0) {{
      parts.push(agentConfig.effort || 'default');
    }}
  }}
  var folder = metaEl && metaEl.dataset ? (metaEl.dataset.folder || '') : '';
  if (folder) parts.push(folder);
  if (metaEl) metaEl.textContent = parts.join(' \u00b7 ');
  var statusClass = chatStatusClass(agentStatus);
  var useManagerGlyph = shouldUseManagerGlyph(currentAgent, statusClass);
  var statusTitle = agentStatus === 'idle' ? 'Finished' : agentStatus === 'thinking' ? 'Working' : agentStatus === 'restarting' ? 'Restarting' : 'Stopped';
  var glyphHtml = useManagerGlyph
    ? '{ICON_MANAGER}'
    : agentStatus === 'idle'
    ? '{ICON_STATUS_DONE}'
    : agentStatus === 'thinking'
    ? '{ICON_STATUS_WORKING}'
    : agentStatus === 'restarting'
    ? '{ICON_RESTART}'
    : '{ICON_STATUS_STOPPED}';
  if (statusEl) statusEl.innerHTML = '<span class="chat-status-glyph ' + statusClass + '" title="' + statusTitle + '">' + glyphHtml + '</span>';
}}

function shouldUseManagerGlyph(agent, statusClass) {{
  if (statusClass !== 'chat-status-working' || !agent) return false;
  var item = document.querySelector('.chat-agent-item[data-agent="' + CSS.escape(agent) + '"]');
  if (item && item.dataset && item.dataset.manageEnabled === 'true') return true;
  return !!(
    agent === currentAgent &&
    manageConfigData &&
    manageConfigData.enabled
  );
}}

function chatStatusClass(status) {{
  if (status === 'idle') return 'chat-status-running';
  if (status === 'thinking') return 'chat-status-working';
  if (status === 'restarting') return 'chat-status-restarting';
  return 'chat-status-stopped';
}}

function updateAgentListStatus(agent, status) {{
  if (!agent) return;
  var item = document.querySelector('.chat-agent-item[data-agent="' + CSS.escape(agent) + '"]');
  if (!item) return;
  var glyph = item.querySelector('.chat-status-glyph');
  if (!glyph) return;
  glyph.classList.remove('chat-status-running', 'chat-status-working', 'chat-status-restarting', 'chat-status-stopped');
  var statusClass = chatStatusClass(status);
  glyph.classList.add(statusClass);
  var useManagerGlyph = shouldUseManagerGlyph(agent, statusClass);
  if (status === 'idle') {{
    glyph.title = 'Finished';
    glyph.innerHTML = '{ICON_STATUS_DONE}';
  }} else if (status === 'thinking') {{
    glyph.title = 'Working';
    glyph.innerHTML = useManagerGlyph ? '{ICON_MANAGER}' : '{ICON_STATUS_WORKING}';
  }} else if (status === 'restarting') {{
    glyph.title = 'Restarting';
    glyph.innerHTML = '{ICON_RESTART}';
  }} else {{
    glyph.title = 'Stopped';
    glyph.innerHTML = '{ICON_STATUS_STOPPED}';
  }}
}}

function maybeAppendFinishedMessage() {{
  var lastIdx = findLastNonQueuedMessageIndex();
  var lastMsg = lastIdx >= 0 ? chatMessages[lastIdx] : null;
  if (lastMsg && lastMsg.role === 'system' && lastMsg.content === '\u2705 Finished') return false;
  insertChatMessage({{ role: 'system', content: '\u2705 Finished' }});
  return true;
}}

function maybeRemoveFinishedMessage() {{
  for (var i = chatMessages.length - 1; i >= 0; i--) {{
    var msg = chatMessages[i];
    if (msg.role === 'system' && msg.content === '\u2705 Finished') {{
      chatMessages.splice(i, 1);
      break;
    }}
  }}
}}

function markAgentActivity(agent) {{
  maybeRemoveFinishedMessage();
  updateAgentListStatus(agent, 'thinking');
  if (agent === currentAgent) {{
    agentStatus = 'thinking';
    updateHeaderStatus();
  }}
}}

function chatMessageId(msg) {{
  if (!msg) return 0;
  var id = msg._id || msg.id || 0;
  if (typeof id === 'string') id = parseInt(id, 10);
  return Number.isFinite(id) ? id : 0;
}}

function chatMessageStableKey(msg) {{
  var id = chatMessageId(msg);
  return id > 0 ? ('id:' + id) : '';
}}

function mergeChatMessagesPreservingVisibleOrder(existingMessages, incomingMessages) {{
  if (!Array.isArray(incomingMessages) || !incomingMessages.length) return incomingMessages || [];
  if (!Array.isArray(existingMessages) || !existingMessages.length) return incomingMessages;
  var incomingByKey = {{}};
  for (var i = 0; i < incomingMessages.length; i++) {{
    var key = chatMessageStableKey(incomingMessages[i]);
    if (key) incomingByKey[key] = incomingMessages[i];
  }}
  var merged = [];
  var used = {{}};
  for (var j = 0; j < existingMessages.length; j++) {{
    var existingKey = chatMessageStableKey(existingMessages[j]);
    if (!existingKey || !incomingByKey[existingKey]) continue;
    var next = Object.assign({{}}, existingMessages[j], incomingByKey[existingKey]);
    merged.push(next);
    used[existingKey] = true;
  }}
  for (var k = 0; k < incomingMessages.length; k++) {{
    var incomingKey = chatMessageStableKey(incomingMessages[k]);
    if (!incomingKey || !used[incomingKey]) {{
      merged.push(incomingMessages[k]);
      if (incomingKey) used[incomingKey] = true;
    }}
  }}
  return merged;
}}

function chatMessageCanMutate(msg) {{
  if (!msg || msg._thinking) return false;
  if (msg.role !== 'user') return false;
  return chatMessageId(msg) > 0;
}}

function findChatMessageById(messageId) {{
  for (var i = 0; i < chatMessages.length; i++) {{
    if (chatMessageId(chatMessages[i]) === messageId) return chatMessages[i];
  }}
  return null;
}}

function isQueuedFollowUpUserMessage(msg) {{
  if (!msg || msg.role !== 'user') return false;
  var id = chatMessageId(msg);
  if (id > 0) return id > activeTurnUserId;
  return !!msg.queued_follow_up;
}}

function hasQueuedFollowUpUserMessages() {{
  for (var i = 0; i < chatMessages.length; i++) {{
    if (isQueuedFollowUpUserMessage(chatMessages[i])) return true;
  }}
  return false;
}}

function syncQueuedFollowUpFlags(promoteOptimisticQueued) {{
  if (!chatMessages || !chatMessages.length) return false;
  var changed = false;
  for (var i = 0; i < chatMessages.length; i++) {{
    var msg = chatMessages[i];
    if (!msg || msg.role !== 'user') continue;
    var id = chatMessageId(msg);
    var nextQueued = id > 0 ? id > activeTurnUserId : (!!msg.queued_follow_up && !promoteOptimisticQueued);
    if (!!msg.queued_follow_up !== nextQueued) {{
      msg.queued_follow_up = nextQueued;
      changed = true;
    }}
  }}
  return changed;
}}

function insertChatMessage(msg) {{
  var insertAt = chatMessages.length;
  if (!isQueuedFollowUpUserMessage(msg)) {{
    while (insertAt > 0 && isQueuedFollowUpUserMessage(chatMessages[insertAt - 1])) {{
      insertAt -= 1;
    }}
  }}
  chatMessages.splice(insertAt, 0, msg);
  return msg;
}}

function findLastNonQueuedMessageIndex() {{
  for (var i = chatMessages.length - 1; i >= 0; i--) {{
    if (!isQueuedFollowUpUserMessage(chatMessages[i])) return i;
  }}
  return -1;
}}

function normalizeChatMessageOrder() {{
  if (!chatMessages || !chatMessages.length) return;
  var main = [];
  var pending = [];
  var finished = null;
  for (var i = 0; i < chatMessages.length; i++) {{
    var msg = chatMessages[i];
    if (msg.role === 'system' && msg.content === '\u2705 Finished') {{
      finished = msg;
      continue;
    }}
    if (isQueuedFollowUpUserMessage(msg)) {{
      pending.push(msg);
    }} else {{
      main.push(msg);
    }}
  }}
  pending.sort(function(a, b) {{
    var aId = chatMessageId(a);
    var bId = chatMessageId(b);
    if (aId > 0 && bId > 0 && aId !== bId) return aId - bId;
    if (aId > 0 && bId === 0) return -1;
    if (aId === 0 && bId > 0) return 1;
    return 0;
  }});
  chatMessages = main;
  if (finished) chatMessages.push(finished);
  Array.prototype.push.apply(chatMessages, pending);
}}

function updateCachedChatPanelFromEvent(evt) {{
  if (!evt || !evt.agent || evt.agent === currentAgent) return;
  var cached = chatPanelCache[evt.agent];
  if (!cached) return;
  var savedMessages = chatMessages;
  var savedActiveTurnUserId = activeTurnUserId;
  var savedAgentStatus = agentStatus;
  var savedStreamingContent = streamingContent;
  chatMessages = cached.messages || [];
  activeTurnUserId = cached.active_turn_user_id || 0;
  agentStatus = cached.agent_status || '';
  streamingContent = cached.streaming_content || '';
  try {{
    if (evt.event_type === 'message_sent' || (evt.event_type === 'message' && evt.data && evt.data.role === 'user')) {{
      insertOrReconcileConfirmedUserMessage(evt.data || {{}});
    }} else if (evt.event_type === 'message' && evt.data && evt.data.role === 'error') {{
      agentStatus = 'thinking';
      maybeRemoveFinishedMessage();
      var updated = false;
      for (var mi = chatMessages.length - 1; mi >= 0; mi--) {{
        if (chatMessages[mi]._id === evt.data.id) {{
          chatMessages[mi].content = evt.data.content;
          updated = true;
          break;
        }}
      }}
      if (!updated) insertChatMessage({{ role: 'error', content: evt.data.content, _id: evt.data.id }});
    }} else if (evt.event_type === 'message' && evt.data && evt.data.role === 'assistant') {{
      agentStatus = 'thinking';
      maybeRemoveFinishedMessage();
      var lastIdx = findLastNonQueuedMessageIndex();
      var lastMsg = lastIdx >= 0 ? chatMessages[lastIdx] : null;
      if (lastMsg && lastMsg.role === 'assistant' && lastMsg.streaming) {{
        lastMsg.streaming = false;
        if (!lastMsg.content) chatMessages.splice(lastIdx, 1);
      }}
      streamingContent = '';
      insertChatMessage({{ role: 'assistant', content: evt.data.content || '', _id: evt.data.id }});
    }} else if (evt.event_type === 'tool_use') {{
      agentStatus = 'thinking';
      maybeRemoveFinishedMessage();
      var detail = '\u{{1F527}} ' + evt.data.detail;
      var toolIdx = findLastNonQueuedMessageIndex();
      var toolMsg = toolIdx >= 0 ? chatMessages[toolIdx] : null;
      if (toolMsg && toolMsg.role === 'tool') {{
        var lines = toolMsg.content.split('\n');
        var prevLine = lines[lines.length - 1];
        var prevMatch = prevLine.match(/^(.+?)( \(x(\d+)\))?$/);
        if (prevMatch && prevMatch[1] === detail) {{
          var count = prevMatch[3] ? parseInt(prevMatch[3]) + 1 : 2;
          lines[lines.length - 1] = detail + ' (x' + count + ')';
          toolMsg.content = lines.join('\n');
        }} else {{
          toolMsg.content += '\n' + detail;
        }}
      }} else {{
        insertChatMessage({{ role: 'tool', content: detail }});
      }}
    }} else if (evt.event_type === 'chunk') {{
      agentStatus = 'thinking';
      maybeRemoveFinishedMessage();
      streamingContent += evt.data.text || '';
      var chunkIdx = findLastNonQueuedMessageIndex();
      var chunkMsg = chunkIdx >= 0 ? chatMessages[chunkIdx] : null;
      if (chunkMsg && chunkMsg.role === 'assistant' && chunkMsg.streaming) {{
        chunkMsg.content = streamingContent;
      }} else {{
        insertChatMessage({{ role: 'assistant', content: streamingContent, streaming: true }});
      }}
    }} else if (evt.event_type === 'response_complete') {{
      var responseIdx = findLastNonQueuedMessageIndex();
      var responseMsg = responseIdx >= 0 ? chatMessages[responseIdx] : null;
      if (responseMsg && responseMsg.streaming) {{
        responseMsg.streaming = false;
        responseMsg.content = evt.data.content || responseMsg.content;
      }} else if (evt.data && evt.data.content) {{
        insertChatMessage({{ role: 'assistant', content: evt.data.content, _id: evt.data.id }});
      }}
      streamingContent = '';
    }} else if (evt.event_type === 'auto_message') {{
      insertChatMessage({{ role: 'user', content: evt.data.content }});
    }} else if (evt.event_type === 'command_response') {{
      insertChatMessage({{ role: 'system', content: evt.data.response }});
    }} else if (evt.event_type === 'status') {{
      var prevActiveTurnUserId = activeTurnUserId;
      agentStatus = evt.data && evt.data.status ? evt.data.status : '';
      if (evt.data && typeof evt.data.active_turn_user_id !== 'undefined') {{
        activeTurnUserId = evt.data.active_turn_user_id || 0;
      }}
      var activeTurnAdvancedWhileThinking = agentStatus === 'thinking' && activeTurnUserId > prevActiveTurnUserId;
      syncQueuedFollowUpFlags(activeTurnAdvancedWhileThinking);
      if (agentStatus === 'idle') {{
        maybeAppendFinishedMessage();
      }} else {{
        maybeRemoveFinishedMessage();
      }}
    }}
    normalizeChatMessageOrder();
    cached.messages = chatMessages;
    cached.active_turn_user_id = activeTurnUserId;
    cached.agent_status = agentStatus;
    cached.streaming_content = streamingContent;
    cached.cached_at = Date.now();
    touchChatPanelCache(evt.agent);
  }} finally {{
    chatMessages = savedMessages;
    activeTurnUserId = savedActiveTurnUserId;
    agentStatus = savedAgentStatus;
    streamingContent = savedStreamingContent;
  }}
}}

function connectSSE() {{
  if (eventSource) eventSource.close();
  eventSource = new EventSource('/ui/chat/stream');
  markChatStreamAlive();
  eventSource.onopen = function() {{
    markChatStreamAlive();
  }};
  eventSource.addEventListener('heartbeat', function() {{
    markChatStreamAlive();
  }});
  eventSource.onmessage = function(e) {{
    try {{
      markChatStreamAlive();
      var evt = JSON.parse(e.data);
      if (evt.event_type === 'message_sent' || (evt.event_type === 'message' && evt.data && evt.data.role === 'user')) {{
        moveAgentItemToTop(evt.agent);
        updateAgentListPreview(
          evt.agent,
          evt.data && evt.data.content ? evt.data.content : '',
          sidebarTimeNow()
        );
        if (evt.agent === currentAgent && evt.data) {{
          insertOrReconcileConfirmedUserMessage(evt.data);
          renderMessages();
        }}
      }} else if (evt.event_type === 'message' && evt.data) {{
        updateAgentListPreview(evt.agent, evt.data.content || '');
      }} else if (evt.event_type === 'response_complete' && evt.data && evt.data.content) {{
        updateAgentListPreview(evt.agent, evt.data.content);
      }} else if (evt.event_type === 'status') {{
        updateAgentListStatus(evt.agent, evt.data && evt.data.status ? evt.data.status : '');
      }}
      if (evt.agent !== currentAgent) {{
        updateCachedChatPanelFromEvent(evt);
        return;
      }}
      if (evt.event_type === 'message' && evt.data && evt.data.role === 'error') {{
        markAgentActivity(evt.agent);
        var updated = false;
        for (var mi = chatMessages.length - 1; mi >= 0; mi--) {{
          if (chatMessages[mi]._id === evt.data.id) {{
            chatMessages[mi].content = evt.data.content;
            updated = true;
            break;
          }}
        }}
        if (!updated) {{
          insertChatMessage({{ role: 'error', content: evt.data.content, _id: evt.data.id }});
        }}
        renderMessages();
        if (typeof refreshErrorsPanel === 'function') refreshErrorsPanel();
      }} else if (evt.event_type === 'message' && evt.data && evt.data.role === 'assistant') {{
        markAgentActivity(evt.agent);
        var lastIdx = findLastNonQueuedMessageIndex();
        var lastMsg = lastIdx >= 0 ? chatMessages[lastIdx] : null;
        if (lastMsg && lastMsg.role === 'assistant' && lastMsg.streaming) {{
          lastMsg.streaming = false;
          if (!lastMsg.content) chatMessages.splice(lastIdx, 1);
        }}
        streamingContent = '';
        insertChatMessage({{ role: 'assistant', content: evt.data.content || '', _id: evt.data.id }});
        renderMessages();
      }} else if (evt.event_type === 'tool_use') {{
        markAgentActivity(evt.agent);
        var detail = '\u{{1F527}} ' + evt.data.detail;
        var lastIdx = findLastNonQueuedMessageIndex();
        var lastMsg = lastIdx >= 0 ? chatMessages[lastIdx] : null;
        if (lastMsg && lastMsg.role === 'tool') {{
          var lines = lastMsg.content.split('\n');
          var prevLine = lines[lines.length - 1];
          var prevMatch = prevLine.match(/^(.+?)( \(x(\d+)\))?$/);
          if (prevMatch && prevMatch[1] === detail) {{
            var count = prevMatch[3] ? parseInt(prevMatch[3]) + 1 : 2;
            lines[lines.length - 1] = detail + ' (x' + count + ')';
            lastMsg.content = lines.join('\n');
          }} else {{
            lastMsg.content += '\n' + detail;
          }}
        }} else {{
          insertChatMessage({{ role: 'tool', content: detail }});
        }}
        renderMessages();
      }} else if (evt.event_type === 'chunk') {{
        markAgentActivity(evt.agent);
        streamingContent += evt.data.text || '';
        var lastIdx = findLastNonQueuedMessageIndex();
        var lastMsg = lastIdx >= 0 ? chatMessages[lastIdx] : null;
        if (lastMsg && lastMsg.role === 'assistant' && lastMsg.streaming) {{
          lastMsg.content = streamingContent;
        }} else {{
          insertChatMessage({{ role: 'assistant', content: streamingContent, streaming: true }});
        }}
        renderMessages();
      }} else if (evt.event_type === 'response_complete') {{
        var lastIdx = findLastNonQueuedMessageIndex();
        var lastMsg = lastIdx >= 0 ? chatMessages[lastIdx] : null;
        if (lastMsg && lastMsg.streaming) {{
          lastMsg.streaming = false;
          lastMsg.content = evt.data.content || lastMsg.content;
        }} else if (evt.data && evt.data.content) {{
          insertChatMessage({{
            role: 'assistant',
            content: evt.data.content,
            _id: evt.data.id
          }});
        }}
        streamingContent = '';
        renderMessages();
      }} else if (evt.event_type === 'auto_message') {{
        insertChatMessage({{ role: 'user', content: evt.data.content }});
        renderMessages();
      }} else if (evt.event_type === 'command_response') {{
        insertChatMessage({{ role: 'system', content: evt.data.response }});
        renderMessages();
      }} else if (evt.event_type === 'config_info') {{
        agentConfig.backend = evt.data.backend || '';
        agentConfig.model = evt.data.model || '';
        agentConfig.effort = evt.data.effort || '';
        updateHeaderStatus();
      }} else if (evt.event_type === 'status') {{
        var prevStatus = agentStatus;
        var prevActiveTurnUserId = activeTurnUserId;
        agentStatus = evt.data.status || '';
        if (evt.data && typeof evt.data.active_turn_user_id !== 'undefined') {{
          activeTurnUserId = evt.data.active_turn_user_id || 0;
        }}
        var activeTurnAdvancedWhileThinking =
          agentStatus === 'thinking' && activeTurnUserId > prevActiveTurnUserId;
        var queueStateChanged = syncQueuedFollowUpFlags(activeTurnAdvancedWhileThinking);
        updateHeaderStatus();
        if (agentStatus === 'idle') {{
          var appendedFinished = maybeAppendFinishedMessage();
          if (queueStateChanged || prevStatus !== agentStatus || prevActiveTurnUserId !== activeTurnUserId || appendedFinished) {{
            renderMessages();
          }}
        }} else {{
          maybeRemoveFinishedMessage();
          if (queueStateChanged || prevStatus !== agentStatus || prevActiveTurnUserId !== activeTurnUserId) {{
            renderMessages();
          }}
        }}
        if (evt.data.cwd) {{
          var cwdEl = document.getElementById('chat-agent-cwd');
          if (cwdEl) {{
            var parts = evt.data.cwd.split(/[\/\\\\]/).filter(function(s){{ return s.length > 0; }});
            cwdEl.dataset.folder = parts.length ? parts[parts.length - 1] : '';
            updateHeaderStatus();
          }}
        }}
      }}
    }} catch(err) {{}}
  }};
  eventSource.onerror = function() {{
    setTimeout(connectSSE, 3000);
  }};
}}

// No custom swipe handler on mobile — let the OS/browser handle back navigation

var chatConfigOpen = false;
var chatManageOpen = false;
var chatConfigData = null;
var manageConfigData = null;
var configSaveTimer = null;
var manageSaveTimer = null;
var chatMessageEditPending = false;
var chatMessageSwipeGesture = null;
var CHAT_MESSAGE_SWIPE_REVEAL = 44;
var CHAT_MESSAGE_SWIPE_OPEN_THRESHOLD = 14;
var CHAT_MESSAGE_SWIPE_TOGGLE_THRESHOLD = 30;

var backendModels = {{
  claude: ['default', 'opus', 'sonnet', 'haiku'],
  agy: ['default'],
  codex: ['default', 'gpt-5.5', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-5.3-codex', 'gpt-5.3-codex-spark', 'gpt-5.2'],
  openai: ['default']
}};

var backendEfforts = {{
  claude: ['default', 'low', 'medium', 'high', 'max'],
  agy: [],
  codex: ['default', 'minimal', 'low', 'medium', 'high', 'xhigh'],
  openai: []
}};

var backendLabels = {{
  claude: 'Claude',
  agy: 'Antigravity',
  codex: 'Codex',
  openai: 'OpenAI'
}};

function closeAllPanels() {{
  cancelExpandedTextEditor();
  var msgsWrap = document.getElementById('chat-messages-wrap');
  var form = document.getElementById('chat-input-form');
  var cfg = document.getElementById('chat-config-panel');
  var mgr = document.getElementById('chat-manage-panel');
  var cfgBtn = document.getElementById('chat-config-btn');
  var mgrBtn = document.getElementById('chat-manage-btn');
  if (msgsWrap) msgsWrap.style.display = '';
  if (form) form.style.display = '';
  if (cfg) cfg.style.display = 'none';
  if (mgr) mgr.style.display = 'none';
  if (cfgBtn) cfgBtn.classList.remove('active');
  if (mgrBtn) mgrBtn.classList.remove('active');
  chatConfigOpen = false;
  chatManageOpen = false;
  updateChatJumpButton();
}}

function toggleChatConfig() {{
  if (chatConfigOpen) {{ closeAllPanels(); return; }}
  closeAllPanels();
  var msgsWrap = document.getElementById('chat-messages-wrap');
  var cfg = document.getElementById('chat-config-panel');
  var btn = document.getElementById('chat-config-btn');
  var form = document.getElementById('chat-input-form');
  if (!msgsWrap || !cfg) return;
  chatConfigOpen = true;
  msgsWrap.style.display = 'none';
  cfg.style.display = '';
  if (form) form.style.display = 'none';
  if (btn) btn.classList.add('active');
  updateChatJumpButton();
  if (!isLibrarian) {{ loadChatConfig(); }}
}}

function toggleManagePanel() {{
  if (chatManageOpen) {{ closeAllPanels(); return; }}
  closeAllPanels();
  var msgsWrap = document.getElementById('chat-messages-wrap');
  var mgr = document.getElementById('chat-manage-panel');
  var btn = document.getElementById('chat-manage-btn');
  var form = document.getElementById('chat-input-form');
  if (!msgsWrap || !mgr) return;
  chatManageOpen = true;
  msgsWrap.style.display = 'none';
  mgr.style.display = '';
  if (form) form.style.display = 'none';
  if (btn) btn.classList.add('active');
  updateChatJumpButton();
  loadManageConfig();
}}

function loadChatConfig() {{
  fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/config', {{ cache: 'no-store' }})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      chatConfigData = data;
      applyBackendModelOptions(data.model_options);
      populateConfigDropdowns(data.backend, data.prefs);
      var ta = document.getElementById('cfg-pinned-context');
      if (ta) ta.value = data.pinned_context || '';
      var pctx = data.project_context || '';
      var pfield = document.getElementById('cfg-project-context-field');
      var pta = document.getElementById('cfg-project-context');
      if (pfield && pta) {{
        if (pctx) {{
          pfield.style.display = 'flex';
          pta.value = pctx;
        }} else {{
          pfield.style.display = 'none';
          pta.value = '';
        }}
      }}
    }});
  refreshErrorsPanel();
}}

function normalizeModelOptions(models) {{
  var seen = {{}};
  var normalized = [];
  function add(model) {{
    if (!model || typeof model !== 'string') return;
    if (seen[model]) return;
    seen[model] = true;
    normalized.push(model);
  }}
  add('default');
  if (Array.isArray(models)) {{
    for (var i = 0; i < models.length; i++) add(models[i]);
  }}
  return normalized;
}}

function applyBackendModelOptions(options) {{
  if (!options || typeof options !== 'object') return;
  Object.keys(options).forEach(function(backend) {{
    backendModels[backend] = normalizeModelOptions(options[backend]);
  }});
}}

function refreshErrorsPanel() {{
  if (!currentAgent || isLibrarian) return;
  var list = document.getElementById('cfg-errors-list');
  var countEl = document.getElementById('cfg-errors-count');
  if (!list) return;
  fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/errors', {{ cache: 'no-store' }})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      var records = (data && data.records) || [];
      if (countEl) countEl.textContent = records.length ? '(' + records.length + ')' : '';
      if (records.length === 0) {{
        list.innerHTML = '<div class="chat-errors-empty">No errors in the last 3 days.</div>';
        return;
      }}
      var html = '';
      for (var i = 0; i < records.length; i++) {{
        var r = records[i];
        var ts = r.ts || '';
        var cat = r.category || 'error';
        var detail = r.detail || '';
        var status = r.status_code ? ('HTTP ' + r.status_code) : '';
        var endpoint = r.endpoint_id ? ('endpoint ' + r.endpoint_id) : '';
        var meta = [ts, cat, status, endpoint].filter(function(s){{ return s && s.length; }}).join(' \u2022 ');
        html += '<div class="chat-errors-row">';
        html += '<div class="chat-errors-meta">' + escapeHtmlRaw(meta) + '</div>';
        html += '<div class="chat-errors-detail">' + escapeHtmlRaw(detail) + '</div>';
        if (r.preview_request || r.preview_response) {{
          html += '<details class="chat-errors-preview"><summary>details</summary>';
          if (r.preview_request) html += '<pre><code>request: ' + escapeHtmlRaw(r.preview_request) + '</code></pre>';
          if (r.preview_response) html += '<pre><code>response: ' + escapeHtmlRaw(r.preview_response) + '</code></pre>';
          html += '</details>';
        }}
        html += '</div>';
      }}
      list.innerHTML = html;
    }})
    .catch(function() {{
      if (countEl) countEl.textContent = '';
      list.innerHTML = '<div class="chat-errors-empty">Failed to load errors.</div>';
    }});
}}

var pinnedSaveTimer = null;
function onPinnedContextChange() {{
  if (pinnedSaveTimer) clearTimeout(pinnedSaveTimer);
  pinnedSaveTimer = setTimeout(savePinnedContext, 600);
}}

function savePinnedContext() {{
  var ta = document.getElementById('cfg-pinned-context');
  if (!ta) return;
  var body = 'csrf_token=' + encodeURIComponent(csrfToken)
    + '&pinned_context=' + encodeURIComponent(ta.value);
  fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/config', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: body
  }});
}}

function loadManageConfig() {{
  fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/manage', {{ cache: 'no-store' }})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      manageConfigData = data;
      var bSel = document.getElementById('mgr-backend');
      if (bSel) {{
        bSel.innerHTML = '';
        var cliBackends = ['claude', 'agy', 'codex'];
        var hasEndpoints = data.endpoints && data.endpoints.length > 0;
        var selectedBackend = data.backend || '';
        var selectedEndpoint = data.endpoint_id || '';
        var cliGroup = document.createElement('optgroup');
        cliGroup.label = 'CLI';
        for (var i = 0; i < cliBackends.length; i++) {{
          var opt = document.createElement('option');
          opt.value = 'cli:' + cliBackends[i];
          opt.textContent = backendLabels[cliBackends[i]] || (cliBackends[i].charAt(0).toUpperCase() + cliBackends[i].slice(1));
          if (!selectedEndpoint && selectedBackend === cliBackends[i]) opt.selected = true;
          cliGroup.appendChild(opt);
        }}
        bSel.appendChild(cliGroup);
        if (hasEndpoints) {{
          var epGroup = document.createElement('optgroup');
          epGroup.label = 'Endpoints';
          var eps = data.endpoints;
          for (var j = 0; j < eps.length; j++) {{
            var eopt = document.createElement('option');
            eopt.value = 'ep:' + eps[j].id;
            eopt.textContent = eps[j].name + ' (' + eps[j].model + ')';
            if (selectedEndpoint === eps[j].id) eopt.selected = true;
            epGroup.appendChild(eopt);
          }}
          bSel.appendChild(epGroup);
        }}
        if (!selectedBackend && !selectedEndpoint) bSel.selectedIndex = 0;
      }}
      var goals = document.getElementById('mgr-goals');
      var stopping = document.getElementById('mgr-stopping');
      var checks = document.getElementById('mgr-checks');
      var redflags = document.getElementById('mgr-redflags');
      if (goals) goals.value = data.goals || '';
      if (stopping) stopping.value = data.stopping_point || '';
      if (checks) checks.value = data.periodic_checks || '';
      if (redflags) redflags.value = data.red_flags || '';
      updateManageToggle(data.enabled);
      var status = document.getElementById('mgr-status');
      if (status && data.enabled) {{
        status.textContent = 'Turn ' + data.turn_counter;
      }} else if (status) {{
        status.textContent = '';
      }}
    }});
}}

function updateManageToggle(enabled) {{
  var btn = document.getElementById('mgr-toggle');
  var headerBtn = document.getElementById('chat-manage-btn');
  var currentItem = currentAgent
    ? document.querySelector('.chat-agent-item[data-agent="' + CSS.escape(currentAgent) + '"]')
    : null;
  if (btn) {{
    btn.textContent = enabled ? 'Disable' : 'Enable';
    btn.className = enabled ? 'btn-lg button-danger' : 'btn-lg';
  }}
  if (headerBtn) {{
    headerBtn.style.color = enabled ? 'var(--accent)' : '';
  }}
  if (currentItem && currentItem.dataset) {{
    currentItem.dataset.manageEnabled = enabled ? 'true' : 'false';
  }}
  updateHeaderStatus();
  if (currentAgent) updateAgentListStatus(currentAgent, agentStatus);
}}

function onManageChange() {{
  saveManageConfig();
}}

function onManageFieldChange() {{
  if (manageSaveTimer) clearTimeout(manageSaveTimer);
  manageSaveTimer = setTimeout(saveManageConfig, 600);
}}

function saveManageConfig() {{
  var bSel = document.getElementById('mgr-backend');
  var goals = document.getElementById('mgr-goals');
  var stopping = document.getElementById('mgr-stopping');
  var checks = document.getElementById('mgr-checks');
  var redflags = document.getElementById('mgr-redflags');
  var val = bSel ? bSel.value : '';
  var backend = '';
  var endpointId = '';
  if (val.startsWith('cli:')) {{
    backend = val.substring(4);
  }} else if (val.startsWith('ep:')) {{
    endpointId = val.substring(3);
  }}
  var body = 'csrf_token=' + encodeURIComponent(csrfToken)
    + '&backend=' + encodeURIComponent(backend)
    + '&endpoint_id=' + encodeURIComponent(endpointId)
    + '&goals=' + encodeURIComponent(goals ? goals.value : '')
    + '&stopping_point=' + encodeURIComponent(stopping ? stopping.value : '')
    + '&periodic_checks=' + encodeURIComponent(checks ? checks.value : '')
    + '&red_flags=' + encodeURIComponent(redflags ? redflags.value : '');
  fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/manage', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: body
  }});
}}

function toggleManageMode() {{
  var isEnabled = manageConfigData && manageConfigData.enabled;
  var body = 'csrf_token=' + encodeURIComponent(csrfToken)
    + '&enabled=' + (!isEnabled);
  fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/manage', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: body
  }}).then(function(r) {{ return r.json(); }}).then(function(data) {{
    if (manageConfigData) manageConfigData.enabled = data.enabled;
    updateManageToggle(data.enabled);
    var status = document.getElementById('mgr-status');
    if (status) status.textContent = data.enabled ? 'Turn 0' : '';
  }});
}}

function populateConfigDropdowns(backend, prefs) {{
  var bSel = document.getElementById('cfg-backend');
  bSel.innerHTML = '';
  var cliBackends = ['claude', 'agy', 'codex'];
  var hasEndpoints = chatConfigData && chatConfigData.endpoints && chatConfigData.endpoints.length > 0;
  var selectedEndpoint = chatConfigData && chatConfigData.endpoint_id;

  var cliGroup = document.createElement('optgroup');
  cliGroup.label = 'CLI';
  for (var i = 0; i < cliBackends.length; i++) {{
    var opt = document.createElement('option');
    opt.value = 'cli:' + cliBackends[i];
    opt.textContent = backendLabels[cliBackends[i]] || (cliBackends[i].charAt(0).toUpperCase() + cliBackends[i].slice(1));
    if (!selectedEndpoint && cliBackends[i] === backend) opt.selected = true;
    cliGroup.appendChild(opt);
  }}
  bSel.appendChild(cliGroup);

  if (hasEndpoints) {{
    var epGroup = document.createElement('optgroup');
    epGroup.label = 'Endpoints';
    for (var j = 0; j < chatConfigData.endpoints.length; j++) {{
      var ep = chatConfigData.endpoints[j];
      var eopt = document.createElement('option');
      eopt.value = 'ep:' + ep.id;
      eopt.textContent = ep.name + ' (' + ep.model + ')';
      if (selectedEndpoint === ep.id) eopt.selected = true;
      epGroup.appendChild(eopt);
    }}
    bSel.appendChild(epGroup);
  }}

  if (selectedEndpoint) {{
    document.getElementById('cfg-model').parentNode.style.display = 'none';
    var eField = document.getElementById('cfg-effort-field');
    if (eField) eField.style.display = 'none';
  }} else {{
    document.getElementById('cfg-model').parentNode.style.display = '';
    populateModelEffort(backend, prefs);
  }}
}}

function onBackendSelectChange(val) {{
  if (val.indexOf('ep:') === 0) {{
    var eid = val.substring(3);
    if (chatConfigData) chatConfigData.endpoint_id = eid;
    var ep = chatConfigData && chatConfigData.endpoints && chatConfigData.endpoints.find(function(e) {{ return e.id === eid; }});
    if (ep) {{
      agentConfig.backend = ep.name;
      agentConfig.model = ep.model;
      agentConfig.effort = '';
    }}
    document.getElementById('cfg-model').parentNode.style.display = 'none';
    var eField = document.getElementById('cfg-effort-field');
    if (eField) eField.style.display = 'none';
    var body = 'csrf_token=' + encodeURIComponent(csrfToken)
      + '&endpoint_id=' + encodeURIComponent(eid);
    fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/config', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
      body: body
    }});
  }} else {{
    var cli = val.indexOf('cli:') === 0 ? val.substring(4) : val;
    if (chatConfigData) chatConfigData.endpoint_id = null;
    agentConfig.backend = cli;
    document.getElementById('cfg-model').parentNode.style.display = '';
    if (chatConfigData) populateModelEffort(cli, chatConfigData.prefs);
    saveConfig();
  }}
  updateHeaderStatus();
}}

function populateModelEffort(backend, prefs) {{
  var mSel = document.getElementById('cfg-model');
  var eSel = document.getElementById('cfg-effort');
  var eField = document.getElementById('cfg-effort-field');

  var models = backendModels[backend] || ['default'];
  var currentModel = (prefs && prefs[backend] && prefs[backend].model) || null;
  mSel.innerHTML = '';
  for (var i = 0; i < models.length; i++) {{
    var opt = document.createElement('option');
    opt.value = models[i] === 'default' ? '' : models[i];
    opt.textContent = models[i];
    if ((models[i] === 'default' && !currentModel) || models[i] === currentModel) opt.selected = true;
    mSel.appendChild(opt);
  }}
  if (currentModel && models.indexOf(currentModel) === -1 && currentModel !== 'default') {{
    var custom = document.createElement('option');
    custom.value = currentModel;
    custom.textContent = currentModel;
    custom.selected = true;
    mSel.appendChild(custom);
  }}

  var efforts = backendEfforts[backend] || [];
  if (efforts.length === 0) {{
    eField.style.display = 'none';
  }} else {{
    eField.style.display = '';
    var currentEffort = (prefs && prefs[backend] && prefs[backend].effort) || null;
    eSel.innerHTML = '';
    for (var j = 0; j < efforts.length; j++) {{
      var eopt = document.createElement('option');
      eopt.value = efforts[j] === 'default' ? '' : efforts[j];
      eopt.textContent = efforts[j];
      if ((efforts[j] === 'default' && !currentEffort) || efforts[j] === currentEffort) eopt.selected = true;
      eSel.appendChild(eopt);
    }}
  }}
}}

function onBackendChange() {{
  var bSel = document.getElementById('cfg-backend');
  onBackendSelectChange(bSel.value);
}}

function onConfigChange() {{
  if (configSaveTimer) clearTimeout(configSaveTimer);
  configSaveTimer = setTimeout(saveConfig, 300);
}}

function saveConfig() {{
  var raw = document.getElementById('cfg-backend').value;
  var backend = raw.indexOf('cli:') === 0 ? raw.substring(4) : raw;
  var model = document.getElementById('cfg-model').value;
  var eField = document.getElementById('cfg-effort-field');
  var effort = (eField && eField.style.display !== 'none') ? document.getElementById('cfg-effort').value : '';
  var body = 'csrf_token=' + encodeURIComponent(csrfToken)
    + '&backend=' + encodeURIComponent(backend)
    + '&model=' + encodeURIComponent(model)
    + '&effort=' + encodeURIComponent(effort)
    + '&endpoint_id=';
  fetch('/ui/chat/' + encodeURIComponent(currentAgent) + '/config', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: body
  }}).then(function(r) {{ return r.json(); }}).then(function(d) {{
    if (d.ok && chatConfigData) {{
      chatConfigData.backend = backend;
      if (!chatConfigData.prefs[backend]) chatConfigData.prefs[backend] = {{}};
      chatConfigData.prefs[backend].model = model || null;
      chatConfigData.prefs[backend].effort = effort || null;
      agentConfig.backend = backend;
      agentConfig.model = model || '';
      agentConfig.effort = (backendEfforts[backend] && backendEfforts[backend].length > 0) ? (effort || '') : '';
      updateHeaderStatus();
    }}
  }});
}}

function handleLibrarianCommand(text) {{
  var parts = text.split(/\s+/);
  var cmd = parts[0].toLowerCase();
  var arg = parts.slice(1).join(' ').trim();

  if (cmd === '/help') {{
    return 'Available commands:\n/clear \u2014 clear chat history\n/project <name> \u2014 switch project\n/history on|off \u2014 toggle include history\n/edits on|off \u2014 toggle allow edits\n/help \u2014 show this message';
  }}

  if (cmd === '/clear') {{
    fetch('/ui/chat/librarian/clear', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
      body: 'csrf_token=' + encodeURIComponent(csrfToken) + '&project=' + encodeURIComponent(libProject)
    }});
    chatMessages = [];
    renderMessages();
    return null;
  }}

  if (cmd === '/project') {{
    if (!arg) return 'Usage: /project <name>';
    var sel = document.getElementById('lib-project');
    if (!sel) return 'Project selector not found.';
    var found = false;
    var argLower = arg.toLowerCase();
    for (var i = 0; i < sel.options.length; i++) {{
      var optText = sel.options[i].text.toLowerCase();
      var optVal = sel.options[i].value.toLowerCase();
      if (optText === argLower || optVal === argLower) {{
        sel.selectedIndex = i;
        found = true;
        break;
      }}
    }}
    if (!found) {{
      for (var i = 0; i < sel.options.length; i++) {{
        if (sel.options[i].text.toLowerCase().indexOf(argLower) !== -1) {{
          sel.selectedIndex = i;
          found = true;
          break;
        }}
      }}
    }}
    if (!found) return 'No project matching "' + arg + '" found.';
    onLibProjectChange();
    return 'Switched to project: ' + sel.options[sel.selectedIndex].text;
  }}

  if (cmd === '/history') {{
    var btn = document.getElementById('lib-toggle-history');
    if (!btn) return 'History toggle not found.';
    if (arg === 'on') {{
      if (!btn.classList.contains('active')) btn.classList.add('active');
      return 'Include history: on';
    }} else if (arg === 'off') {{
      btn.classList.remove('active');
      return 'Include history: off';
    }} else {{
      btn.classList.toggle('active');
      return 'Include history: ' + (btn.classList.contains('active') ? 'on' : 'off');
    }}
  }}

  if (cmd === '/edits') {{
    var btn = document.getElementById('lib-toggle-edits');
    if (!btn) return 'Edits toggle not found.';
    if (arg === 'on') {{
      if (!btn.classList.contains('active')) btn.classList.add('active');
      return 'Allow edits: on';
    }} else if (arg === 'off') {{
      btn.classList.remove('active');
      return 'Allow edits: off';
    }} else {{
      btn.classList.toggle('active');
      return 'Allow edits: ' + (btn.classList.contains('active') ? 'on' : 'off');
    }}
  }}

  return 'Unknown command: ' + cmd + '\nType /help for available commands.';
}}

function sendLibrarianMessage(e) {{
  e.preventDefault();
  var input = document.getElementById('chat-input');
  var text = input.value.trim();
  if (!text) return false;
  input.value = '';
  resizeChatInput();

  if (text.startsWith('/')) {{
    chatFollowScroll = true;
    chatMessages.push({{ role: 'user', content: text }});
    var result = handleLibrarianCommand(text);
    if (result) {{
      chatMessages.push({{ role: 'system', content: result }});
    }}
    renderMessages();
    return false;
  }}

  chatFollowScroll = true;
  updateAgentListStatus('librarian', 'thinking');
  chatMessages.push({{ role: 'user', content: text }});
  chatMessages.push({{ role: 'assistant', content: 'Thinking\u2026', _thinking: true }});
  renderMessages();
  var histBtn = document.getElementById('lib-toggle-history');
  var editsBtn = document.getElementById('lib-toggle-edits');
  var body = 'csrf_token=' + encodeURIComponent(csrfToken)
    + '&project=' + encodeURIComponent(libProject)
    + '&question=' + encodeURIComponent(text)
    + '&include_history=' + (histBtn && histBtn.classList.contains('active') ? '1' : '0')
    + '&allow_edits=' + (editsBtn && editsBtn.classList.contains('active') ? '1' : '0');
  fetch('/ui/chat/librarian/ask', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: body
  }}).then(function(r) {{ return r.json(); }}).then(function(data) {{
    updateAgentListStatus('librarian', 'idle');
    chatMessages = chatMessages.filter(function(m) {{ return !m._thinking; }});
    if (data.ok) {{
      var content = data.answer || data.error || 'No response.';
      if (data.pending) content = '[Pending approval] ' + content;
      chatMessages.push({{ role: 'assistant', content: content }});
    }} else {{
      chatMessages.push({{ role: 'system', content: 'Error: ' + (data.error || 'request failed') }});
    }}
    renderMessages();
  }}).catch(function() {{
    updateAgentListStatus('librarian', 'idle');
    chatMessages = chatMessages.filter(function(m) {{ return !m._thinking; }});
    chatMessages.push({{ role: 'system', content: 'Failed to send (network error)' }});
    renderMessages();
  }});
  return false;
}}

function onLibProjectChange() {{
  var sel = document.getElementById('lib-project');
  libProject = sel ? sel.value : '';
  localStorage.setItem('libProject', libProject);
  loadLibrarianHistory();
}}

function loadLibrarianHistory() {{
  fetch('/ui/chat/librarian/history?project=' + encodeURIComponent(libProject), {{ cache: 'no-store' }})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      chatMessages = data.messages || [];
      renderMessages();
      renderPendingActions(data.pending_actions || []);
    }}).catch(function() {{
      chatMessages = [];
      renderMessages();
    }});
}}

function renderPendingActions(actions) {{
  var el = document.getElementById('lib-pending-actions');
  if (!el) return;
  if (!actions.length) {{ el.innerHTML = ''; return; }}
  var html = '<div class="chat-config-label" style="margin-bottom:var(--s-2);">Pending Actions</div>';
  for (var i = 0; i < actions.length; i++) {{
    var a = actions[i];
    html += '<div style="display:flex;align-items:center;gap:var(--s-2);margin-bottom:var(--s-2);padding:var(--s-2);border:1px solid var(--line);border-radius:var(--radius);">';
    html += '<span style="flex:1;font-size:0.85em;">' + escapeHtml(a.summary) + ' (' + a.operation_count + ' ops)</span>';
    html += '<button class="btn-sm" onclick="libApproveAction(\'' + a.id + '\')" title="Approve"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg></button>';
    html += '<button class="btn-sm" onclick="libRejectAction(\'' + a.id + '\')" title="Reject"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"/><path d="M6 6l12 12"/></svg></button>';
    html += '</div>';
  }}
  el.innerHTML = html;
}}

function libApproveAction(id) {{
  fetch('/ui/chat/librarian/action/' + encodeURIComponent(id) + '/approve', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: 'csrf_token=' + encodeURIComponent(csrfToken)
  }}).then(function() {{ loadLibrarianHistory(); }});
}}

function libRejectAction(id) {{
  fetch('/ui/chat/librarian/action/' + encodeURIComponent(id) + '/reject', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body: 'csrf_token=' + encodeURIComponent(csrfToken)
  }}).then(function() {{ loadLibrarianHistory(); }});
}}

function toggleLibOption(opt) {{
  var btn = document.getElementById('lib-toggle-' + opt);
  if (!btn) return;
  btn.classList.toggle('active');
}}

if (!restorePersistedChatAgentSelection('replace')) {{
  initializeChatPanel();
}}

window.addEventListener('pageshow', function(e) {{
  if (restorePersistedChatAgentSelection('replace')) return;
  if (isMobileChatLayout() && e.persisted) {{
    closeAllPanels();
    setActiveAgentInList(currentAgent);
    var shell = document.querySelector('.shell');
    if (shell && !currentAgent) {{
      shell.style.bottom = '';
    }}
    document.querySelectorAll('.svg-overlay').forEach(function(ov) {{ ov.remove(); }});
    applyChatViewportFix();
  }}
  if (e.persisted) refreshChatOnResume(true);
  if (e.persisted && chatConfigOpen) loadChatConfig();
}});

document.addEventListener('visibilitychange', function() {{
  if (document.visibilityState === 'hidden') {{
    chatWasBackgrounded = true;
    return;
  }}
  if (document.visibilityState === 'visible') {{
    if (restorePersistedChatAgentSelection('replace')) return;
    refreshChatOnResume(false);
  }}
}});

window.addEventListener('pagehide', function() {{
  persistCurrentChatDraft();
  chatWasBackgrounded = true;
}});

window.addEventListener('focus', function() {{
  refreshChatOnResume(false);
}});

window.addEventListener('online', function() {{
  refreshChatOnResume(true);
}});

window.addEventListener('pointerdown', refreshChatAfterWakeActivity, {{ capture: true, passive: true }});
window.addEventListener('touchstart', refreshChatAfterWakeActivity, {{ capture: true, passive: true }});
window.addEventListener('keydown', refreshChatAfterWakeActivity, true);
setInterval(reconcileVisibleChatIfStale, CHAT_FOREGROUND_RECONCILE_INTERVAL_MS);

window.addEventListener('popstate', function() {{
  if (isMobileChatLayout()) return;
  var params = new URLSearchParams(window.location.search);
  loadDesktopChatPanel(params.get('agent'), false);
}});
</script>"#,
        layout_class = layout_class,
        agent_list_html = agent_list_html,
        chat_area_html = chat_area_html,
        selected_agent_js = selected_agent_js,
        csrf_token = escape_attribute(csrf_token),
        username_js = username_js,
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

pub fn render_chat_attachment_view_page(
    theme: UiTheme,
    color_mode: ColorMode,
    username: &str,
    is_admin: bool,
    file_name: &str,
    raw_url: &str,
    download_url: &str,
    is_svg: bool,
) -> String {
    let media_html = if is_svg {
        format!(
            r#"<img class="chat-media-viewer-image" src="{}" alt="{}">"#,
            escape_attribute(raw_url),
            escape_attribute(file_name),
        )
    } else {
        format!(
            r#"<img class="chat-media-viewer-image" src="{}" alt="{}">"#,
            escape_attribute(raw_url),
            escape_attribute(file_name),
        )
    };

    let content = format!(
        r#"<div class="panel chat-media-viewer-panel">
  <div class="chat-media-viewer-header">
    <div>
      <h1 class="page-title" style="margin:0;">{}</h1>
      <p class="subtitle">Open in a separate tab for pinch zoom and full-size viewing.</p>
    </div>
    <a class="btn-lg button-link chat-media-viewer-download" href="{}">Download</a>
  </div>
  <div class="chat-media-viewer-stage">
    {}
  </div>
</div>"#,
        escape_text(file_name),
        escape_attribute(download_url),
        media_html,
    );

    render_shell(
        PageShell {
            title: file_name,
            username: Some(username),
            is_admin,
            theme,
            color_mode,
            csrf_token: None,
            flash: None,
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

pub fn render_admin_errors_page(
    theme: UiTheme,
    color_mode: ColorMode,
    username: &str,
    csrf_token: &str,
    reporting_enabled: bool,
) -> String {
    let reporting_checked = if reporting_enabled { " checked" } else { "" };
    let toggle_panel = format!(
        r#"<section class="panel">
        <div class="panel-header">
          <h2>Server-side reporting</h2>
          <p>When enabled, agent machines forward LLM/CLI errors here for the last 3 days. Agents always keep a local log in <code>.lore/&lt;agent&gt;/error-*.jsonl</code> regardless.</p>
        </div>
        <label class="toggle" style="padding:var(--s-5);">
          <input type="checkbox" id="errors-reporting-toggle" data-csrf="{csrf_token}"{reporting_checked}>
          <span>Accept and persist errors reported by agents</span>
        </label>
      </section>"#
    );
    let content = r#"<h1 class="page-title">Errors</h1>
    <div class="layout admin-layout">
      {TOGGLE_PANEL}
      <section class="panel">
        <div class="panel-header">
          <h2>Recent errors</h2>
          <p>All agent and server LLM errors from the last 3 days. Newest first.</p>
        </div>
        <div class="errors-toolbar">
          <input type="text" id="errors-filter-input" placeholder="Filter by owner, agent, or text"/>
          <select id="errors-filter-category">
            <option value="">All categories</option>
            <option value="llm_api">LLM API</option>
            <option value="cli">CLI</option>
            <option value="tool">Tool</option>
            <option value="parse">Parse</option>
            <option value="manager">Manager</option>
          </select>
          <button class="btn-sm" id="errors-refresh" type="button" title="Refresh"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/><path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14"/></svg></button>
        </div>
        <div class="errors-count" id="errors-count"></div>
        <div class="errors-list" id="errors-list"><p class="hint padded">Loading errors...</p></div>
      </section>
    </div>
<script>
(function(){
  var all = [];
  function categoryLabel(c){
    return ({llm_api:'LLM API',cli:'CLI',tool:'Tool',parse:'Parse',manager:'Manager'})[c] || c;
  }
  function escapeHtml(s){
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function render(){
    var list = document.getElementById('errors-list');
    var filter = (document.getElementById('errors-filter-input').value || '').toLowerCase();
    var category = document.getElementById('errors-filter-category').value;
    var rows = all.filter(function(r){
      if (category && r.category !== category) return false;
      if (!filter) return true;
      var hay = [r.owner, r.agent, r.detail, r.category, r.endpoint_id].filter(Boolean).join(' ').toLowerCase();
      return hay.indexOf(filter) >= 0;
    });
    document.getElementById('errors-count').textContent = rows.length + ' error' + (rows.length===1?'':'s');
    if (!rows.length){
      list.innerHTML = '<p class="hint padded">No errors match.</p>';
      return;
    }
    list.innerHTML = rows.map(function(r){
      var tag = r.agent ? (r.owner + ' / ' + r.agent) : (r.owner === '_server' ? 'server' : r.owner);
      var status = r.status_code ? (' (HTTP ' + r.status_code + ')') : '';
      var details = '';
      if (r.preview_request || r.preview_response){
        details = '<details class="errors-preview"><summary>Preview</summary>' +
          (r.preview_request ? '<pre>REQUEST\n' + escapeHtml(r.preview_request) + '</pre>' : '') +
          (r.preview_response ? '<pre>RESPONSE\n' + escapeHtml(r.preview_response) + '</pre>' : '') +
          '</details>';
      }
      var endpoint = r.endpoint_id ? ' <span class="errors-endpoint">ep:' + escapeHtml(r.endpoint_id) + '</span>' : '';
      return '<div class="errors-card">' +
        '<div class="errors-card-head">' +
          '<span class="errors-card-ts">' + escapeHtml(r.ts||'') + '</span>' +
          '<span class="errors-card-scope">' + escapeHtml(tag) + '</span>' +
          '<span class="errors-card-cat">' + escapeHtml(categoryLabel(r.category||'')) + status + '</span>' +
          endpoint +
        '</div>' +
        '<div class="errors-card-detail">' + escapeHtml(r.detail||'') + '</div>' +
        details +
        '</div>';
    }).join('');
  }
  function load(){
    fetch('/v1/admin/errors').then(function(r){return r.json();}).then(function(data){
      all = data.records || [];
      render();
    }).catch(function(){
      document.getElementById('errors-list').innerHTML = '<p class="hint padded">Failed to load errors.</p>';
    });
  }
  document.getElementById('errors-refresh').addEventListener('click', load);
  document.getElementById('errors-filter-input').addEventListener('input', render);
  document.getElementById('errors-filter-category').addEventListener('change', render);
  var reportCb = document.getElementById('errors-reporting-toggle');
  if (reportCb) {
    reportCb.addEventListener('change', function(){
      var csrf = reportCb.getAttribute('data-csrf');
      fetch('/ui/admin/errors/reporting-toggle-json', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'csrf_token=' + encodeURIComponent(csrf) + '&enabled=' + reportCb.checked
      });
    });
  }
  load();
})();
</script>"#;

    let content = content.replace("{TOGGLE_PANEL}", &toggle_panel);
    render_shell(
        PageShell {
            title: "Lore admin errors",
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
    reserved_blocks: &[Block],
    documents: &[DocumentInfo],
    flash: Option<&str>,
    username: &str,
    can_write: bool,
    is_admin: bool,
    csrf_token: &str,
) -> String {
    let project_slug = escape_attribute(project.as_str());
    let csrf = escape_attribute(csrf_token);

    let delete_project_html = if is_admin {
        format!(
            r#"<div class="delete-project-section">
              <form method="post" action="/ui/{project_slug}/delete"
                    onsubmit="return confirm('Are you sure you want to delete this project? This cannot be undone.');">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <button type="submit" class="delete-project-btn">Delete project</button>
              </form>
            </div>"#,
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
              <input type="hidden" name="csrf_token" value="{csrf}">
              <input type="text" name="display_name" value="{display_name_attr}" class="rename-input"
                     autofocus onfocus="this.select()">
              <button type="submit" class="button-link">Save</button>
              <button type="button" class="button-link" onclick="this.closest('form').style.display='none'; document.getElementById('project-title').style.display='';">Cancel</button>
            </form>"#,
            display_name = escape_text(display_name),
            display_name_attr = escape_attribute(display_name),
            project_slug = project_slug,
            csrf = csrf,
            copy_project_link_btn = copy_project_link_btn,
        )
    } else {
        format!(
            r#"<div style="display:flex; align-items:center;"><h1 class="page-title" style="margin:0;">{display_name}</h1>{copy_project_link_btn}</div>"#,
            display_name = escape_text(display_name),
            copy_project_link_btn = copy_project_link_btn,
        )
    };

    let reserved_html: String = reserved_blocks
        .iter()
        .map(|block| render_reserved_block_panel(project, block, can_write, csrf_token))
        .collect::<Vec<_>>()
        .join("\n");

    let doc_list_html = render_doc_list_for_project(project, documents, can_write, csrf_token);

    let read_only_notice = if !can_write {
        r#"<section class="panel composer"><div class="panel-header"><h2>Read-only access</h2><p>Viewing only.</p></div></section>"#
    } else {
        ""
    };

    let content = format!(
        r#"<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--s-3);">
      {rename_html}
      <div style="display:flex; gap:var(--s-3); align-items:center;">
        <a class="button-link" href="/ui/{project_slug}/history">History</a>
      </div>
    </div>
    <div style="margin-top:var(--s-4);">{reserved_html}</div>
    {doc_list_html}
    {read_only_notice}
    {delete_project_html}
    {expanded_editor_shell}"#,
        rename_html = rename_html,
        project_slug = project_slug,
        reserved_html = reserved_html,
        doc_list_html = doc_list_html,
        read_only_notice = read_only_notice,
        delete_project_html = delete_project_html,
        expanded_editor_shell = render_expanded_text_editor_shell(),
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

fn reserved_block_label(id: &str) -> &'static str {
    match id {
        RESERVED_AGENT_CONTEXT => "Agent Context",
        RESERVED_OVERVIEW => "Overview",
        RESERVED_MAP => "File Map",
        _ => "Reserved",
    }
}

fn reserved_block_limit(id: &str) -> Option<(usize, usize)> {
    match id {
        RESERVED_OVERVIEW => Some((1600, 2000)),
        RESERVED_MAP => Some((3200, 4000)),
        _ => None,
    }
}

fn render_reserved_block_panel(
    project: &ProjectName,
    block: &Block,
    can_write: bool,
    _csrf_token: &str,
) -> String {
    let block_id_str = block.id.as_str();
    let label = reserved_block_label(block_id_str);
    let safe_id = block_id_str.replace('-', "_");
    let project_slug = escape_attribute(project.as_str());
    let content = &block.content;

    let limit_warning = if let Some((soft, hard)) = reserved_block_limit(block_id_str) {
        let len = content.len();
        if len > soft {
            let pct = (len as f64 / hard as f64 * 100.0).min(100.0);
            format!(
                r#"<div class="reserved-limit-warning"><span>{len} / {hard} chars ({pct:.0}%)</span></div>"#,
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let over_soft = if let Some((soft, _)) = reserved_block_limit(block_id_str) {
        content.len() > soft
    } else {
        false
    };
    let panel_class = if over_soft {
        "panel reserved-over-soft"
    } else {
        "panel"
    };

    let expanded_editor_source = if can_write {
        format!(
            r#"<textarea
        name="content"
        id="reserved-{safe_id}-content"
        class="expanded-editor-source"
        data-editor-label="{label}"
        data-editor-save="reserved"
        data-editor-action="/ui/{project_slug}/reserved/{block_id}"
        style="display:none;">{escaped}</textarea>"#,
            safe_id = safe_id,
            label = escape_attribute(label),
            project_slug = project_slug,
            block_id = escape_attribute(block_id_str),
            escaped = escape_text(content),
        )
    } else {
        String::new()
    };

    let band_html = if can_write {
        format!(
            r#"<div class="editline-band editline-band-even reserved-band-{safe_id}" onclick="toggleReservedEdit('{safe_id}')" title="Click to edit {label}"></div>"#,
        )
    } else {
        String::new()
    };

    let rendered_body = if content.trim().is_empty() {
        format!(
            "<span class=\"hint\">No {} set</span>",
            label.to_lowercase()
        )
    } else {
        render_markdown(content)
    };

    format!(
        r#"<section class="{panel_class}">
  <div class="panel-title">{label}</div>
  {limit_warning}
  <div class="editline-row">
    <article class="block reserved-block reserved-block-{safe_id}">
      <div class="block-body" id="reserved-{safe_id}-body">{rendered_body}</div>
      {expanded_editor_source}
    </article>{band_html}
  </div>
</section>"#,
    )
}

fn render_doc_tree_items(project: &ProjectName, docs: &[DocumentInfo], depth: usize) -> String {
    let project_slug = escape_attribute(project.as_str());
    docs.iter()
        .map(|doc| {
            let doc_id = escape_attribute(doc.id.as_str());
            let name = escape_text(&doc.display_name);
            let indent = if depth > 0 {
                format!(" style=\"padding-left:{}px\"", depth * 20)
            } else {
                String::new()
            };
            let children = render_doc_tree_items(project, &doc.children, depth + 1);
            format!(
                r#"<a href="/ui/{project_slug}/doc/{doc_id}" class="doc-tree-item"{indent}>
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
  <span>{name}</span>
</a>{children}"#,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_doc_list_for_project(
    project: &ProjectName,
    docs: &[DocumentInfo],
    can_write: bool,
    csrf_token: &str,
) -> String {
    let project_slug = escape_attribute(project.as_str());
    let csrf = escape_attribute(csrf_token);

    let doc_items = if docs.is_empty() {
        "<p class=\"hint\" style=\"margin:0;\">No documents yet</p>".to_string()
    } else {
        render_doc_tree_items(project, docs, 0)
    };

    let add_doc_html = if can_write {
        format!(
            r#"<form class="doc-add-form" method="post" action="/ui/{project_slug}/documents" style="display:none;" id="add-doc-form">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="text" name="name" placeholder="Document name" required class="tree-inline-input" style="flex:1;">
  <button type="submit" class="button-link">Create</button>
  <button type="button" class="button-link" onclick="this.closest('form').style.display='none'">Cancel</button>
</form>
<button type="button" class="button-link" style="margin-top:var(--s-3);" onclick="var f=document.getElementById('add-doc-form'); f.style.display='flex'; f.querySelector('input[name=name]').focus();">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
  New document
</button>"#,
        )
    } else {
        String::new()
    };

    format!(
        r#"<section class="panel">
  <div class="panel-title">Documents</div>
  <div class="doc-tree">{doc_items}</div>
  {add_doc_html}
</section>"#,
    )
}

pub fn render_document_page(
    theme: UiTheme,
    color_mode: ColorMode,
    project: &ProjectName,
    project_display_name: &str,
    doc_id: &str,
    doc_display_name: &str,
    blocks: &[Block],
    child_docs: &[DocumentInfo],
    flash: Option<&str>,
    username: &str,
    can_write: bool,
    is_admin: bool,
    csrf_token: &str,
    store: &FileBlockStore,
) -> String {
    let project_infos = store.list_project_infos().unwrap_or_default();
    let project_slug = escape_attribute(project.as_str());
    let doc_id_attr = escape_attribute(doc_id);
    let csrf = escape_attribute(csrf_token);

    let blocks_html = if blocks.is_empty() && can_write {
        format!(
            r#"<section class="empty-state"><h2>No blocks yet</h2><p>Click the button below to add the first block.</p></section>{}"#,
            render_doc_block_inserter(project, doc_id, None, csrf_token, &project_infos),
        )
    } else if blocks.is_empty() {
        r#"<section class="empty-state"><h2>No blocks yet</h2></section>"#.to_string()
    } else {
        let mut html = String::new();
        if can_write {
            html.push_str(&render_doc_block_inserter(
                project,
                doc_id,
                None,
                csrf_token,
                &project_infos,
            ));
        }
        for (i, block) in blocks.iter().enumerate() {
            html.push_str(&render_doc_block(
                project,
                doc_id,
                block,
                can_write,
                &project_infos,
                csrf_token,
                i,
            ));
            if can_write {
                html.push_str(&render_doc_block_inserter(
                    project,
                    doc_id,
                    Some(&block.id),
                    csrf_token,
                    &project_infos,
                ));
            }
        }
        html
    };
    let blocks_html = resolve_lore_links_in_html(&blocks_html, store);

    let rename_html = if can_write {
        format!(
            r#"<div style="display:flex; align-items:center;">
            <h1 class="page-title editable-title" style="margin:0;" id="doc-title"
                title="Click to rename" onclick="document.getElementById('doc-rename-form').style.display='flex'; this.style.display='none';"
            >{doc_name}</h1></div>
            <form id="doc-rename-form" method="post" action="/ui/{project_slug}/doc/{doc_id_attr}/rename"
                  style="display:none; align-items:center; gap:var(--s-3); margin:0;">
              <input type="hidden" name="csrf_token" value="{csrf}">
              <input type="text" name="name" value="{doc_name_attr}" class="rename-input"
                     autofocus onfocus="this.select()">
              <button type="submit" class="button-link">Save</button>
              <button type="button" class="button-link" onclick="this.closest('form').style.display='none'; document.getElementById('doc-title').style.display='';">Cancel</button>
            </form>"#,
            doc_name = escape_text(doc_display_name),
            doc_name_attr = escape_attribute(doc_display_name),
        )
    } else {
        format!(
            r#"<div style="display:flex; align-items:center;"><h1 class="page-title" style="margin:0;">{}</h1></div>"#,
            escape_text(doc_display_name),
        )
    };

    let child_doc_items = if child_docs.is_empty() {
        String::new()
    } else {
        let items = render_doc_tree_items(project, child_docs, 0);
        format!(
            r#"<section class="panel">
  <div class="panel-title">Sub-documents</div>
  <div class="doc-tree">{items}</div>
</section>"#,
        )
    };

    let add_subdoc_html = if can_write {
        format!(
            r#"<form class="doc-add-form" method="post" action="/ui/{project_slug}/documents" style="display:none;" id="add-subdoc-form">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="parent_document_id" value="{doc_id_attr}">
  <input type="text" name="name" placeholder="Document name" required class="tree-inline-input" style="flex:1;">
  <button type="submit" class="button-link">Create</button>
  <button type="button" class="button-link" onclick="this.closest('form').style.display='none'">Cancel</button>
</form>
<button type="button" class="button-link" style="margin-top:var(--s-3);" onclick="var f=document.getElementById('add-subdoc-form'); f.style.display='flex'; f.querySelector('input[name=name]').focus();">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
  New sub-document
</button>"#,
        )
    } else {
        String::new()
    };

    let delete_doc_html = if can_write {
        format!(
            r#"<div class="delete-project-section">
              <form method="post" action="/ui/{project_slug}/doc/{doc_id_attr}/delete"
                    onsubmit="return confirm('Delete this document and all its contents? This cannot be undone.');">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <button type="submit" class="delete-project-btn">Delete document</button>
              </form>
            </div>"#,
        )
    } else {
        String::new()
    };

    let read_only_notice = if !can_write {
        r#"<section class="panel composer"><div class="panel-header"><h2>Read-only access</h2><p>Viewing only.</p></div></section>"#
    } else {
        ""
    };

    let content = format!(
        r#"<div style="margin-bottom:var(--s-3);">
      <a href="/ui/{project_slug}" class="breadcrumb-link">{project_name}</a>
    </div>
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--s-3);">
      {rename_html}
    </div>
    <section class="panel" id="document" style="margin-top:var(--s-4);">
      <div class="timeline">{blocks_html}</div>
    </section>
    {child_doc_items}
    {add_subdoc_html}
    {read_only_notice}
    {delete_doc_html}
    {expanded_editor_shell}"#,
        project_slug = project_slug,
        project_name = escape_text(project_display_name),
        rename_html = rename_html,
        blocks_html = blocks_html,
        child_doc_items = child_doc_items,
        add_subdoc_html = add_subdoc_html,
        read_only_notice = read_only_notice,
        delete_doc_html = delete_doc_html,
        expanded_editor_shell = render_expanded_text_editor_shell(),
    );

    render_shell(
        PageShell {
            title: &format!("Lore · {} · {}", project_display_name, doc_display_name),
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

fn render_doc_block_inserter(
    project: &ProjectName,
    doc_id: &str,
    after_block_id: Option<&BlockId>,
    csrf_token: &str,
    project_infos: &[ProjectInfo],
) -> String {
    let after_value = after_block_id
        .map(|id| escape_attribute(id.as_str()).to_string())
        .unwrap_or_default();
    let project_attr = escape_attribute(project.as_str());
    let doc_id_attr = escape_attribute(doc_id);
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
      <form class="inserter-form inserter-form-md" style="display:none" method="post" action="/ui/{project_attr}/doc/{doc_id_attr}/blocks" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{csrf_attr}">
        <input type="hidden" name="block_type" value="markdown">
        <input type="hidden" name="after_block_id" value="{after_value}">
        <textarea name="content" placeholder="Write markdown..." rows="6"></textarea>
        {doc_link_picker}
        <button type="submit">Add markdown</button>
      </form>
      <form class="inserter-form inserter-form-svg" style="display:none" method="post" action="/ui/{project_attr}/doc/{doc_id_attr}/blocks" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{csrf_attr}">
        <input type="hidden" name="block_type" value="svg">
        <input type="hidden" name="after_block_id" value="{after_value}">
        <textarea name="content" placeholder="Paste SVG markup or describe what you want..." rows="6"></textarea>
        <label>Or upload an SVG file
          <input type="file" name="image_file" accept=".svg,image/svg+xml">
        </label>
        <button type="submit">Add SVG</button>
      </form>
      <form class="inserter-form inserter-form-image" style="display:none" method="post" action="/ui/{project_attr}/doc/{doc_id_attr}/blocks" enctype="multipart/form-data">
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
        doc_id_attr = doc_id_attr,
        csrf_attr = csrf_attr,
        after_value = after_value,
        doc_link_picker = render_doc_link_picker(project_infos),
    )
}

fn render_doc_block(
    project: &ProjectName,
    doc_id: &str,
    block: &Block,
    can_write: bool,
    _project_infos: &[ProjectInfo],
    csrf_token: &str,
    block_index: usize,
) -> String {
    let block_id = escape_attribute(block.id.as_str());
    let project_slug = escape_attribute(project.as_str());
    let doc_id_attr = escape_attribute(doc_id);
    let csrf = escape_attribute(csrf_token);

    let copy_link_btn = format!(
        r##"<button type="button" class="block-header-btn" title="Copy link" onclick="copyLoreLink('{block_id}')">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
  </button>"##,
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

    let uses_expanded_editor = can_write && block.block_type == crate::model::BlockType::Markdown;

    let header_actions = if can_write {
        let inline_edit_actions = if uses_expanded_editor {
            String::new()
        } else {
            format!(
                r#"
  <button type="button" class="block-header-btn" title="Save" onclick="document.querySelector('#edit-{block_id} form').submit();">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
  </button>
  <button type="button" class="block-header-btn" title="Cancel" onclick="cancelBlockEdit('{block_id}')">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
  </button>"#,
            )
        };
        format!(
            r##"<div class="block-header-actions">
  <button type="button" class="block-header-btn danger" title="Delete" onclick="if(confirm('Delete this block? This cannot be undone.')){{document.getElementById('del-{block_id}').submit();}}">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
  </button>
  {copy_link_btn}
  <button type="button" class="{pin_class}" title="{pin_title}" onclick="document.getElementById('pin-{block_id}').submit();">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>
  </button>
  {inline_edit_actions}
  <form id="del-{block_id}" method="post" action="/ui/{project_slug}/doc/{doc_id_attr}/blocks/{block_id}/delete" style="display:none;">
    <input type="hidden" name="csrf_token" value="{csrf}">
  </form>
  <form id="pin-{block_id}" method="post" action="/ui/{project_slug}/doc/{doc_id_attr}/blocks/{block_id}/pin" style="display:none;">
    <input type="hidden" name="csrf_token" value="{csrf}">
  </form>
</div>"##,
            inline_edit_actions = inline_edit_actions,
        )
    } else {
        format!(r##"<div class="block-header-actions">{copy_link_btn}</div>"##,)
    };

    let block_type_label = format!("{:?}", block.block_type).to_lowercase();
    let body_html = render_block_body_with_doc(block, Some(doc_id));
    let edit_panel = if uses_expanded_editor {
        format!(
            r#"<textarea name="content" id="block-edit-content-{block_id}" class="expanded-editor-source" data-editor-label="Edit Markdown" data-editor-save="block" data-editor-action="/ui/{project_slug}/doc/{doc_id_attr}/blocks/{block_id}/edit" data-editor-block-type="markdown" style="display:none;">{content}</textarea>"#,
            content = escape_text(&block.content),
        )
    } else if can_write {
        let block_type_options = render_block_type_options(block.block_type);
        let content_escaped = escape_text(&block.content);
        let media_replace = match block.block_type {
            crate::model::BlockType::Markdown | crate::model::BlockType::Html => "",
            _ => {
                r#"<label class="image-upload-label">Replace media <input type="file" name="image_file" accept="image/*,.svg"></label>"#
            }
        };
        format!(
            r#"<div class="block-edit-panel" id="edit-{block_id}" style="display:none;">
  <form id="block-edit-form-{block_id}" method="post" action="/ui/{project_slug}/doc/{doc_id_attr}/blocks/{block_id}/edit" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <div class="block-edit-top-row">
      <select name="block_type" class="block-type-select">{block_type_options}</select>
    </div>
    <textarea name="content" class="block-edit-textarea{expanded_editor_class}"{expanded_editor_attrs}>{content_escaped}</textarea>
    {media_replace}
    <div class="block-edit-actions">
      <button type="submit" class="button-link">Save</button>
      <button type="button" class="button-link" onclick="cancelBlockEdit('{block_id}')">Cancel</button>
    </div>
  </form>
</div>"#,
            expanded_editor_class = "",
            expanded_editor_attrs = String::new(),
        )
    } else {
        String::new()
    };

    let band_class = if block.pinned {
        "editline-band editline-band-pinned"
    } else if block_index % 2 == 0 {
        "editline-band editline-band-even"
    } else {
        "editline-band editline-band-odd"
    };

    let band_html = if can_write {
        format!(
            r#"<div class="{band_class}" onclick="toggleBlockEdit('{block_id}')" title="Click to edit" draggable="true" ondragstart="blockDragStart(event, '{block_id}')" ondragend="blockDragEnd(event)"></div>"#,
        )
    } else {
        String::new()
    };

    let meta_display = if uses_expanded_editor {
        "none"
    } else {
        "display:none;"
    };
    let meta_html = format!(
        r#"<div class="block-meta" id="meta-{block_id}" style="{meta_display}">
  <span class="pill">{block_type_label}</span>
  {header_actions}
</div>"#,
    );

    format!(
        r#"<div class="editline-row">
  <article class="block" id="block-{block_id}">
    {meta_html}
    <div class="block-body" id="body-{block_id}">{body_html}</div>
    {edit_panel}
  </article>{band_html}
</div>"#,
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

fn render_user_detail(
    user: &UiUserSummary,
    agents: &[AgentTokenSummary],
    machines: &[StoredMachine],
    csrf_token: &str,
) -> String {
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
        r#"<p style="font-size:0.85rem; color:var(--fg-muted); margin:0;">No agents</p>"#
            .to_string()
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
        r#"<p style="font-size:0.85rem; color:var(--fg-muted); margin:0;">No machines</p>"#
            .to_string()
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
        r#"<div class="sel-detail" data-sel-id="{username_attr}" style="display:none;">
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
        action_label = if user.disabled {
            "Enable user"
        } else {
            "Disable user"
        },
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
    let edit_form = if can_write && block.block_type == crate::model::BlockType::Markdown {
        format!(
            r#"<textarea name="content" id="block-edit-content-{block_id}" class="expanded-editor-source" data-editor-label="Edit Markdown" data-editor-save="block" data-editor-action="/ui/{project_slug}/blocks/{block_id}/edit" data-editor-block-type="markdown" style="display:none;">{content}</textarea>"#,
            block_id = block_id,
            project_slug = project_slug,
            content = escape_text(&block.content),
        )
    } else if can_write {
        format!(
            r#"<form id="block-edit-form-{block_id}" method="post" action="/ui/{project_slug}/blocks/{block_id}/edit" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <textarea name="content" class="block-edit-textarea{expanded_editor_class}"{expanded_editor_attrs}>{content}</textarea>
    {edit_doc_link_picker}
    {image_replace}
  </form>"#,
            block_id = block_id,
            project_slug = project_slug,
            csrf = csrf,
            content = escape_text(&block.content),
            expanded_editor_class = "",
            expanded_editor_attrs = String::new(),
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
    let band_pinned = if block.pinned {
        " editline-band-pinned"
    } else {
        ""
    };

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
    render_block_body_with_doc(block, None)
}

fn render_block_body_with_doc(block: &Block, doc_id: Option<&str>) -> String {
    match block.block_type {
        BlockType::Markdown => render_markdown(&block.content),
        BlockType::Html => format!(
            r#"<pre class="raw-content">{}</pre>"#,
            escape_text(&block.content)
        ),
        BlockType::Svg => render_data_image("image/svg+xml", &block.content, "SVG block"),
        BlockType::Image => render_image_block(block, doc_id),
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

fn render_image_block(block: &Block, doc_id: Option<&str>) -> String {
    let src = if block.media_type.is_some() {
        if let Some(did) = doc_id {
            format!(
                "/ui/{}/doc/{}/blocks/{}/media",
                escape_attribute(block.project.as_str()),
                escape_attribute(did),
                escape_attribute(block.id.as_str()),
            )
        } else {
            format!(
                "/ui/{}/blocks/{}/media",
                escape_attribute(block.project.as_str()),
                escape_attribute(block.id.as_str())
            )
        }
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
        "id" | "class"
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
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn escape_attribute(value: &str) -> String {
    escape_text(value)
}

fn escape_json_for_inline_script(value: &str) -> String {
    value
        .replace('<', "\\u003C")
        .replace('>', "\\u003E")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
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
            code_background: "#f6eee6",
            code_text: "#4d3325",
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
            code_background: "#e8eff8",
            code_text: "#223248",
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
            code_background: "#e7f4ef",
            code_text: "#18483d",
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

fn accent_foreground(hex: &str) -> &'static str {
    let h = hex.trim_start_matches('#').as_bytes();
    let parse2 = |i: usize| {
        let hi = match h[i] {
            b'0'..=b'9' => h[i] - b'0',
            b'a'..=b'f' => h[i] - b'a' + 10,
            b'A'..=b'F' => h[i] - b'A' + 10,
            _ => 0,
        } as f64;
        let lo = match h[i + 1] {
            b'0'..=b'9' => h[i + 1] - b'0',
            b'a'..=b'f' => h[i + 1] - b'a' + 10,
            b'A'..=b'F' => h[i + 1] - b'A' + 10,
            _ => 0,
        } as f64;
        let v = (hi * 16.0 + lo) / 255.0;
        if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    let lum = 0.2126 * parse2(0) + 0.7152 * parse2(2) + 0.0722 * parse2(4);
    if lum > 0.36 { "#111" } else { "#fff" }
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
      --accent-fg: {accent_fg};
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
        accent_fg = accent_foreground(p.accent),
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
                "    :root {{\n      {light_vars}\n\n      --system-color-mode: light;\n      --s-1: 4px;\n      --s-2: 8px;\n      --s-3: 12px;\n      --s-4: 16px;\n      --s-5: 24px;\n      --s-6: 32px;\n      --s-7: 48px;\n      --s-8: 64px;\n    }}\n    :root[data-color-mode=\"system\"] {{\n      color-scheme: light dark;\n      {light_vars}\n    }}\n    @media (prefers-color-scheme: dark) {{\n      :root[data-color-mode=\"system\"] {{\n        --system-color-mode: dark;\n        {dark_vars}\n      }}\n    }}",
                light_vars = palette_css_vars(&light),
                dark_vars = palette_css_vars(&dark)
            )
        }
    };
    let base = r#"

    * { box-sizing: border-box; }

    html {
      scrollbar-gutter: stable;
      -webkit-text-size-adjust: 100%;
      text-size-adjust: 100%;
    }

    body {
      margin: 0;
      font-family: var(--font-sans);
      color: var(--ink);
      background: var(--body-bg);
      min-height: 100vh;
      line-height: 1.5;
      touch-action: manipulation;
      -webkit-text-size-adjust: 100%;
      text-size-adjust: 100%;
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

    .nav-right-btns {
      display: contents;
    }

    .nav-projects-btn,
    .nav-chat-btn {
      display: none;
      color: var(--muted);
      padding: var(--s-2);
    }
    .nav-projects-btn:hover,
    .nav-chat-btn:hover {
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
      padding: var(--s-5);
      margin-bottom: var(--s-4);
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

    .admin-page-header {
      display: grid;
      gap: var(--s-1);
      margin: 0 0 var(--s-5) 0;
    }

    .admin-page-header .page-title {
      margin: 0;
    }

    .admin-version {
      margin: 0;
      color: var(--muted);
      font-size: 0.85rem;
      line-height: 1.4;
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

    .btn-sm.button-link {
      width: 28px;
      height: 28px;
      min-height: auto;
      padding: 0;
      border-radius: 6px;
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

    .agents-options {
      display: flex;
      flex-direction: column;
      gap: var(--s-5);
      margin-top: var(--s-6);
    }

    /* Selectable list — standard pattern for list + detail panel */
    .sel-list {
      display: flex;
      flex-direction: column;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      margin: 0;
      overflow: hidden;
    }
    .sel-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: var(--s-3) var(--s-4);
      border-bottom: 1px solid var(--line);
      text-decoration: none;
      color: var(--fg);
      cursor: pointer;
      transition: background 0.1s;
    }
    .sel-item:last-child { border-bottom: none; }
    .sel-item:hover { background: var(--bg-hover); }
    .sel-item.active {
      background: var(--bg-hover);
      border-left: 4px solid var(--accent);
    }
    .sel-item-name {
      font-weight: 600;
      font-family: var(--font-mono);
      font-size: 0.9rem;
    }
    .sel-item-meta {
      font-size: 0.82rem;
      color: var(--fg-muted);
      display: flex;
      align-items: center;
      gap: var(--s-2);
    }
    .sel-item-actions {
      display: flex;
      gap: var(--s-1);
      flex-shrink: 0;
    }
    .sel-detail {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      margin: var(--s-3) 0 0;
      padding: var(--s-4) 0;
    }

    .folder-entry:hover {
      background: var(--bg-hover);
    }
    .folder-entry:last-child {
      border-bottom: none !important;
    }

    /* Chat pages: page header fixed at top, shell fixed below it to bottom. */
    body:has(.chat-layout) {
      margin: 0;
      overflow: hidden;
    }
    .top-nav:has(~ .shell .chat-layout) {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 100;
      margin-bottom: 0;
    }
    .shell:has(.chat-layout) {
      position: fixed;
      top: 64px;
      left: 0;
      right: 0;
      bottom: 0;
      width: 100%;
      max-width: 100%;
      padding: 0;
      margin: 0;
      overflow: hidden;
    }
    .chat-layout {
      display: flex;
      height: 100%;
      overflow: hidden;
    }
    .chat-sidebar {
      width: 280px;
      min-width: 280px;
      border-right: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      overscroll-behavior: none;
    }
    .chat-sidebar-header {
      padding: var(--s-3) var(--s-4);
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      line-height: 28px;
    }
    .chat-agent-list {
      flex: 1;
      overflow-y: auto;
      overscroll-behavior: none;
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
      border-left: 4px solid var(--accent);
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
    .chat-status-glyph {
      width: 14px;
      height: 14px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex: 0 0 auto;
    }
    .chat-status-glyph svg {
      width: 14px;
      height: 14px;
      display: block;
    }
    .chat-status-running { color: #22c55e; }
    .chat-status-working {
      color: var(--accent);
      animation: chat-status-working-color-shift 1.1s ease-in-out infinite;
    }
    .chat-status-restarting { color: #f59e0b; }
    .chat-status-stopped { color: var(--fg-muted); }
    @keyframes chat-status-working-color-shift {
      0%, 100% {
        color: var(--accent);
        opacity: 1;
        filter: drop-shadow(0 0 0 rgba(56, 189, 248, 0));
      }
      50% {
        color: #38bdf8;
        opacity: 0.72;
        filter: drop-shadow(0 0 4px rgba(56, 189, 248, 0.35));
      }
    }
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
      min-height: 1em;
    }
    .chat-main {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-width: 0;
      min-height: 0;
      overflow: hidden;
    }
    .chat-header {
      padding: var(--s-3) var(--s-4);
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: baseline;
      gap: var(--s-3);
      flex-shrink: 0;
      background: var(--panel);
      min-width: 0;
    }
    .chat-header-name {
      font-weight: 600;
      font-size: 1rem;
      display: block;
      line-height: 1.3;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .chat-header-actions {
      margin-left: 0;
      display: inline-flex;
      align-items: center;
      gap: var(--s-2);
      min-width: 0;
      flex-shrink: 0;
    }
    .chat-header-status {
      font-size: 0.82rem;
      color: var(--fg-muted);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: var(--s-2);
      width: 28px;
      height: 28px;
      flex: 0 0 28px;
      line-height: 1.3;
      min-width: 28px;
    }
    .chat-header-cwd {
      flex: 1 1 auto;
      min-width: 0;
      margin: 0 var(--s-3);
      font-size: 0.82rem;
      color: var(--fg-muted);
      display: block;
      line-height: 1.3;
      text-align: center;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .chat-avatar-sm-wrap {
      width: 24px;
      height: 24px;
      border-radius: 4px;
      flex-shrink: 0;
      margin-right: var(--s-2);
      cursor: pointer;
      position: relative;
      overflow: hidden;
    }
    .chat-avatar-sm-wrap:hover {
      opacity: 0.8;
    }
    .chat-avatar-empty {
      background: var(--line);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .chat-avatar-librarian {
      background: var(--accent-soft);
      color: var(--accent);
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent) 18%, transparent);
    }
    .chat-avatar-sm {
      width: 24px;
      height: 24px;
      border-radius: 4px;
      object-fit: cover;
      flex-shrink: 0;
    }
    .chat-avatar-header {
      width: 28px;
      height: 28px;
      border-radius: 5px;
      object-fit: cover;
      flex-shrink: 0;
    }
    .chat-back-btn {
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.12);
      border: none;
      color: var(--fg);
      cursor: pointer;
      width: 28px;
      height: 28px;
      padding: 0;
      min-height: auto;
      border-radius: 6px;
      flex-shrink: 0;
      align-self: center;
    }
    .chat-header-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: var(--accent-soft);
      color: var(--accent);
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent) 18%, transparent);
      flex-shrink: 0;
      align-self: center;
    }
    .chat-header .chat-avatar-header,
    .chat-header .btn-sm {
      align-self: center;
    }
    .chat-config-panel {
      flex: 1;
      min-height: 0;
      min-width: 0;
      overflow-y: auto;
      overflow-x: hidden;
      overscroll-behavior: none;
      padding: var(--s-5);
    }
    .chat-config-inner {
      width: 100%;
      max-width: 100%;
      min-width: 0;
      display: flex;
      flex-direction: column;
      gap: var(--s-4);
      height: 100%;
    }
    .chat-config-field {
      display: flex;
      flex-direction: column;
      gap: var(--s-1);
      width: 100%;
      max-width: 400px;
      min-width: 0;
      box-sizing: border-box;
    }
    .chat-config-field-wide {
      max-width: none;
    }
    .chat-config-label {
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--fg-muted);
    }
    .chat-config-select {
      width: 100%;
      max-width: 100%;
      box-sizing: border-box;
      padding: var(--s-2) var(--s-3);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--input-bg);
      color: var(--ink);
      font-size: 0.95rem;
      font-family: var(--font-sans);
    }
    .chat-config-textarea {
      width: 100%;
      max-width: 100%;
      min-width: 0;
      box-sizing: border-box;
      flex: 1;
      min-height: 120px;
      padding: var(--s-3);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--input-bg);
      color: var(--ink);
      font-size: 0.85rem;
      font-family: var(--font-mono);
      resize: vertical;
      line-height: 1.5;
    }
    .chat-config-textarea[readonly] {
      background: var(--bg-secondary, var(--bg));
      opacity: 0.75;
      cursor: default;
    }
    .expanded-editor-source {
      resize: none;
      cursor: pointer;
    }
    .expanded-editor-source:hover {
      border-color: color-mix(in srgb, var(--accent) 28%, var(--line));
    }
    .expanded-editor-preview {
      min-height: 9rem;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      cursor: pointer;
      background: var(--bg-secondary, var(--bg));
    }
    .expanded-editor-preview:hover {
      border-color: color-mix(in srgb, var(--accent) 28%, var(--line));
    }
    .expanded-editor-preview.is-disabled {
      opacity: 0.45;
      cursor: default;
    }
    .expanded-editor-preview.is-disabled:hover {
      border-color: var(--line);
    }
    .expanded-editor-preview.is-placeholder {
      color: var(--fg-muted);
      font-style: italic;
    }
    body.expanded-editor-open {
      overflow: hidden;
      overscroll-behavior: none;
    }
    .expanded-editor-overlay {
      position: fixed;
      inset: 0;
      width: 100%;
      max-width: 100vw;
      z-index: 1000;
      background: var(--bg);
      display: none;
      overflow: hidden;
      overscroll-behavior: none;
    }
    .expanded-editor-shell {
      position: absolute;
      inset: 0;
      width: 100%;
      max-width: 100%;
      height: 100%;
      min-height: 0;
      min-width: 0;
      display: flex;
      flex-direction: column;
      gap: var(--s-4);
      padding: max(var(--s-5), env(safe-area-inset-top)) var(--s-5) max(var(--s-5), env(safe-area-inset-bottom));
      background: var(--bg);
      overflow: hidden;
    }
    .expanded-editor-header {
      display: flex;
      flex-direction: column;
      gap: var(--s-1);
    }
    .expanded-editor-kicker {
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--fg-muted);
    }
    .expanded-editor-title {
      margin: 0;
      font-size: 1.15rem;
      line-height: 1.2;
    }
    .expanded-editor-input {
      flex: 1;
      min-height: 0;
      min-width: 0;
      width: 100%;
      max-width: 100%;
      padding: var(--s-4);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--input-bg);
      color: var(--ink);
      font: inherit;
      font-family: var(--font-mono);
      font-size: 0.95rem;
      line-height: 1.55;
      resize: none;
      overflow-x: hidden;
      overflow-y: auto;
      overscroll-behavior: contain;
      -webkit-overflow-scrolling: touch;
      touch-action: pan-y;
    }
    .expanded-editor-footer {
      position: sticky;
      bottom: 0;
      padding-top: var(--s-2);
      background: linear-gradient(to top, var(--bg) 72%, transparent);
      flex-shrink: 0;
    }
    .expanded-editor-actions {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: var(--s-2);
    }
    .expanded-editor-actions-mobile {
      display: none;
    }
    .chat-messages-wrap {
      position: relative;
      flex: 1;
      min-height: 0;
      min-width: 0;
      overflow: hidden;
    }
    .chat-messages {
      height: 100%;
      min-height: 0;
      overflow-y: auto;
      overflow-x: hidden;
      overscroll-behavior: none;
      overflow-anchor: none;
      padding: var(--s-4);
      display: flex;
      flex-direction: column;
      gap: var(--s-3);
      -webkit-text-size-adjust: 100%;
      text-size-adjust: 100%;
    }
    .chat-msg-row {
      display: flex;
      flex-direction: column;
      gap: 2px;
      max-width: 100%;
      --chat-msg-swipe-offset: 0px;
    }
    .chat-msg-row-mutable {
      touch-action: pan-y;
    }
    .chat-msg-swipe-shell {
      width: 100%;
      display: flex;
      justify-content: flex-end;
      align-items: center;
      position: relative;
    }
    .chat-msg-row-mutable .chat-msg {
      cursor: grab;
      position: relative;
      z-index: 1;
      transform: translateX(calc(-1 * var(--chat-msg-swipe-offset)));
      transition: transform 140ms ease;
      will-change: transform;
    }
    .chat-msg-row-mutable.chat-msg-row-swipe-visible .chat-msg {
      transition-duration: 120ms;
    }
    .chat-msg-swipe-action {
      position: absolute;
      right: 0;
      top: 50%;
      transform: translateY(-50%) scale(0.92);
      opacity: 0;
      pointer-events: none;
      color: var(--danger);
      background: color-mix(in srgb, var(--danger) 16%, transparent);
      border-color: color-mix(in srgb, var(--danger) 35%, transparent);
      transition: opacity 140ms ease, transform 140ms ease, background 140ms ease;
    }
    .chat-msg-row-mutable.chat-msg-row-swipe-visible .chat-msg-swipe-action {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(-50%) scale(1);
    }
    .chat-msg-swipe-action:hover {
      background: color-mix(in srgb, var(--danger) 24%, transparent);
    }
    .chat-msg-swipe-action-active {
      color: var(--accent);
      background: color-mix(in srgb, var(--accent) 16%, transparent);
      border-color: color-mix(in srgb, var(--accent) 35%, transparent);
    }
    .chat-msg-swipe-action-active:hover {
      background: color-mix(in srgb, var(--accent) 24%, transparent);
    }
    .chat-msg-row-excluded .chat-msg-timestamp {
      color: var(--fg-dim);
    }
    .chat-msg-row-user {
      align-items: flex-end;
    }
    .chat-msg-row-assistant,
    .chat-msg-row-tool,
    .chat-msg-row-error {
      align-items: flex-start;
    }
    .chat-msg-row-system,
    .chat-msg-row-config {
      align-items: center;
    }
    .chat-msg-timestamp {
      font-size: 0.74rem;
      line-height: 1.25;
      font-style: italic;
      color: var(--fg-muted);
      opacity: 0.85;
      padding: 0 var(--s-1);
      max-width: 90%;
    }
    .chat-jump-btn {
      position: absolute;
      right: var(--s-4);
      bottom: var(--s-4);
      z-index: 2;
      display: none;
      width: auto;
      min-height: 44px;
      padding: var(--s-2) var(--s-4);
      box-shadow: 0 8px 24px rgba(0,0,0,0.16);
    }
    .chat-msg {
      max-width: 80%;
      padding: var(--s-3) var(--s-4);
      border-radius: 8px;
      font-size: 0.92rem;
      line-height: 1.5;
      word-wrap: break-word;
      min-width: 0;
      box-sizing: border-box;
      -webkit-text-size-adjust: 100%;
      text-size-adjust: 100%;
    }
    .chat-msg-excluded {
      opacity: 0.78;
      filter: saturate(0.55);
    }
    .chat-msg-excluded-prefix {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      margin-bottom: var(--s-1);
      font-size: 0.9rem;
      line-height: 1;
      opacity: 0.9;
    }
    .chat-msg-user {
      align-self: flex-end;
      background: var(--accent);
      color: var(--accent-fg);
    }
    .chat-msg-assistant {
      align-self: flex-start;
      background: var(--bg-hover);
      color: var(--fg);
      display: flex;
      gap: var(--s-2);
      align-items: flex-start;
      min-width: 0;
      max-width: 100%;
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
    .chat-msg-thinking {
      opacity: 0.6;
      animation: pulse 1.5s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 0.6; }
      50% { opacity: 0.3; }
    }
    .chat-msg-config {
      align-self: center;
      background: none;
      color: var(--fg-muted);
      font-size: 0.8rem;
      padding: var(--s-1) var(--s-3);
      opacity: 0.7;
    }
    .chat-msg-tool {
      align-self: flex-start;
      background: none;
      color: var(--fg-muted);
      font-size: 0.8rem;
      padding: var(--s-1) var(--s-3);
      font-family: var(--font-mono);
      max-width: 100%;
    }
    .chat-tool-summary {
      display: flex;
      align-items: center;
      gap: var(--s-2);
      min-width: 0;
    }
    .chat-tool-toggle {
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--fg-muted);
      flex-shrink: 0;
    }
    .chat-tool-toggle:hover {
      background: var(--surface-hover);
      color: var(--fg);
    }
    .chat-tool-line {
      min-width: 0;
      flex: 1 1 auto;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .chat-tool-count {
      flex-shrink: 0;
      color: var(--fg-dim, var(--fg-muted));
      font-size: 0.75rem;
      white-space: nowrap;
    }
    .chat-tool-lines {
      margin: var(--s-2) 0 0 36px;
      padding: var(--s-2) var(--s-3);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: var(--details-bg);
    }
    .chat-msg-error {
      align-self: stretch;
      background: rgba(220, 38, 38, 0.08);
      color: #dc2626;
      border: 1px solid rgba(220, 38, 38, 0.35);
      border-radius: var(--radius-sm);
      font-size: 0.82rem;
      padding: var(--s-2) var(--s-3);
      font-family: var(--font-mono);
      max-width: 100%;
    }
    .chat-msg-error .chat-msg-content {
      min-width: 0;
    }
    .chat-msg-error-content {
      display: flex;
      gap: var(--s-2);
      align-items: flex-start;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .chat-msg-error-content span {
      min-width: 0;
      flex: 1;
    }
    .chat-msg-error-icon {
      flex-shrink: 0;
      margin-top: 0.15rem;
    }
    .chat-errors-list {
      display: flex;
      flex-direction: column;
      gap: var(--s-2);
      overflow-y: auto;
      max-height: 100%;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      padding: var(--s-2);
      background: var(--bg-subtle, transparent);
    }
    .chat-errors-empty {
      color: var(--fg-muted);
      font-size: 0.85rem;
      padding: var(--s-2);
      text-align: center;
    }
    .chat-errors-row {
      display: flex;
      flex-direction: column;
      gap: var(--s-1);
      padding: var(--s-2);
      border-left: 3px solid #dc2626;
      background: rgba(220, 38, 38, 0.04);
      border-radius: var(--radius-sm);
    }
    .chat-errors-meta {
      font-size: 0.75rem;
      color: var(--fg-muted);
      font-family: var(--font-mono);
    }
    .chat-errors-detail {
      font-size: 0.85rem;
      color: var(--fg);
      word-break: break-word;
    }
    .chat-errors-preview {
      font-size: 0.75rem;
    }
    .chat-errors-preview summary {
      cursor: pointer;
      color: var(--fg-muted);
    }
    .chat-errors-preview pre {
      margin: var(--s-1) 0 0;
      padding: var(--s-2);
      background: var(--bg-subtle, #f5f5f5);
      border-radius: var(--radius-sm);
      max-height: 200px;
      overflow: auto;
    }
    .errors-toolbar {
      display: flex;
      gap: var(--s-2);
      align-items: center;
      padding: var(--s-2) var(--s-3);
      border-bottom: 1px solid var(--line);
    }
    .errors-toolbar input[type=text] {
      flex: 1;
    }
    .errors-count {
      padding: var(--s-2) var(--s-3);
      color: var(--fg-muted);
      font-size: 0.85rem;
    }
    .errors-list {
      display: flex;
      flex-direction: column;
      gap: var(--s-2);
      padding: var(--s-3);
    }
    .errors-card {
      padding: var(--s-2) var(--s-3);
      border-left: 3px solid #dc2626;
      background: rgba(220, 38, 38, 0.04);
      border-radius: var(--radius-sm);
      display: flex;
      flex-direction: column;
      gap: var(--s-1);
    }
    .errors-card-head {
      display: flex;
      gap: var(--s-2);
      flex-wrap: wrap;
      font-size: 0.78rem;
      color: var(--fg-muted);
      font-family: var(--font-mono);
    }
    .errors-card-scope { color: var(--fg); font-weight: 600; }
    .errors-card-cat { color: #dc2626; }
    .errors-endpoint { color: var(--fg-muted); }
    .errors-card-detail {
      font-size: 0.9rem;
      color: var(--fg);
      word-break: break-word;
    }
    .errors-preview summary {
      cursor: pointer;
      color: var(--fg-muted);
      font-size: 0.78rem;
    }
    .errors-preview pre {
      margin: var(--s-1) 0 0;
      padding: var(--s-2);
      background: var(--bg-subtle, #f5f5f5);
      border-radius: var(--radius-sm);
      max-height: 240px;
      overflow: auto;
      font-size: 0.78rem;
    }
    .chat-msg-system .chat-msg-content { white-space: pre-wrap; }
    .chat-msg-content {
      min-width: 0;
      width: 100%;
      max-width: 100%;
      box-sizing: border-box;
    }
    .chat-msg-assistant .chat-msg-content,
    .chat-msg-user .chat-msg-content {
      min-width: 0;
      max-width: 100%;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .chat-msg-assistant .chat-msg-content > *,
    .chat-msg-user .chat-msg-content > * {
      max-width: 100%;
    }
    .chat-msg-assistant .chat-msg-content p,
    .chat-msg-user .chat-msg-content p { margin: 0.3em 0; }
    .chat-msg-assistant .chat-msg-content p:first-child,
    .chat-msg-user .chat-msg-content p:first-child { margin-top: 0; }
    .chat-msg-assistant .chat-msg-content p:last-child,
    .chat-msg-user .chat-msg-content p:last-child { margin-bottom: 0; }
    .chat-msg-assistant .chat-msg-content h1,
    .chat-msg-assistant .chat-msg-content h2,
    .chat-msg-assistant .chat-msg-content h3,
    .chat-msg-assistant .chat-msg-content h4,
    .chat-msg-user .chat-msg-content h1,
    .chat-msg-user .chat-msg-content h2,
    .chat-msg-user .chat-msg-content h3,
    .chat-msg-user .chat-msg-content h4 {
      margin: 0.6em 0 0.3em;
      line-height: 1.3;
    }
    .chat-msg-assistant .chat-msg-content h1,
    .chat-msg-user .chat-msg-content h1 { font-size: 1.15em; }
    .chat-msg-assistant .chat-msg-content h2,
    .chat-msg-user .chat-msg-content h2 { font-size: 1.05em; }
    .chat-msg-assistant .chat-msg-content h3,
    .chat-msg-user .chat-msg-content h3 { font-size: 1em; font-weight: 600; }
    .chat-msg-assistant .chat-msg-content h4,
    .chat-msg-user .chat-msg-content h4 { font-size: 0.95em; font-weight: 600; }
    .chat-msg-assistant .chat-msg-content ul,
    .chat-msg-assistant .chat-msg-content ol,
    .chat-msg-user .chat-msg-content ul,
    .chat-msg-user .chat-msg-content ol {
      margin: 0.3em 0;
      padding-left: 1.4em;
    }
    .chat-msg-assistant .chat-msg-content li,
    .chat-msg-user .chat-msg-content li { margin: 0.15em 0; }
    .chat-msg-assistant .chat-msg-content blockquote,
    .chat-msg-user .chat-msg-content blockquote {
      border-left: 3px solid var(--accent);
      margin: 0.3em 0;
      padding: 0.15em 0.7em;
      color: var(--muted);
    }
    .chat-msg-user .chat-msg-content blockquote {
      border-left-color: color-mix(in srgb, var(--accent-fg) 70%, transparent);
      color: color-mix(in srgb, var(--accent-fg) 88%, transparent);
    }
    .chat-msg-assistant .chat-msg-content hr,
    .chat-msg-user .chat-msg-content hr {
      border: none;
      border-top: 1px solid var(--line);
      margin: 0.5em 0;
    }
    .chat-msg-user .chat-msg-content hr {
      border-top-color: color-mix(in srgb, var(--accent-fg) 28%, transparent);
    }
    .chat-msg-assistant .chat-msg-content pre,
    .chat-msg-user .chat-msg-content pre {
      background: var(--code-bg);
      color: var(--code-ink);
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 0.5em 0.7em;
      overflow-x: auto;
      max-width: 100%;
      box-sizing: border-box;
      font-family: var(--font-mono);
      font-size: 0.85em;
      margin: 0.4em 0;
      white-space: pre;
    }
    .chat-msg-user .chat-msg-content pre {
      background: color-mix(in srgb, var(--accent-fg) 12%, var(--accent));
      color: var(--accent-fg);
      border-color: color-mix(in srgb, var(--accent-fg) 20%, transparent);
    }
    .chat-msg-assistant .chat-msg-content code,
    .chat-msg-user .chat-msg-content code {
      font-family: var(--font-mono);
      font-size: 0.88em;
    }
    .chat-msg-assistant .chat-msg-content :not(pre) > code,
    .chat-msg-user .chat-msg-content :not(pre) > code {
      background: var(--code-bg);
      color: var(--code-ink);
      border-radius: 3px;
      padding: 0.1em 0.3em;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .chat-msg-user .chat-msg-content :not(pre) > code {
      background: color-mix(in srgb, var(--accent-fg) 14%, var(--accent));
      color: var(--accent-fg);
    }
    .chat-msg-assistant .chat-msg-content a,
    .chat-msg-user .chat-msg-content a {
      color: var(--accent);
      text-decoration: underline;
    }
    .chat-msg-user .chat-msg-content a {
      color: var(--accent-fg);
    }
    .chat-table-wrap {
      overflow-x: auto;
      margin: 0.4em 0;
      max-width: 100%;
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
      width: 100%;
      max-width: 100%;
      border-radius: 4px;
      border: 1px solid var(--line);
      padding: 0.5em;
      position: relative;
      box-sizing: border-box;
    }
    .chat-svg-wrap svg { width: 100%; height: auto; display: block; }
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
      background: color-mix(in srgb, var(--bg) 90%, transparent);
      backdrop-filter: blur(4px);
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
      background: var(--panel);
    }
    .svg-overlay-close {
      position: fixed;
      top: 1rem; right: 1rem;
      background: var(--surface-hover);
      border: none;
      color: var(--ink);
      font-size: 1.5rem;
      cursor: pointer;
      z-index: 10000;
      width: 36px; height: 36px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 50%;
    }
    .svg-overlay-close:hover { background: var(--line); }
    .chat-input-form {
      display: flex;
      gap: var(--s-2);
      padding: var(--s-3) var(--s-4) calc(var(--s-3) + env(safe-area-inset-bottom));
      border-top: 1px solid var(--line);
      align-items: flex-end;
      flex-shrink: 0;
      background: var(--panel);
      overflow-anchor: none;
    }
    .chat-input {
      flex: 1;
      min-width: 0;
      padding: var(--s-3);
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--bg);
      color: var(--fg);
      font-family: var(--font-sans);
      font-size: 1rem;
      resize: none;
      min-height: 38px;
      max-height: 50vh;
      overflow-y: hidden;
      -webkit-text-size-adjust: 100%;
      text-size-adjust: 100%;
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
      align-self: flex-end;
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
      min-width: 0;
      max-width: 100%;
      overflow-x: hidden;
    }

    .project-tree-panel {
      padding: var(--s-5);
      overflow-x: hidden;
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
      min-width: 0;
    }

    .tree-node-row {
      display: flex;
      align-items: center;
      gap: var(--s-3);
      padding: var(--s-2) var(--s-3);
      border-radius: var(--radius);
      transition: background 0.15s;
      min-width: 0;
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
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
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

    .tree-inline-create .tree-row-right {
      flex-shrink: 1;
    }

    .tree-inline-create .tree-perm {
      display: none;
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
      width: auto;
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
      flex: 1 1 0;
      min-width: 60px;
      font-size: 1rem;
      font-weight: 600;
      padding: var(--s-1) var(--s-2);
      border: 1px solid var(--accent);
      border-radius: var(--radius);
      background: var(--input-bg);
      color: var(--ink);
      outline: none;
    }

    .tree-doc-inline-create .tree-add-child {
      flex-shrink: 0;
      white-space: nowrap;
      padding: 2px 8px;
      font-size: 0.85rem;
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

    .tree-expand-btn {
      background: none;
      border: none;
      color: var(--muted);
      cursor: pointer;
      font-size: 0.7rem;
      padding: 2px;
      width: auto;
      min-height: auto;
      line-height: 1;
      flex-shrink: 0;
      transition: color 0.15s;
    }
    .tree-expand-btn:hover {
      color: var(--accent);
    }

    .tree-doc-list {
      list-style: none;
      margin: 0;
      padding: 0 0 0 var(--s-5);
      border-left: 1px solid var(--line);
      margin-left: var(--s-4);
    }

    .tree-doc-node {
      margin: var(--s-1) 0;
    }

    .tree-doc-row {
      display: flex;
      align-items: center;
      gap: var(--s-2);
      padding: var(--s-1) var(--s-2);
      border-radius: var(--radius);
      transition: background 0.15s;
    }
    .tree-doc-row:hover {
      background: var(--surface-hover);
    }
    .tree-doc-add {
      opacity: 0;
      flex-shrink: 0;
      margin-left: auto;
    }
    .tree-doc-row:hover .tree-doc-add {
      opacity: 1;
    }

    .tree-doc-link {
      display: flex;
      align-items: center;
      gap: var(--s-2);
      flex: 1;
      min-width: 0;
      color: var(--ink);
      text-decoration: none;
      font-size: 0.9rem;
    }
    .tree-doc-link:hover {
      color: var(--accent);
    }
    .tree-doc-link svg {
      flex-shrink: 0;
      color: var(--muted);
    }

    .timeline {
      padding: var(--s-5);
    }

    /* Edit-line paradigm: seamless document with vertical band indicator */
    .editline-row {
      display: flex;
      align-items: stretch;
      min-width: 0;
      max-width: 100%;
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

    .panel-title {
      font-size: 0.75em;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--fg);
      opacity: 0.35;
      margin: 0 0 var(--s-3) 0;
    }

    .reserved-over-soft {
      border-color: #d4a017;
      box-shadow: 0 0 0 1px #d4a017;
    }

    .reserved-limit-warning {
      font-size: 0.8rem;
      font-weight: 600;
      color: #d4a017;
      margin-bottom: var(--s-2);
    }

    .reserved-textarea {
      min-height: 120px;
    }

    .doc-tree {
      display: flex;
      flex-direction: column;
    }

    .doc-tree-item {
      display: flex;
      align-items: center;
      gap: var(--s-2);
      padding: var(--s-2) var(--s-3);
      border-radius: var(--radius);
      color: var(--ink);
      text-decoration: none;
      font-weight: 500;
      font-size: 0.95rem;
      transition: background 0.15s;
    }

    .doc-tree-item:hover {
      background: var(--surface-hover);
      color: var(--accent);
    }

    .doc-tree-item svg {
      flex-shrink: 0;
      color: var(--muted);
    }

    .doc-add-form {
      display: flex;
      align-items: center;
      gap: var(--s-3);
    }

    .breadcrumb-link {
      color: var(--muted);
      text-decoration: none;
      font-size: 0.9rem;
      font-weight: 600;
    }

    .breadcrumb-link:hover {
      color: var(--accent);
    }

    .agent-context-textarea {
      min-height: 120px;
    }

    .block {
      padding: var(--s-3) 0;
      border: none;
      border-radius: 0;
      background: transparent;
      min-width: 0;
      max-width: 100%;
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
      padding: 0;
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

    input:not([type="checkbox"]), select, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: var(--s-3);
      padding: var(--s-3) var(--s-4);
      font-size: 16px;
      background: var(--input-bg);
      color: var(--ink);
      font-family: inherit;
    }

    select option {
      background: var(--panel-strong);
      color: var(--ink);
    }

    select optgroup {
      background: var(--panel-strong);
      color: var(--muted);
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
      border-radius: 8px;
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

    .btn-sm {
      width: 28px;
      height: 28px;
      min-height: auto;
      padding: 0;
      border-radius: 6px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .lib-toggle.active {
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
    }

    .btn-lg {
      min-height: 48px;
      padding: var(--s-3) var(--s-4);
      font-size: 16px;
      border-radius: var(--s-3);
    }

    .create-agent-panel select,
    .create-agent-panel button:not(.btn-lg) {
      width: auto;
      min-height: auto;
    }

    .create-agent-backend-row {
      display: flex;
      align-items: stretch;
      gap: var(--s-2);
    }

    .create-agent-backend-row select {
      min-width: 0;
    }

    .create-folder-toggle {
      min-width: 28px;
      width: 28px;
      height: 28px;
      flex: 0 0 28px;
      align-self: flex-end;
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

    .search-inline {
      display: flex;
    }
    .search-inline input {
      width: 160px;
      margin: 0;
      padding: 6px 10px;
      font-size: 0.9rem;
    }
    .search-scope {
      display: flex;
      gap: var(--s-2);
      margin-top: var(--s-3);
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
      min-width: 0;
      max-width: 100%;
      overflow-x: hidden;
      overflow-wrap: anywhere;
      word-break: break-word;
    }

    .block-body > * {
      min-width: 0;
      max-width: 100%;
      box-sizing: border-box;
    }

    .block-body img,
    .block-body svg {
      display: block;
      max-width: 100%;
      height: auto;
    }

    .block-body table {
      display: block;
      width: max-content;
      max-width: 100%;
      overflow-x: auto;
      border-collapse: collapse;
      margin: var(--s-4) 0;
      font-size: 0.95rem;
    }

    .block-body th,
    .block-body td {
      border: 1px solid var(--line);
      padding: 0.4em 0.65em;
      text-align: left;
    }

    .block-body th {
      background: var(--surface);
      font-weight: 600;
    }

    .block-body :not(pre) > code {
      background: var(--code-bg);
      color: var(--code-ink);
      border-radius: 3px;
      padding: 0.1em 0.3em;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }

    .block-body pre {
      display: block;
      width: 100%;
      min-width: 0;
      margin: var(--s-4) 0;
      padding: var(--s-4);
      border-radius: var(--s-3);
      background: var(--code-bg);
      color: var(--code-ink);
      overflow-x: auto;
      max-width: 100%;
      box-sizing: border-box;
      -webkit-overflow-scrolling: touch;
      font-size: 0.9rem;
    }

    .block-body pre code {
      display: block;
      min-width: max-content;
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
      .top-nav {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        width: 100%;
      }
      .shell {
        width: min(100vw - 16px, 1080px);
        padding-top: calc(64px + max(8px, env(safe-area-inset-top)));
        padding-bottom: calc(28px + env(safe-area-inset-bottom));
      }

      .layout,
      .admin-layout {
        grid-template-columns: 1fr;
      }

      .composer {
        position: static;
      }

      .panel {
        padding: var(--s-3);
      }

      .timeline {
        padding: var(--s-3);
      }

      .block.editing {
        padding: var(--s-2) var(--s-3);
      }

      .block-edit-actions button {
        padding: var(--s-2) var(--s-3);
      }

      .block-header-btn {
        width: 28px;
        height: 28px;
      }

      /* Burger menu */
      .nav-right-btns {
        display: flex;
        align-items: center;
        gap: var(--s-1);
      }

      .nav-projects-btn,
      .nav-chat-btn {
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .nav-link-projects,
      .nav-link-chat {
        display: none;
      }

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

      /* Chat mobile: adjust shell top for safe area */
      .shell:has(.chat-layout) {
        top: calc(64px + env(safe-area-inset-top));
      }
      .chat-layout {
        flex-direction: column;
        height: 100%;
        width: 100%;
        max-width: 100%;
        overflow-x: hidden;
      }
      .chat-sidebar {
        width: 100%;
        min-width: 100%;
        max-width: 100%;
        border-right: none;
        max-height: none;
      }
      .chat-main { display: none; }
      .chat-has-agent .chat-sidebar { display: none; }
      .chat-has-agent .chat-main {
        display: flex;
        flex: 1;
        min-height: 0;
        min-width: 0;
        width: 100%;
        max-width: 100%;
        overflow: hidden;
      }
      .chat-back-btn { display: flex; margin: 0; }
      .chat-header { align-items: center; gap: var(--s-2); padding: var(--s-2); }
      .chat-header,
      .chat-messages-wrap,
      .chat-messages,
      .chat-config-panel,
      .chat-input-form,
      .chat-empty {
        width: 100%;
        max-width: 100%;
        min-width: 0;
      }
      .chat-header .chat-avatar-sm-wrap { margin-right: 0; margin-left: 0; }
      .chat-header .chat-avatar-header { margin: 0; }
      .chat-header-cwd { display: none; }
      .chat-header-actions { margin-left: auto; gap: var(--s-2); }
      .chat-header-status { gap: 0; }
      .chat-messages {
        overflow-y: scroll;
        overflow-x: hidden;
      }
      .chat-msg { max-width: 90%; }
      .chat-msg-assistant,
      .chat-msg-content,
      .chat-table-wrap,
      .chat-svg-wrap {
        max-width: 100%;
        min-width: 0;
      }

      .tree-perm { display: none; }
      .tree-doc-add { opacity: 1; }

      .project-tree-panel { padding: var(--s-3); }
      .tree-list .tree-list {
        padding-left: var(--s-3);
        margin-left: var(--s-2);
      }
      .tree-doc-list {
        padding-left: var(--s-3);
        margin-left: var(--s-2);
      }
      .tree-row-right {
        gap: var(--s-2);
        flex-shrink: 1;
        min-width: 0;
      }
      .tree-node-row {
        gap: var(--s-2);
        padding: var(--s-2);
      }

    }

    @media (max-width: 640px) {
      .expanded-editor-shell {
        padding: max(var(--s-4), env(safe-area-inset-top)) var(--s-3) max(var(--s-4), env(safe-area-inset-bottom));
        gap: var(--s-3);
      }

      .expanded-editor-input {
        padding: var(--s-3);
      }

      .expanded-editor-actions-desktop {
        display: none;
      }

      .expanded-editor-actions-mobile {
        display: flex;
      }
    }
    "#;
    format!("{root}{base}{rest}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserName;
    use crate::config::{ColorMode, ExternalScheme, ServerConfig, UiTheme};
    use crate::librarian::LibrarianConfig;
    use crate::manager::ManagerPromptConfig;
    use crate::model::{BlockType, NewBlock};
    use crate::store::FileBlockStore;
    use crate::updater::AutoUpdateConfig;
    use crate::versioning::GitExportConfig;
    use tempfile::tempdir;

    #[test]
    fn html_escaping_preserves_slashes_without_dropping_safety_escapes() {
        let escaped = escape_text(r#"https://lore.example.com/a?x=1&name=<tag>"'"#);
        assert_eq!(
            escaped,
            "https://lore.example.com/a?x=1&amp;name=&lt;tag&gt;&quot;&#x27;"
        );

        let escaped_attr = escape_attribute(r#"/docs/"quoted"&one=<two>"#);
        assert_eq!(escaped_attr, "/docs/&quot;quoted&quot;&amp;one=&lt;two&gt;");
    }

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

    #[test]
    fn document_page_uses_expanded_editor_for_markdown_block_edit_line() {
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
        let block_id = block.id.clone();

        let html = render_document_page(
            UiTheme::Parchment,
            ColorMode::Light,
            &info.slug,
            "My Docs",
            "doc-1",
            "Doc 1",
            &[block],
            &[],
            None,
            "admin",
            true,
            true,
            "csrf",
            &store,
        );

        assert!(html.contains(r#"data-editor-save="block""#));
        assert!(html.contains(r#"data-editor-action="/ui/"#));
        assert!(html.contains(r#"data-editor-block-type="markdown""#));
        assert!(html.contains(r#"id="block-edit-content-"#));
        assert!(html.contains(r#"id="expanded-text-editor""#));
        assert!(html.contains("function openExpandedTextEditor(sourceId) {"));
        assert!(html.contains(
            "var directSource = document.getElementById('block-edit-content-' + blockId);"
        ));
        assert!(html.contains(format!(r#"id="block-edit-content-{}""#, block_id).as_str()));
        assert!(!html.contains(format!(r#"id="edit-{}""#, block_id).as_str()));
        assert!(
            !html.contains(
                format!(
                    r#"document.querySelector('#edit-{} form').submit();"#,
                    block_id
                )
                .as_str()
            )
        );
    }

    #[test]
    fn project_page_reserved_sections_use_expanded_editor() {
        let project = ProjectName::new("my-docs").unwrap();
        let reserved = Block {
            id: BlockId::reserved(RESERVED_OVERVIEW),
            project: project.clone(),
            block_type: BlockType::Markdown,
            order: crate::model::OrderKey::new("00000001".into()).unwrap(),
            author: crate::model::KeyFingerprint::from_user_name("admin").unwrap(),
            content: "Overview body".into(),
            media_type: None,
            created_at: time::OffsetDateTime::now_utc(),
            pinned: false,
        };

        let html = render_project_page(
            UiTheme::Parchment,
            ColorMode::Light,
            &project,
            "My Docs",
            "project-uuid",
            &[reserved],
            &[],
            None,
            "admin",
            true,
            true,
            "csrf",
        );

        assert!(html.contains(r#"id="expanded-text-editor""#));
        assert!(html.contains(r#"id="reserved-_overview-content""#));
        assert!(html.contains(r#"data-editor-save="reserved""#));
        assert!(html.contains(r#"data-editor-action="/ui/my-docs/reserved/_overview""#));
        assert!(html.contains(r#"onclick="toggleReservedEdit('_overview')""#));
        assert!(html.contains("var formData = new URLSearchParams();"));
        assert!(html.contains("headers: {'Content-Type': 'application/x-www-form-urlencoded'},"));
        assert!(
            html.contains(
                "var source = document.getElementById('reserved-' + safeId + '-content');"
            )
        );
        assert!(!html.contains(r#"id="reserved-_overview-edit""#));
        assert!(!html.contains(r#"id="reserved-_overview-form""#));
        assert!(!html.contains("class=\"block-edit-textarea reserved-textarea\""));
    }

    #[test]
    fn document_page_bounds_code_blocks_to_document_width() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let info = store.create_project("My Docs", None).unwrap();
        let block = store
            .create_block(NewBlock {
                project: info.slug.clone(),
                block_type: BlockType::Markdown,
                content: "```rust\nlet really_long_name = \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\";\n```".into(),
                author_key: "key-a".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        let html = render_document_page(
            UiTheme::Parchment,
            ColorMode::Light,
            &info.slug,
            "My Docs",
            "doc-1",
            "Doc 1",
            &[block],
            &[],
            None,
            "admin",
            true,
            true,
            "csrf",
            &store,
        );

        assert!(html.contains(".timeline {\n      display: grid;\n      gap: 6px;\n      min-width: 0;\n      max-width: 100%;\n      overflow-x: hidden;"));
        assert!(html.contains(".editline-row {\n      display: flex;\n      align-items: stretch;\n      min-width: 0;\n      max-width: 100%;"));
        assert!(html.contains(".block-body {\n      font-size: 1.05rem;\n      line-height: 1.7;\n      min-width: 0;\n      max-width: 100%;\n      overflow-x: hidden;"));
        assert!(html.contains(".block-body > * {\n      min-width: 0;\n      max-width: 100%;"));
        assert!(html.contains(".block-body pre {"));
        assert!(html.contains("overflow-x: auto;"));
        assert!(html.contains("-webkit-overflow-scrolling: touch;"));
    }

    #[test]
    fn agents_page_uses_chat_status_icons() {
        let config = ServerConfig::new(
            ExternalScheme::Https,
            "example.com".into(),
            443,
            UiTheme::Parchment,
        )
        .unwrap();
        let agents = vec![
            AgentTokenSummary {
                name: "worker".into(),
                display_name: "Worker".into(),
                owner: Some("admin".into()),
                grants: Vec::new(),
                backend: "codex".into(),
                endpoint_id: None,
                machine_name: Some("desk".into()),
                process_status: Some("running".into()),
                status: "thinking".into(),
                created_at: time::OffsetDateTime::now_utc(),
            },
            AgentTokenSummary {
                name: "done".into(),
                display_name: "Done".into(),
                owner: Some("admin".into()),
                grants: Vec::new(),
                backend: "codex".into(),
                endpoint_id: None,
                machine_name: Some("desk".into()),
                process_status: Some("running".into()),
                status: "idle".into(),
                created_at: time::OffsetDateTime::now_utc(),
            },
        ];
        let html = render_agents_page(
            &config,
            "admin",
            true,
            UiTheme::Parchment,
            ColorMode::Light,
            "csrf",
            &agents,
            &[],
            &[],
            &[],
            None,
            None,
            None,
        );

        assert!(html.contains(r#"title="Working""#));
        assert!(html.contains(r#"chat-status-working"#));
        assert!(html.contains("chat-status-working-color-shift"));
        assert!(!html.contains("status-working-gradient"));
        assert!(html.contains(r#"title="Finished""#));
        assert!(html.contains(r#"chat-status-running"#));
        assert!(!html.contains("agent-status-badge"));
    }

    #[test]
    fn agent_setup_uses_server_hosted_cli_installer() {
        let config = ServerConfig::new(
            ExternalScheme::Https,
            "lore.example.com".into(),
            443,
            UiTheme::Parchment,
        )
        .unwrap();
        let agents = vec![AgentTokenSummary {
            name: "worker".into(),
            display_name: "Worker".into(),
            owner: Some("admin".into()),
            grants: Vec::new(),
            backend: "codex".into(),
            endpoint_id: None,
            machine_name: Some("desk".into()),
            process_status: Some("running".into()),
            status: "idle".into(),
            created_at: time::OffsetDateTime::now_utc(),
        }];

        let agents_html = render_agents_page(
            &config,
            "admin",
            true,
            UiTheme::Parchment,
            ColorMode::Light,
            "csrf",
            &agents,
            &[],
            &[],
            &[],
            Some("worker"),
            None,
            None,
        );
        let guide_html = render_agent_guide_page(
            &config,
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            true,
            "csrf",
        );

        for html in [&agents_html, &guide_html] {
            assert!(html.contains("https://lore.example.com/install-cli.sh"));
            assert!(html.contains("https://lore.example.com/install-cli.ps1"));
            assert!(!html.contains("raw.githubusercontent.com/brontoguana/lore"));
        }
        assert!(
            agents_html.contains("lore setup-external https://lore.example.com --token YOUR_TOKEN")
        );
        assert!(
            agents_html
                .contains("This does not register a machine or start a Lore-managed agent service")
        );
    }

    #[test]
    fn agents_page_create_agent_joins_grants_with_newline_escape() {
        let config = ServerConfig::new(
            ExternalScheme::Https,
            "lore.example.com".into(),
            443,
            UiTheme::Parchment,
        )
        .unwrap();
        let machines = vec![StoredMachine {
            name: "desk".into(),
            username: UserName::new("admin").unwrap(),
            token_hash: "hash".into(),
            created_at: time::OffsetDateTime::now_utc(),
            cli_version: Some("0.1.65-test".into()),
            pending_update: false,
        }];
        let projects = vec![
            UserProjectAccess {
                slug: "company".into(),
                display_name: "Company".into(),
                max_permission: ProjectPermission::ReadWrite,
            },
            UserProjectAccess {
                slug: "development".into(),
                display_name: "Development".into(),
                max_permission: ProjectPermission::Read,
            },
        ];

        let html = render_agents_page(
            &config,
            "admin",
            true,
            UiTheme::Parchment,
            ColorMode::Light,
            "csrf",
            &[],
            &machines,
            &projects,
            &[],
            None,
            None,
            None,
        );

        assert!(html.contains("grants: grants.join('\\n')"));
        assert!(html.contains("lines.join('\\n')"));
        assert!(html.contains("data-external-project-grant"));
        assert!(html.contains("row.getAttribute('data-external-project-grant')"));
        assert!(!html.contains("grants: grants.join('\\\\n')"));
    }

    #[test]
    fn agents_page_created_token_is_shown_in_client_cli_instructions() {
        let config = ServerConfig::new(
            ExternalScheme::Https,
            "lore.example.com".into(),
            443,
            UiTheme::Parchment,
        )
        .unwrap();
        let agents = vec![AgentTokenSummary {
            name: "codex-laptop".into(),
            display_name: "Codex Laptop".into(),
            owner: Some("admin".into()),
            grants: Vec::new(),
            backend: "claude".into(),
            endpoint_id: None,
            machine_name: None,
            process_status: None,
            status: "offline".into(),
            created_at: time::OffsetDateTime::now_utc(),
        }];

        let html = render_agents_page(
            &config,
            "admin",
            true,
            UiTheme::Parchment,
            ColorMode::Light,
            "csrf",
            &agents,
            &[],
            &[],
            &[],
            Some("codex-laptop"),
            None,
            Some("lore_at_created_secret"),
        );

        assert!(html.contains("Copy this token now. Lore only shows it once."));
        assert!(html.contains(
            "lore setup-external https://lore.example.com --token lore_at_created_secret"
        ));
        assert!(html.contains("Bearer lore_at_created_secret"));
        assert!(html.contains("external agent"));
    }

    #[test]
    fn mobile_chat_header_keeps_status_glyph_before_manage_button() {
        let html = render_shell(
            PageShell {
                title: "Lore",
                username: None,
                is_admin: false,
                theme: UiTheme::Parchment,
                color_mode: ColorMode::Light,
                csrf_token: None,
                flash: None,
            },
            String::new(),
        );
        assert!(html.contains(".chat-header-actions {"));
        assert!(html.contains("margin-left: 0;"));
        assert!(html.contains("display: inline-flex;"));
        assert!(html.contains(".chat-header-actions { margin-left: auto; gap: var(--s-2); }"));
        assert!(html.contains(".chat-header-status { gap: 0; }"));

        let panel = render_chat_main_panel(
            &[ChatAgentSummary {
                name: "worker".into(),
                display_name: "Worker".into(),
                owner: "admin".into(),
                status: "thinking".into(),
                manage_enabled: false,
                last_message: None,
                last_message_time: None,
                profile_url: None,
                cwd: None,
                git_branch: None,
            }],
            Some("worker"),
            "csrf",
            &[],
        );
        assert!(panel.contains(r#"<div class="chat-header-actions">"#));
        assert!(
            panel.contains(r#"<span class="chat-header-status" id="chat-agent-status"></span>"#)
        );
        assert!(panel.contains(r#"id="chat-manage-btn""#));
    }

    #[test]
    fn desktop_chat_header_combines_backend_model_effort_and_folder() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[ChatAgentSummary {
                name: "worker".into(),
                display_name: "Worker".into(),
                owner: "admin".into(),
                status: "idle".into(),
                manage_enabled: false,
                last_message: None,
                last_message_time: None,
                profile_url: None,
                cwd: Some("/home/main/Documents/Lore/project-alpha".into()),
                git_branch: Some("main".into()),
            }],
            Some("worker"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(
            html.contains(
                r#"id="chat-agent-cwd" data-folder="project-alpha">project-alpha</span>"#
            )
        );
        assert!(!html.contains("Documents/Lore/project-alpha"));
        assert!(!html.contains("project-alpha (main)"));
        assert!(html.contains("parts.push(agentConfig.backend);"));
        assert!(html.contains("parts.push(agentConfig.model || 'default');"));
        assert!(html.contains("parts.push(agentConfig.effort || 'default');"));
        assert!(html.contains("if (folder) parts.push(folder);"));
        assert!(html.contains("metaEl.textContent = parts.join(' \\u00b7 ');"));
        assert!(
            html.contains("statusEl.innerHTML = '<span class=\"chat-status-glyph ' + statusClass")
        );
        assert!(!html.contains("chat-header-status-text"));
        assert!(
            html.contains("cwdEl.dataset.folder = parts.length ? parts[parts.length - 1] : '';")
        );
        assert!(html.contains(".chat-header-cwd {\n      flex: 1 1 auto;"));
        assert!(html.contains("text-align: center;"));
    }

    #[test]
    fn chat_page_uses_manager_glyph_for_enabled_manager_working_status() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[ChatAgentSummary {
                name: "worker".into(),
                display_name: "Worker".into(),
                owner: "admin".into(),
                status: "thinking".into(),
                manage_enabled: true,
                last_message: None,
                last_message_time: None,
                profile_url: None,
                cwd: None,
                git_branch: None,
            }],
            Some("worker"),
            "[]",
            0,
            None,
            &[],
        );
        assert!(
            html.contains(
                "var useManagerGlyph = shouldUseManagerGlyph(currentAgent, statusClass);"
            )
        );
        assert!(html.contains(format!("? '{}'", ICON_MANAGER).as_str()));
        assert!(html.contains("function shouldUseManagerGlyph(agent, statusClass) {"));
        assert!(html.contains("item.dataset.manageEnabled === 'true'"));
        assert!(html.contains(r#"data-manage-enabled="true""#));
        assert!(html.contains("glyph.innerHTML = useManagerGlyph ? '"));
        assert!(
            html.contains("if (currentAgent) updateAgentListStatus(currentAgent, agentStatus);")
        );
    }

    #[test]
    fn chat_page_escapes_inline_message_json_for_script_tags() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[ChatAgentSummary {
                name: "lore".into(),
                display_name: "Lore".into(),
                owner: "admin".into(),
                status: "idle".into(),
                manage_enabled: false,
                last_message: Some("</script> boom".into()),
                last_message_time: None,
                profile_url: None,
                cwd: None,
                git_branch: None,
            }],
            Some("lore"),
            r#"[{"role":"assistant","content":"</script> boom"}]"#,
            0,
            None,
            &[],
        );

        assert!(html.contains(
            r#"var chatMessages = [{"role":"assistant","content":"\u003C/script\u003E boom"}];"#
        ));
        assert!(
            !html.contains(
                r#"var chatMessages = [{"role":"assistant","content":"</script> boom"}];"#
            )
        );
    }

    #[test]
    fn chat_page_includes_message_timestamp_renderer_and_styles() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[],
            Some("lore"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("function formatChatTimestamp(value) {"));
        assert!(html.contains(".chat-msg-timestamp {"));
        assert!(html.contains("chat-msg-row-"));
    }

    #[test]
    fn chat_page_preserves_visible_message_order_across_panel_refreshes() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[],
            Some("lore"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains(
            "function mergeChatMessagesPreservingVisibleOrder(existingMessages, incomingMessages) {"
        ));
        assert!(
            html.contains("Object.assign({}, existingMessages[j], incomingByKey[existingKey])")
        );
        assert!(html.contains("incomingMessages = mergeChatMessagesPreservingVisibleOrder(chatMessages, incomingMessages);"));
        assert!(html.contains("incomingMessages = mergeChatMessagesPreservingVisibleOrder(cached.messages, incomingMessages);"));
    }

    #[test]
    fn chat_page_updates_agent_list_preview_for_assistant_message_events() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[],
            Some("worker"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("updateAgentListPreview(evt.agent, evt.data.content || '');"));
        assert!(html.contains(
            "} else if (evt.event_type === 'response_complete' && evt.data && evt.data.content) {\n        updateAgentListPreview(evt.agent, evt.data.content);"
        ));
        assert!(html.contains("moveAgentItemToTop(evt.agent);"));
        assert!(html.contains(
            "if (evt.event_type === 'message_sent' || (evt.event_type === 'message' && evt.data && evt.data.role === 'user'))"
        ));
        assert!(!html.contains(
            "}} else if (evt.event_type === 'message' && evt.data) {{\n        moveAgentItemToTop(evt.agent);"
        ));
        assert!(!html.contains(
            "} else if (evt.event_type === 'response_complete') {\n        updateAgentListPreview(evt.agent, evt.data && evt.data.content ? evt.data.content : '');"
        ));
    }

    #[test]
    fn chat_page_reconnects_stream_and_refreshes_on_resume() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[],
            Some("worker"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("function reconnectChatStreamForResume() {"));
        assert!(html.contains("eventSource.close();"));
        assert!(html.contains("connectSSE();"));
        assert!(html.contains("var chatLastFullPanelRefreshAt = Date.now();"));
        assert!(html.contains("var CHAT_PANEL_FETCH_TIMEOUT_MS = 15000;"));
        assert!(html.contains("var CHAT_WAKE_ACTIVITY_REFRESH_AFTER_MS = 60000;"));
        assert!(html.contains("var CHAT_FOREGROUND_RECONCILE_AFTER_MS = 300000;"));
        assert!(html.contains("var CHAT_FOREGROUND_RECONCILE_INTERVAL_MS = 30000;"));
        assert!(html.contains("function fetchChatJson(url, options, timeoutMs) {"));
        assert!(html.contains("controller.abort();"));
        assert!(html.contains("reconnectChatStreamForResume();\n  var resumeSeq = ++chatResumeRefreshSeq;\n  var refreshAgent = currentAgent;\n  var requestSeq = ++chatPanelRequestSeq;"));
        assert!(html.contains("fetchDesktopChatPanel(refreshAgent, false, 'normal', requestSeq)"));
        assert!(html.contains("chatResumeRefreshTimer = setTimeout(function() {"));
        assert!(html.contains("finishChatResumeRefresh(resumeSeq);"));
        assert!(html.contains(".catch(function() {\n      reconnectChatStreamForResume();"));
        assert!(html.contains(
            "return (now - Math.max(chatLastStreamEventAt, chatLastFullPanelRefreshAt)) > CHAT_RESUME_STALE_AFTER_MS;"
        ));
        assert!(html.contains("function refreshChatAfterWakeActivity() {"));
        assert!(html.contains(
            "if (now - chatLastFullPanelRefreshAt > CHAT_WAKE_ACTIVITY_REFRESH_AFTER_MS) return true;"
        ));
        assert!(html.contains(
            "return (now - Math.max(chatLastStreamEventAt, chatLastResumeRefreshAt)) > CHAT_WAKE_ACTIVITY_REFRESH_AFTER_MS;"
        ));
        assert!(html.contains("function reconcileVisibleChatIfStale() {"));
        assert!(html.contains(
            "if (now - chatLastFullPanelRefreshAt > CHAT_FOREGROUND_RECONCILE_AFTER_MS) {"
        ));
        assert!(html.contains(
            "eventSource.addEventListener('heartbeat', function() {\n    markChatStreamAlive();"
        ));
        assert!(html.contains("window.addEventListener('online', function() {"));
        assert!(html.contains(
            "window.addEventListener('pointerdown', refreshChatAfterWakeActivity, { capture: true, passive: true });"
        ));
        assert!(
            html.contains(
                "window.addEventListener('keydown', refreshChatAfterWakeActivity, true);"
            )
        );
        assert!(html.contains(
            "setInterval(reconcileVisibleChatIfStale, CHAT_FOREGROUND_RECONCILE_INTERVAL_MS);"
        ));
        assert!(html.contains(
            "if (document.visibilityState === 'visible') {\n    if (restorePersistedChatAgentSelection('replace')) return;\n    refreshChatOnResume(false);"
        ));
    }

    #[test]
    fn chat_page_refresh_preserves_focused_composer_and_bottom_scroll() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[],
            Some("worker"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("var chatPanelRefreshScrollSnapshot = null;"));
        assert!(html.contains("function captureChatComposerState() {"));
        assert!(html.contains("focused: input === document.activeElement,"));
        assert!(html.contains("function restoreChatComposerState(snapshot) {"));
        assert!(html.contains("input.focus({ preventScroll: true });"));
        assert!(
            html.contains("function shouldApplyChatRefreshWithoutPanelReplace(selectedAgent) {")
        );
        assert!(html.contains("return chatInputIsFocused();"));
        assert!(html.contains(
            "if (!fromCache && shouldApplyChatRefreshWithoutPanelReplace(selectedAgent)) {"
        ));
        assert!(html.contains(
            "renderMessages();\n    updateHeaderStatus();\n    setActiveAgentInList(currentAgent);"
        ));
        assert!(html.contains("scheduleChatResizeScrollRestore(activeSnapshot);"));
        assert!(html.contains("var composerSnapshot = captureChatComposerState();"));
        assert!(html.contains("var scrollSnapshot = chatPanelRefreshScrollSnapshot || captureChatResizeScrollSnapshot();"));
        assert!(html.contains("restoreChatComposerState(composerSnapshot);"));
        assert!(html.contains("scheduleChatResizeScrollRestore(scrollSnapshot);"));
        assert!(html.contains("chatPanelRefreshScrollSnapshot = panelRefreshScrollSnapshot;"));
    }

    #[test]
    fn desktop_chat_restores_persisted_agent_selection() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[ChatAgentSummary {
                name: "worker".into(),
                display_name: "Worker".into(),
                owner: "admin".into(),
                status: "idle".into(),
                manage_enabled: false,
                last_message: None,
                last_message_time: None,
                profile_url: None,
                cwd: None,
                git_branch: None,
            }],
            None,
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("function readLastChatAgent() {"));
        assert!(html.contains("localStorage.getItem('lastChatAgent') || '';"));
        assert!(html.contains("function canRestoreChatAgent(agent) {"));
        assert!(html.contains(
            "document.querySelector('.chat-agent-item[data-agent=\"' + CSS.escape(agent) + '\"]')"
        ));
        assert!(html.contains("function restorePersistedChatAgentSelection(historyMode) {"));
        assert!(html.contains("if (currentAgent || isMobileChatLayout()) return false;"));
        assert!(html.contains("if (chatRestoreInFlight) return true;"));
        assert!(html.contains("chatRestoreInFlight = true;"));
        assert!(html.contains(
            "loadDesktopChatPanel(savedAgent, historyMode || false)\n    .catch(function() {})"
        ));
        assert!(html.contains(".finally(function() { chatRestoreInFlight = false; });"));
        assert!(html.contains(
            "if (!restorePersistedChatAgentSelection('replace')) {\n  initializeChatPanel();\n}"
        ));
        assert!(html.contains("if (restorePersistedChatAgentSelection('replace')) return;"));
        assert!(html.contains(
            "history.replaceState({ agent: currentAgent }, '', currentChatUrl(currentAgent));"
        ));
        assert!(html.contains(r#"<div class="chat-empty">"#));
        assert!(html.contains(r#"data-agent="worker""#));
        assert!(html.contains("var currentAgent = null;"));
    }

    #[test]
    fn desktop_chat_switches_from_memory_cache_and_refreshes_in_background() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[ChatAgentSummary {
                name: "worker".into(),
                display_name: "Worker".into(),
                owner: "admin".into(),
                status: "idle".into(),
                manage_enabled: false,
                last_message: None,
                last_message_time: None,
                profile_url: None,
                cwd: None,
                git_branch: None,
            }],
            Some("worker"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("var CHAT_PANEL_CACHE_LIMIT = 100;"));
        assert!(html.contains("var chatPanelCache = {};"));
        assert!(html.contains("function cacheCurrentChatPanelState(includePanelHtml) {"));
        assert!(html.contains("function applyCachedChatPanel(agent, pushHistory) {"));
        assert!(html.contains("usedCache = applyCachedChatPanel(agent, pushHistory);"));
        assert!(html.contains(
            "return fetchDesktopChatPanel(agent, pushHistory, usedCache ? 'background' : 'normal', requestSeq);"
        ));
        assert!(html.contains(
            "if (applyMode === 'background' && currentAgent !== requestedAgent) return data;"
        ));
        assert!(html.contains(
            "if (applyMode === 'background' && (chatConfigOpen || chatManageOpen || expandedTextEditorState)) return data;"
        ));
        assert!(
            html.contains("if (requestSeq && requestSeq !== chatPanelRequestSeq) return data;")
        );
        assert!(html.contains("cacheChatPanelResponse(data);"));
        assert!(html.contains("function updateCachedChatPanelFromEvent(evt) {"));
        assert!(html.contains(
            "if (evt.agent !== currentAgent) {\n        updateCachedChatPanelFromEvent(evt);\n        return;\n      }"
        ));
        assert!(html.contains("cacheCurrentChatPanelState(false);"));
    }

    #[test]
    fn chat_page_includes_expanded_text_editor_shell_for_large_config_fields() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[],
            Some("worker"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains(r#"id="expanded-text-editor""#));
        assert!(html.contains("function openExpandedTextEditor(sourceId) {"));
        assert!(html.contains("function saveExpandedTextEditor() {"));
        assert!(html.contains(r#"data-editor-save="pinned""#));
        assert!(html.contains(r#"data-editor-save="manage""#));
        assert!(html.contains(
            r#"<div class="chat-config-field chat-config-field-wide">
      <label class="chat-config-label" for="cfg-pinned-context">Pinned Context</label>"#
        ));
        assert!(html.contains(
            r#"<div class="chat-config-field chat-config-field-wide" id="cfg-project-context-field" style="display:none;">"#
        ));
        assert!(html.contains(
            r#"<div class="chat-config-field chat-config-field-wide">
      <label class="chat-config-label" for="mgr-goals">Goals</label>"#
        ));
        assert!(html.contains(r#"for="mgr-stopping">Stopping Point</label>"#));
        assert!(html.contains(r#"for="mgr-checks">Periodic Checks</label>"#));
        assert!(html.contains(r#"for="mgr-redflags">Red Flags</label>"#));
        let manage_panel_pos = html
            .find(r#"id="chat-manage-panel""#)
            .expect("manager panel");
        let manage_toggle_pos = html.find(r#"id="mgr-toggle""#).expect("manager toggle");
        let manage_backend_pos = html
            .find(r#"id="mgr-backend""#)
            .expect("manager backend select");
        let manage_goals_pos = html.find(r#"id="mgr-goals""#).expect("manager goals field");
        assert!(manage_panel_pos < manage_toggle_pos);
        assert!(manage_toggle_pos < manage_backend_pos);
        assert!(manage_toggle_pos < manage_goals_pos);
        assert!(html.contains(".chat-config-inner {\n      width: 100%;\n      max-width: 100%;"));
        assert!(html.contains(".chat-config-field {\n      display: flex;\n      flex-direction: column;\n      gap: var(--s-1);\n      width: 100%;\n      max-width: 400px;"));
        assert!(html.contains(".chat-config-field-wide {\n      max-width: none;"));
        assert!(html.contains(".chat-config-textarea {\n      width: 100%;\n      max-width: 100%;\n      min-width: 0;"));
        assert!(html.contains("overflow-x: hidden;\n      overscroll-behavior: none;"));
        assert!(!html.contains(r#"title="Edit Pinned Context""#));
        assert!(!html.contains(r#"title="Edit Goals""#));
        assert!(!html.contains(r#"title="Edit Stopping Point""#));
        assert!(!html.contains(r#"title="Edit Periodic Checks""#));
        assert!(!html.contains(r#"title="Edit Red Flags""#));
        assert!(html.contains(
            "codex: ['default', 'gpt-5.5', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-5.3-codex', 'gpt-5.3-codex-spark', 'gpt-5.2']"
        ));
        assert!(html.contains("function applyBackendModelOptions(options) {"));
        assert!(html.contains("applyBackendModelOptions(data.model_options);"));
        assert!(html.contains("codex: ['default', 'minimal', 'low', 'medium', 'high', 'xhigh']"));
        assert!(html.contains("function syncExpandedTextEditorViewport() {"));
        assert!(html.contains("scheduleExpandedTextEditorViewportSync();"));
        assert!(html.contains("window.visualViewport.addEventListener('resize'"));
        assert!(html.contains(
            "var shell = overlay ? overlay.querySelector('.expanded-editor-shell') : null;"
        ));
        assert!(html.contains(
            "shell.style.left = Math.max(0, Math.round(window.visualViewport.offsetLeft)) + 'px';"
        ));
        assert!(html.contains(
            "shell.style.width = Math.max(0, Math.round(window.visualViewport.width)) + 'px';"
        ));
        assert!(html.contains("document.body.style.position = 'fixed';"));
        assert!(html.contains("window.scrollTo(0, restoreY);"));
        assert!(html.contains(".expanded-editor-actions-desktop {"));
        assert!(html.contains(".expanded-editor-actions-mobile {"));
        assert!(html.contains(".expanded-editor-overlay {"));
        assert!(html.contains("background: var(--bg);"));
        assert!(html.contains(".expanded-editor-shell {"));
        assert!(html.contains("position: absolute;"));
        assert!(html.contains("overflow: hidden;"));
        assert!(html.contains("overscroll-behavior: contain;"));
        assert!(html.contains("-webkit-overflow-scrolling: touch;"));
        assert!(html.contains("@media (max-width: 640px) {"));
    }

    #[test]
    fn admin_page_shows_lore_version_under_header() {
        let html = render_admin_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            &[],
            &[],
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            &ServerConfig::new(
                ExternalScheme::Https,
                "example.com".into(),
                443,
                UiTheme::Parchment,
            )
            .unwrap(),
            &crate::config::ExternalAuthConfig::default(),
            &crate::config::OidcConfig::default(),
            &AutoUpdateConfig::default(),
            &ManagerPromptConfig::default(),
            &LibrarianConfig::default(),
            &[],
            &GitExportConfig::default(),
            None,
            None,
            None,
            &[],
            &[],
            &[],
            &[],
            None,
            "users",
        );

        assert!(html.contains(r#"<div class="admin-page-header">"#));
        assert!(html.contains(r#"<h1 class="page-title">Admin</h1>"#));
        assert!(html.contains(&format!(
            r#"<p class="admin-version">Lore v{}</p>"#,
            env!("CARGO_PKG_VERSION")
        )));
        assert!(html.contains(".admin-version {"));
        assert!(html.contains("font-size: 0.85rem;"));
    }

    #[test]
    fn settings_page_renders_change_password_form() {
        let html = render_settings_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "antony",
            "csrf-token",
            None,
            None,
            UiTheme::Parchment,
            true,
            None,
        );

        assert!(html.contains(r#"<h2>Account</h2>"#));
        assert!(html.contains("Signed in as"));
        assert!(html.contains("antony"));
        assert!(html.contains(r#"action="/ui/settings/password""#));
        assert!(html.contains(r#"name="current_password" autocomplete="current-password""#));
        assert!(html.contains(r#"name="password" autocomplete="new-password""#));
        assert!(html.contains(r#"name="confirm_password" autocomplete="new-password""#));
        assert!(html.contains(r#"<button type="submit" class="btn-lg">Change password</button>"#));
    }

    #[test]
    fn admin_manager_special_case_fields_use_expanded_editor() {
        let html = render_admin_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            &[],
            &[],
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            &ServerConfig::new(
                ExternalScheme::Https,
                "example.com".into(),
                443,
                UiTheme::Parchment,
            )
            .unwrap(),
            &crate::config::ExternalAuthConfig::default(),
            &crate::config::OidcConfig::default(),
            &AutoUpdateConfig::default(),
            &ManagerPromptConfig::default(),
            &LibrarianConfig::default(),
            &[],
            &GitExportConfig::default(),
            None,
            None,
            None,
            &[],
            &[],
            &[],
            &[],
            None,
            "manager",
        );

        assert!(html.contains(r#"data-expanded-editor-preview-for="manager-review-prompt""#));
        assert!(html.contains(r#"data-expanded-editor-preview-for="manager-periodic-prompt""#));
        assert!(html.contains(r#"data-expanded-editor-preview-for="manager-validate-prompt""#));
        assert!(html.contains(r#"class="chat-config-textarea expanded-editor-source""#));
        assert!(html.contains(r#"style="display:none;""#));
        assert!(html.contains(r#"data-editor-label="Review Latest Output Prompt""#));
        assert!(html.contains(r#"data-editor-label="Run Periodic Checks Prompt""#));
        assert!(html.contains(r#"data-editor-label="Validate Periodic Check Results Prompt""#));
        assert!(
            html.contains(r#"onclick="return openManagerPromptEditor('manager-review-prompt')""#)
        );
        assert!(!html.contains(r#"data-manager-edit-button="#));
        assert!(!html.contains(r#"class="btn-sm manager-prompt-edit-button""#));
        assert!(!html.contains(r#"aria-disabled="true""#));
        assert!(html.contains("window.openManagerPromptEditor = function(targetId) {"));
        assert!(html.contains("syncManagerPromptEditor(toggle);"));
        assert!(html.contains("return openExpandedTextEditor(targetId);"));
        assert!(!html.contains(".chat-config-field-header {"));
        assert!(!html.contains(".chat-config-field-actions {"));
        assert!(!html.contains(".manager-prompt-edit-button[aria-disabled=\"true\"]"));
        assert!(html.contains("function syncExpandedEditorPreview(sourceId) {"));
        assert!(!html.contains("var editButton = document.querySelector("));
        assert!(html.contains("textarea.removeAttribute('disabled');"));
        assert!(html.contains("textarea.setAttribute('disabled', 'disabled');"));
    }

    #[test]
    fn chat_page_includes_message_exclusion_swipe_hooks() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf",
            true,
            &[],
            Some("worker"),
            r#"[{"id":1,"role":"user","content":"hello"}]"#,
            0,
            None,
            &[],
        );

        assert!(html.contains("function bindChatMessageMutationGestures() {"));
        assert!(html.contains("function toggleChatMessageContextExclusion(messageId, excluded) {"));
        assert!(html.contains("CHAT_MESSAGE_SWIPE_TOGGLE_THRESHOLD = 30;"));
        assert!(html.contains(".chat-msg-swipe-action {"));
        assert!(html.contains(".chat-msg-excluded {"));
        assert!(html.contains("data-chat-msg-id="));
    }

    #[test]
    fn chat_page_locks_mobile_text_size_adjustment() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf123",
            true,
            &[],
            Some("agent-main"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("-webkit-text-size-adjust: 100%;"));
        assert!(html.contains("text-size-adjust: 100%;"));
        assert!(html.contains(".chat-messages {\n      height: 100%;"));
        assert!(html.contains(".chat-msg {\n      max-width: 80%;"));
        assert!(html.contains(".chat-input {\n      flex: 1;"));
    }

    #[test]
    fn chat_page_preserves_bottom_scroll_across_mobile_viewport_resize() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf123",
            true,
            &[],
            Some("agent-main"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("var chatViewportResizeRestorePending = false;"));
        assert!(html.contains("var chatViewportResizeRestoreSeq = 0;"));
        assert!(html.contains("function captureChatResizeScrollSnapshot() {"));
        assert!(html.contains("follow: !!chatFollowScroll || chatIsNearBottom(container, 96),"));
        assert!(html.contains("container.scrollTop = container.scrollHeight;"));
        assert!(html.contains("function scheduleChatResizeScrollRestore(snapshot) {"));
        assert!(html.contains("if (chatViewportResizeRestorePending) {\n        updateChatJumpButton();\n        return;"));
        assert!(html.contains("window.addEventListener('resize', function() {"));
        assert!(html.contains("window.addEventListener('orientationchange', function() {"));
        assert!(html.contains("scheduleChatResizeScrollRestore(snapshot);"));
    }

    #[test]
    fn chat_page_submits_on_desktop_enter_but_keeps_shift_enter_newline() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf123",
            true,
            &[],
            Some("agent-main"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("function handleChatKey(e) {"));
        assert!(html.contains("if (!e || e.key !== 'Enter') return true;"));
        assert!(
            html.contains("if (e.shiftKey || e.isComposing || e.keyCode === 229) return true;")
        );
        assert!(html.contains("if (isMobileChatLayout()) return true;"));
        assert!(html.contains("form.requestSubmit();"));
        assert!(html.contains(r#"onkeydown="return handleChatKey(event)"></textarea>"#));
    }

    #[test]
    fn chat_composer_autosize_avoids_per_character_height_probe() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf123",
            true,
            &[],
            Some("agent-main"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("var valueLength = (input.value || '').length;"));
        assert!(
            html.contains("var prevValueLength = parseInt(input.dataset.chatComposerValueLength")
        );
        assert!(html.contains(
            "function measureChatInputContentHeight(input, isBorderBox, borderY, useClone)"
        ));
        assert!(
            html.contains(
                "if (!useClone) return input.scrollHeight + (isBorderBox ? borderY : 0);"
            )
        );
        assert!(html.contains(
            "var needsShrinkProbe = !!input.style.height && valueLength <= prevValueLength;"
        ));
        assert!(html.contains("var measuredHeight = measureChatInputContentHeight(input, isBorderBox, borderY, needsShrinkProbe);"));
        assert!(!html.contains("input.style.height = 'auto';"));
        assert!(html.contains("input.dataset.chatComposerValueLength = String(valueLength);"));
    }

    #[test]
    fn chat_page_initializer_does_not_reference_removed_long_press_handler() {
        let html = render_chat_page(
            UiTheme::Parchment,
            ColorMode::Light,
            "admin",
            "csrf123",
            true,
            &[],
            Some("agent-main"),
            "[]",
            0,
            None,
            &[],
        );

        assert!(html.contains("clearChatMessageSwipeGesture();"));
        assert!(!html.contains("cancelChatMessageLongPress();"));
    }

    #[test]
    fn shell_uses_css_only_system_color_mode_bootstrap() {
        let html = render_shell(
            PageShell {
                title: "Lore",
                username: None,
                is_admin: false,
                theme: UiTheme::Parchment,
                color_mode: ColorMode::System,
                csrf_token: None,
                flash: None,
            },
            "<p>content</p>".into(),
        );

        assert!(html.contains(r#"<html lang="en" data-color-mode="system">"#));
        assert!(html.contains(r#"<meta name="color-scheme" content="light dark">"#));
        assert!(html.contains(r#"root.setAttribute('data-color-mode', mode);"#));
        assert!(html.contains(r#"if (mode === 'system') {"#));
        assert!(html.contains(r#"root.removeAttribute('data-resolved-color-mode');"#));
        assert!(html.contains(r#"root.style.colorScheme = 'light dark';"#));
        assert!(html.contains(r#"--system-color-mode: light;"#));
        assert!(html.contains(r#"--system-color-mode: dark;"#));
        assert!(html.contains(r#":root[data-color-mode="system"] {"#));
        assert!(html.contains(r#"@media (prefers-color-scheme: dark) {"#));
        assert!(!html.contains(r#"window.matchMedia('(prefers-color-scheme: dark)')"#));
        assert!(
            !html.contains(
                r#"window.getComputedStyle(root).getPropertyValue('--system-color-mode');"#
            )
        );
        assert!(!html.contains(r#"data-resolved-color-mode="light"] {"#));
        assert!(!html.contains(r#"data-resolved-color-mode="dark"] {"#));
    }

    #[test]
    fn code_blocks_follow_selected_theme_mode_palette() {
        let light = shared_styles(UiTheme::Parchment, ColorMode::Light);
        assert!(light.contains("--code-bg: #f6eee6;"));
        assert!(light.contains("--code-ink: #4d3325;"));

        let dark = shared_styles(UiTheme::Parchment, ColorMode::Dark);
        assert!(dark.contains("--code-bg: #120e0a;"));
        assert!(dark.contains("--code-ink: #f0e6d8;"));
    }
}
