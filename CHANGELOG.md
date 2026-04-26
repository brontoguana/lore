# Changelog

## 2026-04-26

- Added a long-idle wake refresh for agent chat so returning to a stale browser tab forces a no-store panel refresh on focus/visibility or first user activity after stream silence.
- Added `lore-server install --no-caddy` for installing only the Lore systemd service behind an existing external Caddy reverse proxy.
- Added `scripts/quick-deploy-personal.sh` to build, test, bootstrap, and update Lore on the personal `lore.armino.me` box without managing Caddy.
- Added `scripts/install-personal-first.sh` and installed it on BOX_PERSONAL as `/usr/local/sbin/install-lore-first.sh` for one-time sudo service setup before normal personal quick deploys.

## 2026-04-25

- Removed redundant expanded-editor launch glyph buttons from chat/manager config and admin manager prompt fields, keeping the multiline textarea or preview surface as the editor entry point.
- Made desktop chat composer Enter submit the message while Shift+Enter still inserts a newline; mobile keeps the existing return-key newline behavior.
- Combined the desktop agent chat toolbar metadata into the centered folder slot as backend/model/effort/folder, with the folder shortened to its basename.
- Widened agent chat config and manager large text fields so their inline summary surfaces span the available panel width while staying clamped to the device width on mobile.
- Stabilized agent chat composer autosizing so the message field no longer bounces between heights while typing.
- Added a small Lore version line directly under the Admin page header.
- Restored the last selected desktop chat agent when returning to `/ui/chat` without an explicit agent query, including refresh/resume paths.
- Reconciled machine-assigned agents from the server during service polling so locally missing agents can be re-imported into `agents.json` from the local token cache and reported as missing when they cannot be restored.
- Moved the agent chat manager enable/disable control to the top of the manager config panel.
- Added a generous desktop in-memory cache for agent chat panels so previously loaded agents switch instantly while a no-store refresh reconciles in the background.
- Stopped multiline chat composer Backspace from visibly jiggling the textarea by measuring shrink candidates in a hidden clone instead of collapsing the live field.

## 2026-04-24

- Removed the obsolete inline markdown block edit state from document pages so markdown edit lines use only the fullscreen expanded editor and browser back cannot surface the intermediate form.
- Switched the admin Project manager special-case prompt fields to the fullscreen expanded editor path so they no longer rely on inline textarea editing.
- Replaced the visible admin manager prompt textareas with expanded-editor preview panels backed by hidden source fields, so those prompts now use the fullscreen editor cleanly instead of looking like inline textarea editors.
- Made the fullscreen expanded editor track the mobile visual viewport so it resizes above the on-screen keyboard and keeps its action row visible just above the keyboard.
- Tightened document-page code-block containment so very long code lines stay bounded to the current screen width and scroll inside the code block instead of pushing the document horizontally off-screen.
- Switched project reserved sections such as Overview, File Map, and Agent Context to the shared fullscreen expanded editor path so desktop and mobile use the same edit flow with no inline intermediate form.
- Added Codex reasoning-effort selection to agent configuration and wired Codex process launches to pass the selected effort through to the Codex CLI.
- Locked the fullscreen expanded editor to the visible viewport and editor scroll area so document content cannot scroll underneath it and the editor cannot drift horizontally.
- Kept the fullscreen expanded editor backdrop fixed edge-to-edge while only the editor shell tracks the visual viewport, preventing document content from showing at the top or bottom edges.
- Added Codex model selection to agent configuration, using Codex's local model cache when available and a current documented Codex model fallback otherwise.
- Fixed admin manager prompt edit controls so the glyph edit button is right-aligned and ticking "Edit this prompt" reliably enables the shared expanded editor from either the button or preview.
- Hardened admin manager prompt editing so the glyph action has a dedicated right-aligned style slot and checked prompts explicitly remove the disabled source-field attribute before opening the expanded editor.
- Locked chat text-size adjustment on mobile so rotating the phone cannot leave agent chat messages or the composer stuck at an inflated Safari font size.
- Fixed project reserved-section expanded-editor saves so Agent Context, Overview, and File Map submit URL-encoded form bodies matching the UI endpoint instead of multipart `FormData`.
