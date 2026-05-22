# Changelog

## 2026-05-22

- Moved external-agent token creation behind a collapsed button at the bottom of the Machines section. The agent name, project permissions, and final create action now appear only after choosing to create an external agent, and selected external agents now show real token setup only immediately after create/regenerate instead of placeholder token text.
- Split the Lore CLI top-level help into explicit User Commands (`setup-machine`, `setup-external`) and Agent Commands sections so setup commands are clearly separated from external-agent and daemon operations.

## 2026-05-20

- Added first-class external agents. They are created and permissioned from the Agents page like normal agents, can be selected to copy/regenerate their setup token, do not appear in chat, and use `lore setup-external <url> --token <token>` for client-only CLI setup without registering a machine.
- Added `lore setup-machine` as the explicit machine-agent setup command and updated external-agent setup instructions plus server-hosted CLI installers to show the external-agent and machine-agent paths separately.
- Replaced Gemini CLI process-agent support with Antigravity CLI (`agy`). Lore now exposes `agy` as the CLI backend, maps legacy stored `gemini` backend values to `agy`, invokes `agy` print mode with permission bypass and a 15-minute print timeout, treats plain stdout as the assistant response, and detects Antigravity OAuth/auth prompts even when the CLI exits successfully.
- Added headless Antigravity auth handling for machine-service agents. When the Antigravity OAuth token file exists and no SSH session variables are present, Lore sets SSH-style environment markers only for the `agy` child process so Antigravity uses file-token storage under systemd.

## 2026-05-14

- Expanded the README's agent control and orchestration positioning, including browser-managed agents, backend routing, machine execution, visible failures, retries, and live status.
- Switched the README hero screenshot to `lore-screenshot-2.jpg`.
- Refreshed the README with a top-of-page product screenshot, a friendlier overview for general users, clearer developer positioning, and reorganized install/build sections.
- Fixed Windows release builds by correcting a platform-only updater permission-copy parameter reference, and made full-release matrix builds continue other platform artifacts when one target fails.
- Fixed full-release automation so GitHub release workflows inject tag versions portably on macOS/Linux/Windows runners, and the local release script no longer fails when `Cargo.lock` is intentionally ignored.
- Installed a local user systemd unit for this machine's Lore client service so it is enabled under `default.target`, uses `/home/main/.local/bin/lore service --fg`, and can start after reboot via the user manager with lingering enabled.

## 2026-05-12

- Fixed agent chat background refreshes so same-agent panel refreshes no longer replace the focused composer while the user is typing. Refreshes now update messages/status in place and preserve composer value, focus, selection, and bottom-follow scroll snapshots across full panel swaps.

## 2026-05-09

- Added current date/time context to all Lore LLM prompt builders: process-agent turns, manager prompts, API agents, API side questions, CLI/API compaction, and librarian answer/action prompts now include a UTC line with weekday, date, and time.
- Hardened agent chat resume updates after long idle/browser sleep. The chat UI now times out stale panel fetches, reconnects SSE with heartbeat awareness, refreshes on online/wake activity, and periodically reconciles the visible selected chat from the no-store panel endpoint.

## 2026-05-06

- Fixed CLI backend auth-prompt hangs. Agent and manager CLI runners now watch backend stdout/stderr for non-JSON login, OAuth, and API-key prompts, report a visible chat error, terminate the child process, and finalize the active turn instead of leaving the agent stuck in thinking.
- Fixed CLI backend executable resolution to prefer explicit user-local installs such as `~/.npm-global/bin/gemini` before system `PATH` binaries, and report Gemini startup blockers such as disabled YOLO mode as visible agent errors.
- Fixed CLI backend spawn retry loops so identical failures for the same claimed user turn stop after three attempts, report a final visible error, and finalize that turn instead of retrying indefinitely.
- Fixed live chat sidebar ordering so assistant/error/tool activity updates previews and status without moving conversations; only user-authored messages affect conversation recency.
- Fixed chat sidebar previews so empty agent completion events no longer overwrite the last assistant preview with "No messages yet"; completions with content still update to the final response text.

## 2026-05-05

- Fixed chat panel refresh reconciliation so a queued follow-up message keeps its visible end-of-chat position when the agent claims it, instead of jumping back to its raw database insertion point.

## 2026-05-04

- Fixed mobile chat scroll restoration during iPhone rotation so conversations that are already at the end stay anchored to the newest message after viewport height changes.

## 2026-05-01

- Fixed machine-agent create/control JSON error handling on the Agents page. Machine list/create/mkdir/stop/restart/remove endpoints now return JSON errors for early session, CSRF and validation failures instead of generic HTML UI error pages, and the browser surfaces non-JSON response bodies instead of only showing "Failed to create agent".
- Added server journal logging for failed machine JSON actions, including machine-returned `{error}` payloads from create/list/mkdir/control operations.
- Fixed agent/role grant parsing so "No access" style values are accepted as omitted grants during agent creation instead of failing validation.
- Fixed machine-agent project grant parsing to tolerate literal escaped newline separators from already-loaded Agents pages, and corrected the create-agent UI to join selected project grants with a real newline separator.
- Fixed project-level `lore grep` coverage so it searches document blocks as well as legacy project blocks, includes document source metadata in results, and can match block ID fragments from `docs read` markers.

## 2026-04-30

- Improved Lore CLI document-edit ergonomics with robust `blocks edit` text sources for leading-dash/multiline replacements, native `docs append`, `docs insert-after-heading`, and `blocks append` workflows, dry-run/diff previews, and project labels on write outputs.

## 2026-04-27

- Fixed librarian/API-agent provider endpoint handling so OpenAI-compatible base URLs and bare hosts are normalized to chat-completions URLs when possible, and provider `detail` errors are surfaced when `error.message` is empty.
- Fixed machine-service reconciliation so server-assigned agents update and restart when the server-side backend changes, preventing stale local Claude overrides after switching an agent to Codex.
- Fixed UI HTML escaping so renderer output preserves literal `/` characters in document/setup text while still escaping XSS-sensitive characters.

## 2026-04-26

- Changed agent setup CLI install advice to use server-hosted `/install-cli.sh` and `/install-cli.ps1` endpoints, backed by the server's staged `/downloads/lore/{target}` CLI artifacts, instead of raw GitHub installer URLs.
- Fixed external-proxy setup URLs so `http` plus port `443` is normalized to HTTPS, and personal-box deploy/bootstrap scripts pin Lore's public setup address to `https://lore.armino.me`.
- Added a Settings account form for changing your own password with current-password verification, confirmation matching, and other-session revocation.
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
