# Changelog

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
