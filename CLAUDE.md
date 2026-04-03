# Lore

Lore is a knowledge base server written in Rust (Axum). It serves a web UI, REST API, and MCP endpoint from a single binary.

## Architecture

- `src/main.rs` — server entry point (`lore-server` binary)
- `src/bin/lore.rs` — client CLI (`lore` binary)
- `src/api.rs` — all HTTP routes (UI pages, REST API, MCP)
- `src/ui.rs` — HTML rendering, CSS, and inline JS (no templates, no external CSS/JS files)
- `src/store.rs` — file-based storage (projects, blocks, metadata)
- `src/model.rs` — core data types (Block, BlockId, BlockType, ProjectName)
- `src/auth.rs` — authentication, sessions, tokens, role-based access
- `src/config.rs` — server configuration
- `src/librarian.rs` — AI librarian (search, Q&A, project actions)
- `src/audit.rs` — audit logging
- `src/versioning.rs` — block version history, git export
- `src/updater.rs` — auto-update mechanism
- `src/order.rs` — block ordering
- `src/error.rs` — error types

## UI Style Guide

**Read `STYLE.md` before making any UI changes.** It documents all button categories, icon conventions, CSS variables, spacing tokens, layout components, and the responsive breakpoint. Follow it to keep the UI consistent.

Key rules from STYLE.md:
- All styles live in `render_styles()` in `src/ui.rs` — no external CSS files
- All icons are inline SVGs using Lucide-style attributes (14x14, viewBox 0 0 24 24, stroke currentColor)
- Use the existing CSS variables (--s-1 through --s-8, --accent, --line, etc.) — don't hardcode values
- Six button categories exist with distinct purposes — pick the right one, don't invent new styles
- Single responsive breakpoint at 860px

## Build & Test

```
cargo build
cargo test
```

All tests must pass before release. Current test count is ~97.

## Release Process

Bump the version in `Cargo.toml`, commit, tag as `v{version}`, push tag. GitHub Actions builds binaries for 4 targets (linux x86_64, linux aarch64, macOS x86_64, macOS aarch64).

## Conventions

- No external JS or CSS dependencies — everything is self-contained in Rust source
- HTML is built with Rust `format!()` strings, not a template engine
- Blocks have UUIDs; projects have slugs (from display name) and UUIDs (in project.json)
- Internal links use `lore://` protocol with standard markdown link syntax
- The public repo (lore) is for all development; commercial/architectural docs go in lore-commercial
