# Lore

Lore is a self-hosted project memory system for humans and agents.

It exposes:

- a browser UI
- a project-scoped HTTP API
- a native MCP endpoint
- a Rust CLI

Lore stores project data as ordered typed blocks on disk rather than in a traditional database. It also records project history, supports reversible versioning, and can export project state plus history into Git.

Install

CLI installer:

```sh
curl -fsSL https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-cli.sh | sh
```

Server installer:

```sh
curl -fsSL https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-server.sh | sh
```

The install scripts are designed to download versioned GitHub release artifacts, verify published checksums, and place the binaries in a predictable local install path.

Docker is not the primary install path today. Lore currently prioritizes direct binary installation and simple self-hosting.

Run

After installing the server:

```sh
LORE_DATA_ROOT=$HOME/.local/share/lore \
LORE_BIND=127.0.0.1:8080 \
lore-server
```

Then open:

```text
http://127.0.0.1:8080/setup
```

That setup flow explains when to use HTTP vs MCP and gives agent-oriented instructions for the specific Lore server URL you configure.

Updates

The CLI includes an optional self-update flow backed by GitHub releases:

```sh
lore self-update status
lore self-update check
lore self-update apply
lore self-update enable
```

The server also supports optional startup self-update from the admin UI. When enabled, `lore-server` checks the configured GitHub repo before it starts listening, installs a newer release in place if one exists, and relaunches itself once with the same arguments.

CLI usage

Set defaults once:

```sh
lore config set --url http://127.0.0.1:8080 --token YOUR_AGENT_TOKEN --project alpha.docs
```

Examples:

```sh
lore projects
lore self-update check
lore blocks list
lore grep "deployment"
lore blocks read BLOCK_ID
lore add "New note"
lore update BLOCK_ID "Updated content"
lore librarian answer "Summarise the current project status"
lore history list
lore history show VERSION_ID
```

Current capabilities

- Human login with local auth, OIDC, and optional trusted-header auth
- Roles, users, sessions, and scoped agent tokens
- Generated setup pages at `/setup` and `/setup.txt`
- Project-scoped answer librarian and project librarian
- Optional approval for project librarian actions
- Audit trails for auth, librarian activity, and project actions
- Reversible project version history with diff-style views
- Admin-configured Git export
- Optional GitHub-release-backed self-update for the CLI and server
- Per-user UI theme selection with server default fallback

Build locally

```sh
cargo test -q
```

Binaries:

```sh
cargo run --bin lore-server
cargo run --bin lore -- --help
```
