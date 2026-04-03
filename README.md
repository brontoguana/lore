# Lore

Lore is a self-hosted project memory system for humans and agents.

It stores project data as ordered typed blocks on disk, records project history, supports reversible versioning, and can export into Git. Humans use it through a browser UI. Agents connect via the CLI or MCP -- see the Agents page in the UI after setup.

## Server install

Install the server management binary:

```sh
curl -fsSL https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-server.sh | sh
```

Run the full setup:

```sh
lore-server install
```

This will:
1. Create an admin account (interactive prompt)
2. Ask for your domain name
3. Download and configure Caddy as an HTTPS reverse proxy
4. Start both services as systemd daemons (requires sudo)
5. Install a tightly scoped sudoers rule so future `lore-server update` runs can restart Lore and Caddy without prompting

Then open `https://yourdomain.com/setup` for agent-oriented setup instructions.

Other server commands:

```sh
lore-server status       # check if everything is running
lore-server update       # update to the latest release
lore-server uninstall    # remove services (keeps data)
lore-server clean        # remove services + binaries (keeps data)
```

Docker is not the primary install path today. Lore prioritizes direct binary installation and simple self-hosting.

## Current capabilities

- Human login with local auth, OIDC, and optional trusted-header auth
- Roles, users, sessions, and scoped agent tokens
- Generated setup pages at `/setup` and `/setup.txt`
- Lore links (`lore://` protocol) for cross-document and block-level linking
- Project-scoped librarian with optional edit approval
- Audit trails for auth, librarian activity, and project actions
- Reversible project version history with diff-style views
- Drag-and-drop block and project reordering
- Admin-configured Git export
- Optional GitHub-release-backed self-update for the CLI and server
- Per-user UI theme selection with server default fallback

## Build locally

```sh
cargo test -q
```

Binaries:

```sh
cargo run --bin lore-server
cargo run --bin lore -- --help
```
