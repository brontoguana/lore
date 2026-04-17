#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

cd "$(git rev-parse --show-toplevel)"

SERVER="lore@lore.simplehelp.io"
REMOTE_BIN="/home/lore/.local/bin/lore-server"

# --- Version bump ---
CURRENT=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
BASE=$(echo "$CURRENT" | sed 's/-rc[0-9]*//')
LAST_RC=$(git tag -l "v${BASE}-rc*" | sed "s/v${BASE}-rc//" | sort -n | tail -1)
NEXT_RC=$(( ${LAST_RC:-0} + 1 ))
VERSION="${BASE}-rc${NEXT_RC}"
TAG="v${VERSION}"
echo "Quick deploy: ${TAG}"

# --- Stage uncommitted changes ---
DIRTY=$(git diff --name-only HEAD)
if [ -n "$DIRTY" ]; then
    echo ""
    echo "Uncommitted changes:"
    echo "$DIRTY"
    echo ""
    read -p "Include in release? [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    git add -u
fi

# --- Build and test ---
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
echo "Building..."
cargo build --release 2>&1 | tail -1
echo "Testing..."
cargo test 2>&1 | tail -3
echo ""

# --- Commit and tag (local only) ---
git add Cargo.toml
git commit -m "${TAG}"
git tag "$TAG"

# --- Deploy: SCP to /tmp then swap binary while service is running ---
echo "Uploading to ${SERVER}..."
scp -q target/release/lore-server "${SERVER}:/tmp/lore-server-upload"
ssh "$SERVER" "chmod +x /tmp/lore-server-upload && mv /tmp/lore-server-upload ${REMOTE_BIN}"

# --- Restart service ---
echo "Restarting..."
if ssh "$SERVER" "sudo systemctl restart lore-server" 2>/dev/null; then
    echo "Restarted via systemd"
else
    echo "sudo unavailable, using pkill..."
    ssh "$SERVER" "pkill -f 'lore-server.*start' || true; sleep 1; nohup ${REMOTE_BIN} --data-dir /home/lore/lore --bind 127.0.0.1:7043 start </dev/null >/dev/null 2>&1 &"
fi

# --- Verify ---
sleep 2
REMOTE_VERSION=$(ssh "$SERVER" "${REMOTE_BIN} --version 2>/dev/null" || echo "unknown")
echo "Server: ${REMOTE_VERSION}"
echo "Done: ${TAG}"
