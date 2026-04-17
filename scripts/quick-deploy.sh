#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

cd "$(git rev-parse --show-toplevel)"

SERVER="lore@lore.simplehelp.io"
REMOTE_BIN="/home/lore/.local/bin/lore-server"

# Read current version from Cargo.toml
CURRENT=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo "Current: ${CURRENT}"

# Parse base version (strip any -rcN suffix)
BASE=$(echo "$CURRENT" | sed 's/-rc[0-9]*//')

# Find the highest rc tag for this base version
LAST_RC=$(git tag -l "v${BASE}-rc*" | sed "s/v${BASE}-rc//" | sort -n | tail -1)
if [ -z "$LAST_RC" ]; then
    NEXT_RC=1
else
    NEXT_RC=$((LAST_RC + 1))
fi

VERSION="${BASE}-rc${NEXT_RC}"
TAG="v${VERSION}"
echo "Quick deploy: ${TAG}"

# Include uncommitted changes
DIRTY=$(git diff --name-only HEAD)
if [ -n "$DIRTY" ]; then
    echo ""
    echo "Uncommitted changes:"
    echo "$DIRTY"
    echo ""
    read -p "Include in release? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    git add -A
fi

# Update Cargo.toml
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml

# Build and test
echo "Building..."
cargo build --release 2>&1 | tail -1
echo "Testing..."
cargo test 2>&1 | tail -3
echo ""

# Commit and tag (no push)
git add Cargo.toml
git commit -m "${TAG}"
git tag "$TAG"

# Deploy to server
echo "Deploying to ${SERVER}..."
scp target/release/lore-server "${SERVER}:/tmp/lore-server-upload"
ssh "$SERVER" "mv /tmp/lore-server-upload ${REMOTE_BIN} && chmod +x ${REMOTE_BIN}"
ssh "$SERVER" "sudo systemctl restart lore-server" 2>/dev/null \
    || ssh "$SERVER" "pkill -f 'lore-server.*start' && sleep 1 && nohup ${REMOTE_BIN} --data-dir /home/lore/lore --bind 127.0.0.1:7043 start </dev/null >/dev/null 2>&1 &"
echo ""

# Verify it came up
sleep 2
REMOTE_VERSION=$(ssh "$SERVER" "${REMOTE_BIN} --version 2>/dev/null" || echo "unknown")
echo "Server running: ${REMOTE_VERSION}"
echo "Done: ${TAG} (local only, not pushed to GitHub)"
