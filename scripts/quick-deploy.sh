#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

cd "$(git rev-parse --show-toplevel)"

SERVER="lore@lore.simplehelp.io"
REMOTE_BIN="/home/lore/.local/bin/lore-server"
REMOTE_UPLOAD="/tmp/lore-server-upload.$$"
REMOTE_BACKUP="/tmp/lore-server-backup.$$"
REMOTE_CLIENT_UPLOAD="/tmp/lore-client-upload.$$"
ORIGINAL_CARGO_TOML="$(mktemp)"
cp Cargo.toml "$ORIGINAL_CARGO_TOML"

VERSION_BUMPED=0
COMMIT_CREATED=0
TAG_CREATED=0
REMOTE_BINARY_SWAPPED=0
REMOTE_BACKUP_CREATED=0
DEPLOY_VERIFIED=0

cleanup() {
    local exit_code=$?
    set +e

    if [ "$exit_code" -ne 0 ] && [ "$VERSION_BUMPED" -eq 1 ] && [ "$COMMIT_CREATED" -eq 0 ]; then
        cp "$ORIGINAL_CARGO_TOML" Cargo.toml
        echo "Restored Cargo.toml after failed deploy"
    fi

    if [ "$REMOTE_BINARY_SWAPPED" -eq 1 ] && [ "$DEPLOY_VERIFIED" -eq 0 ]; then
        echo "Deploy failed after remote binary swap; attempting remote rollback..."
        ssh "$SERVER" "
            if [ -f '${REMOTE_BACKUP}' ]; then
                mv '${REMOTE_BACKUP}' '${REMOTE_BIN}' &&
                chmod +x '${REMOTE_BIN}'
            fi
        "

        if restart_remote_service >/dev/null 2>&1; then
            check_remote_health >/dev/null 2>&1 || true
            echo "Rollback completed"
        else
            echo "Rollback restart attempt failed"
        fi
    fi

    if [ "$REMOTE_BACKUP_CREATED" -eq 1 ]; then
        ssh "$SERVER" "rm -f '${REMOTE_BACKUP}'" >/dev/null 2>&1 || true
    fi

    ssh "$SERVER" "rm -f '${REMOTE_UPLOAD}' '${REMOTE_CLIENT_UPLOAD}'" >/dev/null 2>&1 || true

    if [ "$exit_code" -ne 0 ] && [ "$COMMIT_CREATED" -eq 1 ]; then
        echo "Release commit ${TAG} was created locally before failure."
    fi

    if [ "$exit_code" -ne 0 ] && [ "$TAG_CREATED" -eq 1 ]; then
        echo "Release tag ${TAG} was created locally before failure."
    fi

    rm -f "$ORIGINAL_CARGO_TOML"
    exit "$exit_code"
}

trap cleanup EXIT

run_step() {
    local description=$1
    shift

    echo "${description}..."
    "$@"
}

restart_remote_service() {
    if ssh "$SERVER" "sudo -n systemctl restart lore-server" 2>/dev/null; then
        echo "Restarted via systemd"
    else
        echo "Systemd restart unavailable, using fallback start command..."
        ssh "$SERVER" "pkill -f 'lore-server.*start' || true; sleep 1; nohup ${REMOTE_BIN} --data-dir /home/lore/lore --bind 127.0.0.1:7043 start </dev/null >/dev/null 2>&1 &"
    fi
}

restart_remote_proxy() {
    if ssh "$SERVER" "sudo -n systemctl restart lore-caddy" 2>/dev/null; then
        echo "Restarted lore-caddy via systemd"
        return 0
    fi

    echo "lore-caddy restart unavailable without sudo"
    return 1
}

check_remote_health() {
    ssh "$SERVER" '
for _ in 1 2 3 4 5 6 7 8 9 10; do
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:7043/ || true)
    case "$status" in
        200|302|303|401|403|404)
            echo "$status"
            exit 0
            ;;
    esac
    sleep 1
done
exit 1
'
}

check_public_health() {
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 https://lore.simplehelp.io/ || true)
        case "$status" in
            200|302|303|401|403|404)
                echo "$status"
                return 0
                ;;
        esac
        sleep 1
    done
    return 1
}

# --- Version bump ---
CURRENT=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
BASE=$(echo "$CURRENT" | sed 's/-rc[0-9]*//')
LAST_RC=$(git tag -l "v${BASE}-rc*" | sed "s/v${BASE}-rc//" | sort -n | tail -1)
NEXT_RC=$(( ${LAST_RC:-0} + 1 ))
VERSION="${BASE}-rc${NEXT_RC}"
TAG="v${VERSION}"
echo "Quick deploy: ${TAG}"

HEAD_TAGS=$(git tag --points-at HEAD)
if echo "$HEAD_TAGS" | grep -Eq '^v.*-rc[0-9]+$'; then
    echo "HEAD already has a release candidate tag:"
    echo "$HEAD_TAGS" | grep -E '^v.*-rc[0-9]+$'
    echo "Aborting to avoid creating a duplicate quick deploy release."
    exit 1
fi

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
    echo "Tag ${TAG} already exists. Aborting."
    exit 1
fi

# --- Stage uncommitted changes ---
DIRTY=$(git status --porcelain)
if [ -n "$DIRTY" ]; then
    echo ""
    echo "Uncommitted changes:"
    echo "$DIRTY"
    echo ""
    if [ -t 0 ]; then
        read -p "Include in release? [y/N] " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    else
        echo "Non-interactive mode: auto-including changes"
    fi
    git add -A
fi

# --- Build and test ---
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
VERSION_BUMPED=1
run_step "Building" cargo build --release
run_step "Testing" cargo test
echo ""

# --- Commit and tag (local only) ---
git add Cargo.toml
if git diff --cached --quiet; then
    echo "No staged changes to release after version bump. Aborting."
    exit 1
fi

git commit -m "${TAG}"
COMMIT_CREATED=1
git tag "$TAG"
TAG_CREATED=1

# --- Deploy: SCP to /tmp then swap binary while service is running ---
echo "Uploading to ${SERVER}..."
scp -q target/release/lore-server "${SERVER}:${REMOTE_UPLOAD}"
ssh "$SERVER" "
    chmod +x '${REMOTE_UPLOAD}' &&
    cp '${REMOTE_BIN}' '${REMOTE_BACKUP}' &&
    mv '${REMOTE_UPLOAD}' '${REMOTE_BIN}'
"
REMOTE_BACKUP_CREATED=1
REMOTE_BINARY_SWAPPED=1

# --- Stage client binary for machine self-update (direct download, no GitHub release needed) ---
echo "Staging client binary for machine updates..."
ssh "$SERVER" "mkdir -p /home/lore/lore/updates"
scp -q target/release/lore "${SERVER}:${REMOTE_CLIENT_UPLOAD}"
ssh "$SERVER" "chmod +x '${REMOTE_CLIENT_UPLOAD}' && mv '${REMOTE_CLIENT_UPLOAD}' /home/lore/lore/updates/lore"

# --- Restart service ---
echo "Restarting..."
restart_remote_service

echo "Ensuring public proxy is up..."
ssh "$SERVER" "systemctl is-active lore-caddy >/dev/null 2>&1" || restart_remote_proxy || true

# --- Verify ---
echo "Verifying remote binary..."
REMOTE_VERSION=$(ssh "$SERVER" "${REMOTE_BIN} --version 2>/dev/null" || echo "unknown")
echo "Server: ${REMOTE_VERSION}"

echo "Checking service health..."
HEALTH_STATUS=$(check_remote_health)

echo "Health check HTTP status: ${HEALTH_STATUS}"
echo "Checking public health..."
PUBLIC_STATUS=$(check_public_health) || {
    echo "Public health check failed: https://lore.simplehelp.io/ is unreachable"
    ssh "$SERVER" "systemctl status lore-caddy --no-pager -n 20 || true" || true
    exit 1
}
echo "Public health HTTP status: ${PUBLIC_STATUS}"
DEPLOY_VERIFIED=1
echo "Done: ${TAG}"
