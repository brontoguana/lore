#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

cd "$(git rev-parse --show-toplevel)"

SERVER="${LORE_PERSONAL_SERVER:-root@151.242.127.155}"
DOMAIN="${LORE_PERSONAL_DOMAIN:-lore.armino.me}"
PUBLIC_URL="${LORE_PERSONAL_PUBLIC_URL:-https://${DOMAIN}/}"
REMOTE_SERVICE_USER="${LORE_PERSONAL_SERVICE_USER:-lore}"
REMOTE_HOME="${LORE_PERSONAL_HOME:-/home/${REMOTE_SERVICE_USER}}"
REMOTE_DATA_DIR="${LORE_PERSONAL_DATA_DIR:-${REMOTE_HOME}/lore}"
REMOTE_BIND="${LORE_PERSONAL_BIND:-127.0.0.1:7043}"
REMOTE_BIN="${LORE_PERSONAL_REMOTE_BIN:-${REMOTE_HOME}/.local/bin/lore-server}"
REMOTE_CLIENT_UPLOAD="/tmp/lore-client-upload.$$"
REMOTE_UPLOAD="/tmp/lore-server-upload.$$"
REMOTE_BACKUP="/tmp/lore-server-backup.$$"
REMOTE_CLIENT_UPDATE_DIR="${LORE_PERSONAL_CLIENT_UPDATE_DIR:-${REMOTE_DATA_DIR}/updates}"
ORIGINAL_CARGO_TOML="$(mktemp)"
cp Cargo.toml "$ORIGINAL_CARGO_TOML"

VERSION_BUMPED=0
COMMIT_CREATED=0
TAG_CREATED=0
REMOTE_BINARY_SWAPPED=0
REMOTE_BACKUP_CREATED=0
DEPLOY_VERIFIED=0
CLIENT_TARGET="$(rustc -vV | sed -n 's/^host: //p' | head -1)"
INITIAL_ADMIN_REQUIRED=0
INITIAL_ADMIN_USERNAME=""
INITIAL_ADMIN_PASSWORD=""

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
                install -o '${REMOTE_SERVICE_USER}' -g '${REMOTE_SERVICE_USER}' -m 0755 '${REMOTE_BACKUP}' '${REMOTE_BIN}'
            fi
        "

        restart_remote_service >/dev/null 2>&1 || true
        check_remote_health >/dev/null 2>&1 || true
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

remote_quote() {
    printf "%q" "$1"
}

ensure_remote_layout() {
    local q_user q_home q_data q_bin_dir q_updates q_bin
    q_user=$(remote_quote "$REMOTE_SERVICE_USER")
    q_home=$(remote_quote "$REMOTE_HOME")
    q_data=$(remote_quote "$REMOTE_DATA_DIR")
    q_bin_dir=$(remote_quote "$(dirname "$REMOTE_BIN")")
    q_updates=$(remote_quote "$REMOTE_CLIENT_UPDATE_DIR")
    q_bin=$(remote_quote "$REMOTE_BIN")

    ssh "$SERVER" "set -eu
if ! id -u ${q_user} >/dev/null 2>&1; then
    useradd --system --create-home --home-dir ${q_home} --shell /usr/sbin/nologin ${q_user}
fi
install -d -o ${q_user} -g ${q_user} -m 0755 ${q_home}
install -d -o ${q_user} -g ${q_user} -m 0755 ${q_bin_dir} ${q_data} ${q_updates}
if [ -f ${q_bin} ]; then
    chown ${q_user}:${q_user} ${q_bin}
    chmod 0755 ${q_bin}
	fi"
}

configure_remote_setup_address() {
    ssh "$SERVER" "DATA_DIR=$(remote_quote "$REMOTE_DATA_DIR") DOMAIN=$(remote_quote "$DOMAIN") python3 - <<'PY'
import datetime
import json
import os
import tempfile

data_dir = os.environ['DATA_DIR']
domain = os.environ['DOMAIN']
config_dir = os.path.join(data_dir, 'config')
path = os.path.join(config_dir, 'server.json')
os.makedirs(config_dir, mode=0o700, exist_ok=True)

config = {}
if os.path.exists(path):
    with open(path, 'r', encoding='utf-8') as fh:
        config = json.load(fh)

now = datetime.datetime.now(datetime.timezone.utc)
config['external_scheme'] = 'https'
config['external_host'] = domain
config['external_port'] = 443
config['default_theme'] = config.get('default_theme') or 'parchment'
config['updated_at'] = config.get('updated_at') or [
    now.year,
    int(now.strftime('%j')),
    now.hour,
    now.minute,
    now.second,
    now.microsecond * 1000,
    0,
    0,
    0,
]

fd, tmp = tempfile.mkstemp(prefix='server.', suffix='.json', dir=config_dir)
with os.fdopen(fd, 'w', encoding='utf-8') as fh:
    json.dump(config, fh, indent=2)
    fh.write('\n')
os.replace(tmp, path)
PY
chown -R $(remote_quote "$REMOTE_SERVICE_USER"):$(remote_quote "$REMOTE_SERVICE_USER") $(remote_quote "$REMOTE_DATA_DIR")/config
chmod 0700 $(remote_quote "$REMOTE_DATA_DIR")/config
chmod 0600 $(remote_quote "$REMOTE_DATA_DIR")/config/server.json
"
}

write_remote_service() {
    local q_user q_bin q_data q_bind
    q_user=$(remote_quote "$REMOTE_SERVICE_USER")
    q_bin=$(remote_quote "$REMOTE_BIN")
    q_data=$(remote_quote "$REMOTE_DATA_DIR")
    q_bind=$(remote_quote "$REMOTE_BIND")

    ssh "$SERVER" "cat > /etc/systemd/system/lore-server.service" <<EOF
[Unit]
Description=Lore knowledge server
After=network.target

[Service]
Type=simple
User=${REMOTE_SERVICE_USER}
ExecStart=${REMOTE_BIN} --data-dir ${REMOTE_DATA_DIR} --bind ${REMOTE_BIND} start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    ssh "$SERVER" "set -eu
systemctl_path=\$(command -v systemctl || echo /bin/systemctl)
cat > /etc/sudoers.d/lore-server-restart <<EOF
${q_user} ALL=(root) NOPASSWD: \${systemctl_path} restart lore-server, \${systemctl_path} start lore-server, \${systemctl_path} daemon-reload
EOF
chmod 0440 /etc/sudoers.d/lore-server-restart
systemctl daemon-reload
systemctl enable lore-server >/dev/null
test -x ${q_bin}
install -d -o ${q_user} -g ${q_user} -m 0755 ${q_data}
printf 'installed unit for %s on %s\n' ${q_user} ${q_bind}
"
}

remote_admin_state() {
    ssh "$SERVER" "DATA_DIR=$(remote_quote "$REMOTE_DATA_DIR") python3 - <<'PY'
import os
import sqlite3
import sys

db_path = os.path.join(os.environ['DATA_DIR'], 'lore.db')
if not os.path.exists(db_path):
    print('needs-admin')
    sys.exit(0)

try:
    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
except Exception as exc:
    print(f'unknown: {exc}')
    sys.exit(0)

print('has-users' if count > 0 else 'needs-admin')
PY
"
}

prepare_initial_admin_credentials() {
    local state admin_user admin_password admin_confirm
    state=$(remote_admin_state)
    case "$state" in
        has-users)
            INITIAL_ADMIN_REQUIRED=0
            return 0
            ;;
        needs-admin)
            INITIAL_ADMIN_REQUIRED=1
            ;;
        *)
            echo "Cannot determine remote admin state: ${state}" >&2
            echo "Create the initial admin manually, then rerun this deploy." >&2
            exit 1
            ;;
    esac

    admin_user="${LORE_PERSONAL_ADMIN_USERNAME:-}"
    admin_password="${LORE_PERSONAL_ADMIN_PASSWORD:-}"

    if [ -z "$admin_user" ]; then
        if [ ! -t 0 ]; then
            echo "First install needs an admin user; set LORE_PERSONAL_ADMIN_USERNAME and LORE_PERSONAL_ADMIN_PASSWORD." >&2
            exit 1
        fi
        read -r -p "Initial Lore admin username for ${DOMAIN}: " admin_user
    fi

    if [ -z "$admin_password" ]; then
        if [ ! -t 0 ]; then
            echo "First install needs an admin password; set LORE_PERSONAL_ADMIN_PASSWORD." >&2
            exit 1
        fi
        read -r -s -p "Initial Lore admin password: " admin_password
        echo
        read -r -s -p "Confirm initial Lore admin password: " admin_confirm
        echo
        if [ "$admin_password" != "$admin_confirm" ]; then
            echo "Passwords do not match" >&2
            exit 1
        fi
    fi

    if [ "${#admin_password}" -lt 12 ]; then
        echo "Initial admin password must be at least 12 characters" >&2
        exit 1
    fi

    INITIAL_ADMIN_USERNAME="$admin_user"
    INITIAL_ADMIN_PASSWORD="$admin_password"
}

create_initial_admin_if_needed() {
    if [ "$INITIAL_ADMIN_REQUIRED" -ne 1 ]; then
        return 0
    fi

    echo "Creating initial admin on ${SERVER}..."
    printf '%s\n%s\n%s\n' "$INITIAL_ADMIN_USERNAME" "$INITIAL_ADMIN_PASSWORD" "$INITIAL_ADMIN_PASSWORD" |
        ssh "$SERVER" "runuser -u $(remote_quote "$REMOTE_SERVICE_USER") -- script -qec '$(remote_quote "$REMOTE_BIN") --data-dir $(remote_quote "$REMOTE_DATA_DIR") create-admin' /dev/null >/dev/null"
}

restart_remote_service() {
    ssh "$SERVER" "systemctl daemon-reload && (systemctl restart lore-server || systemctl start lore-server)"
}

check_remote_health() {
    ssh "$SERVER" "
for _ in 1 2 3 4 5 6 7 8 9 10; do
    status=\$(curl -s -o /dev/null -w \"%{http_code}\" --max-time 5 http://${REMOTE_BIND}/v1/health || true)
    case \"\$status\" in
        200|302|303|401|403|404)
            echo \"\$status\"
            exit 0
            ;;
    esac
    sleep 1
done
exit 1
"
}

check_public_health() {
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$PUBLIC_URL" || true)
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
if [[ "$CURRENT" == *-rc* ]]; then
    BASE=$(echo "$CURRENT" | sed 's/-rc[0-9]*//')
else
    BASE="$CURRENT"
    if git rev-parse -q --verify "refs/tags/v${BASE}" >/dev/null; then
        MAJOR=$(echo "$BASE" | cut -d. -f1)
        MINOR=$(echo "$BASE" | cut -d. -f2)
        PATCH=$(echo "$BASE" | cut -d. -f3)
        BASE="${MAJOR}.${MINOR}.$((PATCH + 1))"
    fi
fi
LAST_RC=$(git tag -l "v${BASE}-rc*" | sed "s/v${BASE}-rc//" | sort -n | tail -1)
NEXT_RC=$(( ${LAST_RC:-0} + 1 ))
VERSION="${BASE}-rc${NEXT_RC}"
TAG="v${VERSION}"
echo "Personal quick deploy: ${TAG}"
echo "Target: ${SERVER} (${PUBLIC_URL})"

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

run_step "Checking personal-box admin bootstrap state" prepare_initial_admin_credentials

# --- Build and test ---
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
VERSION_BUMPED=1
run_step "Building" cargo build --release
run_step "Testing" cargo test
run_step "UI smoke" ./tests/run-smoke.sh
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

# --- Deploy ---
run_step "Preparing remote service account and directories" ensure_remote_layout
run_step "Configuring public setup address" configure_remote_setup_address

echo "Uploading server binary to ${SERVER}..."
scp -q target/release/lore-server "${SERVER}:${REMOTE_UPLOAD}"
ssh "$SERVER" "set -eu
if [ -x '${REMOTE_BIN}' ]; then
    cp '${REMOTE_BIN}' '${REMOTE_BACKUP}'
    chmod 0600 '${REMOTE_BACKUP}'
fi
install -o '${REMOTE_SERVICE_USER}' -g '${REMOTE_SERVICE_USER}' -m 0755 '${REMOTE_UPLOAD}' '${REMOTE_BIN}'
rm -f '${REMOTE_UPLOAD}'
"
if ssh "$SERVER" "test -f '${REMOTE_BACKUP}'"; then
    REMOTE_BACKUP_CREATED=1
fi
REMOTE_BINARY_SWAPPED=1

run_step "Writing systemd service" write_remote_service
run_step "Ensuring initial admin exists" create_initial_admin_if_needed

echo "Staging client binary for machine updates..."
if [ -z "$CLIENT_TARGET" ]; then
    echo "Could not determine local Rust host target"
    exit 1
fi
scp -q target/release/lore "${SERVER}:${REMOTE_CLIENT_UPLOAD}"
ssh "$SERVER" "set -eu
install -d -o '${REMOTE_SERVICE_USER}' -g '${REMOTE_SERVICE_USER}' -m 0755 '${REMOTE_CLIENT_UPDATE_DIR}'
install -o '${REMOTE_SERVICE_USER}' -g '${REMOTE_SERVICE_USER}' -m 0755 '${REMOTE_CLIENT_UPLOAD}' '${REMOTE_CLIENT_UPDATE_DIR}/lore-${CLIENT_TARGET}'
rm -f '${REMOTE_CLIENT_UPLOAD}'
"

echo "Restarting lore-server..."
restart_remote_service

# --- Verify ---
echo "Verifying remote binary..."
REMOTE_VERSION=$(ssh "$SERVER" "${REMOTE_BIN} --version 2>/dev/null" || echo "unknown")
echo "Server: ${REMOTE_VERSION}"

echo "Checking service health..."
HEALTH_STATUS=$(check_remote_health)
echo "Health check HTTP status: ${HEALTH_STATUS}"

echo "Checking public health..."
PUBLIC_STATUS=$(check_public_health) || {
    echo "Public health check failed: ${PUBLIC_URL} is unreachable"
    ssh "$SERVER" "systemctl status lore-server --no-pager || true; journalctl -u lore-server -n 50 --no-pager || true" || true
    exit 1
}
echo "Public health HTTP status: ${PUBLIC_STATUS}"

DEPLOY_VERIFIED=1
echo "Done: ${TAG}"
