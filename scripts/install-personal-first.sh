#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${LORE_PERSONAL_DOMAIN:-lore.armino.me}"
SERVICE_USER="${LORE_PERSONAL_SERVICE_USER:-lore}"
SERVICE_HOME="${LORE_PERSONAL_HOME:-/home/${SERVICE_USER}}"
DATA_DIR="${LORE_PERSONAL_DATA_DIR:-${SERVICE_HOME}/lore}"
BIND="${LORE_PERSONAL_BIND:-127.0.0.1:7043}"
SERVER_BIN="${LORE_PERSONAL_REMOTE_BIN:-${SERVICE_HOME}/.local/bin/lore-server}"
UPDATE_DIR="${LORE_PERSONAL_CLIENT_UPDATE_DIR:-${DATA_DIR}/updates}"
SERVICE_FILE="/etc/systemd/system/lore-server.service"
SUDOERS_FILE="/etc/sudoers.d/lore-server-restart"
CADDYFILE="${LORE_PERSONAL_CADDYFILE:-/etc/caddy/Caddyfile}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this first-install script with sudo or as root." >&2
    echo "Example: sudo $0" >&2
    exit 1
fi

systemctl_path="$(command -v systemctl || echo /bin/systemctl)"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$SERVICE_HOME" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0755 "$SERVICE_HOME"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0755 "$(dirname "$SERVER_BIN")"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0755 "$DATA_DIR" "$UPDATE_DIR"
DATA_DIR="$DATA_DIR" DOMAIN="$DOMAIN" python3 - <<'PY'
import datetime
import json
import os
import tempfile

data_dir = os.environ["DATA_DIR"]
domain = os.environ["DOMAIN"]
config_dir = os.path.join(data_dir, "config")
path = os.path.join(config_dir, "server.json")
os.makedirs(config_dir, mode=0o700, exist_ok=True)

config = {}
if os.path.exists(path):
    with open(path, "r", encoding="utf-8") as fh:
        config = json.load(fh)

now = datetime.datetime.now(datetime.timezone.utc)
config["external_scheme"] = "https"
config["external_host"] = domain
config["external_port"] = 443
config["default_theme"] = config.get("default_theme") or "parchment"
config["updated_at"] = config.get("updated_at") or [
    now.year,
    int(now.strftime("%j")),
    now.hour,
    now.minute,
    now.second,
    now.microsecond * 1000,
    0,
    0,
    0,
]

fd, tmp = tempfile.mkstemp(prefix="server.", suffix=".json", dir=config_dir)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    json.dump(config, fh, indent=2)
    fh.write("\n")
os.replace(tmp, path)
PY
chown -R "$SERVICE_USER:$SERVICE_USER" "${DATA_DIR}/config"
chmod 0700 "${DATA_DIR}/config"
chmod 0600 "${DATA_DIR}/config/server.json"

if [ -f "$SERVER_BIN" ]; then
    chown "$SERVICE_USER:$SERVICE_USER" "$SERVER_BIN"
    chmod 0755 "$SERVER_BIN"
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Lore knowledge server
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
ExecStart=${SERVER_BIN} --data-dir ${DATA_DIR} --bind ${BIND} start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > "$SUDOERS_FILE" <<EOF
${SERVICE_USER} ALL=(root) NOPASSWD: ${systemctl_path} restart lore-server, ${systemctl_path} start lore-server, ${systemctl_path} daemon-reload
EOF
chmod 0440 "$SUDOERS_FILE"

"$systemctl_path" daemon-reload
"$systemctl_path" enable lore-server >/dev/null

if [ -f "$CADDYFILE" ]; then
    if grep -Eq "^[[:space:]]*${DOMAIN}[[:space:]]*\\{" "$CADDYFILE" &&
        grep -Fq "reverse_proxy ${BIND}" "$CADDYFILE"; then
        echo "Caddy already has ${DOMAIN} -> ${BIND}"
    else
        cat <<EOF
Warning: ${CADDYFILE} does not appear to contain this block:

${DOMAIN} {
    reverse_proxy ${BIND}
}

Add it to the existing Caddy service before expecting public HTTPS to work.
EOF
    fi
else
    echo "Warning: ${CADDYFILE} not found; this script did not install or manage Caddy." >&2
fi

if [ -x "$SERVER_BIN" ]; then
    if [ -f "${DATA_DIR}/lore.db" ] && command -v python3 >/dev/null 2>&1 &&
        DATA_DIR="$DATA_DIR" python3 - <<'PY'
import os
import sqlite3
import sys

db_path = os.path.join(os.environ["DATA_DIR"], "lore.db")
try:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    has_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
except Exception:
    has_users = False

sys.exit(0 if has_users else 1)
PY
    then
        "$systemctl_path" restart lore-server || "$systemctl_path" start lore-server
        echo "lore-server restarted"
    else
        echo "Lore binary exists, but no app admin was detected; not starting the service yet."
        echo "Create the initial admin or run scripts/quick-deploy-personal.sh from the repo."
    fi
else
    echo "No Lore binary at ${SERVER_BIN} yet."
    echo "Next step from the repo: scripts/quick-deploy-personal.sh"
fi

echo
echo "Installed first-run host setup:"
echo "  service user: ${SERVICE_USER}"
echo "  binary path:  ${SERVER_BIN}"
echo "  data dir:     ${DATA_DIR}"
echo "  bind:         ${BIND}"
echo "  systemd unit: ${SERVICE_FILE}"
