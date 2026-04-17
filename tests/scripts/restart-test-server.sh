#!/usr/bin/env bash
# Restart the test server against the same data dir and port.
# Expects: LORE_DATA_DIR, LORE_BIND_ADDR, LORE_PID_FILE, LORE_SERVER_BIN env vars.
set -euo pipefail

: "${LORE_DATA_DIR:?LORE_DATA_DIR is required}"
: "${LORE_BIND_ADDR:?LORE_BIND_ADDR is required (e.g. 127.0.0.1:7043)}"
: "${LORE_PID_FILE:?LORE_PID_FILE is required}"
: "${LORE_SERVER_BIN:?LORE_SERVER_BIN is required}"

if [ -f "$LORE_PID_FILE" ]; then
  OLD_PID=$(cat "$LORE_PID_FILE")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    kill "$OLD_PID" || true
    # Wait for clean exit (up to 5s).
    for _ in $(seq 1 50); do
      kill -0 "$OLD_PID" 2>/dev/null || break
      sleep 0.1
    done
    # Force-kill if it didn't stop.
    kill -9 "$OLD_PID" 2>/dev/null || true
  fi
fi

LORE_SKIP_SELF_UPDATE=1 "$LORE_SERVER_BIN" --data-dir "$LORE_DATA_DIR" \
    --bind "$LORE_BIND_ADDR" start >> "${LORE_SERVER_LOG:-/tmp/lore-test-restart.log}" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$LORE_PID_FILE"

# Wait for health.
PORT="${LORE_BIND_ADDR##*:}"
for _ in $(seq 1 60); do
  if curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/v1/health" 2>/dev/null; then
    exit 0
  fi
  sleep 0.2
done
echo "restart: server did not come healthy on $LORE_BIND_ADDR" >&2
exit 1
