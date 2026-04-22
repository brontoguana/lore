#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -x "./target/release/lore-server" ]; then
    echo "ERROR: ./target/release/lore-server not found. Run cargo build --release first."
    exit 1
fi

echo "=== Playwright setup ==="
cd tests/playwright
npm install --silent 2>&1 | tail -3
cd ../..

echo ""
echo "=== Starting test server for UI smoke ==="
TEST_DIR=$(mktemp -d)
PID_FILE="$TEST_DIR/.server.pid"
SERVER_LOG="$TEST_DIR/.server.log"
trap "rm -rf $TEST_DIR; if [ -f '$PID_FILE' ]; then kill \"\$(cat '$PID_FILE')\" 2>/dev/null || true; fi; pkill -f 'lore-server.*$TEST_DIR' 2>/dev/null || true" EXIT

printf 'admin\ncorrect-horse-battery\ncorrect-horse-battery\n' | \
    script -qec "./target/release/lore-server --data-dir $TEST_DIR create-admin" /dev/null >/dev/null 2>&1

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
BIND_ADDR="127.0.0.1:$PORT"

LORE_SKIP_SELF_UPDATE=1 ./target/release/lore-server --data-dir "$TEST_DIR" --bind "$BIND_ADDR" start > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

for _ in $(seq 1 60); do
    if curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/v1/health" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if ! curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/v1/health"; then
    echo "ERROR: Server failed to start on $BIND_ADDR"
    exit 1
fi

echo "Server on port $PORT (PID $SERVER_PID)"

echo ""
echo "=== Playwright UI smoke ==="
cd tests/playwright
LORE_URL="http://127.0.0.1:$PORT" \
  npm run test:smoke 2>&1
