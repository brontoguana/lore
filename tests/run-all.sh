#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Building ==="
cargo build --release 2>&1 | tail -3

echo ""
echo "=== Rust integration tests (Layer 2 + 3: API, MCP, mock LLM) ==="
cargo test --test integration -- --test-threads=4 2>&1
RUST_EXIT=$?

echo ""
echo "=== Playwright setup ==="
cd tests/playwright
npm install --silent 2>&1 | tail -3
cd ../..

echo ""
echo "=== Starting test server for UI tests ==="
TEST_DIR=$(mktemp -d)
PID_FILE="$TEST_DIR/.server.pid"
SERVER_LOG="$TEST_DIR/.server.log"
trap "rm -rf $TEST_DIR; pkill -f 'lore-server.*$TEST_DIR' 2>/dev/null || true" EXIT

printf 'admin\ncorrect-horse-battery\ncorrect-horse-battery\n' | \
    script -qec "./target/release/lore-server --data-dir $TEST_DIR create-admin" /dev/null >/dev/null 2>&1

# Pre-allocate a free port so restart-test-server.sh can reuse it.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
BIND_ADDR="127.0.0.1:$PORT"

LORE_SKIP_SELF_UPDATE=1 ./target/release/lore-server --data-dir "$TEST_DIR" --bind "$BIND_ADDR" start > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

for i in $(seq 1 60); do
    if curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/v1/health" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if ! curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/v1/health"; then
    echo "ERROR: Server failed to start on $BIND_ADDR"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "Server on port $PORT (PID $SERVER_PID)"

SERVER_BIN="$PWD/target/release/lore-server"
RESTART_SCRIPT="$PWD/tests/scripts/restart-test-server.sh"

echo ""
echo "=== Playwright UI tests ==="
cd tests/playwright
LORE_URL="http://127.0.0.1:$PORT" \
  LORE_DATA_DIR="$TEST_DIR" \
  LORE_BIND_ADDR="$BIND_ADDR" \
  LORE_PID_FILE="$PID_FILE" \
  LORE_SERVER_BIN="$SERVER_BIN" \
  LORE_SERVER_LOG="$SERVER_LOG" \
  LORE_RESTART_CMD="$RESTART_SCRIPT" \
  npx playwright test 2>&1
PW_EXIT=$?
cd ../..

# Server PID may have changed if tests restarted it; re-read.
if [ -f "$PID_FILE" ]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi

echo ""
echo "=== Summary ==="
echo "Unit tests:        110 (cargo test --lib)"
echo "Integration tests: 26  (cargo test --test integration)  $([ $RUST_EXIT -eq 0 ] && echo PASS || echo FAIL)"
echo "Playwright tests:  26  (npx playwright test)            $([ $PW_EXIT -eq 0 ] && echo PASS || echo FAIL)"
echo "Total:             162"

exit $(( RUST_EXIT + PW_EXIT ))
