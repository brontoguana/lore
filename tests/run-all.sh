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
trap "rm -rf $TEST_DIR; pkill -f 'lore-server.*$TEST_DIR' 2>/dev/null || true" EXIT

printf 'admin\ncorrect-horse-battery\ncorrect-horse-battery\n' | \
    script -qec "./target/release/lore-server --data-dir $TEST_DIR create-admin" /dev/null >/dev/null 2>&1

LORE_SKIP_SELF_UPDATE=1 ./target/release/lore-server --data-dir "$TEST_DIR" --bind "127.0.0.1:0" start &
SERVER_PID=$!

for i in $(seq 1 30); do
    PORT=$(ss -tlnp 2>/dev/null | grep "$SERVER_PID" | grep -oP '127\.0\.0\.1:\K\d+' | head -1 || true)
    if [ -n "${PORT:-}" ]; then break; fi
    sleep 0.2
done

if [ -z "${PORT:-}" ]; then
    echo "ERROR: Server failed to start"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "Server on port $PORT (PID $SERVER_PID)"

echo ""
echo "=== Playwright UI tests (18 tests) ==="
cd tests/playwright
LORE_URL="http://127.0.0.1:$PORT" npx playwright test 2>&1
PW_EXIT=$?
cd ../..

kill $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Summary ==="
echo "Unit tests:        110 (cargo test --lib)"
echo "Integration tests: 22  (cargo test --test integration)  $([ $RUST_EXIT -eq 0 ] && echo PASS || echo FAIL)"
echo "Playwright tests:  18  (npx playwright test)            $([ $PW_EXIT -eq 0 ] && echo PASS || echo FAIL)"
echo "Total:             150"

exit $(( RUST_EXIT + PW_EXIT ))
