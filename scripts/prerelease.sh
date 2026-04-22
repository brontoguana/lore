#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Read current version from Cargo.toml
CURRENT=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo "Current Cargo.toml version: ${CURRENT}"

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

echo "Next prerelease: ${VERSION}"

# Safety: check for uncommitted changes (besides Cargo.toml/Cargo.lock which we'll touch)
DIRTY=$(git diff --name-only HEAD)
if [ -n "$DIRTY" ]; then
    echo ""
    echo "Uncommitted changes:"
    echo "$DIRTY"
    echo ""
    read -p "Continue anyway? These will be included in the release commit. [y/N] " -n 1 -r
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
echo "UI smoke..."
./tests/run-smoke.sh
echo ""

# Commit, tag, push
git add Cargo.toml Cargo.lock
git commit -m "${TAG}"
git tag "$TAG"
git push origin main
git push origin "$TAG"

echo ""
echo "Done: ${TAG}"
echo "Monitor build: gh run list --limit 3"
