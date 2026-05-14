#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Read current version from Cargo.toml
CURRENT=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo "Current Cargo.toml version: ${CURRENT}"

# Derive release version (strip -rcN)
if [[ "$CURRENT" == *-rc* ]]; then
    VERSION=$(echo "$CURRENT" | sed 's/-rc[0-9]*//')
else
    # Already a release version — bump patch
    MAJOR=$(echo "$CURRENT" | cut -d. -f1)
    MINOR=$(echo "$CURRENT" | cut -d. -f2)
    PATCH=$(echo "$CURRENT" | cut -d. -f3)
    VERSION="${MAJOR}.${MINOR}.$((PATCH + 1))"
fi

TAG="v${VERSION}"

echo "Release version: ${VERSION}"

# Check tag doesn't already exist
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Error: tag ${TAG} already exists"
    exit 1
fi

# Safety: check for uncommitted changes
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
git add Cargo.toml
if git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1; then
    git add Cargo.lock
fi
git commit -m "${TAG}"
git tag "$TAG"
git push origin main
git push origin "$TAG"

echo ""
echo "Done: ${TAG}"
echo "Monitor build: gh run list --limit 3"
