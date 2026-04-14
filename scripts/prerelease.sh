#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.66-rc1"
    exit 1
fi

VERSION="$1"
TAG="v${VERSION}"

if [[ ! "$VERSION" == *-* ]]; then
    echo "Error: prerelease version must contain a hyphen (e.g. 0.1.66-rc1)"
    exit 1
fi

cd "$(git rev-parse --show-toplevel)"

sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml

cargo build --release 2>/dev/null
cargo test 2>/dev/null
echo "Build and tests passed."

git add Cargo.toml
git commit -m "${TAG}"
git tag "$TAG"
git push origin main
git push origin "$TAG"

echo "Pushed ${TAG}. Monitor build: gh run list --limit 3"
