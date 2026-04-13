# Build & Release

Lore produces two binaries: `lore` (CLI client) and `lore-server`. Both are built from the same crate.

## Local Build

```
cargo build --release
cargo test
```

All tests must pass before tagging a release.

## Release Streams

Both streams are triggered by pushing a git tag starting with `v`. The tag format determines which stream runs.

### Prerelease

For testing builds. Linux only (x86_64 and aarch64).

```
# 1. Bump version in Cargo.toml to include a pre-release suffix
#    e.g. version = "0.1.65-rc1"

# 2. Commit and tag
git add Cargo.toml
git commit -m "Bump to v0.1.65-rc1"
git tag v0.1.65-rc1

# 3. Push
git push origin main --tags
```

The tag must contain a hyphen (e.g. `-rc1`, `-beta2`). This is what routes it to the prerelease workflow.

Outputs: GitHub prerelease with linux x86_64 and aarch64 tarballs + sha256 checksums.

### Release

Full production release. Builds for all platforms:
- Linux x86_64
- Linux aarch64
- macOS x86_64
- macOS aarch64
- Windows x86_64

```
# 1. Set a clean version in Cargo.toml (no suffix)
#    e.g. version = "0.1.65"

# 2. Commit and tag
git add Cargo.toml
git commit -m "Release v0.1.65"
git tag v0.1.65

# 3. Push
git push origin main --tags
```

The tag must NOT contain a hyphen. This routes it to the full release workflow.

Outputs: GitHub release (not marked as prerelease) with tarballs + sha256 checksums for all 5 targets. Release notes are auto-generated from commits since the last tag.

## How Routing Works

Both workflows trigger on `v*` tags. They use a condition on the tag name:
- Contains `-` → prerelease workflow runs
- No `-` → release workflow runs

## Artifacts

Each binary is packaged as `{binary}-{target}.tar.gz` with a corresponding `.sha256` checksum file. For example:
- `lore-server-x86_64-unknown-linux-gnu.tar.gz`
- `lore-server-x86_64-unknown-linux-gnu.tar.gz.sha256`
