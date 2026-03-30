#!/bin/sh
set -eu

REPO="${LORE_GITHUB_REPO:-brontoguana/lore}"
VERSION="${LORE_VERSION:-latest}"
INSTALL_DIR="${LORE_INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="lore"

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux) os="unknown-linux-gnu" ;;
    Darwin) os="apple-darwin" ;;
    *)
      echo "unsupported operating system: $os" >&2
      exit 1
      ;;
  esac

  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="aarch64" ;;
    *)
      echo "unsupported architecture: $arch" >&2
      exit 1
      ;;
  esac

  printf "%s-%s" "$arch" "$os"
}

fetch() {
  url="$1"
  output="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$output"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$output" "$url"
  else
    echo "curl or wget is required" >&2
    exit 1
  fi
}

verify_checksum() {
  archive="$1"
  checksum_file="$2"
  expected="$(cut -d' ' -f1 "$checksum_file")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$archive" | cut -d' ' -f1)"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$archive" | cut -d' ' -f1)"
  else
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
  if [ "$expected" != "$actual" ]; then
    echo "checksum mismatch for $archive" >&2
    exit 1
  fi
}

TARGET="$(detect_target)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/$REPO/releases/latest/download"
else
  BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
fi

ARCHIVE="$TMP_DIR/${BINARY_NAME}-${TARGET}.tar.gz"
CHECKSUM="$ARCHIVE.sha256"

fetch "$BASE_URL/${BINARY_NAME}-${TARGET}.tar.gz" "$ARCHIVE"
fetch "$BASE_URL/${BINARY_NAME}-${TARGET}.tar.gz.sha256" "$CHECKSUM"
verify_checksum "$ARCHIVE" "$CHECKSUM"

mkdir -p "$INSTALL_DIR"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
install "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"

echo "installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"
echo "ensure $INSTALL_DIR is on your PATH"
