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

resolve_latest_version() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's|.*/tag/||'
  elif command -v wget >/dev/null 2>&1; then
    wget --max-redirect=0 -qS "https://github.com/$REPO/releases/latest" 2>&1 | sed -n 's/.*Location: .*\/tag\/\(.*\)/\1/p' | tr -d '\r'
  fi
}

get_current_version() {
  if [ -x "$INSTALL_DIR/$BINARY_NAME" ]; then
    "$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null | sed "s/$BINARY_NAME //" || echo "unknown"
  else
    echo "not installed"
  fi
}

# Resolve the version we'll install
if [ "$VERSION" = "latest" ]; then
  REMOTE_VERSION="$(resolve_latest_version)"
else
  REMOTE_VERSION="$VERSION"
fi

CURRENT_VERSION="$(get_current_version)"

# Check if this is an update and whether it's needed
if [ "$CURRENT_VERSION" != "not installed" ]; then
  remote_cmp="$(echo "$REMOTE_VERSION" | sed 's/^v//')"
  current_cmp="$(echo "$CURRENT_VERSION" | sed 's/^v//')"

  if [ "$remote_cmp" = "$current_cmp" ]; then
    echo "$BINARY_NAME is already at version $CURRENT_VERSION — nothing to do."
    exit 0
  fi

  echo "updating $BINARY_NAME: $CURRENT_VERSION -> $REMOTE_VERSION"
else
  echo "installing $BINARY_NAME $REMOTE_VERSION"
fi

TARGET="$(detect_target)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

BASE_URL="https://github.com/$REPO/releases/download/$REMOTE_VERSION"

ARCHIVE="$TMP_DIR/${BINARY_NAME}-${TARGET}.tar.gz"
CHECKSUM="$ARCHIVE.sha256"

fetch "$BASE_URL/${BINARY_NAME}-${TARGET}.tar.gz" "$ARCHIVE"
fetch "$BASE_URL/${BINARY_NAME}-${TARGET}.tar.gz.sha256" "$CHECKSUM"
verify_checksum "$ARCHIVE" "$CHECKSUM"

mkdir -p "$INSTALL_DIR"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
install "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"

if [ "$CURRENT_VERSION" != "not installed" ]; then
  echo "updated $BINARY_NAME to $REMOTE_VERSION (was $CURRENT_VERSION)"
else
  echo ""
  echo " _      ____  _____  ______ "
  echo "| |    / __ \\|  __ \\|  ____|"
  echo "| |   | |  | | |__) | |__   "
  echo "| |   | |  | |  _  /|  __|  "
  echo "| |___| |__| | | \\ \\| |____ "
  echo "|______\\____/|_|  \\_\\______|"
  echo ""
  echo "installed $BINARY_NAME $REMOTE_VERSION to $INSTALL_DIR/$BINARY_NAME"
  echo ""

  # Check if INSTALL_DIR is on PATH
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      echo "add $INSTALL_DIR to your PATH:"
      echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
      echo ""
      ;;
  esac

  echo "quick start:"
  echo "  lore config set --url https://your-server.com --token YOUR_TOKEN"
  echo "  lore projects                # list projects"
  echo "  lore blocks <project>        # list blocks in a project"
  echo "  lore read <project>          # read all blocks"
  echo "  lore add <project> --type markdown --content '...'  # add a block"
  echo ""
  echo "run lore --help for all commands."
fi
