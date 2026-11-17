#!/usr/bin/env bash
# stages/sbom/install.sh - Install Syft for SBOM generation
# Owner: P3  Phase: 3
set -euo pipefail

SYFT_VERSION="1.18.1"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/syft-${SYFT_VERSION}"
SYFT_BIN="$CACHE_DIR/syft"

if [ "${SYFT_SKIP_VERIFY:-0}" != "1" ] && [ -f "$SYFT_BIN" ]; then
  echo "[install] Syft already cached at $SYFT_BIN" >&2
  exit 0
fi

mkdir -p "$CACHE_DIR"
OS=$(uname -s)
ARCH=$(uname -m)

if [ "$OS" = "Linux" ]; then
  if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    TARBALL="syft_${SYFT_VERSION}_linux_arm64.tar.gz"
  else
    TARBALL="syft_${SYFT_VERSION}_linux_amd64.tar.gz"
  fi
elif [ "$OS" = "Darwin" ]; then
  if [ "$ARCH" = "arm64" ]; then
    TARBALL="syft_${SYFT_VERSION}_darwin_arm64.tar.gz"
  else
    TARBALL="syft_${SYFT_VERSION}_darwin_amd64.tar.gz"
  fi
else
  echo "ERROR: Unsupported OS: $OS" >&2
  exit 1
fi

URL="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${TARBALL}"
TMPDIR_INSTALL=$(mktemp -d)
trap 'rm -rf "$TMPDIR_INSTALL"' EXIT

echo "[install] Downloading Syft $SYFT_VERSION ($TARBALL)..." >&2
curl -fsSL "$URL" -o "$TMPDIR_INSTALL/$TARBALL"
tar -xzf "$TMPDIR_INSTALL/$TARBALL" -C "$TMPDIR_INSTALL"
mv "$TMPDIR_INSTALL/syft" "$SYFT_BIN"
chmod +x "$SYFT_BIN"
echo "[install] Syft installed at $SYFT_BIN" >&2
