#!/usr/bin/env bash
set -euo pipefail
TRIVY_VERSION="0.58.1"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-${TRIVY_VERSION}"
TRIVY_BIN="$CACHE_DIR/trivy"

if [ "${TRIVY_SKIP_VERIFY:-0}" != "1" ] && [ -f "$TRIVY_BIN" ]; then
  echo "[install] Trivy already cached" >&2; exit 0
fi

mkdir -p "$CACHE_DIR"
OS=$(uname -s)
ARCH=$(uname -m)

if [ "$OS" = "Linux" ]; then
  if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    TARBALL="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"
  else
    TARBALL="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
  fi
elif [ "$OS" = "Darwin" ]; then
  if [ "$ARCH" = "arm64" ]; then
    TARBALL="trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz"
  else
    TARBALL="trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz"
  fi
else
  echo "ERROR: Unsupported OS: $OS" >&2; exit 1
fi

URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TARBALL}"
TMPDIR_INSTALL=$(mktemp -d)
trap 'rm -rf "$TMPDIR_INSTALL"' EXIT

echo "[install] Downloading Trivy $TRIVY_VERSION ($TARBALL)..." >&2
curl -fsSL "$URL" -o "$TMPDIR_INSTALL/$TARBALL"
tar -xzf "$TMPDIR_INSTALL/$TARBALL" -C "$TMPDIR_INSTALL"
mv "$TMPDIR_INSTALL/trivy" "$TRIVY_BIN"
chmod +x "$TRIVY_BIN"
echo "[install] Trivy installed at $TRIVY_BIN" >&2
