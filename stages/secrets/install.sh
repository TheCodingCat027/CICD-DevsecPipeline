#!/usr/bin/env bash
set -euo pipefail
# Install Gitleaks v8.21.2 into cache dir
GL_VERSION="8.21.2"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/gitleaks-${GL_VERSION}"
GL_BIN="$CACHE_DIR/gitleaks"

if [ "${GITLEAKS_SKIP_VERIFY:-0}" != "1" ] && [ -f "$GL_BIN" ]; then
  echo "[install] Gitleaks already cached at $GL_BIN" >&2
  exit 0
fi

mkdir -p "$CACHE_DIR"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$OS" = "linux" ]; then
  if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    TARBALL="gitleaks_${GL_VERSION}_linux_arm64.tar.gz"
  else
    TARBALL="gitleaks_${GL_VERSION}_linux_x64.tar.gz"
  fi
elif [ "$OS" = "darwin" ]; then
  if [ "$ARCH" = "arm64" ]; then
    TARBALL="gitleaks_${GL_VERSION}_darwin_arm64.tar.gz"
  else
    TARBALL="gitleaks_${GL_VERSION}_darwin_x64.tar.gz"
  fi
else
  echo "ERROR: Unsupported OS: $OS" >&2; exit 1
fi

URL="https://github.com/gitleaks/gitleaks/releases/download/v${GL_VERSION}/${TARBALL}"
TMPDIR_INSTALL=$(mktemp -d)
trap "rm -rf $TMPDIR_INSTALL" EXIT

echo "[install] Downloading Gitleaks $GL_VERSION ($TARBALL)..." >&2
curl -fsSL "$URL" -o "$TMPDIR_INSTALL/$TARBALL"
tar -xzf "$TMPDIR_INSTALL/$TARBALL" -C "$TMPDIR_INSTALL" gitleaks
mv "$TMPDIR_INSTALL/gitleaks" "$GL_BIN"
chmod +x "$GL_BIN"
echo "[install] Gitleaks installed at $GL_BIN" >&2
