#!/usr/bin/env bash
# stages/iac/install.sh - Install Hadolint and Checkov for the IAC stage
# Owner: P3  Phase: 3
set -euo pipefail

HADOLINT_VERSION="2.12.0"
HADOLINT_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/hadolint-${HADOLINT_VERSION}"
HADOLINT_BIN="$HADOLINT_CACHE_DIR/hadolint"

CHECKOV_VERSION="3.2.405"
CHECKOV_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/checkov-${CHECKOV_VERSION}"
CHECKOV_VENV="$CHECKOV_CACHE_DIR/venv"
CHECKOV_BIN="$CHECKOV_VENV/bin/checkov"

# ---------------------------------------------------------------------------
# Install Hadolint
# ---------------------------------------------------------------------------
if [ -f "$HADOLINT_BIN" ] && [ "${HADOLINT_SKIP_VERIFY:-0}" != "1" ]; then
  echo "[install] Hadolint $HADOLINT_VERSION already cached at $HADOLINT_BIN" >&2
else
  mkdir -p "$HADOLINT_CACHE_DIR"
  OS=$(uname -s)
  ARCH=$(uname -m)

  if [ "$OS" = "Linux" ]; then
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
      HADOLINT_ASSET="hadolint-Linux-arm64"
    else
      HADOLINT_ASSET="hadolint-Linux-x86_64"
    fi
  elif [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" = "arm64" ]; then
      HADOLINT_ASSET="hadolint-Darwin-arm64"
    else
      HADOLINT_ASSET="hadolint-Darwin-x86_64"
    fi
  else
    echo "ERROR: Unsupported OS: $OS" >&2
    exit 1
  fi

  HADOLINT_URL="https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/${HADOLINT_ASSET}"
  echo "[install] Downloading Hadolint $HADOLINT_VERSION from $HADOLINT_URL ..." >&2
  curl -fsSL "$HADOLINT_URL" -o "$HADOLINT_BIN"
  chmod +x "$HADOLINT_BIN"
  echo "[install] Hadolint installed at $HADOLINT_BIN" >&2
fi

# ---------------------------------------------------------------------------
# Install Checkov
# ---------------------------------------------------------------------------
if [ -f "$CHECKOV_BIN" ] && [ "${CHECKOV_SKIP_VERIFY:-0}" != "1" ]; then
  echo "[install] Checkov $CHECKOV_VERSION already cached at $CHECKOV_BIN" >&2
else
  mkdir -p "$CHECKOV_CACHE_DIR"
  echo "[install] Creating Checkov venv at $CHECKOV_VENV ..." >&2
  python3 -m venv "$CHECKOV_VENV"
  "$CHECKOV_VENV/bin/pip" install --quiet --upgrade pip
  "$CHECKOV_VENV/bin/pip" install --quiet "checkov==${CHECKOV_VERSION}"
  echo "[install] Checkov installed at $CHECKOV_BIN" >&2
fi
