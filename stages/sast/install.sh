#!/usr/bin/env bash
set -euo pipefail
SEMGREP_VERSION="1.100.0"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/semgrep-${SEMGREP_VERSION}"
VENV_DIR="$CACHE_DIR/venv"
SEMGREP_BIN="$VENV_DIR/bin/semgrep"

# Support both POSIX (bin) and Windows (Scripts) venv layouts if present
if [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep" ]; then
  SEMGREP_BIN="$VENV_DIR/Scripts/semgrep"
elif [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep.exe" ]; then
  SEMGREP_BIN="$VENV_DIR/Scripts/semgrep.exe"
fi

if [ -f "$SEMGREP_BIN" ]; then
  INSTALLED=$("$SEMGREP_BIN" --version 2>/dev/null | head -1 | tr -d '[:space:]') || true
  if echo "$INSTALLED" | grep -q "$SEMGREP_VERSION"; then
    echo "[install] Semgrep $SEMGREP_VERSION already installed" >&2; exit 0
  fi
fi

mkdir -p "$CACHE_DIR"

PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  fi
fi

"$PYTHON_BIN" -m venv "$VENV_DIR"

PIP_BIN="$VENV_DIR/bin/pip"
if [ ! -f "$PIP_BIN" ] && [ -f "$VENV_DIR/Scripts/pip" ]; then
  PIP_BIN="$VENV_DIR/Scripts/pip"
elif [ ! -f "$PIP_BIN" ] && [ -f "$VENV_DIR/Scripts/pip.exe" ]; then
  PIP_BIN="$VENV_DIR/Scripts/pip.exe"
fi

"$PIP_BIN" install --quiet "semgrep==$SEMGREP_VERSION"

if [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep" ]; then
  SEMGREP_BIN="$VENV_DIR/Scripts/semgrep"
elif [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep.exe" ]; then
  SEMGREP_BIN="$VENV_DIR/Scripts/semgrep.exe"
fi

echo "[install] Semgrep $SEMGREP_VERSION installed at $SEMGREP_BIN" >&2
