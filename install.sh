#!/usr/bin/env bash
# install.sh - install mkexe on Termux (no root) or any Linux.
#
#   bash install.sh              install mkexe + git + GitHub CLI + python
#   bash install.sh --with-local also set up PyInstaller on this device
#                                (for `mkexe --local`; makes Android/Linux
#                                binaries, not .exe files)
set -euo pipefail

WITH_LOCAL=false
for a in "$@"; do
  case "$a" in
    --with-local) WITH_LOCAL=true;;
    -h|--help) sed -n '2,8p' "$0"; exit 0;;
    *) echo "unknown option: $a" >&2; exit 1;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/mkexe" ] || { echo "mkexe file not found next to install.sh" >&2; exit 1; }

if command -v pkg >/dev/null 2>&1 && [ -n "${PREFIX:-}" ]; then
  echo "==> Termux detected; installing packages"
  pkg update -y
  pkg install -y git gh python tar coreutils sed grep
  BIN_DIR="$PREFIX/bin"
else
  for c in git gh python3; do
    command -v "$c" >/dev/null 2>&1 || {
      echo "missing '$c'. Install it first (GitHub CLI: https://cli.github.com)" >&2
      exit 1
    }
  done
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
fi

install -m 755 "$HERE/mkexe" "$BIN_DIR/mkexe"
echo "==> Installed $BIN_DIR/mkexe"

if [ "$WITH_LOCAL" = true ]; then
  echo "==> Setting up local PyInstaller (Android/Linux builds only)"
  if command -v pkg >/dev/null 2>&1 && [ -n "${PREFIX:-}" ]; then
    pkg install -y clang binutils ldd python-pip
  fi
  python3 -m pip install --upgrade --no-cache-dir pyinstaller
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "NOTE: add $BIN_DIR to your PATH";;
esac

cat <<'EOF'

Next steps:
  1. mkexe --setup        # log in to GitHub, creates a private build repo
  2. mkexe yourscript.py  # builds and downloads yourscript.exe
EOF
