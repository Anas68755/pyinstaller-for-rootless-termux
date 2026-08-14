#!/data/data/com.termux/files/usr/bin/bash
# ══════════════════════════════════════════════════════════════
# termux-pyinstaller — Wrapper for PyInstaller on rootless Termux
# ══════════════════════════════════════════════════════════════
# This wrapper must be installed AFTER running termux_pyinstaller_setup.sh
# It sets up the correct environment before delegating to PyInstaller.
# ══════════════════════════════════════════════════════════════

set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
ARCH=$(uname -m)

# ── Environment Setup ──────────────────────────────────────

# TMPDIR: Android has no /tmp; use Termux's tmp
export TMPDIR="${TMPDIR:-$PREFIX/tmp}"
mkdir -p "$TMPDIR"

# LDD_SHIM: our custom ldd that uses readelf fallback
export LDD_SHIM="$PREFIX/bin/ldd-pyinstaller-shim"

# LD_LIBRARY_PATH: so the runtime linker finds Termux .so files
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"

# PyInstaller home
export PYINSTALLER_HOME="$(python3 -c 'import PyInstaller; print(PyInstaller.__path__[0])' 2>/dev/null || echo '')"

# Disable UPX (not reliable on Android)
export PYINSTALLER_UPX="${PYINSTALLER_UPX:-0}"

# Disable hardlinks (Android fs may not support them)
export PYINSTALLER_NO_HARDCOPY="${PYINSTALLER_NO_HARDCOPY:-1}"

# ── Argument Parsing ───────────────────────────────────────
# We intercept --patchelf to auto-fix binaries after build

AUTO_PATCHELF=0
REAL_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --auto-patchelf)
            AUTO_PATCHELF=1
            ;;
        *)
            REAL_ARGS+=("$arg")
            ;;
    esac
done

# Determine the output spec name (for patchelf hook)
SPEC_NAME=""
DIST_DIR=""
for i in "${!REAL_ARGS[@]}"; do
    case "${REAL_ARGS[$i]}" in
        -n|--name)
            if [[ $((i+1)) -lt ${#REAL_ARGS[@]} ]]; then
                SPEC_NAME="${REAL_ARGS[$((i+1))]}"
            fi
            ;;
        --distpath)
            if [[ $((i+1)) -lt ${#REAL_ARGS[@]} ]]; then
                DIST_DIR="${REAL_ARGS[$((i+1))]}"
            fi
            ;;
    esac
done

# ── Run PyInstaller ────────────────────────────────────────
info() { echo -e "\033[0;34m[termux-pyinstaller]\033[0m $*"; }

info "Running PyInstaller with Termux environment..."
info "  ARCH=$ARCH  PREFIX=$PREFIX  TMPDIR=$TMPDIR"

python3 -m PyInstaller "${REAL_ARGS[@]}"
RC=$?

if [ $RC -ne 0 ]; then
    echo -e "\033[0;31m[ERROR]\033[0m PyInstaller exited with code $RC"
    exit $RC
fi

# ── Auto-patchelf (if requested) ──────────────────────────
if [ "$AUTO_PATCHELF" = "1" ]; then
    info "Running patchelf fixup..."

    # Find the dist directory
    if [ -z "$DIST_DIR" ]; then
        DIST_DIR="dist"
    fi

    if [ -z "$SPEC_NAME" ]; then
        # Try to infer from .spec file or args
        for arg in "${REAL_ARGS[@]}"; do
            if [[ "$arg" == *.py && -z "$SPEC_NAME" ]]; then
                SPEC_NAME=$(basename "${arg%.py}")
            fi
        done
    fi

    if [ -d "$DIST_DIR" ]; then
        termux-pyinstaller-patchelf "$DIST_DIR"
    else
        info "Could not find dist directory for patchelf"
    fi
fi

info "Build complete!"
exit 0
