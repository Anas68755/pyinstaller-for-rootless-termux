#!/data/data/com.termux/files/usr/bin/bash
# ══════════════════════════════════════════════════════════════
# termux-pyinstaller-patchelf — Post-build ELF fixer for Termux
# ══════════════════════════════════════════════════════════════
# After PyInstaller creates a bundle, the ELF binaries may have
# an incorrect interpreter/rpath pointing to a GNU/Linux linker.
# This script uses patchelf to fix them for Android/Termux.
# ══════════════════════════════════════════════════════════════

set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
ARCH=$(uname -m)

# ── Determine correct ELF interpreter ──────────────────────
case "$ARCH" in
    aarch64|arm64)  INTERP="/system/bin/linker64" ;;
    armv7l|armv7)   INTERP="/system/bin/linker"   ;;
    x86_64)         INTERP="/system/bin/linker64" ;;
    i686|x86)       INTERP="/system/bin/linker"   ;;
    *)
        echo "Warning: Unknown arch $ARCH, assuming linker64"
        INTERP="/system/bin/linker64"
        ;;
esac

# ── Validate arguments ─────────────────────────────────────
DIST_DIR="$1"
if [ -z "$DIST_DIR" ]; then
    echo "Usage: termux-pyinstaller-patchelf <dist_dir>"
    echo ""
    echo "  Fix ELF interpreter and rpath in PyInstaller output"
    echo "  so binaries can run on Termux without root."
    echo ""
    echo "  Example:"
    echo "    termux-pyinstaller-patchelf dist/myapp"
    exit 1
fi

if [ ! -d "$DIST_DIR" ]; then
    echo "Error: '$DIST_DIR' is not a directory"
    exit 1
fi

if ! command -v patchelf >/dev/null 2>&1; then
    echo "Error: patchelf not found. Install it with:"
    echo "  pkg install patchelf"
    exit 1
fi

# ── Fix all ELF binaries ───────────────────────────────────
RPATH="$PREFIX/lib:/system/lib64:/system/lib"
FIXED=0
SKIPPED=0

echo "Fixing ELF files in $DIST_DIR ..."
echo "  Interpreter: $INTERP"
echo "  RPATH: $ $RPATH"
echo ""

find "$DIST_DIR" -type f -executable -o -name "*.so" -o -name "*.so.*" | while read -r bin; do
    # Skip non-ELF files
    if ! readelf -h "$bin" >/dev/null 2>&1; then
        continue
    fi

    # Skip if it's a shell script (has shebang)
    if head -c 4 "$bin" | grep -q "^#!"; then
        continue
    fi

    echo "  [fix] $(basename "$bin")"

    # Set the correct ELF interpreter (Android linker)
    patchelf --set-interpreter "$INTERP" "$bin" 2>/dev/null || {
        echo "    Warning: could not set interpreter on $(basename "$bin")"
    }

    # Set rpath to include Termux + system lib dirs
    patchelf --set-rpath "$RPATH" "$bin" 2>/dev/null || {
        echo "    Warning: could not set rpath on $(basename "$bin")"
    }

    # Make sure the binary is executable
    chmod +x "$bin" 2>/dev/null || true
done

echo ""
echo "Done! Binaries in $DIST_DIR should now be runnable from Termux."
echo ""
echo "Test with:"
echo "  find $DIST_DIR -type f -executable -name '*.py' -o -type f -name '$(basename "$DIST_DIR")' | xargs -I{} sh -c 'echo Testing: {} && {} --help 2>&1 | head -1'"
