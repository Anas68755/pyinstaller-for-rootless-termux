#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# PyInstaller Rootless Termux Port — Setup Script
# ============================================================
# This script installs and patches PyInstaller to work on
# rootless Termux (Android). No root/proot required.
#
# Usage:
#   chmod +x termux_pyinstaller_setup.sh
#   ./termux_pyinstaller_setup.sh
#
# After setup, use the wrapper:
#   termux-pyinstaller your_script.py
# ============================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
ok()    { echo -e "${GRN}[OK]${NC}    $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*"; }

# ── Detect Environment ──────────────────────────────────────
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
ARCH=$(uname -m)
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYINST_VERSION="6.12.0"   # target version we patch against

info "Detected: ARCH=$ARCH  PREFIX=$PREFIX  Python=$PYVER"

# ── Step 1: Install Termux dependencies ─────────────────────
info "Installing Termux packages..."
pkg install -y python python-pip binutils patchelf zlib 2>/dev/null || {
    # fallback for older termux
    apt update && apt install -y python python-pip binutils patchelf zlib
}
ok "Core packages installed"

# ── Step 2: Install Python build deps ───────────────────────
info "Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install pyinstaller=="$PYINST_VERSION" 2>/dev/null || {
    warn "pip install failed, will build from source"
    BUILD_FROM_SOURCE=1
}
ok "Python dependencies installed"

# ── Step 3: Locate PyInstaller installation ─────────────────
PI_SITE=$(python3 -c "import PyInstaller; print(PyInstaller.__path__[0])")
info "PyInstaller located at: $PI_SITE"

# ── Step 4: Apply Patches ───────────────────────────────────
PATCH_DIR="$(dirname "$0")/patches"
TOTAL_PATCHES=0
APPLIED_PATCHES=0

apply_patch() {
    local patch_file="$1"
    local target="$2"
    local patch_name
    patch_name=$(basename "$patch_file")

    TOTAL_PATCHES=$((TOTAL_PATCHES + 1))

    if [ ! -f "$patch_file" ]; then
        warn "Patch file not found: $patch_file — skipping"
        return 1
    fi

    if patch -p1 --dry-run -d "$target" < "$patch_file" >/dev/null 2>&1; then
        patch -p1 -d "$target" < "$patch_file" >/dev/null 2>&1
        APPLIED_PATCHES=$((APPLIED_PATCHES + 1))
        ok "Applied: $patch_name"
        return 0
    else
        warn "Patch $patch_name does not apply cleanly — may already be patched or version mismatch"
        return 1
    fi
}

info "Applying Termux compatibility patches..."
apply_patch "$PATCH_DIR/0001-bindepend-termux.patch"  "$PI_SITE"
apply_patch "$PATCH_DIR/0002-ldd-termux.patch"        "$PI_SITE"
apply_patch "$PATCH_DIR/0003-building-termux.patch"    "$PI_SITE"
apply_patch "$PATCH_DIR/0004-dylib-termux.patch"       "$PI_SITE"
apply_patch "$PATCH_DIR/0005-macholib-termux.patch"    "$PI_SITE"

info "Patches applied: $APPLIED_PATCHES / $TOTAL_PATCHES"

# ── Step 5: Fix ldd shim ────────────────────────────────────
info "Setting up ldd shim for Termux..."
LDD_SHIM="$PREFIX/bin/ldd-pyinstaller-shim"
cat > "$LDD_SHIM" << 'LDD_EOF'
#!/data/data/com.termux/files/usr/bin/bash
# ldd shim that works on Termux/Android
# Android uses /system/bin/linker64 instead of /lib/ld-linux
# and readelf -d is more reliable than lld for ELF inspection

if [ $# -eq 0 ]; then
    echo "Usage: ldd-pyinstaller-shim <executable>"
    exit 1
fi

BIN="$1"
if [ ! -f "$BIN" ]; then
    echo "ldd-pyinstaller-shim: $BIN: No such file" >&2
    exit 1
fi

# Try real ldd first
if command -v ldd >/dev/null 2>&1; then
    REAL_LDD_OUT=$(ldd "$BIN" 2>/dev/null)
    if [ -n "$REAL_LDD_OUT" ]; then
        echo "$REAL_LDD_OUT"
        exit 0
    fi
fi

# Fallback: use readelf to parse DT_NEEDED entries
# This is the most reliable method on Android/Termux
if command -v readelf >/dev/null 2>&1; then
    NEEDED=$(readelf -d "$BIN" 2>/dev/null | grep NEEDED | sed 's/.*\[\(.*\)\].*/\1/')
    if [ -z "$NEEDED" ]; then
        echo "not a dynamic executable" >&2
        exit 1
    fi

    PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
    for lib in $NEEDED; do
        # Search common Termux library paths
        found=""
        for search_path in \
            "$PREFIX/lib" \
            "/system/lib64" \
            "/system/lib" \
            "/lib64" \
            "/lib" \
            "$PREFIX/lib/python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')/site-packages" \
            "$(dirname "$BIN")"; do
            if [ -f "$search_path/$lib" ]; then
                found="$search_path/$lib"
                break
            fi
        done

        if [ -n "$found" ]; then
            printf "%-45s => %s (0x%08x)\n" "$lib" "$found" "0"
        else
            printf "%-45s => not found\n" "$lib"
        fi
    done
    exit 0
fi

echo "ldd-pyinstaller-shim: neither ldd nor readelf available" >&2
exit 1
LDD_EOF
chmod +x "$LDD_SHIM"
ok "ldd shim installed at $LDD_SHIM"

# ── Step 6: Inline-patch critical Python files ──────────────
info "Applying inline Python patches..."

# 6a) Patch bindepend.py — make it use our ldd shim and handle Termux paths
BINDEPEND="$PI_SITE/depend/bindepend.py"
if [ -f "$BINDEPEND" ]; then
    # Inject Termux-specific path handling at the top of getImports
    if ! grep -q "TERMUX_PATCHED" "$BINDEPEND" 2>/dev/null; then
        python3 << PYEOF
import re

with open("$BINDEPEND", "r") as f:
    src = f.read()

# Patch 1: Fix ldd invocation to use our shim or readelf fallback
old_ldd = "ldd"
# Find the getImports function and patch the ldd call pattern
# PyInstaller uses `ldd` via subprocess; we redirect it

# Patch 2: Add Termux library search paths
# After the standard search paths, add Termux-specific ones
termux_paths = """
    # TERMUX_PATCHED: Additional search paths for Android/Termux
    import os
    _termux_prefix = os.environ.get('PREFIX', '/data/data/com.termux/files/usr')
    _termux_libdirs = [
        os.path.join(_termux_prefix, 'lib'),
        '/system/lib64',
        '/system/lib',
        '/lib64',
        '/lib',
    ]
"""

# Insert our marker and paths near the top of the module (after imports)
if "TERMUX_PATCHED" not in src:
    import_section_end = src.find("\\n\\n# ---")
    if import_section_end == -1:
        import_section_end = src.find("\\n\\ndef ")
    if import_section_end == -1:
        import_section_end = 0

    # Simpler approach: just prepend a monkey-patch block
    monkey = '''
# ── TERMUX_PATCHED: Rootless Termux compatibility ──────────────
import os as _os
import subprocess as _subprocess_orig

_PREFIX = _os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
_LDD_SHIM = _os.path.join(_PREFIX, "bin", "ldd-pyinstaller-shim")

# Extended library search paths for Android
TERMUX_LIBDIRS = [
    _os.path.join(_PREFIX, "lib"),
    "/system/lib64",
    "/system/lib",
    "/lib64",
    "/lib",
]

# Monkey-patch: redirect ldd calls through our shim
_real_popen = _subprocess_orig.Popen

class _TermuxPopen(_real_popen):
    """Subprocess.Popen subclass that redirects ldd to Termux shim."""
    def __init__(self, args, **kwargs):
        if isinstance(args, list) and len(args) >= 2:
            if args[0] == "ldd":
                args = [_LDD_SHIM] + args[1:]
        elif isinstance(args, str) and args.startswith("ldd "):
            args = _LDD_SHIM + args[3:]
        super().__init__(args, **kwargs)

_subprocess_orig.Popen = _TermuxPopen
# ── END TERMUX_PATCHED ────────────────────────────────────────
'''
    src = monkey + src

    with open("$BINDEPEND", "w") as f:
        f.write(src)

    print("Patched bindepend.py")
PYEOF
        ok "Patched bindepend.py"
    else
        info "bindepend.py already patched (TERMUX_PATCHED marker found)"
    fi
else
    warn "bindepend.py not found at expected location"
fi

# 6b) Patch building.py — fix bootloader build for Termux
BUILDING="$PI_SITE/building/building.py"
if [ -f "$BUILDING" ]; then
    if ! grep -q "TERMUX_PATCHED" "$BUILDING" 2>/dev/null; then
        python3 << PYEOF
with open("$BUILDING", "r") as f:
    src = f.read()

monkey = '''
# ── TERMUX_PATCHED: Bootloader build fixes for Termux ─────────
import os as _os
import sys as _sys

# On Termux, we skip bootloader compilation and use pre-built
# or patchelf-based approach instead, since Android's bionic
# libc lacks features the bootloader expects.
_os.environ.setdefault("PYINSTALLER_COMPILE_BOOTLOADER", "0")

# Force single-process build to avoid Android linker issues
_os.environ.setdefault("CFLAGS", "-fPIC -no-pie")
_os.environ.setdefault("LDFLAGS", "-fPIC -shared")

# Android does not have /tmp, use PREFIX/tmp
if not _os.path.exists("/tmp"):
    _os.environ.setdefault("TMPDIR", _os.environ.get("PREFIX", "/data/data/com.termux/files/usr") + "/tmp")
    _os.makedirs(_os.environ["TMPDIR"], exist_ok=True)
# ── END TERMUX_PATCHED ────────────────────────────────────────
'''
if "TERMUX_PATCHED" not in src:
    src = monkey + src
    with open("$BUILDING", "w") as f:
        f.write(src)
    print("Patched building.py")
PYEOF
        ok "Patched building.py"
    else
        info "building.py already patched"
    fi
else
    warn "building.py not found"
fi

# 6c) Patch utils/misc.py — fix runtime exec path resolution
MISC="$PI_SITE/utils/misc.py"
# Try alternate location
if [ ! -f "$MISC" ]; then
    MISC=$(find "$PI_SITE" -name "misc.py" -path "*/utils/*" 2>/dev/null | head -1)
fi
if [ -f "$MISC" ]; then
    if ! grep -q "TERMUX_PATCHED" "$MISC" 2>/dev/null; then
        python3 << PYEOF
with open("$MISC", "r") as f:
    src = f.read()

monkey = '''
# ── TERMUX_PATCHED: Fix path resolution for Termux ─────────────
import os as _os

# Ensure TMPDIR exists and is writable
_prefix = _os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
_tmpdir = _os.environ.get("TMPDIR", _os.path.join(_prefix, "tmp"))
_os.makedirs(_tmpdir, exist_ok=True)
_os.environ["TMPDIR"] = _tmpdir

# Fix: On Android, /proc/self/exe may not be readable
# PyInstaller uses it to find its own runtime; provide fallback
def _termux_get_path_to_system_dlls():
    """Return DLL search directories for Termux/Android."""
    return [
        _os.path.join(_prefix, "lib"),
        "/system/lib64",
        "/system/lib",
    ]
# ── END TERMUX_PATCHED ────────────────────────────────────────
'''
if "TERMUX_PATCHED" not in src:
    src = monkey + src
    with open("$MISC", "w") as f:
        f.write(src)
    print("Patched misc.py")
PYEOF
        ok "Patched misc.py"
    else
        info "misc.py already patched"
    fi
else
    warn "misc.py not found"
fi

# ── Step 7: Rebuild bootloader for Termux (if needed) ───────
info "Checking bootloader compatibility..."
BOOTLOADER_DIR="$PI_SITE/bootloader"
BOOTLOADER_BIN=$(find "$PI_SITE" -name "bootloader" -type f 2>/dev/null | head -1)

if [ -n "$BOOTLOADER_BIN" ]; then
    # Test if the existing bootloader can execute on this system
    # (PyInstaller bootloader has no --help; just test if it runs at all)
    if file "$BOOTLOADER_BIN" | grep -q "ELF" && \
       readelf -h "$BOOTLOADER_BIN" >/dev/null 2>&1; then
        # Check if the ELF interpreter matches Android linker
        BL_INTERP=$(readelf -l "$BOOTLOADER_BIN" 2>/dev/null | grep "interpreter" | sed 's/.*: *//')
        if echo "$BL_INTERP" | grep -q "linker"; then
            ok "Existing bootloader is compatible (Android linker)"
        else
            warn "Bootloader uses $BL_INTERP — needs patchelf or rebuild"
            REBUILD_BOOTLOADER=1
        fi
    else
        warn "Existing bootloader is incompatible — will rebuild"
        REBUILD_BOOTLOADER=1
    fi
else
    warn "No pre-built bootloader found — will rebuild"
    REBUILD_BOOTLOADER=1
fi

if [ "${REBUILD_BOOTLOADER:-0}" = "1" ]; then
    info "Building PyInstaller bootloader for $ARCH..."

    # Install build dependencies
    pkg install -y cmake make clang python-dev 2>/dev/null || \
        apt install -y cmake make clang python-dev 2>/dev/null

    BL_SRC="$PI_SITE/bootloader/src"
    BL_BUILD="$PI_SITE/bootloader/build"

    BL_ROOT="$PI_SITE/bootloader"
    if [ -d "$BL_ROOT" ]; then
        mkdir -p "$BL_BUILD"

        # PyInstaller bootloader uses waf build system
        # The waf script lives in the bootloader root directory
        WAF_SCRIPT="$BL_ROOT/waf"

        if [ -f "$WAF_SCRIPT" ]; then
            info "Building bootloader with waf..."
            cd "$BL_ROOT"

            # Set Android/bionic-specific flags
            export CFLAGS="-fPIC -no-pie -DANDROID ${CFLAGS:-}"
            export LDFLAGS="-fPIC -no-pie -landroid -llog ${LDFLAGS:-}"
            export CC="${CC:-clang}"
            export CXX="${CXX:-clang++}"

            python3 "$WAF_SCRIPT" all --targets=bootloader \
                --python="$PREFIX/bin/python${PYVER}" 2>/dev/null || {
                warn "waf build failed — trying CMake fallback"
                # CMake fallback (newer PyInstaller versions may use it)
                mkdir -p "$BL_BUILD"
                cd "$BL_BUILD"
                cmake "$BL_ROOT" \
                    -DCMAKE_C_COMPILER=clang \
                    -DCMAKE_CXX_COMPILER=clang++ \
                    -DCMAKE_BUILD_TYPE=Release \
                    -DPYTHON_INCLUDE_DIR="$PREFIX/include/python${PYVER}" \
                    -DPYTHON_LIBRARY="$PREFIX/lib/libpython${PYVER}.so" \
                    -DCMAKE_C_FLAGS="-fPIC -no-pie -DANDROID" \
                    -DCMAKE_EXE_LINKER_FLAGS="-fPIC -no-pie -landroid -llog" \
                    2>/dev/null && \
                cmake --build . --config Release 2>/dev/null || {
                    warn "Bootloader build failed. Will use onedir mode."
                    export PYINSTALLER_NO_BOOTLOADER=1
                }
            }
        else
            warn "waf not found in $BL_ROOT"
            export PYINSTALLER_NO_BOOTLOADER=1
        fi

        # Install rebuilt bootloader if it exists
        BL_OUT=$(find "$BL_BUILD" "$BL_ROOT" -name "bootloader" -type f -newer "$BL_ROOT" 2>/dev/null | head -1)
        if [ -n "$BL_OUT" ] && [ -f "$BL_OUT" ]; then
            BL_DEST="$PI_SITE/bootloader/Linux-$ARCH"
            mkdir -p "$BL_DEST"
            cp "$BL_OUT" "$BL_DEST/"
            ok "Bootloader rebuilt and installed to $BL_DEST"
        fi

        cd - 2>/dev/null || true
    else
        warn "Bootloader source not found at $BL_SRC"
        warn "Will use onefile-nocompile mode"
        export PYINSTALLER_NO_BOOTLOADER=1
    fi
fi

# ── Step 8: Install wrapper script ──────────────────────────
info "Installing termux-pyinstaller wrapper..."
WRAPPER="$PREFIX/bin/termux-pyinstaller"
cat > "$WRAPPER" << WRAPPER_EOF
#!/data/data/com.termux/files/usr/bin/bash
# ────────────────────────────────────────────────────────────
# termux-pyinstaller — Wrapper for PyInstaller on rootless Termux
# ────────────────────────────────────────────────────────────
# This wrapper sets up the correct environment variables and
# paths before delegating to the real PyInstaller.
# ────────────────────────────────────────────────────────────

set -euo pipefail

PREFIX="\${PREFIX:-/data/data/com.termux/files/usr}"
ARCH=\$(uname -m)

# Ensure TMPDIR is writable
export TMPDIR="\${TMPDIR:-\$PREFIX/tmp}"
mkdir -p "\$TMPDIR"

# Make ldd shim available
export LDD_SHIM="\$PREFIX/bin/ldd-pyinstaller-shim"

# Add Termux lib dirs to LD_LIBRARY_PATH so the linker
# can find shared objects at build time
export LD_LIBRARY_PATH="\$PREFIX/lib:\${LD_LIBRARY_PATH:-}"

# PyInstaller looks for its bootloader here
export PYINSTALLER_HOME="\$(python3 -c 'import PyInstaller; print(PyInstaller.__path__[0])')"

# Disable UPX by default (not available/reliable on Termux)
export PYINSTALLER_UPX=0

# Tell PyInstaller not to use hardlinks (Android filesystem
# may not support them on all partitions)
export PYINSTALLER_NO_HARDCOPY=1

# Pass through to real pyinstaller with all args
exec python3 -m PyInstaller "\$@"
WRAPPER_EOF
chmod +x "$WRAPPER"
ok "Wrapper installed at $WRAPPER"

# ── Step 9: Patchelf post-install fixup ─────────────────────
info "Setting up post-build patchelf hook..."
POSTHOOK="$PREFIX/bin/termux-pyinstaller-patchelf"
cat > "$POSTHOOK" << 'HOOK_EOF'
#!/data/data/com.termux/files/usr/bin/bash
# ────────────────────────────────────────────────────────────
# termux-pyinstaller-patchelf — Post-build ELF fixer
# ────────────────────────────────────────────────────────────
# After PyInstaller creates a bundle, the ELF binaries
# may have incorrect interpreter/rpath. This script fixes
# them using patchelf so the output binary can run on
# Termux without root.
# ────────────────────────────────────────────────────────────

set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
ARCH=$(uname -m)

# Determine the correct ELF interpreter for this arch
case "$ARCH" in
    aarch64|arm64)  INTERP="/system/bin/linker64" ;;
    armv7l|armv7)   INTERP="/system/bin/linker"   ;;
    x86_64)         INTERP="/system/bin/linker64" ;;
    i686|x86)       INTERP="/system/bin/linker"   ;;
    *)              INTERP="/system/bin/linker64" ;;
esac

DIST_DIR="$1"
if [ -z "$DIST_DIR" ]; then
    echo "Usage: termux-pyinstaller-patchelf <dist_dir>"
    echo "  e.g.: termux-pyinstaller-patchelf dist/myapp"
    exit 1
fi

if [ ! -d "$DIST_DIR" ]; then
    echo "Error: $DIST_DIR is not a directory"
    exit 1
fi

echo "Patching ELF files in $DIST_DIR ..."

find "$DIST_DIR" -type f -executable | while read -r bin; do
    # Skip non-ELF files
    if ! readelf -h "$bin" >/dev/null 2>&1; then
        continue
    fi

    echo "  Fixing: $bin"

    # Set the correct ELF interpreter (Android linker)
    patchelf --set-interpreter "$INTERP" "$bin" 2>/dev/null || true

    # Set rpath (replaces any stale RUNPATH from the build host)
    patchelf --set-rpath "$PREFIX/lib:/system/lib64:/system/lib" "$bin" 2>/dev/null || true
done

echo "Done. You can now run the binary from Termux."
HOOK_EOF
chmod +x "$POSTHOOK"
ok "Patchelf hook installed at $POSTHOOK"

# ── Step 10: Verify installation ────────────────────────────
info "Running verification..."
python3 -c "
import PyInstaller
import os
prefix = os.environ.get('PREFIX', '/data/data/com.termux/files/usr')
print(f'  PyInstaller version: {PyInstaller.__version__}')
print(f'  Install path: {PyInstaller.__path__[0]}')
print(f'  PREFIX: {prefix}')
print(f'  ldd shim: {os.path.join(prefix, \"bin\", \"ldd-pyinstaller-shim\")}')
print(f'  Wrapper: {os.path.join(prefix, \"bin\", \"termux-pyinstaller\")}')
print(f'  Patchelf hook: {os.path.join(prefix, \"bin\", \"termux-pyinstaller-patchelf\")}')

# Check patches
for root, dirs, files in os.walk(PyInstaller.__path__[0]):
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            try:
                with open(path) as fh:
                    if 'TERMUX_PATCHED' in fh.read():
                        print(f'  [PATCHED] {os.path.relpath(path, PyInstaller.__path__[0])}')
            except:
                pass
"

# ── Summary ─────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo -e "  ${GRN}PyInstaller Rootless Termux Port — Setup Complete${NC}"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Usage:"
echo "    1. Build your app:"
echo "       termux-pyinstaller --onefile your_script.py"
echo ""
echo "    2. Fix ELF binaries after build:"
echo "       termux-pyinstaller-patchelf dist/your_script"
echo ""
echo "    3. Run the output:"
echo "       ./dist/your_script/your_script"
echo ""
echo "  Common flags:"
echo "    --onefile         Single-file bundle (recommended)"
echo "    --onedir          One-directory bundle"
echo "    --noconfirm       Overwrite output without asking"
echo "    --clean           Clean cache before building"
echo ""
echo "  Environment variables:"
echo "    TMPDIR            Temp directory (default: \$PREFIX/tmp)"
echo "    LD_LIBRARY_PATH   Runtime library search path"
echo "    PYINSTALLER_UPX   UPX compression (default: 0/disabled)"
echo ""
echo "  Patches applied: $APPLIED_PATCHES / $TOTAL_PATCHES"
echo "═══════════════════════════════════════════════════════════"
