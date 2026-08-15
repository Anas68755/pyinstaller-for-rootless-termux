#!/data/data/com.termux/files/usr/bin/bash
# termux-pyinstaller-setup.sh
#
# PyInstaller's Termux-breaking bugs (bootloader compile failure via
# SysV semaphores, libpython path lookup, _bootlocale on py3.10+) were
# fixed upstream as of PyInstaller 6.20.0. No source patching needed --
# just the right toolchain and a recent enough version.
set -e

MIN_VERSION="6.20.0"

echo "==> Updating packages"
pkg update -y && pkg upgrade -y

echo "==> Installing build dependencies (clang, binutils, ldd, python)"
pkg install -y clang binutils ldd python python-pip

echo "==> Installing/upgrading pyinstaller (forcing a clean, current build)"
pip install --upgrade --force-reinstall --no-cache-dir pyinstaller

INSTALLED_VERSION=$(python3 -c "import PyInstaller; print(PyInstaller.__version__)")
echo "==> Installed PyInstaller version: $INSTALLED_VERSION"

python3 - "$INSTALLED_VERSION" "$MIN_VERSION" <<'EOF'
import sys
def parse(v):
    return tuple(int(x) for x in v.split('.')[:3])
installed, minimum = sys.argv[1], sys.argv[2]
if parse(installed) < parse(minimum):
    print(f"ERROR: PyInstaller {installed} is older than {minimum}, the first "
          f"release with the Termux bootloader/libpython fixes. "
          f"Run: pip install 'pyinstaller>={minimum}'")
    sys.exit(1)
EOF

echo "==> Verifying with a test build"
WORKDIR=$(mktemp -d)
cd "$WORKDIR"
echo 'print("Hello, PyInstaller on Termux")' > hello.py
pyinstaller -F hello.py

if [ -f "$WORKDIR/dist/hello" ]; then
    echo "==> SUCCESS: built $WORKDIR/dist/hello"
    "$WORKDIR/dist/hello"
else
    echo "==> Build did not produce an executable."
    echo "    If the bootloader failed to compile, check that 'clang' and"
    echo "    'binutils' installed correctly above, then re-run this script."
    exit 1
fi

echo
echo "PyInstaller is set up and working. Use it normally from here on:"
echo "  pyinstaller -F yourscript.py"
