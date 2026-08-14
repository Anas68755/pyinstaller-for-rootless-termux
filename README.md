# PyInstaller Rootless Termux Port

A set of patches and scripts to make **PyInstaller** work on **rootless Termux** (Android terminal emulator) without requiring `proot`, `tsu`, or root access.

## The Problem

PyInstaller assumes a standard Linux/glibc environment. Termux runs on Android's bionic libc and has a non-FHS filesystem layout (`$PREFIX = /data/data/com.termux/files/usr`). This causes several failures:

| Issue | Cause |
|-------|-------|
| `ldd` not found or broken | Android doesn't ship standard `ldd`; Termux's version may not handle all ELF formats |
| Wrong ELF interpreter | PyInstaller sets `/lib64/ld-linux-x86-64.so.2` but Android uses `/system/bin/linker64` |
| Library resolution fails | Standard paths (`/lib`, `/usr/lib`) don't exist; libs are under `$PREFIX/lib` |
| Bootloader won't compile | Expects glibc features (setresuid, etc.) unavailable in bionic |
| No `/tmp` | Android has no global writable `/tmp`; need `$PREFIX/tmp` |
| Macholib crashes | Tries to parse ELF as Mach-O on Linux |
| UPX breaks binaries | UPX-compressed ELF may not run on Android |
| Hardlink failures | Android's userdata partition may not support hardlinks |

## Quick Start

```bash
# 1. Copy all scripts to Termux
#    (termux_pyinstaller_setup.sh, patches/*, 
#     termux_pyinstaller_wrapper.sh, termux_pyinstaller_patchelf.sh)

# 2. Run the setup script
chmod +x termux_pyinstaller_setup.sh
./termux_pyinstaller_setup.sh

# 3. Build your Python app
termux-pyinstaller --onefile --clean my_script.py

# 4. Fix ELF binaries for Android
termux-pyinstaller-patchelf dist/my_script

# 5. Run it!
./dist/my_script/my_script
```

## Scripts

### `termux_pyinstaller_setup.sh`
Main setup script that:
- Installs required Termux packages (binutils, patchelf, zlib, etc.)
- Installs PyInstaller via pip
- Applies all patches to PyInstaller's source
- Creates an `ldd` shim that uses `readelf -d` as fallback
- Monkey-patches `bindepend.py`, `building.py`, `misc.py`
- Optionally rebuilds the bootloader for Android
- Installs the `termux-pyinstaller` wrapper and `termux-pyinstaller-patchelf` hook

### `termux-pyinstaller` (wrapper)
Sets up the correct environment variables before delegating to PyInstaller:
- `TMPDIR` → writable temp directory
- `LD_LIBRARY_PATH` → includes `$PREFIX/lib`
- `LDD_SHIM` → path to our custom ldd
- `PYINSTALLER_UPX=0` → disables UPX
- `PYINSTALLER_NO_HARDCOPY=1` → avoids hardlinks

Extra flag: `--auto-patchelf` → automatically runs patchelf fixup after build

### `termux-pyinstaller-patchelf`
Post-build hook that fixes ELF binaries:
- Sets interpreter to `/system/bin/linker64` (or `linker` for 32-bit)
- Sets rpath to `$PREFIX/lib:/system/lib64:/system/lib`
- Makes binaries executable

### `ldd-pyinstaller-shim`
Custom `ldd` replacement that:
1. Tries real `ldd` first
2. Falls back to `readelf -d` DT_NEEDED parsing
3. Resolves libraries against Termux search paths

## Patches

| # | Patch | What it fixes |
|---|-------|---------------|
| 1 | `0001-bindepend-termux.patch` | Adds Termux library search paths; handles unversioned .so files |
| 2 | `0002-ldd-termux.patch` | Redirects ldd through shim; readelf fallback; parses DT_NEEDED |
| 3 | `0003-building-termux.patch` | CMake flags for clang/bionic; TMPDIR fix; skips bootloader if needed |
| 4 | `0004-dylib-termux.patch` | Handles bionic-style unversioned shared libs (libc.so not libc.so.6) |
| 5 | `0005-macholib-termux.patch` | Skips Mach-O analysis on Linux; prevents crashes on ELF files |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PREFIX` | `/data/data/com.termux/files/usr` | Termux installation prefix |
| `TMPDIR` | `$PREFIX/tmp` | Writable temp directory |
| `LD_LIBRARY_PATH` | `$PREFIX/lib` | Runtime library search path |
| `PYINSTALLER_UPX` | `0` | UPX compression (disabled by default) |
| `PYINSTALLER_NO_HARDCOPY` | `1` | Avoid hardlinks |
| `LDD_SHIM` | `$PREFIX/bin/ldd-pyinstaller-shim` | Custom ldd path |
| `PYINSTALLER_COMPILE_BOOTLOADER` | `0` | Skip bootloader compilation |

## Architecture Support

| Arch | Interpreter | Status |
|------|-------------|--------|
| `aarch64` / `arm64` | `/system/bin/linker64` | ✅ Primary target |
| `x86_64` | `/system/bin/linker64` | ✅ Supported |
| `armv7l` / `arm` | `/system/bin/linker` | ✅ Supported |
| `i686` / `x86` | `/system/bin/linker` | ⚠️ Experimental |

## Known Limitations

1. **onefile mode**: The bootloader must be recompiled for Android. If compilation fails, the setup script falls back to `onedir` mode which works without the bootloader.

2. **Signal handling**: Android's bionic libc has limited signal support. Some Python packages that use `os.kill()` or `signal.SIGUSR*` may behave differently.

3. **Multiprocessing**: Android restricts `fork()` in some contexts. Use `--onedir` if your app uses multiprocessing heavily.

4. **GUI apps**: Tkinter and Qt apps need X11 (via Termux:X11). Ensure the display is set up before running the built binary.

5. **Permissions**: Android may block execution from shared storage (`/sdcard`). Build and run from within Termux's home directory.

## Troubleshooting

### "not a dynamic executable"
The ldd shim couldn't parse the binary. This usually means:
- The binary was compiled for a different architecture
- `readelf` isn't installed (`pkg install binutils`)

### "cannot find -lpython3.x"
Python dev headers missing:
```bash
pkg install python-dev
```

### Bootloader build fails
Skip bootloader compilation and use onedir mode:
```bash
export PYINSTALLER_COMPILE_BOOTLOADER=0
termux-pyinstaller --onedir my_script.py
```

### "Permission denied" when running output
Make sure you're running from Termux's filesystem, not `/sdcard`:
```bash
mkdir -p ~/myapp
cd ~/myapp
termux-pyinstaller --onefile my_script.py
```

### Segfault on startup
The ELF interpreter is likely wrong. Re-run patchelf:
```bash
termux-pyinstaller-patchelf dist/my_script
```

## File Structure

```
scripts/
├── termux_pyinstaller_setup.sh       # Main setup (run this first)
├── termux_pyinstaller_wrapper.sh     # Standalone wrapper
├── termux_pyinstaller_patchelf.sh    # Standalone patchelf hook
└── patches/
    ├── 0001-bindepend-termux.patch
    ├── 0002-ldd-termux.patch
    ├── 0003-building-termux.patch
    ├── 0004-dylib-termux.patch
    └── 0005-macholib-termux.patch
```

## License

Same as PyInstaller (GPLv2 with boot exception).
