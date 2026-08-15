# termux-pyinstaller-setup

Get PyInstaller working in Termux (Android) with no root required.

## Background

PyInstaller historically didn't work out of the box in Termux because:

1. Termux ships no `gcc`, and PyInstaller's bootloader needs to compile
   itself on first install.
2. Older PyInstaller versions used SysV semaphores in the bootloader,
   which don't exist in Android's Bionic libc.
3. Older versions also looked for `libpython3.x.so` only in `/lib` and
   `/usr/lib`, not Termux's actual prefix.

**As of PyInstaller 6.20.0 (April 2026), all of this is fixed upstream.**
The project added native Termux detection (`is_termux`) and switched the
bootloader to POSIX semaphores. No forking or source patching is needed
anymore — you just need the right toolchain and a current version.

This script automates that setup and proves it works with a real test
build, rather than just trusting that `pip install` succeeded.

## Usage

```bash
bash termux-pyinstaller-setup.sh
```

The script will:

1. Update Termux packages.
2. Install `clang`, `binutils`, `ldd`, `python`, `python-pip` (the
   toolchain PyInstaller's bootloader needs to compile).
3. Force-install a clean, current copy of PyInstaller.
4. Verify the installed version is ≥ 6.20.0 and fail with a clear
   message if not.
5. Build and run a "Hello World" binary to confirm the whole pipeline
   actually works end to end.

If the last step prints `SUCCESS`, PyInstaller is ready — use it
normally from there:

```bash
pyinstaller -F yourscript.py
```

## Troubleshooting

- **Bootloader fails to compile:** confirm `clang` and `binutils`
  installed correctly (`clang --version`, `strip --version`), then
  re-run the script.
- **Version check fails:** you're likely pulling from a stale
  pip cache or mirror. Run `pip install --no-cache-dir
  'pyinstaller>=6.20.0'` manually.
- **Still fails on your device:** a few ARM32-vs-ARM64 edge cases have
  been reported even post-fix. Share the exact error output for
  further debugging.

## Requirements

- Termux (no root needed)
- Internet access on first run (for `pkg` and `pip` installs)
