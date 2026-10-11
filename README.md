# mkexe

Build Windows `.exe` files from Python scripts, straight from Termux. No root, no Windows PC.

```bash
mkexe myscript.py      # -> myscript.exe in the current folder
```

## How it works

PyInstaller can only build for the OS it runs on, so Termux (Android/Linux) can never produce a Windows `.exe` locally. `mkexe` gets around that:

1. Copies your script (or project folder) into a **private** GitHub repo it manages for you (`<you>/mkexe-builds`).
2. Starts a GitHub Actions build on a real **Windows** runner using PyInstaller.
3. Waits for it, then downloads the finished `.exe` to your device.

You only run one command. Everything else is automatic.

## Install

Copy the folder to your device, then:

```bash
bash install.sh
mkexe --setup        # one-time: log in to GitHub, create the build repo
```

`install.sh` installs `git`, `gh` (GitHub CLI) and `python` with `pkg`, and puts `mkexe` on your PATH.

During `mkexe --setup`, choose **GitHub.com > HTTPS > Login with a web browser** (or paste a personal access token). If asked for the `workflow` permission, accept it; it is needed to push the build workflow.

## Usage

```
mkexe [options] SOURCE
```

`SOURCE` is a `.py` file, or a project folder (entry script defaults to `main.py`).

| Option | What it does |
|---|---|
| `-n, --name NAME` | Output name (default: script name) |
| `-e, --entry FILE` | Entry script inside a project folder |
| `-r, --requirements FILE` | Requirements file (auto-detects `requirements.txt`) |
| `-w, --windowed` | No console window (GUI apps) |
| `-d, --onedir` | Folder build returned as a `.zip` instead of a single `.exe` |
| `-i, --icon FILE.ico` | Icon for the exe |
| `-o, --out DIR` | Where to save the result (default: current folder) |
| `--pyver VERSION` | Python version on the runner (default `3.12`) |
| `--repo OWNER/REPO` | Use a different build repo |
| `--no-wait` | Start the build and exit; prints the download command |
| `--local` | Build on this device instead (see below) |
| `--setup` | Only log in and create the build repo |

### Examples

```bash
mkexe tool.py
mkexe -w -i app.ico -n MyApp gui.py
mkexe ~/projects/myapp -e run.py -o ~/storage/downloads
```

To save into your phone's Downloads folder, run `termux-setup-storage` once, then use `-o ~/storage/downloads`.

## Dependencies

If a `requirements.txt` sits next to your script (or inside your project folder), it is installed on the runner before building. Or pass one with `-r`.

## Local builds (optional)

```bash
bash install.sh --with-local
mkexe --local myscript.py
```

This installs PyInstaller on your device (`clang`, `binutils`, `ldd`) and builds a binary for **Android/Linux**. It is not a Windows `.exe`. PyInstaller has supported Termux upstream since 6.20.0, so no patching is involved.

## Good to know

- **Your code is uploaded** to your private GitHub repo. Don't include secrets in the project folder.
- Only the 10 most recent jobs are kept in the repo; older ones are pruned automatically. Build artifacts expire after 7 days.
- **Cost:** public repos get free Actions minutes; private repos have a monthly free allowance, and Windows minutes count at a higher rate. Check GitHub's current limits if you build a lot.
- PyInstaller `.exe` files are sometimes flagged by antivirus software (false positives). `--onedir` is flagged less often than single-file builds.
- A build that fails prints the last log lines and a link to the full log.

## Troubleshooting

| Problem | Fix |
|---|---|
| `push failed ... workflow scope` | `gh auth refresh -s workflow`, then retry |
| `could not start the workflow` | Wait a few seconds and retry; GitHub is slow to register a new workflow file |
| Build fails on `ModuleNotFoundError` | Add the package to `requirements.txt` |
| Exe crashes at startup | Rebuild without `-w` to see the console error |
| Wrong build repo | `mkexe --repo OWNER/REPO --setup` (saved to `~/.config/mkexe/config`) |

## Files

- `mkexe`: the tool (the Windows build workflow is embedded inside it and pushed automatically)
- `install.sh`: installer
- `README.md`: this file
