# gh-exe-build

Build real Windows `.exe` files from Python scripts, triggered from Termux
(or anywhere) via `git push` — no Windows machine, no root, no local
cross-compiling.

## Why

PyInstaller cannot cross-compile: it only builds an executable for the
OS it runs on. Termux runs on Android/Linux, so it can never produce a
Windows `.exe` locally, no matter what's patched or installed. This
workflow solves that by offloading the actual build to a real Windows
machine — a `windows-latest` GitHub Actions runner — for free, on
GitHub's infrastructure.

## Setup (one-time)

1. Create a new GitHub repo (or use an existing one).
2. Copy this whole folder's contents into the repo root, so you have:
   ```
   your-repo/
     .github/workflows/build-exe.yml
     main.py              <- your script
     requirements.txt     <- optional, only if you have dependencies
   ```
3. From Termux:
   ```bash
   pkg install git
   cd your-repo
   git init
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
   git add .
   git commit -m "initial commit"
   git push -u origin main
   ```

Pushing to `main` automatically triggers a build.

## Usage after setup

Every time you push a change to a `.py` file:

```bash
git add .
git commit -m "update script"
git push
```

GitHub builds the `.exe` on a Windows runner automatically. No local
compiling, no Termux limitations.

### Manually triggering a build

You can also trigger a build without pushing new code, and specify
which script to build, from the GitHub web UI:

1. Go to your repo → **Actions** tab → **Build Windows EXE** workflow.
2. Click **Run workflow**.
3. Enter the path to your entry script (default: `main.py`).

### Getting the .exe

1. Go to the **Actions** tab in your repo.
2. Click the latest successful run.
3. Under **Artifacts**, download `windows-exe` — it's a zip containing
   your `.exe`.

You can also download artifacts from Termux with `curl` and a
[GitHub personal access token](https://github.com/settings/tokens) if
you want to fetch the `.exe` without opening a browser — ask if you
want that added as a script.

## Notes

- By default the workflow looks for `main.py` in the repo root. Rename
  your script or edit `entry_script` default in the workflow file to
  match, or pass a different path via **Run workflow** as above.
- If your script has dependencies, list them in `requirements.txt` in
  the repo root — the workflow installs them automatically before
  building.
- The build uses `--onefile`, producing a single standalone `.exe`. Edit
  the `pyinstaller` line in `.github/workflows/build-exe.yml` if you
  want different PyInstaller flags (e.g. `--windowed` for GUI apps with
  no console window, or `--icon=yourfile.ico`).
- Builds are free on public repos. Private repos get a monthly free
  minutes allowance on GitHub's standard plans.
