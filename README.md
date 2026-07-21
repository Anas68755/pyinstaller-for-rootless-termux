# secfil

A small tool for encrypting a file into a single, self-decrypting HTML page.

Encrypt a file with AES-256-GCM and wrap it in a single, offline HTML page
that decrypts itself in the browser when the recipient enters the password.
No server, no accounts, no internet connection needed to decrypt — everything
happens client-side with the Web Crypto API.

Includes a companion CLI tool to decrypt without a browser at all, which is
handy for Termux-to-Termux transfers.

Works on Termux (Android) with **no root required** — it's pure Python plus
one native-extension dependency (pycryptodome).

## Files

| File | Purpose |
|---|---|
| `secfil.py` | Encrypts a file → produces `*_secure.html` |
| `secfil_decrypt.py` | Decrypts a `*_secure.html` file from the command line |

## Install

**Termux:**
```bash
pkg install clang python -y
pip install pycryptodome
```

**Desktop (Linux / macOS / Windows):**
```bash
pip install pycryptodome
```

## Usage

### Encrypt a file

```bash
python secfil.py vacation_photo.jpg
```

You'll be prompted twice for a password, then get:

```
✅ Self-decrypting file created: vacation_photo_secure.html
📁 Original: vacation_photo.jpg (4.32 MB)
🔎 SHA-256 of original file (verify after decrypting): 6ba6ea58...
```

Send that single `.html` file to whoever needs it, and give them the
password through a **different channel** than the one you send the file on
(e.g. file over email, password over text) — see [Security notes](#security-notes).

### Decrypt — in a browser

Open the `.html` file on any device, enter the password, tap **Unlock &
Restore**. The original file downloads automatically. Nothing is uploaded
anywhere; decryption happens entirely in the page's JavaScript.

### Decrypt — from the command line (no browser)

```bash
python secfil_decrypt.py vacation_photo_secure.html
```

### Options

```
python secfil.py <input_file> [options]

  -o, --output PATH     Output .html path (default: <name>_secure.html)
  --compress             zlib-compress before encrypting. Helps text, logs,
                          and other compressible data; does nothing useful
                          for photos, video, or already-zipped files.
  --iterations N         PBKDF2 iterations (default 250000). Stored inside
                          the file itself, so you can safely raise it for
                          extra brute-force resistance without breaking
                          decryption on either end.
  --verify               Immediately decrypts what was just created and
                          compares it byte-for-byte against the original,
                          so you know the file is good before sending it.
  -q, --quiet             Suppress the progress bar.
```

```
python secfil_decrypt.py <secure_file.html> [options]

  -o, --output PATH     Where to save the decrypted file (default: the
                          original filename embedded in the page)
```

### Example: compress a large log file and verify before sending

```bash
python secfil.py server.log --compress --verify
```

## How it works

- **Encryption:** AES-256-GCM with a random salt and nonce per file. The key
  is derived from your password with PBKDF2-HMAC-SHA256 (250,000 iterations
  by default).
- **Blob layout** (all embedded as one base64 string in the HTML):

  ```
  salt        16 bytes
  nonce       12 bytes
  flag         1 byte   (0 = raw, 1 = zlib-compressed)
  iterations   4 bytes  (big-endian, the PBKDF2 count actually used)
  ciphertext   variable
  tag         16 bytes  (AES-GCM authentication tag)
  ```

  `flag` and `iterations` are passed to AES-GCM as *associated data* — they
  ride alongside the ciphertext unencrypted but are still authenticated, so
  tampering with them (e.g. to force a weak iteration count) breaks
  decryption instead of silently succeeding.

- **Streaming:** the Python side never holds the whole file — or its
  encrypted/base64 form — in memory at once. It reads, compresses (if
  requested), encrypts, and base64-encodes in 1 MB chunks straight to disk.
- **Integrity:** AES-GCM's tag detects any corruption or tampering,
  whether the file was modified in transit or someone guessed wrong. `--verify`
  additionally does a full round-trip decrypt right after creation and
  compares SHA-256 hashes, so you catch problems before sharing, not after.
- **Browser decrypt:** uses the standard Web Crypto API (`crypto.subtle`)
  for PBKDF2 and AES-GCM, and `DecompressionStream` for the optional
  compression — both are built into modern Chrome, Firefox, Safari, and Edge.
  No external libraries are loaded, so the page works fully offline.

## Security notes

- **Send the password separately from the file.** If both travel through
  the same channel (e.g. the same chat thread), anyone who intercepts one
  gets the other too. Use a different app, a phone call, or an in-person
  exchange for the password.
- **The unlock page is styled to look like a native app dialog.** That's
  cosmetic polish for people you've told what it is — tell recipients
  what the file is and where the password is coming from. A password
  prompt that looks native but isn't is the same pattern phishing pages
  use, so don't hand this to someone without that context.
- **Password strength matters more than anything else here.** AES-256-GCM
  and 250,000 PBKDF2 iterations are strong, but a weak or reused password
  is still the easiest way in. Use `--iterations` to raise the cost of
  brute-forcing further if you're using a shorter/simpler password, or
  just use a longer, unique password.
- **Very large files:** base64 adds ~33% overhead, and some mobile browsers
  struggle with extremely large inline HTML. The tool warns above ~300 MB.
  `--compress` helps for compressible content; for large already-compressed
  files (video, zip, most photos), consider splitting the file instead.

## Troubleshooting

- **"Wrong password or corrupted file"** on decrypt — either the password
  is wrong, or the `.html` file was modified/corrupted in transit (e.g. by
  an email client re-encoding it). Re-download or re-send the original file.
- **pycryptodome fails to install on Termux** — make sure `clang` is
  installed first (`pkg install clang python -y`); pycryptodome needs a C
  compiler to build its native extension.
- **Password prompt shows a `GetPassWarning`** — this happens when stdin
  isn't a real terminal (e.g. piping input for scripting/testing). In a
  normal interactive Termux/terminal session, password entry is hidden as
  usual.
