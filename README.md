# secfil

Encrypt a file into a single, offline, self-decrypting HTML page.

**v2** — enhanced with built-in decrypt, keyfile support, filename encryption,
attempt lockout, expiry timers, and more. All in a single Python file.

---

## What it does

`secfil.py` encrypts any file with AES-256-GCM, wraps it in a single HTML
page, and hands you a `.html` file you can send to anyone. When they open it
in a browser, a dialog appears — they enter the password, and the original
file downloads. **No server, no accounts, no internet needed** to decrypt.
Everything happens client-side with the Web Crypto API.

Works on **Termux (Android) with no root** — just pure Python + pycryptodome.

## Files

| File | Purpose |
|---|---|
| `secfil.py` | All-in-one: encrypt, decrypt, info, keygen |
| `secfil_decrypt.py` | Standalone CLI decrypt (for Termux / headless use) |

> **Note:** `secfil.py` now has `--decrypt` built in, so `secfil_decrypt.py`
> is only needed if you want a minimal, single-purpose decrypt-only tool.

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

---

## Quick start

### Encrypt a file
```bash
python secfil.py vacation_photo.jpg
```

You'll be prompted for a password (twice), then get:

```
Self-decrypting file created: vacation_photo_secure.html
  Original: vacation_photo.jpg (4.32 MB) [name hidden]
  SHA-256 of original: 6ba6ea58...
```

Send that single `.html` file, and give the password through a **different
channel** (e.g. file over email, password over text message).

### Decrypt — in a browser
Open the `.html` file on any device, enter the password, tap **Unlock &
Restore**. The original file downloads. Nothing is uploaded anywhere;
decryption happens entirely in the page's JavaScript.

### Decrypt — from the command line
```bash
python secfil.py --decrypt vacation_photo_secure.html
# or use the standalone tool:
python secfil_decrypt.py vacation_photo_secure.html
```

---

## All options

```
python secfil.py <input_file> [options]

Modes:
  --decrypt              Decrypt an encrypted file from the CLI
  --info                 Show metadata about an encrypted file (no password needed)
  --keygen               Generate a strong random password or keyfile

Encryption:
  -o, --output PATH      Output path (default: <name>_secure.html or <name>.scf1)
  --compress              zlib-compress before encrypting (helps text/logs, not photos/video/zip)
  --armor                 Output ASCII-armored base64 blob instead of HTML
  --iterations N          PBKDF2 iterations (default 250,000)
  --verify                Round-trip decrypt after encrypting to confirm correctness
  --shred                 Securely delete original file after encrypting (3 overwrite passes)

Security:
  --keyfile PATH          Use a keyfile as additional authentication factor (two-factor)
  --show-name             Don't encrypt the original filename (filename is hidden by default)
  --max-attempts N        Lock out decryption after N failed attempts in browser (0 = unlimited)
  --expiry-days D         File expires and can't be decrypted after D days (0 = never)
  --gen-password          Generate and display a strong random password

Keygen:
  --length N              Password length for --keygen (default 24)

General:
  -q, --quiet             Suppress progress output
```

---

## Examples

### Basic encrypt
```bash
python secfil.py secret.pdf
```

### Compress a log file and verify before sending
```bash
python secfil.py server.log --compress --verify
```

### Auto-generate a strong password
```bash
python secfil.py secret.pdf --gen-password
# Output: Generated password (24 chars): Kx9#mP2$vL7!nQ4@wR8&sT3^
```

### Two-factor auth with a keyfile
```bash
# Generate a keyfile
python secfil.py --keygen --keyfile mykey.bin

# Encrypt with password + keyfile
python secfil.py secret.pdf --keyfile mykey.bin

# Decrypt (needs both password AND keyfile)
python secfil.py --decrypt secret_secure.html --keyfile mykey.bin
```

### Time-limited file that expires in 7 days
```bash
python secfil.py contract.pdf --expiry-days 7
```

### Lock out after 5 wrong password attempts (browser)
```bash
python secfil.py secret.pdf --max-attempts 5
```

### Encrypt and securely delete the original
```bash
python secfil.py sensitive_data.csv --shred
```

### ASCII-armored output (for piping, QR codes, etc.)
```bash
python secfil.py small_file.txt --armor
```

### Show metadata without decrypting
```bash
python secfil.py --info secret_secure.html
# Output:
#   Format: secfil v2 (SCF1)
#   PBKDF2 iterations: 250,000
#   Compressed: Yes
#   Filename encrypted: Yes
#   Created: 2026-08-08 19:00:00 UTC
#   Expiry: 2026-08-15 19:00:00 UTC (6d 23h remaining)
#   Max attempts: 5
```

### Decrypt from CLI
```bash
python secfil.py --decrypt secret_secure.html
python secfil.py --decrypt secret_secure.html --keyfile mykey.bin
python secfil.py --decrypt armor_file.scf1
```

### Standalone decrypt tool
```bash
python secfil_decrypt.py secret_secure.html
python secfil_decrypt.py secret_secure.html --keyfile mykey.bin
python secfil_decrypt.py secret_secure.html --info
```

---

## How it works

### Encryption
AES-256-GCM with a random 16-byte salt and 12-byte nonce per file. The key
is derived from your password with PBKDF2-HMAC-SHA256 (250,000 iterations by
default). If a keyfile is provided, the password and keyfile contents are
combined before key derivation (two-factor authentication).

### Blob format (v2, self-describing)

```
magic       4 bytes   b'SCF1'
salt        16 bytes
nonce       12 bytes
flag         1 byte   bit0 = compressed, bit1 = filename encrypted
iterations   4 bytes  (big-endian, PBKDF2 count)
created      8 bytes  (big-endian unix timestamp, 0 = unknown)
expiry       8 bytes  (big-endian unix timestamp, 0 = never)
max_attempts 2 bytes  (big-endian, 0 = unlimited)
name_len     2 bytes  (big-endian, 0 = no encrypted name)
enc_name   name_len bytes (AES-GCM encrypted filename, if bit1 set)
ciphertext   variable
tag         16 bytes  (AES-GCM authentication tag)
```

All header fields from `flag` through `name_len` are passed as **GCM
associated data** — they ride alongside the ciphertext unencrypted but are
authenticated, so tampering with any of them (e.g. lowering the iteration
count, changing the expiry, or removing attempt limits) breaks the tag check
instead of silently succeeding.

### Filename encryption
By default, the original filename is encrypted with a separate AES-GCM
operation using the same derived key. The HTML page shows "Encrypted File"
instead of leaking the real name. Use `--show-name` to disable this.

### Keyfile (two-factor)
When `--keyfile` is used, the key is derived from
`PBKDF2(password + "\0" + keyfile_contents, salt, ...)`. Both the password
and the keyfile are required to decrypt — losing either one means the file
is unrecoverable.

### Attempt lockout
When `--max-attempts N` is set, the browser JavaScript tracks failed decrypt
attempts in `localStorage`. After N failures, the unlock button is disabled
and the user is locked out. (Clearing localStorage resets this — it's a
client-side rate limit, not a cryptographic guarantee.)

### Expiry
When `--expiry-days D` is set, the expiry timestamp is embedded in the blob
and checked both in the browser JS and in the Python decrypt code. After the
expiry time, decryption is refused.

### Streaming
The Python side never holds the whole file — or its encrypted/base64 form —
in memory at once. It reads, compresses (if requested), encrypts, and
base64-encodes in 1 MB chunks straight to disk.

### Integrity
AES-GCM's tag detects any corruption or tampering. `--verify` additionally
does a full round-trip decrypt right after creation and compares SHA-256
hashes, so you catch problems before sharing, not after.

### Browser decrypt
Uses the standard Web Crypto API (`crypto.subtle`) for PBKDF2 and AES-GCM,
and `DecompressionStream` for optional compression — all built into modern
Chrome, Firefox, Safari, and Edge. No external libraries are loaded; the
page works fully offline.

---

## Browser UI features (v2)

The generated HTML page includes:

- **Real-time password strength meter** — color-coded bar that updates as you type
- **Failed attempt tracking** — shows remaining attempts, locks out when limit reached
- **SHA-256 hash display** — after successful decrypt, shows the hash with a
  **Copy** button so you can verify against the original
- **Expiry countdown** — shows time remaining before the file can no longer be decrypted
- **File metadata** — creation date, expiry, max attempts displayed in the dialog
- **Password visibility toggle** — eye icon to show/hide the typed password
- **Keyboard support** — press Enter to decrypt

---

## Backward compatibility

v2 can decrypt files produced by v1, and `secfil_decrypt.py` handles both
formats automatically. The v1 format (no magic bytes) is detected by the
absence of the `SCF1` magic header.

---

## Security notes

- **Send the password separately from the file.** If both travel through the
  same channel (e.g. the same chat thread), anyone who intercepts one gets
  the other too. Use a different app, a phone call, or an in-person exchange.
- **With a keyfile, protect the keyfile too.** Store it somewhere separate
  from both the encrypted file and the password. A lost keyfile means a
  permanently unrecoverable file.
- **Password strength matters more than anything else.** AES-256-GCM and
  250,000 PBKDF2 iterations are strong, but a weak or reused password is
  still the easiest way in. Use `--gen-password` to get a strong one
  automatically, or raise `--iterations` for extra brute-force resistance.
- **Filename encryption is on by default.** Filenames can leak sensitive
  information (e.g. "salary_review_2026.xlsx"). Use `--show-name` only if
  the recipient needs to see the filename before entering the password.
- **Attempt lockout is client-side only.** A determined attacker can clear
  localStorage or modify the HTML to bypass it. It's a convenience feature
  to prevent casual brute-forcing, not a cryptographic guarantee.
- **Expiry is enforced client-side.** The expiry timestamp is authenticated
  (tampering breaks the GCM tag), but a technically skilled recipient could
  modify the JavaScript to skip the check. Expiry is a deterrent, not a
  hard guarantee.
- **Very large files:** base64 adds ~33% overhead, and some mobile browsers
  struggle with extremely large inline HTML. The tool warns above ~300 MB.
  `--compress` helps for compressible content; for large already-compressed
  files (video, zip, most photos), consider splitting instead.
- **Secure delete (`--shred`):** overwrites the file 3 times with random data
  before deleting. Effective on HDDs; on SSDs with wear leveling, true
  secure deletion requires OS-level TRIM support.

---

## Troubleshooting

- **"Wrong password or corrupted file"** — either the password is wrong, or
  the file was modified in transit (e.g. by an email client re-encoding it).
  Re-download or re-send the original file.
- **"This file has expired"** — the sender set an expiry date that has now
  passed. Ask them to re-encrypt and send a new copy.
- **"Locked out: too many failed attempts"** — in the browser, clearing
  localStorage (DevTools > Application > Local Storage > Clear) resets the
  counter.
- **"Failed to decrypt filename"** — you likely used the wrong keyfile or
  forgot to provide `--keyfile` for a two-factor-encrypted file.
- **pycryptodome fails to install on Termux** — make sure `clang` is installed
  first (`pkg install clang python -y`); pycryptodome needs a C compiler.
- **GetPassWarning in scripts** — this happens when stdin isn't a real
  terminal (e.g. piping input). In a normal interactive session, password
  entry is hidden as usual.

---

## License

This is a personal tool. Use it at your own risk. No warranty is provided.
