#!/usr/bin/env python3
"""
secfil - encrypt

Part of secfil, a small tool for encrypting a file into a single,
offline, self-decrypting HTML page. Works on Termux (Android) without
root - no native Android APIs are used, only pure Python + pycryptodome.

Termux setup (one-time):
    pkg install clang python -y
    pip install pycryptodome

Companion decrypt tool: secfil_decrypt.py (decrypt without a browser)

Blob format (self-describing, all versions can decrypt any other version's output):
    salt (16 bytes)
    nonce (12 bytes)
    flag (1 byte)        0 = raw, 1 = zlib-compressed before encryption
    iterations (4 bytes, big-endian unsigned int)  -- PBKDF2 iteration count used
    ciphertext (variable)
    tag (16 bytes)        AES-GCM authentication tag
`flag` and `iterations` are passed as GCM associated data, so tampering
with them (e.g. to force a weak iteration count) breaks the tag check.
"""

import os
import sys
import json
import html
import zlib
import base64
import getpass
import hashlib
import argparse
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("❌ pycryptodome is not installed.")
    print()
    print("On Termux, run:")
    print("    pkg install clang python -y")
    print("    pip install pycryptodome")
    print()
    print("On desktop Linux/macOS/Windows:")
    print("    pip install pycryptodome")
    sys.exit(1)

# ==================== CONSTANTS ====================
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
DEFAULT_ITERATIONS = 250_000
CHUNK_SIZE = 1024 * 1024
MIN_PASSWORD_LEN = 8
LARGE_FILE_WARN_MB = 300  # base64+HTML overhead makes very large files unwieldy in-browser

FLAG_NONE = 0
FLAG_COMPRESSED = 1


# ==================== STREAMING BASE64 ====================
class Base64ChunkWriter:
    """Incrementally base64-encodes bytes and writes them to a text file-like
    object, without ever holding the full encoded string in memory."""

    def __init__(self, fh):
        self.fh = fh
        self.buffer = b''

    def write(self, data: bytes):
        self.buffer += data
        usable = (len(self.buffer) // 3) * 3
        if usable:
            self.fh.write(base64.b64encode(self.buffer[:usable]).decode('ascii'))
            self.buffer = self.buffer[usable:]

    def close(self):
        if self.buffer:
            self.fh.write(base64.b64encode(self.buffer).decode('ascii'))
            self.buffer = b''


# ==================== CORE CRYPTO ====================
def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE,
                  count=iterations, hmac_hash_module=SHA256)


def encrypt_and_stream(input_path: str, password: str, out_fh, compress: bool,
                        iterations: int, progress_cb=None) -> str:
    """Encrypts input_path and writes base64(blob) directly to out_fh (a text
    file handle). Returns the SHA-256 hex digest of the ORIGINAL plaintext,
    so the user has something to manually verify against after decrypting."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    flag = FLAG_COMPRESSED if compress else FLAG_NONE
    header_meta = bytes([flag]) + iterations.to_bytes(4, 'big')

    key = derive_key(password, salt, iterations)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header_meta)  # authenticated, not encrypted

    b64w = Base64ChunkWriter(out_fh)
    b64w.write(salt + nonce + header_meta)

    total_size = os.path.getsize(input_path)
    processed = 0
    sha = hashlib.sha256()
    compressor = zlib.compressobj() if compress else None

    with open(input_path, 'rb') as fin:
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            sha.update(chunk)
            processed += len(chunk)
            if progress_cb:
                progress_cb(processed, total_size)
            data = compressor.compress(chunk) if compressor else chunk
            if data:
                b64w.write(cipher.encrypt(data))
        if compressor:
            tail = compressor.flush()
            if tail:
                b64w.write(cipher.encrypt(tail))

    tag = cipher.digest()
    b64w.write(tag)
    b64w.close()
    if progress_cb:
        progress_cb(total_size, total_size)
    return sha.hexdigest()


def decrypt_blob_to_file(blob: bytes, password: str, out_path: str):
    """Companion decrypt used by --verify and by secfil_decrypt.py. Raises
    ValueError on wrong password / corrupted data."""
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    flag = blob[SALT_SIZE + NONCE_SIZE]
    iterations = int.from_bytes(blob[SALT_SIZE + NONCE_SIZE + 1:SALT_SIZE + NONCE_SIZE + 5], 'big')
    header_meta = blob[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + 5]
    tag = blob[-TAG_SIZE:]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE + 5:-TAG_SIZE]

    key = derive_key(password, salt, iterations)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header_meta)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("Wrong password or corrupted/tampered file.")

    if flag == FLAG_COMPRESSED:
        plaintext = zlib.decompress(plaintext)

    with open(out_path, 'wb') as f:
        f.write(plaintext)


# ==================== MISC HELPERS ====================
def get_password_securely(prompt: str) -> str:
    try:
        return getpass.getpass(prompt)
    except Exception:
        print("⚠️  Secure password entry unavailable in this terminal session; "
              "input will be visible.")
        return input(prompt)


def password_strength_note(password: str) -> str:
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if len(password) < MIN_PASSWORD_LEN:
        return f"⚠️ Password is short - use at least {MIN_PASSWORD_LEN} characters."
    if len(password) < 12 and classes < 3:
        return "⚠️ Consider a longer password or mixing letters, numbers, and symbols."
    return ""


def print_progress(processed, total, label="Encrypting"):
    pct = 100 if total == 0 else min(100, processed * 100 // total)
    bar_len = 24
    filled = bar_len * pct // 100
    bar = '#' * filled + '-' * (bar_len - filled)
    sys.stdout.write(f"\r{label} [{bar}] {pct}%")
    sys.stdout.flush()
    if processed >= total:
        sys.stdout.write("\n")


# ==================== HTML GENERATION ====================
def generate_self_decrypting_html(input_path: str, output_html: str, password: str,
                                   compress: bool, iterations: int, quiet: bool):
    original_name = os.path.basename(input_path)
    file_size_mb = os.path.getsize(input_path) / (1024 * 1024)

    if file_size_mb > LARGE_FILE_WARN_MB and not compress:
        print(f"⚠️ File is {file_size_mb:.0f} MB. Base64 + HTML overhead adds ~33%, "
              f"and some mobile browsers struggle with very large inline pages.")
        print("   Consider re-running with --compress if the file is compressible "
              "(text, logs, uncompressed docs - won't help much for photos/video/zip).")

    safe_name_html = html.escape(original_name)
    ext = original_name.split('.')[-1] if '.' in original_name else 'file'
    safe_ext_html = html.escape(ext)
    js_original_name = json.dumps(original_name)

    head_part = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>🔐 secfil</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, 'Segoe UI', system-ui, sans-serif; }}
        body {{
            min-height: 100vh; background: rgba(0,0,0,0.75);
            backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
            display: flex; align-items: center; justify-content: center; padding: 24px; margin: 0;
        }}
        .popup {{
            background: #1a1e26; border-radius: 36px; padding: 34px 28px 28px;
            max-width: 380px; width: 100%;
            box-shadow: 0 40px 100px rgba(0,0,0,0.9), 0 0 0 1px rgba(255,255,255,0.06);
            animation: popIn 0.22s cubic-bezier(0.2, 0.9, 0.3, 1.1);
        }}
        @keyframes popIn {{ from {{ opacity: 0; transform: scale(0.92) translateY(10px); }} to {{ opacity: 1; transform: scale(1) translateY(0); }} }}
        .header {{ display: flex; align-items: center; gap: 14px; margin-bottom: 22px; }}
        .header .icon {{ font-size: 32px; background: rgba(255,215,0,0.08); width: 54px; height: 54px; border-radius: 18px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }}
        .header .info h2 {{ color: #fff; font-size: 19px; font-weight: 700; letter-spacing: -0.3px; }}
        .header .info p {{ color: #7e8aa5; font-size: 13px; font-weight: 500; margin-top: 2px; }}
        .file-badge {{ background: rgba(255,255,255,0.04); border-radius: 16px; padding: 12px 16px; margin-bottom: 20px; display: flex; align-items: center; gap: 12px; border: 1px solid rgba(255,255,255,0.05); }}
        .file-badge .ext {{ background: #f0b429; color: #0b0e14; font-weight: 800; font-size: 12px; padding: 4px 12px; border-radius: 40px; text-transform: uppercase; }}
        .file-badge .name {{ color: #d0d8e8; font-size: 14px; font-weight: 500; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .file-badge .size {{ color: #6b7a93; font-size: 12px; }}
        .pass-wrap {{ background: rgba(0,0,0,0.40); border-radius: 16px; border: 1px solid rgba(255,255,255,0.06); display: flex; align-items: center; margin-bottom: 20px; transition: 0.2s; }}
        .pass-wrap:focus-within {{ border-color: #f0b429; box-shadow: 0 0 0 4px rgba(240,180,41,0.08); }}
        .pass-wrap input {{ flex: 1; background: transparent; border: none; padding: 16px 18px; color: #fff; font-size: 16px; outline: none; letter-spacing: 1.5px; }}
        .pass-wrap input::placeholder {{ color: #3d4a5c; letter-spacing: 0; }}
        .pass-wrap .toggle {{ background: none; border: none; color: #6b7a93; padding: 0 16px; font-size: 18px; cursor: pointer; }}
        .btn-unlock {{ width: 100%; padding: 16px; background: linear-gradient(135deg, #f0b429, #d4910e); border: none; border-radius: 16px; color: #0b0e14; font-size: 17px; font-weight: 700; cursor: pointer; box-shadow: 0 8px 24px rgba(240,180,41,0.20); transition: 0.15s; display: flex; align-items: center; justify-content: center; gap: 10px; }}
        .btn-unlock:hover:not(:disabled) {{ transform: translateY(-1px); }}
        .btn-unlock:disabled {{ opacity: 0.4; cursor: not-allowed; }}
        .progress-area {{ margin: 18px 0 0; display: none; }}
        .progress-area.active {{ display: block; }}
        .bar-bg {{ height: 4px; background: rgba(255,255,255,0.06); border-radius: 100px; overflow: hidden; }}
        .bar-fill {{ height: 100%; width: 0%; background: linear-gradient(90deg, #f0b429, #ffd966); border-radius: 100px; transition: width 0.2s; }}
        .prog-labels {{ display: flex; justify-content: space-between; color: #6b7a93; font-size: 12px; margin-top: 6px; }}
        .status {{ text-align: center; font-size: 14px; font-weight: 500; padding: 10px; border-radius: 12px; margin-top: 14px; display: none; }}
        .status.error {{ display: block; background: rgba(255,70,70,0.10); color: #ff6b6b; border: 1px solid rgba(255,70,70,0.10); }}
        .status.success {{ display: block; background: rgba(70,255,130,0.06); color: #5ddf8a; border: 1px solid rgba(70,255,130,0.08); }}
        .footer {{ text-align: center; color: #3d4a5c; font-size: 11px; margin-top: 20px; border-top: 1px solid rgba(255,255,255,0.03); padding-top: 16px; letter-spacing: 0.3px; }}
    </style>
</head>
<body>
<div class="popup" role="dialog" aria-label="Unlock encrypted file">
    <div class="header">
        <div class="icon">🔐</div>
        <div class="info"><h2>Unlock File</h2><p>AES‑256 · Offline</p></div>
    </div>
    <div class="file-badge">
        <span class="ext">{safe_ext_html}</span>
        <span class="name">{safe_name_html}</span>
        <span class="size">{file_size_mb:.1f} MB</span>
    </div>
    <div class="pass-wrap">
        <input type="password" id="passwordInput" placeholder="Enter password" autocomplete="off">
        <button class="toggle" id="toggleVis" type="button">👁️</button>
    </div>
    <button class="btn-unlock" id="unlockBtn">🔓 Unlock &amp; Restore</button>
    <div class="progress-area" id="progressWrap">
        <div class="bar-bg"><div class="bar-fill" id="progressFill"></div></div>
        <div class="prog-labels"><span id="progLabel">Decrypting...</span><span id="progPercent">0%</span></div>
    </div>
    <div class="status" id="statusMsg"></div>
    <div class="footer">🔒 secfil · 100% offline · Data is embedded in this file</div>
</div>
<script>
(function() {{
    "use strict";
    const ORIGINAL_NAME = {js_original_name};
    const SALT_SIZE = 16, NONCE_SIZE = 12, TAG_SIZE = 16;
    const B64_DATA = "'''

    tail_part = '''";

    const pwInput = document.getElementById('passwordInput');
    const toggleVis = document.getElementById('toggleVis');
    const unlockBtn = document.getElementById('unlockBtn');
    const progressWrap = document.getElementById('progressWrap');
    const progressFill = document.getElementById('progressFill');
    const progLabel = document.getElementById('progLabel');
    const progPercent = document.getElementById('progPercent');
    const statusMsg = document.getElementById('statusMsg');

    function setStatus(msg, type) { statusMsg.textContent = msg; statusMsg.className = 'status'; if (type) statusMsg.classList.add(type); }
    function clearStatus() { statusMsg.className = 'status'; statusMsg.textContent = ''; }
    function updateProgress(pct, label) { progressWrap.classList.add('active'); progressFill.style.width = pct + '%'; progPercent.textContent = Math.round(pct) + '%'; if (label) progLabel.textContent = label; }
    function resetProgress() { progressWrap.classList.remove('active'); progressFill.style.width = '0%'; progPercent.textContent = '0%'; progLabel.textContent = 'Decrypting...'; }
    function setLoading(loading) { unlockBtn.disabled = loading; unlockBtn.textContent = loading ? '⏳ Unlocking...' : '🔓 Unlock & Restore'; }

    toggleVis.addEventListener('click', () => {
        const t = pwInput.type === 'password' ? 'text' : 'password';
        pwInput.type = t;
        toggleVis.textContent = t === 'password' ? '👁️' : '🙈';
    });

    function base64ToBytes(b64) {
        const bin = atob(b64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return arr;
    }

    async function deriveKey(password, salt, iterations) {
        const enc = new TextEncoder();
        const keyMat = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
        return await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
            keyMat, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
        );
    }

    async function maybeDecompress(buffer, flag) {
        if (flag !== 1) return buffer;
        if (typeof DecompressionStream === 'undefined') {
            throw new Error('This file is compressed but your browser lacks DecompressionStream support. Try a recent Chrome, Firefox, or Edge.');
        }
        const ds = new DecompressionStream('deflate');
        const stream = new Blob([buffer]).stream().pipeThrough(ds);
        return await new Response(stream).arrayBuffer();
    }

    async function decryptBlob(encryptedBytes, password) {
        const data = new Uint8Array(encryptedBytes);
        const salt = data.slice(0, SALT_SIZE);
        const nonce = data.slice(SALT_SIZE, SALT_SIZE + NONCE_SIZE);
        const flag = data[SALT_SIZE + NONCE_SIZE];
        const iterView = data.slice(SALT_SIZE + NONCE_SIZE + 1, SALT_SIZE + NONCE_SIZE + 5);
        const iterations = (iterView[0] << 24 | iterView[1] << 16 | iterView[2] << 8 | iterView[3]) >>> 0;
        const headerMeta = data.slice(SALT_SIZE + NONCE_SIZE, SALT_SIZE + NONCE_SIZE + 5);
        const tagStart = data.length - TAG_SIZE;
        const tag = data.slice(tagStart);
        const ciphertext = data.slice(SALT_SIZE + NONCE_SIZE + 5, tagStart);

        const full = new Uint8Array(ciphertext.length + tag.length);
        full.set(ciphertext, 0);
        full.set(tag, ciphertext.length);

        const key = await deriveKey(password, salt, iterations);
        const plainCompressed = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: headerMeta, tagLength: 128 },
            key, full
        );
        return await maybeDecompress(plainCompressed, flag);
    }

    unlockBtn.addEventListener('click', async () => {
        const password = pwInput.value;
        if (!password) { setStatus('⚠️ Please enter the password.', 'error'); return; }

        clearStatus();
        setLoading(true);
        resetProgress();
        updateProgress(5, 'Preparing...');

        try {
            updateProgress(15, 'Decoding data...');
            const encryptedBytes = base64ToBytes(B64_DATA);

            updateProgress(25, 'Deriving key (this can take a few seconds)...');
            const decryptedBuffer = await decryptBlob(encryptedBytes, password);
            updateProgress(85, 'Restoration successful!');

            const blob = new Blob([decryptedBuffer]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = ORIGINAL_NAME;
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 10000);

            updateProgress(100, '✅ Done!');
            setStatus('✅ File restored and downloaded successfully!', 'success');
        } catch (err) {
            console.error(err);
            let msg = '❌ Decryption failed. ';
            if (err.message && err.message.toLowerCase().includes('decrypt')) {
                msg += 'Wrong password or corrupted file.';
            } else if (err.message) {
                msg += err.message;
            } else {
                msg += 'Check your password and try again.';
            }
            setStatus(msg, 'error');
            resetProgress();
        } finally {
            setLoading(false);
        }
    });

    pwInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlockBtn.click(); });
    console.log('🔐 Self-decrypting pop-up ready.');
})();
</script>
</body>
</html>
'''

    try:
        with open(output_html, 'w', encoding='utf-8') as f:
            f.write(head_part)
            sha_hex = encrypt_and_stream(
                input_path, password, f, compress, iterations,
                progress_cb=None if quiet else lambda p, t: print_progress(p, t)
            )
            f.write(tail_part)
    except (IOError, OSError) as e:
        print(f"❌ Could not write output file: {e}")
        print("   On Termux, make sure you're writing to a location you have")
        print("   permission for (e.g. run 'termux-setup-storage' once, then")
        print("   write to ~/storage/downloads/).")
        sys.exit(1)

    print(f"✅ Self-decrypting file created: {output_html}")
    print(f"📁 Original: {original_name} ({file_size_mb:.2f} MB)"
          f"{' [compressed]' if compress else ''}")
    print(f"🔎 SHA-256 of original file (verify after decrypting): {sha_hex}")
    print("\n📤 Share this SINGLE HTML file with your friend, and give them")
    print("   the password through a separate channel (not in the same message).")
    print("   They just open it → pop-up appears → enter password → file downloads.")
    print("   (No browser handy? secfil_decrypt.py can decrypt from the command line instead.)")

    return sha_hex


def extract_blob_from_html(html_path: str) -> bytes:
    """Pull the base64 blob back out of a generated HTML file (used by --verify)."""
    text = Path(html_path).read_text(encoding='utf-8')
    marker = 'const B64_DATA = "'
    start = text.index(marker) + len(marker)
    end = text.index('"', start)
    return base64.b64decode(text[start:end])


# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(
        prog="secfil",
        description="secfil - encrypt a file into a single self-decrypting HTML page.")
    parser.add_argument("input_file")
    parser.add_argument("-o", "--output", help="output .html path (default: <name>_secure.html next to input)")
    parser.add_argument("--compress", action="store_true",
                         help="zlib-compress before encrypting (helps text/logs, not photos/video/zip)")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                         help=f"PBKDF2 iterations (default {DEFAULT_ITERATIONS}); stored in the file itself")
    parser.add_argument("--verify", action="store_true",
                         help="round-trip decrypt after encrypting to confirm it's correct before sharing")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"❌ File not found: {args.input_file}")
        sys.exit(1)
    if not os.path.isfile(args.input_file):
        print(f"❌ Not a regular file: {args.input_file}")
        sys.exit(1)
    if args.iterations < 100_000:
        print("⚠️ --iterations below 100000 is not recommended.")

    if args.output:
        output_file = args.output
    else:
        base = Path(args.input_file).stem
        output_file = str(Path(args.input_file).parent / f"{base}_secure.html")

    if os.path.exists(output_file):
        answer = input(f"⚠️ '{output_file}' already exists. Overwrite? [y/N]: ").strip().lower()
        if answer != 'y':
            print("Aborted.")
            sys.exit(1)

    try:
        password = get_password_securely("🔑 Enter a strong password: ")
        confirm = get_password_securely("Confirm password: ")
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)

    if password != confirm:
        print("❌ Passwords do not match.")
        sys.exit(1)
    if not password:
        print("❌ Password cannot be empty.")
        sys.exit(1)
    note = password_strength_note(password)
    if note:
        print(note)

    try:
        sha_hex = generate_self_decrypting_html(
            args.input_file, output_file, password, args.compress, args.iterations, args.quiet)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)

    if args.verify:
        print("\n🔬 Verifying (round-trip decrypt)...")
        tmp_out = output_file + ".verify.tmp"
        try:
            blob = extract_blob_from_html(output_file)
            decrypt_blob_to_file(blob, password, tmp_out)
            check_sha = hashlib.sha256(Path(tmp_out).read_bytes()).hexdigest()
            if check_sha == sha_hex:
                print("✅ Verify passed: decrypted content matches the original exactly.")
            else:
                print("❌ Verify FAILED: decrypted content does not match the original!")
                print("   Do not share this file. Please re-run and report this.")
                sys.exit(1)
        finally:
            if os.path.exists(tmp_out):
                os.remove(tmp_out)


if __name__ == "__main__":
    main()
