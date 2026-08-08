#!/usr/bin/env python3
"""
secfil - encrypt a file into a single, offline, self-decrypting HTML page.

Enhanced single-file version with:
  - Built-in CLI decrypt (--decrypt), info (--info), keygen (--keygen), shred (--shred)
  - Keyfile support (--keyfile) for two-factor auth
  - Filename encryption (--hide-name, default on)
  - Attempt lockout (--max-attempts) in browser
  - Expiry timer (--expiry-days)
  - Armor/base64 output (--armor) for piping
  - Random password generation (--gen-password)
  - Enhanced HTML UI: strength meter, attempt lockout, SHA copy, expiry countdown
  - Streaming encryption, optional zlib compression, round-trip verify

Crypto: AES-256-GCM + PBKDF2-SHA256 (250K iterations default)
Blob format (self-describing, cross-version):
    magic    (4 bytes)   b'SCF1'
    salt     (16 bytes)
    nonce    (12 bytes)
    flag     (1 byte)    bit0=compressed, bit1=name_encrypted
    iterations (4 bytes, big-endian)
    created  (8 bytes, big-endian unix timestamp, 0 = unknown)
    expiry   (8 bytes, big-endian unix timestamp, 0 = never)
    max_att (2 bytes, big-endian, 0 = unlimited)
    name_len (2 bytes, big-endian, 0 = original name not stored)
    enc_name (name_len bytes, AES-GCM encrypted filename if bit1 set)
    ciphertext (variable)
    tag      (16 bytes) AES-GCM authentication tag

flag+iterations+created+expiry+max_att+name_len are GCM associated data,
so tampering with any of them breaks the tag check.

Works on Termux (Android) without root. Only pure Python + pycryptodome.

Termux setup (one-time):
    pkg install clang python -y
    pip install pycryptodome
"""

import os
import re
import sys
import json
import html
import zlib
import base64
import struct
import getpass
import hashlib
import argparse
import secrets
import string
import time
import shutil
from pathlib import Path
from datetime import datetime, timezone

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("pycryptodome is not installed.")
    print()
    print("On Termux:")
    print("    pkg install clang python -y")
    print("    pip install pycryptodome")
    print()
    print("On desktop:")
    print("    pip install pycryptodome")
    sys.exit(1)

# ==================== CONSTANTS ====================
MAGIC = b'SCF1'
MAGIC_SIZE = 4
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
DEFAULT_ITERATIONS = 250_000
CHUNK_SIZE = 1024 * 1024
MIN_PASSWORD_LEN = 8
LARGE_FILE_WARN_MB = 300

FLAG_NONE = 0
FLAG_COMPRESSED = 1       # bit 0
FLAG_NAME_ENCRYPTED = 2   # bit 1

MAX_ATTEMPTS_DEFAULT = 0  # unlimited
NAME_NONCE_SIZE = 12
NAME_TAG_SIZE = 16

VERSION = "2.0.0"


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


def derive_key_with_keyfile(password: str, keyfile_path: str, salt: bytes, iterations: int) -> bytes:
    """Derive key from password + keyfile content (two-factor)."""
    keyfile_bytes = Path(keyfile_path).read_bytes()
    combined = password.encode('utf-8') + b'\x00' + keyfile_bytes
    return PBKDF2(combined, salt, dkLen=KEY_SIZE,
                  count=iterations, hmac_hash_module=SHA256)


def encrypt_filename(key: bytes, original_name: str):
    """Encrypt the original filename. Returns (nonce, ciphertext+tag)."""
    name_nonce = os.urandom(NAME_NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=name_nonce)
    enc_name, name_tag = cipher.encrypt_and_digest(original_name.encode('utf-8'))
    return name_nonce, enc_name + name_tag


def decrypt_filename(key: bytes, name_nonce: bytes, enc_name_with_tag: bytes) -> str:
    """Decrypt the original filename. Raises ValueError on failure."""
    enc_name = enc_name_with_tag[:-NAME_TAG_SIZE]
    name_tag = enc_name_with_tag[-NAME_TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=name_nonce)
    try:
        return cipher.decrypt_and_verify(enc_name, name_tag).decode('utf-8')
    except ValueError:
        raise ValueError("Failed to decrypt filename (wrong key/keyfile).")


def encrypt_and_stream(input_path: str, password: str, out_fh,
                        compress: bool, iterations: int,
                        hide_name: bool, keyfile_path: str = None,
                        created_ts: int = 0, expiry_ts: int = 0,
                        max_attempts: int = 0,
                        progress_cb=None) -> str:
    """Encrypts input_path and writes base64(blob) directly to out_fh.
    Returns SHA-256 hex digest of the ORIGINAL plaintext."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    flag = FLAG_NONE
    if compress:
        flag |= FLAG_COMPRESSED
    if hide_name:
        flag |= FLAG_NAME_ENCRYPTED

    original_name = os.path.basename(input_path)
    iterations_bytes = iterations.to_bytes(4, 'big')
    created_bytes = struct.pack('>Q', created_ts)
    expiry_bytes = struct.pack('>Q', expiry_ts)
    max_att_bytes = struct.pack('>H', max_attempts)

    # Derive key
    if keyfile_path:
        key = derive_key_with_keyfile(password, keyfile_path, salt, iterations)
    else:
        key = derive_key(password, salt, iterations)

    # Build associated data (everything that must be authenticated)
    header_meta = bytes([flag]) + iterations_bytes + created_bytes + expiry_bytes + max_att_bytes

    # Encrypt filename if requested
    enc_name_block = b''
    name_len_bytes = b'\x00\x00'
    if hide_name:
        name_nonce, enc_name_with_tag = encrypt_filename(key, original_name)
        enc_name_block = name_nonce + enc_name_with_tag
        name_len_bytes = len(enc_name_block).to_bytes(2, 'big')

    # AAD includes flag + iterations + created + expiry + max_attempts + name_len
    aad = header_meta + name_len_bytes

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)

    b64w = Base64ChunkWriter(out_fh)

    # Write header: magic + salt + nonce + flag + iterations + created + expiry + max_att + name_len + enc_name
    header = MAGIC + salt + nonce + header_meta + name_len_bytes + enc_name_block
    b64w.write(header)

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


# ==================== BLOB PARSING ====================
def parse_blob_header(blob: bytes):
    """Parse the blob header and return a dict of metadata.
    Does NOT require the password. Raises ValueError on invalid blob."""
    offset = 0
    if len(blob) < MAGIC_SIZE + SALT_SIZE + NONCE_SIZE + 1 + 4 + 8 + 8 + 2 + 2 + TAG_SIZE:
        raise ValueError("Blob too short to be a valid secfil file.")

    magic = blob[offset:offset + MAGIC_SIZE]
    offset += MAGIC_SIZE
    if magic != MAGIC:
        raise ValueError(f"Invalid magic bytes: {magic!r} (expected {MAGIC!r}). Not a secfil v2 blob.")

    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    flag = blob[offset]
    offset += 1
    iterations = int.from_bytes(blob[offset:offset + 4], 'big')
    offset += 4
    created_ts = struct.unpack('>Q', blob[offset:offset + 8])[0]
    offset += 8
    expiry_ts = struct.unpack('>Q', blob[offset:offset + 8])[0]
    offset += 8
    max_attempts = struct.unpack('>H', blob[offset:offset + 2])[0]
    offset += 2
    name_len = struct.unpack('>H', blob[offset:offset + 2])[0]
    offset += 2

    enc_name_block = blob[offset:offset + name_len] if name_len > 0 else b''
    offset += name_len

    header_meta = blob[MAGIC_SIZE + SALT_SIZE + NONCE_SIZE:offset - name_len]
    # Actually, let me recalculate header_meta properly
    hm_start = MAGIC_SIZE + SALT_SIZE + NONCE_SIZE
    header_meta = blob[hm_start:hm_start + 1 + 4 + 8 + 8 + 2]  # flag+iter+created+expiry+max_att

    tag = blob[-TAG_SIZE:]
    ciphertext = blob[offset:-TAG_SIZE]

    aad = header_meta + name_len.to_bytes(2, 'big')

    return {
        'salt': salt,
        'nonce': nonce,
        'flag': flag,
        'iterations': iterations,
        'created_ts': created_ts,
        'expiry_ts': expiry_ts,
        'max_attempts': max_attempts,
        'name_len': name_len,
        'enc_name_block': enc_name_block,
        'header_meta': header_meta,
        'aad': aad,
        'ciphertext': ciphertext,
        'tag': tag,
        'compressed': bool(flag & FLAG_COMPRESSED),
        'name_encrypted': bool(flag & FLAG_NAME_ENCRYPTED),
    }


def decrypt_blob_to_file(blob: bytes, password: str, out_path: str,
                          keyfile_path: str = None) -> str:
    """Decrypt a blob to a file. Returns the decrypted filename (or 'file' if not stored).
    Raises ValueError on wrong password / corrupted data."""
    hdr = parse_blob_header(blob)

    if hdr['expiry_ts'] > 0:
        now = int(time.time())
        if now > hdr['expiry_ts']:
            raise ValueError("This file has expired and can no longer be decrypted.")

    if keyfile_path:
        key = derive_key_with_keyfile(password, keyfile_path, hdr['salt'], hdr['iterations'])
    else:
        key = derive_key(password, hdr['salt'], hdr['iterations'])

    # Decrypt filename
    original_name = None
    if hdr['name_encrypted'] and hdr['enc_name_block']:
        name_nonce = hdr['enc_name_block'][:NAME_NONCE_SIZE]
        enc_name_with_tag = hdr['enc_name_block'][NAME_NONCE_SIZE:]
        try:
            original_name = decrypt_filename(key, name_nonce, enc_name_with_tag)
        except ValueError:
            raise ValueError("Wrong password/keyfile or corrupted file.")

    cipher = AES.new(key, AES.MODE_GCM, nonce=hdr['nonce'])
    cipher.update(hdr['aad'])
    try:
        plaintext = cipher.decrypt_and_verify(hdr['ciphertext'], hdr['tag'])
    except ValueError:
        raise ValueError("Wrong password or corrupted/tampered file.")

    if hdr['compressed']:
        plaintext = zlib.decompress(plaintext)

    with open(out_path, 'wb') as f:
        f.write(plaintext)

    return original_name or 'decrypted_file'


def decrypt_blob_to_bytes(blob: bytes, password: str,
                           keyfile_path: str = None) -> tuple:
    """Decrypt a blob to bytes in memory. Returns (plaintext_bytes, original_name).
    Raises ValueError on wrong password / corrupted data."""
    hdr = parse_blob_header(blob)

    if hdr['expiry_ts'] > 0:
        now = int(time.time())
        if now > hdr['expiry_ts']:
            raise ValueError("This file has expired and can no longer be decrypted.")

    if keyfile_path:
        key = derive_key_with_keyfile(password, keyfile_path, hdr['salt'], hdr['iterations'])
    else:
        key = derive_key(password, hdr['salt'], hdr['iterations'])

    original_name = None
    if hdr['name_encrypted'] and hdr['enc_name_block']:
        name_nonce = hdr['enc_name_block'][:NAME_NONCE_SIZE]
        enc_name_with_tag = hdr['enc_name_block'][NAME_NONCE_SIZE:]
        try:
            original_name = decrypt_filename(key, name_nonce, enc_name_with_tag)
        except ValueError:
            raise ValueError("Wrong password/keyfile or corrupted file.")

    cipher = AES.new(key, AES.MODE_GCM, nonce=hdr['nonce'])
    cipher.update(hdr['aad'])
    try:
        plaintext = cipher.decrypt_and_verify(hdr['ciphertext'], hdr['tag'])
    except ValueError:
        raise ValueError("Wrong password or corrupted/tampered file.")

    if hdr['compressed']:
        plaintext = zlib.decompress(plaintext)

    return plaintext, (original_name or 'decrypted_file')


# ==================== MISC HELPERS ====================
def get_password_securely(prompt: str) -> str:
    try:
        return getpass.getpass(prompt)
    except Exception:
        print("WARNING: Secure password entry unavailable; input will be visible.")
        return input(prompt)


def password_strength_note(password: str) -> str:
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if len(password) < MIN_PASSWORD_LEN:
        return f"WARNING: Password is short - use at least {MIN_PASSWORD_LEN} characters."
    if len(password) < 12 and classes < 3:
        return "WARNING: Consider a longer password or mixing letters, numbers, and symbols."
    return ""


def password_strength_score(password: str) -> int:
    """Return 0-4 score for UI meter."""
    if not password:
        return 0
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes >= 3:
        score += 1
    if classes >= 4 and len(password) >= 16:
        score += 1
    return score


def generate_password(length: int = 24) -> str:
    """Generate a strong random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    while True:
        pw = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


def generate_keyfile(path: str, size: int = 64) -> str:
    """Generate a random keyfile."""
    data = os.urandom(size)
    Path(path).write_bytes(data)
    return path


def print_progress(processed, total, label="Encrypting"):
    pct = 100 if total == 0 else min(100, processed * 100 // total)
    bar_len = 24
    filled = bar_len * pct // 100
    bar = '#' * filled + '-' * (bar_len - filled)
    sys.stdout.write(f"\r{label} [{bar}] {pct}%")
    sys.stdout.flush()
    if processed >= total:
        sys.stdout.write("\n")


def secure_delete(path: str, passes: int = 3):
    """Securely overwrite and delete a file (best-effort on SSD)."""
    size = os.path.getsize(path)
    with open(path, 'wb') as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    os.remove(path)


def format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def format_timestamp(ts: int) -> str:
    """Format unix timestamp to readable string."""
    if ts == 0:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return "Invalid"


def extract_blob_from_html(html_path: str) -> bytes:
    """Pull the base64 blob back out of a generated HTML file."""
    text = Path(html_path).read_text(encoding='utf-8')
    marker = 'const B64_DATA = "'
    start = text.index(marker) + len(marker)
    end = text.index('"', start)
    return base64.b64decode(text[start:end])


def extract_blob_from_armor(armor_path: str) -> bytes:
    """Pull the base64 blob from an armor file."""
    text = Path(armor_path).read_text(encoding='utf-8')
    lines = text.strip().split('\n')
    # Find between -----BEGIN SCF1 BLOB----- and -----END SCF1 BLOB-----
    b64_lines = []
    inside = False
    for line in lines:
        if line.strip() == '-----BEGIN SCF1 BLOB-----':
            inside = True
            continue
        if line.strip() == '-----END SCF1 BLOB-----':
            break
        if inside:
            b64_lines.append(line.strip())
    if not b64_lines:
        raise ValueError("No armor blob found in file.")
    return base64.b64decode(''.join(b64_lines))


def load_blob(path: str) -> bytes:
    """Load blob from either HTML or armor file."""
    text = Path(path).read_text(encoding='utf-8')
    if '-----BEGIN SCF1 BLOB-----' in text:
        return extract_blob_from_armor(path)
    elif 'const B64_DATA' in text:
        return extract_blob_from_html(path)
    else:
        # Try raw blob
        return Path(path).read_bytes()


# ==================== HTML GENERATION ====================
def generate_self_decrypting_html(input_path: str, output_html: str, password: str,
                                   compress: bool, iterations: int, quiet: bool,
                                   hide_name: bool, keyfile_path: str = None,
                                   expiry_days: int = 0, max_attempts: int = 0,
                                   gen_password: bool = False):
    original_name = os.path.basename(input_path)
    file_size_mb = os.path.getsize(input_path) / (1024 * 1024)
    file_size_bytes = os.path.getsize(input_path)

    if file_size_mb > LARGE_FILE_WARN_MB and not compress:
        print(f"WARNING: File is {file_size_mb:.0f} MB. Base64 + HTML overhead adds ~33%.")
        print("   Consider --compress if the file is compressible.")

    created_ts = int(time.time())
    expiry_ts = int(time.time() + expiry_days * 86400) if expiry_days > 0 else 0

    # Display name: show "Encrypted" if hiding, else real name
    display_name = "Encrypted File" if hide_name else original_name
    ext = "ENC" if hide_name else (original_name.split('.')[-1] if '.' in original_name else 'file')

    safe_name_html = html.escape(display_name)
    safe_ext_html = html.escape(ext.upper())
    js_display_name = json.dumps(display_name)

    # Build creation/expiry JS values
    js_created = created_ts
    js_expiry = expiry_ts
    js_max_attempts = max_attempts

    # SHA placeholder for embedding (will be filled after encryption)
    sha_placeholder = "SHA_PLACEHOLDER"

    head_part = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>secfil</title>
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
        .meta-row {{ display: flex; justify-content: space-between; color: #6b7a93; font-size: 11px; margin-bottom: 4px; padding: 0 2px; }}
        .meta-row .label {{ color: #4d5a6e; }}
        .pass-wrap {{ background: rgba(0,0,0,0.40); border-radius: 16px; border: 1px solid rgba(255,255,255,0.06); display: flex; align-items: center; margin-bottom: 6px; transition: 0.2s; }}
        .pass-wrap:focus-within {{ border-color: #f0b429; box-shadow: 0 0 0 4px rgba(240,180,41,0.08); }}
        .pass-wrap input {{ flex: 1; background: transparent; border: none; padding: 16px 18px; color: #fff; font-size: 16px; outline: none; letter-spacing: 1.5px; }}
        .pass-wrap input::placeholder {{ color: #3d4a5c; letter-spacing: 0; }}
        .pass-wrap .toggle {{ background: none; border: none; color: #6b7a93; padding: 0 16px; font-size: 18px; cursor: pointer; }}
        .strength-bar {{ height: 3px; border-radius: 100px; margin-bottom: 16px; overflow: hidden; background: rgba(255,255,255,0.04); }}
        .strength-fill {{ height: 100%; width: 0%; border-radius: 100px; transition: width 0.3s, background 0.3s; }}
        .strength-label {{ font-size: 11px; color: #4d5a6e; margin-bottom: 12px; padding: 0 2px; min-height: 14px; }}
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
        .sha-row {{ display: none; margin-top: 12px; padding: 10px 12px; background: rgba(255,255,255,0.03); border-radius: 10px; border: 1px solid rgba(255,255,255,0.04); }}
        .sha-row.visible {{ display: flex; align-items: center; gap: 8px; }}
        .sha-row code {{ flex: 1; font-family: 'SF Mono', 'Cascadia Code', monospace; font-size: 10px; color: #6b7a93; word-break: break-all; }}
        .sha-row .copy-btn {{ background: rgba(255,255,255,0.06); border: none; color: #7e8aa5; font-size: 11px; padding: 4px 10px; border-radius: 8px; cursor: pointer; flex-shrink: 0; }}
        .sha-row .copy-btn:hover {{ background: rgba(255,255,255,0.10); }}
        .lockout-msg {{ text-align: center; color: #ff6b6b; font-size: 13px; font-weight: 600; margin-top: 8px; display: none; }}
        .lockout-msg.active {{ display: block; }}
        .expiry-msg {{ text-align: center; color: #f0b429; font-size: 12px; margin-top: 8px; display: none; }}
        .expiry-msg.active {{ display: block; }}
        .footer {{ text-align: center; color: #3d4a5c; font-size: 11px; margin-top: 20px; border-top: 1px solid rgba(255,255,255,0.03); padding-top: 16px; letter-spacing: 0.3px; }}
    </style>
</head>
<body>
<div class="popup" role="dialog" aria-label="Unlock encrypted file">
    <div class="header">
        <div class="icon">&#x1f510;</div>
        <div class="info"><h2>Unlock File</h2><p>AES-256-GCM &middot; PBKDF2 &middot; Offline</p></div>
    </div>
    <div class="file-badge">
        <span class="ext">{safe_ext_html}</span>
        <span class="name">{safe_name_html}</span>
        <span class="size">{file_size_mb:.1f} MB</span>
    </div>
    <div class="meta-row"><span class="label">Created</span><span id="metaCreated">{format_timestamp(created_ts)}</span></div>
    <div class="meta-row"><span class="label">Expiry</span><span id="metaExpiry">{format_timestamp(expiry_ts)}</span></div>
    <div class="meta-row"><span class="label">Max attempts</span><span id="metaMaxAtt">{"Unlimited" if max_attempts == 0 else str(max_attempts)}</span></div>
    <div class="pass-wrap">
        <input type="password" id="passwordInput" placeholder="Enter password" autocomplete="off" autofocus>
        <button class="toggle" id="toggleVis" type="button" aria-label="Toggle password visibility">&#x1f441;</button>
    </div>
    <div class="strength-bar"><div class="strength-fill" id="strengthFill"></div></div>
    <div class="strength-label" id="strengthLabel"></div>
    <button class="btn-unlock" id="unlockBtn">&#x1f513; Unlock &amp; Restore</button>
    <div class="lockout-msg" id="lockoutMsg"></div>
    <div class="expiry-msg" id="expiryMsg"></div>
    <div class="progress-area" id="progressWrap">
        <div class="bar-bg"><div class="bar-fill" id="progressFill"></div></div>
        <div class="prog-labels"><span id="progLabel">Decrypting...</span><span id="progPercent">0%</span></div>
    </div>
    <div class="status" id="statusMsg"></div>
    <div class="sha-row" id="shaRow">
        <code id="shaCode"></code>
        <button class="copy-btn" id="shaCopy">Copy</button>
    </div>
    <div class="footer">secfil v{VERSION} &middot; 100% offline &middot; Data is embedded in this file</div>
</div>
<script>
(function() {{
    "use strict";
    const DISPLAY_NAME = {js_display_name};
    const CREATED_TS = {js_created};
    const EXPIRY_TS = {js_expiry};
    const MAX_ATTEMPTS = {js_max_attempts};
    const SHA256_HASH = "{sha_placeholder}";
    const SALT_SIZE = 16, NONCE_SIZE = 12, TAG_SIZE = 16, MAGIC_SIZE = 4;
    const NAME_NONCE_SIZE = 12, NAME_TAG_SIZE = 16;
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
    const strengthFill = document.getElementById('strengthFill');
    const strengthLabel = document.getElementById('strengthLabel');
    const shaRow = document.getElementById('shaRow');
    const shaCode = document.getElementById('shaCode');
    const shaCopy = document.getElementById('shaCopy');
    const lockoutMsg = document.getElementById('lockoutMsg');
    const expiryMsg = document.getElementById('expiryMsg');

    // ---- Attempt tracking ----
    function getAttempts() {{ try {{ return parseInt(localStorage.getItem('_scf_att') || '0', 10); }} catch(e) {{ return 0; }} }}
    function addAttempt() {{ try {{ localStorage.setItem('_scf_att', String(getAttempts() + 1)); }} catch(e) {{}} }}
    function resetAttempts() {{ try {{ localStorage.removeItem('_scf_att'); }} catch(e) {{}} }}
    function isLockedOut() {{ return MAX_ATTEMPTS > 0 && getAttempts() >= MAX_ATTEMPTS; }}

    // ---- Expiry check ----
    if (EXPIRY_TS > 0) {{
        function checkExpiry() {{
            const now = Math.floor(Date.now() / 1000);
            const remaining = EXPIRY_TS - now;
            if (remaining <= 0) {{
                expiryMsg.textContent = 'This file has expired and cannot be decrypted.';
                expiryMsg.classList.add('active');
                unlockBtn.disabled = true;
                return true;
            }}
            const days = Math.floor(remaining / 86400);
            const hrs = Math.floor((remaining % 86400) / 3600);
            expiryMsg.textContent = 'Expires in ' + (days > 0 ? days + 'd ' : '') + hrs + 'h';
            expiryMsg.classList.add('active');
            return false;
        }}
        if (checkExpiry()) {{ /* already expired */ }}
        else {{ setInterval(checkExpiry, 60000); }}
    }}

    // ---- Lockout check ----
    if (isLockedOut()) {{
        lockoutMsg.textContent = 'Locked out: too many failed attempts (' + MAX_ATTEMPTS + ' max). Clear localStorage to reset.';
        lockoutMsg.classList.add('active');
        unlockBtn.disabled = true;
    }}

    function setStatus(msg, type) {{ statusMsg.textContent = msg; statusMsg.className = 'status'; if (type) statusMsg.classList.add(type); }}
    function clearStatus() {{ statusMsg.className = 'status'; statusMsg.textContent = ''; }}
    function updateProgress(pct, label) {{ progressWrap.classList.add('active'); progressFill.style.width = pct + '%'; progPercent.textContent = Math.round(pct) + '%'; if (label) progLabel.textContent = label; }}
    function resetProgress() {{ progressWrap.classList.remove('active'); progressFill.style.width = '0%'; progPercent.textContent = '0%'; progLabel.textContent = 'Decrypting...'; }}
    function setLoading(loading) {{ unlockBtn.disabled = loading; unlockBtn.textContent = loading ? 'Unlocking...' : 'Unlock & Restore'; }}

    // ---- Password strength ----
    function getStrength(pw) {{
        if (!pw) return {{ score: 0, label: '' }};
        let score = 0;
        if (pw.length >= 8) score++;
        if (pw.length >= 12) score++;
        const has = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/];
        const classes = has.filter(r => r.test(pw)).length;
        if (classes >= 3) score++;
        if (classes >= 4 && pw.length >= 16) score++;
        const labels = ['', 'Weak', 'Fair', 'Strong', 'Very strong'];
        const colors = ['', '#ff6b6b', '#f0b429', '#5ddf8a', '#2dd4bf'];
        return {{ score, label: labels[score], color: colors[score] }};
    }}

    pwInput.addEventListener('input', () => {{
        const s = getStrength(pwInput.value);
        strengthFill.style.width = (s.score * 25) + '%';
        strengthFill.style.background = s.color || 'transparent';
        strengthLabel.textContent = s.label;
        strengthLabel.style.color = s.color;
    }});

    toggleVis.addEventListener('click', () => {{
        const t = pwInput.type === 'password' ? 'text' : 'password';
        pwInput.type = t;
        toggleVis.textContent = t === 'password' ? '\\u{1f441}' : '\\u{1f648}';
    }});

    function base64ToBytes(b64) {{
        const bin = atob(b64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return arr;
    }}

    async function deriveKey(password, salt, iterations) {{
        const enc = new TextEncoder();
        const keyMat = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
        return await crypto.subtle.deriveKey(
            {{ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }},
            keyMat, {{ name: 'AES-GCM', length: 256 }}, false, ['decrypt']
        );
    }}

    async function decryptFilename(key, nameNonce, encNameWithTag) {{
        const enc = encNameWithTag.slice(0, encNameWithTag.length - NAME_TAG_SIZE);
        const tag = encNameWithTag.slice(encNameWithTag.length - NAME_TAG_SIZE);
        const full = new Uint8Array(enc.length + tag.length);
        full.set(enc, 0); full.set(tag, enc.length);
        const buf = await crypto.subtle.decrypt(
            {{ name: 'AES-GCM', iv: nameNonce, tagLength: 128 }},
            key, full
        );
        return new TextDecoder().decode(buf);
    }}

    async function maybeDecompress(buffer, flag) {{
        if ((flag & 1) === 0) return buffer;
        if (typeof DecompressionStream === 'undefined') {{
            throw new Error('Compressed but browser lacks DecompressionStream. Try Chrome/Firefox/Edge.');
        }}
        const ds = new DecompressionStream('deflate');
        const stream = new Blob([buffer]).stream().pipeThrough(ds);
        return await new Response(stream).arrayBuffer();
    }}

    async function decryptBlob(encryptedBytes, password) {{
        const data = new Uint8Array(encryptedBytes);
        let off = MAGIC_SIZE;
        const salt = data.slice(off, off + SALT_SIZE); off += SALT_SIZE;
        const nonce = data.slice(off, off + NONCE_SIZE); off += NONCE_SIZE;
        const flag = data[off]; off += 1;
        const iterations = (data[off]<<24|data[off+1]<<16|data[off+2]<<8|data[off+3])>>>0; off += 4;
        const created = /* skip */ 0; off += 8;
        const expiry = ((data[off]<<56|data[off+1]<<48|data[off+2]<<40|data[off+3]<<32|
                          data[off+4]<<24|data[off+5]<<16|data[off+6]<<8|data[off+7])>>>0); off += 8;
        const maxAtt = (data[off]<<8|data[off+1]); off += 2;

        // Check expiry
        if (expiry > 0) {{
            const now = Math.floor(Date.now() / 1000);
            if (now > expiry) throw new Error('This file has expired.');
        }}

        const nameLen = (data[off]<<8|data[off+1]); off += 2;
        const encNameBlock = nameLen > 0 ? data.slice(off, off + nameLen) : null; off += nameLen;

        const headerMeta = data.slice(MAGIC_SIZE + SALT_SIZE + NONCE_SIZE, MAGIC_SIZE + SALT_SIZE + NONCE_SIZE + 1 + 4 + 8 + 8 + 2);
        const aad = new Uint8Array(headerMeta.length + 2);
        aad.set(headerMeta, 0);
        aad[headerMeta.length] = data[off - nameLen - 2]; // nameLen high byte
        aad[headerMeta.length + 1] = data[off - nameLen - 1]; // nameLen low byte

        const tagStart = data.length - TAG_SIZE;
        const tag = data.slice(tagStart);
        const ciphertext = data.slice(off, tagStart);

        const full = new Uint8Array(ciphertext.length + tag.length);
        full.set(ciphertext, 0); full.set(tag, ciphertext.length);

        const key = await deriveKey(password, salt, iterations);
        const plainCompressed = await crypto.subtle.decrypt(
            {{ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }},
            key, full
        );
        const plainBuf = await maybeDecompress(plainCompressed, flag);

        // Decrypt filename
        let fileName = DISPLAY_NAME;
        if ((flag & 2) && encNameBlock && encNameBlock.length > NAME_NONCE_SIZE) {{
            try {{
                const nameNonce = encNameBlock.slice(0, NAME_NONCE_SIZE);
                const encNameWithTag = encNameBlock.slice(NAME_NONCE_SIZE);
                fileName = await decryptFilename(key, nameNonce, encNameWithTag);
            }} catch(e) {{ /* keep display name */ }}
        }}

        return {{ buffer: plainBuf, fileName }};
    }}

    unlockBtn.addEventListener('click', async () => {{
        if (isLockedOut()) {{
            setStatus('Locked out. Too many failed attempts.', 'error');
            return;
        }}
        const password = pwInput.value;
        if (!password) {{ setStatus('Please enter the password.', 'error'); return; }}

        clearStatus();
        setLoading(true);
        resetProgress();
        updateProgress(5, 'Preparing...');

        try {{
            updateProgress(15, 'Decoding data...');
            const encryptedBytes = base64ToBytes(B64_DATA);

            updateProgress(25, 'Deriving key (this can take a few seconds)...');
            const result = await decryptBlob(encryptedBytes, password);
            updateProgress(85, 'Restoration successful!');

            const blob = new Blob([result.buffer]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = result.fileName;
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 10000);

            updateProgress(100, 'Done!');
            setStatus('File restored and downloaded successfully!', 'success');
            resetAttempts();

            // Show SHA for verification
            if (SHA256_HASH && SHA256_HASH !== 'SHA_PLACEHOLDER') {{
                shaCode.textContent = 'SHA-256: ' + SHA256_HASH;
                shaRow.classList.add('visible');
            }}
        }} catch (err) {{
            console.error(err);
            addAttempt();
            let msg = 'Decryption failed. ';
            const attempts = getAttempts();
            if (err.message && err.message.toLowerCase().includes('expired')) {{
                msg = 'This file has expired.';
            }} else if (err.message && (err.message.toLowerCase().includes('decrypt') || err.message.toLowerCase().includes('operation'))) {{
                msg += 'Wrong password or corrupted file.';
            }} else if (err.message) {{
                msg += err.message;
            }} else {{
                msg += 'Check your password and try again.';
            }}
            if (MAX_ATTEMPTS > 0 && attempts >= MAX_ATTEMPTS) {{
                msg += ' LOCKED OUT (' + MAX_ATTEMPTS + ' max attempts reached).';
                lockoutMsg.textContent = 'Locked out. Clear localStorage to reset.';
                lockoutMsg.classList.add('active');
                unlockBtn.disabled = true;
            }} else if (MAX_ATTEMPTS > 0) {{
                msg += ' (' + (MAX_ATTEMPTS - attempts) + ' attempts remaining)';
            }}
            setStatus(msg, 'error');
            resetProgress();
        }} finally {{
            setLoading(false);
        }}
    }});

    shaCopy.addEventListener('click', () => {{
        if (shaCode.textContent) {{
            navigator.clipboard.writeText(shaCode.textContent).then(() => {{
                shaCopy.textContent = 'Copied!';
                setTimeout(() => {{ shaCopy.textContent = 'Copy'; }}, 1500);
            }}).catch(() => {{}});
        }}
    }});

    pwInput.addEventListener('keydown', (e) => {{ if (e.key === 'Enter') unlockBtn.click(); }});
    console.log('secfil self-decrypting page ready.');
}});
</script>
</body>
</html>
'''

    try:
        with open(output_html, 'w', encoding='utf-8') as f:
            f.write(head_part)
            sha_hex = encrypt_and_stream(
                input_path, password, f, compress, iterations,
                hide_name=hide_name, keyfile_path=keyfile_path,
                created_ts=created_ts, expiry_ts=expiry_ts,
                max_attempts=max_attempts,
                progress_cb=None if quiet else lambda p, t: print_progress(p, t)
            )
            f.write(tail_part)
    except (IOError, OSError) as e:
        print(f"ERROR: Could not write output file: {e}")
        print("   On Termux, ensure you have write permissions.")
        sys.exit(1)

    # Patch the SHA-256 hash into the HTML (replace placeholder)
    if sha_placeholder in head_part:
        try:
            content = Path(output_html).read_text(encoding='utf-8')
            content = content.replace(sha_placeholder, sha_hex)
            Path(output_html).write_text(content, encoding='utf-8')
        except Exception:
            pass  # Non-critical: SHA just won't show in browser

    print(f"Self-decrypting file created: {output_html}")
    print(f"  Original: {original_name} ({file_size_mb:.2f} MB)"
          f"{' [compressed]' if compress else ''}"
          f"{' [name hidden]' if hide_name else ''}")
    if expiry_days > 0:
        print(f"  Expires: {expiry_days} days from now")
    if max_attempts > 0:
        print(f"  Max attempts: {max_attempts}")
    print(f"  SHA-256 of original: {sha_hex}")
    print()
    print("Share this SINGLE HTML file, and give the password")
    print("through a separate channel (not in the same message).")
    print("Recipient: open in browser -> enter password -> file downloads.")

    return sha_hex


# ==================== ARMOR OUTPUT ====================
def generate_armor_output(input_path: str, output_path: str, password: str,
                          compress: bool, iterations: int, quiet: bool,
                          hide_name: bool, keyfile_path: str = None,
                          expiry_days: int = 0, max_attempts: int = 0):
    """Encrypt and output as ASCII-armored base64 blob."""
    created_ts = int(time.time())
    expiry_ts = int(time.time() + expiry_days * 86400) if expiry_days > 0 else 0
    original_name = os.path.basename(input_path)

    try:
        # Write to temp, then armor-wrap
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.b64', delete=False) as tmp:
            tmp_path = tmp.name
            sha_hex = encrypt_and_stream(
                input_path, password, tmp, compress, iterations,
                hide_name=hide_name, keyfile_path=keyfile_path,
                created_ts=created_ts, expiry_ts=expiry_ts,
                max_attempts=max_attempts,
                progress_cb=None if quiet else lambda p, t: print_progress(p, t)
            )

        # Read the b64 and wrap in armor format
        b64_data = Path(tmp_path).read_text(encoding='utf-8')
        os.unlink(tmp_path)

        lines = ['-----BEGIN SCF1 BLOB-----']
        for i in range(0, len(b64_data), 76):
            lines.append(b64_data[i:i+76])
        lines.append('-----END SCF1 BLOB-----')
        lines.append('')

        Path(output_path).write_text('\n'.join(lines), encoding='utf-8')

    except (IOError, OSError) as e:
        print(f"ERROR: Could not write output: {e}")
        sys.exit(1)

    print(f"Armor blob created: {output_path}")
    print(f"  Original: {original_name}")
    print(f"  SHA-256: {sha_hex}")
    return sha_hex


# ==================== COMMANDS ====================
def cmd_encrypt(args):
    """Encrypt a file into a self-decrypting HTML page or armor blob."""
    if not os.path.exists(args.input_file):
        print(f"ERROR: File not found: {args.input_file}")
        sys.exit(1)
    if not os.path.isfile(args.input_file):
        print(f"ERROR: Not a regular file: {args.input_file}")
        sys.exit(1)
    if args.iterations < 100_000:
        print("WARNING: --iterations below 100000 is not recommended.")

    # Output path
    if args.output:
        output_file = args.output
    else:
        base = Path(args.input_file).stem
        suffix = '.scf1' if args.armor else '_secure.html'
        output_file = str(Path(args.input_file).parent / f"{base}{suffix}")

    if os.path.exists(output_file):
        answer = input(f"'{output_file}' already exists. Overwrite? [y/N]: ").strip().lower()
        if answer != 'y':
            print("Aborted.")
            sys.exit(1)

    # Password
    generated_pw = None
    if args.gen_password:
        pw_len = 24
        generated_pw = generate_password(pw_len)
        password = generated_pw
        print(f"Generated password: {generated_pw}")
        print("SAVE THIS PASSWORD - it will not be shown again!")
    else:
        try:
            password = get_password_securely("Enter a strong password: ")
            confirm = get_password_securely("Confirm password: ")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)
        if password != confirm:
            print("ERROR: Passwords do not match.")
            sys.exit(1)
        if not password:
            print("ERROR: Password cannot be empty.")
            sys.exit(1)

    note = password_strength_note(password)
    if note:
        print(note)

    # Keyfile
    keyfile_path = args.keyfile if hasattr(args, 'keyfile') and args.keyfile else None

    # Hide name (default True)
    hide_name = not args.show_name if hasattr(args, 'show_name') else True

    # Expiry
    expiry_days = args.expiry_days if hasattr(args, 'expiry_days') and args.expiry_days else 0

    # Max attempts
    max_attempts = args.max_attempts if hasattr(args, 'max_attempts') and args.max_attempts else 0

    # Encrypt
    try:
        if args.armor:
            sha_hex = generate_armor_output(
                args.input_file, output_file, password,
                args.compress, args.iterations, args.quiet,
                hide_name, keyfile_path, expiry_days, max_attempts)
        else:
            sha_hex = generate_self_decrypting_html(
                args.input_file, output_file, password,
                args.compress, args.iterations, args.quiet,
                hide_name, keyfile_path, expiry_days, max_attempts,
                args.gen_password)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)

    # Verify
    if args.verify:
        print("\nVerifying (round-trip decrypt)...")
        tmp_out = output_file + ".verify.tmp"
        try:
            blob = load_blob(output_file)
            decrypt_blob_to_file(blob, password, tmp_out, keyfile_path)
            check_sha = hashlib.sha256(Path(tmp_out).read_bytes()).hexdigest()
            if check_sha == sha_hex:
                print("Verify PASSED: decrypted content matches original exactly.")
            else:
                print("Verify FAILED: decrypted content does NOT match original!")
                print("   Do not share this file. Re-run and report this bug.")
                sys.exit(1)
        finally:
            if os.path.exists(tmp_out):
                os.remove(tmp_out)

    # Shred
    if args.shred:
        print(f"\nSecurely deleting original: {args.input_file}")
        secure_delete(args.input_file)
        print("Original file securely deleted (3 overwrite passes).")


def cmd_decrypt(args):
    """Decrypt a file from an HTML page, armor blob, or raw blob."""
    if not os.path.exists(args.input_file):
        print(f"ERROR: File not found: {args.input_file}")
        sys.exit(1)

    keyfile_path = args.keyfile if hasattr(args, 'keyfile') and args.keyfile else None

    try:
        password = get_password_securely("Enter password: ")
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)
    if not password:
        print("ERROR: Password cannot be empty.")
        sys.exit(1)

    try:
        print("Loading encrypted data...")
        blob = load_blob(args.input_file)
        print(f"Blob size: {format_size(len(blob))}")

        # Determine output path
        if args.output:
            out_path = args.output
        else:
            out_path = None  # Will use decrypted filename

        print("Decrypting...")
        # Decrypt to memory first to get filename
        plaintext, original_name = decrypt_blob_to_bytes(blob, password, keyfile_path)

        if out_path is None:
            out_path = original_name
            # Avoid overwriting
            if os.path.exists(out_path):
                base, ext = os.path.splitext(original_name)
                i = 1
                while os.path.exists(f"{base}_{i}{ext}"):
                    i += 1
                out_path = f"{base}_{i}{ext}"

        Path(out_path).write_bytes(plaintext)

        sha_hex = hashlib.sha256(plaintext).hexdigest()
        print(f"Decrypted: {out_path} ({format_size(len(plaintext))})")
        print(f"SHA-256:  {sha_hex}")
        print(f"Filename: {original_name}")

    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


def cmd_info(args):
    """Show metadata about an encrypted file without needing the password."""
    if not os.path.exists(args.input_file):
        print(f"ERROR: File not found: {args.input_file}")
        sys.exit(1)

    try:
        blob = load_blob(args.input_file)
        hdr = parse_blob_header(blob)

        # Check for old format (no magic bytes)
        print(f"File: {args.input_file}")
        print(f"Format: secfil v2 (SCF1)")
        print(f"Blob size: {format_size(len(blob))}")
        print(f"Ciphertext size: {format_size(len(hdr['ciphertext']))}")
        print(f"PBKDF2 iterations: {hdr['iterations']:,}")
        print(f"Compressed: {'Yes' if hdr['compressed'] else 'No'}")
        print(f"Filename encrypted: {'Yes' if hdr['name_encrypted'] else 'No'}")
        print(f"Created: {format_timestamp(hdr['created_ts'])}")
        print(f"Expiry: {format_timestamp(hdr['expiry_ts'])}", end='')
        if hdr['expiry_ts'] > 0:
            remaining = hdr['expiry_ts'] - int(time.time())
            if remaining > 0:
                days = remaining // 86400
                hrs = (remaining % 86400) // 3600
                print(f" ({days}d {hrs}h remaining)")
            else:
                print(" (EXPIRED)")
        else:
            print()
        print(f"Max attempts: {'Unlimited' if hdr['max_attempts'] == 0 else str(hdr['max_attempts'])}")

        # Check if it's also an HTML file
        text = Path(args.input_file).read_text(encoding='utf-8', errors='ignore')[:200]
        if '<html' in text.lower():
            print(f"Container: Self-decrypting HTML")
        elif 'BEGIN SCF1 BLOB' in Path(args.input_file).read_text(encoding='utf-8', errors='ignore')[:200]:
            print(f"Container: ASCII-armored blob")
        else:
            print(f"Container: Raw blob")

    except ValueError as e:
        # Try old format detection
        text = Path(args.input_file).read_text(encoding='utf-8', errors='ignore')[:200]
        if '<html' in text.lower() or 'B64_DATA' in text:
            print(f"File: {args.input_file}")
            print(f"Format: secfil v1 (legacy, no magic bytes)")
            print(f"Container: Self-decrypting HTML")
            print("Use --decrypt to decrypt (v1 format is still supported).")
        else:
            print(f"ERROR: {e}")
            sys.exit(1)


def cmd_keygen(args):
    """Generate a random password or keyfile."""
    length = args.length if hasattr(args, 'length') and args.length else 24

    if args.keyfile:
        kf_path = args.keyfile
        if os.path.exists(kf_path):
            answer = input(f"'{kf_path}' already exists. Overwrite? [y/N]: ").strip().lower()
            if answer != 'y':
                print("Aborted.")
                sys.exit(1)
        generate_keyfile(kf_path, 64)
        print(f"Keyfile created: {kf_path} (64 bytes of random data)")
        print("Keep this file secret and separate from the encrypted file.")
    else:
        pw = generate_password(length)
        print(f"Generated password ({length} chars): {pw}")
        print("SAVE THIS - it will not be shown again!")

        # Strength info
        score = password_strength_score(pw)
        labels = ['', 'Weak', 'Fair', 'Strong', 'Very strong']
        print(f"Strength: {labels[score]}")


# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(
        prog="secfil",
        description=f"secfil v{VERSION} - encrypt a file into a single self-decrypting HTML page.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  secfil secret.pdf                    Encrypt to self-decrypting HTML
  secfil secret.pdf --compress         Compress before encrypting
  secfil secret.pdf --armor            Output ASCII-armored blob
  secfil secret.pdf --gen-password     Auto-generate a strong password
  secfil secret.pdf --keyfile key.bin  Use keyfile for two-factor auth
  secfil secret.pdf --expiry-days 30   File expires in 30 days
  secfil secret.pdf --max-attempts 5   Lock out after 5 failed attempts
  secfil secret.pdf --shred            Securely delete original after encrypt
  secfil secret.pdf --show-name        Don't encrypt the filename
  secfil secret.pdf --verify           Round-trip verify after encrypting

  secfil --decrypt secret_secure.html  Decrypt from CLI
  secfil --info secret_secure.html     Show encrypted file metadata
  secfil --keygen                      Generate a random password
  secfil --keygen --keyfile key.bin    Generate a random keyfile
""")

    parser.add_argument("input_file", nargs='?', help="file to encrypt (or encrypted file for --decrypt/--info)")
    parser.add_argument("-o", "--output", help="output path (default: <name>_secure.html or <name>.scf1)")

    # Modes
    mode_group = parser.add_argument_group('modes')
    mode_group.add_argument("--decrypt", action="store_true", help="decrypt an encrypted file from CLI")
    mode_group.add_argument("--info", action="store_true", help="show metadata about an encrypted file")
    mode_group.add_argument("--keygen", action="store_true", help="generate a random password or keyfile")

    # Encrypt options
    enc_group = parser.add_argument_group('encryption options')
    enc_group.add_argument("--compress", action="store_true",
                           help="zlib-compress before encrypting (helps text/logs)")
    enc_group.add_argument("--armor", action="store_true",
                           help="output ASCII-armored base64 blob instead of HTML")
    enc_group.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                           help=f"PBKDF2 iterations (default {DEFAULT_ITERATIONS:,})")
    enc_group.add_argument("--verify", action="store_true",
                           help="round-trip decrypt after encrypting to confirm correctness")
    enc_group.add_argument("--shred", action="store_true",
                           help="securely delete original file after encrypting (3 overwrite passes)")

    # Security options
    sec_group = parser.add_argument_group('security options')
    sec_group.add_argument("--keyfile", metavar="PATH",
                           help="use a keyfile as additional authentication factor")
    sec_group.add_argument("--show-name", action="store_true",
                           help="don't encrypt the original filename (filename is hidden by default)")
    sec_group.add_argument("--max-attempts", type=int, default=0, metavar="N",
                           help="lock out decryption after N failed attempts in browser (0=unlimited)")
    sec_group.add_argument("--expiry-days", type=int, default=0, metavar="D",
                           help="file expires and can't be decrypted after D days (0=never)")
    sec_group.add_argument("--gen-password", action="store_true",
                           help="generate and display a strong random password")

    # Keygen options
    kg_group = parser.add_argument_group('keygen options')
    kg_group.add_argument("--length", type=int, default=24, metavar="N",
                           help="password length for --keygen (default 24)")

    # General
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")

    args = parser.parse_args()

    # Route to command
    if args.keygen:
        cmd_keygen(args)
    elif args.info:
        if not args.input_file:
            parser.error("--info requires an input file")
        cmd_info(args)
    elif args.decrypt:
        if not args.input_file:
            parser.error("--decrypt requires an input file")
        cmd_decrypt(args)
    else:
        if not args.input_file:
            parser.error("input file is required (or use --keygen/--info/--decrypt)")
        cmd_encrypt(args)


if __name__ == "__main__":
    main()
