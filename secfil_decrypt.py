#!/usr/bin/env python3
"""
secfil - decrypt

Decrypts a file produced by secfil.py v2 (or v1), purely from the
command line — no browser required. Handy for Termux-to-Termux transfers
where launching a browser is inconvenient.

Supports:
  - v2 format (SCF1 magic): filename encryption, keyfiles, expiry, attempt info
  - v1 format (legacy): backward compatible, auto-detected
  - Input from self-decrypting HTML or ASCII-armored blob files

Usage:
    python secfil_decrypt.py secure_file.html [-o restored_name.ext]
    python secfil_decrypt.py secure_file.html --keyfile key.bin
    python secfil_decrypt.py armor_file.scf1
"""

import os
import sys
import json
import base64
import getpass
import hashlib
import argparse
import struct
import zlib
import time
from pathlib import Path
from datetime import datetime, timezone

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("pycryptodome is not installed.")
    print("On Termux: pkg install clang python -y && pip install pycryptodome")
    print("On desktop: pip install pycryptodome")
    sys.exit(1)

# ==================== CONSTANTS ====================
MAGIC = b'SCF1'
MAGIC_SIZE = 4
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32

FLAG_COMPRESSED = 1       # bit 0
FLAG_NAME_ENCRYPTED = 2   # bit 1

NAME_NONCE_SIZE = 12
NAME_TAG_SIZE = 16


# ==================== HELPERS ====================
def format_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def format_timestamp(ts: int) -> str:
    if ts == 0:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return "Invalid"


# ==================== BLOB LOADING ====================
def extract_blob_from_html(html_path: str) -> bytes:
    """Pull the base64 blob from a self-decrypting HTML file."""
    text = Path(html_path).read_text(encoding='utf-8')
    marker = 'const B64_DATA = "'
    start = text.index(marker) + len(marker)
    end = text.index('"', start)
    return base64.b64decode(text[start:end])


def extract_blob_from_armor(armor_path: str) -> bytes:
    """Pull the base64 blob from an ASCII-armored file."""
    text = Path(armor_path).read_text(encoding='utf-8')
    lines = text.strip().split('\n')
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
    """Load blob from HTML, armor, or raw blob file. Auto-detects format."""
    text = Path(path).read_text(encoding='utf-8')
    if '-----BEGIN SCF1 BLOB-----' in text:
        return extract_blob_from_armor(path)
    elif 'const B64_DATA' in text:
        return extract_blob_from_html(path)
    else:
        # Try raw binary blob
        return Path(path).read_bytes()


def detect_format(blob: bytes) -> str:
    """Detect blob format version."""
    if len(blob) >= MAGIC_SIZE and blob[:MAGIC_SIZE] == MAGIC:
        return 'v2'
    return 'v1'


# ==================== V2 DECRYPT ====================
def decrypt_filename_v2(key: bytes, name_nonce: bytes, enc_name_with_tag: bytes) -> str:
    """Decrypt the original filename (v2 format)."""
    enc_name = enc_name_with_tag[:-NAME_TAG_SIZE]
    name_tag = enc_name_with_tag[-NAME_TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=name_nonce)
    try:
        return cipher.decrypt_and_verify(enc_name, name_tag).decode('utf-8')
    except ValueError:
        raise ValueError("Failed to decrypt filename (wrong key/keyfile).")


def decrypt_blob_v2(blob: bytes, password: str, keyfile_path: str = None) -> tuple:
    """Decrypt a v2 (SCF1) blob. Returns (plaintext_bytes, original_name, metadata).
    Raises ValueError on wrong password / corrupted data / expired file."""
    offset = 0
    # Magic
    magic = blob[offset:offset + MAGIC_SIZE]; offset += MAGIC_SIZE
    if magic != MAGIC:
        raise ValueError(f"Invalid magic: {magic!r}")

    salt = blob[offset:offset + SALT_SIZE]; offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]; offset += NONCE_SIZE
    flag = blob[offset]; offset += 1
    iterations = int.from_bytes(blob[offset:offset + 4], 'big'); offset += 4
    created_ts = struct.unpack('>Q', blob[offset:offset + 8])[0]; offset += 8
    expiry_ts = struct.unpack('>Q', blob[offset:offset + 8])[0]; offset += 8
    max_attempts = struct.unpack('>H', blob[offset:offset + 2])[0]; offset += 2
    name_len = struct.unpack('>H', blob[offset:offset + 2])[0]; offset += 2
    enc_name_block = blob[offset:offset + name_len] if name_len > 0 else b''; offset += name_len

    header_meta = blob[MAGIC_SIZE + SALT_SIZE + NONCE_SIZE:MAGIC_SIZE + SALT_SIZE + NONCE_SIZE + 1 + 4 + 8 + 8 + 2]
    aad = header_meta + name_len.to_bytes(2, 'big')

    tag = blob[-TAG_SIZE:]
    ciphertext = blob[offset:-TAG_SIZE]

    # Check expiry
    if expiry_ts > 0:
        now = int(time.time())
        if now > expiry_ts:
            raise ValueError(
                f"This file expired on {format_timestamp(expiry_ts)} "
                f"and can no longer be decrypted."
            )

    # Derive key
    if keyfile_path:
        keyfile_bytes = Path(keyfile_path).read_bytes()
        combined = password.encode('utf-8') + b'\x00' + keyfile_bytes
        key = PBKDF2(combined, salt, dkLen=KEY_SIZE,
                     count=iterations, hmac_hash_module=SHA256)
    else:
        key = PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE,
                     count=iterations, hmac_hash_module=SHA256)

    # Decrypt filename
    original_name = None
    if (flag & FLAG_NAME_ENCRYPTED) and enc_name_block:
        name_nonce = enc_name_block[:NAME_NONCE_SIZE]
        enc_name_with_tag = enc_name_block[NAME_NONCE_SIZE:]
        try:
            original_name = decrypt_filename_v2(key, name_nonce, enc_name_with_tag)
        except ValueError:
            raise ValueError("Wrong password/keyfile or corrupted file.")

    # Decrypt content
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("Wrong password or corrupted/tampered file.")

    if flag & FLAG_COMPRESSED:
        plaintext = zlib.decompress(plaintext)

    metadata = {
        'iterations': iterations,
        'compressed': bool(flag & FLAG_COMPRESSED),
        'name_encrypted': bool(flag & FLAG_NAME_ENCRYPTED),
        'created_ts': created_ts,
        'expiry_ts': expiry_ts,
        'max_attempts': max_attempts,
    }

    return plaintext, (original_name or 'decrypted_file'), metadata


# ==================== V1 DECRYPT (legacy) ====================
def extract_name_from_html_v1(html_path: str) -> str:
    """Extract the ORIGINAL_NAME from a v1 HTML file."""
    text = Path(html_path).read_text(encoding='utf-8')
    marker = 'const ORIGINAL_NAME = '
    n_start = text.index(marker) + len(marker)
    n_end = text.index(';', n_start)
    return json.loads(text[n_start:n_end].strip())


def decrypt_blob_v1(blob: bytes, password: str) -> tuple:
    """Decrypt a v1 (legacy, no magic) blob. Returns (plaintext_bytes, metadata)."""
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    flag = blob[SALT_SIZE + NONCE_SIZE]
    iterations = int.from_bytes(blob[SALT_SIZE + NONCE_SIZE + 1:SALT_SIZE + NONCE_SIZE + 5], 'big')
    header_meta = blob[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + 5]
    tag = blob[-TAG_SIZE:]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE + 5:-TAG_SIZE]

    key = PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE,
                 count=iterations, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header_meta)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("Wrong password or the file is corrupted/tampered with.")

    if flag == FLAG_COMPRESSED:
        plaintext = zlib.decompress(plaintext)

    metadata = {
        'iterations': iterations,
        'compressed': flag == FLAG_COMPRESSED,
        'name_encrypted': False,
        'created_ts': 0,
        'expiry_ts': 0,
        'max_attempts': 0,
    }

    return plaintext, metadata


# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(
        prog="secfil-decrypt",
        description="secfil - decrypt a self-decrypting HTML or armor file from the CLI. "
                    "Supports both v1 (legacy) and v2 (SCF1) formats.")
    parser.add_argument("input_file",
                        help="encrypted file (.html or .scf1 armor)")
    parser.add_argument("-o", "--output",
                        help="output path (default: original filename from the encrypted file)")
    parser.add_argument("--keyfile", metavar="PATH",
                        help="keyfile used during encryption (for two-factor auth)")
    parser.add_argument("--info", action="store_true",
                        help="show metadata about the encrypted file without decrypting")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"ERROR: File not found: {args.input_file}")
        sys.exit(1)

    # Load blob
    try:
        blob = load_blob(args.input_file)
    except (ValueError, IndexError) as e:
        print(f"ERROR: Could not load encrypted data: {e}")
        sys.exit(1)

    fmt = detect_format(blob)

    # ---- Info mode ----
    if args.info:
        print(f"File: {args.input_file}")
        print(f"Format: {'secfil v2 (SCF1)' if fmt == 'v2' else 'secfil v1 (legacy)'}")
        print(f"Blob size: {format_size(len(blob))}")

        if fmt == 'v2':
            offset = MAGIC_SIZE + SALT_SIZE + NONCE_SIZE
            flag = blob[offset]; offset += 1
            iterations = int.from_bytes(blob[offset:offset + 4], 'big'); offset += 4
            created_ts = struct.unpack('>Q', blob[offset:offset + 8])[0]; offset += 8
            expiry_ts = struct.unpack('>Q', blob[offset:offset + 8])[0]; offset += 8
            max_attempts = struct.unpack('>H', blob[offset:offset + 2])[0]; offset += 2
            name_len = struct.unpack('>H', blob[offset:offset + 2])[0]; offset += 2

            ct_size = len(blob) - offset - name_len - TAG_SIZE
            print(f"Ciphertext size: {format_size(max(0, ct_size))}")
            print(f"PBKDF2 iterations: {iterations:,}")
            print(f"Compressed: {'Yes' if flag & FLAG_COMPRESSED else 'No'}")
            print(f"Filename encrypted: {'Yes' if flag & FLAG_NAME_ENCRYPTED else 'No'}")
            print(f"Created: {format_timestamp(created_ts)}")
            print(f"Expiry: {format_timestamp(expiry_ts)}", end='')
            if expiry_ts > 0:
                remaining = expiry_ts - int(time.time())
                if remaining > 0:
                    days = remaining // 86400
                    hrs = (remaining % 86400) // 3600
                    print(f" ({days}d {hrs}h remaining)")
                else:
                    print(" (EXPIRED)")
            else:
                print()
            print(f"Max attempts: {'Unlimited' if max_attempts == 0 else str(max_attempts)}")
        else:
            offset = SALT_SIZE + NONCE_SIZE
            flag = blob[offset]; offset += 1
            iterations = int.from_bytes(blob[offset:offset + 4], 'big'); offset += 4
            ct_size = len(blob) - SALT_SIZE - NONCE_SIZE - 5 - TAG_SIZE
            print(f"Ciphertext size: {format_size(max(0, ct_size))}")
            print(f"PBKDF2 iterations: {iterations:,}")
            print(f"Compressed: {'Yes' if flag == FLAG_COMPRESSED else 'No'}")
            print(f"Filename encrypted: No (v1 format)")

        # Container type
        text = Path(args.input_file).read_text(encoding='utf-8', errors='ignore')[:200]
        if '<html' in text.lower():
            print("Container: Self-decrypting HTML")
        elif 'BEGIN SCF1 BLOB' in Path(args.input_file).read_text(encoding='utf-8', errors='ignore')[:200]:
            print("Container: ASCII-armored blob")
        else:
            print("Container: Raw blob")

        return

    # ---- Decrypt mode ----
    # Password
    try:
        password = getpass.getpass("Enter password: ")
    except Exception:
        print("WARNING: Secure password entry unavailable; input will be visible.")
        password = input("Enter password: ")
    if not password:
        print("ERROR: Password cannot be empty.")
        sys.exit(1)

    # Decrypt
    try:
        if fmt == 'v2':
            plaintext, original_name, metadata = decrypt_blob_v2(
                blob, password, args.keyfile)
        else:
            plaintext, metadata = decrypt_blob_v1(blob, password)
            # Get original name from HTML for v1
            try:
                original_name = extract_name_from_html_v1(args.input_file)
            except (ValueError, IndexError):
                original_name = 'decrypted_file'
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    # Determine output path
    output_path = args.output or original_name
    if os.path.exists(output_path):
        answer = input(f"'{output_path}' already exists. Overwrite? [y/N]: ").strip().lower()
        if answer != 'y':
            print("Aborted.")
            sys.exit(1)

    # Write
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    sha_hex = hashlib.sha256(plaintext).hexdigest()
    print(f"Decrypted: {output_path} ({format_size(len(plaintext))})")
    print(f"SHA-256:  {sha_hex}")
    print(f"Filename: {original_name}")

    if metadata.get('expiry_ts', 0) > 0:
        remaining = metadata['expiry_ts'] - int(time.time())
        if remaining > 0:
            days = remaining // 86400
            hrs = (remaining % 86400) // 3600
            print(f"Expires in: {days}d {hrs}h")


if __name__ == "__main__":
    main()
