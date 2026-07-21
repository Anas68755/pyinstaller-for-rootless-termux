#!/usr/bin/env python3
"""
secfil - decrypt

Decrypts a file produced by secfil.py, purely from the command line - no
browser required. Handy for Termux-to-Termux transfers where launching a
browser is inconvenient.

Usage:
    python secfil_decrypt.py secure_file.html [-o restored_name.ext]
"""

import os
import sys
import base64
import getpass
import argparse
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("❌ pycryptodome is not installed.")
    print("On Termux: pkg install clang python -y && pip install pycryptodome")
    sys.exit(1)

import zlib

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
FLAG_COMPRESSED = 1


def extract_blob_and_name(html_path: str):
    text = Path(html_path).read_text(encoding='utf-8')

    marker = 'const B64_DATA = "'
    start = text.index(marker) + len(marker)
    end = text.index('"', start)
    blob = base64.b64decode(text[start:end])

    name_marker = 'const ORIGINAL_NAME = '
    n_start = text.index(name_marker) + len(name_marker)
    n_end = text.index(';', n_start)
    # The value is a JSON-style JS string literal; safe to json-decode.
    import json
    original_name = json.loads(text[n_start:n_end].strip())

    return blob, original_name


def decrypt_blob(blob: bytes, password: str) -> bytes:
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
    return plaintext


def main():
    parser = argparse.ArgumentParser(
        prog="secfil-decrypt",
        description="secfil - decrypt a self-decrypting HTML file from the CLI.")
    parser.add_argument("html_file")
    parser.add_argument("-o", "--output", help="output path (default: original filename embedded in the file)")
    args = parser.parse_args()

    if not os.path.exists(args.html_file):
        print(f"❌ File not found: {args.html_file}")
        sys.exit(1)

    try:
        blob, original_name = extract_blob_and_name(args.html_file)
    except (ValueError, IndexError):
        print("❌ Could not find encrypted data in this HTML file. "
              "Is it one produced by secfil.py?")
        sys.exit(1)

    output_path = args.output or original_name
    if os.path.exists(output_path):
        answer = input(f"⚠️ '{output_path}' already exists. Overwrite? [y/N]: ").strip().lower()
        if answer != 'y':
            print("Aborted.")
            sys.exit(1)

    try:
        password = getpass.getpass("🔑 Enter password: ")
    except Exception:
        print("⚠️  Secure password entry unavailable; input will be visible.")
        password = input("🔑 Enter password: ")

    try:
        plaintext = decrypt_blob(blob, password)
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(1)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"✅ Decrypted and saved to: {output_path}")


if __name__ == "__main__":
    main()
