#!/usr/bin/env python3
"""Generate test vectors for all supported hash types."""

import hashlib
import bcrypt
import argparse
from pathlib import Path

HASHES_DIR = Path(__file__).parent / "test_vectors"

PASSWORDS = [
    "hello",
    "world",
    "password",
    "12345",
    "abc123",
    "Passw0rd",
    "ILoveYou",
    "test",
    "admin",
    "letmein",
    "qwerty123",
    "monkey",
    "dragon",
    "master",
    "p@ssw0rd!",
]


def gen_md5():
    lines = []
    for pw in PASSWORDS:
        h = hashlib.md5(pw.encode()).hexdigest()
        lines.append(f"{h}:{pw}")
    (HASHES_DIR / "md5.txt").write_text("\n".join(lines) + "\n")
    print(f"MD5: {len(lines)} vectors")


def gen_sha1():
    lines = []
    for pw in PASSWORDS:
        h = hashlib.sha1(pw.encode()).hexdigest()
        lines.append(f"{h}:{pw}")
    (HASHES_DIR / "sha1.txt").write_text("\n".join(lines) + "\n")
    print(f"SHA1: {len(lines)} vectors")


def gen_sha256():
    lines = []
    for pw in PASSWORDS:
        h = hashlib.sha256(pw.encode()).hexdigest()
        lines.append(f"{h}:{pw}")
    (HASHES_DIR / "sha256.txt").write_text("\n".join(lines) + "\n")
    print(f"SHA-256: {len(lines)} vectors")


def gen_ntlm():
    """NTLM = MD4(UTF16-LE(password))"""
    lines = []
    for pw in PASSWORDS:
        utf16 = pw.encode("utf-16le")
        h = hashlib.new("md4", utf16).hexdigest()
        lines.append(f"{h}:{pw}")
    (HASHES_DIR / "ntlm.txt").write_text("\n".join(lines) + "\n")
    print(f"NTLM: {len(lines)} vectors")


def gen_bcrypt(cost=6):
    lines = []
    for pw in PASSWORDS:
        h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=cost)).decode()
        lines.append(f"{h}:{pw}")
    (HASHES_DIR / "bcrypt.txt").write_text("\n".join(lines) + "\n")
    print(f"bcrypt (cost={cost}): {len(lines)} vectors")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate test vectors")
    parser.add_argument("--cost", type=int, default=6, help="bcrypt cost")
    args = parser.parse_args()

    HASHES_DIR.mkdir(parents=True, exist_ok=True)

    gen_md5()
    gen_sha1()
    gen_sha256()
    gen_ntlm()
    gen_bcrypt(args.cost)

    print(f"\nAll vectors saved to {HASHES_DIR}")
