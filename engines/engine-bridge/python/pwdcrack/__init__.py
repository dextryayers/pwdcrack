"""pwdcrack — Python bindings to Rust core engine.

Usage:
    import pwdcrack

    # Auto-detect hardware
    info = pwdcrack.detect()
    print(info)

    # Load hashes
    hashes = pwdcrack.load_file("hashes.txt")

    # Dictionary attack
    for result in pwdcrack.attack_dictionary("rockyou.txt"):
        print(f"{result}")

    # GPU benchmark
    print(pwdcrack.benchmark("md5"))

    # Verify one password
    if pwdcrack.verify_one("password123", hash_str):
        print("Cracked!")
"""

from pwdcrack._native import (
    detect,
    load_file,
    load_buffer,
    identify,
    attack_dictionary,
    attack_bruteforce,
    verify_one,
    found_count,
    get_result,
    benchmark,
    version,
)

__all__ = [
    "detect",
    "load_file",
    "load_buffer",
    "identify",
    "attack_dictionary",
    "attack_bruteforce",
    "verify_one",
    "found_count",
    "get_result",
    "benchmark",
    "version",
]
