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
        print(f"{result.hash}:{result.password}")

    # GPU benchmark
    print(pwdcrack.benchmark("md5", backend="gpu"))
"""

try:
    from pwdcrack._native import *
except ImportError:
    # Placeholder when native module isn't built
    pass
