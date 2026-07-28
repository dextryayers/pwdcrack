"""
pwdcrack — high-performance hash cracker with GPU/FPGA/CLI support.

Python API providing full access to pwdcrack's hash detection,
verification, and cracking capabilities.

Usage:
    import pwdcrack
    info = pwdcrack.detect()
    results = pwdcrack.attack_dictionary("hashes.txt", "wordlist.txt")
    for r in results:
        print(f"{r['hash']}:{r['password']}")
"""

from pwdcrack._native import (
    detect, load_file, load_buffer, identify,
    attack_dictionary, attack_bruteforce, attack_combinator,
    verify_one, verify_batch, found_count, get_result, get_all_results,
    benchmark, version, suggest_attack, rule_apply,
)

__all__ = [
    'detect', 'load_file', 'load_buffer', 'identify',
    'attack_dictionary', 'attack_bruteforce', 'attack_combinator',
    'verify_one', 'verify_batch',
    'found_count', 'get_result', 'get_all_results',
    'benchmark', 'version', 'suggest_attack', 'rule_apply',
]
