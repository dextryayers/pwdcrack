"""Password hash cracking from Python.

Backed by the same Rust engine the CLI uses, so a result here means what the
same hash would mean on the command line.

Two interfaces are exported:

* The `Cracker` class, which owns its own hashes and results. Use this.
* The free functions, which share one process wide engine. They predate the
  class and are kept because scripts use them.

They hold different state. A hash loaded through the free functions is not
visible to a `Cracker`, and the reverse is also true.
"""

from __future__ import annotations

from ._native import (
    CrackedHash,
    Cracker,
    EngineInfo,
    Target,
    __version__,
    attack_bruteforce,
    attack_combinator,
    attack_dictionary,
    benchmark,
    detect,
    found_count,
    get_all_results,
    get_result,
    identify,
    load_buffer,
    load_file,
    rule_apply,
    suggest_attack,
    verify_batch,
    verify_one,
    version,
)

__all__ = [
    # Classes
    "Cracker",
    "CrackedHash",
    "Target",
    "EngineInfo",
    # Free functions
    "detect",
    "load_file",
    "load_buffer",
    "identify",
    "verify_one",
    "verify_batch",
    "attack_dictionary",
    "attack_bruteforce",
    "attack_combinator",
    "found_count",
    "get_result",
    "get_all_results",
    "benchmark",
    "suggest_attack",
    "rule_apply",
    "version",
    "__version__",
]
