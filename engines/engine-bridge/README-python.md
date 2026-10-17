# pwdcrack for Python

Password hash cracking from Python, backed by the same Rust engine the CLI uses.

## Build

```sh
# From the repository root.
maturin develop --manifest-path engines/engine-bridge/python/pyproject.toml \
                --features engine-bridge/python

# Or build a wheel.
maturin build --manifest-path engines/engine-bridge/python/pyproject.toml \
              --features engine-bridge/python
```

The crate must be built with the `python` feature. `pyproject.toml` passes it
through `[tool.maturin] features`, so `maturin develop` alone is enough.

## Use

```python
from pwdcrack import Cracker

c = Cracker()
c.load_text("8350c7ecc6d4706e12107df747eb6e71\n")
c.attack_dictionary("rockyou.txt")

for r in c.results:
    print(r.hash, r.password, r.hash_type)

print(c.hashes_per_second, "H/s")
```

Two things this surface is careful about:

* `verify` raises on a hash no parser recognised rather than returning `False`.
  A `False` means "checked and it does not match"; a raised error means "not
  checked". Collapsing them is how a cracker reports a recovery that did not
  happen.
* `hashes_per_second` is `None` until an attack has run and been timed. Zero
  would read as "measured, and it was very slow".

## Types

* `Cracker` - an independent session with its own hashes and results
* `CrackedHash` - one recovered hash
* `Target` - one loaded hash and what it was recognised as
* `EngineInfo` - what the engine reports about itself

The module also keeps free functions (`detect`, `load_file`, `verify_one`, ...)
that operate on one process-wide engine. They are a different set of state from
`Cracker`; pick one and stay with it.

## Typing

The package ships `py.typed`, so type checkers use the inline annotations in
`__init__.py` rather than treating the extension as untyped.
