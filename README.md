# pwdcrack

Offline password hash recovery toolkit. Detects, verifies, and cracks hashes across
the major algorithm families using CPU, GPU, FPGA, and distributed back ends.

Version: **1.2.0**

## Status

Read this before relying on any number in this file.

| Area | State |
|------|-------|
| Hash detection | Working. 348 hash types are registered for detection. |
| Hash verification | Partial. A substantial subset is implemented as real verifiers. A number of types are detection only, meaning they can be identified but not cracked. Run `pwdcrack list` to see what is supported. |
| Attacks | Dictionary, brute force mask, combinator, PRINCE, toggle case, substitution, and rules. |
| Tier builds | `tier-low` and `tier-mid` build and run. `tier-high` requires GPU engine work that is not complete. |
| Engines | SIMD detection works. GPU, CUDA, OpenCL, Metal, Vulkan, FPGA, distributed, web, and the remaining engines are incomplete or stubs. See `docs/plan.md` for the current status of each. |

The honest summary: the CPU core does real work, and several upper tiers are not
finished. Nothing in this README claims a capability that has not been verified.

## Build

```sh
cargo build --release              # default tier-auto
cargo build --release --features tier-low    # low-end and embedded targets
```

Requires a Rust toolchain with edition 2024 support (Rust 1.85 or newer).

## Usage

```sh
pwdcrack --help                    # full option list, grouped by category
pwdcrack <COMMAND> --help          # options for one command
```

### Examples

Identify what is in a hash file:

```sh
pwdcrack identify hashes.txt
pwdcrack identify hashes.txt -v    # per-hash detail
```

Hash a password to build a test hash:

```sh
pwdcrack hash mypassword -t sha256
pwdcrack hash mypassword -t ntlm
```

Verify one password against one hash:

```sh
pwdcrack verify 5d41402abc4b2a76b9719d911017c592 hello
```

Dictionary attack:

```sh
pwdcrack dictionary hashes.txt rockyou.txt
pwdcrack dictionary hashes.txt rockyou.txt -r rules/best64.rule
```

Brute force with a mask:

```sh
pwdcrack brute-force hashes.txt '?u?l?l?l?l?d?d'
pwdcrack brute-force hashes.txt '?d?d?d?d?d?d'      # 6-digit PIN
```

Combinator over two wordlists:

```sh
pwdcrack combinator hashes.txt left.txt right.txt
```

Check a hash file for malformed or duplicate entries:

```sh
pwdcrack check hashes.txt
pwdcrack check hashes.txt -v
```

Review what has already been cracked:

```sh
pwdcrack show
pwdcrack show -t                  # with hash types
pwdcrack stats                    # breakdown by type
```

## Hash file formats

One hash per line. Blank lines and lines starting with `#` are ignored.

```text
5d41402abc4b2a76b9719d911017c592            raw MD5
b1b3773a05c0ed0176787a4f1574ff0075          raw SHA-1
8846f7eaee8fb117ad06bdd830b7586c328b8b3     NTLM
$2b$12$...                                   bcrypt
$1$salt$hash                                md5crypt
$6$rounds=5000$salt$hash                    sha512crypt
admin:5d41402abc4b2a76b9719d911017c592       user:hash form
```

Unparsable lines are reported with a reason and a line number rather than being
skipped silently.

## Potfile

Cracked hashes are appended to `pwdcrack.pot` in `hash:password` form. Use
`--potfile` to change the path and `--skip-cracked` to skip entries already
present.

## Platform support

| Platform | Status |
|----------|--------|
| Linux x86-64 | Working |
| Linux aarch64 | Builds via `scripts/build-all.sh` |
| macOS | Builds; Metal engine incomplete |
| Windows | Builds; not tested here |
| Android / Termux | Partial, via `engine-android` |

## Security notice

This tool is for recovering hashes you own or are authorised to test. It performs
no network access and stores nothing outside the paths you pass on the command
line, with two exceptions you should know about:

- `--distributed` opens a TCP listener. It binds to all interfaces by default and
  has no authentication. Do not enable it on an untrusted network.
- `--gpu` and other engine flags may print device details to the log.

Treat a hash file as sensitive: it contains password material.

## Documentation

| File | Contents |
|------|----------|
| `ARCHITECTURE.md` | Design notes and project map. Some sections describe intended structure rather than current code; those are labelled. |
| `docs/plan.md` | Full upgrade plan. Phase 0 and Phase 1 are the current work items. Includes a per-item status table and acceptance gates. |
| `pwdcrack --help` | Authoritative option reference. |

## License

MIT, as declared in `Cargo.toml`. The `LICENSE` file has not been added to the
repository yet; add it before publishing.

## Attribution

Copyright (c) 2026 Hanif Abdur - AniipID
