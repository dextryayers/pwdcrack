# Benchmark Reference Machine

Throughput numbers are only meaningful next to the machine that produced them.
This file records that machine. Update it whenever the reference changes, and
never compare a result against a target in `docs/plan.md` unless it was measured
here.

## How to record a run

1. Capture the machine details with `scripts/bench-reference.sh > docs/BENCH_REFERENCE.md`.
2. Record the wordlist name, size, and line count.
3. Record the hash file: total lines and the type distribution.
4. Record the exact command, the cargo features, and the profile.

## Current reference

No measurement has been recorded yet. Run `scripts/bench-reference.sh` on the
intended reference machine and commit the output here before treating any
throughput target as validated.

## Why this file exists

`docs/plan.md` Section 2.2 states throughput targets as multiples of a baseline.
A multiple without an absolute denominator is not a claim, it is a shape. This
file supplies the denominator.

## Corpus requirements

| Corpus | Requirement |
|--------|-------------|
| Wordlist | At least 1,000,000 candidates. `rockyou.txt` at 14 million is the reference. |
| Fast hash set | 10,000 raw MD5 hashes, none of which are in the wordlist. |
| Slow hash set | 100 bcrypt cost 12 hashes, to measure the memory hard path. |
| Known-plant set | 50 hashes whose plaintext is at a known position in the wordlist, to measure time-to-crack rather than raw rate. |

The planted set matters: raw hashes per second measures the verifier, but a
cracking tool is judged by how quickly it finds an answer. Report both.
