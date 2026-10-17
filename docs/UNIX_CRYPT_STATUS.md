# Phase 1 Status: Unix Crypt (`$1$`, `$5$`, `$6$`)

Status as of the first Phase 1 pass.

## Summary

| Item | State |
|------|-------|
| Infinite loop (`wrapping_sub`) in all three algorithms | **Fixed** |
| Out of bounds panic in md5crypt tail | **Fixed** (no longer panics) |
| md5crypt (`$1$`) correctness | **Not working.** `verify` returns `false` on purpose. |
| sha256crypt (`$5$`) correctness | **Not verified.** The tail encoder had a byte-role bug; fix applied but not yet confirmed against openssl. |
| sha512crypt (`$6$`) correctness | **Not verified.** Same situation as sha256crypt. |

## Oracle available on this machine

`openssl` and `libcrypt.so.1` both provide a trustworthy `$1$`/`$5$`/`$6$` oracle and
agree with each other:

```sh
openssl passwd -1 -salt abcdefgh password   # $1$abcdefgh$G//4keteveJp0qb8z2DxG/
openssl passwd -5 -salt abcdefgh password   # $5$...
openssl passwd -6 -salt abcdefgh password   # $6$...
```

Use these as the differential test source for the rewrite. Do not trust any
vector recalled from memory: the published value remembered during this pass
turned out to be wrong, and only the local oracle was reliable.

## Defect 1: non terminating loop (fixed)

All three algorithms walked a length counter with `wrapping_sub`:

```rust
let mut i = password.len();
while i > 0 {
    ctx.update(&final1[..i.min(BLOCK)]);
    i = i.wrapping_sub(BLOCK);   // wraps for len % BLOCK != 0
}
```

For a key whose length was not a multiple of the block size the counter wrapped
to near `usize::MAX`, so the loop never returned. `md5crypt`, `sha256crypt`, and
`sha512crypt` verification hung for essentially any non-empty password.

Replaced with an equivalent that cannot wrap:

```rust
for i in (1..=password.len()).rev().step_by(BLOCK) {
    ctx.update(&digest[..i.min(BLOCK)]);
}
```

This is provably correct and matches the reference loop
`for (i = strlen(key); i; i -= 16)`.

## Defect 2: md5crypt tail was always out of bounds

The md5crypt tail indexed a 16 byte MD5 digest as if it were 32 bytes:

```rust
results.push((final_bytes[0] as u64) | ((final_bytes[10] as u64) << 8)
           | ((final_bytes[20] as u64) << 16) | ((final_bytes[30] as u64) << 24));
```

`final_bytes[20]` and `final_bytes[30]` do not exist for MD5. Every call panicked
with `index out of bounds: the len is 16 but the index is 30`. This path never
produced a correct hash for any input.

Reconstructing the correct 22 character tail from the algorithm description did
not converge: the resulting final digest differed from the oracle in every byte
position, not only in the tail ordering, which places the discrepancy in the core
digest computation rather than the base64 step.

`Md5Crypt::verify` now returns `false` with a comment explaining why. Returning
`false` is deliberate. A wrong hash here produces either a missed crack or, worse,
a false positive in a tool whose entire purpose is to report correct results.

## Defect 3: SHA-256 tail byte roles swapped

`encode_sha256_crypt` built each 24 bit group as:

```rust
d[a] | (d[b] << 8) | (d[c] << 16)
```

The specification macro is `b64_from_24bit(B2, B1, B0, N)` forming
`w = (B2 << 16) | (B1 << 8) | B0`, so the byte roles are reversed relative to the
code. The index triples were correct; only the shift direction was wrong. A fix
is drafted but is **not yet verified** against openssl. Confirm before trusting.

## Next steps

1. Rewrite `Md5Crypt::crypt_raw` against the verified oracle, testing password
   lengths 0 through 80 to cover every block boundary.
2. Apply and verify the same correction to `encode_sha512_crypt`, whose group
   order for `$6$` steps by 21 rather than 10.
3. Add a differential test that generates expected values with `openssl passwd`
   at test time and skips cleanly when openssl is absent, rather than hardcoding
   vectors that can drift.
4. Only then re-enable `verify` for each of the three types.

## Note on the FIPS test vectors embedded in the spec

The Drepper specification includes SHA-256 and SHA-512 crypt vectors that were
read during this pass. They are the right oracle for `$5$` and `$6$` and should
be used in preference to generated values where the salt and rounds match:

| Salt | Password | Expected |
|------|----------|----------|
| `$5$saltstring` | `Hello world!` | `$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5` |
| `$6$saltstring` | `Hello world!` | `$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1` |
