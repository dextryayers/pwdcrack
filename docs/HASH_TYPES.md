# Hash type coverage

Generated against the crate as built. The authoritative source is the
`is_verifiable` override on each `HashCracker` implementation, which
`src/hash/audit.rs` enforces in tests. The numbers here come from
`pwdcrack list`, which reads the same registry rather than a hand written
table.

## The rule

A hash type is listed as supported only if `verify` actually computes that
hash. A cracker that recognises a format but cannot compute it returns `false`
for every input **and** overrides `is_verifiable` to return `false`, so the gap
is a fact the program reports rather than a silent behaviour.

The reason this matters is not a wrong digest. It is a wrong *report*. Before
this was made explicit, a detect-only type produced exactly the same output as a
correct negative result: the attack ran, finished, and reported zero cracks. The
user had no way to tell that no hashing had ever happened. An attack that never
ran and an attack that ran and found nothing are indistinguishable from the
output alone, and only one of them is a real result.

## Current state

| | Count |
|---|---|
| Types in `HashType` | 354 |
| Verifiable by this build | 140 |
| Detection only | 214 |

`pwdcrack list` prints this status per type and warns before any attack whose
target set contains a detect-only type.

## What is verifiable

Every raw digest family backed by a RustCrypto crate, plus the application and
database schemes built on them:

- MD5, MD4, SHA-1, the SHA-2 family, SHA-3, BLAKE2
- NTLM, LM
- bcrypt (`$2a$`, `$2b$`, `$2y$`)
- Argon2i, Argon2d, Argon2id
- scrypt
- The unsalted and salted application schemes that are a single digest over a
  rearranged input, such as osCommerce, Joomla, phpBB, PunBB, vBulletin and the
  MySQL and PostgreSQL family

## What is detection only, and why

Three groups.

**Unimplemented algorithms.** The named type exists in `HashType` and has a
parser, but no implementation of the digest. These are the bulk of the list and
include most of the SHA-3 candidates (BLAKE, BMW, CubeHash, Echo, Fugue, Groestl,
Hamsi, HAS-160, Luffa, Panama, RadioGatun, SHAvite, SIMD, Skein, SM3, Streebog),
the checksum and CRC variants, several network device schemes (Alcatel, Ericsson,
Huawei, Juniper, Nokia, ZTE), the cryptocurrency wallets, and the enterprise
authentication schemes (Kerberos 5, RADIUS CHAP, AF, DPAPI, BitLocker,
VeraCrypt).

**Blocked on dependencies.** bcrypt, Argon2 and scrypt are implemented, but some
named variants in the list need a primitive the current dependency set does not
provide.

**Known-broken implementation.** `MD5 Crypt` (`$1$`) is the one case where code
exists and is known to be wrong. Its `verify` returns `false` and
`is_verifiable` returns `false`, so it is listed here rather than reported as
crackable. See `docs/UNIX_CRYPT_STATUS.md` for the oracle used to prove it wrong
and what would be needed to fix it.

## Adding an implementation

1. Implement `verify` against the specification, not from a remembered vector.
   See `docs/PHASE4_STATUS.md` for how a multi-buffer MD5 kernel went wrong four
   separate times while looking correct, and how the differential test caught
   each one.
2. Produce test vectors from an independent oracle. For MD4 and the SHA-2 family
   this machine has `openssl dgst -md4 -provider legacy`. Cross check against a
   second source before committing the vectors.
3. Add the pair to `known_pairs` in `src/hash/audit.rs` so
   `verification_is_not_vacuous_for_raw_digests` covers it.
4. Remove the `is_verifiable` override.
5. Confirm `pwdcrack list` shows `yes` and that an attack against a real hash of
   that type produces a match.

Step 3 is not optional bookkeeping. Without a known digest for the type, no test
can distinguish a working implementation from a stub, which is precisely the
condition this document exists to end.

## Full list of detection-only types

| Type | Status |
|------|--------|
| `AFS` | detect only |
| `Alcatel` | detect only |
| `Aws4HmacSha256Hash` | detect only |
| `BSD Auth` | detect only |
| `BSDi Crypt` | detect only |
| `BitLocker` | detect only |
| `BitcoinHash` | detect only |
| `Blowfish OpenBSD` | detect only |
| `Bmw224Hash` | detect only |
| `Bmw256Hash` | detect only |
| `Bmw384Hash` | detect only |
| `Bmw512Hash` | detect only |
| `CakePHP` | detect only |
| `Cardano` | detect only |
| `Cisco PIX` | detect only |
| `Cisco Type 5` | detect only |
| `Cisco Type 7` | detect only |
| `CodeIgniter` | detect only |
| `CouchDB` | detect only |
| `Crc10Hash` | detect only |
| `Crc11Hash` | detect only |
| `Crc12Hash` | detect only |
| `Crc13Hash` | detect only |
| `Crc14Hash` | detect only |
| `Crc15Hash` | detect only |
| `Crc17Hash` | detect only |
| `Crc21Hash` | detect only |
| `Crc24CHash` | detect only |
| `Crc30Hash` | detect only |
| `Crc31Hash` | detect only |
| `Crc40Hash` | detect only |
| `Crc82Hash` | detect only |
| `CrcDnpHash` | detect only |
| `CrcJamHash` | detect only |
| `CubeHash224Hash` | detect only |
| `CubeHash256Hash` | detect only |
| `CubeHash384Hash` | detect only |
| `CubeHash512Hash` | detect only |
| `DES BSDi` | detect only |
| `DES Crypt` | detect only |
| `DPAPI` | detect only |
| `Dash` | detect only |
| `DigestMd5Hash` | detect only |
| `Django MD5` | detect only |
| `Django PBKDF2` | detect only |
| `Django SHA-256` | detect only |
| `Dogecoin` | detect only |
| `Drupal 8` | detect only |
| `Echo224Hash` | detect only |
| `Echo256Hash` | detect only |
| `Echo384Hash` | detect only |
| `Echo512Hash` | detect only |
| `Ecoh128Hash` | detect only |
| `Ecoh192Hash` | detect only |
| `Ecoh256Hash` | detect only |
| `Elgg` | detect only |
| `Ericsson` | detect only |
| `Ethereum Wallet` | detect only |
| `EthereumHash` | detect only |
| `FileVault` | detect only |
| `Fletcher16Hash` | detect only |
| `Fletcher32Hash` | detect only |
| `Fletcher4Hash` | detect only |
| `Fletcher8Hash` | detect only |
| `FluxBB` | detect only |
| `FreeRadiusMd5Hash` | detect only |
| `Fsb160Hash` | detect only |
| `Fsb224Hash` | detect only |
| `Fsb256Hash` | detect only |
| `Fsb384Hash` | detect only |
| `Fsb512Hash` | detect only |
| `Fugue224Hash` | detect only |
| `Fugue256Hash` | detect only |
| `Fugue384Hash` | detect only |
| `Fugue512Hash` | detect only |
| `GOST94-512` | detect only |
| `GPG` | detect only |
| `HMAC-BLAKE2b-224` | detect only |
| `HMAC-BLAKE2b-256` | detect only |
| `HMAC-BLAKE2b-384` | detect only |
| `HMAC-BLAKE2b-512` | detect only |
| `HMAC-BLAKE2s-256` | detect only |
| `HMAC-Tiger` | detect only |
| `HP Managed` | detect only |
| `Hamsi224Hash` | detect only |
| `Hamsi256Hash` | detect only |
| `Hamsi384Hash` | detect only |
| `Hamsi512Hash` | detect only |
| `Has160Hash` | detect only |
| `Haval128Hash` | detect only |
| `Haval160Hash` | detect only |
| `Haval192Hash` | detect only |
| `Haval224Hash` | detect only |
| `Haval256Hash` | detect only |
| `HmacSha1_96Hash` | detect only |
| `HmacSha256_128Hash` | detect only |
| `Huawei` | detect only |
| `IBM DB2` | detect only |
| `IScsiChapHash` | detect only |
| `Joomla MD5` | detect only |
| `Joomla SHA-256` | detect only |
| `Juniper` | detect only |
| `Kerberos 5` | detect only |
| `LM CHAPv2` | detect only |
| `LUKS` | detect only |
| `Laravel bcrypt` | detect only |
| `Linux Overflow` | detect only |
| `LitecoinHash` | detect only |
| `Lotus Notes 5` | detect only |
| `Lotus Notes` | detect only |
| `Luffa224Hash` | detect only |
| `Luffa256Hash` | detect only |
| `Luffa384Hash` | detect only |
| `Luffa512Hash` | detect only |
| `Lyra2ReHash` | detect only |
| `MD2` | detect only |
| `MD5 Crypt APR` | detect only |
| `MODX` | detect only |
| `MSSQL 2000` | detect only |
| `MSSQL 2008` | detect only |
| `MSSQL 2017` | detect only |
| `MSSQL Old` | detect only |
| `Magento` | detect only |
| `Monero` | detect only |
| `MongoDB` | detect only |
| `Moodle` | detect only |
| `MyBB 1.x` | detect only |
| `MySQL 5` | detect only |
| `MySQL 8` | detect only |
| `MySqlOld1Hash` | detect only |
| `NTLMv2` | detect only |
| `Namecoin` | detect only |
| `NeoscryptHash` | detect only |
| `Nokia` | detect only |
| `OpenVpnMd5Hash` | detect only |
| `Oracle 12c` | detect only |
| `Oracle 7` | detect only |
| `Oracle8Hash` | detect only |
| `Oracle9Hash` | detect only |
| `PGP S2K` | detect only |
| `PHP Hash` | detect only |
| `Panama128Hash` | detect only |
| `Peercoin` | detect only |
| `Polkadot` | detect only |
| `PostgreSQL SCRAM-SHA-256` | detect only |
| `PostgreSQL SCRAM` | detect only |
| `PrestaShop` | detect only |
| `Progress` | detect only |
| `PythonMd5Hash` | detect only |
| `QuarkHash` | detect only |
| `RADIUS CHAP` | detect only |
| `RabbitMqMd5Hash` | detect only |
| `RadioGatun32Hash` | detect only |
| `RadioGatun64Hash` | detect only |
| `RavenDB` | detect only |
| `RedisMd5Hash` | detect only |
| `Redis` | detect only |
| `Ripple Wallet` | detect only |
| `Ripple` | detect only |
| `SAP CODVN B` | detect only |
| `SAP CODVN F/G` | detect only |
| `SHA-256 Crypt` | detect only |
| `SKIP32` | detect only |
| `SNEFRU-128 Legacy` | detect only |
| `SNMP` | detect only |
| `ScryptJHash` | detect only |
| `ScryptNHash` | detect only |
| `Shavite3224Hash` | detect only |
| `Shavite3256Hash` | detect only |
| `Shavite3384Hash` | detect only |
| `Shavite3512Hash` | detect only |
| `Simd224Hash` | detect only |
| `Simd256Hash` | detect only |
| `Simd384Hash` | detect only |
| `Simd512Hash` | detect only |
| `Snefru-128` | detect only |
| `Snefru-256` | detect only |
| `Solana` | detect only |
| `Stellar` | detect only |
| `Sum16Hash` | detect only |
| `Sum24Hash` | detect only |
| `Sum32Hash` | detect only |
| `Sum64Hash` | detect only |
| `Sum8Hash` | detect only |
| `Sun MD5` | detect only |
| `Sybase` | detect only |
| `TYPO3` | detect only |
| `Teradata` | detect only |
| `TrueCrypt` | detect only |
| `Umbraco` | detect only |
| `Unix Old` | detect only |
| `Vanilla` | detect only |
| `VeraCrypt` | detect only |
| `WHMCS` | detect only |
| `WPA2 PMKID` | detect only |
| `Windows Hello` | detect only |
| `Woltlab` | detect only |
| `WordPress PHPass` | detect only |
| `Wpa3SaeHash` | detect only |
| `WpaPbkdf2Hash` | detect only |
| `X11Hash` | detect only |
| `X13Hash` | detect only |
| `X15Hash` | detect only |
| `X17Hash` | detect only |
| `XenForo` | detect only |
| `Xor8Hash` | detect only |
| `YescryptHash` | detect only |
| `ZTE` | detect only |
| `Zcash` | detect only |
| `Zikula` | detect only |
| `macOS PBKDF2` | detect only |
| `xxHash32` | detect only |
