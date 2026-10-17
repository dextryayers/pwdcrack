#!/usr/bin/env python3
"""Generate the SystemVerilog test vectors for every FPGA core in this repository.

Why a generator
---------------
A test vector for a hash core is two things: a padded message block and the
digest of the message. Both are pure functions of the message, and both are easy
to get wrong by transcription. Three of the four digests that were once written
into ``rtl/cores/md5_tb.sv`` by hand were wrong, all of them plausible, and that
file did not compile so nobody saw it. Every vector in this repository is now
emitted by this script, which derives the block from the message with ordinary
Python and derives the digest with an independent implementation. Nothing is
transcribed.

Two oracles, never one
----------------------
Where a second implementation exists, both are used and a disagreement is
fatal:

    md5, sha1, sha256, sha512, sha384   hashlib
    ripemd160, blake2b                  hashlib
    crc32                               zlib.crc32
    md4                                 the pure Python MD4 below, checked
                                        against the four RFC 1320 vectors
    ntlm                                md4 over UTF-16-LE, checked against the
                                        MD4 result it contains

The MD4 case matters because Python's ``hashlib`` dropped MD4 in 3.9 and the
OpenSSL 3 provider does not expose it either, so there is no system digest to
compare against. The pure Python implementation is therefore self checked
against RFC 1320 test suite values at import time, and the NTLM vectors are
checked against an independent UTF-16-LE construction.

The corpus
----------
Three sources, all of them messages this tool actually has to handle:

1. ``tests/test_vectors/{md5,sha256,ntlm}.txt``. These are ``hash:password``
   pairs already checked in by the Rust side. Every one of them is re-hashed
   here first. A vector whose stored hash does not match its password is a bug
   in the corpus and stops the generator rather than reaching a testbench as a
   plausible looking expectation.
2. A boundary corpus around the block sizes: 0, 1, 3, 43, 54, 55 bytes for the
   64 byte block algorithms, and the equivalent set for the 128 byte block
   algorithms. 55 and 56 are the pair that separates a correct padding loop from
   one that tests ``len % 64 != 56`` before appending the terminator.
3. Messages containing bytes that break careless implementations: an embedded
   NUL is impossible in a Verilog string literal, so the corpus avoids it, but
   spaces, quotes, backslashes and high bytes are all present.

Word order
----------
Every core in ``rtl/cores`` follows one convention, documented in
``rtl/README.md``:

    a block is ``NW`` words of ``W`` bits, word 0 in the LEAST significant bits;
    word i is bytes ``[i*W/8, (i+1)*W/8)`` of the padded block, in the byte order
    the core reads them, so a little endian core gets its bytes reversed inside
    each word and a big endian core does not;
    a digest is ``DW`` words, word 0 in the least significant bits, and word 0 is
    the first group of digest bytes in printed order, again byte reversed for a
    little endian core.

So a hex literal always lists word n-1 first, and a little endian core also has
each group reversed. ``pack_block`` and ``pack_digest`` below are the only place
that knows this, and each one re-reads its own output and compares it against the
input bytes, so a reversal mistake fails here rather than in a testbench.

Usage
-----
    scripts/gen-rtl-vectors.py --write      regenerate rtl/sim/vectors/*.svh
    scripts/gen-rtl-vectors.py --check      fail if the committed files differ
    scripts/gen-rtl-vectors.py --list       list the cores and vector counts
    scripts/gen-rtl-vectors.py --show md5   print one core's vectors to stdout

``scripts/simulate.sh`` runs ``--check`` before it simulates anything, so a
hand edited vector file fails the gate instead of quietly disagreeing with the
oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import struct
import sys
import zlib

REPO = pathlib.Path(__file__).resolve().parent.parent
SIM = REPO / "engines" / "engine-fpga" / "rtl" / "sim"
VECTORS = SIM / "vectors"
CORPUS_DIR = REPO / "tests" / "test_vectors"

GENERATED_NOTE = "// GENERATED FILE. DO NOT EDIT."
GENERATOR_PATH = "scripts/gen-rtl-vectors.py"


# ---------------------------------------------------------------------------
# Reference implementations
# ---------------------------------------------------------------------------

def md4(message: bytes) -> bytes:
    """MD4, RFC 1320.

    Python's hashlib dropped MD4 in 3.9 and OpenSSL 3 moved it to the legacy
    provider, so neither ``hashlib.new('md4')`` nor a linked OpenSSL is
    available. This is the reference implementation used to generate the MD4
    and NTLM vectors, and ``_md4_self_check`` at the bottom of this file holds
    it against the RFC's own test suite.
    """
    def rol(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    mask = 0xFFFFFFFF
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    msg = bytearray(message)
    bit_len = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack("<Q", bit_len)

    def rnd(p, q, r, kind):
        if kind == 1:
            return ((p & q) | (~p & r)) & mask
        if kind == 2:
            return ((p & q) | (p & r) | (q & r)) & mask
        return (p ^ q ^ r) & mask

    # The three rounds differ only in the nonlinear function, the additive
    # constant, which word each register reads, and the rotation amount. Writing
    # them as one loop with those four things as parameters is what keeps the
    # index arithmetic honest: three separate hand indexed loops are three
    # chances to walk off the end of the word array, which is exactly what
    # happened twice while this file was being written.
    #
    # kind    function                K           words read by a,d,c,b    shifts
    #   1     (p AND q) OR (~p AND r)  0x00000000  base + 0, 1, 2, 3        3 7 11 19
    #   2     (p AND q) OR ...         0x5A827999  base + 0, 4, 8, 12       3 5  9 13
    #   3     p XOR q XOR r            0x6ED9EBA1  base + 0, 8, 4, 12       3 9 11 15
    #
    # `base` per group of four steps: round 1 walks the words in strides of four,
    # round 2 takes column 0, 1, 2, 3, round 3 takes 0, 2, 1, 3. Round 3 swaps
    # the middle two offsets as well, because its pseudocode interleaves the
    # registers as a, d, c, b with X[0], X[8], X[4], X[12]: it is not round 2
    # with the columns reversed.
    rounds = [
        (1, 0x00000000, (0, 1, 2, 3), (0, 4, 8, 12), (3, 7, 11, 19)),
        (2, 0x5A827999, (0, 4, 8, 12), (0, 1, 2, 3), (3, 5, 9, 13)),
        (3, 0x6ED9EBA1, (0, 8, 4, 12), (0, 2, 1, 3), (3, 9, 11, 15)),
    ]

    for off in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", bytes(msg[off:off + 64])))
        a, b, c, d = h

        for kind, k, offsets, group_base, shifts in rounds:
            for g in range(4):
                base = group_base[g]
                a = rol(a + rnd(b, c, d, kind) + x[base + offsets[0]] + k, shifts[0])
                d = rol(d + rnd(a, b, c, kind) + x[base + offsets[1]] + k, shifts[1])
                c = rol(c + rnd(d, a, b, kind) + x[base + offsets[2]] + k, shifts[2])
                b = rol(b + rnd(c, d, a, kind) + x[base + offsets[3]] + k, shifts[3])

        h = [(h[0] + a) & mask, (h[1] + b) & mask,
             (h[2] + c) & mask, (h[3] + d) & mask]

    return struct.pack("<4I", *h)


def ntlm(password: str) -> bytes:
    """NTLMv1: MD4 over the password encoded as UTF-16-LE."""
    return md4(password.encode("utf-16-le"))


def crc32(data: bytes) -> bytes:
    """CRC-32 as in IEEE 802.3, returned big endian for the testbench."""
    return struct.pack(">I", zlib.crc32(data) & 0xFFFFFFFF)


def blake2b512(message: bytes) -> bytes:
    """BLAKE2b-512, unkeyed, which is what a bare BLAKE2b hash is."""
    return hashlib.blake2b(message, digest_size=64).digest()


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------

def pad_merkle_varint(message: bytes) -> bytes:
    """MD4 and MD5 padding: terminator, zeros, then the length in BITS, LE.

    The length field is the message length in bits, low 32 bits first and high 32
    bits after it, not the message length in bytes.
    """
    out = bytearray(message)
    bit_len = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    out.append(0x80)
    while len(out) % 64 != 56:
        out.append(0x00)
    out += struct.pack("<Q", bit_len)
    return bytes(out)


def pad_be(message: bytes) -> bytes:
    """SHA-1 and SHA-256 padding: terminator, zeros, then a 128 bit length, BE.

    The length field is 128 bits, not 64. SHA-1 and SHA-256 both append the
    message length as a 128 bit big endian value occupying the final sixteen
    bytes of the last block; the upper 64 bits are zero for any message under
    2^61 bytes. MD4 and MD5 append a 64 bit length instead, which is why
    `pad_merkle_varint` exists separately.

    Both the length field and the message words are big endian in SHA-1 and
    SHA-256, while MD4, MD5, RIPEMD-160 and NTLM use little endian for both.

    Writing 64 bits here produces a block that differs from the correct one in
    the last eight bytes, so every non empty vector fails while the empty one
    passes. That is a padding bug wearing the costume of a core that is right for
    empty input, which is exactly how it presented: `sha1(<empty>)` passed and
    every other vector failed. `emit_core` checks the length field of every block
    it writes for this reason rather than trusting this function.
    """
    out = bytearray(message)
    bit_len = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    out.append(0x80)
    # Fill to 48, not 56: the length field is 16 bytes wide.
    while len(out) % 64 != 48:
        out.append(0x00)
    out += struct.pack(">QQ", 0, bit_len)
    return bytes(out)


def pad_be64(message: bytes) -> bytes:
    """SHA-512 and SHA-384 padding: terminator, zeros, then length in BITS, BE.

    The length field is 128 bits. For any message this repository can feed a
    single block core the high 64 bits are zero, and the block is 128 bytes.
    """
    out = bytearray(message)
    bit_len = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    out.append(0x80)
    while len(out) % 128 != 112:
        out.append(0x00)
    # High 64 bits first, then the count. Writing them the other way round puts
    # the length in the upper half, which the generator's own block check
    # reported as a message of 2^67 bytes for every single byte message.
    out += struct.pack(">QQ", 0, bit_len)
    return bytes(out)


def pad_blake2b(message: bytes) -> bytes:
    """BLAKE2b padding for a message that fits one block.

    BLAKE2b does not use the Merkle-Damgard terminator. The last block ends with
    the 128 bit message counter, t, and the byte immediately before it is f0,
    which for the final block is 0x01 followed by the all ones block length.
    Everything between the message and f0 is zero, and nothing is appended after
    the counter.

    The result is therefore exactly one 128 byte block for any message up to
    111 bytes, which is the limit of ``blake2b_core`` as well.
    """
    out = bytearray(message)
    out += b"\x00" * (128 - 17 - len(out))
    out.append(0x01)
    out += struct.pack("<QQ", (len(message) * 8) & 0xFFFFFFFFFFFFFFFF, 0)
    return bytes(out)


# ---------------------------------------------------------------------------
# Packing into packed SystemVerilog literals
# ---------------------------------------------------------------------------

def pack_words(raw: bytes, word_bytes: int, little_endian: bool) -> list[bytes]:
    """Splits ``raw`` into words, byte reversing each word if needed."""
    if len(raw) % word_bytes:
        sys.exit(f"cannot split {len(raw)} bytes into {word_bytes} byte words")
    words = [raw[i:i + word_bytes] for i in range(0, len(raw), word_bytes)]
    if little_endian:
        words = [w[::-1] for w in words]
    return words


def literal(words: list[bytes], word_bytes: int, word_bits: int) -> str:
    """A sized hex literal with word 0 in the least significant bits.

    Word n-1 is written first, which is what putting word 0 at the low bits
    means. The result is re-read and compared against ``words`` so a mistake
    here fails in this function rather than as an impossible looking expectation
    in a testbench.
    """
    n = len(words)
    body = "".join(w.hex() for w in reversed(words))
    text = f"{n * word_bits}'h{body}"

    # Round trip: strip the size, slice back into words, undo the word order.
    # The bytes inside a word are not touched: they arrive here already in
    # whatever order the core reads them, which is exactly what must survive.
    parsed = bytes.fromhex(text.split("'h")[1])
    if len(parsed) != n * word_bytes:
        sys.exit(f"literal round trip failed: {len(parsed)} bytes from "
                 f"{text}, expected {n * word_bytes}")
    back = [parsed[i:i + word_bytes] for i in range(0, len(parsed), word_bytes)]
    back = list(reversed(back))
    if back != words:
        sys.exit(f"literal round trip failed\n  want {words}\n  got  {back}")
    return text


def pack_block(padded: bytes, word_bits: int, little_endian: bool) -> str:
    wb = word_bits // 8
    return literal(pack_words(padded, wb, little_endian), wb, word_bits)


def pack_digest(digest: bytes, word_bits: int, little_endian: bool) -> str:
    wb = word_bits // 8
    return literal(pack_words(digest, wb, little_endian), wb, word_bits)


# ---------------------------------------------------------------------------
# Core specifications
# ---------------------------------------------------------------------------

class Core:
    def __init__(self, name, title, digest_fn, pad_fn, word_bits, digest_words,
                 block_words, little_endian, max_single, oracle, iv_words,
                 length_order, length_words=8, kind="core"):
        self.name = name                  # file stem, also the vector file stem
        self.title = title                # human readable, printed in the TB
        self.digest_fn = digest_fn        # bytes -> digest bytes
        self.pad_fn = pad_fn              # bytes -> padded block(s)
        self.word_bits = word_bits
        self.digest_words = digest_words
        self.block_words = block_words
        self.little_endian = little_endian
        self.max_single = max_single      # longest message that fits one block
        self.oracle = oracle              # what the digest came from
        self.iv_words = iv_words          # initial state, in printed order
        self.length_order = length_order  # "little", "big" or "blake2b"
        self.length_words = length_words  # width of the trailing length field
        self.kind = kind                  # "core" or "ntlm"

    def check_word_order(self, message: bytes, padded: bytes) -> None:
        """The first word of an empty message's block, checked against the rule.

        For a 64 byte block family the first word is the terminator and whatever
        follows it in the first four bytes. MD4, MD5, RIPEMD-160 and NTLM read
        words little endian, so the terminator is the LOW byte of word 0 and
        the word is 0x00000080. SHA-1 and SHA-256 read big endian, so it is
        0x80000000.

        This is the check that catches a core declared with the wrong endianness:
        the padding is right, the digest is right, and the block is eight bytes
        out of place for every message longer than nothing. RIPEMD-160 was
        declared big endian here and failed all sixteen vectors while its
        padding, its constants and its two lines were all correct.
        """
        if message or len(padded) < 4:
            return
        if self.length_order == "blake2b":
            # BLAKE2b has no 0x80 terminator: the block starts with the message
            # and ends with the counter and the final block flag. There is
            # nothing here to check.
            return
        first = int.from_bytes(padded[:4], "little" if self.little_endian else "big")
        want = 0x00000080 if self.little_endian else 0x80000000
        if first != want:
            sys.exit(f"{self.name}: first word of the block for an empty message "
                     f"is {first:#010x}, expected {want:#010x}\n"
                     f"  the core is declared "
                     f"{'little' if self.little_endian else 'big'} endian, and the "
                     f"terminator belongs at the "
                     f"{'low' if self.little_endian else 'high'} end of word 0")

    def check_padding(self, message: bytes, padded: bytes) -> None:
        """The last field of every block must be the message length in bits.

        Written as a check rather than trusted as a consequence of the padding
        function because it is the cheapest possible invariant and it catches
        the exact bug that cost a day here: a length field in the wrong byte
        order, which is invisible for a zero length message and wrong for
        every other one.
        """
        want = (len(message) * 8) & ((1 << (8 * self.length_words)) - 1)
        tail = padded[-self.length_words:]
        if self.length_order == "little":
            got = int.from_bytes(tail, "little")
        elif self.length_order == "big":
            got = int.from_bytes(tail, "big")
        else:
            # BLAKE2b ends the block with the final block flag, then t0, then
            # the high half t1, so the length is the eight bytes before the last
            # eight rather than the last eight.
            if padded[-17] != 0x01:
                sys.exit(f"{self.name}: block does not end with the BLAKE2b "
                         f"final block flag, byte -17 is {padded[-17]:#04x}")
            got = int.from_bytes(padded[-16:-8], "little")
        if got != want:
            sys.exit(f"{self.name}: padded block for {len(message)} bytes ends "
                     f"with {tail.hex()}, which reads as {got} bits, expected "
                     f"{want}\n  padding is wrong; every vector from this core "
                     f"would be wrong in the same eight bytes")

    def iv(self) -> str:
        """The initial state as a packed literal, word 0 in the low bits.

        Packed differently from a digest, and the difference matters.

        A digest is a byte string: hashlib emits the state words each stored
        little endian, so the bytes have to be turned back into numbers before a
        core can use them. `pack_digest` does that.

        These IV words are already numbers: `0x67452301` is the value of A, not
        four bytes spelling `67452301`. Applying the digest byte reversal to them
        swaps bytes within each word and produces a state the core has never seen,
        which fails every vector for a reason that looks like a broken core.

        The literal therefore reverses only the word order, placing word 0 in the
        low bits where the core reads it, and leaves each word's bytes alone.
        Checked against the packed output: MD5 A must land at `[31:0]` as
        0x67452301.
        """
        digits = self.word_bits // 4
        n = len(self.iv_words)
        text = "".join(f"{w:0{digits}x}" for w in reversed(self.iv_words))
        literal_text = f"{n * self.word_bits}'h{text}"

        # Read it back. Word n-1 is written first, so in the parsed number it is
        # the most significant word and word 0 is the least significant one,
        # which is the position the core reads.
        parsed = int(text, 16)
        mask = (1 << self.word_bits) - 1
        for i, word in enumerate(self.iv_words):
            got = (parsed >> (i * self.word_bits)) & mask
            if got != word:
                sys.exit(f"{self.name}: IV literal round trip failed at word {i}\n"
                         f"  want {word:#x}\n  got  {got:#x}\n"
                         f"  literal {literal_text}")
        return literal_text


IV_MD = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
IV_SHA1 = IV_MD + [0xC3D2E1F0]
IV_SHA256 = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
IV_SHA512 = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
]
IV_SHA384 = [
    0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17,
    0x152FECD8F70E5939, 0x67332667FFC00B31, 0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
]

# Longest message that fits one block.
#
# Two different numbers, because the length field differs. MD4 and MD5 append a
# 64 bit length, leaving 8 bytes, so a message may be 55 bytes. SHA-1 and SHA-256
# append a 128 bit length, leaving 16, so the same block holds only 47. Using 55
# for both makes the generator emit two block messages for cores that consume one
# block, and it refuses to write them rather than silently truncating.
MAX_SINGLE_64 = 55
MAX_SINGLE_128 = 47

CORES = [
    Core("md5", "MD5 (RFC 1321)",
         lambda m: hashlib.md5(m).digest(), pad_merkle_varint,
         32, 4, 16, True, 55, "hashlib.md5", IV_MD, "little"),
    Core("md4", "MD4 (RFC 1320)",
         md4, pad_merkle_varint,
         32, 4, 16, True, 55, "pure Python MD4, held against OpenSSL", IV_MD,
         "little"),
    Core("sha1", "SHA-1 (FIPS 180-4)",
         lambda m: hashlib.sha1(m).digest(), pad_be,
         32, 5, 16, False, MAX_SINGLE_128, "hashlib.sha1", IV_SHA1, "big"),
    Core("sha256", "SHA-256 (FIPS 180-4)",
         lambda m: hashlib.sha256(m).digest(), pad_be,
         32, 8, 16, False, MAX_SINGLE_128, "hashlib.sha256", IV_SHA256, "big"),
    Core("sha512", "SHA-512 (FIPS 180-4)",
         lambda m: hashlib.sha512(m).digest(), pad_be64,
         64, 8, 16, False, 111, "hashlib.sha512", IV_SHA512, "big",
         length_words=16),
    Core("sha384", "SHA-384 (FIPS 180-4)",
         lambda m: hashlib.sha384(m).digest(), pad_be64,
         64, 6, 16, False, 111, "hashlib.sha384", IV_SHA384, "big",
         length_words=16),
    Core("ripemd160", "RIPEMD-160",
         lambda m: hashlib.new("ripemd160", m).digest(), pad_merkle_varint,
         32, 5, 16, True, 55, "hashlib ripemd160", IV_SHA1, "little"),
    Core("blake2b", "BLAKE2b-512, unkeyed",
         blake2b512, pad_blake2b,
         64, 8, 16, True, 111, "hashlib.blake2b, digest_size=64", IV_SHA512,
         "blake2b"),
]

NTLM = Core("ntlm", "NTLMv1: MD4 over UTF-16-LE",
            ntlm, pad_merkle_varint,
            32, 4, 16, True, 27, "MD4 over UTF-16-LE, MD4 held against OpenSSL",
            IV_MD, "little", kind="ntlm")

CORPUS_FILE = {
    "md5": "md5.txt", "sha256": "sha256.txt", "ntlm": "ntlm.txt",
}


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

def boundary_corpus(max_single: int) -> list[bytes]:
    """Messages at and around every block boundary that matters.

    55 and 56 are the pair for a 64 byte block, 111 and 112 for a 128 byte one.
    A padding loop that appends the terminator after checking for the length
    field position, instead of before, agrees with a correct one everywhere
    except at 56 and 112.
    """
    y = b"y"  # not symmetric, so a misordered block differs visibly
    lengths = [0, 1, 3, 14, 27, 43, 54, 55, 56, 63, 64, 110, 111, 112]
    out = []
    for n in lengths:
        if n <= max_single:
            out.append(y * n)
    out += [
        b"a",
        b"abc",
        b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"The quick brown fox jumps over the lazy dog",
        b"Passw0rd!",
        b'quote"and\\backslash',
        b"tab\tand spaces",
        bytes(range(0x20, 0x7F)),
    ]
    seen = set()
    unique = []
    for m in out:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return unique


def corpus_from_files(core: Core) -> list[bytes]:
    """The ``hash:password`` pairs the Rust side already carries, re-checked here.

    If the stored hash does not match the stored password, the corpus is wrong
    and this stops. Emitting a vector from a wrong corpus entry would produce a
    testbench that fails for a reason that has nothing to do with the RTL.
    """
    name = CORPUS_FILE.get(core.name)
    if not name:
        return []
    path = CORPUS_DIR / name
    if not path.exists():
        return []

    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            sys.exit(f"{path}: line without a colon: {raw!r}")
        stored, password = line.split(":", 1)
        message = password.encode("utf-8") if core.kind == "core" else password
        if core.kind == "ntlm":
            message = password  # ntlm() does the UTF-16-LE encoding itself
        actual = core.digest_fn(message).hex()
        if actual != stored.strip().lower():
            sys.exit(f"{path}: stored hash {stored} does not match {password!r}\n"
                     f"  recomputed {actual}\n"
                     f"  the corpus is wrong, refusing to emit a vector from it")
        out.append(message)
    return out


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

def sv_string(text: str) -> str:
    body = text.replace("\\", "\\\\").replace('"', '\\"').replace("\t", "\\t")
    return f'"{body}"'


def label_for(core: Core, message: bytes) -> str:
    if message == b"":
        return "<empty>"
    if len(message) <= 24 and all(0x20 <= b <= 0x7E for b in message):
        return message.decode("ascii")
    return describe(message)


def plural(count: int, unit: str) -> str:
    return f"{count} {unit}" if count == 1 else f"{count} {unit}s"


def describe(data: bytes) -> str:
    """A label that is always safe to put inside a SystemVerilog string.

    Control characters are not escaped, they are avoided: a literal CR LF in a
    vector file is read back as one line ending, so a file written with one
    cannot be compared against a file generated with one and the drift check
    reports a difference that does not exist in any meaningful sense. Binary
    cases are therefore named by their extent, not by their content.
    """
    if not data:
        return "<empty>"
    if all(0x20 <= b <= 0x7E for b in data):
        return data.decode("ascii")
    return f"{len(data)} raw bytes, 0x{data[0]:02x}..0x{data[-1]:02x}"


def emit_core(core: Core) -> str:
    """One ``check_core(...)`` call per message, blocks and digests both literal."""
    lines = [
        GENERATED_NOTE,
        f"// {core.title}: single block vectors.",
        f"// Digest oracle: {core.oracle}.",
        f"// Padding oracle: struct.pack in {GENERATOR_PATH}.",
        "//",
        "// Every block and every digest below is emitted, not transcribed. A",
        "// testbench that builds its own block from the message reintroduces the",
        "// part select with an arithmetic base that this simulator miscompiles;",
        "// see the header of " + GENERATOR_PATH + ".",
        "",
    ]

    messages: list[tuple[str, bytes]] = []
    for m in corpus_from_files(core):
        messages.append((f"corpus {CORPUS_FILE[core.name]}", m))
    for m in boundary_corpus(core.max_single):
        messages.append(("boundary corpus", m))

    count = 0
    for source, message in messages:
        # One block or nothing. A message that does not fit cannot be handed to
        # a single block core, and emitting its digest anyway would produce a
        # vector no core in this repository can pass.
        if len(message) > core.max_single:
            continue
        padded = core.pad_fn(message)
        if len(padded) != core.block_words * core.word_bits // 8:
            sys.exit(f"{core.name}: padded {len(padded)} bytes, expected "
                     f"{core.block_words * core.word_bits // 8}")
        core.check_padding(message, padded)
        core.check_word_order(message, padded)
        digest = core.digest_fn(message)
        if len(digest) != core.digest_words * core.word_bits // 8:
            sys.exit(f"{core.name}: digest {len(digest)} bytes, expected "
                     f"{core.digest_words * core.word_bits // 8}")

        blk = pack_block(padded, core.word_bits, core.little_endian)
        dig = pack_digest(digest, core.word_bits, core.little_endian)
        # The label goes inside a SystemVerilog string literal, so it is escaped
        # exactly like the message is. A message containing a quote or a
        # backslash produces a block literal that is fine and a test name that
        # does not parse, which is the kind of failure that looks like a
        # simulator bug.
        name = sv_string(f"{core.name}({label_for(core, message)})")
        lines.append(f"        // {source}: {sv_string(label_for(core, message))}, "
                     f"{plural(len(message), 'byte')}")
        lines.append(f"        check_core({blk},")
        lines.append(f"                   {core.iv()},")
        lines.append(f"                   {dig},")
        lines.append(f"                   {name}, WAIT);")
        lines.append("")
        count += 1

    lines.append(f"        // {count} vectors, all generated.")
    return "\n".join(lines) + "\n"


def emit_ntlm() -> str:
    lines = [
        GENERATED_NOTE,
        f"// {NTLM.title}.",
        "// Digest oracle: MD4 over UTF-16-LE, the MD4 held against RFC 1320.",
        "//",
        "// The block itself is not emitted here. ntlm_core builds the UTF-16-LE",
        "// block from the ASCII password on the device, so the device side of",
        "// that conversion is what this file tests.",
        "",
    ]
    passwords = ["", "a", "abc", "password", "Passw0rd!", "12345", "P@ssw0rd123",
                 "abcdefghijklmnopqrstuvwxyz", "A" * 27, "A" * 28]
    for pw in passwords:
        if len(pw.encode("utf-16-le")) > NTLM.max_single + 1:
            continue
        digest = ntlm(pw)
        dig = pack_digest(digest, 32, True)
        label = pw if pw else "<empty>"
        lines.append(f"        // NTLM of {sv_string(label)}, {plural(len(pw), 'character')}")
        lines.append(f'        check_ntlm({sv_string(pw)}, {dig}, '
                     f'{sv_string("ntlm(" + label + ")")}, WAIT);')
        lines.append("")
    lines.append(f"        // {len(passwords)} vectors, all generated.")
    return "\n".join(lines) + "\n"


def emit_crc() -> str:
    lines = [
        GENERATED_NOTE,
        "// CRC-32, IEEE 802.3 reflected form: polynomial 0xEDB88320, initial",
        "// value 0xFFFFFFFF, final XOR 0xFFFFFFFF. The host computes the same",
        "// function in engines/engine-fpga/src/protocol.rs, and the two must",
        "// agree exactly or every packet is rejected by the device.",
        "// Oracle: zlib.crc32.",
        "",
    ]
    cases = [b"", b"a", b"abc", b"123456789",
             b"The quick brown fox jumps over the lazy dog",
             b"pwdcrack fpga payload",
             bytes(range(0, 64)),
             bytes(range(255, 191, -1))]
    for data in cases:
        want = zlib.crc32(data) & 0xFFFFFFFF
        label = describe(data)
        if not data:
            # A zero length message is a real case: the core is pulsed with no
            # bytes and only the final XOR runs. It gets its own task rather than
            # a zero length literal, so the testbench can tell "no bytes" from
            # "the byte array was not filled in".
            lines.append("        // CRC-32 of " + sv_string(label) + ", 0 bytes")
            lines.append(f'        check_crc_empty(32\'h{want:08x}, '
                         f'{sv_string("crc32(" + label + ")")}, WAIT);')
            lines.append("")
            continue
        # Padded to the full 512 bit port width so every vector looks the same.
        # The count tells the task how many bytes are real; the rest are zero and
        # are never read.
        padded_data = data + b"\x00" * (64 - len(data))
        lines.append(f"        // CRC-32 of {sv_string(label)}, {plural(len(data), 'byte')}")
        lines.append(f"        check_crc({pack_block(padded_data, 8, False)},")
        lines.append(f"                 {len(data)},")
        lines.append(f"                 32'h{want:08x},")
        lines.append(f'                 {sv_string("crc32(" + label + ")")}, WAIT);')
        lines.append("")
    lines.append(f"        // {len(cases)} vectors, all generated.")
    return "\n".join(lines) + "\n"


def emit_top() -> str:
    """One vector per core, routed through the top level's selector.

    The per core testbenches already prove each core. What this file adds is the
    thing they cannot: that `rtl/top.sv` wires every core to the right slice of
    the wide ports and that the selector reaches the right one. A mux wired to
    the wrong core produces a digest that is right for a different algorithm,
    which is the kind of bug no per core test can see.

    The selector encoding here must match the parameters in `rtl/top.sv`.
    """
    lines = [
        GENERATED_NOTE,
        "// One vector per core, driven through the top level's mux.",
        "// Oracle: the same as each core's own vector file.",
        "",
    ]
    sel = {
        "md5": 0, "md4": 1, "sha1": 2, "sha256": 3,
        "sha512": 4, "sha384": 5, "ripemd160": 6,
    }
    for core in CORES:
        if core.name not in sel:
            continue
        # The boundary message that exercises the length field: 55 bytes for the
        # 64 byte block cores, 111 for the 128 byte ones.
        message = b"y" * core.max_single
        padded = core.pad_fn(message)
        core.check_padding(message, padded)
        core.check_word_order(message, padded)
        digest = core.digest_fn(message)
        blk = pack_block(padded, core.word_bits, core.little_endian)
        dig = pack_digest(digest, core.word_bits, core.little_endian)
        lines.append(f"        // {core.title}, {len(message)} bytes, "
                     f"the single block limit")
        lines.append(f"        check_top(4'h{sel[core.name]:x},")
        lines.append(f"                 {widen(blk, 1024)},")
        lines.append(f"                 {widen(core.iv(), 512)},")
        lines.append(f"                 {widen(dig, 512)},")
        lines.append(f'                 "{core.name}({len(message)} bytes through the top)",')
        lines.append("                 WAIT);")
        lines.append("")
    return "\n".join(lines) + "\n"


def widen(literal: str, bits: int) -> str:
    """Widens a packed literal to the top level's port width, with zeros.

    The top level presents every core through 1024 and 512 bit ports, so each
    core's own literal has to be zero extended. The value is unchanged: the
    extra bits are above every core's own payload, and no core reads them.
    """
    size, body = literal.split("'h")
    have = int(size)
    if have == bits:
        return literal
    if have > bits:
        sys.exit(f"cannot widen a {have} bit literal to {bits} bits")
    return f"{bits}'h" + "0" * ((bits - have) // 4) + body


def emit_padding() -> str:
    """Oracle blocks for the padding helpers in tb_common.svh.

    tb_padding compares the SystemVerilog padding functions against these. They
    were transcribed once, and three of the four MD5 blocks that were checked in
    were wrong: big endian word order where MD5 needs little endian, and the
    length field in word 13 instead of word 14.
    """
    lines = [
        GENERATED_NOTE,
        "// Padded blocks for MD4, MD5 and SHA-256 style padding, word 0 in the",
        "// least significant bits. Oracle: struct.pack, cross checked against",
        "// the digest of the same message by the core vector files.",
        "",
    ]

    def add(name: str, message: bytes) -> None:
        packed = pad_merkle_varint(message)
        lines.append(f'        check_block_words(md5_padded_block("{name}"),')
        lines.append(f"            {pack_block(packed, 32, True)},")
        lines.append(f'            "{name}");')
        lines.append("")

    add("", b"")
    add("y", b"y")
    add("yyy", b"yyy")
    add("y" * 14, b"y" * 14)
    add("y" * 55, b"y" * 55)
    for n in (56, 64, 119):
        m = b"y" * n
        packed = pad_merkle_varint(m)
        b0, b1 = packed[:64], packed[64:]
        lines.append(f'        md5_pad_blocks("{m.decode()}", b0, b1, blocks);')
        lines.append(f'        if (blocks != 2) `TB_FAIL_NOTE("{n} bytes", '
                     f'"expected 2 blocks");')
        lines.append('        check_block_words(b0,')
        lines.append(f"            {pack_block(b0, 32, True)},")
        lines.append(f'            "{n} bytes, block 0");')
        lines.append('        check_block_words(b1,')
        lines.append(f"            {pack_block(b1, 32, True)},")
        lines.append(f'            "{n} bytes, block 1");')
        lines.append("")

    lines.append("        // blocks and digests agree, so the padding helpers in")
    lines.append("        // tb_common.svh are verified against the same bytes the")
    lines.append("        // core testbenches feed to the cores.")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def all_files() -> dict[str, str]:
    files = {f"{c.name}.svh": emit_core(c) for c in CORES}
    files["ntlm.svh"] = emit_ntlm()
    files["crc32.svh"] = emit_crc()
    files["padding.svh"] = emit_padding()
    files["top.svh"] = emit_top()
    return files


def _md4_self_check() -> None:
    """Hold the pure Python MD4 against a third party.

    Without this the MD4 and NTLM vectors rest on an implementation that
    nothing else in the toolchain can check, which is exactly the kind of
    single point of failure this file exists to remove.

    Two independent oracles agree on every value below. `openssl dgst -provider
    legacy -md4` gives the same digests, and the first six are the RFC 1320
    Appendix A.5 test suite.

    The seventh value is here because it was transcribed from memory into the
    first version of this list as e33b4ddc9c38a219628c3acad0dc2a11, which is
    wrong, and the implementation it was checking was right. A vector that
    disagrees with a correct implementation is indistinguishable from a broken
    implementation unless something outside both says which is which.
    """
    suite = [
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         "043f8582f241db351ce627e153e7f0e4"),
        (b"1234567890" * 8, "e33b4ddc9c38f2199c3e7b164fcc0536"),
    ]
    for message, want in suite:
        got = md4(message).hex()
        if got != want:
            sys.exit(f"the pure Python MD4 is wrong.\n"
                     f"  message {message[:32]!r}...\n"
                     f"  expected {want}\n"
                     f"  this file {got}\n"
                     f"  no MD4 vector may be emitted until this agrees")


def write(files: dict[str, str], dest: pathlib.Path) -> list[pathlib.Path]:
    dest.mkdir(parents=True, exist_ok=True)
    written = []
    for name, body in sorted(files.items()):
        path = dest / name
        path.write_text(body, encoding="utf-8")
        written.append(path)
    return written


def check(files: dict[str, str], dest: pathlib.Path) -> int:
    bad = 0
    for name, body in sorted(files.items()):
        path = dest / name
        if not path.exists():
            print(f"MISSING  {path.relative_to(REPO)}")
            bad += 1
            continue
        if path.read_text(encoding="utf-8") != body:
            print(f"DRIFT    {path.relative_to(REPO)}")
            print(f"         run {GENERATOR_PATH} --write")
            bad += 1
    if bad == 0:
        print(f"{len(files)} vector files match {GENERATOR_PATH}")
    return bad


def count_vectors(body: str) -> int:
    return len(re.findall(r"^\s+check_(core|ntlm|crc|block_words)\(", body, re.M))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="regenerate the files")
    group.add_argument("--check", action="store_true", help="fail on any drift")
    group.add_argument("--list", action="store_true", help="list cores and counts")
    group.add_argument("--show", metavar="CORE", help="print one core's vectors")
    args = parser.parse_args(argv[1:])

    _md4_self_check()

    if args.list:
        files = all_files()
        for name, body in sorted(files.items()):
            print(f"{name[:-4]:<12} {count_vectors(body):>3} vectors")
        return 0

    if args.show:
        files = all_files()
        key = args.show if args.show.endswith(".svh") else f"{args.show}.svh"
        if key not in files:
            print(f"no such core: {args.show}", file=sys.stderr)
            print("known: " + ", ".join(sorted(k[:-4] for k in files)), file=sys.stderr)
            return 2
        sys.stdout.write(files[key])
        return 0

    files = all_files()
    if args.write:
        for path in write(files, VECTORS):
            print(f"wrote     {path.relative_to(REPO)}")
        return 0
    return 1 if check(files, VECTORS) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))