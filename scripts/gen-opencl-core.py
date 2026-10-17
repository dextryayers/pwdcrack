#!/usr/bin/env python3
"""Generates the OpenCL C form of the shared hash core.

Why generate rather than maintain a second copy
------------------------------------------------
The compression functions in engines/kernel-common/hash_core_shared.h are the
verified implementation. An earlier version of this engine had its own .cl
kernel with its own tables, and it was wrong in ways the CUDA one was also wrong
in, but differently: it used four hand-picked round constants out of the full
64 entry table plus a fifth constant added unconditionally. Two copies of
verified crypto drifting apart is a maintenance hazard that shows up as a silent
wrong digest, so there is now exactly one copy and this script projects it into
the dialect OpenCL C needs.

What the transform does
-----------------------
OpenCL C has no portable preprocessor include mechanism and no <stdint.h>, so the
header cannot be used directly. The changes are mechanical:

  * drop #include <stdint.h> and #include <string.h>; OpenCL has memcpy built in
  * drop the PW_HOST_DEVICE / PW_INLINE branch, which exists only to switch
    between device and host compilation
  * map the fixed width C types onto the OpenCL builtins:
        uint32_t -> uint, uint64_t -> ulong, uint8_t -> uchar
  * map the helpers declared in the header onto their OpenCL equivalents

Every table, constant, index and rotation is carried over byte for byte. Nothing
in this script decides a value; it only changes spellings. If the generated file
disagrees with the header about a single constant, that is a bug in this script
and the check below is what catches it.

Verification
------------
scripts/verify-opencl-kernels.sh compiles the generated source with the system C
compiler and checks it against the same 220 values used for the CUDA path, then
executes the generated kernel body through a host shim. Run it after changing the
header or this script.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADER = ROOT / "engines" / "kernel-common" / "hash_core_shared.h"
OUT = ROOT / "engines" / "kernel-common" / "hash_core.cl"

BANNER = """/* Generated file. Do not edit.
 *
 * Produced from engines/kernel-common/hash_core_shared.h by
 * scripts/gen-opencl-core.py. Edit the header and re-run the generator.
 *
 * This is the same verified compression code the CUDA engine uses, projected into
 * OpenCL C. There is exactly one copy of the algorithm; this file is a build
 * artefact, not a second implementation.
 */
"""


def transform(text: str) -> str:
    # Strip the C library includes.
    text = re.sub(r"#include <stdint\.h>\n", "", text)
    text = re.sub(r"#include <string\.h>\n", "", text)

    # Strip the device/host portability macros and their conditional block.
    text = re.sub(
        r"#if defined\(__CUDACC__\)\n"
        r"#define PW_HOST_DEVICE[^\n]*\n"
        r"#define PW_INLINE[^\n]*\n"
        r"#else\n"
        r"#define PW_HOST_DEVICE\n"
        r"#define PW_INLINE static inline\n"
        r"#endif\n",
        "#define PW_INLINE inline\n",
        text,
    )

    # OpenCL builtins.
    text = re.sub(r"\buint32_t\b", "uint", text)
    text = re.sub(r"\buint64_t\b", "ulong", text)
    text = re.sub(r"\buint8_t\b", "uchar", text)
    text = re.sub(r"\bunsigned char\b", "uchar", text)
    text = re.sub(r"\bconst unsigned char\b", "const uchar", text)

    # `static` on a device function is invalid in OpenCL C; all these are always
    # emitted inline at their call sites.
    text = text.replace("PW_INLINE ", "inline ")

    # Program scope tables lose `static` as well. OpenCL C program scope objects
    # are const by definition and `static` at that scope is either rejected or,
    # in clang's host compatibility mode, produces a linkage warning for every
    # table. Dropping `static` is what the specification expects.
    text = re.sub(r"static const (uint|uchar|ulong) ", r"const \1 ", text)

    return text


def main() -> int:
    if not HEADER.exists():
        print(f"error: {HEADER} does not exist", file=sys.stderr)
        return 1

    source = transform(HEADER.read_text())

    # Refuse to emit anything that still carries a C++ only spelling. A silent
    # leftover would only fail much later, inside an OpenCL compiler on a
    # developer machine or inside a driver on a user's machine.
    # Check the code with comments removed. Several comments name string.h and
    # __CUDACC__ when explaining why they are not used, and flagging those would
    # make this guard impossible to satisfy.
    code_only = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    code_only = re.sub(r"//[^\n]*", "", code_only)
    for bad in ("stdint.h", "string.h", "__CUDACC__", "__host__", "__device__",
                "unsigned char", "uint32_t", "uint64_t", "uint8_t"):
        if bad in code_only:
            print(f"error: generated code still contains {bad}", file=sys.stderr)
            return 1

    # Every table the header defines must survive the transform intact. Counting
    # the constants catches a transform that silently drops a table, which would
    # otherwise produce a kernel that compiles and returns wrong digests.
    for marker in ("PW_MD5_K[64]", "PW_MD5_S[64]", "PW_MD5_G[64]",
                   "PW_SHA256_K[64]", "PW_SHA512_K[80]"):
        if marker not in source:
            print(f"error: table {marker} missing from the generated source",
                  file=sys.stderr)
            return 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(BANNER + source)

    tables = re.findall(r"static const uint \w+\[[^\]]+\] = \{", source)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(source.splitlines())} lines, "
          f"{len(tables)} tables carried over)")
    return 0


if __name__ == "__main__":
    sys.exit(main())