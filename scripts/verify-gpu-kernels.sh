#!/usr/bin/env bash
# Runs both kernel verification stages. Thin wrapper so CI and humans invoke the
# same thing.
#
# Stage 1 compiles engines/engine-cuda/src/kernels/hash_core.h with the system C
# compiler and checks the compression functions against RFC vectors, python
# hashlib and openssl.
#
# Stage 2 executes the actual .cu kernel bodies through a host shim, which checks
# the kernel entry points, the thread to candidate mapping, the bounds check and
# the padding path.
#
# Neither stage needs a CUDA toolkit or a GPU. Neither stage proves anything
# about real parallel execution or performance. See docs/PHASE6_STATUS.md.

set -euo pipefail
cd "$(dirname "$0")/.."
exec bash scripts/verify-kernels.sh