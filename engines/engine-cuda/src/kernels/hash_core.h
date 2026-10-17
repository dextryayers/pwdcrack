/* Forwarding header.
 *
 * The hash core lives in engines/kernel-common/hash_core.h because the CUDA and
 * OpenCL engines must not carry two copies of the same compression functions.
 * Two copies is how they drift, and these functions are exactly where a silent
 * wrong digest hides.
 *
 * The build script adds engines/kernel-common to the include path, and
 * scripts/verify-kernels.sh does the same, so both resolve to the one file.
 * This header has no include guard of its own because the file it pulls in
 * already has one.
 */
#include "hash_core_shared.h"
