#!/bin/bash
# ============================================================
# Build pwdcrack for Android/Termux
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Building pwdcrack for Android ==="

# Detect NDK
NDK_DIR="${ANDROID_NDK_HOME:-$HOME/android-ndk-r26b}"
if [ ! -d "$NDK_DIR" ]; then
    echo "ERROR: Android NDK not found at $NDK_DIR"
    echo "Set ANDROID_NDK_HOME or run scripts/cross-compile/android-ndk.sh"
    exit 1
fi

TOOLCHAIN="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64"

# ARM64 (64-bit, modern phones)
echo "--- ARM64 (aarch64-linux-android) ---"
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/aarch64-linux-android21-clang" \
    cargo build --release --target aarch64-linux-android --features tier-mid

# ARM32 (32-bit, older phones)  
echo "--- ARM32 (armv7-linux-androideabi) ---"
CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang" \
    cargo build --release --target armv7-linux-androideabi --features tier-low

echo ""
echo "=== Android Build Complete ==="
echo "ARM64 binary: target/aarch64-linux-android/release/pwdcrack"
echo "ARM32 binary: target/armv7-linux-androideabi/release/pwdcrack"
echo ""
echo "To install on phone via Termux:"
echo "  scp target/aarch64-linux-android/release/pwdcrack phone:~/"
echo "  # On phone: mv pwdcrack \$PREFIX/bin/ && chmod +x \$PREFIX/bin/pwdcrack"
