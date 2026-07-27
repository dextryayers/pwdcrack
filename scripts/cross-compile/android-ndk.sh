#!/bin/bash
# ============================================================
# Setup Android NDK for cross-compilation
# ============================================================
# Run this once to configure the Android NDK environment.
# Download NDK from: https://developer.android.com/ndk/downloads

set -euo pipefail

NDK_VERSION="${1:-r26b}"
NDK_DIR="$HOME/android-ndk-$NDK_VERSION"

if [ ! -d "$NDK_DIR" ]; then
    echo "Downloading Android NDK $NDK_VERSION..."
    cd /tmp
    wget -q "https://dl.google.com/android/repository/android-ndk-$NDK_VERSION-linux.zip"
    unzip -q "android-ndk-$NDK_VERSION-linux.zip" -d "$HOME"
    rm "android-ndk-$NDK_VERSION-linux.zip"
fi

# Find toolchains
TOOLCHAIN="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64"
echo "NDK toolchain: $TOOLCHAIN"

# Create cargo config
CARGO_CONFIG="$HOME/.cargo/config.toml"
cat >> "$CARGO_CONFIG" << EOF

# Android targets
[target.aarch64-linux-android]
linker = "$TOOLCHAIN/bin/aarch64-linux-android21-clang"

[target.armv7-linux-androideabi]
linker = "$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang"

EOF

echo "Done! Android NDK configured at $NDK_DIR"
echo "To build for Android:"
echo "  cargo build --target aarch64-linux-android --features tier-mid"
