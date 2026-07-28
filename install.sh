#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
DATADIR="${PREFIX}/share/pwdcrack"

print_step()  { printf "${BOLD}${CYAN}[*]${NC} %s\n" "$1"; }
print_ok()    { printf "${GREEN}[✓]${NC} %s\n" "$1"; }
print_err()   { printf "${RED}[✗]${NC} %s\n" "$1"; }

# --- Detect source directory ---
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SRC_DIR"

# --- Pre-flight checks ---
print_step "Pre-flight checks"
if [ "$(id -u)" -eq 0 ]; then
    print_err "Do not run as root directly"
    echo "  The script will use sudo when needed. Run as normal user."
    exit 1
fi

# --- Find or build binary ---
BINARY=""
RELEASE_BIN="target/release/pwdcrack"
DEBUG_BIN="target/debug/pwdcrack"

if [ -f "$RELEASE_BIN" ]; then
    BINARY="$RELEASE_BIN"
    print_ok "Using pre-built release binary: $RELEASE_BIN"
elif [ -f "$DEBUG_BIN" ]; then
    BINARY="$DEBUG_BIN"
    print_ok "Using pre-built debug binary: $DEBUG_BIN"
else
    print_step "No pre-built binary found — building pwdcrack"
    if ! command -v cargo &>/dev/null; then
        print_err "cargo not found. Install Rust first:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
    cargo build --release -p pwdcrack --bin pwdcrack
    BINARY="$RELEASE_BIN"
    if [ ! -f "$BINARY" ]; then
        print_err "Build failed — binary not found"
        exit 1
    fi
    print_ok "Build complete: $BINARY"
fi

# --- Install binary (with sudo if needed) ---
print_step "Installing to ${BINDIR}"
INSTALL_CMD="install -m 755 '$BINARY' '${BINDIR}/pwdcrack'"
if mkdir -p "$BINDIR" 2>/dev/null; then
    eval "$INSTALL_CMD"
else
    print_step "Need sudo to install to ${PREFIX}"
    sudo mkdir -p "$BINDIR"
    sudo sh -c "$INSTALL_CMD"
fi
print_ok "Installed: ${BINDIR}/pwdcrack"

# --- Install test vectors ---
if [ -d "tests/test_vectors" ]; then
    print_step "Installing test vectors"
    if mkdir -p "$DATADIR" 2>/dev/null; then
        cp -r tests/test_vectors "$DATADIR/"
    else
        sudo mkdir -p "$DATADIR"
        sudo cp -r tests/test_vectors "$DATADIR/"
    fi
    print_ok "Test vectors: ${DATADIR}/test_vectors"
fi

# --- Verify ---
print_step "Verification"
if "${BINDIR}/pwdcrack" --help &>/dev/null; then
    print_ok "pwdcrack installed successfully!"
    echo ""
    echo "  ${BINDIR}/pwdcrack --help"
else
    print_err "Install verification failed"
    exit 1
fi
