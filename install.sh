#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
DATADIR="${PREFIX}/share/pwdcrack"

print_step() { printf "\r${BOLD}${CYAN}[*]${NC} %s\n" "$1"; }
print_ok()   { printf "\r${GREEN}[✓]${NC} %s\n" "$1"; }
print_err()  { printf "\r${RED}[✗]${NC} %s\n" "$1"; }
print_info() { printf "  ${YELLOW}%s${NC}\n" "$1"; }

# ── Spinner ──────────────────────────────────────────────────────────
spin() {
  local pid=$1 msg=$2
  local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${BOLD}${CYAN}[${spin:$((i%${#spin})):1}]${NC} %s ..." "$msg"
    i=$((i+1))
    sleep 0.1
  done
  printf "\r${BOLD}${CYAN}[${GREEN}✓${CYAN}]${NC} %s ... ${GREEN}done${NC}\n" "$msg"
}

run_with_spinner() {
  local msg=$1; shift
  ("$@" &>/tmp/pwdcrack_install.log) &
  local pid=$!
  spin "$pid" "$msg"
  wait "$pid" || {
    printf "\r${RED}[✗]${NC} %s ... ${RED}failed${NC}\n" "$msg"
    cat /tmp/pwdcrack_install.log 2>/dev/null | tail -5
    exit 1
  }
}

# ── Detect source ────────────────────────────────────────────────────
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SRC_DIR"

# ── Header ───────────────────────────────────────────────────────────
printf "\n${BOLD}╔══════════════════════════════════╗${NC}\n"
printf "${BOLD}║    ${GREEN}pwdcrack installer${CYAN} v0.1.0${BOLD}    ║${NC}\n"
printf "${BOLD}╚══════════════════════════════════╝${NC}\n\n"

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

# ── 1. Find or build binary ─────────────────────────────────────────
print_step "Binary"
BINARY=""
RELEASE_BIN="target/release/pwdcrack"
DEBUG_BIN="target/debug/pwdcrack"

if [ -f "$RELEASE_BIN" ]; then
  BINARY="$RELEASE_BIN"
  print_ok "Using pre-built release binary"
elif [ -f "$DEBUG_BIN" ]; then
  BINARY="$DEBUG_BIN"
  print_ok "Using pre-built debug binary"
else
  if ! command -v cargo &>/dev/null; then
    print_err "cargo not found. Install Rust first:"
    print_info "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
  fi
  run_with_spinner "Building pwdcrack (release)" cargo build --release -p pwdcrack --bin pwdcrack
  BINARY="$RELEASE_BIN"
  [ -f "$BINARY" ] || { print_err "Build failed"; exit 1; }
fi

# ── File size ────────────────────────────────────────────────────────
SIZE=$(stat --format=%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY" 2>/dev/null || true)
if [ -n "$SIZE" ] && [ "$SIZE" -gt 0 ] 2>/dev/null; then
  if [ "$SIZE" -ge 1048576 ]; then
    printf "  ${YELLOW}size: %d MB${NC}\n" "$((SIZE / 1048576))"
  elif [ "$SIZE" -ge 1024 ]; then
    printf "  ${YELLOW}size: %d KB${NC}\n" "$((SIZE / 1024))"
  else
    printf "  ${YELLOW}size: %d B${NC}\n" "$SIZE"
  fi
fi

# ── 2. Install binary ────────────────────────────────────────────────
print_step "Installing"
if [ "$IS_ROOT" -eq 1 ]; then
  mkdir -p "$BINDIR"
  install -m 755 "$BINARY" "${BINDIR}/pwdcrack"
else
  if mkdir -p "$BINDIR" 2>/dev/null; then
    install -m 755 "$BINARY" "${BINDIR}/pwdcrack"
  else
    print_info "sudo required for ${PREFIX}"
    sudo mkdir -p "$BINDIR"
    sudo install -m 755 "$BINARY" "${BINDIR}/pwdcrack"
  fi
fi
print_ok "${BINDIR}/pwdcrack"

# ── 3. Install test vectors ──────────────────────────────────────────
if [ -d "tests/test_vectors" ]; then
  print_step "Test vectors"
  if [ "$IS_ROOT" -eq 1 ]; then
    mkdir -p "$DATADIR"
    cp -r tests/test_vectors "$DATADIR/"
  elif mkdir -p "$DATADIR" 2>/dev/null; then
    cp -r tests/test_vectors "$DATADIR/"
  else
    sudo mkdir -p "$DATADIR"
    sudo cp -r tests/test_vectors "$DATADIR/"
  fi
  print_ok "${DATADIR}/test_vectors"
fi

# ── 4. Verify ────────────────────────────────────────────────────────
print_step "Verification"
if "${BINDIR}/pwdcrack" --help &>/dev/null; then
  print_ok "Installation successful!"
  echo ""
  printf "  ${GREEN}${BOLD}➜${NC}  ${BINDIR}/pwdcrack --help\n"
  printf "  ${GREEN}${BOLD}➜${NC}  pwdcrack identify --file <hashfile>\n"
  echo ""
else
  print_err "Verification failed"
  exit 1
fi
