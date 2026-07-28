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
  ("$@" &>/tmp/pwdcrack_uninstall.log) &
  local pid=$!
  spin "$pid" "$msg"
  wait "$pid" || true
}

# ── Header ───────────────────────────────────────────────────────────
printf "\n${BOLD}╔══════════════════════════════════╗${NC}\n"
printf "${BOLD}║    ${RED}pwdcrack uninstaller${CYAN} v0.1.0${BOLD}   ║${NC}\n"
printf "${BOLD}╚══════════════════════════════════╝${NC}\n\n"

# ── Root / sudo ──────────────────────────────────────────────────────
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

NEED_SUDO=0
if [ "$IS_ROOT" -eq 0 ]; then
  if ! mkdir -p "$BINDIR" 2>/dev/null; then
    NEED_SUDO=1
  fi
fi

if [ "$NEED_SUDO" -eq 1 ]; then
  if command -v sudo &>/dev/null; then
    print_info "sudo required for ${PREFIX}"
    exec sudo bash "$0" "$@"
    exit 0
  else
    print_err "Need root but sudo not available"
    print_info "Run with sudo or set PREFIX to a writable directory"
    print_info "  PREFIX=\$HOME/.local $0"
    exit 1
  fi
fi

# ── Remove files ─────────────────────────────────────────────────────
REMOVED=0

remove_item() {
  local path=$1 label=$2
  if [ -f "$path" ] || [ -d "$path" ]; then
    run_with_spinner "Removing ${label}" rm -rf "$path"
    REMOVED=$((REMOVED+1))
  fi
}

print_step "Scanning installed files"

remove_item "${BINDIR}/pwdcrack" "binary"
remove_item "${DATADIR}"          "shared data"
remove_item "${PREFIX}/share/man/man1/pwdcrack.1" "man page"
remove_item "/etc/profile.d/pwdcrack.sh"          "profile script"
remove_item "${PREFIX}/share/bash-completion/completions/pwdcrack" "completions"

# ── Result ───────────────────────────────────────────────────────────
echo ""
if [ "$REMOVED" -gt 0 ]; then
  printf "  ${GREEN}${BOLD}✔${NC} ${REMOVED} file(s) removed.\n"
  printf "  ${YELLOW}ℹ${NC}  Source directory is kept:\n"
  printf "     %s\n" "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  print_err "Nothing to remove at ${PREFIX}"
  print_info "Was it installed with a different PREFIX?"
  print_info "Try: PREFIX=/usr $0"
  print_info "Try: PREFIX=\$HOME/.local $0"
fi
echo ""
