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
MANDIR="${PREFIX}/share/man/man1"
PROFILE_DIR="/etc/profile.d"
COMPLETION_DIR="${PREFIX}/share/bash-completion/completions"

print_step()  { printf "${BOLD}${CYAN}[*]${NC} %s\n" "$1"; }
print_ok()    { printf "${GREEN}[✓]${NC} %s\n" "$1"; }
print_err()   { printf "${RED}[✗]${NC} %s\n" "$1"; }

NEED_SUDO=0
if [ ! -w "$PREFIX" ] && [ "$PREFIX" != "/usr/local" ]; then
    NEED_SUDO=1
elif [ "$PREFIX" = "/usr/local" ] && [ ! -w "/usr/local" ]; then
    NEED_SUDO=1
fi

if [ "$NEED_SUDO" -eq 1 ]; then
    if command -v sudo &>/dev/null; then
        exec sudo bash "$0" "$@"
        exit 0
    else
        print_err "Need root but sudo not available"
        echo "  Run with sudo or set PREFIX to a writable directory"
        exit 1
    fi
fi

REMOVED=0

remove_if_exists() {
    if [ -f "$1" ] || [ -d "$1" ]; then
        rm -rf "$1"
        print_ok "Removed: $1"
        REMOVED=$((REMOVED + 1))
    fi
}

print_step "Uninstalling pwdcrack"

remove_if_exists "${BINDIR}/pwdcrack"
remove_if_exists "${DATADIR}"
remove_if_exists "${MANDIR}/pwdcrack.1"
remove_if_exists "${PROFILE_DIR}/pwdcrack.sh"
remove_if_exists "${COMPLETION_DIR}/pwdcrack"

if [ "$REMOVED" -eq 0 ]; then
    print_err "pwdcrack not found in ${PREFIX} — nothing to remove"
    echo "  Was it installed with a different PREFIX?"
    echo "  Try: PREFIX=/usr ./uninstall.sh"
    echo "  Try: PREFIX=$HOME/.local ./uninstall.sh"
else
    echo ""
    printf "${GREEN}${BOLD}✔ Uninstall complete!${NC}  ${REMOVED} file(s) removed.\n"
fi
