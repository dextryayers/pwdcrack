#!/bin/bash
# ============================================================
# Download common wordlists for pwdcrack
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Downloading wordlists..."
echo "WARNING: Some files are large (>100MB)"
echo ""

download() {
    local url="$1"
    local name="$2"
    if [ ! -f "$name" ]; then
        echo "Downloading $name..."
        wget -q --show-progress "$url" -O "$name"
        echo "  Done: $(ls -lh "$name" | awk '{print $5}')"
    else
        echo "  $name already exists"
    fi
}

# Common wordlists
download "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" "rockyou.txt"
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt" "10k-most-common.txt"
download "https://raw.githubusercontent.com/praetorian/Hob0Rules/master/hob0.rule" "hob0.rule"

echo ""
echo "To use:"
echo "  pwdcrack dictionary hashes.txt rockyou.txt"
echo "  pwdcrack dictionary hashes.txt 10k-most-common.txt -r hob0.rule"
