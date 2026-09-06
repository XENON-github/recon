#!/bin/bash

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="$(basename "$PROJECT_DIR")"

echo "[+] Building $PROJECT_NAME..."

cd "$PROJECT_DIR"

make clean
make

echo "[+] Installing recon to /usr/bin..."

sudo make install

echo "[+] Verifying installation..."

if ! command -v recon >/dev/null 2>&1; then
    echo "[-] Installation failed: recon was not found in PATH."
    exit 1
fi

echo "[+] Installed successfully:"
command -v recon

echo "[+] Removing source directory..."

cd /

rm -rf "$PROJECT_DIR"

echo "[+] Done."
echo "[+] You can now run: recon"

