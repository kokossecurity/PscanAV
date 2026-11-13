
#!/usr/bin/env bash

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

echo "================================"
echo "          PscanAV"
echo "       Full Access Scan"
echo "================================"

echo "[+] Building PscanAV..."

if ! cargo build --release; then
    echo "[ERROR] Build failed."
    exit 1
fi

echo "[+] Starting full-access scan..."

exec ./target/release/pscanav /
