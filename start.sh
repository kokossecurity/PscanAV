
#!/usr/bin/env bash

set -eu

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================"
echo "          PscanAV"
echo "       Full System Scan"
echo "================================"

echo "[+] Building PscanAV..."

cargo build --release

echo "[+] Starting scan from /..."
exec ./target/release/pscanav /
