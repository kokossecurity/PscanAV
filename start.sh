
#!/usr/bin/env bash
set -euo pipefail

echo "================================"
echo "       PscanAV Launcher"
echo "================================"

if [[ $# -ne 1 ]]; then
    echo "Usage: bash start.sh <directory>"
    exit 1
fi

if [[ ! -d "$1" ]]; then
    echo "[ERROR] Directory does not exist."
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "[ERROR] Rust/Cargo is not installed."
    exit 1
fi

TARGET_DIR="$(realpath -- "$1")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

echo "[+] Building PscanAV..."
cargo build --release

echo "[+] Launching scanner..."
exec ./target/release/pscanav "$TARGET_DIR"
