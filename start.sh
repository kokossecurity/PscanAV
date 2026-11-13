
#!/usr/bin/env bash
set -euo pipefail

echo "================================"
echo "       PscanAV Launcher"
echo "================================"

if ! command -v cargo >/dev/null 2>&1; then
    echo "[ERROR] Rust/Cargo is not installed."
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGETS=(
    "$HOME"
    "$PREFIX"
)

# Include shared Android storage when accessible.
if [[ -d "$HOME/storage/shared" ]]; then
    TARGETS+=("$HOME/storage/shared")
else
    echo "[!] Shared storage unavailable."
    echo "[!] Run termux-setup-storage to request access."
fi

echo "[+] Building PscanAV..."
cargo build --release

echo "[+] Launching scanner..."
exec ./target/release/pscanav "${TARGETS[@]}"
