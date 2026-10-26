#!/usr/bin/env bash
# Launcher recon TUI. Pakai venv bila ada, pastikan dependency terpasang, jalankan.
set -euo pipefail

cd "$(dirname "$0")"
PY="venv/bin/python"
[ -x "$PY" ] || PY="python3"

# install dep bila readchar/rich belum ada (sekali jalan)
if ! "$PY" -c "import rich, readchar" >/dev/null 2>&1; then
    echo "[*] Installing dependencies..."
    "$PY" -m pip install -r requirements.txt --break-system-packages
fi

exec "$PY" recon.py "$@"