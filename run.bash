#!/usr/bin/env bash
# Launcher recon TUI. Pakai venv bila ada, pastikan dependency terpasang, jalankan.
set -euo pipefail

cd "$(dirname "$0")"

# self-update: tarik versi terbaru bila ini git repo (aman bila offline / ada perubahan lokal)
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "[*] Cek update..."
    if git pull --ff-only --quiet 2>/dev/null; then
        echo "[+] Kode terbaru."
    else
        echo "[i] Update dilewati (offline / ada perubahan lokal / bukan fast-forward)."
    fi
fi

PY="venv/bin/python"
[ -x "$PY" ] || PY="python3"

# install dep bila readchar/rich belum ada (sekali jalan)
if ! "$PY" -c "import rich, readchar" >/dev/null 2>&1; then
    echo "[*] Installing dependencies..."
    "$PY" -m pip install -r requirements.txt --break-system-packages
fi

# pastikan tool recon (Go) ada; tanpa ini menu jalan tapi recon kosong
export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin"
need=0
for t in subfinder httpx katana nuclei; do command -v "$t" >/dev/null 2>&1 || need=1; done
if [ "$need" = 1 ]; then
    if ! command -v go >/dev/null 2>&1; then
        echo "[!] Go belum terpasang. Install dulu: https://go.dev/dl/  lalu jalankan ulang."
    else
        echo "[*] Installing recon tools (sekali jalan, bisa agak lama)..."
        set +e
        command -v subfinder >/dev/null 2>&1 || go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        command -v httpx     >/dev/null 2>&1 || go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        command -v katana    >/dev/null 2>&1 || go install github.com/projectdiscovery/katana/cmd/katana@latest
        command -v nuclei    >/dev/null 2>&1 || go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        export PATH="$PATH:$(go env GOPATH)/bin"
        command -v nuclei >/dev/null 2>&1 && nuclei -update-templates -silent
        set -e
    fi
fi

exec "$PY" recon.py "$@"