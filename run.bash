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

# ---- bootstrap: pastikan python3, pip, go terpasang (sekali jalan) ----
# deteksi package manager + sudo
if   command -v apt-get >/dev/null 2>&1; then PM="apt"
elif command -v dnf     >/dev/null 2>&1; then PM="dnf"
elif command -v pacman  >/dev/null 2>&1; then PM="pacman"
elif command -v brew    >/dev/null 2>&1; then PM="brew"
else PM=""; fi
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi

pkg_install() {  # pkg_install <paket...>
    case "$PM" in
        apt)    $SUDO apt-get update -y && $SUDO apt-get install -y "$@" ;;
        dnf)    $SUDO dnf install -y "$@" ;;
        pacman) $SUDO pacman -Sy --noconfirm "$@" ;;
        brew)   brew install "$@" ;;
        *)      return 1 ;;
    esac
}

set +e
# Python3
if ! command -v python3 >/dev/null 2>&1; then
    echo "[*] Python3 belum ada, mencoba install..."
    case "$PM" in
        apt)    pkg_install python3 python3-pip python3-venv ;;
        dnf)    pkg_install python3 python3-pip ;;
        pacman) pkg_install python python-pip ;;
        brew)   pkg_install python ;;
        *)      echo "[!] Package manager tak dikenal. Install Python3 manual lalu ulangi."; exit 1 ;;
    esac
fi
# pip
if ! python3 -m pip --version >/dev/null 2>&1; then
    echo "[*] pip belum ada, mencoba install..."
    python3 -m ensurepip --upgrade >/dev/null 2>&1 || pkg_install python3-pip || pkg_install python-pip
fi
# Go (tool projectdiscovery butuh Go >= 1.21)
GO_MIN="1.21"
go_ok() {  # true bila go ada DAN versinya >= GO_MIN
    command -v go >/dev/null 2>&1 || return 1
    v=$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
    [ -n "$v" ] && [ "$(printf '%s\n%s\n' "$GO_MIN" "$v" | sort -V | head -1)" = "$GO_MIN" ]
}
install_go_tarball() {  # Go resmi terbaru dari go.dev ke /usr/local/go
    case "$(uname -m)" in
        x86_64|amd64)  arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) echo "[!] Arch tak didukung utk auto-Go: $(uname -m). Install manual: https://go.dev/dl/"; return 1 ;;
    esac
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    ver=$(curl -fsSL "https://go.dev/VERSION?m=text" 2>/dev/null | head -1); ver=${ver#go}
    [ -n "$ver" ] || ver="1.23.4"
    url="https://go.dev/dl/go${ver}.${os}-${arch}.tar.gz"
    echo "[*] Download Go ${ver} ..."
    tmp=$(mktemp -d)
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$url" -o "$tmp/go.tgz"
    else wget -qO "$tmp/go.tgz" "$url"; fi || { echo "[!] Gagal download Go"; rm -rf "$tmp"; return 1; }
    $SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf "$tmp/go.tgz"
    rm -rf "$tmp"
    export PATH="$PATH:/usr/local/go/bin"
}
if ! go_ok; then
    echo "[*] Go belum ada / terlalu lama, mencoba install..."
    case "$PM" in
        apt)    pkg_install golang-go ;;
        dnf)    pkg_install golang ;;
        pacman) pkg_install go ;;
        brew)   pkg_install go ;;
    esac
    go_ok || install_go_tarball
fi
set -e

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