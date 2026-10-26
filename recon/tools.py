"""Tool presence detection + install. gf added as optional (detect + install only)."""

import sys
import shutil
import subprocess

from .events import Notice, OutputLine

TOOLS = ["subfinder", "httpx", "katana", "nuclei"]
OPTIONAL_TOOLS = ["uro", "gf"]

INSTALL_CMDS = {
    "subfinder": ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "httpx":     ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "katana":    ["go", "install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest"],
    "nuclei":    ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
    "uro":       [sys.executable, "-m", "pip", "install", "uro", "--break-system-packages"],
    "gf":        ["go", "install", "github.com/tomnomnom/gf@latest"],
}


def check_tools():
    """Return (missing_required, missing_optional)."""
    return ([t for t in TOOLS if not shutil.which(t)],
            [t for t in OPTIONAL_TOOLS if not shutil.which(t)])


def tool_status():
    """Per-tool OK/MISSING map for the install screen (incl. go)."""
    status = {t: bool(shutil.which(t)) for t in TOOLS + OPTIONAL_TOOLS}
    status["go"] = bool(shutil.which("go"))
    return status


def _emit(emit, level, text):
    if emit:
        emit(Notice(level, text))


def install_tool(name, emit=None):
    """Install one tool, streaming output via emit. Returns True if present after."""
    cmd = INSTALL_CMDS.get(name)
    if not cmd:
        return False
    if cmd[0] == "go" and not shutil.which("go"):
        _emit(emit, "error", f"'{name}' butuh Go. Install Go dulu: https://go.dev/dl/")
        return False
    _emit(emit, "info", f"[>] Install {name} ...")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except FileNotFoundError:
        _emit(emit, "error", f"Tool tidak ditemukan: {cmd[0]}")
        return False
    with proc:  # closes stdout pipe on exit
        for line in proc.stdout:
            line = line.rstrip("\n")
            if line and emit:
                emit(OutputLine("", name, line))
    ok = bool(shutil.which(name))
    if ok:
        _emit(emit, "ok", f"[+] {name} OK.")
    else:
        _emit(emit, "warn", f"[!] {name} belum terdeteksi. Cek PATH: $(go env GOPATH)/bin")
    if name == "gf":
        _emit(emit, "info", "[i] gf butuh pattern di ~/.gf (mis: git clone tomnomnom/gf, 1ndianl33t/Gf-Patterns).")
    return ok


def update_nuclei_templates(emit=None):
    """Update nuclei templates (if nuclei present). Streams via emit."""
    if not shutil.which("nuclei"):
        return False
    _emit(emit, "info", "[>] Update nuclei templates ...")
    try:
        proc = subprocess.Popen(["nuclei", "-update-templates", "-silent"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except FileNotFoundError:
        return False
    with proc:  # closes stdout pipe on exit
        for line in proc.stdout:
            line = line.rstrip("\n")
            if line and emit:
                emit(OutputLine("", "nuclei", line))
    return proc.returncode == 0
