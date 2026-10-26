"""Open an exploit command in a new terminal tab — PRE-FILLED, never executed.

Auto-detect: a tmux window when inside tmux, else a gnome-terminal tab running
the user's zsh with the command typed on the prompt (zsh `print -z`). The
command is handed over as argv/env data, never interpolated into a shell launch
string, so a crafted target/filename cannot inject a second command. Nothing
runs until the user presses Enter in the new tab.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def _in_tmux() -> bool:
    return bool(os.environ.get("TMUX")) and shutil.which("tmux") is not None


def _has_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _tmux(command: str, title: str) -> bool:
    try:
        subprocess.run(["tmux", "new-window", "-n", title or "exploit"], check=True)
        # -l: send literally, no key translation; no Enter -> command waits on prompt
        subprocess.run(["tmux", "send-keys", "-l", command], check=True)
    except Exception:
        return False
    return True


def _gnome_tab(command: str, title: str) -> bool:
    term = shutil.which("gnome-terminal")
    if not term:
        return False
    # Temp ZDOTDIR: load the real ~/.zshrc, then push the command onto the line
    # editor buffer (shown, not run). env is passed via `env KEY=VALUE` argv so
    # it survives the gnome-terminal client/server split.
    tmp = tempfile.mkdtemp(prefix="recon-prefill-")
    (Path(tmp) / ".zshrc").write_text(
        '[ -f "$HOME/.zshrc" ] && source "$HOME/.zshrc"\n'
        'print -z -- "$RECON_PREFILL"\n'
        'unset RECON_PREFILL\n'
    )
    argv = [term, "--tab", "--title", title or "exploit", "--",
            "env", f"ZDOTDIR={tmp}", f"RECON_PREFILL={command}", "zsh"]
    try:
        subprocess.Popen(argv)
    except Exception:
        return False
    return True


def open_in_tab(command: str, title: str = ""):
    """Open `command` pre-filled in a new tab. Returns (ok, how)."""
    if _in_tmux() and _tmux(command, title):
        return True, "tmux window"
    if _has_display() and _gnome_tab(command, title):
        return True, "gnome-terminal tab"
    return False, "no tmux session or GUI terminal detected"
