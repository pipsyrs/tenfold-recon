"""StageRunner: non-blocking subprocess streaming + cancel + event emit.

Bridge between backend (pipeline/state) and UI. No Textual import.
Designer imports StageRunner, StageResult, and the Event types from here.
"""

import time
import threading
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict

from . import pipeline, state, tagging
from .pipeline import (_augment, count_lines, STAGE_OUTPUTS, STEP_FUNCS,
                       _write_list, redact_command)
from .events import (StageStarted, OutputLine, StageProgress, StageFinished,
                     QueueProgress, Notice)

__all__ = [
    "StageRunner", "StageResult", "Cancelled", "default_emit",
    "StageStarted", "OutputLine", "StageProgress", "StageFinished",
    "QueueProgress", "Notice",
]


class Cancelled(Exception):
    """Raised inside a stage when the user cancels, to stop remaining work."""


@dataclass
class StageResult:
    stage: str
    target: str
    status: str                       # done|cancelled|error|skipped
    outputs: Dict[str, int] = field(default_factory=dict)
    command: str = ""
    duration: float = 0.0


def _iso(dt):
    return dt.isoformat(timespec="seconds")


class StageRunner:
    def __init__(self, cfg, target_dir, emit=None):
        self.cfg = cfg
        self.d = Path(target_dir)
        self.emit = emit or (lambda ev: None)
        self.target = cfg.get("target", "")
        self.cancel_event = threading.Event()
        self._proc = None
        self._commands = []
        self._tool_missing = False

    # ---- cancel ----
    def cancel(self):
        self.cancel_event.set()
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    # ---- streaming executor passed to step_* ----
    def _run(self, cmd, stage, use_header=True, max_lines=0):
        if self.cancel_event.is_set():
            raise Cancelled()
        cmd = _augment(list(cmd), use_header, self.cfg)
        cmd_str = redact_command(cmd)  # real argv executed; stored/emitted copy redacted
        self._commands.append(cmd_str)
        self.emit(StageStarted(self.target, stage, cmd_str))
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
        except FileNotFoundError:
            self._tool_missing = True
            self.emit(Notice("error", f"[!] Tool tidak ditemukan: {cmd[0]}"))
            return False, 0
        self._proc = proc
        start = time.time()
        n = 0
        last_emit = 0.0
        truncated = False
        try:
            with proc:  # ensures stdout pipe is closed on exit
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    n += 1
                    if max_lines and n == max_lines + 1:
                        truncated = True
                        self.emit(Notice("warn",
                            f"  │ ... output live dipotong di {max_lines} baris (file lengkap)"))
                    if not max_lines or n <= max_lines:
                        self.emit(OutputLine(self.target, stage, line))
                    now = time.time()
                    if now - last_emit > 0.2:
                        self.emit(StageProgress(self.target, stage, n, now - start))
                        last_emit = now
        finally:
            self._proc = None
        self.emit(StageProgress(self.target, stage, n, time.time() - start))
        if self.cancel_event.is_set():
            raise Cancelled()
        _ = truncated
        return proc.returncode == 0, n

    # ---- run one stage ----
    def run_stage(self, name, mode="rerun"):
        d = self.d
        started_dt = datetime.now()
        self._commands = []
        self._tool_missing = False

        if mode == "skip":
            outputs = {f: count_lines(d / f) for f in STAGE_OUTPUTS[name]
                       if (d / f).exists()}
            self.emit(Notice("info", f"[i] {name}: dilewati (skip, output lama dipakai)."))
            self.emit(StageFinished(self.target, name, "skipped", outputs))
            return StageResult(name, self.target, "skipped", outputs, "", 0.0)

        snapshot = {}
        if mode == "append":
            for f in STAGE_OUTPUTS[name]:
                p = d / f
                snapshot[f] = p.read_text(errors="ignore").splitlines() if p.exists() else []

        status = "done"
        try:
            STEP_FUNCS[name](self.cfg, d, self.emit, self._run)
        except Cancelled:
            status = "cancelled"
        if status != "cancelled" and self._tool_missing:
            status = "error"

        if mode == "append":
            for f, old in snapshot.items():
                if not old:
                    continue
                p = d / f
                cur = p.read_text(errors="ignore").splitlines() if p.exists() else []
                _write_list(p, old + cur)

        finished_dt = datetime.now()
        duration = (finished_dt - started_dt).total_seconds()
        outputs = {f: count_lines(d / f) for f in STAGE_OUTPUTS[name]
                   if (d / f).exists()}
        command = "; ".join(self._commands)
        tag_src = None
        if name == "katana":
            tag_src = "gf" if tagging.gf_usable(self.cfg) else "regex"

        state.record_stage(d, self.cfg, self.target, name, status, command,
                           _iso(started_dt), _iso(finished_dt), duration, tag_src)
        self.emit(StageFinished(self.target, name, status, outputs))
        return StageResult(name, self.target, status, outputs, command, duration)


# ---- default emit for headless / installer ----

def _a(text, col):
    codes = {"g": "92", "y": "93", "r": "91", "b": "94", "c": "96", "d": "90"}
    return f"\033[{codes.get(col, '0')}m{text}\033[0m"


def default_emit(ev):
    """Print events (headless/installer). UI replaces this with its own emit."""
    if isinstance(ev, StageStarted):
        print(_a(f"[>] {ev.stage}", "c"))
        print(_a(f"    $ {ev.command}", "d"))
    elif isinstance(ev, OutputLine):
        print(_a("  │ ", "d") + ev.line)
    elif isinstance(ev, StageFinished):
        print(_a(f"  └ {ev.stage}: {ev.status} · {ev.outputs}", "d"))
    elif isinstance(ev, Notice):
        col = {"ok": "g", "warn": "y", "error": "r", "info": "d"}.get(ev.level, "d")
        print(_a(ev.text, col))
    elif isinstance(ev, QueueProgress):
        print(_a(f">>> [{ev.index}/{ev.total}] {ev.target}", "c"))
    # StageProgress intentionally ignored in headless (spinner is a UI concern)
