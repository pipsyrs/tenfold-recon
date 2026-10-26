#!/usr/bin/env python3
"""Recon Automation — interactive CLI (Rich).

A scrolling, CLI-style front-end (NOT a full-screen app): numbered menus,
rich tables/panels/rules, and an inline live run view (rich.live) that leaves
scrollback intact. Consumes the backend through the documented contract;
a fake stub (recon/_stub_backend.py) is used when real modules are absent.
"""

from __future__ import annotations

import shutil
import sys
import threading
import time
from collections import deque

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

try:
    import readchar
except ImportError:
    readchar = None

from recon.launcher import open_in_tab
try:
    from recon.exploit_hints import exploit_commands
except Exception:  # noqa: BLE001
    exploit_commands = None

# ---------- backend contract (real first, stub fallback) ----------
try:
    from recon.config import load_config, save_config
    from recon.tools import check_tools, install_tool
    from recon.pipeline import count_lines, target_dir
    from recon.runner import (Notice, OutputLine, QueueProgress, StageFinished,
                              StageProgress, StageRunner, StageStarted)
    from recon.state import apply_resume_decisions, plan_resume
    from recon.queue import TargetQueue
    from recon.export import export_json, export_markdown
    try:
        from recon.pipeline import results_rows
    except ImportError:
        from recon.state import results_rows
    try:
        from recon.tools import TOOLS, OPTIONAL_TOOLS
    except ImportError:
        TOOLS, OPTIONAL_TOOLS = ["subfinder", "httpx", "katana", "nuclei"], ["uro", "gf"]
    try:
        from recon.tools import update_nuclei_templates as _update_templates
    except ImportError:
        try:
            from recon.tools import update_templates as _update_templates
        except ImportError:
            _update_templates = None
    BACKEND = "real"
except Exception:  # noqa: BLE001 — backend not ready yet
    from recon import _stub_backend as _s
    load_config, save_config = _s.load_config, _s.save_config
    check_tools, install_tool = _s.check_tools, _s.install_tool
    count_lines, target_dir = _s.count_lines, _s.target_dir
    results_rows = _s.results_rows
    StageRunner = _s.StageRunner
    StageStarted, OutputLine, StageProgress = _s.StageStarted, _s.OutputLine, _s.StageProgress
    StageFinished, QueueProgress, Notice = _s.StageFinished, _s.QueueProgress, _s.Notice
    plan_resume, apply_resume_decisions = _s.plan_resume, _s.apply_resume_decisions
    TargetQueue = _s.TargetQueue
    export_json, export_markdown = _s.export_json, _s.export_markdown
    TOOLS, OPTIONAL_TOOLS = _s.TOOLS, _s.OPTIONAL_TOOLS
    _update_templates = getattr(_s, "update_templates", None)
    BACKEND = "stub"

console = Console()

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
# default FULL run = recon + URL cleaning/tagging only; nuclei is manual
STAGES = ["subfinder", "httpx", "katana"]
ALL_STAGES = ["subfinder", "httpx", "katana", "nuclei"]
MAX_PRINT = 200
SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
             "low": "green", "info": "cyan"}
STATUS_STYLE = {"done": "green", "partial": "yellow", "skipped": "dim",
                "cancelled": "yellow", "error": "red"}
NOTICE_STYLE = {"info": "cyan", "ok": "green", "warn": "yellow", "error": "red"}

CONFIG_FIELDS = [
    ("target", "Target", "text"),
    ("output_base", "Output path", "text"),
    ("wildcard", "Wildcard subdomain", "switch"),
    ("__headers__", "Headers", "headers"),
    ("rate_limit", "Rate limit (req/s)", "int"),
    ("threads", "Threads", "int"),
    ("katana_depth", "Katana depth", "int"),
    ("crawl_time", "Crawl time (-ct, 0=inf)", "int"),
    ("field_scope", "Field scope (-fs)", "scope"),
    ("ignore_qp", "Ignore query (-iqp)", "switch"),
    ("exclude_ext", "Exclude ext (-ef)", "text"),
    ("nuclei_severity", "Nuclei severity", "text"),
    ("proxy", "Proxy", "text"),
    ("use_gf", "Use gf tagging", "switch"),
    ("export_format", "Export format", "export"),
]


# ---------- helpers / guards ----------

def bad_target(t: str) -> bool:
    """UI-side defense-in-depth: reject traversal/injection-shaped targets."""
    s = (t or "").strip().replace("https://", "").replace("http://", "")
    if not s or s.startswith("-"):
        return True
    return ".." in s or "/" in s or "\\" in s


def split_targets(items):
    """Return (accepted, rejected) target lists."""
    good, bad = [], []
    for t in items:
        (bad if bad_target(t) else good).append(t.strip())
    return good, bad


def line_renderable(line: str):
    """Colorize severity tokens in a stream line; plain text otherwise."""
    low = line.lower()
    for sev, style in SEV_STYLE.items():
        if f"[{sev}]" in low:
            t = Text(line)
            t.highlight_words([f"[{sev}]"], style, case_sensitive=False)
            return t
    return Text(line)


def _stage_status(info) -> str:
    return info if isinstance(info, str) else (info or {}).get("status", "pending")


def _plan_stages(plan) -> dict:
    if not isinstance(plan, dict):
        return {}
    if "stages" in plan and isinstance(plan["stages"], dict):
        return plan["stages"]
    return {k: v for k, v in plan.items()
            if k not in ("fingerprint", "config_changed")}


def _notice_text(level: str, text: str) -> Text:
    return Text(f"[{level}] {text}", style=NOTICE_STYLE.get(level, "cyan"))


def select_menu(title, options, subtitle=""):
    """Arrow-key menu. options: list[(key, label)]. Returns chosen key, or None
    on ESC. Falls back to a numbered prompt when readchar/TTY is unavailable."""
    if not options:
        return None
    if readchar is None or not sys.stdin.isatty():
        for k, label in options:
            console.print(f"  [cyan]{k}[/] {label}")
        keys = [k for k, _ in options]
        return Prompt.ask("select", choices=keys, default=keys[0])

    def render(idx):
        t = Table.grid(padding=(0, 1))
        t.add_column(no_wrap=True)
        t.add_column()
        for i, (k, label) in enumerate(options):
            sel = i == idx
            style = "bold black on cyan" if sel else ""
            t.add_row(Text(f" {'›' if sel else ' '} {k} ", style=style),
                      Text(str(label), style=style))
        return Panel(t, title=title, subtitle=subtitle or "↑/↓ · Enter · Esc",
                     border_style="cyan", expand=False)

    idx = 0
    with Live(render(idx), console=console, transient=True,
              auto_refresh=False) as live:
        while True:
            key = readchar.readkey()
            if key in (readchar.key.UP, "k"):
                idx = (idx - 1) % len(options)
            elif key in (readchar.key.DOWN, "j"):
                idx = (idx + 1) % len(options)
            elif key in (readchar.key.ENTER, "\r", "\n"):
                return options[idx][0]
            elif key == readchar.key.ESC:
                return None
            else:
                for k, _ in options:  # direct hotkey
                    if key == k:
                        return k
            live.update(render(idx), refresh=True)


def confirm_menu(title, default_yes=True):
    """Yes/No via arrow-select. Falls back to Confirm when readchar/TTY absent."""
    if readchar is None or not sys.stdin.isatty():
        return Confirm.ask(title, default=default_yes)
    opts = [("y", "Yes"), ("n", "No")]
    ans = select_menu(title, opts)
    if ans is None:
        return default_yes
    return ans == "y"


def text_input(prompt, default="", is_int=False):
    """Single-line editor with cursor movement (←/→, Home/End, Backspace/Del).
    ESC returns the default. Falls back to Prompt/IntPrompt without readchar/TTY."""
    if readchar is None or not sys.stdin.isatty():
        if is_int:
            return IntPrompt.ask(prompt, default=int(default or 0))
        return Prompt.ask(prompt, default=str(default))

    buf = list(str(default))
    pos = len(buf)

    def render():
        t = Text()
        t.append(f"{prompt}: ", style="bold cyan")
        for i, ch in enumerate(buf):
            t.append(ch, style="reverse" if i == pos else "")
        t.append(" ", style="reverse" if pos >= len(buf) else "")
        return t

    with Live(render(), console=console, transient=True,
              auto_refresh=False) as live:
        while True:
            key = readchar.readkey()
            if key in (readchar.key.ENTER, "\r", "\n"):
                break
            elif key == readchar.key.ESC:
                buf = list(str(default))
                break
            elif key == readchar.key.LEFT:
                pos = max(0, pos - 1)
            elif key == readchar.key.RIGHT:
                pos = min(len(buf), pos + 1)
            elif key == readchar.key.HOME:
                pos = 0
            elif key == readchar.key.END:
                pos = len(buf)
            elif key in (readchar.key.BACKSPACE, "\x7f", "\x08"):
                if pos > 0:
                    del buf[pos - 1]
                    pos -= 1
            elif key == readchar.key.DELETE:
                if pos < len(buf):
                    del buf[pos]
            elif len(key) == 1 and key.isprintable():
                if is_int and not (key.isdigit()
                                   or (key == "-" and pos == 0 and "-" not in buf)):
                    continue
                buf.insert(pos, key)
                pos += 1
            live.update(render(), refresh=True)

    text = "".join(buf)
    if is_int:
        try:
            return int(text)
        except ValueError:
            return int(default or 0)
    return text


class _RunState:
    """Shared state between the worker thread (emit) and the live renderer."""

    def __init__(self, stage: str = ""):
        self.lock = threading.Lock()
        self.buffer = deque()      # (kind, renderable); kind in {"out","meta"}
        self.lines = 0
        self.printed = 0
        self.stage = stage
        self.start = time.time()
        self.status = "running"


# ===================== CLI =====================

class ReconCLI:
    def __init__(self, cfg):
        self.cfg = cfg
        self._cur = None  # active _RunState

    # ---- notices ----
    def notice(self, level: str, text: str) -> None:
        console.print(_notice_text(level, text))

    # ---- emit (called from worker thread) ----
    def _emit(self, ev) -> None:
        st = self._cur
        if st is None:
            return
        with st.lock:
            if isinstance(ev, StageStarted):
                st.stage, st.start, st.lines, st.printed = ev.stage, time.time(), 0, 0
                st.buffer.append(("meta", Text(f"  $ {ev.command}", style="dim")))
            elif isinstance(ev, OutputLine):
                st.lines += 1
                st.buffer.append(("out", line_renderable(ev.line)))
            elif isinstance(ev, StageProgress):
                st.lines = ev.lines
            elif isinstance(ev, StageFinished):
                st.status = ev.status
                style = STATUS_STYLE.get(ev.status, "red")
                summ = ", ".join(f"{k}:{v}" for k, v in (ev.outputs or {}).items()) or "-"
                st.buffer.append(("meta",
                                  Text(f"  └ {ev.stage}: {ev.status} ({summ})", style=style)))
            elif isinstance(ev, QueueProgress):
                st.buffer.append(("meta",
                                  Text(f"  target {ev.index}/{ev.total}: {ev.target}", style="cyan")))
            elif isinstance(ev, Notice):
                st.buffer.append(("meta", _notice_text(ev.level, ev.text)))

    # ---- live rendering ----
    def _status_render(self, st) -> Text:
        frame = SPINNER[int(time.time() * 12) % len(SPINNER)]
        with st.lock:
            el, lines, stage = time.time() - st.start, st.lines, st.stage
        return Text(f"  {frame} {stage} · {el:.0f}s · {lines} lines  (Ctrl+C to cancel)",
                    style="bold cyan")

    def _flush(self, st, printer) -> None:
        with st.lock:
            items = list(st.buffer)
            st.buffer.clear()
        for kind, r in items:
            if kind == "out":
                if st.printed < MAX_PRINT:
                    printer(r)
                elif st.printed == MAX_PRINT:
                    printer(Text(f"  … live output capped at {MAX_PRINT} lines "
                                 "(full file saved)", style="yellow"))
                st.printed += 1
            else:
                printer(r)

    def _live_run(self, worker, on_cancel) -> bool:
        """Run worker() in a thread; render inline status; return cancelled?"""
        st = self._cur
        th = threading.Thread(target=worker, daemon=True)
        th.start()
        cancelled = False
        try:
            with Live("", console=console, transient=True, refresh_per_second=12) as live:
                while th.is_alive():
                    self._flush(st, live.console.print)
                    live.update(self._status_render(st))
                    time.sleep(0.08)
                self._flush(st, live.console.print)
        except KeyboardInterrupt:
            cancelled = True
            on_cancel()
            th.join(timeout=6)
        self._flush(st, console.print)
        th.join(timeout=1)
        return cancelled

    def _pipe_worker(self, runner, stage, mode) -> None:
        try:
            try:
                runner.run_stage(stage, mode=mode)
            except TypeError:
                runner.run_stage(stage)  # backend without mode param
        except Exception as e:  # noqa: BLE001
            self._emit(Notice("error", f"{stage} failed: {e}"))

    # ---- pipeline / install runs ----
    def run_pipeline(self, targets, stages, decisions) -> None:
        total = len(targets)
        start = time.time()
        run_cancelled = False
        for idx, tg in enumerate(targets, 1):
            if run_cancelled:
                break
            console.print(Rule(f"[{idx}/{total}] {tg}", style="cyan"))
            tcfg = dict(self.cfg, target=tg)
            try:
                d = target_dir(tcfg)
            except ValueError as e:
                self.notice("error", f"invalid target '{tg}': {e}")
                continue
            runner = StageRunner(tcfg, d, self._emit)
            for k, stage in enumerate(stages, 1):
                if run_cancelled:
                    break
                self._cur = _RunState(stage)
                console.print(Text(f"── stage {k}/{len(stages)}: {stage} ──", style="blue"))
                mode = decisions.get(stage, "rerun")
                run_cancelled = self._live_run(
                    lambda r=runner, s=stage, m=mode: self._pipe_worker(r, s, m),
                    on_cancel=runner.cancel)
            if not run_cancelled:
                console.print(Text(f">>> done: {tg} → {d}", style="green"))
        if run_cancelled:
            console.print(Text("Run cancelled.", style="yellow"))
        else:
            console.print(Rule(f"complete ({time.time() - start:.0f}s)", style="green"))

    def run_install(self, names, update) -> None:
        self._cur = _RunState("install")

        def worker():
            for n in names:
                try:
                    install_tool(n, self._emit)
                except Exception as e:  # noqa: BLE001
                    self._emit(Notice("error", f"{n}: {e}"))
            if update and _update_templates:
                try:
                    _update_templates(self._emit)
                except Exception as e:  # noqa: BLE001
                    self._emit(Notice("error", f"templates: {e}"))

        console.print(Rule("install", style="cyan"))
        self._live_run(worker, on_cancel=lambda: self.notice(
            "warn", "install can't be interrupted mid-tool; stops after current tool"))

    # ---- screens ----
    def main_menu(self) -> None:
        while True:
            console.clear()  # redraw frame in place instead of appending
            self._banner()
            self._status_panel()
            self._tool_banner()
            ch = select_menu("main menu", [
                ("1", "Configuration"), ("2", "Run recon (subfinder→katana, no nuclei)"),
                ("3", "Run single step (incl. nuclei)"), ("4", "Target queue"),
                ("5", "Results / exploit"), ("6", "Install / check tools"),
                ("7", "Export summary"), ("q", "Quit")])
            if ch in (None, "q"):
                break
            if ch == "1":
                self.screen_config()
            elif ch == "2":
                self.screen_run_full()
            elif ch == "3":
                self.screen_run_step()
            elif ch == "4":
                self.screen_queue()
            elif ch == "5":
                self.screen_results()
            elif ch == "6":
                self.screen_install()
            elif ch == "7":
                self.screen_export()
            elif ch == "q":
                break
        console.print("Bye. Happy hunting (in scope!).", style="cyan")

    def _require_target(self) -> bool:
        t = self.cfg.get("target")
        if not t:
            self.notice("warn", "set a target first (Config)")
            return False
        if bad_target(t):
            self.notice("warn", f"unsafe target in config: {t}")
            return False
        return True

    def screen_config(self) -> None:
        while True:
            opts = []
            for i, (key, label, kind) in enumerate(CONFIG_FIELDS, 1):
                opts.append((str(i), f"{label:<22} {self._config_value(key, kind)}"))
            opts.append(("b", "← back"))
            ans = select_menu("configuration", opts)
            if ans in (None, "b"):
                save_config(self.cfg)
                return
            key, label, kind = CONFIG_FIELDS[int(ans) - 1]
            self._edit_field(key, label, kind)
            save_config(self.cfg)

    def _config_value(self, key, kind) -> str:
        c = self.cfg
        if kind == "headers":
            return f"{len(c.get('headers', {}))} set"
        if kind == "switch":
            return "on" if c.get(key) else "off"
        if kind == "scope":
            return c.get(key) or "default"
        return str(c.get(key, "")) or "-"

    def _edit_field(self, key, label, kind) -> None:
        c = self.cfg
        if kind == "headers":
            self.screen_headers()
        elif kind == "text":
            v = text_input(label, default=str(c.get(key, "")))
            if key == "target" and v and bad_target(v):
                self.notice("warn", f"unsafe target rejected: {v}")
                return
            c[key] = v
        elif kind == "int":
            c[key] = text_input(label, default=str(c.get(key, 0) or 0), is_int=True)
        elif kind == "switch":
            c[key] = confirm_menu(f"{label}?", default_yes=bool(c.get(key)))
        elif kind == "scope":
            v = select_menu(label, [(x, x) for x in
                                    ("default", "rdn", "fqdn", "dn")])
            if v:
                c[key] = "" if v == "default" else v
        elif kind == "export":
            v = select_menu(label, [(x, x) for x in ("both", "json", "md")])
            if v:
                c[key] = v

    def screen_headers(self) -> None:
        while True:
            console.clear()  # redraw frame in place instead of appending
            self._headers_table()
            ans = select_menu("headers", [("a", "add"), ("d", "delete"),
                                          ("b", "← back")])
            if ans in (None, "b"):
                return
            if ans == "a":
                name = text_input("header name").strip()
                if not name:
                    self.notice("warn", "name required")
                    continue
                val = text_input(f"value for {name}", default="")
                self.cfg.setdefault("headers", {})[name] = val
                save_config(self.cfg)
            elif ans == "d":
                hdrs = self.cfg.get("headers", {})
                if not hdrs:
                    self.notice("warn", "no headers to delete")
                    continue
                name = select_menu("delete which header",
                                   [(k, k) for k in hdrs] + [("__b", "← back")])
                if name and name != "__b":
                    hdrs.pop(name, None)
                    save_config(self.cfg)

    def screen_queue(self) -> None:
        raw = text_input("targets (space/comma) — blank to load a file", default="")
        if raw.strip():
            items = raw.replace(",", " ").split()
        else:
            path = text_input("file path", default="")
            if not path.strip():
                return
            try:
                with open(path, errors="ignore") as f:
                    items = [l.strip() for l in f if l.strip()]
            except OSError as e:
                self.notice("error", f"cannot read file: {e}")
                return
        good, bad = split_targets(items)
        if bad:
            self.notice("warn", "rejected (unsafe): " + ", ".join(bad[:10]))
        q = TargetQueue(good)
        good = list(q.targets)  # .targets = strings
        if not good:
            self.notice("warn", "no valid targets")
            return
        self._simple_list("queue", good)
        if not confirm_menu(f"run full pipeline on {len(good)} target(s)?"):
            return
        self.cfg["last_targets"] = good
        save_config(self.cfg)
        self.run_pipeline(good, list(STAGES), {})

    def screen_run_full(self) -> None:
        if not self._require_target():
            return
        t = self.cfg["target"]
        try:
            d = target_dir(self.cfg)
        except ValueError as e:
            self.notice("error", f"invalid target: {e}")
            return
        plan = plan_resume(self.cfg, d)
        stages_map = _plan_stages(plan)
        done = [s for s in STAGES if _stage_status(stages_map.get(s)) == "done"]
        decisions = {}
        if done:
            decisions = self._resume_prompt(plan, done)
            if decisions is None:
                return
        stages = [s for s in STAGES if decisions.get(s, "rerun") != "skip"]
        if not stages:
            self.notice("warn", "all stages skipped")
            return
        try:
            apply_resume_decisions(decisions)
        except Exception:  # noqa: BLE001
            pass
        self.run_pipeline([t], stages, decisions)

    def _resume_prompt(self, plan, done):
        if plan.get("config_changed"):
            self.notice("warn", "config changed since last run — skip may mislead")
        self.notice("info", f"existing output for: {', '.join(done)}")
        decisions = {}
        for s in done:
            d = select_menu(f"{s}: existing output — choose",
                            [("skip", "skip"), ("rerun", "rerun"),
                             ("append", "append")])
            decisions[s] = d or "skip"
        for s in STAGES:
            decisions.setdefault(s, "rerun")
        if all(decisions[s] == "skip" for s in STAGES):
            self.notice("warn", "all skipped — nothing to run")
            return None
        return decisions

    def screen_run_step(self) -> None:
        if not self._require_target():
            return
        s = select_menu("run single step",
                        [(x, x) for x in ALL_STAGES] + [("cancel", "← cancel")])
        if s in (None, "cancel"):
            return
        self.run_pipeline([self.cfg["target"]], [s], {})

    def screen_results(self) -> None:
        if not self._require_target():
            return
        try:
            d = target_dir(self.cfg)
        except ValueError as e:
            self.notice("error", f"invalid target: {e}")
            return
        rows = list(results_rows(d))
        filt, sort_key, rev = "", "file", False
        while True:
            console.clear()  # redraw frame in place instead of appending
            self._results_table(rows, filt, sort_key, rev, d)
            ans = select_menu("results", [
                ("p", "Preview a file"), ("x", "Exploit a finding"),
                ("s", f"Toggle sort (now: {sort_key})"), ("f", "Filter"),
                ("b", "← back")])
            if ans in (None, "b"):
                return
            if ans == "f":
                filt = text_input("filter substring (blank=clear)", default="")
            elif ans == "s":
                sort_key = "count" if sort_key == "file" else "file"
                rev = sort_key == "count"
            elif ans == "x":
                self._exploit_menu(rows, d)
            elif ans == "p":
                opts = [(r["file"], f'{r["file"]}  ({r.get("count") or "—"})')
                        for r in rows] + [("__b", "← back")]
                pick = select_menu("preview — pick a file", opts)
                if pick and pick != "__b":
                    self._preview(rows, pick, d)

    def _exploit_menu(self, rows, d) -> None:
        if exploit_commands is None:
            self.notice("warn", "exploit command map unavailable")
            return
        cmds = exploit_commands(self.cfg, d, redact=False)
        avail = [r for r in rows if r.get("count") and r["file"][:-4] in cmds]
        if not avail:
            self.notice("warn", "no non-empty category has exploit commands")
            return
        opts = [(r["file"], f'{r["file"]}  ({r["count"]})') for r in avail]
        pick = select_menu("exploit — pick a finding", opts + [("b", "← back")])
        if pick in (None, "b"):
            return
        hints = cmds[pick[:-4]]
        cmd_opts = [(str(i), f"{label}  ·  {cmd}")
                    for i, (label, cmd) in enumerate(hints)]
        which = select_menu(f"{pick} — opens a new tab, pre-filled (not run)",
                            cmd_opts + [("b", "← back")])
        if which in (None, "b"):
            return
        label, cmd = hints[int(which)]
        ok, how = open_in_tab(cmd, title=pick[:-4])
        if ok:
            self.notice("ok", f"opened in {how} — press Enter there to run: {label}")
        else:
            self.notice("warn", f"{how}; copy & run manually:")
            console.print(Text("  " + cmd, style="cyan"))

    def _preview(self, rows, name, d) -> None:
        row = next((r for r in rows if r.get("file") == name), None)
        if not row:
            self.notice("warn", f"no such file: {name}")
            return
        if not row.get("count"):
            self.notice("warn", f"{name}: empty / not produced")
            return
        path = row.get("path") or str(d / name)
        try:
            with open(path, errors="ignore") as f:
                content = f.read()
        except OSError as e:
            self.notice("error", str(e))
            return
        with console.pager(styles=True):
            console.print(Rule(name, style="cyan"))
            console.print(content)

    def screen_install(self) -> None:
        while True:
            console.clear()  # redraw frame in place instead of appending
            self._tool_table()
            ans = select_menu("install / check tools", [
                ("a", "install all missing"), ("o", "install one tool"),
                ("t", "update nuclei templates"), ("b", "← back")])
            if ans in (None, "b"):
                return
            if ans == "a":
                miss = self._missing()
                if not miss:
                    self.notice("ok", "nothing missing")
                else:
                    self.run_install(miss, update=True)
            elif ans == "o":
                allt = list(TOOLS) + list(OPTIONAL_TOOLS)
                name = select_menu("install which tool",
                                   [(t, t) for t in allt] + [("__b", "← cancel")])
                if name and name != "__b":
                    self.run_install([name], update=False)
            elif ans == "t":
                if not shutil.which("nuclei"):
                    self.notice("warn", "nuclei not installed")
                elif not _update_templates:
                    self.notice("warn", "template update not exposed by backend")
                else:
                    self.run_install([], update=True)

    def screen_export(self) -> None:
        if not self._require_target():
            return
        fmt = select_menu("export format", [(x, x) for x in ("both", "json", "md")])
        if fmt is None:
            return
        try:
            d = target_dir(self.cfg)
        except ValueError as e:
            self.notice("error", f"invalid target: {e}")
            return
        out = []
        try:
            if fmt in ("json", "both"):
                out.append(str(export_json(self.cfg, d)))
            if fmt in ("md", "both"):
                out.append(str(export_markdown(self.cfg, d)))
        except Exception as e:  # noqa: BLE001
            self.notice("error", f"export failed: {e}")
            return
        self.notice("ok", "exported: " + ", ".join(out))

    # ---- rendering helpers ----
    def _banner(self) -> None:
        console.print(Panel("[b]RECON AUTOMATION v2[/]\n"
                            "[dim]subfinder › httpx › katana › clean/tag  ·  "
                            "nuclei & exploit = manual (menu 5)[/]",
                            border_style="cyan", expand=False))

    def _status_panel(self) -> None:
        c = self.cfg
        mode = "wildcard" if c.get("wildcard") else "single host"
        t = Table.grid(padding=(0, 1))
        t.add_column(style="bold")
        t.add_column()
        t.add_row("Target", c.get("target") or "[dim](unset)[/]")
        t.add_row("Mode", f"{mode}   rate {c.get('rate_limit')}/s   "
                          f"threads {c.get('threads')}")
        t.add_row("Severity", str(c.get("nuclei_severity")))
        t.add_row("Headers", f"{len(c.get('headers', {}))} set   "
                            f"proxy {c.get('proxy') or '-'}")
        t.add_row("Tagging", "gf" if c.get("use_gf") else "regex-forced")
        t.add_row("Output", str(c.get("output_base")))
        console.print(Panel(t, title="status", border_style="blue",
                            subtitle=f"backend: {BACKEND}", expand=False))

    def _tool_banner(self) -> None:
        missing_req, missing_opt = check_tools()
        if missing_req:
            console.print(Text(f"[!] Missing required: {', '.join(missing_req)} "
                               "— choose 6 (Install)", style="bold red"))
        elif missing_opt:
            console.print(Text(f"[i] Optional not installed: {', '.join(missing_opt)}",
                               style="yellow"))

    def _menu(self) -> None:
        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold cyan")
        t.add_column()
        rows = [("1", "Configuration"), ("2", "Run FULL pipeline"),
                ("3", "Run single step"), ("4", "Target queue"),
                ("5", "Results"), ("6", "Install / check tools"),
                ("7", "Export summary"), ("q", "Quit")]
        for k, v in rows:
            t.add_row(k, v)
        console.print(t)

    def _config_table(self) -> None:
        c = self.cfg
        t = Table(title="Configuration", title_style="bold",
                  show_lines=False, expand=False)
        t.add_column("#", justify="right", style="cyan")
        t.add_column("Field")
        t.add_column("Value", style="green")
        for i, (key, label, kind) in enumerate(CONFIG_FIELDS, 1):
            if kind == "headers":
                val = f"{len(c.get('headers', {}))} set"
            elif kind == "switch":
                val = "on" if c.get(key) else "off"
            elif kind == "scope":
                val = c.get(key) or "default"
            else:
                val = str(c.get(key, ""))
            t.add_row(str(i), label, val or "[dim]-[/]")
        console.print(t)

    def _headers_table(self) -> None:
        t = Table(title="Headers", expand=False)
        t.add_column("Name", style="cyan")
        t.add_column("Value")
        headers = self.cfg.get("headers", {})
        if not headers:
            t.add_row("[dim](none)[/]", "")
        for k, v in headers.items():
            t.add_row(k, v)
        console.print(t)

    def _tool_table(self) -> None:
        t = Table(title="Tools", expand=False)
        t.add_column("Tool", style="cyan")
        t.add_column("Status")
        for name in list(TOOLS) + list(OPTIONAL_TOOLS) + ["go"]:
            ok = shutil.which(name) is not None
            opt = " (optional)" if name in OPTIONAL_TOOLS else ""
            t.add_row(name + opt,
                      "[green]OK[/]" if ok else "[red]MISSING[/]")
        console.print(t)

    def _missing(self):
        return [n for n in list(TOOLS) + list(OPTIONAL_TOOLS) if not shutil.which(n)]

    def _results_table(self, rows, filt, sort_key, rev, d) -> None:
        def match(r):
            if not filt:
                return True
            f = filt.lower()
            return f in str(r.get("file", "")).lower() or f in str(r.get("tag", "")).lower()

        def key(r):
            return (r.get("count", 0) or -1) if sort_key == "count" \
                else str(r.get(sort_key, ""))

        view = sorted((r for r in rows if match(r)), key=key, reverse=rev)
        t = Table(title=f"Results · {self.cfg.get('target')}",
                  caption=f"{d}  (sort:{sort_key}{' desc' if rev else ''}"
                          f"{'  filter:'+filt if filt else ''})", expand=False)
        for col in ("file", "kind", "count", "tag", "updated"):
            t.add_column(col, style="cyan" if col == "file" else None)
        for r in view:
            cnt = r.get("count", 0)
            t.add_row(r.get("file", ""), r.get("kind", ""),
                      str(cnt) if cnt else "—", r.get("tag", "") or "",
                      r.get("updated", "") or "")
        console.print(t)

    def _simple_list(self, title, items) -> None:
        t = Table(title=title, expand=False)
        t.add_column("#", justify="right", style="cyan")
        t.add_column("target")
        for i, it in enumerate(items, 1):
            t.add_row(str(i), it)
        console.print(t)


# ===================== entry =====================

def main() -> None:
    cfg = load_config()
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("recon: non-interactive terminal — run in a real TTY.")
        return
    cli = ReconCLI(cfg)
    # Own the alternate screen so frames redraw in place with no scrollback.
    try:
        if readchar is not None:
            with console.screen():
                cli.main_menu()
        else:
            cli.main_menu()  # Prompt fallback: keep normal buffer
    except KeyboardInterrupt:
        console.print("\n[!] Exit.", style="yellow")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
