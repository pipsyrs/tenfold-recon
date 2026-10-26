"""FAKE backend stub — UI dev only.

Implements the documented designer<->backend contract (architecture doc 6)
so recon/app.py runs standalone before the real backend modules land.
Every symbol here mirrors a real backend signature; when the real
recon/{runner,config,tools,pipeline,state,queue,export}.py drop in, app.py
imports those instead and this file is unused. DO NOT ship as backend.
"""

from __future__ import annotations

import json
import random
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

CONFIG_FILE = Path.home() / ".recon_automation.json"

# mirrors config.DEFAULT_CONFIG + new keys (doc 5)
DEFAULT_CONFIG = {
    "target": "",
    "output_base": str(Path(__file__).resolve().parent.parent / "targets"),
    "wildcard": True,
    "headers": {},
    "rate_limit": 20,
    "threads": 40,
    "katana_depth": 2,
    "crawl_time": 180,
    "field_scope": "fqdn",
    "ignore_qp": False,
    "exclude_ext": "png,jpg,jpeg,gif,svg,css,woff,woff2,ico,ttf,eot,mp4,webp",
    "nuclei_severity": "medium,high,critical",
    "proxy": "",
    # new keys
    "use_gf": True,
    "export_format": "both",
    "last_targets": [],
}

TOOLS = ["subfinder", "httpx", "katana", "nuclei"]
OPTIONAL_TOOLS = ["uro", "gf"]

PIPELINE_FILES = [
    "subs.txt", "live.txt", "urls_raw.txt", "urls.txt", "endpoints.txt",
    "params.txt", "sqli-idor.txt", "xss.txt", "ssrf-lfi.txt", "js.txt",
    "host-findings.txt", "url-findings.txt",
]

_KIND = {
    "subs.txt": "subdomains", "live.txt": "hosts",
    "urls.txt": "urls", "urls_raw.txt": "urls", "endpoints.txt": "endpoints",
    "params.txt": "params", "js.txt": "urls",
    "sqli-idor.txt": "tagged", "xss.txt": "tagged", "ssrf-lfi.txt": "tagged",
    "host-findings.txt": "findings", "url-findings.txt": "findings",
}
_TAG = {"sqli-idor.txt": "sqli/idor", "xss.txt": "xss", "ssrf-lfi.txt": "ssrf/lfi"}


# ---------- Event types (doc 6) ----------

@dataclass
class StageStarted:
    target: str
    stage: str
    command: str


@dataclass
class OutputLine:
    target: str
    stage: str
    line: str


@dataclass
class StageProgress:
    target: str
    stage: str
    lines: int
    elapsed_sec: float


@dataclass
class StageFinished:
    target: str
    stage: str
    status: str                 # done|partial|cancelled|error
    outputs: dict               # {file: count}


@dataclass
class QueueProgress:
    index: int
    total: int
    target: str


@dataclass
class Notice:
    level: str                  # info|warning|error|success
    text: str


@dataclass
class StageResult:
    status: str
    outputs: dict = field(default_factory=dict)
    command: str = ""
    duration: float = 0.0


# ---------- config.py ----------

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text())}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ---------- tools.py ----------

def check_tools():
    return ([t for t in TOOLS if not shutil.which(t)],
            [t for t in OPTIONAL_TOOLS if not shutil.which(t)])


def install_tool(name: str, emit) -> bool:
    """Fake install with streamed output through emit."""
    emit(StageStarted("", name, f"go install … {name}@latest"))
    start = time.time()
    for i, msg in enumerate([f"fetching {name}", "building", "linking", "done"]):
        time.sleep(0.25)
        emit(OutputLine("", name, f"  {msg}"))
        emit(StageProgress("", name, i + 1, time.time() - start))
    ok = shutil.which(name) is not None
    emit(StageFinished("", name, "done" if ok else "error",
                       {"installed": 1 if ok else 0}))
    emit(Notice("success" if ok else "warning",
                f"{name}: {'OK' if ok else 'not detected (check $GOPATH/bin, stub)'}"))
    return ok


# ---------- pipeline.py ----------

def target_dir(cfg: dict) -> Path:
    t = cfg["target"].replace("https://", "").replace("http://", "")
    d = Path(cfg["output_base"]) / t
    d.mkdir(parents=True, exist_ok=True)
    return d


def count_lines(path) -> int:
    p = Path(path)
    if not p.exists():
        return 0
    with open(p, errors="ignore") as f:
        return sum(1 for _ in f)


def results_rows(target_dir) -> list:
    d = Path(target_dir)
    rows = []
    for name in PIPELINE_FILES:
        p = d / name
        n = count_lines(p)
        updated = (datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                   if p.exists() else "")
        rows.append({
            "file": name,
            "kind": _KIND.get(name, "urls"),
            "count": n,
            "tag": _TAG.get(name, ""),
            "updated": updated,
            "path": str(p),
        })
    return rows


# ---------- state.py ----------

def plan_resume(cfg: dict, target_dir) -> dict:
    """Stage done if its key output already exists non-empty."""
    d = Path(target_dir)
    key = {"subfinder": "subs.txt", "httpx": "live.txt",
           "katana": "urls_raw.txt", "nuclei": "host-findings.txt"}
    stages = {}
    for stage, out in key.items():
        done = count_lines(d / out) > 0
        stages[stage] = {
            "status": "done" if done else "pending",
            "outputs": {out: count_lines(d / out)} if done else {},
        }
    return {"fingerprint": "sha1:stub", "config_changed": False, "stages": stages}


def apply_resume_decisions(decisions: dict) -> list:
    """Return ordered stages to run (skip excluded). Append/re-run handled by backend state."""
    order = ["subfinder", "httpx", "katana", "nuclei"]
    return [s for s in order if decisions.get(s, "rerun") != "skip"]


# ---------- queue.py ----------

class TargetQueue:
    def __init__(self, targets):
        self.targets = [t.strip() for t in targets if t and t.strip()]

    def __iter__(self):
        return iter(self.targets)

    def __len__(self):
        return len(self.targets)


# ---------- export.py ----------

def export_json(cfg: dict, target_dir) -> Path:
    d = Path(target_dir)
    counts = {f.replace(".txt", ""): count_lines(d / f) for f in PIPELINE_FILES}
    data = {
        "schema": 1, "target": cfg.get("target", ""),
        "generated": datetime.now().isoformat(timespec="seconds"),
        "config": {k: cfg.get(k) for k in
                   ("rate_limit", "threads", "katana_depth", "nuclei_severity", "wildcard")},
        "counts": counts,
        "tagging": "gf" if cfg.get("use_gf") and shutil.which("gf") else "regex",
    }
    out = d / "recon-summary.json"
    out.write_text(json.dumps(data, indent=2))
    return out


def export_markdown(cfg: dict, target_dir) -> Path:
    d = Path(target_dir)
    lines = [f"# Recon summary — {cfg.get('target','')}",
             f"_generated {datetime.now():%Y-%m-%d %H:%M}_", "",
             "| file | count |", "|---|---|"]
    for f in PIPELINE_FILES:
        lines.append(f"| {f} | {count_lines(d / f)} |")
    lines.append("\n> Exploitation stays manual / in-scope.")
    out = d / "recon-summary.md"
    out.write_text("\n".join(lines) + "\n")
    return out


def update_templates(emit) -> bool:
    """Fake nuclei template update streamed through emit (parity: menu_install)."""
    emit(StageStarted("", "nuclei-templates", "nuclei -update-templates -silent"))
    start = time.time()
    for i, msg in enumerate(["fetching templates", "applying", "done"]):
        time.sleep(0.2)
        emit(OutputLine("", "nuclei-templates", f"  {msg}"))
        emit(StageProgress("", "nuclei-templates", i + 1, time.time() - start))
    emit(StageFinished("", "nuclei-templates", "done", {"templates": 1}))
    emit(Notice("success", "nuclei templates updated (stub)"))
    return True


# ---------- runner.py: StageRunner ----------

def _fake_cmd(stage: str, cfg: dict, d: Path) -> str:
    t = cfg.get("target", "target")
    return {
        "subfinder": f"subfinder -d {t} -all -recursive -silent -o {d}/subs.txt",
        "httpx": f"httpx -l {d}/subs.txt -silent -rl {cfg['rate_limit']} -t {cfg['threads']} -o {d}/live.txt",
        "katana": f"katana -list {d}/live.txt -jc -d {cfg['katana_depth']} -rl {cfg['rate_limit']} -silent -o {d}/urls_raw.txt",
        "nuclei": f"nuclei -list {d}/live.txt -severity {cfg['nuclei_severity']} -rl {cfg['rate_limit']} -silent -o {d}/host-findings.txt",
    }.get(stage, stage)


class StageRunner:
    """Fake streaming runner matching StageRunner(cfg, target_dir, emit).run_stage(name)."""

    STAGES = ["subfinder", "httpx", "katana", "nuclei"]

    def __init__(self, cfg: dict, target_dir, emit):
        self.cfg = cfg
        self.d = Path(target_dir)
        self.emit = emit
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def run_stage(self, name: str, mode: str = "rerun") -> StageResult:
        t = self.cfg.get("target", "")
        cmd = _fake_cmd(name, self.cfg, self.d)
        self.emit(StageStarted(t, name, cmd))
        start = time.time()
        total = random.randint(8, 22)
        n = 0
        for i in range(total):
            if self._cancel.is_set():
                self.emit(StageFinished(t, name, "cancelled", {}))
                return StageResult("cancelled", {}, cmd, time.time() - start)
            time.sleep(0.12)
            n += 1
            self.emit(OutputLine(t, name, self._fake_line(name, i)))
            self.emit(StageProgress(t, name, n, time.time() - start))
        outputs = self._write_fake(name, total)
        self.emit(StageFinished(t, name, "done", outputs))
        return StageResult("done", outputs, cmd, time.time() - start)

    def _fake_line(self, name, i):
        if name == "nuclei":
            sev = random.choice(["info", "low", "medium", "high", "critical"])
            return f"[{sev}] https://{self.cfg.get('target')}/path{i} exposure-detected"
        if name == "subfinder":
            return f"sub{i}.{self.cfg.get('target')}"
        if name == "httpx":
            return f"https://host{i}.{self.cfg.get('target')} [200] [nginx]"
        return f"https://{self.cfg.get('target')}/page{i}?id={i}"

    def _write_fake(self, name, total):
        """Write fake output files so Results/Preview/Export have data."""
        t = self.cfg.get("target", "target")
        out = {}
        mk = lambda fn, lines: (self.d / fn).write_text("\n".join(lines) + "\n")
        if name == "subfinder":
            lines = [f"sub{i}.{t}" for i in range(total)]
            mk("subs.txt", lines); out["subs.txt"] = len(lines)
        elif name == "httpx":
            lines = [f"https://host{i}.{t}" for i in range(total)]
            mk("live.txt", lines); out["live.txt"] = len(lines)
        elif name == "katana":
            urls = [f"https://{t}/page{i}?id={i}" for i in range(total)]
            mk("urls_raw.txt", urls); out["urls_raw.txt"] = len(urls)
            mk("urls.txt", urls); out["urls.txt"] = len(urls)
            mk("endpoints.txt", [u.split("?")[0] for u in urls]); out["endpoints.txt"] = len(urls)
            mk("params.txt", urls); out["params.txt"] = len(urls)
            mk("sqli-idor.txt", urls[:3]); out["sqli-idor.txt"] = 3
            mk("xss.txt", urls[:2]); out["xss.txt"] = 2
        elif name == "nuclei":
            f = [f"[{random.choice(['medium','high','critical'])}] https://{t}/x{i}"
                 for i in range(max(1, total // 3))]
            mk("host-findings.txt", f); out["host-findings.txt"] = len(f)
        return out
