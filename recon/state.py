"""Per-target run manifest (.recon_state.json) + resume logic.

Resume source-of-truth = file existence; the manifest adds metadata
(timestamps, duration, cancelled, command, tagging source, config fingerprint).
A stage is treated "done" when its primary output exists non-empty OR the
manifest recorded it done (covers nuclei whose empty findings are deleted).
"""

import os
import json
import hashlib
from pathlib import Path

from .pipeline import count_lines, STAGE_OUTPUTS

STATE_FILE = ".recon_state.json"
SCHEMA = 1
STAGES = ["subfinder", "httpx", "katana", "nuclei"]

# flags that change results -> drive the config fingerprint
FINGERPRINT_KEYS = ["katana_depth", "field_scope", "rate_limit",
                    "nuclei_severity", "ignore_qp", "exclude_ext"]

# primary output used for file-existence "done" detection
PRIMARY_OUTPUTS = {
    "subfinder": ["subs.txt"],
    "httpx": ["live.txt"],
    "katana": ["urls_raw.txt"],
    "nuclei": ["host-findings.txt", "url-findings.txt"],
}

# file -> (kind, is_param_category) for results rows
FILE_KIND = {
    "subs.txt": ("subdomains", False),
    "live.txt": ("hosts", False),
    "urls.txt": ("urls", False),
    "endpoints.txt": ("endpoints", False),
    "params.txt": ("params", False),
    "sqli-idor.txt": ("tagged", True),
    "xss.txt": ("tagged", True),
    "ssrf-lfi.txt": ("tagged", True),
    "js.txt": ("urls", False),
    "host-findings.txt": ("findings", False),
    "url-findings.txt": ("findings", False),
}
RESULT_FILES = list(FILE_KIND.keys())


def _state_path(target_dir):
    return Path(target_dir) / STATE_FILE


def config_fingerprint(cfg):
    blob = json.dumps({k: cfg.get(k) for k in FINGERPRINT_KEYS}, sort_keys=True)
    return "sha1:" + hashlib.sha1(blob.encode()).hexdigest()[:16]


def load_state(target_dir):
    p = _state_path(target_dir)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {"schema": SCHEMA, "target": "", "config_fingerprint": "",
            "last_run": {}, "stages": {}}


def save_state(target_dir, state):
    state["schema"] = SCHEMA
    p = _state_path(target_dir)
    p.write_text(json.dumps(state, indent=2))
    try:
        os.chmod(p, 0o600)  # command strings are redacted, but keep it private
    except OSError:
        pass


def record_stage(target_dir, cfg, target, stage, status, command,
                 started, finished, duration, tagging=None):
    """Merge one stage's result into the manifest."""
    state = load_state(target_dir)
    state["target"] = target
    state["config_fingerprint"] = config_fingerprint(cfg)
    outputs = {f: count_lines(Path(target_dir) / f)
               for f in STAGE_OUTPUTS[stage] if (Path(target_dir) / f).exists()}
    entry = {"status": status, "command": command, "outputs": outputs,
             "started": started, "finished": finished, "duration_sec": duration}
    if tagging is not None:
        entry["tagging"] = tagging
    state.setdefault("stages", {})[stage] = entry
    save_state(target_dir, state)
    return state


def record_run(target_dir, started, finished, duration, cancelled):
    state = load_state(target_dir)
    state["last_run"] = {"started": started, "finished": finished,
                         "duration_sec": duration, "cancelled": cancelled}
    save_state(target_dir, state)
    return state


def _files_present(stage, target_dir):
    return any(count_lines(Path(target_dir) / f) > 0 for f in PRIMARY_OUTPUTS[stage])


def plan_resume(cfg, target_dir):
    """Return resume plan the UI shows as skip/re-run/append per stage.

    { "fingerprint": str, "config_changed": bool,
      "stages": { stage: {"status": "done"|"pending", "outputs": {file:count}} } }
    """
    state = load_state(target_dir)
    stage_state = state.get("stages", {})
    fp = config_fingerprint(cfg)
    config_changed = bool(state.get("config_fingerprint")) and \
        state.get("config_fingerprint") != fp
    stages = {}
    for stage in STAGES:
        st = stage_state.get(stage, {})
        done = _files_present(stage, target_dir) or st.get("status") == "done"
        outputs = {f: count_lines(Path(target_dir) / f)
                   for f in STAGE_OUTPUTS[stage]
                   if (Path(target_dir) / f).exists()}
        stages[stage] = {"status": "done" if done else "pending", "outputs": outputs}
    return {"fingerprint": fp, "config_changed": config_changed, "stages": stages}


def apply_resume_decisions(decisions):
    """Normalize UI decisions -> {stage: mode} with mode in skip|rerun|append.

    Missing stages default to rerun. Returns the full 4-stage plan.
    """
    valid = {"skip", "rerun", "append"}
    plan = {}
    for stage in STAGES:
        mode = (decisions or {}).get(stage, "rerun")
        plan[stage] = mode if mode in valid else "rerun"
    return plan


def results_rows(target_dir):
    """DataTable rows: file / kind / count / tag / updated (see arch doc §4)."""
    target_dir = Path(target_dir)
    state = load_state(target_dir)
    tagging = state.get("stages", {}).get("katana", {}).get("tagging")
    rows = []
    for fname in RESULT_FILES:
        p = target_dir / fname
        kind, is_cat = FILE_KIND[fname]
        count = count_lines(p)
        tag = ""
        if is_cat:
            base = fname[:-4]  # strip .txt
            src = tagging or "regex"
            tag = f"{base} ({src})"
        updated = ""
        if p.exists():
            try:
                from datetime import datetime
                updated = datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds")
            except Exception:
                updated = ""
        rows.append({"file": fname, "kind": kind, "count": count,
                     "tag": tag, "updated": updated})
    return rows
