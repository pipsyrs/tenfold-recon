"""Export a target run summary -> recon-summary.json / recon-summary.md.

Names chosen to avoid clashing with the 12 guarded pipeline output files.
"""

import json
from pathlib import Path
from datetime import datetime

from .pipeline import count_lines
from .state import load_state

SCHEMA = 1
MAX_FINDINGS = 200   # trim findings lists in exports

COUNT_FILES = {
    "subs": "subs.txt", "live": "live.txt", "urls": "urls.txt",
    "endpoints": "endpoints.txt", "params": "params.txt",
    "sqli-idor": "sqli-idor.txt", "xss": "xss.txt", "ssrf-lfi": "ssrf-lfi.txt",
    "js": "js.txt", "host-findings": "host-findings.txt",
    "url-findings": "url-findings.txt",
}


def _counts(d):
    return {k: count_lines(d / f) for k, f in COUNT_FILES.items()}


def _read_lines(path, limit):
    if not Path(path).exists():
        return []
    lines = Path(path).read_text(errors="ignore").splitlines()
    return [l for l in lines if l.strip()][:limit]


def _summary(cfg, target_dir):
    d = Path(target_dir)
    st = load_state(d)
    tagging = st.get("stages", {}).get("katana", {}).get("tagging", "regex")
    return {
        "target": cfg.get("target", st.get("target", "")),
        "generated": datetime.now().isoformat(timespec="seconds"),
        "run": st.get("last_run", {}),
        "config": {
            "rate_limit": cfg.get("rate_limit"),
            "threads": cfg.get("threads"),
            "katana_depth": cfg.get("katana_depth"),
            "nuclei_severity": cfg.get("nuclei_severity"),
            "wildcard": cfg.get("wildcard"),
        },
        "counts": _counts(d),
        "tagging": tagging,
        "findings": {
            "host": _read_lines(d / "host-findings.txt", MAX_FINDINGS),
            "url": _read_lines(d / "url-findings.txt", MAX_FINDINGS),
        },
    }


def export_json(cfg, target_dir):
    d = Path(target_dir)
    data = {"schema": SCHEMA, **_summary(cfg, target_dir)}
    out = d / "recon-summary.json"
    out.write_text(json.dumps(data, indent=2))
    return out


def export_markdown(cfg, target_dir):
    d = Path(target_dir)
    s = _summary(cfg, target_dir)
    L = []
    L.append(f"# Recon summary — {s['target']}")
    L.append("")
    L.append(f"Generated: {s['generated']}")
    run = s.get("run") or {}
    if run:
        L.append(f"Last run: {run.get('started', '?')} → {run.get('finished', '?')} "
                 f"({run.get('duration_sec', 0)}s"
                 f"{', cancelled' if run.get('cancelled') else ''})")
    cfgc = s["config"]
    L.append(f"Config: rate={cfgc['rate_limit']}/s · threads={cfgc['threads']} · "
             f"depth={cfgc['katana_depth']} · severity={cfgc['nuclei_severity']} · "
             f"wildcard={cfgc['wildcard']}")
    L.append("")
    L.append("## Counts")
    L.append("")
    L.append("| stage/file | count |")
    L.append("|---|---|")
    for k, v in s["counts"].items():
        L.append(f"| {k} | {v} |")
    L.append("")
    L.append(f"Param tagging source: **{s['tagging']}**")
    L.append("")
    L.append("## Findings")
    L.append("")
    for scope in ("host", "url"):
        items = s["findings"][scope]
        L.append(f"### {scope}-findings ({len(items)})")
        L.append("")
        if items:
            for line in items:
                L.append(f"- {line}")
        else:
            L.append("_none_")
        L.append("")
    L.append("---")
    L.append("_Exploitation is MANUAL / suggestion-only. Stay within authorized scope._")
    out = d / "recon-summary.md"
    out.write_text("\n".join(L) + "\n")
    return out


def export_run(cfg, target_dir, fmt=None):
    """Export per cfg['export_format'] (json|md|both) unless fmt overrides. Returns [Path]."""
    fmt = fmt or cfg.get("export_format", "both")
    paths = []
    if fmt in ("json", "both"):
        paths.append(export_json(cfg, target_dir))
    if fmt in ("md", "both"):
        paths.append(export_markdown(cfg, target_dir))
    return paths
