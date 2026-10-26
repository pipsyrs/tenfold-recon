"""Param tagging: gf-per-pattern when available, else legacy regex.

MUST: when gf is absent, ~/.gf is empty, or cfg.use_gf is False, fall back to the
exact legacy PARAM_PATTERNS regex behavior. Never fail silently.
"""

import re
import shutil
import subprocess
from pathlib import Path

from .events import Notice
from .pipeline import PARAM_PATTERNS, _write_list

# our 3 category files -> candidate gf pattern names
GF_MAP = {
    "sqli-idor": ["sqli", "idor"],
    "xss": ["xss"],
    "ssrf-lfi": ["ssrf", "lfi", "redirect"],
}

GF_DIR = Path.home() / ".gf"


def _gf_patterns():
    """Pattern names present in ~/.gf (filenames without .json)."""
    if not GF_DIR.is_dir():
        return set()
    return {p.stem for p in GF_DIR.glob("*.json")}


def gf_usable(cfg):
    """True only if gf binary present, ~/.gf has patterns, and use_gf enabled."""
    if not cfg.get("use_gf", True):
        return False
    if not shutil.which("gf"):
        return False
    return bool(_gf_patterns())


def _run_gf(pattern, params):
    """Run one gf pattern. Returns (ok, lines); ok=False on error (not silent)."""
    try:
        p = subprocess.run(["gf", pattern], input="\n".join(params),
                           capture_output=True, text=True)
    except Exception as exc:
        return False, str(exc)
    if p.returncode != 0:
        return False, (p.stderr or "").strip()
    return True, [l for l in p.stdout.splitlines() if l.strip()]


def _regex_items(cat, params):
    """Legacy regex selection for one category — identical to old categorize_params."""
    return [l for l in params if re.search(PARAM_PATTERNS[cat], l, re.I)]


def tag_params(params, outdir, cfg, emit=None):
    """Write sqli-idor/xss/ssrf-lfi category files from `params`.

    Returns (counts: {cat: n}, source: "gf"|"regex"). On a per-pattern gf error,
    warn and fall back to regex for that category (never silently empty).
    """
    outdir = Path(outdir)
    counts = {}
    if gf_usable(cfg):
        available = _gf_patterns()
        for cat, patterns in GF_MAP.items():
            usable = [p for p in patterns if p in available]
            if usable:
                items, failed = [], False
                for pat in usable:
                    ok, res = _run_gf(pat, params)
                    if ok:
                        items += res
                    else:
                        failed = True
                        if emit:
                            emit(Notice("warn", f"[!] gf '{pat}' gagal ({res}); pakai regex untuk {cat}."))
                if failed:
                    items = _regex_items(cat, params)   # fall back, don't drop data
            else:
                # no gf pattern for this category -> legacy regex for it
                items = _regex_items(cat, params)
            counts[cat] = _write_list(outdir / f"{cat}.txt", items)
        return counts, "gf"

    # full regex fallback (legacy behavior, unchanged)
    for cat in PARAM_PATTERNS:
        counts[cat] = _write_list(outdir / f"{cat}.txt", _regex_items(cat, params))
    return counts, "regex"
