"""Backend pipeline: pure stage logic. No print, no Textual.

Stage functions take `(cfg, d, emit, run)`:
  emit(Event) -> one-way backend->UI channel (Notice/OutputLine).
  run(cmd, stage, use_header=True, max_lines=0) -> (ok: bool, nlines: int)
         the streaming subprocess executor supplied by StageRunner (runner.py).

PARITY: subfinder/httpx/katana/nuclei flags, output filenames, and the
delete-if-empty convention are identical to the legacy recon.py.
"""

import re
import shutil
import subprocess
from pathlib import Path

from .events import Notice

PARAM_PATTERNS = {
    "sqli-idor": r"id=|user=|account=|order=|uid=|pid=|no=|key=",
    "xss": r"search=|q=|query=|name=|msg=|keyword=|s=|lang=",
    "ssrf-lfi": r"url=|file=|path=|page=|redirect=|dest=|load=|dir=|src=",
}

STATIC_EXT = r"\.(png|jpg|jpeg|gif|svg|css|woff|woff2|ico|ttf|eot|mp4|webp)($|\?)"

# canonical output files per stage (for resume/append/results)
STAGE_OUTPUTS = {
    "subfinder": ["subs.txt"],
    "httpx": ["live.txt"],
    "katana": ["urls_raw.txt", "urls.txt", "endpoints.txt", "params.txt",
               "sqli-idor.txt", "xss.txt", "ssrf-lfi.txt", "js.txt"],
    "nuclei": ["host-findings.txt", "url-findings.txt"],
}


def _notice(emit, level, text):
    if emit:
        emit(Notice(level, text))


# ---------- config -> tool args ----------

def header_args(cfg):
    args = []
    for k, v in cfg["headers"].items():
        args += ["-H", f"{k}: {v}"]
    return args


def _augment(cmd, use_header, cfg):
    if use_header and cfg:
        cmd += header_args(cfg)
        if cfg.get("proxy"):
            cmd += ["-proxy", cfg["proxy"]]
    return cmd


# ---------- fs util ----------

def validate_target(target):
    """Return scheme-stripped target or raise ValueError. Blocks path traversal
    and arg injection (absolute paths, leading '-', '/', '\\', '..', NUL)."""
    t = (target or "").strip().replace("https://", "").replace("http://", "")
    if not t:
        raise ValueError("target kosong")
    if t.startswith("-"):
        raise ValueError(f"target tidak valid (diawali '-'): {target}")
    if any(ch in t for ch in ("/", "\\", "\x00")) or ".." in t:
        raise ValueError(f"target tidak valid (karakter path terlarang): {target}")
    return t


def target_dir(cfg):
    t = validate_target(cfg["target"])
    base = Path(cfg["output_base"]).resolve()
    d = (base / t).resolve()
    if d != base and base not in d.parents:
        raise ValueError(f"target di luar output_base: {cfg['target']}")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _redact_proxy(url):
    """Strip user:pass from a proxy URL for display/storage."""
    return re.sub(r"(://)[^/@]+@", r"\1<redacted>@", url or "")


def redact_command(cmd):
    """Join argv for display/storage, redacting -H header values and -proxy creds.
    The real argv is still used for execution; only the recorded copy is redacted."""
    out, i = [], 0
    while i < len(cmd):
        a = cmd[i]
        if a == "-H" and i + 1 < len(cmd):
            name = cmd[i + 1].split(":", 1)[0]
            out += ["-H", f"{name}: <redacted>"]
            i += 2
            continue
        if a == "-proxy" and i + 1 < len(cmd):
            out += ["-proxy", _redact_proxy(cmd[i + 1])]
            i += 2
            continue
        out.append(a)
        i += 1
    return " ".join(out)


def count_lines(path):
    if not Path(path).exists():
        return 0
    with open(path, errors="ignore") as f:
        return sum(1 for _ in f)


def report(path, label, emit=None):
    """Report line count; delete file if empty (delete-if-empty convention)."""
    n = count_lines(path)
    if n:
        _notice(emit, "ok", f"[+] {label}: {n}")
    else:
        if Path(path).exists():
            Path(path).unlink()
        _notice(emit, "warn", f"[i] {label}: tidak ada.")
    return n


# ---------- cleaning ----------

def dedup_file(path):
    if not Path(path).exists():
        return
    seen, out = set(), []
    for ln in Path(path).read_text(errors="ignore").splitlines():
        ln = ln.strip()
        if ln and ln not in seen:
            seen.add(ln)
            out.append(ln)
    Path(path).write_text("\n".join(out) + ("\n" if out else ""))


def _write_list(path, items):
    """Write unique sorted list; delete file if empty. Return count."""
    uniq = sorted(set(items))
    if uniq:
        Path(path).write_text("\n".join(uniq) + "\n")
    elif Path(path).exists():
        Path(path).unlink()
    return len(uniq)


def dedup_by_shape(urls):
    """uro-like fallback without uro: 1 sample per shape (param values ignored)."""
    seen, out = set(), []
    for u in urls:
        key = re.sub(r"=[^&]*", "=", u)
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def reduce_urls(urls):
    """Trim redundant URLs: uro if present, else Python fallback."""
    urls = [u for u in urls if u.strip()]
    if not urls:
        return []
    if shutil.which("uro"):
        p = subprocess.run(["uro"], input="\n".join(urls), capture_output=True, text=True)
        return [l for l in p.stdout.splitlines() if l.strip()]
    return dedup_by_shape(urls)


def clean_urls(src, dst, cfg, emit=None):
    if not Path(src).exists():
        _notice(emit, "error", f"[!] {src} tidak ada.")
        return 0
    lines = Path(src).read_text(errors="ignore").splitlines()
    filtered = [l.strip() for l in lines if l.strip() and not re.search(STATIC_EXT, l, re.I)]
    filtered = reduce_urls(filtered)
    n = _write_list(dst, filtered)
    if n:
        _notice(emit, "ok", f"[+] URL bersih: {n} -> {dst}")
    else:
        _notice(emit, "warn", "[i] Tidak ada URL setelah cleaning.")
    return n


def make_endpoints(src, dst):
    """From raw: strip param values (?id=1 -> ?id=), unique. Endpoint overview."""
    if not Path(src).exists():
        return 0
    seen = []
    for l in Path(src).read_text(errors="ignore").splitlines():
        l = l.strip()
        if not l or re.search(STATIC_EXT, l, re.I):
            continue
        seen.append(re.sub(r"=[^&]*", "=", l))
    return _write_list(dst, seen)


def categorize_params(urls_file, outdir, cfg, emit=None):
    """Write params.txt + category files + js.txt. Returns (counts, tagging_source)."""
    from .tagging import tag_params
    if not Path(urls_file).exists():
        _notice(emit, "warn", "[i] Belum ada URL untuk dikategorikan.")
        return {}, "regex"
    lines = Path(urls_file).read_text(errors="ignore").splitlines()
    params = reduce_urls([l for l in lines if "=" in l])
    counts = {}

    # params.txt
    counts["params"] = _write_list(Path(outdir) / "params.txt", params)
    # category files (gf or regex)
    cat_counts, source = tag_params(params, outdir, cfg, emit)
    counts.update(cat_counts)
    # js.txt
    js = [l for l in lines if re.search(r"\.js($|\?)", l, re.I)]
    counts["js"] = _write_list(Path(outdir) / "js.txt", js)

    # emit in legacy order: params, sqli-idor, xss, ssrf-lfi, js
    order = ["params"] + list(PARAM_PATTERNS.keys()) + ["js"]
    for label in order:
        n = counts.get(label, 0)
        if n:
            _notice(emit, "ok", f"    {label}.txt: {n}")
        else:
            _notice(emit, "info", f"    {label}: tidak ada")
    return counts, source


# ---------- command builders ----------

def subfinder_cmd(cfg, d):
    return ["subfinder", "-d", cfg["target"], "-all", "-recursive",
            "-silent", "-o", str(d / "subs.txt")]


def httpx_cmd(cfg, d):
    return ["httpx", "-l", str(d / "subs.txt"), "-silent",
            "-rl", str(cfg["rate_limit"]), "-t", str(cfg["threads"]),
            "-o", str(d / "live.txt")]


def katana_cmd(cfg, d):
    cmd = ["katana", "-list", str(d / "live.txt"), "-jc",
           "-d", str(cfg["katana_depth"]), "-rl", str(cfg["rate_limit"]),
           "-silent", "-o", str(d / "urls_raw.txt")]
    if cfg.get("crawl_time"):
        cmd += ["-ct", str(cfg["crawl_time"])]
    if cfg.get("field_scope"):
        cmd += ["-fs", cfg["field_scope"]]
    if cfg.get("exclude_ext"):
        cmd += ["-ef", cfg["exclude_ext"]]
    if cfg.get("ignore_qp"):
        cmd += ["-iqp"]
    return cmd


def nuclei_cmd(cfg, d, src, out):
    return ["nuclei", "-list", str(d / src), "-severity", cfg["nuclei_severity"],
            "-rl", str(cfg["rate_limit"]), "-silent", "-o", str(d / out)]


# ---------- pipeline steps (emit-based) ----------

def step_subfinder(cfg, d, emit=None, run=None):
    if not cfg["wildcard"]:
        (d / "subs.txt").write_text(cfg["target"] + "\n")
        _notice(emit, "info", "[i] Mode single host, subfinder dilewati.")
        return
    run(subfinder_cmd(cfg, d), "subfinder", use_header=False)
    report(d / "subs.txt", "Subdomain", emit)


def step_httpx(cfg, d, emit=None, run=None):
    if not count_lines(d / "subs.txt"):
        _notice(emit, "warn", "[i] subs.txt kosong, httpx dilewati.")
        return
    run(httpx_cmd(cfg, d), "httpx", use_header=True)
    report(d / "live.txt", "Host hidup", emit)


def step_katana(cfg, d, emit=None, run=None):
    if not count_lines(d / "live.txt"):
        _notice(emit, "warn", "[i] live.txt kosong, katana dilewati.")
        return
    run(katana_cmd(cfg, d), "katana", use_header=True, max_lines=200)
    report(d / "urls_raw.txt", "URL mentah", emit)
    clean_urls(d / "urls_raw.txt", d / "urls.txt", cfg, emit)
    ne = make_endpoints(d / "urls_raw.txt", d / "endpoints.txt")
    if ne:
        _notice(emit, "ok", f"    endpoints.txt: {ne}")
    else:
        _notice(emit, "info", "    endpoints: tidak ada")
    categorize_params(d / "urls_raw.txt", d, cfg, emit)
    from .exploit_hints import exploit_hints
    exploit_hints(cfg, d, emit, target=cfg.get("target", ""))


def step_nuclei(cfg, d, emit=None, run=None):
    if count_lines(d / "live.txt"):
        run(nuclei_cmd(cfg, d, "live.txt", "host-findings.txt"), "nuclei", use_header=True)
        report(d / "host-findings.txt", "Host findings", emit)
    if count_lines(d / "urls.txt"):
        run(nuclei_cmd(cfg, d, "urls.txt", "url-findings.txt"), "nuclei", use_header=True)
        report(d / "url-findings.txt", "URL findings", emit)


STEP_FUNCS = {
    "subfinder": step_subfinder,
    "httpx": step_httpx,
    "katana": step_katana,
    "nuclei": step_nuclei,
}
