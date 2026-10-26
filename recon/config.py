"""Config IO. Path stays ~/.recon_automation.json; back-compat via dict merge."""

import os
import json
from pathlib import Path

CONFIG_FILE = Path.home() / ".recon_automation.json"

DEFAULT_CONFIG = {
    "target": "",
    "output_base": str(Path.home() / "recon"),
    "wildcard": True,
    "headers": {},
    "rate_limit": 20,
    "threads": 40,
    "katana_depth": 2,
    "crawl_time": 180,        # -ct detik; 0 = tanpa batas
    "field_scope": "fqdn",    # -fs: rdn/fqdn/dn ("" = default katana)
    "ignore_qp": False,       # -iqp: gabung URL beda value (params.txt jadi kosong)
    "exclude_ext": "png,jpg,jpeg,gif,svg,css,woff,woff2,ico,ttf,eot,mp4,webp",
    "nuclei_severity": "medium,high,critical",
    "proxy": "",
    # new optional keys (back-compat: old config still loads, these get defaults)
    "use_gf": True,           # use gf when present; False = force legacy regex
    "export_format": "both",  # json | md | both
    "last_targets": [],       # last queue memory (optional)
}


def load_config():
    if CONFIG_FILE.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text())}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG_FILE, 0o600)  # may hold cookies/tokens/proxy creds
    except OSError:
        pass
