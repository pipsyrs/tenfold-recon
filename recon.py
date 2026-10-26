#!/usr/bin/env python3
"""Recon Automation — launcher. Pipeline/TUI live in the `recon/` package."""

import sys

from recon.app import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Keluar.")
        sys.exit(0)