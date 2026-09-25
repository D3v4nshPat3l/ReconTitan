#!/usr/bin/env python3
"""ReconTitan command-line entry point.

Run a scan without the web UI:

    python recontitan.py example.com
    python recontitan.py example.com --profile recon --format json
    python recontitan.py example.com -m dns_lookup,subdomain_sources
    python recontitan.py --list-modules

This is a launcher only. It puts ``backend/`` on the path so ``app`` imports
resolve the same way they do under uvicorn, then hands over to the CLI. Keeping
it at the repository root means the command works from a fresh clone with no
install step and no PYTHONPATH to set.
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.cli import main  # noqa: E402 — must follow the sys.path change above

if __name__ == "__main__":
    raise SystemExit(main())
