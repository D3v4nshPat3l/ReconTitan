"""Vercel serverless entry point.

Vercel imports ``app`` from this module and invokes it per request. Nothing
here is specific to scanning; the differences that matter live behind
``settings.SERVERLESS``:

* scans run synchronously in the request, because there is no worker process
  to hand them to. This caps them at the function's maxDuration;
* rate limiting and admin lockout counters must come from Redis, since each
  invocation may be a different instance with its own memory.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.main import app  # noqa: E402  (path must be set first)
