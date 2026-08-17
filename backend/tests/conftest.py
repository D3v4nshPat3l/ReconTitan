from __future__ import annotations

import os
import sys
from pathlib import Path

# Must be set before app.config is imported anywhere. Otherwise the suite picks
# up the developer's real .env and results vary by machine — a local
# API_ACCESS_KEY 401s every API test, and ALLOW_DANGER_MODE=true inverts the
# Danger Mode gate tests.
os.environ["RECONTITAN_SKIP_DOTENV"] = "1"

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
