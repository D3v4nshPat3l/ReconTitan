"""Run the admin SOC console on its own port.

The console is a separate ASGI application from app.main:app by design: the
public app has no admin routes at all, so no public-routing bug can expose it.
Bind it to loopback only; reach a remote deployment through an SSH tunnel:

    ssh -N -L 9000:127.0.0.1:9000 user@server
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

import uvicorn

from app.admin.main import create_admin_app
from app.config import settings

if __name__ == "__main__":
    uvicorn.run(create_admin_app(), host="127.0.0.1", port=settings.ADMIN_PORT, log_level="info")
