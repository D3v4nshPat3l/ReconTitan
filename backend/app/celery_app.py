"""
ReconTitan — Celery Application

Configures the distributed task queue used to run long-running
security scans (Nmap, Nuclei, ZAP, etc.) asynchronously. Each scan
tool runs as a Celery task so the API never blocks.

Broker: Redis
Result Backend: Redis
"""

from celery import Celery
from app.config import settings


celery_app = Celery(
    "recontitan",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

# ── Celery Configuration ──
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task behavior
    task_track_started=True,          # Track when a task starts executing
    task_acks_late=True,              # Acknowledge after completion (safer)
    worker_prefetch_multiplier=1,     # One task at a time per worker (scans are heavy)

    # Result expiry — keep results for 24 hours
    result_expires=86400,

    # Task time limits (hard kill after this)
    task_time_limit=900,              # 15 minutes max per individual tool
    task_soft_time_limit=840,         # Soft warning at 14 minutes

    # Task routes — different queues for different workload types
    task_routes={
        "app.tasks.scan_tasks.run_recon":       {"queue": "recon"},
        "app.tasks.scan_tasks.run_vuln_scan":   {"queue": "vulnscan"},
        "app.tasks.scan_tasks.run_osint":       {"queue": "osint"},
        "app.tasks.scan_tasks.run_danger_scan": {"queue": "danger"},
        "app.tasks.scan_tasks.orchestrate_scan": {"queue": "orchestrator"},
    },

    # Default queue for anything not explicitly routed
    task_default_queue="default",
)

# Auto-discover task modules
celery_app.autodiscover_tasks(["app.tasks"])
