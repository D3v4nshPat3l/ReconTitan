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

    # Task time limits. These are the *default* per-task ceilings; the
    # orchestrator overrides them below because it runs every phase inline.
    task_time_limit=settings.CELERY_TASK_TIME_LIMIT,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT,

    # A scan killed by the hard limit must not be redelivered. Without this a
    # long scan is retried forever by the next worker, re-attacking the target.
    task_acks_on_failure_or_timeout=True,
    task_reject_on_worker_lost=False,

    # Task routes — different queues for different workload types
    task_routes={
        "app.tasks.scan_tasks.run_recon":       {"queue": "recon"},
        "app.tasks.scan_tasks.run_vuln_scan":   {"queue": "vulnscan"},
        "app.tasks.scan_tasks.run_osint":       {"queue": "osint"},
        "app.tasks.scan_tasks.run_danger_scan": {"queue": "danger"},
        "app.tasks.scan_tasks.orchestrate_scan": {"queue": "orchestrator"},
    },

    # ``orchestrate_scan`` runs recon, OSINT, portscan, vulnscan and danger
    # inline in a single task, so the per-tool default above would hard-kill it
    # partway through — usually before the danger phase ever started, leaving
    # the scan stuck at "running" because a signal kill skips the except block.
    # It gets its own ceiling sized to the whole pipeline instead.
    task_annotations={
        "app.tasks.scan_tasks.orchestrate_scan": {
            "time_limit": settings.SCAN_HARD_TIME_LIMIT,
            "soft_time_limit": settings.SCAN_SOFT_TIME_LIMIT,
        },
    },

    # Default queue for anything not explicitly routed
    task_default_queue="default",
)

# Auto-discover task modules
celery_app.autodiscover_tasks(["app.tasks"])
