"""MongoDB connection manager with graceful degraded mode."""

from __future__ import annotations

import logging
from typing import Any

from app.config import settings

logger = logging.getLogger("recontitan.db")

try:
    from pymongo import MongoClient
    from pymongo.database import Database
    from pymongo.errors import ConnectionFailure
except ImportError:  # Local quick-scan mode can run without persistence packages.
    MongoClient = None  # type: ignore[assignment]
    Database = Any  # type: ignore[misc,assignment]

    class ConnectionFailure(Exception):
        pass

_client: Any = None
_db: Any = None
_missing_driver_logged = False


def get_db() -> Any:
    global _client, _db, _missing_driver_logged
    if _db is not None:
        return _db
    if MongoClient is None:
        if not _missing_driver_logged:
            logger.warning("pymongo is not installed; running without persistent scan storage")
            _missing_driver_logged = True
        return None

    try:
        _client = MongoClient(
            settings.MONGO_URI,
            serverSelectionTimeoutMS=2500,
            connectTimeoutMS=2500,
            socketTimeoutMS=5000,
        )
        _client.admin.command("ping")
        _db = _client[settings.MONGO_DB]
        _ensure_indexes(_db)
        logger.info("Connected to MongoDB: %s:%s/%s", settings.MONGO_HOST, settings.MONGO_PORT, settings.MONGO_DB)
        return _db
    except ConnectionFailure:
        logger.warning("MongoDB unavailable; running in degraded mode")
    except Exception as exc:
        logger.warning("MongoDB connection error: %s", str(exc)[:200])
    return None


def _ensure_indexes(db: Any) -> None:
    scans = db["scans"]
    scans.create_index("scan_id", unique=True)
    scans.create_index("created_at")
    scans.create_index("status")
    scans.create_index("target")
    news = db["news"]
    news.create_index("published_at")
    news.create_index("source")


def close_db() -> None:
    global _client, _db
    if _client:
        _client.close()
    _client = None
    _db = None
