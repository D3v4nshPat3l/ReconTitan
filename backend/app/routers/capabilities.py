"""Public product-capability metadata for the dashboard and API clients."""

from fastapi import APIRouter

from app.config import settings
from app.services.capabilities import capabilities_payload

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/capabilities")
def get_capabilities():
    """Return non-sensitive feature, profile, and tool metadata."""
    return capabilities_payload(settings.APP_VERSION)
