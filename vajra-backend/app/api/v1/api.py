"""API v1 master router re-export."""
from app.api.v1.router import router as api_router, router

__all__ = ["api_router", "router"]
