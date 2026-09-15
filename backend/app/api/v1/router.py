"""
VAJRA Forensic Platform - API v1 Master Router
Aggregates Forensic Analysis, Cases Storage, and PDF Report endpoints.
"""

from fastapi import APIRouter
from app.api.v1.analyze_routes import router as analyze_router
from app.api.v1.cases_routes import router as cases_router
from app.api.v1.report_routes import router as report_router

router = APIRouter()

router.include_router(analyze_router, tags=["Forensic Analysis"])
router.include_router(cases_router, tags=["Forensic Cases"])
router.include_router(report_router, tags=["Forensic Reports"])

# Alias api_router for backward compatibility
api_router = router
