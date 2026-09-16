"""
VAJRA Forensic Platform - High-Performance Offline-First API Entry Point
SIH Problem Statement SIH26106 | Zero Disk Database | Pure In-Memory Forensic Intelligence
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.storage.memory_store import case_store
from app.api.v1.router import router as api_v1_router

# Configure platform-wide logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vajra.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for offline-first / air-gapped forensic engine."""
    logger.info("=" * 65)
    logger.info("Initializing VAJRA Forensic Email Intelligence Engine...")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Payload Ceiling: {settings.MAX_PAYLOAD_BYTES // (1024 * 1024)} MB")
    logger.info("Storage Architecture: Thread-Safe RAM FIFO Case Store (Capacity: 25)")
    logger.info(f"Threat Intel MMDB: {settings.GEOLITE2_CITY_PATH.exists()}")
    logger.info("=" * 65)

    yield

    logger.info("VAJRA Forensic Platform shutdown complete.")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="2.0.0",
        description=(
            "Offline-first / air-gapped-capable, zero-database REST API for AI-Powered Email Threat Detection, "
            "sending infrastructure geolocation, and Forensic Intelligence Platform (SIH 2026 - Problem Statement SIH26106)."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan,
    )

    # CORS Middleware configuration explicitly whitelisted for local React development
    cors_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    if settings.CORS_ORIGINS:
        for origin in settings.CORS_ORIGINS:
            if origin != "*" and origin not in cors_origins:
                cors_origins.append(origin)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # In-flight default parameter normalization for programmatic clients
    @app.middleware("http")
    async def default_dlp_query_param(request: Request, call_next):
        path = request.url.path
        if path in ("/api/v1/raw", "/api/v1/upload", "/api/v1/analyze/raw", "/api/v1/analyze/upload"):
            if "dlp_masking" not in request.query_params:
                qs = request.scope.get("query_string", b"").decode("latin-1")
                new_qs = f"{qs}&dlp_masking=true" if qs else "dlp_masking=true"
                request.scope["query_string"] = new_qs.encode("latin-1")
        return await call_next(request)

    # Mount API v1 Routes
    app.include_router(api_v1_router, prefix=settings.API_V1_STR)

    # Global Exception Handlers
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                },
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={
                "success": False,
                "error": {
                    "code": 422,
                    "message": "Request payload validation failed.",
                    "details": jsonable_encoder(exc.errors()),
                },
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled system error on {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "error": {
                    "code": 500,
                    "message": f"An internal forensic engine error occurred: {str(exc)}",
                },
            },
        )

    # Diagnostics & System Health Endpoint
    @app.get("/health", tags=["Diagnostics"], summary="System health check and dependency telemetry")
    async def health_check() -> Dict[str, Any]:
        return {
            "status": "online",
            "service": "VAJRA Forensic Platform Backend",
            "version": "2.0.0",
            "timestamp": time.time(),
            "telemetry": {
                "active_memory_cases": case_store.count,
                "max_memory_capacity": 25,
                "max_payload_bytes": settings.MAX_PAYLOAD_BYTES,
                "geoip_city_available": settings.GEOLITE2_CITY_PATH.exists(),
                "geoip_asn_available": settings.GEOLITE2_ASN_PATH.exists(),
                "tor_cache_available": settings.TOR_EXIT_NODES_PATH.exists(),
                "groq_configured": bool(settings.GROQ_API_KEY),
                "ollama_url": settings.OLLAMA_URL,
            },
        }

    return app


app = create_app()
