"""
VAJRA Forensic Platform - High-Performance Offline-First API Entry Point
SIH Problem Statement SIH26106 | Zero Disk Database | Pure In-Memory Forensic Intelligence
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.storage.memory_store import case_store
from app.api.v1.router import router as api_v1_router
from app.schemas.analysis import ThreatAnalysisReport, CaseResponseDTO
from app.services.ai.groq_provider import analyze_threat_with_groq_async

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
        if path in ("/api/scan", "/api/v1/raw", "/api/v1/upload", "/api/v1/analyze/raw", "/api/v1/analyze/upload"):
            if "dlp_masking" not in request.query_params:
                qs = request.scope.get("query_string", b"").decode("latin-1")
                new_qs = f"{qs}&dlp_masking=true" if qs else "dlp_masking=true"
                request.scope["query_string"] = new_qs.encode("latin-1")
        return await call_next(request)

    # Mount API v1 Routes
    app.include_router(api_v1_router, prefix=settings.API_V1_STR)

    # Unified Forensic Analysis Endpoint: /api/scan
    @app.post(
        "/api/scan",
        response_model=CaseResponseDTO,
        tags=["Forensic Threat Analysis"],
        summary="Unified Forensic Scan & Threat Analysis",
        description="Comprehensive email analysis executing full forensic pipeline with Groq AI Threat Analysis Report.",
    )
    async def scan_email_endpoint(request: Request):
        from app.parsers.eml_parser import parse_eml_bytes
        from app.parsers.msg_parser import parse_msg_bytes
        from app.api.v1.analyze_routes import execute_forensic_pipeline
        from app.storage.memory_store import save_case
        from app.schemas.analysis import CaseResponseDTO

        content_type = request.headers.get("content-type", "").lower()
        raw_bytes = b""

        if "multipart/form-data" in content_type:
            form = await request.form()
            file = form.get("file")
            if file and hasattr(file, "read"):
                f_bytes = await file.read()
                filename = (getattr(file, "filename", "") or "").lower()
                if filename.endswith(".msg"):
                    try:
                        parsed = parse_msg_bytes(f_bytes)
                    except Exception as e:
                        raise HTTPException(
                            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail=f"Failed to parse Outlook .msg file: {e}",
                        )
                else:
                    parsed = parse_eml_bytes(f_bytes)
                case_data = await execute_forensic_pipeline(parsed, dlp_masking=True)
                saved = save_case(case_data)
                return CaseResponseDTO.model_validate(saved)

            raw_text = form.get("raw_email") or form.get("data") or form.get("text") or ""
            if hasattr(raw_text, "read"):
                raw_bytes = await raw_text.read()
            else:
                raw_bytes = str(raw_text).encode("utf-8", errors="ignore")
        elif "application/json" in content_type:
            try:
                body = await request.json()
            except Exception:
                body = {}
            if isinstance(body, dict):
                raw_text = body.get("raw_email") or body.get("data") or body.get("text") or ""
                raw_bytes = str(raw_text).encode("utf-8", errors="ignore")
            else:
                raw_bytes = str(body).encode("utf-8", errors="ignore")
        else:
            raw_bytes = await request.body()

        if len(raw_bytes.strip()) < 10:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Raw email payload must be at least 10 characters.",
            )

        parsed = parse_eml_bytes(raw_bytes)
        case_data = await execute_forensic_pipeline(parsed, dlp_masking=True)
        saved = save_case(case_data)
        return CaseResponseDTO.model_validate(saved)

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
                "groq_model": settings.GROQ_MODEL,
            },
        }

    return app


app = create_app()
