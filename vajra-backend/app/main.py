import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, Any
import httpx
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from sqlalchemy import text
from app.core.config import settings
from app.core.database import init_db, engine
from app.services.threat_intel import load_tor_exit_nodes
from app.api.v1.api import api_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vajra.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for initialization and graceful shutdown."""
    logger.info("=" * 60)
    logger.info("Initializing VAJRA Forensic Intelligence API...")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Payload ceiling: {settings.MAX_PAYLOAD_BYTES // (1024 * 1024)} MB")
    logger.info("=" * 60)

    # 1. Load Threat Intel Caches (Tor Exit Nodes)
    try:
        nodes = load_tor_exit_nodes()
        logger.info(f"Loaded {len(nodes)} Tor exit node signatures.")
    except Exception as e:
        logger.warning(f"Failed to load Tor exit node cache: {e}")

    # 2. Verify / Initialize Database Schema
    await init_db()

    yield

    # Graceful shutdown
    logger.info("Disposing database engine pools...")
    await engine.dispose()
    logger.info("VAJRA API shutdown complete.")


def create_app() -> FastAPI:
    """Factory function for FastAPI application instance."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        description=(
            "Production-grade headless REST API for AI-Powered Email Threat Detection, "
            "GeoLocation, and Forensic Intelligence Platform (SIH 2026 - Problem Statement SIH26106)."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan,
    )

    # CORS Middleware configuration for frontend integration (Vite / Next.js / React)
    cors_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]
    if settings.CORS_ORIGINS:
        if "*" in settings.CORS_ORIGINS:
            cors_origins = ["*"]
        else:
            for origin in settings.CORS_ORIGINS:
                if origin not in cors_origins:
                    cors_origins.append(origin)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API v1 Router
    app.include_router(api_router, prefix=settings.API_V1_STR)

    # Global Exception Handlers ensuring strict JSON contracts
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
                    "message": "An internal forensic engine error occurred.",
                },
            },
        )

    # Diagnostics & Health Check
    @app.get("/health", tags=["Diagnostics"], summary="System health check and dependency telemetry")
    async def health_check() -> Dict[str, Any]:
        # Check database connectivity
        db_connected = False
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
                db_connected = True
        except Exception:
            db_connected = False

        # Check local Ollama connectivity
        ollama_alive = False
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                res = await client.get(f"{settings.OLLAMA_HOST.rstrip('/')}/api/tags")
                if res.status_code == 200:
                    ollama_alive = True
        except Exception:
            ollama_alive = False

        return {
            "status": "online",
            "service": "VAJRA Forensic Platform Backend",
            "timestamp": time.time(),
            "telemetry": {
                "database_connected": db_connected,
                "ollama_available": ollama_alive,
                "ollama_host": settings.OLLAMA_HOST,
                "ollama_model": settings.OLLAMA_MODEL,
                "max_payload_bytes": settings.MAX_PAYLOAD_BYTES,
                "dns_timeout_seconds": settings.DNS_TIMEOUT_SECONDS,
            },
        }

    return app


app = create_app()
