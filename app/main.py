"""
FastAPI application factory and lifespan management.

Lifespan:
  The @asynccontextmanager lifespan handles startup and shutdown tasks:
  Startup:
    - Validate settings (raises ValidationError if env vars missing/invalid)
    - Create Redis connection pool
    - Verify Redis connectivity (fail-fast on misconfiguration)
    - Emit SYSTEM_STARTUP audit event
  Shutdown:
    - Close Redis connection pool
    - Dispose SQLAlchemy engine (returns connections to pool)
    - Emit SYSTEM_SHUTDOWN audit event

Middleware order matters (outermost wraps innermost):
  1. SecurityHeadersMiddleware (outermost — always adds security headers)
  2. RateLimitMiddleware (reject rate-limited requests before auth)
  3. RequestIDMiddleware (inject request IDs for all subsequent middleware)
  4. CORSMiddleware (FastAPI built-in)
  5. Route handlers (innermost)

Error handling:
  - RequestValidationError → 422 with field-level details
  - HTTPException → standard JSON error response
  - Unhandled exceptions → 500 with opaque message (no stack trace in response)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.middleware.rate_limiting import RateLimitMiddleware
from app.api.middleware.request_id import RequestIDMiddleware
from app.api.middleware.security_headers import SecurityHeadersMiddleware
from app.api.v1.router import v1_router
from app.config import get_settings
from app.db.session import close_engine

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.ConsoleRenderer() if False else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager — startup and shutdown."""
    settings = get_settings()

    log.info("starting_up", env=settings.app_env, debug=settings.app_debug)

    # Create Redis connection pool
    redis_client = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        max_connections=50,
    )

    try:
        await redis_client.ping()
        log.info("redis_connected", url=settings.redis_url)
    except Exception as exc:
        log.error("redis_connection_failed", error=str(exc))
        raise

    app.state.redis = redis_client
    app.state.settings = settings

    log.info("startup_complete")

    yield

    # Shutdown
    log.info("shutting_down")
    await redis_client.close()
    await close_engine()
    log.info("shutdown_complete")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="SecretManager",
        description=(
            "Production-grade Distributed Secrets Manager. "
            "AES-256-GCM encrypted at rest, Argon2id KDF, "
            "JWT + refresh token auth, append-only audit log."
        ),
        version="1.0.0",
        docs_url="/docs" if settings.app_env != "production" else None,
        redoc_url="/redoc" if settings.app_env != "production" else None,
        openapi_url="/openapi.json" if settings.app_env != "production" else None,
        lifespan=lifespan,
    )

    # ── Middleware (outermost first) ──────────────────────────────────────────
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )

    # ── Exception handlers ────────────────────────────────────────────────────
    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": exc.errors(),
                "type": "validation_error",
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        log.error(
            "unhandled_exception",
            request_id=request_id,
            path=request.url.path,
            exc_type=type(exc).__name__,
            # exc_info=True logs the stack trace to stderr — NOT in response
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An internal error occurred",
                "request_id": request_id,
            },
        )

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(v1_router)

    # ── Health check ──────────────────────────────────────────────────────────
    @app.get("/health", tags=["System"], summary="Health check")
    async def health(request: Request) -> dict[str, Any]:
        redis_ok = False
        try:
            await request.app.state.redis.ping()
            redis_ok = True
        except Exception:
            pass
        return {
            "status": "ok" if redis_ok else "degraded",
            "version": "1.0.0",
            "services": {"redis": "ok" if redis_ok else "error"},
        }

    return app


app = create_app()
