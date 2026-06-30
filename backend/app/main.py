"""
ShadowCrypt++ v2.0 — FastAPI Application Entry Point

Start with:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.middleware import SecurityMiddleware
from app.core.models import ErrorResponse
from app.routers import compression, devtools, encoding, hashing, jwt
from app.services import encoders, hashers, compressors

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("shadowcrypt")
cfg = get_settings()


# ─────────────────────────────────────────────
# LIFESPAN
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("ShadowCrypt++ %s starting on %s:%d", cfg.app_version, cfg.host, cfg.port)
    yield
    log.info("ShadowCrypt++ shutting down")


# ─────────────────────────────────────────────
# APPLICATION
# ─────────────────────────────────────────────

app = FastAPI(
    title       = cfg.app_name,
    version     = cfg.app_version,
    description = (
        "Universal encoding, hashing, JWT, compression and developer-utility API. "
        "Stateless — no user content is stored or logged."
    ),
    openapi_tags = [
        {"name": "encoding",    "description": "Encode and decode text in 24 formats"},
        {"name": "hashing",     "description": "Cryptographic hash functions"},
        {"name": "jwt",         "description": "JSON Web Token tools"},
        {"name": "compression", "description": "Compress and decompress data"},
        {"name": "dev-tools",   "description": "UUID, password, color, slug, timestamp"},
        {"name": "system",      "description": "Health check and metadata"},
    ],
    lifespan  = lifespan,
    docs_url  = "/docs",
    redoc_url = "/redoc",
)


# ─────────────────────────────────────────────
# MIDDLEWARE  (outermost first)
# ─────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins     = cfg.cors_origins,
    allow_credentials = False,
    allow_methods     = ["GET", "POST", "OPTIONS"],
    allow_headers     = ["Content-Type", "Authorization", "X-API-Key"],
    max_age           = 600,
)

app.add_middleware(SecurityMiddleware)


# ─────────────────────────────────────────────
# EXCEPTION HANDLERS
# ─────────────────────────────────────────────

@app.exception_handler(ValueError)
async def value_error_handler(_: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(
        status_code = 422,
        content     = ErrorResponse(error="Validation Error", detail=str(exc), code=422).model_dump(),
    )


@app.exception_handler(Exception)
async def generic_error_handler(_: Request, exc: Exception) -> JSONResponse:
    log.error("Unhandled %s: %s", type(exc).__name__, exc)
    return JSONResponse(
        status_code = 500,
        content     = ErrorResponse(
            error  = "Internal Server Error",
            detail = "An unexpected error occurred",
            code   = 500,
        ).model_dump(),
    )


# ─────────────────────────────────────────────
# ROUTERS
# ─────────────────────────────────────────────

app.include_router(encoding.router)
app.include_router(hashing.router)    # /api/hash/all and /verify registered BEFORE /{algo}
app.include_router(jwt.router)
app.include_router(compression.router)
app.include_router(devtools.router)


# ─────────────────────────────────────────────
# SYSTEM ROUTES
# ─────────────────────────────────────────────

@app.get("/", tags=["system"], summary="API root")
async def root() -> Dict[str, Any]:
    return {
        "name":    cfg.app_name,
        "version": cfg.app_version,
        "docs":    "/docs",
        "redoc":   "/redoc",
        "health":  "/health",
    }


@app.get("/health", tags=["system"], summary="Health check")
async def health() -> Dict[str, Any]:
    return {
        "status":    "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version":   cfg.app_version,
    }


@app.get("/api/tools", tags=["system"], summary="List all available algorithms")
async def list_tools() -> Dict[str, Any]:
    return {
        "encoding_algorithms":    encoders.list_algorithms(),
        "hash_algorithms":        hashers.list_algorithms(),
        "compression_algorithms": compressors.list_algorithms(),
        "jwt_algorithms":         ["HS256", "HS384", "HS512"],
    }
