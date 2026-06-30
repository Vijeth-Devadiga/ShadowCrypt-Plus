"""
ShadowCrypt++ — Security Middleware
Thread-safe rate limiter, security headers, request size guard.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Tuple

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import get_settings

log = logging.getLogger("shadowcrypt.middleware")
cfg = get_settings()


# ─────────────────────────────────────────────
# RATE LIMITER  (token bucket, asyncio-safe)
# ─────────────────────────────────────────────

class RateLimiter:
    """
    Sliding-window rate limiter.
    asyncio.Lock ensures correctness under concurrent requests.
    """

    def __init__(self, max_requests: int, window: int) -> None:
        self._max    = max_requests
        self._window = window
        self._store: Dict[str, List[float]] = {}
        self._lock   = asyncio.Lock()

    async def check(self, key: str) -> Tuple[bool, int, int]:
        """
        Returns (allowed, remaining, reset_in_seconds).
        """
        async with self._lock:
            now    = time.monotonic()
            cutoff = now - self._window
            bucket = [ts for ts in self._store.get(key, []) if ts > cutoff]

            remaining = self._max - len(bucket)
            reset     = int(self._window - (now - bucket[0])) if bucket else self._window

            if len(bucket) >= self._max:
                return False, 0, reset

            bucket.append(now)
            self._store[key] = bucket
            return True, max(0, remaining - 1), reset


_limiter = RateLimiter(cfg.rate_limit_requests, cfg.rate_limit_window)


# ─────────────────────────────────────────────
# SECURITY HEADERS
# ─────────────────────────────────────────────

_SECURITY_HEADERS: Dict[str, str] = {
    "X-Content-Type-Options":   "nosniff",
    "X-Frame-Options":          "DENY",
    "X-XSS-Protection":         "1; mode=block",
    "Referrer-Policy":          "strict-origin-when-cross-origin",
    "Permissions-Policy":       "geolocation=(), camera=(), microphone=()",
    "Strict-Transport-Security":"max-age=63072000; includeSubDomains; preload",
    "Cache-Control":            "no-store, no-cache, must-revalidate",
    "X-Powered-By":             "ShadowCrypt++",
    "Content-Security-Policy": (
        "default-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'none'"
    ),
}


# ─────────────────────────────────────────────
# MIDDLEWARE
# ─────────────────────────────────────────────

class SecurityMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:

        # ── 1. Request size guard ──────────────────────────────
        cl = request.headers.get("content-length")
        if cl and int(cl) > cfg.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": "Request body too large", "max_bytes": cfg.max_body_bytes},
            )

        # ── 2. Rate limiting ───────────────────────────────────
        client_ip = _resolve_ip(request)
        allowed, remaining, reset = await _limiter.check(client_ip)

        rate_headers = {
            "X-RateLimit-Limit":     str(cfg.rate_limit_requests),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset":     str(reset),
        }

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "retry_after": reset},
                headers={"Retry-After": str(reset), **rate_headers},
            )

        # ── 3. Process ─────────────────────────────────────────
        t0       = time.perf_counter()
        response = await call_next(request)
        elapsed  = (time.perf_counter() - t0) * 1000

        # ── 4. Attach security + rate headers ──────────────────
        for k, v in _SECURITY_HEADERS.items():
            response.headers[k] = v
        for k, v in rate_headers.items():
            response.headers[k] = v
        response.headers["X-Response-Time"] = f"{elapsed:.2f}ms"

        # ── 5. Log (no user content) ───────────────────────────
        log.info(
            "%s %s %d %.1fms ip=%s",
            request.method, request.url.path,
            response.status_code, elapsed, client_ip,
        )

        return response


def _resolve_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
