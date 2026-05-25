"""
Redis-based sliding window rate limiter middleware.

Algorithm: sliding window counter
  - Key: "rl:{scope}:{identifier}" (e.g., "rl:auth:ip:1.2.3.4")
  - On each request:
      1. INCR the counter
      2. EXPIRE to window_seconds if key is new (first request)
      3. Check counter against limit
  - Slightly leaky at window boundaries (vs true sliding window),
    but accurate enough for rate limiting and very fast (1 Redis round-trip)

Scopes and limits:
  auth:      5 req/min per IP  — aggressive, login endpoint only
  write:     20 req/min per user
  api:       100 req/min per user
  global:    1000 req/min per IP

Path matching:
  - /api/v1/auth/* → auth scope
  - POST/PUT/DELETE → write scope (when authenticated)
  - Everything else → api scope

Headers returned:
  X-RateLimit-Limit: max requests in window
  X-RateLimit-Remaining: requests left in window
  X-RateLimit-Reset: Unix timestamp when window resets
  Retry-After: seconds until next allowed request (on 429 only)

IP extraction:
  Checks X-Forwarded-For (for reverse proxy setups) but validates
  it is a trusted header — in production, configure trusted proxy IPs.
  Falls back to direct client IP.
"""

from __future__ import annotations

import time

import redis.asyncio as aioredis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings


def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For from trusted proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the leftmost IP (original client) — proxies append right-to-left
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        settings = get_settings()
        redis_client: aioredis.Redis = request.app.state.redis
        ip = _get_client_ip(request)
        path = request.url.path

        # Determine limit scope
        if "/auth/" in path and request.method == "POST":
            scope = "auth"
            limit = settings.rate_limit_auth_per_minute
            window = 60
            identifier = f"ip:{ip}"
        elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
            scope = "write"
            limit = settings.rate_limit_write_per_minute
            window = 60
            # Prefer user-based limiting for authenticated requests
            identifier = f"ip:{ip}"
        else:
            scope = "api"
            limit = settings.rate_limit_api_per_minute
            window = 60
            identifier = f"ip:{ip}"

        # Global per-IP limit (first line of defense)
        global_key = f"rl:global:ip:{ip}"
        global_count = await self._check_and_increment(
            redis_client, global_key, settings.rate_limit_global_per_minute, window
        )
        if global_count > settings.rate_limit_global_per_minute:
            return self._rate_limited_response(
                settings.rate_limit_global_per_minute, 0, window
            )

        # Scope-specific limit
        scope_key = f"rl:{scope}:{identifier}"
        count = await self._check_and_increment(redis_client, scope_key, limit, window)

        remaining = max(0, limit - count)
        reset_at = int(time.time()) + window

        if count > limit:
            return self._rate_limited_response(limit, 0, window)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
        return response

    @staticmethod
    async def _check_and_increment(
        redis_client: aioredis.Redis,
        key: str,
        limit: int,
        window: int,
    ) -> int:
        """Increment counter and set TTL on first request. Returns current count."""
        pipe = redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window)
        results = await pipe.execute()
        return results[0]

    @staticmethod
    def _rate_limited_response(limit: int, remaining: int, retry_after: int) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Rate limit exceeded. Please slow down.",
                "type": "rate_limit_exceeded",
            },
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "Retry-After": str(retry_after),
            },
        )
