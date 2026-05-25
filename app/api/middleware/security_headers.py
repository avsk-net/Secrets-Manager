"""
Security headers middleware — adds defensive HTTP response headers.

Headers and their purpose:
  Strict-Transport-Security: Force HTTPS; prevents SSL-stripping attacks.
    max-age=31536000 (1 year), includeSubDomains covers all subdomains.
    Only active when app_env=production.

  X-Content-Type-Options: nosniff
    Prevents browsers from MIME-sniffing the response (stops CSS/JS injection
    via attacker-controlled content with a misleading Content-Type).

  X-Frame-Options: DENY
    Prevents the UI from being embedded in iframes (clickjacking protection).
    Use SAMEORIGIN if you have a legitimate iframe use case.

  X-XSS-Protection: 0
    Disables the legacy XSS filter in old IE/Chrome versions.
    Modern apps rely on CSP; the old XSS filter can actually introduce
    vulnerabilities (XSS auditor bypass techniques are well-known).

  Content-Security-Policy:
    Only relevant if this API ever serves HTML. For pure JSON APIs,
    CSP is a defense-in-depth measure — the API itself doesn't produce
    HTML, but including it protects against future scope creep.

  Referrer-Policy: no-referrer
    Prevents secret tokens in URLs from leaking via Referer header.
    (Never put tokens in URLs — but this is a backstop.)

  Permissions-Policy: deny common browser features we don't use.

  Cache-Control: no-store, no-cache
    Prevents secrets from being cached by CDNs or browsers.
    Every response carries this — including list endpoints.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        response = await call_next(request)
        settings = get_settings()

        # HSTS: only in production (dev usually uses HTTP)
        if settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        # Prevent ANY caching of API responses — secrets must not be cached
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

        # Remove server identification headers (information disclosure)
        for header in ("server", "x-powered-by"):
            if header in response.headers:
                del response.headers[header]

        return response
