"""
Request ID middleware — injects a unique X-Request-ID header on every request.

Request IDs enable:
  - Cross-log correlation: tie API logs, audit logs, and DB logs to one request
  - Client-side tracing: clients can echo the ID back in bug reports
  - Distributed tracing: forward X-Request-ID to downstream services

If the client sends X-Request-ID, we use it (after validation).
Otherwise, we generate a new UUID4.

Security note: we validate client-supplied IDs to prevent log injection.
"""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        # Accept client-supplied ID or generate a new one
        client_id = request.headers.get("X-Request-ID", "")
        try:
            # Validate: must be a valid UUID if supplied
            request_id = str(uuid.UUID(client_id)) if client_id else str(uuid.uuid4())
        except ValueError:
            # Invalid format — generate a new one, don't use attacker-controlled value
            request_id = str(uuid.uuid4())

        # Make request_id available to route handlers via request.state
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
