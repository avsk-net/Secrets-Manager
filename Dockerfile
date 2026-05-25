# ── Builder stage ─────────────────────────────────────────────────────────────
# Multi-stage build: install deps in builder, copy only what's needed to runtime.
# This keeps the final image small and avoids shipping build tools.
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies (for cryptography C extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies first (cache layer)
COPY pyproject.toml .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir ".[dev]" 2>/dev/null || \
    pip install --no-cache-dir \
        fastapi>=0.115.0 \
        uvicorn[standard]>=0.32.0 \
        sqlalchemy[asyncio]>=2.0.36 \
        asyncpg>=0.30.0 \
        alembic>=1.14.0 \
        pydantic[email]>=2.10.0 \
        pydantic-settings>=2.7.0 \
        cryptography>=43.0.0 \
        argon2-cffi>=23.1.0 \
        "python-jose[cryptography]>=3.3.0" \
        "redis[asyncio]>=5.2.0" \
        "celery[redis]>=5.4.0" \
        httpx>=0.28.0 \
        structlog>=24.4.0 \
        python-ulid>=3.0.0 \
        python-multipart>=0.0.19

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: run as non-root user
RUN groupadd -r smgr && useradd -r -g smgr -s /sbin/nologin smgr

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini .
COPY scripts/ scripts/

# Set ownership
RUN chown -R smgr:smgr /app

USER smgr

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
