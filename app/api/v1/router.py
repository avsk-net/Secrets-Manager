"""Aggregate all v1 API routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import audit, auth, secrets, users

v1_router = APIRouter(prefix="/api/v1")

v1_router.include_router(auth.router)
v1_router.include_router(secrets.router)
v1_router.include_router(users.router)
v1_router.include_router(audit.router)
