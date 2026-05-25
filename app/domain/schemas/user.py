"""Pydantic v2 schemas for user management endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.domain.enums import UserRole


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: EmailStr
    password: str = Field(..., min_length=16, max_length=256)
    role: UserRole = UserRole.READONLY

    model_config = {"extra": "forbid"}

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in v)
        if not (has_upper and has_lower and has_digit and has_special):
            raise ValueError(
                "Password must contain uppercase, lowercase, digit, and special character"
            )
        return v


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    is_locked: bool | None = None

    model_config = {"extra": "forbid"}


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    role: UserRole
    is_active: bool
    is_locked: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    items: list[UserResponse]
    total: int
    page: int
    page_size: int
