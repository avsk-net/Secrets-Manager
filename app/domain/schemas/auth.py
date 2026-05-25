"""
Pydantic v2 schemas for authentication endpoints.

Schema design principles:
- Request schemas: strict validation, no extra fields allowed
- Response schemas: exclude sensitive fields (password_hash, etc.)
- Passwords validated for minimum complexity in LoginRequest
  (actual complexity rules live in auth_service.py for user creation)
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=256)

    model_config = {"extra": "forbid"}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expiry
    scope: list[str]

    model_config = {"extra": "forbid"}


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)

    model_config = {"extra": "forbid"}


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)

    model_config = {"extra": "forbid"}


class TokenPayload(BaseModel):
    """Internal representation of a decoded JWT access token."""

    sub: str           # user UUID as string
    username: str
    role: str
    scopes: list[str]
    jti: str           # JWT ID for revocation checking
    iat: int           # issued-at (Unix timestamp)
    exp: int           # expiry (Unix timestamp)
    iss: str
    aud: str | list[str]

    model_config = {"extra": "allow"}


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=16, max_length=256)

    model_config = {"extra": "forbid"}

    @field_validator("new_password")
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
