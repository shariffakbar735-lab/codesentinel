from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: EmailStr
    created_at: datetime


class ScanCreate(BaseModel):
    target: str = Field(min_length=8, max_length=2048)
    specification: str = Field(min_length=2, max_length=1_000_000)


class ScanView(BaseModel):
    id: str
    target: str
    status: Literal["Pending", "Running", "Completed", "Failed", "Cancelled"]
    endpoint_count: int
    tested_checks: int
    skipped_checks: int
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None
