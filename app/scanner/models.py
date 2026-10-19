from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(StrEnum):
    informational = "Informational"
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class Verification(StrEnum):
    confirmed = "Confirmed"
    potential = "Potential"
    inconclusive = "Inconclusive"
    not_tested = "Not Tested"


class Endpoint(BaseModel):
    method: str
    path: str
    summary: str | None = None
    parameters: list[dict] = Field(default_factory=list)
    security: list[dict] | None = None
    request_schema: dict | None = None
    responses: dict = Field(default_factory=dict)
    eligible: bool = True
    skip_reason: str | None = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    endpoint: str
    method: str
    check_name: str
    title: str
    description: str
    severity: Severity
    verification: Verification
    evidence: dict
    remediation: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CheckResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    tested: int = 0
    skipped: int = 0
    notes: list[str] = Field(default_factory=list)
