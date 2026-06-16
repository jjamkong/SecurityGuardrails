from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class Intensity(str, Enum):
    passive = "passive"
    safe_active = "safe_active"
    full = "full"


class RemediationGuide(BaseModel):
    """취약점별 조치 가이드 (방어/수정 관점만 — 무기화 금지)."""

    summary: str
    why: str
    how: list[str]
    verification: str
    references: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    check_id: str
    title: str
    severity: Severity
    confidence: Confidence
    location: str
    evidence: str = ""
    description: str = ""
    cwe: str | None = None
    owasp: str | None = None
    remediation_key: str | None = None
    remediation: RemediationGuide | None = None


class ScopeAuthorization(BaseModel):
    """점검 승인·스코프. 승인된 자산만 점검한다는 대원칙(PLAN §0)을 코드로 강제."""

    target: str
    allowed_hosts: list[str]
    intensity: Intensity = Intensity.passive
    authorized_by: str
    authorization_id: str
    expires_at: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        return now > self.expires_at


class ScanSummary(BaseModel):
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)


class ScanReport(BaseModel):
    scan_id: str
    target: str
    intensity: Intensity
    started_at: datetime
    finished_at: datetime
    authorized_by: str
    authorization_id: str
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    tool: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
