from __future__ import annotations

from datetime import datetime

from . import remediation
from .models import Finding, ScanReport, ScanSummary, ScopeAuthorization

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def enrich_remediation(findings: list[Finding]) -> list[Finding]:
    """각 finding에 조치 가이드를 결합한다(필수 산출물 — 통제 ⑦, 방어 관점만)."""
    for f in findings:
        if f.remediation is None and f.remediation_key:
            f.remediation = remediation.get(f.remediation_key)
    return findings


def build_summary(findings: list[Finding]) -> ScanSummary:
    by_sev: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return ScanSummary(total=len(findings), by_severity=by_sev)


def assemble(
    scan_id: str,
    scope: ScopeAuthorization,
    started_at: datetime,
    finished_at: datetime,
    findings: list[Finding],
    errors: list[str],
    tool: dict[str, str] | None = None,
) -> ScanReport:
    enrich_remediation(findings)
    findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))
    return ScanReport(
        scan_id=scan_id,
        target=scope.target,
        intensity=scope.intensity,
        started_at=started_at,
        finished_at=finished_at,
        authorized_by=scope.authorized_by,
        authorization_id=scope.authorization_id,
        findings=findings,
        summary=build_summary(findings),
        tool=tool or {},
        errors=errors,
    )
