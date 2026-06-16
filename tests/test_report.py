from __future__ import annotations

from datetime import datetime, timezone

from sg.models import Confidence, Finding, Severity
from sg.report import assemble, build_summary, enrich_remediation
from sg.scope import build_scope


def _finding(severity: Severity, key: str | None = None) -> Finding:
    return Finding(
        check_id="c",
        title=severity.value,
        severity=severity,
        confidence=Confidence.high,
        location="https://app.test/",
        remediation_key=key,
    )


def test_enrich_attaches_guide() -> None:
    f = _finding(Severity.medium, "missing_hsts")
    enrich_remediation([f])
    assert f.remediation is not None
    assert f.remediation.how  # 단계가 비어있지 않음


def test_summary_counts() -> None:
    findings = [_finding(Severity.high), _finding(Severity.high), _finding(Severity.low)]
    summary = build_summary(findings)
    assert summary.total == 3
    assert summary.by_severity["high"] == 2
    assert summary.by_severity["low"] == 1


def test_assemble_sorts_by_severity_and_enriches() -> None:
    scope = build_scope("https://app.test/", "me", "a1")
    findings = [_finding(Severity.low), _finding(Severity.high, "missing_hsts")]
    now = datetime.now(timezone.utc)
    report = assemble("scan1", scope, now, now, findings, [])
    assert report.findings[0].severity == Severity.high  # critical→info 정렬
    assert report.findings[0].remediation is not None
    assert report.summary.total == 2
