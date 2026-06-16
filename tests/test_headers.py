from __future__ import annotations

from collections.abc import Callable

from sg.checks.base import ScanContext
from sg.checks.headers import SecurityHeadersCheck
from sg.http_client import Probe

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


def test_missing_headers_flagged(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(headers={}))
    findings = SecurityHeadersCheck().run(ctx)
    keys = {f.remediation_key for f in findings}
    assert "missing_hsts" in keys
    assert "missing_csp" in keys
    assert len(findings) == 5


def test_all_headers_present_no_findings(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(headers=dict(GOOD_HEADERS)))
    assert SecurityHeadersCheck().run(ctx) == []


def test_hsts_skipped_on_http(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(scheme="http", final_url="http://app.test/", headers={}))
    keys = {f.remediation_key for f in SecurityHeadersCheck().run(ctx)}
    assert "missing_hsts" not in keys


def test_xfo_satisfied_by_csp_frame_ancestors(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    headers = {"content-security-policy": "frame-ancestors 'none'"}
    ctx = ctx_factory(probe=probe_factory(headers=headers))
    keys = {f.remediation_key for f in SecurityHeadersCheck().run(ctx)}
    assert "missing_xfo" not in keys
