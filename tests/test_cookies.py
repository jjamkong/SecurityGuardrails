from __future__ import annotations

from collections.abc import Callable

from sg.checks.base import ScanContext
from sg.checks.cookies import CookieCheck
from sg.http_client import Probe


def test_cookie_missing_all_flags(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(set_cookies=["sid=abc"]))
    keys = {f.remediation_key for f in CookieCheck().run(ctx)}
    assert keys == {"cookie_no_secure", "cookie_no_httponly", "cookie_no_samesite"}


def test_cookie_all_flags_present(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(set_cookies=["sid=abc; Secure; HttpOnly; SameSite=Lax"]))
    assert CookieCheck().run(ctx) == []


def test_cookie_value_not_leaked_in_evidence(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(set_cookies=["sid=SUPERSECRET"]))
    findings = CookieCheck().run(ctx)
    assert findings
    assert all("SUPERSECRET" not in f.evidence for f in findings)
