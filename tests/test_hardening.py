from __future__ import annotations

from collections.abc import Callable

from sg.checks.base import ScanContext
from sg.checks.cookies import CookieCheck
from sg.checks.headers import SecurityHeadersCheck
from sg.checks.info_disclosure import InfoDisclosureCheck
from sg.checks.tls import TlsCheck
from sg.http_client import Probe, TlsInfo
from sg.scope import AuthorizationError, build_scope, enforce_authorization, is_in_scope

CtxFactory = Callable[..., ScanContext]
ProbeFactory = Callable[..., Probe]


# --- cookies ---
def test_samesite_none_flagged(ctx_factory: CtxFactory, probe_factory: ProbeFactory) -> None:
    ctx = ctx_factory(probe=probe_factory(set_cookies=["sid=abc; Secure; HttpOnly; SameSite=None"]))
    keys = {f.remediation_key for f in CookieCheck().run(ctx)}
    assert keys == {"cookie_samesite_none"}


def test_cookie_no_false_negative_from_value(
    ctx_factory: CtxFactory, probe_factory: ProbeFactory
) -> None:
    # 값/이름에 'secure'·'httponly' 문자열이 있어도 속성이 아니면 누락으로 정확히 탐지
    ctx = ctx_factory(
        probe=probe_factory(set_cookies=["theme=secure; httponly_pref=1; SameSite=Lax"])
    )
    keys = {f.remediation_key for f in CookieCheck().run(ctx)}
    assert "cookie_no_secure" in keys
    assert "cookie_no_httponly" in keys


# --- info disclosure (.env 오탐 방지) ---
def _fetch_for(path: str, probe: Probe) -> Callable[[str], Probe]:
    def fetch(url: str) -> Probe:
        if url.endswith(path):
            return probe
        return Probe(
            url=url,
            final_url=url,
            status_code=404,
            headers={},
            set_cookies=[],
            body="",
            scheme="https",
        )

    return fetch


def test_env_html_fallback_not_flagged(
    ctx_factory: CtxFactory, probe_factory: ProbeFactory
) -> None:
    env = Probe(
        url="x",
        final_url="x",
        status_code=200,
        headers={"content-type": "text/html"},
        set_cookies=[],
        body="<!doctype html><html>app</html>",
        scheme="https",
    )
    ctx = ctx_factory(probe=probe_factory(headers={}), fetch=_fetch_for("/.env", env))
    keys = {f.remediation_key for f in InfoDisclosureCheck().run(ctx)}
    assert "exposed_env" not in keys


def test_env_keyvalue_flagged_without_leaking_secret(
    ctx_factory: CtxFactory, probe_factory: ProbeFactory
) -> None:
    env = Probe(
        url="x",
        final_url="x",
        status_code=200,
        headers={"content-type": "text/plain"},
        set_cookies=[],
        body="DB_PASSWORD=topsecret\nAPI_KEY=abc123\n",
        scheme="https",
    )
    ctx = ctx_factory(probe=probe_factory(headers={}), fetch=_fetch_for("/.env", env))
    findings = InfoDisclosureCheck().run(ctx)
    assert any(f.remediation_key == "exposed_env" for f in findings)
    assert all("topsecret" not in f.evidence for f in findings)  # 통제 ⑥ 비밀 미노출


def test_git_detached_head_detected(ctx_factory: CtxFactory, probe_factory: ProbeFactory) -> None:
    head = Probe(
        url="x",
        final_url="x",
        status_code=200,
        headers={"content-type": "text/plain"},
        set_cookies=[],
        body="a" * 40,
        scheme="https",  # 40 hex = detached HEAD
    )
    ctx = ctx_factory(probe=probe_factory(headers={}), fetch=_fetch_for("/.git/HEAD", head))
    keys = {f.remediation_key for f in InfoDisclosureCheck().run(ctx)}
    assert "exposed_git" in keys


# --- tls dedup ---
def test_expired_takes_precedence_over_invalid(
    ctx_factory: CtxFactory, probe_factory: ProbeFactory
) -> None:
    tls = TlsInfo(
        host="app.test",
        port=443,
        supported=True,
        validates=False,
        self_signed=False,
        days_to_expiry=-5,
    )
    ctx = ctx_factory(probe=probe_factory(scheme="https"), tls=tls)
    keys = {f.remediation_key for f in TlsCheck().run(ctx)}
    assert keys == {"tls_expired"}  # 중복 보고 없음


# --- headers CSP frame-ancestors ---
def test_frame_ancestors_wildcard_not_satisfying(
    ctx_factory: CtxFactory, probe_factory: ProbeFactory
) -> None:
    ctx = ctx_factory(probe=probe_factory(headers={"content-security-policy": "frame-ancestors *"}))
    keys = {f.remediation_key for f in SecurityHeadersCheck().run(ctx)}
    assert "missing_xfo" in keys


def test_frame_ancestors_uppercase_none_satisfies(
    ctx_factory: CtxFactory, probe_factory: ProbeFactory
) -> None:
    ctx = ctx_factory(
        probe=probe_factory(headers={"content-security-policy": "FRAME-ANCESTORS 'none'"})
    )
    keys = {f.remediation_key for f in SecurityHeadersCheck().run(ctx)}
    assert "missing_xfo" not in keys


# --- scope scheme allowlist ---
def test_enforce_rejects_non_http_scheme() -> None:
    scope = build_scope("ftp://app.test/", "me", "a1")
    try:
        enforce_authorization(scope)
        raise AssertionError("ftp scheme should be rejected")
    except AuthorizationError:
        pass


def test_is_in_scope_rejects_non_http_scheme() -> None:
    scope = build_scope("https://app.test/", "me", "a1")
    assert not is_in_scope("ftp://app.test/file", scope)
