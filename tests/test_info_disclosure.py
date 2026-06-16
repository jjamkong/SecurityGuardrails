from __future__ import annotations

from collections.abc import Callable

from sg.checks.base import ScanContext
from sg.checks.info_disclosure import InfoDisclosureCheck
from sg.http_client import Probe
from sg.scope import AuthorizationError


def test_exposed_git_detected(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    def fake_fetch(url: str) -> Probe:
        if url.endswith("/.git/HEAD"):
            return Probe(
                url=url,
                final_url=url,
                status_code=200,
                headers={},
                set_cookies=[],
                body="ref: refs/heads/main",
                scheme="https",
            )
        return Probe(
            url=url,
            final_url=url,
            status_code=404,
            headers={},
            set_cookies=[],
            body="",
            scheme="https",
        )

    ctx = ctx_factory(probe=probe_factory(headers={"server": "nginx"}), fetch=fake_fetch)
    keys = {f.remediation_key for f in InfoDisclosureCheck().run(ctx)}
    assert "exposed_git" in keys


def test_scope_isolation_does_not_crash_check(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    def blocking_fetch(url: str) -> Probe:
        raise AuthorizationError("스코프 밖 차단")

    ctx = ctx_factory(probe=probe_factory(headers={}), fetch=blocking_fetch)
    findings = InfoDisclosureCheck().run(ctx)  # 예외가 전파되지 않아야 함
    assert all(f.remediation_key != "exposed_git" for f in findings)


def test_version_banner_detected(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(headers={"server": "Apache/2.4.49"}))
    keys = {f.remediation_key for f in InfoDisclosureCheck().run(ctx)}
    assert "version_banner" in keys
