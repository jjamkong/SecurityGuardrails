from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from sg.checks.base import ScanContext
from sg.http_client import Probe, TlsInfo
from sg.scope import build_scope


def _make_probe(**kw: Any) -> Probe:
    base: dict[str, Any] = {
        "url": "https://app.test/",
        "final_url": "https://app.test/",
        "status_code": 200,
        "headers": {},
        "set_cookies": [],
        "body": "",
        "scheme": "https",
        "error": None,
    }
    base.update(kw)
    return Probe(**base)


def _make_ctx(
    probe: Probe | None = None,
    tls: TlsInfo | None = None,
    fetch: Callable[[str], Probe] | None = None,
) -> ScanContext:
    probe = probe if probe is not None else _make_probe()
    scope = build_scope("https://app.test/", "tester", "auth-1")

    def default_fetch(url: str) -> Probe:
        return _make_probe(url=url, final_url=url, status_code=404, body="")

    return ScanContext(scope=scope, probe=probe, fetch=fetch or default_fetch, tls=tls)


@pytest.fixture
def probe_factory() -> Callable[..., Probe]:
    return _make_probe


@pytest.fixture
def ctx_factory() -> Callable[..., ScanContext]:
    return _make_ctx
