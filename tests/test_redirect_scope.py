from __future__ import annotations

import pytest

from sg.http_client import Probe, follow_redirects_in_scope
from sg.scope import AuthorizationError


def _probe(status: int = 200, location: str | None = None, url: str = "https://app.test/") -> Probe:
    headers = {"location": location} if location else {}
    return Probe(
        url=url,
        final_url=url,
        status_code=status,
        headers=headers,
        set_cookies=[],
        body="",
        scheme="https",
    )


def _allowed(url: str) -> bool:
    return "app.test/" in url or url.rstrip("/").endswith("app.test")


def test_follows_in_scope_redirect() -> None:
    def fetch_one(u: str) -> Probe:
        if u == "https://app.test/":
            return _probe(302, location="https://app.test/next", url=u)
        return _probe(200, url=u)

    result = follow_redirects_in_scope(fetch_one, "https://app.test/", _allowed)
    assert result.status_code == 200
    assert result.final_url == "https://app.test/next"


def test_blocks_out_of_scope_redirect() -> None:
    blocked: list[str] = []

    def fetch_one(u: str) -> Probe:
        return _probe(302, location="https://evil.test/", url=u)

    with pytest.raises(AuthorizationError):
        follow_redirects_in_scope(
            fetch_one, "https://app.test/", _allowed, on_blocked=blocked.append
        )
    assert blocked == ["https://evil.test/"]  # 외부 호스트로 실제 요청은 나가지 않음


def test_blocks_initial_out_of_scope() -> None:
    def fetch_one(u: str) -> Probe:
        return _probe(200, url=u)

    with pytest.raises(AuthorizationError):
        follow_redirects_in_scope(fetch_one, "https://evil.test/", _allowed)
