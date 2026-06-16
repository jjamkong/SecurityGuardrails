from __future__ import annotations

import pytest

from sg import authz


def test_no_domains_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SG_AUTHORIZED_DOMAINS", raising=False)
    assert authz.authorized_domains() == []


def test_match_domain_and_subdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_AUTHORIZED_DOMAINS", "next-securities.com, mycompany.com")
    assert authz.match_authorized_domain("devkact.next-securities.com") == "next-securities.com"
    assert authz.match_authorized_domain("mycompany.com") == "mycompany.com"


def test_no_match_for_third_party(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_AUTHORIZED_DOMAINS", "mycompany.com")
    assert authz.match_authorized_domain("www.naver.com") is None
    # 부분 문자열 우회 방지 (evil-mycompany.com 은 서브도메인이 아님)
    assert authz.match_authorized_domain("evil-mycompany.com") is None
