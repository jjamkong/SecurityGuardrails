from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from sg import api
from sg.api import _is_loopback, app, require_access
from sg.models import Intensity, ScanReport, ScanSummary


def _make_request(headers: dict[str, str], client: tuple[str, int]) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/scans",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": client,
    }
    return Request(scope)


client = TestClient(app)

_BODY = {"target": "https://app.mycompany.com"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SG_API_KEY", raising=False)
    monkeypatch.delenv("SG_AUTHORIZED_DOMAINS", raising=False)
    monkeypatch.delenv("SG_ALLOW_NO_AUTH", raising=False)


def _dummy_report(scope: object, settings: object = None) -> ScanReport:
    now = datetime.now(timezone.utc)
    return ScanReport(
        scan_id="test",
        target="https://app.mycompany.com/",
        intensity=Intensity.passive,
        started_at=now,
        finished_at=now,
        authorized_by="web-ui",
        authorization_id="web-x",
        summary=ScanSummary(total=0, by_severity={}),
    )


def test_health() -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_index_served() -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "SecurityGuardrails" in resp.text


def test_config_public() -> None:
    resp = client.get("/config")
    assert resp.status_code == 200
    assert "authorized_domains" in resp.json()


def test_is_loopback() -> None:
    assert _is_loopback("127.0.0.1")
    assert _is_loopback("::1")
    assert _is_loopback("localhost")
    assert not _is_loopback("8.8.8.8")
    assert not _is_loopback("testclient")


def test_fail_closed_without_access(monkeypatch: pytest.MonkeyPatch) -> None:
    # 키도 no-auth도 없으면 거부
    assert client.post("/scans", json=_BODY).status_code == 503


def test_rejects_bad_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    assert client.post("/scans", headers={"X-API-Key": "wrong"}, json=_BODY).status_code == 401


def test_target_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    assert client.post("/scans", headers={"X-API-Key": "k"}, json={}).status_code == 422


def test_no_authorized_domains_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    assert client.post("/scans", headers={"X-API-Key": "k"}, json=_BODY).status_code == 503


def test_rejects_unauthorized_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    monkeypatch.setenv("SG_AUTHORIZED_DOMAINS", "mycompany.com")
    resp = client.post(
        "/scans", headers={"X-API-Key": "k"}, json={"target": "https://www.naver.com"}
    )
    assert resp.status_code == 403


def test_authorized_domain_runs_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    monkeypatch.setenv("SG_AUTHORIZED_DOMAINS", "mycompany.com")
    monkeypatch.setattr(api, "run_scan", _dummy_report)
    resp = client.post("/scans", headers={"X-API-Key": "k"}, json=_BODY)
    assert resp.status_code == 200
    assert resp.json()["target"] == "https://app.mycompany.com/"


def test_no_auth_mode_blocks_non_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    # no-auth 모드라도 비-localhost(TestClient='testclient') 요청은 거부
    monkeypatch.setenv("SG_ALLOW_NO_AUTH", "1")
    monkeypatch.setenv("SG_AUTHORIZED_DOMAINS", "mycompany.com")
    resp = client.post("/scans", json=_BODY)
    assert resp.status_code == 403
    assert "localhost" in resp.json()["detail"]


def test_no_auth_rejects_forwarded_header(monkeypatch: pytest.MonkeyPatch) -> None:
    # X-Forwarded-For 위조로 loopback 위장 시도 → 헤더 존재만으로 거부 (프록시 우회 차단)
    monkeypatch.setenv("SG_ALLOW_NO_AUTH", "1")
    with pytest.raises(HTTPException) as ei:
        require_access(_make_request({"x-forwarded-for": "127.0.0.1"}, ("127.0.0.1", 0)))
    assert ei.value.status_code == 403


def test_no_auth_allows_direct_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    # forwarded 헤더 없음 + 직접 loopback 피어 → 통과(예외 없음)
    monkeypatch.setenv("SG_ALLOW_NO_AUTH", "1")
    require_access(_make_request({}, ("127.0.0.1", 0)))


def test_no_auth_rejects_nonloopback_peer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_ALLOW_NO_AUTH", "1")
    with pytest.raises(HTTPException) as ei:
        require_access(_make_request({}, ("203.0.113.7", 0)))
    assert ei.value.status_code == 403
