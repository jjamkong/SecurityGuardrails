from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from sg import api
from sg.api import app
from sg.models import Intensity, ScanReport, ScanSummary

client = TestClient(app)

_VALID_BODY = {
    "target": "https://app.mycompany.com",
    "authorized_by": "me",
    "authorization_id": "a1",
}


def _dummy_report(scope: object, settings: object = None) -> ScanReport:
    now = datetime.now(timezone.utc)
    return ScanReport(
        scan_id="test",
        target="https://app.mycompany.com/",
        intensity=Intensity.passive,
        started_at=now,
        finished_at=now,
        authorized_by="me",
        authorization_id="a1",
        findings=[],
        summary=ScanSummary(total=0, by_severity={}),
    )


def test_health() -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_index_served() -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "SecurityGuardrails" in resp.text


def test_fail_closed_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SG_API_KEY", raising=False)
    assert client.post("/scans", json=_VALID_BODY).status_code == 503


def test_rejects_bad_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    resp = client.post("/scans", headers={"X-API-Key": "wrong"}, json=_VALID_BODY)
    assert resp.status_code == 401


def test_requires_authorization_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    resp = client.post(
        "/scans",
        headers={"X-API-Key": "k"},
        json={"target": "https://app.mycompany.com", "authorized_by": "me"},
    )
    assert resp.status_code == 422


def test_no_authorized_domains_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    monkeypatch.delenv("SG_AUTHORIZED_DOMAINS", raising=False)
    resp = client.post("/scans", headers={"X-API-Key": "k"}, json=_VALID_BODY)
    assert resp.status_code == 503


def test_rejects_unauthorized_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    monkeypatch.setenv("SG_AUTHORIZED_DOMAINS", "mycompany.com")
    resp = client.post(
        "/scans",
        headers={"X-API-Key": "k"},
        json={"target": "https://www.naver.com", "authorized_by": "me", "authorization_id": "a1"},
    )
    assert resp.status_code == 403  # 허용 도메인 밖 → 거부


def test_authorized_domain_runs_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    monkeypatch.setenv("SG_AUTHORIZED_DOMAINS", "mycompany.com")
    monkeypatch.setattr(api, "run_scan", _dummy_report)  # 실제 네트워크 호출 방지
    resp = client.post("/scans", headers={"X-API-Key": "k"}, json=_VALID_BODY)
    assert resp.status_code == 200
    assert resp.json()["target"] == "https://app.mycompany.com/"
