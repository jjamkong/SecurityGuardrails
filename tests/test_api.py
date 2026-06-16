from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sg.api import app

client = TestClient(app)


def test_health() -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_scan_fail_closed_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SG_API_KEY", raising=False)
    resp = client.post(
        "/scans",
        json={"target": "https://app.test/", "authorized_by": "me", "authorization_id": "a1"},
    )
    assert resp.status_code == 503  # 키 미설정 → fail-closed


def test_scan_requires_authorization_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    resp = client.post(
        "/scans",
        headers={"X-API-Key": "k"},
        json={"target": "https://app.test/", "authorized_by": "me"},  # authorization_id 누락
    )
    assert resp.status_code == 422


def test_scan_rejects_bad_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SG_API_KEY", "k")
    resp = client.post(
        "/scans",
        headers={"X-API-Key": "wrong"},
        json={"target": "https://app.test/", "authorized_by": "me", "authorization_id": "a1"},
    )
    assert resp.status_code == 401
