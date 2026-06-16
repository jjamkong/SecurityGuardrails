from __future__ import annotations

from collections.abc import Callable

from sg.checks.base import ScanContext
from sg.checks.tls import TlsCheck
from sg.http_client import Probe, TlsInfo


def test_plaintext_http_flagged(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(scheme="http", final_url="http://app.test/"))
    keys = {f.remediation_key for f in TlsCheck().run(ctx)}
    assert "plaintext_http" in keys


def test_https_handshake_failure(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    ctx = ctx_factory(probe=probe_factory(scheme="https"), tls=None)
    keys = {f.remediation_key for f in TlsCheck().run(ctx)}
    assert "tls_handshake" in keys


def test_expired_certificate(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    tls = TlsInfo(
        host="app.test",
        port=443,
        supported=True,
        validates=True,
        self_signed=False,
        days_to_expiry=-3,
    )
    ctx = ctx_factory(probe=probe_factory(scheme="https"), tls=tls)
    keys = {f.remediation_key for f in TlsCheck().run(ctx)}
    assert "tls_expired" in keys


def test_self_signed_certificate(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    tls = TlsInfo(
        host="app.test",
        port=443,
        supported=True,
        validates=False,
        self_signed=True,
        days_to_expiry=100,
    )
    ctx = ctx_factory(probe=probe_factory(scheme="https"), tls=tls)
    keys = {f.remediation_key for f in TlsCheck().run(ctx)}
    assert "tls_self_signed" in keys
    assert "tls_invalid_cert" not in keys  # 자가서명은 별도로만 보고


def test_valid_certificate_no_findings(
    ctx_factory: Callable[..., ScanContext], probe_factory: Callable[..., Probe]
) -> None:
    tls = TlsInfo(
        host="app.test",
        port=443,
        supported=True,
        validates=True,
        self_signed=False,
        days_to_expiry=200,
    )
    ctx = ctx_factory(probe=probe_factory(scheme="https"), tls=tls)
    assert TlsCheck().run(ctx) == []
