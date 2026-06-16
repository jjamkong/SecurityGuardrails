from __future__ import annotations

from ..models import Confidence, Finding, Severity
from .base import ScanContext


class TlsCheck:
    id = "tls"
    name = "TLS/인증서 점검"

    def run(self, ctx: ScanContext) -> list[Finding]:
        probe = ctx.probe
        findings: list[Finding] = []

        if probe.scheme != "https":
            findings.append(
                Finding(
                    check_id=self.id,
                    title="평문 HTTP 전송 (미암호화)",
                    severity=Severity.high,
                    confidence=Confidence.high,
                    location=probe.final_url or probe.url,
                    evidence=f"스킴이 '{probe.scheme or 'http'}' — TLS 미적용",
                    cwe="CWE-319",
                    owasp="A02:2021 암호화 실패",
                    remediation_key="plaintext_http",
                )
            )
            return findings

        tls = ctx.tls
        if tls is None or not tls.supported:
            findings.append(
                Finding(
                    check_id=self.id,
                    title="TLS 핸드셰이크 실패/미지원",
                    severity=Severity.medium,
                    confidence=Confidence.medium,
                    location=probe.final_url,
                    evidence=(tls.error if tls and tls.error else "TLS 연결 불가"),
                    cwe="CWE-326",
                    owasp="A02:2021 암호화 실패",
                    remediation_key="tls_handshake",
                )
            )
            return findings

        expired = tls.days_to_expiry is not None and tls.days_to_expiry < 0

        # 만료/자가서명/기타 검증실패를 단일 finding으로 — 중복 보고 방지
        if expired:
            findings.append(
                self._f(
                    "인증서 만료됨", Severity.high, "CWE-298", "tls_expired", tls, probe.final_url
                )
            )
        elif tls.self_signed:
            findings.append(
                self._f(
                    "자가서명 인증서",
                    Severity.medium,
                    "CWE-295",
                    "tls_self_signed",
                    tls,
                    probe.final_url,
                )
            )
        elif tls.validates is False:
            findings.append(
                self._f(
                    "인증서 검증 실패",
                    Severity.medium,
                    "CWE-295",
                    "tls_invalid_cert",
                    tls,
                    probe.final_url,
                )
            )
        elif tls.days_to_expiry is not None and tls.days_to_expiry <= 14:
            findings.append(
                self._f(
                    "인증서 만료 임박 (≤14일)",
                    Severity.medium,
                    "CWE-298",
                    "tls_expiring",
                    tls,
                    probe.final_url,
                )
            )

        return findings

    def _f(
        self, title: str, severity: Severity, cwe: str, key: str, tls: object, location: str
    ) -> Finding:
        not_after = getattr(tls, "not_after", None)
        issuer = getattr(tls, "issuer", None)
        return Finding(
            check_id=self.id,
            title=title,
            severity=severity,
            confidence=Confidence.high,
            location=location,
            evidence=f"issuer={issuer}; not_after={not_after}",
            cwe=cwe,
            owasp="A02:2021 암호화 실패",
            remediation_key=key,
        )
