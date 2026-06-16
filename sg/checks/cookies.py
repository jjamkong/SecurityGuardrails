from __future__ import annotations

from ..models import Confidence, Finding, Severity
from .base import ScanContext


def _parse_attrs(raw: str) -> tuple[set[str], str | None]:
    """Set-Cookie를 속성 토큰으로 분해. (속성명 집합, samesite 값) 반환.

    name=value(첫 토큰)는 제외하고 ';'로 분리해 정확히 비교한다(substring 오탐 방지).
    """
    parts = [p.strip() for p in raw.split(";")]
    attr_names: set[str] = set()
    samesite: str | None = None
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        attr_names.add(key)
        if key == "samesite":
            samesite = value.strip().lower()
    return attr_names, samesite


class CookieCheck:
    id = "cookies"
    name = "쿠키 플래그 점검"

    def run(self, ctx: ScanContext) -> list[Finding]:
        probe = ctx.probe
        findings: list[Finding] = []
        for raw in probe.set_cookies:
            name = raw.split("=", 1)[0].strip() or "(unnamed)"
            attrs, samesite = _parse_attrs(raw)
            # 데이터 보호: 쿠키 '값'은 증거에 담지 않고 이름/속성만 기록.
            if probe.scheme == "https" and "secure" not in attrs:
                findings.append(
                    self._finding(
                        name,
                        "Secure",
                        Severity.medium,
                        "CWE-614",
                        "cookie_no_secure",
                        probe.final_url,
                    )
                )
            if "httponly" not in attrs:
                findings.append(
                    self._finding(
                        name,
                        "HttpOnly",
                        Severity.medium,
                        "CWE-1004",
                        "cookie_no_httponly",
                        probe.final_url,
                    )
                )
            if samesite is None:
                findings.append(
                    self._finding(
                        name,
                        "SameSite",
                        Severity.low,
                        "CWE-1275",
                        "cookie_no_samesite",
                        probe.final_url,
                    )
                )
            elif samesite == "none":
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"쿠키 '{name}'의 SameSite=None (CSRF 보호 약화)",
                        severity=Severity.low,
                        confidence=Confidence.high,
                        location=probe.final_url,
                        evidence=f"Set-Cookie '{name}' SameSite=None",
                        cwe="CWE-1275",
                        owasp="A05:2021 보안 구성 오류",
                        remediation_key="cookie_samesite_none",
                    )
                )
        return findings

    def _finding(
        self, cookie: str, flag: str, severity: Severity, cwe: str, key: str, location: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            title=f"쿠키 '{cookie}'에 {flag} 속성 누락",
            severity=severity,
            confidence=Confidence.high,
            location=location,
            evidence=f"Set-Cookie '{cookie}'에 {flag} 미설정",
            cwe=cwe,
            owasp="A05:2021 보안 구성 오류",
            remediation_key=key,
        )
