from __future__ import annotations

from ..models import Confidence, Finding, Severity
from .base import ScanContext

# (헤더명, 제목, 심각도, CWE, remediation_key)
_HEADERS: list[tuple[str, str, Severity, str, str]] = [
    ("strict-transport-security", "HSTS 헤더 누락", Severity.medium, "CWE-693", "missing_hsts"),
    (
        "content-security-policy",
        "Content-Security-Policy 헤더 누락",
        Severity.medium,
        "CWE-693",
        "missing_csp",
    ),
    (
        "x-frame-options",
        "X-Frame-Options 헤더 누락 (클릭재킹)",
        Severity.medium,
        "CWE-1021",
        "missing_xfo",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options 헤더 누락",
        Severity.low,
        "CWE-693",
        "missing_xcto",
    ),
    (
        "referrer-policy",
        "Referrer-Policy 헤더 누락",
        Severity.low,
        "CWE-200",
        "missing_referrer_policy",
    ),
]


def _csp_frame_ancestors_ok(csp_value: str) -> bool:
    """CSP에 frame-ancestors 지시자가 있고 실제로 프레이밍을 제한하면 True (대소문자 무시)."""
    for directive in csp_value.lower().split(";"):
        directive = directive.strip()
        if directive.startswith("frame-ancestors"):
            value = directive[len("frame-ancestors") :].strip()
            return value not in ("", "*")  # '*'/빈 값은 미보호로 간주
    return False


class SecurityHeadersCheck:
    id = "headers"
    name = "보안 헤더 점검"

    def run(self, ctx: ScanContext) -> list[Finding]:
        probe = ctx.probe
        if probe.error or probe.status_code == 0:
            return []
        headers = probe.headers
        findings: list[Finding] = []
        for name, title, severity, cwe, key in _HEADERS:
            # HSTS는 HTTPS에서만 유효
            if name == "strict-transport-security" and probe.scheme != "https":
                continue
            # 클릭재킹은 CSP frame-ancestors로도 방어 가능 (실제 제한이 있을 때만 인정)
            if name == "x-frame-options" and _csp_frame_ancestors_ok(
                headers.get("content-security-policy", "")
            ):
                continue
            if name not in headers:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=title,
                        severity=severity,
                        confidence=Confidence.high,
                        location=probe.final_url,
                        evidence=f"응답 헤더에 '{name}' 없음",
                        cwe=cwe,
                        owasp="A05:2021 보안 구성 오류",
                        remediation_key=key,
                    )
                )
        return findings
