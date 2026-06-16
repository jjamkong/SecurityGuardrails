from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

from ..http_client import Probe
from ..models import Confidence, Finding, Severity
from ..scope import AuthorizationError
from .base import ScanContext

_HTML_RE = re.compile(r"<\s*(!doctype|html|head|body)\b", re.IGNORECASE)
_GIT_HEAD_RE = re.compile(r"^(ref:\s+refs/|[0-9a-f]{40}$)", re.IGNORECASE | re.MULTILINE)
_ENV_LINE_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", re.MULTILINE)


def _looks_html(probe: Probe) -> bool:
    ctype = probe.headers.get("content-type", "")
    return "text/html" in ctype.lower() or bool(_HTML_RE.search(probe.body[:512]))


def _match_git_head(p: Probe) -> bool:
    return not _looks_html(p) and bool(_GIT_HEAD_RE.search(p.body))


def _match_git_config(p: Probe) -> bool:
    return not _looks_html(p) and "[core]" in p.body


def _match_env(p: Probe) -> bool:
    # HTML 폴백/소프트-404 오탐 방지: HTML 아니고 KEY=VALUE 라인이 2개 이상일 때만
    return not _looks_html(p) and len(_ENV_LINE_RE.findall(p.body)) >= 2


def _match_server_status(p: Probe) -> bool:
    return "Apache Server Status" in p.body


# 경로 → (매처, 제목, 심각도, CWE, remediation_key)
_SIGNATURES: dict[str, tuple[Callable[[Probe], bool], str, Severity, str, str]] = {
    "/.git/HEAD": (_match_git_head, "노출된 .git 저장소", Severity.high, "CWE-538", "exposed_git"),
    "/.git/config": (
        _match_git_config,
        "노출된 .git/config",
        Severity.high,
        "CWE-538",
        "exposed_git",
    ),
    "/.env": (_match_env, "노출된 .env 환경설정 파일", Severity.high, "CWE-538", "exposed_env"),
    "/server-status": (
        _match_server_status,
        "노출된 server-status",
        Severity.medium,
        "CWE-200",
        "exposed_server_status",
    ),
}


class InfoDisclosureCheck:
    id = "info_disclosure"
    name = "정보 노출 점검"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        probe = ctx.probe

        # 1) 버전 배너 노출 (정확한 버전 토큰이 보일 때만)
        server = probe.headers.get("server", "")
        powered = probe.headers.get("x-powered-by", "")
        banner = f"{server} {powered}"
        if re.search(r"\d+\.\d+", banner):
            findings.append(
                Finding(
                    check_id=self.id,
                    title="서버/프레임워크 버전 배너 노출",
                    severity=Severity.info,
                    confidence=Confidence.medium,
                    location=probe.final_url,
                    evidence=f"Server: {server!r}; X-Powered-By: {powered!r}",
                    cwe="CWE-200",
                    owasp="A05:2021 보안 구성 오류",
                    remediation_key="version_banner",
                )
            )

        # 2) 잘 알려진 노출 경로 — 비파괴 GET, 스코프 격리된 fetch로만
        if probe.final_url or probe.url:
            parts = urlsplit(probe.final_url or probe.url)
            base = f"{parts.scheme}://{parts.netloc}"
            for path, (matcher, title, severity, cwe, key) in _SIGNATURES.items():
                url = urljoin(base, path)
                try:
                    p = ctx.fetch(url)  # 범위 밖이면 예외
                except (AuthorizationError, ValueError):
                    continue
                if p.error or p.status_code != 200:
                    continue
                if matcher(p):
                    findings.append(
                        Finding(
                            check_id=self.id,
                            title=title,
                            severity=severity,
                            confidence=Confidence.high,
                            location=url,
                            # 통제 ⑥: 노출 파일의 '내용'은 증거에 넣지 않는다(경로·상태만).
                            evidence=f"GET {path} → 200, 시그니처 일치",
                            cwe=cwe,
                            owasp="A05:2021 보안 구성 오류",
                            remediation_key=key,
                        )
                    )
        return findings
