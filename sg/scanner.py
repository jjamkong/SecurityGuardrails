from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

from . import audit, report
from .checks import PASSIVE_CHECKS, ScanContext
from .config import Settings
from .http_client import HttpClient, Probe, follow_redirects_in_scope, get_tls_info
from .models import ScanReport, ScopeAuthorization
from .scope import AuthorizationError, enforce_authorization, host_of, is_in_scope


def run_scan(scope: ScopeAuthorization, settings: Settings | None = None) -> ScanReport:
    """승인 게이트 → 수집 → Passive 점검 → 조치 가이드 포함 레포트.

    승인되지 않은 스코프면 AuthorizationError 로 즉시 차단(점검 0건). 거부·차단은 감사로그에 남는다.
    """
    settings = settings or Settings()
    try:
        enforce_authorization(scope)  # 통제 ① — 미승인/만료/범위밖/비허용 스킴이면 중단
    except AuthorizationError:
        audit.record("scan.denied", scope, settings.audit_path)  # 통제 ⑤ — 거부도 추적
        raise

    scan_id = uuid4().hex[:12]
    started = datetime.now(timezone.utc)
    audit.record("scan.start", scope, settings.audit_path, {"scan_id": scan_id})

    errors: list[str] = []
    findings = []

    with HttpClient(settings) as client:

        def _on_blocked(blocked_url: str) -> None:
            # 통제 ⑤: 차단된 시도도 추적 (URL만 — 쿠키/비밀 미기록)
            audit.record(
                "request.blocked",
                scope,
                settings.audit_path,
                {"scan_id": scan_id, "url": blocked_url},
            )

        def safe_fetch(url: str) -> Probe:
            # 통제 ②: 메인페이지·추가경로·리다이렉트 hop 전부 이 게이트를 통과한다.
            return follow_redirects_in_scope(
                client.fetch,
                url,
                lambda u: is_in_scope(u, scope),
                on_blocked=_on_blocked,
                max_redirects=settings.max_redirects,
            )

        try:
            base = safe_fetch(scope.target)
        except AuthorizationError as exc:
            base = Probe(
                url=scope.target,
                final_url=scope.target,
                status_code=0,
                scheme=urlsplit(scope.target).scheme,
                error=str(exc),
            )
            errors.append(str(exc))
        if base.error:
            errors.append(f"대상 응답 실패: {base.error}")

        tls = None
        if urlsplit(scope.target).scheme == "https" or base.scheme == "https":
            host = host_of(scope.target)
            if host:
                port = urlsplit(scope.target).port or 443
                client.limiter.wait()  # 통제 ④ — TLS 핸드셰이크도 속도제한 회계에 포함
                tls = get_tls_info(host, port, timeout=settings.request_timeout)

        ctx = ScanContext(scope=scope, probe=base, fetch=safe_fetch, tls=tls)
        for check in PASSIVE_CHECKS:
            try:
                findings.extend(check.run(ctx))
            except Exception as exc:  # noqa: BLE001 - 한 체크 실패가 전체를 막지 않게
                errors.append(f"{check.id}: {exc}")

    finished = datetime.now(timezone.utc)
    result = report.assemble(
        scan_id=scan_id,
        scope=scope,
        started_at=started,
        finished_at=finished,
        findings=findings,
        errors=errors,
        tool={"name": "SecurityGuardrails", "version": "0.1.0", "mode": "passive"},
    )
    audit.record(
        "scan.finish",
        scope,
        settings.audit_path,
        {"scan_id": scan_id, "findings": result.summary.total},
    )
    return result
