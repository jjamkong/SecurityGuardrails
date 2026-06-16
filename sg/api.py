from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import authz
from .models import Intensity, ScanReport
from .scanner import run_scan
from .scope import AuthorizationError, build_scope, host_of

_WEB_DIR = Path(__file__).parent / "web"
_TRUTHY = {"1", "true", "yes", "on"}
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

app = FastAPI(
    title="SecurityGuardrails",
    version="0.1.0",
    description=(
        "합법·방어용 웹 취약점 Passive 점검 API + 웹 UI (MVP).\n"
        "점검 허용 도메인(SG_AUTHORIZED_DOMAINS)은 항상 필수 — 그 도메인/서브도메인만 점검 가능. "
        "접근 통제는 SG_API_KEY(키) 또는 SG_ALLOW_NO_AUTH=1(키 없이 localhost 전용) 중 택1."
    ),
)


def _no_auth_enabled() -> bool:
    return os.environ.get("SG_ALLOW_NO_AUTH", "").strip().lower() in _TRUTHY


def _is_loopback(host: str) -> bool:
    return host in _LOOPBACK_HOSTS


def require_access(request: Request, x_api_key: str | None = Header(default=None)) -> None:
    """접근 통제.

    - SG_ALLOW_NO_AUTH=1: 키 없이 허용하되 **직접 localhost 접속만**(로컬 전용). 프록시/외부는 거부.
    - 그 외: SG_API_KEY 필수(fail-closed).
    """
    if _no_auth_enabled():
        # no-auth는 '직접 로컬 접속' 전용. 프록시 경유 신호(forwarded 헤더)가 있으면 거부한다.
        # (X-Forwarded-For 위조로 request.client를 localhost로 위장하는 우회를 차단)
        if request.headers.get("x-forwarded-for") or request.headers.get("forwarded"):
            raise HTTPException(
                status_code=403,
                detail=(
                    "no-auth 모드는 프록시 뒤에서 쓸 수 없습니다. "
                    "원격/프록시 배포는 SG_API_KEY를 사용하세요."
                ),
            )
        client = request.client.host if request.client else ""
        if _is_loopback(client):
            return
        raise HTTPException(
            status_code=403,
            detail=(
                "키 없는(no-auth) 모드는 localhost에서만 허용됩니다. "
                "원격 접근은 SG_API_KEY를 사용하세요."
            ),
        )
    configured = os.environ.get("SG_API_KEY")
    if not configured:
        raise HTTPException(
            status_code=503,
            detail=(
                "접근 미구성: SG_API_KEY를 설정하거나, "
                "로컬 전용이면 SG_ALLOW_NO_AUTH=1로 실행하세요."
            ),
        )
    if not x_api_key or x_api_key != configured:
        raise HTTPException(status_code=401, detail="유효한 X-API-Key가 필요합니다.")


class ScanRequest(BaseModel):
    target: str
    authorized_by: str = "web-ui"
    authorization_id: str = ""  # 비우면 서버가 감사용 ID 생성
    intensity: Intensity = Intensity.passive


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_WEB_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict[str, object]:
    """UI가 모드를 표시하기 위한 공개 정보(허용 도메인·no-auth 여부). 비밀 아님."""
    return {"authorized_domains": authz.authorized_domains(), "no_auth": _no_auth_enabled()}


@app.post("/scans", response_model=ScanReport, dependencies=[Depends(require_access)])
def create_scan(req: ScanRequest) -> ScanReport:
    domains = authz.authorized_domains()
    if not domains:
        raise HTTPException(
            status_code=503,
            detail="점검 허용 도메인(SG_AUTHORIZED_DOMAINS)이 설정되지 않았습니다.",
        )

    target = req.target if "://" in req.target else f"https://{req.target}"
    host = host_of(target)
    if authz.match_authorized_domain(host) is None:
        # 서버측 인가 — 허용 도메인 밖이면 거부 (제3자 무단 점검 차단)
        raise HTTPException(
            status_code=403,
            detail=f"승인된 점검 대상이 아닙니다: {host!r}. 허용 도메인: {domains}",
        )

    # allowed_hosts는 서버가 도출 — 클라이언트 입력을 신뢰하지 않음
    scope = build_scope(
        target=target,
        authorized_by=req.authorized_by or "web-ui",
        authorization_id=req.authorization_id or f"web-{uuid4().hex[:8]}",
        allowed_hosts=[host],
        intensity=req.intensity,
    )
    try:
        return run_scan(scope)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
