from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import authz
from .models import Intensity, ScanReport
from .scanner import run_scan
from .scope import AuthorizationError, build_scope, host_of

_WEB_DIR = Path(__file__).parent / "web"

app = FastAPI(
    title="SecurityGuardrails",
    version="0.1.0",
    description=(
        "합법·방어용 웹 취약점 Passive 점검 API + 웹 UI (MVP).\n"
        "⚠️ 접근 키(SG_API_KEY) + 점검 허용 도메인(SG_AUTHORIZED_DOMAINS) "
        "둘 다 설정해야 동작합니다(fail-closed). "
        "허용 도메인/서브도메인만 점검 가능 — 제3자 도메인은 거부."
    ),
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Fail-closed 인증. SG_API_KEY 미설정이면 거부(우발적 무인증 노출 방지)."""
    configured = os.environ.get("SG_API_KEY")
    if not configured:
        raise HTTPException(status_code=503, detail="API 미구성: SG_API_KEY 환경변수를 설정하세요.")
    if not x_api_key or x_api_key != configured:
        raise HTTPException(status_code=401, detail="유효한 X-API-Key가 필요합니다.")


class ScanRequest(BaseModel):
    target: str
    authorized_by: str
    authorization_id: str  # 필수
    intensity: Intensity = Intensity.passive


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_WEB_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/authorized-domains", dependencies=[Depends(require_api_key)])
def list_authorized_domains() -> dict[str, list[str]]:
    return {"domains": authz.authorized_domains()}


@app.post("/scans", response_model=ScanReport, dependencies=[Depends(require_api_key)])
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
        authorized_by=req.authorized_by,
        authorization_id=req.authorization_id,
        allowed_hosts=[host],
        intensity=req.intensity,
    )
    try:
        return run_scan(scope)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
