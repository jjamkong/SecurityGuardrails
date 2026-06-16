from __future__ import annotations

import os

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .models import Intensity, ScanReport
from .scanner import run_scan
from .scope import AuthorizationError, build_scope

app = FastAPI(
    title="SecurityGuardrails",
    version="0.1.0",
    description=(
        "합법·방어용 웹 취약점 Passive 점검 API (MVP). 승인된 자산만 점검하세요.\n"
        "⚠️ 인증된 호출자가 점검 권한을 책임집니다(CLI --authorized-by와 동등). "
        "API 키(SG_API_KEY) 미설정 시 fail-closed. "
        "미인증 네트워크 노출 금지(localhost 바인딩 권장)."
    ),
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Fail-closed 인증. SG_API_KEY 미설정이면 스캔을 거부한다(우발적 무인증 노출 방지)."""
    configured = os.environ.get("SG_API_KEY")
    if not configured:
        raise HTTPException(status_code=503, detail="API 미구성: SG_API_KEY 환경변수를 설정하세요.")
    if not x_api_key or x_api_key != configured:
        raise HTTPException(status_code=401, detail="유효한 X-API-Key가 필요합니다.")


class ScanRequest(BaseModel):
    target: str
    authorized_by: str
    authorization_id: str  # 필수 — 자동 생성하지 않음
    allowed_hosts: list[str] | None = None
    intensity: Intensity = Intensity.passive


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scans", response_model=ScanReport, dependencies=[Depends(require_api_key)])
def create_scan(req: ScanRequest) -> ScanReport:
    scope = build_scope(
        target=req.target,
        authorized_by=req.authorized_by,
        authorization_id=req.authorization_id,
        allowed_hosts=req.allowed_hosts,
        intensity=req.intensity,
    )
    try:
        return run_scan(scope)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
