from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_USER_AGENT = "SecurityGuardrails/0.1 (+authorized-passive-scan)"

# 정보 노출 점검용 잘 알려진 경로 (비파괴 GET 으로만 확인)
DEFAULT_INFO_PATHS: tuple[str, ...] = (
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/server-status",
)


@dataclass
class Settings:
    """스캔 동작 설정. 안전장치(속도제한·타임아웃 등)의 기본값을 보유한다."""

    request_timeout: float = 10.0
    max_redirects: int = 5
    # DoS 금지: 초당 요청 상한 (속도제한). 0 이하면 무제한(권장 안 함).
    max_requests_per_second: float = 5.0
    # 데이터 보호: 증거로 보관·분석할 응답 본문 최대 길이(문자).
    max_body_chars: int = 200_000
    user_agent: str = DEFAULT_USER_AGENT
    # 우리가 TLS 문제를 직접 진단하므로 전송 자체는 인증서 검증 실패해도 받는다.
    verify_tls_transport: bool = False
    audit_path: str = ".sg/audit.jsonl"
    info_paths: tuple[str, ...] = field(default_factory=lambda: DEFAULT_INFO_PATHS)
