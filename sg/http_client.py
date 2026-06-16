from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

from .config import Settings

# 비파괴(Non-destructive) 기본값: 읽기 메서드만 허용한다.
ALLOWED_METHODS = frozenset({"GET", "HEAD"})


@dataclass
class Probe:
    """단일 HTTP 응답을 점검에 쓰기 좋게 정규화한 결과."""

    url: str
    final_url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)  # 키 소문자
    set_cookies: list[str] = field(default_factory=list)  # 원시 Set-Cookie 값
    body: str = ""
    scheme: str = ""
    error: str | None = None


@dataclass
class TlsInfo:
    host: str
    port: int
    supported: bool = False
    protocol: str | None = None
    not_after: datetime | None = None
    not_before: datetime | None = None
    days_to_expiry: int | None = None
    self_signed: bool | None = None
    validates: bool | None = None
    issuer: str | None = None
    subject: str | None = None
    error: str | None = None


class RateLimiter:
    """요청 간 최소 간격을 강제해 DoS/과부하를 방지한다."""

    def __init__(self, max_per_second: float) -> None:
        self._min_interval = 1.0 / max_per_second if max_per_second > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        delta = time.monotonic() - self._last
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last = time.monotonic()


class HttpClient:
    """안전한 HTTP 클라이언트 — GET/HEAD 전용, 속도제한, 타임아웃, 본문 길이 제한."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.limiter = RateLimiter(settings.max_requests_per_second)
        # 리다이렉트는 자동 추적하지 않는다 — 스코프 격리(통제 ②)를 위해
        # 매 hop을 scanner.safe_fetch가 직접 검증하며 따라간다.
        self._client = httpx.Client(
            headers={"User-Agent": settings.user_agent},
            timeout=settings.request_timeout,
            follow_redirects=False,
            verify=settings.verify_tls_transport,
        )

    def fetch(self, url: str, method: str = "GET") -> Probe:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ValueError(
                f"비파괴 스캐너는 {sorted(ALLOWED_METHODS)} 만 허용한다 (요청: {method})."
            )
        self.limiter.wait()
        scheme = urlsplit(url).scheme
        try:
            resp = self._client.request(method, url)
        except httpx.HTTPError as exc:
            return Probe(url=url, final_url=url, status_code=0, scheme=scheme, error=str(exc))
        headers = {k.lower(): v for k, v in resp.headers.items()}
        set_cookies = list(resp.headers.get_list("set-cookie"))
        body = resp.text[: self.settings.max_body_chars]
        return Probe(
            url=url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            headers=headers,
            set_cookies=set_cookies,
            body=body,
            scheme=urlsplit(str(resp.url)).scheme or scheme,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def follow_redirects_in_scope(
    fetch_one: Callable[[str], Probe],
    url: str,
    is_allowed: Callable[[str], bool],
    on_blocked: Callable[[str], None] | None = None,
    max_redirects: int = 5,
) -> Probe:
    """리다이렉트를 직접 따라가되 매 hop을 is_allowed로 검증한다(통제 ② 스코프 격리).

    범위 밖/비허용 hop이면 on_blocked 호출 후 AuthorizationError를 던진다.
    """
    from .scope import AuthorizationError  # 지연 import (순환 방지)

    current = url
    last = Probe(
        url=url, final_url=url, status_code=0, scheme=urlsplit(url).scheme, error="no-response"
    )
    for _ in range(max_redirects + 1):
        if not is_allowed(current):
            if on_blocked is not None:
                on_blocked(current)
            raise AuthorizationError(f"스코프 밖/비허용 스킴 요청 차단: {current}")
        last = fetch_one(current)
        location = last.headers.get("location")
        if 300 <= last.status_code < 400 and location:
            current = urljoin(current, location)
            continue
        return last
    return last  # 리다이렉트 한도 도달 — 마지막 응답 반환


def get_tls_info(host: str, port: int = 443, timeout: float = 10.0) -> TlsInfo:
    """대상 인증서를 직접 수집·분석한다. 검증 실패해도 cert 메타는 얻기 위해 비검증 연결 사용."""
    info = TlsInfo(host=host, port=port)
    # 1) 비검증 연결로 인증서(DER) + 프로토콜 수집
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                info.protocol = ssock.version()
                info.supported = True
    except Exception as exc:  # noqa: BLE001 - 진단 목적, 모든 연결 실패를 기록
        info.error = str(exc)
        return info

    if der:
        try:
            from cryptography import x509

            cert = x509.load_der_x509_certificate(der)
            info.not_after = cert.not_valid_after_utc
            info.not_before = cert.not_valid_before_utc
            info.issuer = cert.issuer.rfc4514_string()
            info.subject = cert.subject.rfc4514_string()
            info.self_signed = cert.issuer == cert.subject
            info.days_to_expiry = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        except Exception:  # noqa: BLE001 - cert 파싱 실패는 부분 결과 허용
            pass

    # 2) 정식 검증 연결 — 자가서명/만료/호스트불일치 등 검출
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                info.validates = True
    except ssl.SSLError:
        info.validates = False
    except Exception:  # noqa: BLE001 - 네트워크 등 기타 사유는 판정 보류
        info.validates = None
    return info
