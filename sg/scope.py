from __future__ import annotations

from datetime import datetime
from urllib.parse import urlsplit

from .models import Intensity, ScopeAuthorization

ALLOWED_SCHEMES = frozenset({"http", "https"})


class AuthorizationError(Exception):
    """승인되지 않았거나 스코프를 벗어난 점검 시도."""


def host_of(url: str) -> str:
    # trailing dot 제거로 스코프 비교 일관성 확보 (예: app.test. == app.test)
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def scheme_of(url: str) -> str:
    return urlsplit(url).scheme.lower()


def build_scope(
    target: str,
    authorized_by: str,
    authorization_id: str,
    allowed_hosts: list[str] | None = None,
    intensity: Intensity = Intensity.passive,
    expires_at: datetime | None = None,
) -> ScopeAuthorization:
    target_host = host_of(target)
    hosts = [h.lower() for h in (allowed_hosts or [])]
    if not hosts and target_host:
        hosts = [target_host]
    return ScopeAuthorization(
        target=target,
        allowed_hosts=hosts,
        intensity=intensity,
        authorized_by=authorized_by,
        authorization_id=authorization_id,
        expires_at=expires_at,
    )


def enforce_authorization(scope: ScopeAuthorization) -> None:
    """승인 게이트. 통과하지 못하면 점검을 시작하지 않는다(통제 ①②)."""
    if not scope.authorized_by or not scope.authorization_id:
        raise AuthorizationError("점검 승인 정보(authorized_by, authorization_id)가 필요합니다.")
    if not scope.allowed_hosts:
        raise AuthorizationError("스코프에 허용 호스트가 없습니다.")
    if scope.is_expired():
        raise AuthorizationError("점검 승인이 만료되었습니다.")
    if scheme_of(scope.target) not in ALLOWED_SCHEMES:
        raise AuthorizationError(
            f"허용되지 않는 스킴: {scheme_of(scope.target)!r} (http/https만 가능)"
        )
    if host_of(scope.target) not in scope.allowed_hosts:
        raise AuthorizationError(
            f"대상 호스트가 스코프에 없습니다: {host_of(scope.target)!r} "
            f"(허용: {scope.allowed_hosts})"
        )


def is_in_scope(url: str, scope: ScopeAuthorization) -> bool:
    """스코프 격리 — http/https + 허용 호스트의 요청만 발사 가능(통제 ②)."""
    return scheme_of(url) in ALLOWED_SCHEMES and host_of(url) in scope.allowed_hosts
