from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ..http_client import Probe, TlsInfo
from ..models import Finding, ScopeAuthorization


@dataclass
class ScanContext:
    """체크에 전달되는 컨텍스트. fetch는 스코프 검증을 거친 안전 fetch만 주입된다."""

    scope: ScopeAuthorization
    probe: Probe  # 대상 메인 페이지 응답
    fetch: Callable[[str], Probe]  # 스코프 격리된 추가 요청용
    tls: TlsInfo | None = None


class Check(Protocol):
    id: str
    name: str

    def run(self, ctx: ScanContext) -> list[Finding]: ...
