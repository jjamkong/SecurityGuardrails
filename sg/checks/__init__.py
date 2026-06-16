from __future__ import annotations

from .base import Check, ScanContext
from .cookies import CookieCheck
from .headers import SecurityHeadersCheck
from .info_disclosure import InfoDisclosureCheck
from .tls import TlsCheck

# Passive 점검 체크 목록(실행 순서). Active 점검은 Sprint 2.
PASSIVE_CHECKS: list[Check] = [
    SecurityHeadersCheck(),
    TlsCheck(),
    CookieCheck(),
    InfoDisclosureCheck(),
]

__all__ = ["Check", "ScanContext", "PASSIVE_CHECKS"]
