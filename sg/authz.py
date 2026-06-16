from __future__ import annotations

import os


def authorized_domains() -> list[str]:
    """점검이 허용된 도메인 목록(서버측 인가). 환경변수 SG_AUTHORIZED_DOMAINS(쉼표 구분)."""
    raw = os.environ.get("SG_AUTHORIZED_DOMAINS", "")
    return [d.strip().lower().rstrip(".").lstrip(".") for d in raw.split(",") if d.strip()]


def match_authorized_domain(host: str) -> str | None:
    """host가 허용 도메인이거나 그 서브도메인이면 매칭된 도메인을, 아니면 None."""
    host = host.lower().rstrip(".")
    for domain in authorized_domains():
        if host == domain or host.endswith("." + domain):
            return domain
    return None
