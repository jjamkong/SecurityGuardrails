from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from .models import ScopeAuthorization


def record(
    event: str,
    scope: ScopeAuthorization,
    path: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """불변(append-only) 감사 로그(JSONL). 통제 ⑤ — 누가·언제·무엇을·어떤 강도로."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "actor": scope.authorized_by,
        "authorization_id": scope.authorization_id,
        "target": scope.target,
        "intensity": scope.intensity.value,
    }
    if extra:
        entry.update(extra)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
