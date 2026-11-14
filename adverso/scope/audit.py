"""Registro de auditoría append-only en JSON Lines."""

from __future__ import annotations

import json
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path = "audit.log") -> None:
        self.path = Path(path)

    def record(self, event: str, **fields) -> None:
        line = json.dumps({"ts": time.time(), "event": event, **fields}, ensure_ascii=False, default=str)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf8") as f:
            f.write(line + "\n")
