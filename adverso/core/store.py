"""Persistencia en un único JSON (sin base de datos).

Escritura atómica (archivo temporal + rename) y, si el archivo se corrompe, se
aparta como `<nombre>.corrupto-<fecha>` y se empieza limpio en vez de perder el
trabajo en silencio.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

VERSION = 1


class Store:
    def __init__(self, path: str | Path = "adverso.json") -> None:
        self.path = Path(path)
        self.data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf8"))
            if isinstance(data, dict) and isinstance(data.get("palaces"), dict):
                return data
            raise ValueError("estructura inesperada")
        except FileNotFoundError:
            pass
        except (ValueError, OSError):
            backup = self.path.with_name(f"{self.path.name}.corrupto-{time.strftime('%Y%m%d-%H%M%S')}")
            try:
                os.replace(self.path, backup)
            except OSError:
                pass
        return {"version": VERSION, "palaces": {}}

    @property
    def palaces(self) -> dict[str, Any]:
        return self.data["palaces"]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf8")
        os.replace(tmp, self.path)
