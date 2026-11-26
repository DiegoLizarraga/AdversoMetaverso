"""Persistencia en un único JSON (sin base de datos).

Varios procesos escriben a la vez (el agente, el servidor MCP de opencode, el
monitor, la TUI), así que toda modificación va en una **transacción**:

    with store.transaction():
        store.palaces[...] = ...

que toma un bloqueo exclusivo (`flock` sobre `<archivo>.lock`), relee el archivo,
deja aplicar los cambios sobre datos frescos y escribe de forma atómica (archivo
temporal + rename). Los lectores no necesitan bloqueo: el rename garantiza que
siempre ven un archivo completo.

Si el archivo se corrompe, se aparta como `<nombre>.corrupto-<fecha>` y se
empieza limpio en vez de perder el trabajo en silencio.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

VERSION = 1


class Store:
    def __init__(self, path: str | Path = "adverso.json") -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._thread_lock = threading.RLock()
        self._depth = 0
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

    def reload(self) -> None:
        """Relee el archivo: otro proceso puede haberlo actualizado."""
        with self._thread_lock:
            self.data = self._load()

    def mtime(self) -> float:
        """Marca de modificación del archivo (0 si no existe): para refrescar lectores."""
        try:
            return self.path.stat().st_mtime_ns / 1e9
        except FileNotFoundError:
            return 0.0

    @property
    def palaces(self) -> dict[str, Any]:
        return self.data["palaces"]

    @contextmanager
    def transaction(self) -> Iterator["Store"]:
        """Bloqueo exclusivo + datos frescos; al salir sin error, guarda. Reentrante."""
        with self._thread_lock:
            if self._depth:
                self._depth += 1
                try:
                    yield self
                finally:
                    self._depth -= 1
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.lock_path, "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    self.data = self._load()
                    self._depth = 1
                    try:
                        yield self
                    finally:
                        self._depth = 0
                    self._write()
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def save(self) -> None:
        """Guarda el estado en memoria como una transacción sin cambios previos.

        Ojo: fuera de `transaction()` esto sobrescribe lo que otros procesos hayan
        escrito desde la última lectura. Úsalo solo para estados recién leídos.
        """
        with self._thread_lock:
            if self._depth:
                return  # la transacción en curso guardará al salir
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.lock_path, "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    self._write()
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def _write(self) -> None:
        tmp = self.path.with_name(f"{self.path.name}.tmp{os.getpid()}")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf8")
        os.replace(tmp, self.path)
