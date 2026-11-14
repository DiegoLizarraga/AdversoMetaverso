"""Cliente de Ollama (API local, sin dependencias externas)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

DEFAULT_URL = "http://127.0.0.1:11434"


class OllamaClient:
    def __init__(self, model: str, url: str = DEFAULT_URL, timeout: float = 600,
                 think: bool = False, num_ctx: int = 8192, native_tools: bool | None = None) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.think = think
        self.num_ctx = num_ctx
        self._native = native_tools

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            self.url + path, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Ollama {e.code}: {e.read().decode(errors='replace')[:300]}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise RuntimeError(f"no se pudo hablar con Ollama en {self.url}: {e}") from e

    @property
    def native_tools(self) -> bool:
        """Auto-detecta si el modelo anuncia la capacidad `tools`."""
        if self._native is None:
            caps = self._post("/api/show", {"model": self.model}).get("capabilities", [])
            self._native = "tools" in caps
        return self._native

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"num_ctx": self.num_ctx, "temperature": 0.2},
        }
        if tools:
            payload["tools"] = tools
        if self.think is False:
            payload["think"] = False
        return self._post("/api/chat", payload)["message"]
