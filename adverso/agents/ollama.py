"""Cliente de Ollama (API local, sin dependencias externas)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

DEFAULT_URL = os.environ.get("ADVERSO_OLLAMA_URL", "http://127.0.0.1:11434")


def _to_ollama(m: dict[str, Any]) -> dict[str, Any]:
    """Formato canónico → API de Ollama (argumentos como objeto; resultado por nombre)."""
    if m.get("role") == "tool":
        return {"role": "tool", "tool_name": m.get("tool_name", ""), "content": m.get("content", "")}
    if m.get("tool_calls"):
        return {"role": m["role"], "content": m.get("content", ""),
                "tool_calls": [{"function": {"name": tc["function"]["name"], "arguments": tc["function"]["arguments"]}}
                               for tc in m["tool_calls"]]}
    return m


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
            "messages": [_to_ollama(m) for m in messages],
            "stream": False,
            "options": {"num_ctx": self.num_ctx, "temperature": 0.2},
        }
        if tools:
            payload["tools"] = tools
        if self.think is False:
            payload["think"] = False
        return self._post("/api/chat", payload)["message"]
