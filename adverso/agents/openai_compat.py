"""Cliente para cualquier servidor con API de OpenAI (`/v1/chat/completions`).

Sirve para llama.cpp (`llama-server`), vLLM, LM Studio, el endpoint `/v1` de
Ollama, colibri, OpenRouter… Sin dependencias externas.

La clave de API nunca se pasa por la línea de órdenes (quedaría en el historial
y en `ps`): se lee de una variable de entorno.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

DEFAULT_URL = "http://127.0.0.1:8080/v1"  # llama-server
DEFAULT_KEY_ENV = "ADVERSO_API_KEY"


def _to_openai(m: dict[str, Any]) -> dict[str, Any]:
    """Formato canónico → mensaje OpenAI (argumentos como texto JSON, resultado por id)."""
    role = m.get("role")
    if role == "tool":
        return {"role": "tool", "tool_call_id": m.get("tool_call_id", ""), "content": m.get("content", "")}
    if role == "assistant" and m.get("tool_calls"):
        return {
            "role": "assistant",
            "content": m.get("content") or None,
            "tool_calls": [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": json.dumps(tc["function"]["arguments"], ensure_ascii=False),
                    },
                }
                for tc in m["tool_calls"]
            ],
        }
    return {"role": role, "content": m.get("content", "")}


class OpenAICompatClient:
    def __init__(self, model: str, url: str = DEFAULT_URL, api_key: str | None = None,
                 timeout: float = 600, native_tools: bool = True, temperature: float = 0.2) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.native_tools = native_tools
        self.temperature = temperature

    @classmethod
    def from_env(cls, model: str, url: str, key_env: str = DEFAULT_KEY_ENV, **kw: Any) -> "OpenAICompatClient":
        return cls(model, url, api_key=os.environ.get(key_env) or None, **kw)

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "User-Agent": "adverso"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.url + path, method=method, headers=headers,
                                     data=json.dumps(payload).encode() if payload is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:300]
            raise RuntimeError(f"{self.url} respondió {e.code}: {body}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise RuntimeError(f"no se pudo hablar con {self.url}: {e}") from e
        except json.JSONDecodeError as e:
            raise RuntimeError(f"{self.url} no devolvió JSON") from e

    def models(self) -> list[str]:
        return [m.get("id", "") for m in self._request("GET", "/models").get("data", [])]

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [_to_openai(m) for m in messages],
            "temperature": self.temperature,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        data = self._request("POST", "/chat/completions", payload)
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise RuntimeError(f"respuesta inesperada: {json.dumps(data)[:300]}")
        calls = [
            {"id": tc.get("id"), "function": tc.get("function") or {}}
            for tc in msg.get("tool_calls") or []
            if tc.get("type", "function") == "function"
        ]
        return {"content": msg.get("content") or "", "tool_calls": calls}
