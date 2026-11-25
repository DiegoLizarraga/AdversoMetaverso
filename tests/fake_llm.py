"""Servidor falso con API de OpenAI (streaming SSE) para probar agentes de verdad.

Decide por el contenido de la conversación, no por un guion, para no depender
de cuántas peticiones auxiliares haga el cliente (títulos, resúmenes…):

- sin herramientas en la petición → responde un texto corto;
- con herramientas y sin resultados todavía → pide `call` (nombre + argumentos);
- con un resultado de herramienta → responde el informe final, citando el resultado.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

FINAL_PREFIX = "INFORME:"


class FakeLLM:
    def __init__(self, tool_suffix: str, args: dict[str, Any]) -> None:
        self.tool_suffix = tool_suffix  # p. ej. "nmap_scan": el cliente puede añadir prefijo
        self.args = args
        self.requests: list[dict[str, Any]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # /v1/models
                self._json({"object": "list", "data": [{"id": "falso", "object": "model"}]})

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                outer.requests.append(body)
                delta = outer.decide(body)
                if body.get("stream"):
                    self._sse(delta)
                else:
                    self._json({"id": "x", "object": "chat.completion", "created": 0, "model": "falso",
                                "choices": [{"index": 0, "message": {"role": "assistant", **delta},
                                             "finish_reason": "tool_calls" if "tool_calls" in delta else "stop"}]})

            def _json(self, obj: Any) -> None:
                data = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _sse(self, delta: dict[str, Any]) -> None:
                finish = "tool_calls" if "tool_calls" in delta else "stop"
                if "tool_calls" in delta:
                    delta = {"tool_calls": [{"index": i, **tc} for i, tc in enumerate(delta["tool_calls"])]}
                chunks = [
                    {"choices": [{"index": 0, "delta": {"role": "assistant", **delta}, "finish_reason": None}]},
                    {"choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                     "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}},
                ]
                payload = "".join(
                    "data: " + json.dumps({"id": "x", "object": "chat.completion.chunk", "created": 0, "model": "falso", **c}) + "\n\n"
                    for c in chunks
                ) + "data: [DONE]\n\n"
                data = payload.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a: Any) -> None:
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self._srv.server_port}"

    def tool_name(self, body: dict[str, Any]) -> str | None:
        for t in body.get("tools") or []:
            name = t.get("function", {}).get("name", "")
            if name.endswith(self.tool_suffix):
                return name
        return None

    def decide(self, body: dict[str, Any]) -> dict[str, Any]:
        msgs = body.get("messages") or []
        results = [m for m in msgs if m.get("role") == "tool"]
        if results:
            content = results[-1].get("content")
            text = content if isinstance(content, str) else json.dumps(content)
            return {"content": f"{FINAL_PREFIX} {text[:200]}"}
        name = self.tool_name(body)
        if name is None:
            return {"content": "Reconocimiento"}
        return {"tool_calls": [{"id": "call_1", "type": "function",
                                "function": {"name": name, "arguments": json.dumps(self.args)}}]}

    def __enter__(self) -> "FakeLLM":
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._srv.shutdown()
        self._srv.server_close()
