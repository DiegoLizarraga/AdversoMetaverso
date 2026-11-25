"""Canal entre el servidor MCP (proceso hijo de opencode) y adverso (proceso padre).

El servidor MCP habla el protocolo por su stdin/stdout, así que no puede
preguntar nada al operador. Para las acciones intrusivas pregunta al padre por
un socket Unix; el padre, que sí tiene la terminal, pregunta al humano. Por el
mismo canal llegan los eventos (llamada / resultado) para mostrarlos en vivo.

Una conexión por mensaje, una línea JSON por mensaje y una línea de respuesta
(la decisión, o un acuse de recibo para los eventos). El socket vive en un
directorio temporal 0700: solo el mismo usuario puede conectarse.
"""

from __future__ import annotations

import json
import socket
import socketserver
import threading
from pathlib import Path
from typing import Any, Callable

#: Margen sobre el tiempo de aprobación del operador antes de rendirse (y denegar).
CONFIRM_WAIT = 120
EVENT_WAIT = 10
MAX_MESSAGE = 4_000_000


class BridgeServer:
    """Lado del padre. `on_event(kind, data)` y `confirm(tool, target, cmd) -> bool`."""

    def __init__(self, path: str | Path, on_event: Callable[[str, dict[str, Any]], None],
                 confirm: Callable[[str, str, list[str]], bool]) -> None:
        self.path = str(path)
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline(MAX_MESSAGE)
                try:
                    msg = json.loads(line)
                except ValueError:
                    return
                if not isinstance(msg, dict):
                    return
                if msg.get("type") == "event":
                    kind = str(msg.get("kind", ""))
                    try:
                        outer.on_event(kind, {k: v for k, v in msg.items() if k not in ("type", "kind")})
                    finally:
                        # Acuse de recibo: el hijo no sigue hasta que el evento está entregado.
                        self.wfile.write(b"{}\n")
                elif msg.get("type") == "confirm":
                    cmd = msg.get("cmd")
                    try:
                        ok = bool(outer.confirm(str(msg.get("tool", "")), str(msg.get("target", "")),
                                                [str(c) for c in cmd] if isinstance(cmd, list) else []))
                    except Exception:
                        ok = False
                    self.wfile.write((json.dumps({"approved": ok}) + "\n").encode())

        self.on_event = on_event
        self.confirm = confirm
        # Servidor secuencial a propósito: una confirmación cada vez.
        self._server = socketserver.UnixStreamServer(self.path, Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "BridgeServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        Path(self.path).unlink(missing_ok=True)


class BridgeClient:
    """Lado del servidor MCP. Cualquier fallo de canal = denegado / evento perdido."""

    def __init__(self, path: str) -> None:
        self.path = path

    def _send(self, msg: dict[str, Any], wait: float) -> Any:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(wait)
            s.connect(self.path)
            s.sendall((json.dumps(msg, ensure_ascii=False, default=str) + "\n").encode())
            with s.makefile("rb") as f:
                return json.loads(f.readline(MAX_MESSAGE) or b"null")

    def event(self, kind: str, **data: Any) -> None:
        try:
            self._send({"type": "event", "kind": kind, **data}, EVENT_WAIT)
        except (OSError, ValueError):
            pass  # un evento perdido solo afecta a la pantalla, nunca a la seguridad

    def confirm(self, tool: Any, target: str, cmd: list[str]) -> bool:
        name = getattr(tool, "name", str(tool))
        try:
            reply = self._send({"type": "confirm", "tool": name, "target": target, "cmd": cmd}, CONFIRM_WAIT)
        except (OSError, ValueError):
            return False
        return isinstance(reply, dict) and reply.get("approved") is True
