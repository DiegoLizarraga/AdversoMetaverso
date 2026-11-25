"""Adaptador opencode: otro agente (su propio bucle) con NUESTRAS herramientas.

opencode decide qué herramienta llamar y cuándo terminar; las herramientas le
llegan por el servidor MCP de adverso (`python -m adverso mcp`), que envuelve el
mismo `Executor`: alcance, confirmación, auditoría y presupuesto no cambian.
Las herramientas propias de opencode (shell, edición, web…) se deniegan todas.

    adverso (padre) ──run──▶ opencode ──stdio MCP──▶ adverso mcp ──▶ Executor
         ▲                                              │
         └──────── socket Unix: aprobaciones y eventos ─┘

Cada ejecución usa un directorio temporal 0700 como proyecto y como
configuración de opencode, así no hereda la configuración global del usuario
(otros servidores MCP, plugins) ni ve ningún archivo real.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from ..mcp.bridge import BridgeServer
from ..tools.executor import Confirm, default_tools
from .base import MAX_CALLS_PER_TURN, SYSTEM_PROMPT, AgentResult, Event, strip_think

AGENT_NAME = "metaverso"
MCP_NAME = "adverso"
MCP_STARTUP_MS = 30_000
#: Directorio que contiene el paquete `adverso`, para lanzar el servidor MCP sin instalarlo.
_PKG_ROOT = str(Path(__file__).resolve().parent.parent.parent)


class OpencodeAgent:
    def __init__(self, model: str, ollama_url: str, scope_path: str, audit_path: str, state_path: str,
                 confirm: Confirm, store: Any = None, max_steps: int = 10, timeout: float = 3600,
                 response_timeout: float = 600, on_event: Callable[[Event], None] | None = None,
                 opencode_bin: str = "opencode") -> None:
        self.model = model
        self.ollama_url = ollama_url.rstrip("/")
        self.scope_path = str(Path(scope_path).resolve())
        self.audit_path = str(Path(audit_path).resolve())
        self.state_path = str(Path(state_path).resolve())
        self.confirm = confirm
        self.store = store
        self.max_steps = max_steps
        self.timeout = timeout  # para toda la ejecución
        self.response_timeout = response_timeout  # por respuesta del modelo
        self.on_event = on_event or (lambda e: None)
        self.opencode_bin = opencode_bin

    def mcp_command(self, bridge: str) -> list[str]:
        return [sys.executable, "-m", "adverso", "mcp", "--scope", self.scope_path, "--audit", self.audit_path,
                "--state", self.state_path, "--bridge", bridge,
                "--max-calls", str(self.max_steps * MAX_CALLS_PER_TURN)]

    def config(self, bridge: str) -> dict[str, Any]:
        """Configuración de opencode (esquema 1.x, verificado con opencode 1.19.6)."""
        provider, _, model_id = self.model.partition("/")
        cfg: dict[str, Any] = {
            "$schema": "https://opencode.ai/config.json",
            "autoupdate": False,
            "share": "disabled",
            "default_agent": AGENT_NAME,
            "mcp": {
                MCP_NAME: {
                    "type": "local",
                    "enabled": True,
                    # ms para arrancar y listar herramientas (5 s de serie): con la máquina
                    # cargada no basta, y sin lista el agente arrancaría sin herramientas.
                    "timeout": MCP_STARTUP_MS,
                    "command": self.mcp_command(bridge),
                    "environment": {"PYTHONPATH": os.pathsep.join(filter(None, [_PKG_ROOT, os.environ.get("PYTHONPATH")]))},
                },
            },
            "agent": {
                AGENT_NAME: {
                    "mode": "primary",
                    "description": "Reconocimiento con las herramientas de adverso (alcance, confirmación y auditoría)",
                    "prompt": SYSTEM_PROMPT,
                    "model": self.model,
                    "temperature": 0.2,
                    "steps": self.max_steps,
                    # Gana la última regla que coincide: todo denegado salvo nuestras herramientas.
                    "permission": {"*": "deny", f"{MCP_NAME}_*": "allow"},
                },
            },
        }
        if provider == "ollama":
            cfg["provider"] = {"ollama": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "Ollama",
                "options": {
                    "baseURL": f"{self.ollama_url}/v1",
                    # En CPU, cargar el modelo y procesar el prompt puede pasar de los
                    # 300 s que opencode espera de serie a las cabeceras y entre trozos.
                    "headerTimeout": int(self.response_timeout * 1000),
                    "chunkTimeout": int(self.response_timeout * 1000),
                },
                "models": {model_id: {"name": model_id, "tool_call": True}},
            }}
        return cfg

    def command(self) -> list[str]:
        # La tarea va por stdin: como argumento, opencode la re-entrecomilla.
        # Registros de nivel ERROR a stderr: explican los fallos que el JSON resume
        # como "Unexpected server error".
        return [self.opencode_bin, "run", "--pure", "--format", "json", "--title", "adverso",
                "--print-logs", "--log-level", "ERROR", "--agent", AGENT_NAME, "-m", self.model]

    @staticmethod
    def log_error(stderr: str) -> str | None:
        """Última causa registrada por opencode (`error.error="…"`), si la hay."""
        for line in reversed(stderr.splitlines()):
            m = re.search(r'error\.(?:error|message)="((?:[^"\\]|\\.)*)"', line)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def parse_output(stdout: str) -> tuple[str, str | None]:
        """Eventos JSON de `opencode run` → (texto final, error). El texto final es el
        del último mensaje del asistente que tuvo texto."""
        texts: dict[str, list[str]] = {}
        order: list[str] = []
        error = None
        for line in stdout.splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if not isinstance(ev, dict):
                continue
            if ev.get("type") == "text":
                part = ev.get("part") or {}
                mid = str(part.get("messageID", ""))
                if mid not in texts:
                    texts[mid] = []
                    order.append(mid)
                texts[mid].append(str(part.get("text", "")))
            elif ev.get("type") == "error":
                err = ev.get("error") or {}
                data = err.get("data") or {}
                error = str(data.get("message") or err.get("name") or "error desconocido")
        final = strip_think("".join(texts[order[-1]])) if order else ""
        return final, error

    def run(self, task: str) -> AgentResult:
        events: list[Event] = []

        def on_event(kind: str, data: dict[str, Any]) -> None:
            ev = Event(kind, data)
            events.append(ev)
            self.on_event(ev)

        def confirm(name: str, target: str, cmd: list[str]) -> bool:
            tool = default_tools().get(name)
            return tool is not None and tool.intrusive and bool(self.confirm(tool, target, cmd))

        def fail(text: str) -> AgentResult:
            on_event("error", {"error": text})
            return AgentResult(text, len([e for e in events if e.kind == "tool_call"]), events, False)

        with tempfile.TemporaryDirectory(prefix="adverso-oc-") as tmp:
            os.chmod(tmp, 0o700)
            sock = os.path.join(tmp, "bridge.sock")
            work = Path(tmp, "proyecto")
            conf = Path(tmp, "config")
            work.mkdir()
            conf.mkdir()
            cfg = json.dumps(self.config(sock), ensure_ascii=False, indent=2)
            (work / "opencode.json").write_text(cfg, encoding="utf8")
            # Configuración global aislada: sin MCP, plugins ni instrucciones del usuario.
            # PWD también: opencode toma el proyecto de $PWD y no del cwd real, así que
            # lanzado desde un shell usaría el directorio del usuario (y su opencode.json).
            env = {**os.environ, "XDG_CONFIG_HOME": str(conf), "PWD": str(work)}
            with BridgeServer(sock, on_event, confirm):
                try:
                    p = subprocess.run(self.command(), cwd=work, env=env, input=task,
                                       capture_output=True, text=True, errors="replace", timeout=self.timeout)
                except FileNotFoundError:
                    return fail(f"{self.opencode_bin} no está instalado")
                except subprocess.TimeoutExpired:
                    return fail(f"opencode no terminó en {int(self.timeout)} s")
                finally:
                    if self.store is not None:
                        self.store.reload()  # el servidor MCP escribió desde otro proceso

        final, error = self.parse_output(p.stdout)
        if error or p.returncode != 0 or not final:
            cause = self.log_error(p.stderr)
            detail = " — ".join(filter(None, [error, cause])) or (p.stderr or p.stdout).strip()[-500:] or "sin respuesta"
            return fail(f"opencode falló (código {p.returncode}): {detail}")
        on_event("final", {"text": final})
        return AgentResult(final, len([e for e in events if e.kind == "tool_call"]), events, True)
