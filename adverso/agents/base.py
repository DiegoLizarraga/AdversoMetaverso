"""Bucle de agente independiente del modelo.

Un `LLMClient` solo sabe hablar con un modelo (Ollama, opencode, Claude…). El
bucle vive aquí y es el mismo para todos: el modelo pide herramientas, el
`Executor` las ejecuta (con alcance, confirmación y auditoría) y el resultado
vuelve al modelo. El agente nunca toca una herramienta directamente.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from ..tools.executor import Executor

MAX_RESULT_CHARS = 6000


class LLMClient(Protocol):
    #: True si el modelo soporta tool calling nativo.
    native_tools: bool

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> dict[str, Any]:
        """Devuelve el mensaje del asistente: {"content": str, "tool_calls": [...]}."""
        ...


@dataclass
class Event:
    kind: str  # assistant | tool_call | tool_result | final | error
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    final: str
    steps: int
    events: list[Event]
    completed: bool


SYSTEM_PROMPT = """Eres el navegador del Metaverso: un agente de reconocimiento de red para un pentester autorizado.
Cada host es un Palacio y cada servicio o hallazgo es una Sombra.

REGLAS
- Usa SOLO las herramientas que se te dan. No inventes resultados: si no lo has medido, no lo afirmes.
- Un guardia de alcance bloquea todo objetivo no autorizado; si te rechaza un objetivo, no insistas ni lo rodees.
- Empieza por lo barato (nmap perfil rapido) y profundiza solo donde haya algo que ver.
- Las herramientas intrusivas pueden ser denegadas por el operador: acepta la negativa y continúa con lo que sí puedes hacer.
- Cuando tengas suficiente información, responde con un informe final breve: hosts, puertos/servicios, hallazgos y siguientes pasos.
"""

TEXT_PROTOCOL = """
Para llamar a una herramienta responde ÚNICAMENTE con un objeto JSON:
{"tool": "<nombre>", "args": {...}}
Para terminar responde ÚNICAMENTE con:
{"final": "<tu informe>"}
Herramientas disponibles:
"""


def extract_json(text: str) -> dict[str, Any] | None:
    """Primer objeto JSON equilibrado dentro de un texto (tolera ``` y prosa)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = esc = False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start : i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                    break
        start = text.find("{", start + 1)
    return None


def _clip(result: dict[str, Any]) -> str:
    s = json.dumps(result, ensure_ascii=False)
    if len(s) > MAX_RESULT_CHARS:
        s = s[:MAX_RESULT_CHARS] + f'... [truncado, {len(s)} caracteres en total]'
    return s


class Agent:
    def __init__(self, client: LLMClient, executor: Executor, max_steps: int = 10,
                 on_event: Callable[[Event], None] | None = None) -> None:
        self.client = client
        self.executor = executor
        self.max_steps = max_steps
        self.on_event = on_event or (lambda e: None)

    def _emit(self, events: list[Event], kind: str, **data: Any) -> None:
        ev = Event(kind, data)
        events.append(ev)
        self.on_event(ev)

    def run(self, task: str) -> AgentResult:
        native = self.client.native_tools
        schemas = self.executor.schemas()
        system = SYSTEM_PROMPT
        if not native:
            listing = "\n".join(
                f"- {s['function']['name']}: {s['function']['description']} "
                f"Parámetros: {json.dumps(s['function']['parameters']['properties'], ensure_ascii=False)}"
                for s in schemas
            )
            system += TEXT_PROTOCOL + listing
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
        ]
        events: list[Event] = []
        seen: set[str] = set()

        for step in range(1, self.max_steps + 1):
            try:
                msg = self.client.chat(messages, schemas if native else None)
            except Exception as e:  # red caída, modelo no cargado, timeout…
                self._emit(events, "error", error=str(e))
                return AgentResult(f"Error del modelo: {e}", step, events, False)

            content = (msg.get("content") or "").strip()
            calls: list[tuple[str, dict[str, Any]]] = []
            if native:
                for tc in msg.get("tool_calls") or []:
                    fn = tc.get("function", {})
                    args = fn.get("arguments") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}
                    calls.append((fn.get("name", ""), args))
            else:
                obj = extract_json(content)
                if obj and "final" in obj:
                    self._emit(events, "final", text=str(obj["final"]))
                    return AgentResult(str(obj["final"]), step, events, True)
                if obj and "tool" in obj:
                    calls.append((str(obj["tool"]), obj.get("args") or {}))

            if content:
                self._emit(events, "assistant", text=content)

            if not calls:
                if native or not content:
                    # Sin llamadas: en modo nativo es la respuesta final.
                    if content:
                        self._emit(events, "final", text=content)
                        return AgentResult(content, step, events, True)
                    self._emit(events, "error", error="el modelo no respondió")
                    return AgentResult("El modelo no respondió.", step, events, False)
                # Modo texto con salida que no es JSON válido: pedimos corrección.
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": 'Responde SOLO con JSON: {"tool": ..., "args": {...}} o {"final": "..."}.'})
                continue

            messages.append({"role": "assistant", "content": content,
                             **({"tool_calls": msg.get("tool_calls")} if native else {})})
            for name, args in calls:
                key = f"{name}:{json.dumps(args, sort_keys=True, default=str)}"
                self._emit(events, "tool_call", name=name, args=args)
                if key in seen:
                    result = {"ok": False, "error": "llamada repetida: usa otro enfoque o termina con el informe"}
                else:
                    seen.add(key)
                    result = self.executor.run(name, args)
                self._emit(events, "tool_result", name=name, ok=result.get("ok", False), result=result)
                if native:
                    messages.append({"role": "tool", "tool_name": name, "content": _clip(result)})
                else:
                    messages.append({"role": "user", "content": f"Resultado de {name}: {_clip(result)}"})

        text = "Se alcanzó el límite de pasos sin informe final."
        self._emit(events, "error", error=text)
        return AgentResult(text, self.max_steps, events, False)
