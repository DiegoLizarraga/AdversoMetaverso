"""CLI: recon (agente), palaces, report, doctor."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.request
from typing import Any

from ..agents.base import Agent, Event, Runner
from ..agents.ollama import DEFAULT_URL as OLLAMA_URL, OllamaClient
from ..agents.openai_compat import DEFAULT_KEY_ENV, DEFAULT_URL as OPENAI_URL, OpenAICompatClient
from ..core.findings import palace_rank, palace_score
from ..core.store import Store
from ..reports.card import render_markdown
from ..scope.audit import AuditLog
from ..scope.guard import Scope
from ..tools.base import Tool
from ..tools.executor import Executor


APPROVAL_TIMEOUT = 60


def ask_operator(tool: Tool, target: str, cmd: list[str], timeout: float = APPROVAL_TIMEOUT) -> bool:
    """Confirmación humana en terminal. Sin respuesta en `timeout` s: DENEGADA."""
    import select

    print(f"\n⚠  ACCIÓN INTRUSIVA: {tool.name} contra {target}\n   $ {' '.join(cmd)}", file=sys.stderr)
    if not sys.stdin.isatty():
        print("   (sin terminal interactiva: denegada)", file=sys.stderr)
        return False
    print(f"   ¿Aprobar? [s/N] ({int(timeout)} s, sin respuesta = no) ", end="", file=sys.stderr, flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if not ready:
        print("\n   tiempo agotado: denegada", file=sys.stderr)
        return False
    return sys.stdin.readline().strip().lower() in ("s", "si", "sí", "y", "yes")


def show(ev: Event) -> None:
    if ev.kind == "tool_call":
        print(f"→ {ev.data['name']} {json.dumps(ev.data['args'], ensure_ascii=False)}", file=sys.stderr)
    elif ev.kind == "tool_result":
        r = ev.data["result"]
        print(f"  {'✓' if r.get('ok') else '✗'} {r.get('error', 'ok')}", file=sys.stderr)
    elif ev.kind == "error":
        print(f"! {ev.data['error']}", file=sys.stderr)


BACKENDS = ("ollama", "openai", "opencode")
DEFAULT_MODEL = "qwen3:8b"


def add_agent_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--scope", default="scope.toml")
    p.add_argument("--state", default="adverso.json", help="JSON de persistencia (Palacios y Sombras)")
    p.add_argument("--audit", default="audit.log")
    p.add_argument("--backend", choices=BACKENDS, default="ollama",
                   help="ollama: API nativa | openai: cualquier /v1/chat/completions | opencode: el agente opencode")
    p.add_argument("--model", default=None,
                   help=f"por defecto {DEFAULT_MODEL}; con opencode, proveedor/modelo (sin proveedor = ollama/)")
    p.add_argument("--url", "--ollama-url", dest="url", default=None,
                   help=f"URL del modelo (ollama: {OLLAMA_URL}; openai: {OPENAI_URL})")
    p.add_argument("--api-key-env", default=DEFAULT_KEY_ENV,
                   help="variable de entorno con la clave de la API (solo --backend openai)")
    p.add_argument("--text-tools", action="store_true",
                   help="protocolo JSON en texto, para modelos sin tool calling (ollama/openai)")
    p.add_argument("--max-steps", type=int, default=10)
    p.add_argument("--timeout", type=float, default=600, help="segundos por respuesta del modelo")


def build_agent(a: argparse.Namespace, executor: Executor, on_event=show) -> Runner:
    """Construye el agente pedido. Todos comparten el mismo `Executor` y garantías."""
    if a.backend == "opencode":
        from ..agents.opencode import OpencodeAgent
        model = a.model or DEFAULT_MODEL
        return OpencodeAgent(
            model=model if "/" in model else f"ollama/{model}",
            ollama_url=a.url or OLLAMA_URL,
            scope_path=a.scope, audit_path=a.audit, state_path=a.state,
            confirm=executor.confirm, store=executor.store,
            max_steps=a.max_steps, timeout=a.timeout * a.max_steps, response_timeout=a.timeout, on_event=on_event,
        )
    if a.backend == "openai":
        if not a.model:
            raise SystemExit("--backend openai necesita --model (el nombre que espera el servidor)")
        client: Any = OpenAICompatClient.from_env(a.model, a.url or OPENAI_URL, a.api_key_env,
                                                  timeout=a.timeout, native_tools=not a.text_tools)
    else:
        client = OllamaClient(a.model or DEFAULT_MODEL, a.url or OLLAMA_URL, timeout=a.timeout,
                              native_tools=False if a.text_tools else None)
    return Agent(client, executor, max_steps=a.max_steps, on_event=on_event)


def _reachable(url: str, headers: dict[str, str] | None = None) -> bool:
    try:
        urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=3).close()
        return True
    except Exception:
        return False


def doctor(a: argparse.Namespace) -> int:
    """Diagnóstico: qué falta para operar. Devuelve 0 si todo lo necesario está."""
    ok = True

    def line(good: bool, what: str, required: bool = True) -> None:
        nonlocal ok
        print(f"{'✓' if good else ('✗' if required else '·')} {what}")
        ok &= good or not required

    for b in ("nmap", "gobuster", "nikto", "dig", "whois", "theHarvester", "whatweb"):
        line(shutil.which(b) is not None, f"herramienta {b}", required=False)
    line(os.path.isfile("/usr/share/wordlists/dirb/common.txt"), "diccionario dirb/common.txt", required=False)
    line(os.path.isfile(a.scope), f"alcance {a.scope}")
    if a.backend == "openai":
        url = (a.url or OPENAI_URL).rstrip("/")
        key = os.environ.get(a.api_key_env)
        line(_reachable(url + "/models", {"Authorization": f"Bearer {key}"} if key else None), f"API OpenAI en {url}")
    else:
        url = (a.url or OLLAMA_URL).rstrip("/")
        line(_reachable(url + "/api/tags"), f"Ollama en {url}")
    if a.backend == "opencode":
        line(shutil.which("opencode") is not None, "opencode en el PATH")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="adverso")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("recon", help="reconocimiento guiado por un agente")
    r.add_argument("task", help='ej. "Reconoce 192.168.56.10 y dime qué servicios expone"')
    add_agent_args(r)
    for name, helptext in (("palaces", "lista los Palacios conocidos"), ("report", "genera el informe en Markdown")):
        q = sub.add_parser(name, help=helptext)
        q.add_argument("--state", default="adverso.json")
        if name == "report":
            q.add_argument("--out", help="archivo de salida (por defecto, stdout)")
    c = sub.add_parser("chat", help="sesión interactiva con comandos / (estilo asistente)")
    add_agent_args(c)
    d = sub.add_parser("doctor", help="comprueba herramientas, alcance y modelo")
    add_agent_args(d)
    m = sub.add_parser("mcp", help="servidor MCP (stdio) con las herramientas, para opencode u otro cliente")
    m.add_argument("--scope", default="scope.toml")
    m.add_argument("--state", default="adverso.json")
    m.add_argument("--audit", default="audit.log")
    m.add_argument("--bridge", default=None, help="socket del proceso padre para aprobaciones y eventos")
    m.add_argument("--max-calls", type=int, default=30, help="presupuesto de llamadas por sesión")
    a = p.parse_args(argv)

    if a.cmd == "mcp":
        from ..mcp.server import run_mcp
        return run_mcp(a)
    if a.cmd == "chat":
        from .repl import run_chat
        return run_chat(a)
    if a.cmd == "doctor":
        return doctor(a)
    if a.cmd == "palaces":
        for pl in sorted(Store(a.state).palaces.values(), key=palace_score, reverse=True):
            print(f"{pl['ip']:<40} {palace_rank(pl).label:<9} {palace_score(pl):>3}  {len(pl['findings'])} sombras")
        return 0
    if a.cmd == "report":
        text = render_markdown(Store(a.state))
        if a.out:
            open(a.out, "w", encoding="utf8").write(text)
        else:
            print(text)
        return 0

    try:
        scope = Scope.load(a.scope)
    except FileNotFoundError:
        print(f"No existe {a.scope}. Copia scope.example.toml y declara tus objetivos autorizados.", file=sys.stderr)
        return 2
    agent = build_agent(a, Executor(scope, AuditLog(a.audit), confirm=ask_operator, store=Store(a.state)))
    result = agent.run(a.task)
    print(result.final)
    return 0 if result.completed else 1


if __name__ == "__main__":
    sys.exit(main())
