"""CLI: `python -m adverso recon "tarea" --scope scope.toml --model qwen3:30b`."""

from __future__ import annotations

import argparse
import json
import sys

from ..agents.base import Agent, Event
from ..agents.ollama import DEFAULT_URL, OllamaClient
from ..scope.audit import AuditLog
from ..scope.guard import Scope
from ..tools.base import Tool
from ..tools.executor import Executor


def ask_operator(tool: Tool, target: str, cmd: list[str]) -> bool:
    """Confirmación humana en terminal para acciones intrusivas."""
    print(f"\n⚠  ACCIÓN INTRUSIVA: {tool.name} contra {target}\n   $ {' '.join(cmd)}", file=sys.stderr)
    if not sys.stdin.isatty():
        print("   (sin terminal interactiva: denegada)", file=sys.stderr)
        return False
    return input("   ¿Aprobar? [s/N] ").strip().lower() in ("s", "si", "sí", "y", "yes")


def show(ev: Event) -> None:
    if ev.kind == "tool_call":
        print(f"→ {ev.data['name']} {json.dumps(ev.data['args'], ensure_ascii=False)}", file=sys.stderr)
    elif ev.kind == "tool_result":
        r = ev.data["result"]
        print(f"  {'✓' if r.get('ok') else '✗'} {r.get('error', 'ok')}", file=sys.stderr)
    elif ev.kind == "error":
        print(f"! {ev.data['error']}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="adverso")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("recon", help="reconocimiento guiado por un agente")
    r.add_argument("task", help='ej. "Reconoce 192.168.56.10 y dime qué servicios expone"')
    r.add_argument("--scope", default="scope.toml")
    r.add_argument("--model", default="qwen3:30b")
    r.add_argument("--ollama-url", default=DEFAULT_URL)
    r.add_argument("--audit", default="audit.log")
    r.add_argument("--max-steps", type=int, default=10)
    r.add_argument("--timeout", type=float, default=600, help="segundos por respuesta del modelo")
    a = p.parse_args(argv)

    try:
        scope = Scope.load(a.scope)
    except FileNotFoundError:
        print(f"No existe {a.scope}. Copia scope.example.toml y declara tus objetivos autorizados.", file=sys.stderr)
        return 2
    client = OllamaClient(a.model, a.ollama_url, timeout=a.timeout)
    agent = Agent(client, Executor(scope, AuditLog(a.audit), confirm=ask_operator),
                  max_steps=a.max_steps, on_event=show)
    result = agent.run(a.task)
    print(result.final)
    return 0 if result.completed else 1


if __name__ == "__main__":
    sys.exit(main())
