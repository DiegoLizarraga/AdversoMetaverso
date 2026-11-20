"""CLI: recon (agente), palaces, report, doctor."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.request

from ..agents.base import Agent, Event
from ..agents.ollama import DEFAULT_URL, OllamaClient
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


def doctor(scope_path: str, url: str) -> int:
    """Diagnóstico: qué falta para operar. Devuelve 0 si todo lo necesario está."""
    ok = True

    def line(good: bool, what: str, required: bool = True) -> None:
        nonlocal ok
        print(f"{'✓' if good else ('✗' if required else '·')} {what}")
        ok &= good or not required

    for b in ("nmap", "gobuster", "nikto", "dig", "whois", "theHarvester", "whatweb"):
        line(shutil.which(b) is not None, f"herramienta {b}", required=False)
    line(os.path.isfile("/usr/share/wordlists/dirb/common.txt"), "diccionario dirb/common.txt", required=False)
    line(os.path.isfile(scope_path), f"alcance {scope_path}")
    try:
        urllib.request.urlopen(url.rstrip("/") + "/api/tags", timeout=3).close()
        line(True, f"Ollama en {url}")
    except Exception:
        line(False, f"Ollama en {url}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="adverso")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("recon", help="reconocimiento guiado por un agente")
    r.add_argument("task", help='ej. "Reconoce 192.168.56.10 y dime qué servicios expone"')
    r.add_argument("--scope", default="scope.toml")
    r.add_argument("--model", default="qwen3:8b")
    r.add_argument("--state", default="adverso.json", help="JSON de persistencia (Palacios y Sombras)")
    r.add_argument("--ollama-url", default=DEFAULT_URL)
    r.add_argument("--audit", default="audit.log")
    r.add_argument("--max-steps", type=int, default=10)
    r.add_argument("--timeout", type=float, default=600, help="segundos por respuesta del modelo")
    for name, helptext in (("palaces", "lista los Palacios conocidos"), ("report", "genera el informe en Markdown")):
        q = sub.add_parser(name, help=helptext)
        q.add_argument("--state", default="adverso.json")
        if name == "report":
            q.add_argument("--out", help="archivo de salida (por defecto, stdout)")
    c = sub.add_parser("chat", help="sesión interactiva con comandos / (estilo asistente)")
    c.add_argument("--scope", default="scope.toml")
    c.add_argument("--model", default="qwen3:8b")
    c.add_argument("--state", default="adverso.json")
    c.add_argument("--ollama-url", default=DEFAULT_URL)
    c.add_argument("--audit", default="audit.log")
    c.add_argument("--max-steps", type=int, default=10)
    c.add_argument("--timeout", type=float, default=600)
    d = sub.add_parser("doctor", help="comprueba herramientas, alcance y modelo")
    d.add_argument("--scope", default="scope.toml")
    d.add_argument("--ollama-url", default=DEFAULT_URL)
    a = p.parse_args(argv)

    if a.cmd == "chat":
        from .repl import run_chat
        return run_chat(a)
    if a.cmd == "doctor":
        return doctor(a.scope, a.ollama_url)
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
    client = OllamaClient(a.model, a.ollama_url, timeout=a.timeout)
    agent = Agent(client, Executor(scope, AuditLog(a.audit), confirm=ask_operator, store=Store(a.state)),
                  max_steps=a.max_steps, on_event=show)
    result = agent.run(a.task)
    print(result.final)
    return 0 if result.completed else 1


if __name__ == "__main__":
    sys.exit(main())
