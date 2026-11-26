"""Sesión interactiva: texto libre = tarea para el agente; `/comando` = control directo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from ..agents.base import Runner
from ..core.findings import palace_rank, palace_score
from ..core.models import ShadowKind
from ..core.store import Store
from ..reports.card import render_markdown
from ..scope.audit import AuditLog
from ..tools.executor import Executor

HELP = """Escribe una tarea en lenguaje natural ("reconoce 192.168.56.10", "OSINT de example.com")
o usa un comando:
  /palacios            Palacios conocidos y su rango
  /sombras [ip]        hallazgos (de un Palacio o todos), por gravedad
  /informe [archivo]   informe Markdown (a pantalla o a archivo)
  /alcance             objetivos autorizados
  /herramientas        herramientas disponibles (pasivas / activas / intrusivas)
  /auditoria [n]       últimas n entradas de auditoría (por defecto 10)
  /olvida [ip]         borra un Palacio (o todos con /olvida todo)
  /ayuda               esta ayuda
  /salir"""


class Repl:
    def __init__(self, agent: Runner, executor: Executor, store: Store, audit_path: str | Path,
                 out: Callable[[str], None] = print) -> None:
        self.agent, self.executor, self.store = agent, executor, store
        self.audit_path = Path(audit_path)
        self.out = out

    def handle(self, line: str) -> bool:
        """Procesa una línea. Devuelve False cuando hay que salir."""
        line = line.strip()
        if not line:
            return True
        if not line.startswith("/"):
            res = self.agent.run(line)
            self.out(res.final)
            return True
        cmd, _, arg = line[1:].partition(" ")
        arg = arg.strip()
        self.store.reload()  # el monitor o el agente pueden haber escrito desde otro proceso
        fn = getattr(self, f"cmd_{cmd.lower()}", None)
        if cmd.lower() in ("salir", "exit", "quit"):
            return False
        if fn is None:
            self.out(f"Comando desconocido: /{cmd}. Prueba /ayuda.")
        else:
            fn(arg)
        return True

    def cmd_ayuda(self, arg: str) -> None:
        self.out(HELP)

    def cmd_palacios(self, arg: str) -> None:
        if not self.store.palaces:
            return self.out("Sin Palacios todavía.")
        for p in sorted(self.store.palaces.values(), key=palace_score, reverse=True):
            names = f" ({', '.join(p['names'])})" if p["names"] else ""
            self.out(f"{p['ip'] + names:<44} {palace_rank(p).label:<9} {palace_score(p):>3}  {len(p['findings'])} sombras")

    def cmd_sombras(self, arg: str) -> None:
        palaces = [self.store.palaces[arg]] if arg in self.store.palaces else (
            list(self.store.palaces.values()) if not arg else [])
        if not palaces:
            return self.out(f"No conozco el Palacio {arg!r}.")
        rows = [(f["score"], p["ip"], f) for p in palaces for f in p["findings"].values()]
        for score, ip, f in sorted(rows, key=lambda r: -r[0])[:50]:
            self.out(f"{score:>3} {ip:<18} {f['codename']:<12} {ShadowKind[f['kind']].display:<18} {f['title']}")

    def cmd_informe(self, arg: str) -> None:
        text = render_markdown(self.store)
        if arg:
            Path(arg).write_text(text, encoding="utf8")
            self.out(f"Informe escrito en {arg}")
        else:
            self.out(text)

    def cmd_alcance(self, arg: str) -> None:
        s = self.executor.scope
        entries = [str(n) for n in s.networks] + sorted(s.hosts) + [f"*.{w}" for w in sorted(s.wildcards)]
        self.out("Objetivos autorizados:\n  " + "\n  ".join(entries) if entries else "Alcance vacío: no se puede tocar nada.")

    def cmd_herramientas(self, arg: str) -> None:
        for t in self.executor.tools.values():
            kind = "pasiva" if t.passive else ("INTRUSIVA" if t.intrusive else "activa")
            self.out(f"{t.name:<22} {kind:<10} {t.description}")

    def cmd_auditoria(self, arg: str) -> None:
        n = int(arg) if arg.isdigit() else 10
        if not self.audit_path.exists():
            return self.out("Sin auditoría todavía.")
        for raw in self.audit_path.read_text(encoding="utf8").splitlines()[-n:]:
            try:
                e = json.loads(raw)
                self.out(f"{e.pop('event'):<22} " + " ".join(f"{k}={v}" for k, v in e.items() if k not in ("ts", "cmd", "ips")))
            except (ValueError, KeyError):
                self.out(raw)

    def cmd_olvida(self, arg: str) -> None:
        with self.store.transaction():
            if arg == "todo":
                self.store.palaces.clear()
            elif self.store.palaces.pop(arg, None) is None:
                return self.out("Uso: /olvida <ip|dominio> o /olvida todo")
        self.out("Hecho.")


def run_chat(a) -> int:
    from ..scope.guard import Scope
    from .cli import ask_operator, build_agent

    try:
        scope = Scope.load(a.scope)
    except FileNotFoundError:
        print(f"No existe {a.scope}. Copia scope.example.toml y declara tus objetivos autorizados.")
        return 2
    store = Store(a.state)
    executor = Executor(scope, AuditLog(a.audit), confirm=ask_operator, store=store)
    repl = Repl(build_agent(a, executor), executor, store, a.audit)
    print(f"AdversoMetaverso ({a.backend}) — /ayuda para ver comandos.")
    while True:
        try:
            line = input("\n☾ ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not repl.handle(line):
            return 0
