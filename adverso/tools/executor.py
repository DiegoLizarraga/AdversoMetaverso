"""Punto único por el que pasa TODA ejecución de herramientas.

Orden fijo: validar argumentos → guardia de alcance → confirmación humana si es
intrusiva → auditoría → ejecución sin shell → parseo a JSON. El agente nunca
llama a una herramienta directamente.
"""

from __future__ import annotations

import ipaddress
import time
from typing import Any, Callable

from ..scope.audit import AuditLog
from ..scope.guard import OutOfScope, Scope
from .base import Pin, Tool, ToolError
from .gobuster import Gobuster
from .nikto import Nikto
from .nmap import Nmap

#: Recibe (herramienta, objetivo, comando) y devuelve True si el humano aprueba.
Confirm = Callable[[Tool, str, list[str]], bool]


def deny_all(tool: Tool, target: str, cmd: list[str]) -> bool:
    return False


def default_tools() -> dict[str, Tool]:
    return {t.name: t for t in (Nmap(), Gobuster(), Nikto())}


class Executor:
    def __init__(self, scope: Scope, audit: AuditLog, confirm: Confirm = deny_all,
                 tools: dict[str, Tool] | None = None, store: Any = None) -> None:
        self.store = store  # Store opcional: recibe los hallazgos de cada ejecución
        self.scope = scope
        self.audit = audit
        self.confirm = confirm
        self.tools = tools if tools is not None else default_tools()

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self.tools.values()]

    def run(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Devuelve siempre un dict serializable; los fallos van en `error`."""
        tool = self.tools.get(name)
        if tool is None:
            return {"ok": False, "error": f"herramienta desconocida: {name}"}
        try:
            tool.validate(args)
            target = tool.target_of(args)
            tool.build_command(args)  # valida los argumentos antes de tocar la red
        except ToolError as e:
            self.audit.record("invalid_args", tool=name, args=args, error=str(e))
            return {"ok": False, "error": str(e)}

        try:
            ips = self.scope.check(target)
        except OutOfScope as e:
            self.audit.record("denied_scope", tool=name, target=target, reason=str(e))
            return {"ok": False, "error": f"fuera de alcance: {e}"}

        # Anti-TOCTOU: si el objetivo es un nombre, la herramienta recibe la IP que
        # acabamos de validar y no vuelve a resolverlo.
        pin = None
        if not _is_ip_or_net(target):
            if not ips:
                self.audit.record("denied_scope", tool=name, target=target, reason="no resuelve")
                return {"ok": False, "error": f"{target} no resuelve a ninguna IP"}
            pin = Pin(target, ips[0])
            if not all(self.scope._ip_allowed(i) for i in ips):
                self.audit.record("named_host_outside_networks", tool=name, target=target, ips=ips)
        cmd = tool.build_command(args, pin)

        if tool.intrusive:
            approved = self.confirm(tool, target, cmd)
            self.audit.record("confirmation", tool=name, target=target, approved=approved)
            if not approved:
                return {"ok": False, "error": "acción intrusiva no aprobada por el operador"}

        self.audit.record("run", tool=name, target=target, ips=ips, pinned=pin.ip if pin else None, cmd=cmd)
        started = time.time()
        try:
            raw = tool.execute(cmd)
            if raw.timed_out:
                self.audit.record("timeout", tool=name, target=target)
                return {"ok": False, "error": "tiempo agotado", "partial_output": raw.stdout[-2000:]}
            if raw.returncode != 0 and not raw.stdout.strip():
                self.audit.record("failed", tool=name, target=target, rc=raw.returncode)
                return {"ok": False, "error": f"código {raw.returncode}: {raw.stderr.strip()[-500:]}"}
            result = tool.parse(raw.stdout, raw.stderr, args)
        except ToolError as e:
            self.audit.record("failed", tool=name, target=target, error=str(e))
            return {"ok": False, "error": str(e)}
        self.audit.record("done", tool=name, target=target, seconds=round(time.time() - started, 2))
        out = {"ok": True, "tool": name, "target": target, "result": result}
        if pin:
            out["pinned_ip"] = pin.ip
        if self.store is not None:
            from ..core.findings import ingest
            added = ingest(self.store, name, target, pin.ip if pin else None, result)
            out["new_findings"] = added
        return out


def _is_ip_or_net(t: str) -> bool:
    try:
        ipaddress.ip_network(t.strip(), strict=False)
        return True
    except ValueError:
        return False
