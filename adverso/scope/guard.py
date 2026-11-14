"""Guardia de alcance: nada se ejecuta contra un objetivo no autorizado.

El alcance se declara en un archivo TOML (`scope.toml`):

    [scope]
    targets = ["192.168.56.0/24", "lab.local", "10.0.0.5"]

Un nombre de host se acepta si figura en la lista (o coincide con una entrada
`*.dominio`). Si no figura, solo se acepta cuando TODAS las IP a las que resuelve
caen en las redes autorizadas.
"""

from __future__ import annotations

import ipaddress
import socket
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

Resolver = Callable[[str], list[str]]


class OutOfScope(Exception):
    """El objetivo no está en la lista de autorizados."""


def _system_resolver(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


@dataclass
class Scope:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    wildcards: set[str] = field(default_factory=set)
    resolver: Resolver = _system_resolver

    @classmethod
    def from_entries(cls, entries: list[str], resolver: Resolver = _system_resolver) -> "Scope":
        s = cls(resolver=resolver)
        for raw in entries:
            e = raw.strip().lower()
            if not e:
                continue
            if e.startswith("*."):
                s.wildcards.add(e[2:])
                continue
            try:
                s.networks.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                s.hosts.add(e)
        return s

    @classmethod
    def load(cls, path: str | Path, resolver: Resolver = _system_resolver) -> "Scope":
        data = tomllib.loads(Path(path).read_text(encoding="utf8"))
        return cls.from_entries(list(data.get("scope", {}).get("targets", [])), resolver)

    def _ip_allowed(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in self.networks)

    def check(self, target: str) -> list[str]:
        """Devuelve las IP resueltas si el objetivo está autorizado; si no, OutOfScope."""
        t = target.strip().lower().rstrip(".")
        if not t or t.startswith("-") or any(c.isspace() for c in t):
            raise OutOfScope(f"objetivo inválido: {target!r}")

        # IP o red literal
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if any(net.subnet_of(n) for n in self.networks if n.version == net.version):
                return [str(net.network_address)]
            raise OutOfScope(f"{target} no está dentro del alcance")

        # Nombre de host
        named = t in self.hosts or any(t == w or t.endswith("." + w) for w in self.wildcards)
        ips = self.resolver(t)
        if named:
            return ips  # autorizado explícitamente por nombre
        if ips and all(self._ip_allowed(i) for i in ips):
            return ips  # no listado, pero TODAS sus IP caen en redes autorizadas
        raise OutOfScope(f"{target} no está autorizado")
