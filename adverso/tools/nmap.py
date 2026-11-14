from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from .base import Tool, ToolError, require_str

# Perfiles cerrados: el agente elige uno, nunca pasa flags arbitrarios.
PROFILES: dict[str, list[str]] = {
    "ping": ["-sn"],
    "rapido": ["-T4", "-F"],
    "servicios": ["-T4", "-sV", "--version-light"],
    "completo": ["-T4", "-p-"],
}
_PORTS = re.compile(r"^[0-9]{1,5}([,-][0-9]{1,5})*$")


class Nmap(Tool):
    name = "nmap_scan"
    binary = "nmap"
    description = "Descubre hosts y puertos abiertos y, según el perfil, los servicios que corren."
    timeout = 900
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "IP, red CIDR o host autorizado"},
            "profile": {"type": "string", "enum": sorted(PROFILES), "default": "rapido"},
            "ports": {"type": "string", "description": "Opcional, ej. '22,80,8000-8100'"},
        },
        "required": ["target"],
    }

    def target_of(self, args):
        return require_str(args, "target")

    def build_command(self, args):
        profile = args.get("profile", "rapido")
        if profile not in PROFILES:
            raise ToolError(f"perfil desconocido: {profile}")
        cmd = ["nmap", *PROFILES[profile], "-oX", "-"]
        ports = args.get("ports")
        if ports:
            if profile == "ping" or not _PORTS.match(str(ports)):
                raise ToolError("ports inválido")
            cmd += ["-p", str(ports)]
        return [*cmd, "--", require_str(args, "target")]

    def parse(self, stdout, stderr, args):
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as e:
            raise ToolError(f"salida de nmap ilegible: {e}")
        hosts = []
        for h in root.findall("host"):
            addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype", "").startswith("ipv")), None)
            name = h.findtext("hostnames/hostname[@name]") or (h.find("hostnames/hostname").get("name") if h.find("hostnames/hostname") is not None else None)
            ports = []
            for p in h.findall("ports/port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = p.find("service")
                ports.append({
                    "port": int(p.get("portid")),
                    "protocol": p.get("protocol"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                })
            hosts.append({
                "address": addr,
                "hostname": name,
                "up": (h.find("status").get("state") == "up") if h.find("status") is not None else False,
                "open_ports": ports,
            })
        return {"hosts": hosts}
