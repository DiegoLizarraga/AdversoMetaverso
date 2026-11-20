"""Herramientas OSINT pasivas: consultan terceros (DNS, WHOIS, CT logs), no al objetivo.

Por eso `passive = True`: no pasan por la guardia de alcance (investigar un dominio
no es tocarlo), pero el nombre se valida sintácticamente y todo se audita.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .base import Pin, Tool, ToolError, host_header, require_str, swap_host, url_host, url_parts

_NAME = re.compile(r"^(?!-)[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$")
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


def valid_name(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if not _NAME.match(v) or ".." in v:
        raise ToolError(f"nombre de dominio o IP inválido: {value!r}")
    return v


class Dig(Tool):
    name = "dns_lookup"
    binary = "dig"
    description = "Consulta registros DNS de un dominio (A, MX, NS, TXT…). Pasiva."
    passive = True
    timeout = 30
    parameters = {"type": "object", "properties": {
        "domain": {"type": "string"},
        "record": {"type": "string", "enum": RECORD_TYPES, "default": "A"}}, "required": ["domain"]}

    def target_of(self, args):
        return valid_name(require_str(args, "domain"))

    def build_command(self, args, pin: Pin | None = None):
        return ["dig", "+noall", "+answer", "+time=3", "+tries=1", self.target_of(args), args.get("record", "A")]

    def parse(self, stdout, stderr, args):
        records = []
        for line in stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) == 5 and parts[2] == "IN":
                records.append({"name": parts[0].rstrip("."), "ttl": int(parts[1]) if parts[1].isdigit() else None,
                                "type": parts[3], "data": parts[4]})
        return {"records": records}


_WHOIS_KEYS = ("registrar", "creation date", "registry expiry date", "updated date", "name server",
               "registrant organization", "registrant country", "domain status", "netname", "orgname", "country", "cidr")


class Whois(Tool):
    name = "whois_lookup"
    binary = "whois"
    description = "WHOIS de un dominio o IP: registrador, fechas, servidores de nombres, organización. Pasivo."
    passive = True
    timeout = 45
    parameters = {"type": "object", "properties": {"target": {"type": "string", "description": "dominio o IP"}},
                  "required": ["target"]}

    def target_of(self, args):
        return valid_name(require_str(args, "target"))

    def build_command(self, args, pin: Pin | None = None):
        return ["whois", self.target_of(args)]

    def parse(self, stdout, stderr, args):
        fields: dict[str, list[str]] = {}
        for line in stdout.splitlines():
            k, sep, v = line.partition(":")
            k = k.strip().lower()
            if sep and k in _WHOIS_KEYS and v.strip():
                vals = fields.setdefault(k, [])
                if v.strip() not in vals and len(vals) < 8:
                    vals.append(v.strip())
        return {"fields": fields}


class TheHarvester(Tool):
    name = "harvest_domain"
    binary = "theHarvester"
    description = "Enumera subdominios, IPs y correos de un dominio en fuentes públicas (crt.sh, hackertarget). Pasiva."
    passive = True
    timeout = 180
    parameters = {"type": "object", "properties": {
        "domain": {"type": "string"},
        "limit": {"type": "integer", "minimum": 10, "maximum": 500, "default": 100}}, "required": ["domain"]}

    def target_of(self, args):
        return valid_name(require_str(args, "domain"))

    def build_command(self, args, pin: Pin | None = None):
        limit = int(args.get("limit", 100))
        if not 10 <= limit <= 500:
            raise ToolError("limit fuera de rango (10-500)")
        return ["theHarvester", "-d", self.target_of(args), "-b", "crtsh,hackertarget", "-l", str(limit)]

    def parse(self, stdout, stderr, args):
        section = None
        hosts: dict[str, str | None] = {}
        emails: list[str] = []
        for raw in stdout.splitlines():
            line = raw.strip()
            m = re.match(r"^\[\*\] (hosts|ips|emails) found", line, re.I)
            if m:
                section = m.group(1).lower()
                continue
            if not line or line.startswith(("[*]", "*", "-")):
                section = None if line.startswith("[*]") else section
                continue
            if section == "hosts":
                name, _, ip = line.partition(":")
                if _NAME.match(name.lower()):
                    hosts[name.lower()] = ip or None
            elif section == "emails" and "@" in line:
                emails.append(line.lower())
        return {"hosts": [{"name": n, "ip": ip} for n, ip in sorted(hosts.items())][:300], "emails": sorted(set(emails))[:100]}


# Plugins de whatweb que no son tecnologías (metadatos de la respuesta).
_WHATWEB_NOISE = {"Country", "IP", "Title", "UncommonHeaders", "HTML5", "Email", "Cookies", "Script", "Meta-Author"}


class WhatWeb(Tool):
    name = "whatweb_fingerprint"
    binary = "whatweb"
    description = "Identifica tecnologías de un sitio web (servidor, CMS, frameworks). Sigilosa (nivel 1) pero toca el objetivo."
    timeout = 120
    parameters = {"type": "object", "properties": {"url": {"type": "string", "description": "ej. http://10.0.0.5:8080"}},
                  "required": ["url"]}

    def target_of(self, args):
        return url_host(require_str(args, "url"))

    def build_command(self, args, pin: Pin | None = None):
        url = require_str(args, "url")
        self.target_of(args)
        cmd = ["whatweb", "--color=never", "-a", "1", "--log-json=-"]
        if pin:
            cmd += ["--header", f"Host: {host_header(url)}"]
            url = swap_host(url, pin.ip)
        return [*cmd, url]

    def parse(self, stdout, stderr, args):
        techs: dict[str, Any] = {}
        status = None
        text = stdout.strip()
        try:
            data = json.loads(text) if text else []
        except json.JSONDecodeError:
            raise ToolError("salida de whatweb ilegible")
        for entry in data if isinstance(data, list) else [data]:
            status = entry.get("http_status", status)
            for name, info in (entry.get("plugins") or {}).items():
                if name in _WHATWEB_NOISE:
                    continue
                vals = [v for k in ("version", "string") for v in (info.get(k) or [])]
                techs[name] = vals[:3]
        return {"http_status": status, "technologies": techs}
