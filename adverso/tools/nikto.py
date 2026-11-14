from __future__ import annotations

import re

from .base import Tool, ToolError, require_str

_ITEM = re.compile(r"^\+ (?:\[(?P<id>\d+)\] )?(?P<text>.+)$")
_NOISE_START = ("Target ", "Start Time", "End Time", "Platform:")
_NOISE_ANY = ("host(s) tested", " requests: ")


class Nikto(Tool):
    name = "nikto_scan"
    binary = "nikto"
    description = "Busca configuraciones débiles y vulnerabilidades conocidas en un servidor web."
    intrusive = True
    timeout = 900
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL base, ej. http://10.0.0.5:8080"},
            "max_seconds": {"type": "integer", "minimum": 10, "maximum": 600, "default": 120},
        },
        "required": ["url"],
    }

    def target_of(self, args):
        url = require_str(args, "url")
        m = re.match(r"^https?://([^/:?#]+|\[[0-9a-fA-F:]+\])", url)
        if not m:
            raise ToolError("url debe empezar por http:// o https://")
        return m.group(1).strip("[]")

    def build_command(self, args):
        url = require_str(args, "url")
        self.target_of(args)
        secs = int(args.get("max_seconds", 120))
        if not 10 <= secs <= 600:
            raise ToolError("max_seconds fuera de rango (10-600)")
        # stdin cerrado por Tool.execute: nikto nunca puede enviar datos a CIRT.net.
        return ["nikto", "-h", url, "-nointeractive", "-maxtime", f"{secs}s"]

    def parse(self, stdout, stderr, args):
        findings = []
        for line in stdout.splitlines():
            m = _ITEM.match(line.strip())
            if not m:
                continue
            text = m.group("text")
            if text.startswith(_NOISE_START) or any(n in text for n in _NOISE_ANY) or set(text) <= {"-", "*"}:
                continue
            findings.append({"id": m.group("id"), "text": text})
        return {"findings": findings}
