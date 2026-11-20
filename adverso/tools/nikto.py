from __future__ import annotations

import re

from .base import Pin, Tool, ToolError, require_str, swap_host, url_host

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
        return url_host(require_str(args, "url"))

    def build_command(self, args, pin: Pin | None = None):
        url = require_str(args, "url")
        self.target_of(args)
        secs = int(args.get("max_seconds", 120))
        if not 10 <= secs <= 600:
            raise ToolError("max_seconds fuera de rango (10-600)")
        # stdin cerrado por Tool.execute: nikto nunca puede enviar datos a CIRT.net.
        cmd = ["nikto", "-nointeractive", "-maxtime", f"{secs}s"]
        if pin:
            cmd += ["-vhost", pin.host]
            url = swap_host(url, pin.ip)
        return [*cmd, "-h", url]

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
