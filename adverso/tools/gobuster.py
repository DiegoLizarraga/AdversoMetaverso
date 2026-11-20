from __future__ import annotations

import os
import re
from typing import Any

from .base import Pin, Tool, ToolError, host_header, require_str, swap_host, url_host, url_parts

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_LINE = re.compile(r"^(?P<path>/?\S+)\s+(?:\(Status: (?P<st>\d+)\)\s*)?(?:\[Size: (?P<size>\d+)\])?(?:\s*\[--> (?P<redir>\S+)\])?")


class Gobuster(Tool):
    name = "gobuster_dir"
    binary = "gobuster"
    description = "Descubre directorios y archivos en un sitio web por diccionario."
    intrusive = True  # genera miles de peticiones contra el objetivo
    timeout = 900
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL base, ej. http://10.0.0.5:8080"},
            "wordlist": {"type": "string", "description": f"Ruta del diccionario (por defecto {DEFAULT_WORDLIST})"},
            "threads": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
        },
        "required": ["url"],
    }

    def target_of(self, args):
        return url_host(require_str(args, "url"))

    def build_command(self, args, pin: Pin | None = None):
        url = require_str(args, "url")
        self.target_of(args)
        wl = args.get("wordlist") or DEFAULT_WORDLIST
        if not os.path.isfile(wl):
            raise ToolError(f"diccionario no encontrado: {wl}")
        threads = int(args.get("threads", 5))
        if not 1 <= threads <= 20:
            raise ToolError("threads fuera de rango (1-20)")
        cmd = ["gobuster", "dir", "-w", wl, "-q", "--no-color", "-t", str(threads)]
        if pin:
            cmd += ["-H", f"Host: {host_header(url)}"]
            if url_parts(url).scheme == "https":
                cmd += ["-k"]  # el certificado es del nombre, no de la IP
            url = swap_host(url, pin.ip)
        return [*cmd, "-u", url]

    def parse(self, stdout, stderr, args):
        found = []
        for line in stdout.splitlines():
            m = _LINE.match(line.strip())
            if not m or not (m.group("st") or m.group("size")):
                continue
            found.append({
                "path": m.group("path"),
                "status": int(m.group("st")) if m.group("st") else None,
                "size": int(m.group("size")) if m.group("size") else None,
                "redirect": m.group("redir"),
            })
        return {"found": found}
