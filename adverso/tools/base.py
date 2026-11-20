"""Contrato de una herramienta: esquema para el agente, comando, parser."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

MAX_OUTPUT = 2_000_000  # bytes que se conservan de stdout


class ToolError(Exception):
    """Argumentos inválidos o fallo al ejecutar."""


@dataclass
class RawResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class Pin:
    """Nombre validado por la guardia y la IP concreta a la que resolvió entonces.

    La herramienta debe conectarse a `ip` (no volver a resolver `host`): si no, un
    DNS hostil puede devolver una IP autorizada al validar y otra al escanear.
    """

    host: str
    ip: str


def url_parts(url: str):
    """Parsea una URL http(s) o falla. Rechaza `user@host` (el motivo clásico de
    confundir qué host se contacta de verdad: `http://10.0.0.5:80@evil.com/`)."""
    try:
        u = urlsplit(url.strip())
        host, _ = u.hostname, u.port
    except ValueError:
        raise ToolError("url inválida")
    if u.scheme not in ("http", "https") or not host:
        raise ToolError("url debe empezar por http:// o https://")
    if u.username is not None or u.password is not None:
        raise ToolError("la url no puede llevar credenciales (usuario@host)")
    return u


def url_host(url: str) -> str:
    return url_parts(url).hostname  # type: ignore[return-value]


def swap_host(url: str, ip: str) -> str:
    """Reescribe la URL para conectarse a `ip`, conservando puerto y ruta."""
    u = url_parts(url)
    netloc = f"[{ip}]" if ":" in ip else ip
    if u.port:
        netloc += f":{u.port}"
    return u._replace(netloc=netloc).geturl()


def host_header(url: str) -> str:
    u = url_parts(url)
    return u.netloc.rsplit("@", 1)[-1]


class Tool:
    name: str = ""
    binary: str = ""
    description: str = ""
    #: Una herramienta intrusiva exige confirmación humana antes de ejecutarse.
    intrusive: bool = False
    #: Pasiva: consulta a terceros, no al objetivo. Se salta la guardia de alcance
    #: (el nombre se valida igualmente y todo queda auditado).
    passive: bool = False
    timeout: int = 300
    #: JSON Schema de los argumentos que ve el agente.
    parameters: dict[str, Any] = {}

    def validate(self, args: Any) -> None:
        """Valida los argumentos contra `parameters`; los errores guían al modelo."""
        if not isinstance(args, dict):
            raise ToolError("los argumentos deben ser un objeto JSON")
        props = self.parameters.get("properties", {})
        unknown = sorted(set(args) - set(props))
        if unknown:
            raise ToolError(f"argumentos desconocidos {unknown}; los válidos son {sorted(props)}")
        for key in self.parameters.get("required", []):
            if key not in args:
                raise ToolError(f"falta el argumento '{key}'")
        for key, value in args.items():
            spec = props[key]
            kind = spec.get("type")
            if kind == "string" and not isinstance(value, str):
                raise ToolError(f"'{key}' debe ser texto")
            if kind == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
                raise ToolError(f"'{key}' debe ser un entero")
            if "enum" in spec and value not in spec["enum"]:
                raise ToolError(f"'{key}' debe ser uno de {spec['enum']}")
            if kind == "integer":
                if "minimum" in spec and value < spec["minimum"] or "maximum" in spec and value > spec["maximum"]:
                    raise ToolError(f"'{key}' fuera de rango ({spec.get('minimum')}-{spec.get('maximum')})")

    def target_of(self, args: dict[str, Any]) -> str:
        """Objetivo que debe validar la guardia de alcance."""
        raise NotImplementedError

    def build_command(self, args: dict[str, Any], pin: Pin | None = None) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str, args: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def schema(self) -> dict[str, Any]:
        """Definición lista para function-calling (formato OpenAI-compatible)."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description + (" [INTRUSIVA: requiere confirmación]" if self.intrusive else ""),
                "parameters": self.parameters,
            },
        }

    def execute(self, cmd: list[str]) -> RawResult:
        """Ejecuta sin shell, con stdin cerrado y tiempo límite."""
        try:
            p = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            return RawResult(-1, out[:MAX_OUTPUT], "tiempo agotado", timed_out=True)
        except FileNotFoundError:
            raise ToolError(f"{cmd[0]} no está instalado")
        return RawResult(p.returncode, p.stdout[:MAX_OUTPUT], p.stderr[-4000:])


def require_str(args: dict[str, Any], key: str) -> str:
    v = args.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ToolError(f"falta el argumento '{key}'")
    return v.strip()
