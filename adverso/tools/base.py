"""Contrato de una herramienta: esquema para el agente, comando, parser."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any

MAX_OUTPUT = 2_000_000  # bytes que se conservan de stdout


class ToolError(Exception):
    """Argumentos inválidos o fallo al ejecutar."""


@dataclass
class RawResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class Tool:
    name: str = ""
    binary: str = ""
    description: str = ""
    #: Una herramienta intrusiva exige confirmación humana antes de ejecutarse.
    intrusive: bool = False
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

    def build_command(self, args: dict[str, Any]) -> list[str]:
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
