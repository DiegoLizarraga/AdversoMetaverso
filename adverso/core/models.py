"""El vocabulario del Metaverso.

En la versión Linux: un **Palacio** es un host/servicio observado o atacado, y una
**Sombra** es un dominio o hallazgo concreto gobernado por un deseo distorsionado.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ShadowKind(Enum):
    WANDERER = ("SOMBRA ERRANTE", "PEREZA", "Deambula sin intención. Infraestructura.", 8)
    ANONYMOUS = ("SOMBRA ANÓNIMA", "DUDA", "Sin antecedentes en el registro.", 26)
    SEDUCER = ("SOMBRA SEDUCTORA", "VANIDAD", "Se alimenta de tu imagen pública.", 42)
    GREEDY = ("SOMBRA CODICIOSA", "AVARICIA", "Subasta tu atención al mejor postor.", 58)
    WATCHER = ("SOMBRA VIGILANTE", "VIGILANCIA", "Registra cada cosa que haces.", 64)
    CORRUPT = ("SOMBRA CORRUPTA", "IRA", "Su nombre no fue hecho por humanos.", 86)
    DEVOURER = ("SOMBRA DEVORADORA", "GULA", "Usa el DNS como tubería para sacar datos.", 92)

    def __init__(self, display: str, distortion: str, blurb: str, severity: int) -> None:
        self.display = display
        self.distortion = distortion
        self.blurb = blurb
        self.severity = severity


class ThreatTier(Enum):
    CALMA = ("CALMA", 0)
    SOSPECHA = ("SOSPECHA", 25)
    ALERTA = ("ALERTA", 45)
    CAUTELA = ("CAUTELA", 65)
    EMERGENCIA = ("EMERGENCIA", 85)

    def __init__(self, label: str, threshold: int) -> None:
        self.label = label
        self.threshold = threshold

    @classmethod
    def of(cls, score: int) -> "ThreatTier":
        return [t for t in cls if score >= t.threshold][-1]


class PalaceRank(Enum):
    GUARIDA = ("GUARIDA", 0, "E")
    CASTILLO = ("CASTILLO", 20, "D")
    MUSEO = ("MUSEO", 38, "C")
    BANCO = ("BANCO", 52, "B")
    PIRAMIDE = ("PIRÁMIDE", 66, "A")
    CASINO = ("CASINO", 78, "A")
    CRUCERO = ("CRUCERO", 88, "S")

    def __init__(self, label: str, threshold: int, letter: str) -> None:
        self.label = label
        self.threshold = threshold
        self.letter = letter

    @classmethod
    def of(cls, score: int) -> "PalaceRank":
        return [r for r in cls if score >= r.threshold][-1]


@dataclass(frozen=True)
class Verdict:
    domain: str
    kind: ShadowKind
    score: int
    category: str
    reasons: list[str]
    codename: str

    @property
    def tier(self) -> ThreatTier:
        return ThreatTier.of(self.score)


@dataclass
class ShadowEvent:
    """Una observación: la unidad atómica (consulta DNS, conexión, hallazgo)."""

    timestamp: float
    domain: str
    source: str  # proceso/app/herramienta que originó la observación
    verdict: Verdict
    blocked: bool = False
    resolved_ips: list[str] = field(default_factory=list)
    latency_ms: int = -1


@dataclass
class PalaceAggregate:
    name: str
    queries: int = 0
    blocked: int = 0
    domains: set[str] = field(default_factory=set)
    worst_score: int = 0
    threat_score: int = 0
    last_seen: float = 0.0

    @property
    def rank(self) -> PalaceRank:
        return PalaceRank.of(self.threat_score)

    @property
    def tier(self) -> ThreatTier:
        return ThreatTier.of(self.threat_score)
