"""El Códice de Sombras: decide *qué* es un dominio y *cuánto* debe preocupar.

Dos capas: registro conocido (coincidencia por sufijo) y heurística (entropía,
etiquetas gigantes, TLDs quemados, punycode).
"""

from __future__ import annotations

import math
from collections import Counter

from .models import ShadowKind, Verdict
from .registry import CODENAMES, HINTS, REGISTRY, RISKY_TLDS


def evaluate(raw_domain: str) -> Verdict:
    domain = raw_domain.strip().rstrip(".").lower()
    if not domain:
        return Verdict("(vacío)", ShadowKind.ANONYMOUS, 20, "Consulta vacía", ["Consulta sin nombre"], "NIEBLA")

    reasons: list[str] = []
    kind = ShadowKind.ANONYMOUS
    category = "Sin clasificar"
    escalated = False

    def escalate(candidate: ShadowKind) -> None:
        nonlocal kind, escalated
        if candidate.severity > kind.severity:
            kind = candidate
            escalated = True

    rule = next(((s, k, c) for s, k, c in REGISTRY if domain == s or domain.endswith("." + s)), None)
    if rule:
        suffix, kind, category = rule
        score = kind.severity
        reasons.append(f"Registrada en el códice: {suffix} · {category}")
    else:
        hint = next((h for h in HINTS if h[0] in domain), None)
        if hint:
            _, kind, category = hint
            # Sospecha por nombre, no certeza: pesa menos que el registro.
            score = kind.severity - 8
            reasons.append(f"Nombre delator: “{hint[0]}”")
        else:
            score = kind.severity

    labels = domain.split(".")
    longest = max(labels, key=len)

    # Los CDN generan hosts aleatorios por diseño: se anotan pero no castigan.
    known_infra = rule is not None and rule[1] is ShadowKind.WANDERER

    if len(labels) >= 6:
        score += 6
        reasons.append(f"Cadena de {len(labels)} subdominios")

    entropy = _entropy(longest)
    if len(longest) >= 12 and entropy > 3.55:
        if known_infra:
            reasons.append("Etiqueta aleatoria, esperable en un CDN")
        else:
            score += 18
            escalate(ShadowKind.CORRUPT)
            reasons.append(f"Entropía {_fmt(entropy)} en “{longest}”: nombre generado por máquina")
            if category == "Sin clasificar":
                category = "Dominio generado (DGA)"

    if len(longest) >= 34:
        if known_infra:
            score += 4
            reasons.append(f"Etiqueta de {len(longest)} caracteres en infraestructura conocida")
        else:
            score += 24
            escalate(ShadowKind.DEVOURER)
            reasons.append(f"Etiqueta de {len(longest)} caracteres: patrón de fuga de datos por DNS")
            category = "Túnel DNS"

    tld = labels[-1]
    if tld in RISKY_TLDS:
        score += 16
        reasons.append(f"TLD de alto riesgo: .{tld}")

    if "xn--" in domain:
        score += 12
        reasons.append("Punycode: posible dominio homógrafo")

    # La puntuación decide el bloqueo: tiene que seguir a la reclasificación.
    if escalated:
        score = max(score, kind.severity - 14)

    if not reasons:
        reasons.append("Sin antecedentes. Sombra anónima.")

    return Verdict(domain, kind, max(0, min(100, score)), category, reasons, codename_for(domain))


def codename_for(domain: str) -> str:
    """Nombre estable por dominio (hash de 32 bits con signo, como en el original)."""
    h = 0
    for c in domain:
        h = (h * 31 + ord(c)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return CODENAMES[h % len(CODENAMES)]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in Counter(value).values())


def _fmt(value: float) -> str:
    rounded = int(value * 100)
    return f"{rounded // 100}.{rounded % 100:02d}"
