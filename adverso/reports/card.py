"""Tarjeta de presentación: informe en Markdown de los Palacios conocidos."""

from __future__ import annotations

import time

from ..core.findings import palace_rank, palace_score, palace_tier
from ..core.models import ShadowKind
from ..core.store import Store


def render_markdown(store: Store) -> str:
    palaces = sorted(store.palaces.values(), key=palace_score, reverse=True)
    out = [f"# Informe del Metaverso — {time.strftime('%Y-%m-%d %H:%M')}", ""]
    if not palaces:
        return "\n".join(out + ["Sin Palacios registrados todavía."])
    out += ["| Palacio | Rango | Alerta | Sombras |", "| --- | --- | --- | --- |"]
    for p in palaces:
        name = p["ip"] + (f" ({', '.join(p['names'])})" if p["names"] else "")
        out.append(f"| {name} | {palace_rank(p).label} ({palace_rank(p).letter}) | {palace_tier(p).label} {palace_score(p)} | {len(p['findings'])} |")
    for p in palaces:
        out += ["", f"## {p['ip']} — {palace_rank(p).label}", ""]
        for f in sorted(p["findings"].values(), key=lambda f: -f["score"]):
            k = ShadowKind[f["kind"]]
            out.append(f"- **{f['codename']}** · {k.display} · {f['score']} — {f['title']} _({f['source']})_")
    return "\n".join(out) + "\n"
