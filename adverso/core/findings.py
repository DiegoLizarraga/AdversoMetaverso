"""De la salida cruda de las herramientas a Palacios y Sombras.

Un **Palacio** es un host (clave: su IP). Una **Sombra** es un hallazgo en él:
un servicio expuesto, una ruta web sensible, un aviso de nikto. Cada Sombra tiene
tipo, puntuación y nombre en clave estable; el Palacio hereda un rango.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from .models import PalaceRank, ShadowKind as K, ThreatTier
from .store import Store
from .threat import codename_for

# servicio -> (tipo, puntuación, motivo). Lo que no figura cae en ANONYMOUS.
_SERVICES: dict[str, tuple[K, int, str]] = {
    "telnet": (K.GREEDY, 70, "Telnet: credenciales y sesión en claro"),
    "ftp": (K.GREEDY, 58, "FTP: credenciales en claro"),
    "tftp": (K.GREEDY, 60, "TFTP: sin autenticación"),
    "microsoft-ds": (K.WATCHER, 66, "SMB expuesto"),
    "netbios-ssn": (K.WATCHER, 60, "NetBIOS expuesto"),
    "msrpc": (K.WATCHER, 55, "RPC expuesto"),
    "ms-wbt-server": (K.WATCHER, 68, "RDP expuesto"),
    "vnc": (K.WATCHER, 68, "VNC expuesto"),
    "mysql": (K.DEVOURER, 80, "Base de datos MySQL accesible por red"),
    "postgresql": (K.DEVOURER, 78, "Base de datos PostgreSQL accesible por red"),
    "ms-sql-s": (K.DEVOURER, 80, "SQL Server accesible por red"),
    "mongodb": (K.DEVOURER, 88, "MongoDB accesible por red"),
    "redis": (K.DEVOURER, 88, "Redis accesible por red"),
    "memcached": (K.DEVOURER, 82, "Memcached accesible por red"),
    "snmp": (K.WATCHER, 60, "SNMP expuesto"),
    "ssh": (K.WANDERER, 12, "SSH: superficie esperada"),
    "http": (K.WANDERER, 15, "Servicio web"),
    "https": (K.WANDERER, 12, "Servicio web cifrado"),
    "domain": (K.WANDERER, 15, "DNS"),
}

_PATHS = [  # (fragmento, tipo, puntuación, motivo)
    (".git", K.DEVOURER, 90, "Repositorio .git expuesto"),
    (".env", K.DEVOURER, 90, "Archivo .env expuesto"),
    (".htpasswd", K.DEVOURER, 85, "Credenciales .htpasswd"),
    ("backup", K.DEVOURER, 75, "Posible copia de seguridad"),
    (".bak", K.DEVOURER, 70, "Archivo de respaldo"),
    ("phpmyadmin", K.CORRUPT, 78, "Panel phpMyAdmin"),
    ("admin", K.WATCHER, 64, "Panel de administración"),
    ("login", K.WATCHER, 50, "Formulario de acceso"),
    ("config", K.WATCHER, 62, "Archivo/ruta de configuración"),
    ("robots.txt", K.WANDERER, 10, "robots.txt"),
]

_NIKTO = [
    ("vulnerab", K.CORRUPT, 82), ("cve-", K.CORRUPT, 85), ("outdated", K.CORRUPT, 70),
    ("remote code", K.CORRUPT, 92), ("directory indexing", K.WATCHER, 66),
    ("admin", K.WATCHER, 64), ("password", K.WATCHER, 66), ("header", K.ANONYMOUS, 28),
]


def _fid(*parts: Any) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:12]


def _palace(store: Store, ip: str, name: str | None) -> dict[str, Any]:
    now = time.time()
    p = store.palaces.setdefault(ip, {"ip": ip, "names": [], "first_seen": now, "findings": {}})
    p["last_seen"] = now
    if name and name not in p["names"]:
        p["names"].append(name)
    return p


def _shadow(p: dict[str, Any], source: str, key: str, title: str, kind: K, score: int, evidence: Any = None) -> bool:
    fid = _fid(p["ip"], source, key)
    new = fid not in p["findings"]
    p["findings"][fid] = {
        "id": fid, "source": source, "title": title, "kind": kind.name, "score": score,
        "codename": codename_for(f"{p['ip']}/{key}"), "evidence": evidence,
        "first_seen": p["findings"].get(fid, {}).get("first_seen", time.time()), "last_seen": time.time(),
    }
    return new


def ingest(store: Store, tool: str, target: str, pinned_ip: str | None, result: dict[str, Any]) -> int:
    """Vuelca el resultado de una herramienta en el Store. Devuelve las Sombras nuevas."""
    added = 0
    if tool == "nmap_scan":
        for h in result.get("hosts", []):
            if not h.get("up") or not h.get("address"):
                continue
            p = _palace(store, h["address"], h.get("hostname") or (target if target != h["address"] else None))
            for port in h.get("open_ports", []):
                svc = port.get("service") or "desconocido"
                kind, score, why = _SERVICES.get(svc, (K.ANONYMOUS, 30, f"Servicio {svc} sin antecedentes"))
                product = " ".join(x for x in (port.get("product"), port.get("version")) if x)
                title = f"{port['port']}/{port['protocol']} {svc}" + (f" ({product})" if product else "")
                added += _shadow(p, "nmap", f"{port['protocol']}/{port['port']}", f"{title}: {why}", kind, score, port)
    elif tool in ("gobuster_dir", "nikto_scan"):
        ip = pinned_ip or target
        p = _palace(store, ip, target if target != ip else None)
        if tool == "gobuster_dir":
            for f in result.get("found", []):
                path = (f.get("path") or "").lower()
                kind, score, why = next(((k, s, w) for frag, k, s, w in _PATHS if frag in path), (K.ANONYMOUS, 25, "Ruta descubierta"))
                added += _shadow(p, "gobuster", path, f"/{path.lstrip('/')} [{f.get('status')}]: {why}", kind, score, f)
        else:
            for f in result.get("findings", []):
                text = f.get("text", "")
                low = text.lower()
                kind, score = next(((k, s) for frag, k, s in _NIKTO if frag in low), (K.ANONYMOUS, 30))
                added += _shadow(p, "nikto", f.get("id") or text[:60], text[:200], kind, score, None)
    elif tool == "dns_lookup":
        p = _osint_palace(store, target)
        for r in result.get("records", []):
            added += _shadow(p, "dns", f"{r['type']}/{r['data']}", f"{r['type']} {r['data']}", K.WANDERER, 8, r)
    elif tool == "harvest_domain":
        p = _osint_palace(store, target)
        for h in result.get("hosts", []):
            if h["name"] != target:
                label = f"{h['name']}" + (f" → {h['ip']}" if h.get("ip") else "")
                added += _shadow(p, "harvest", h["name"], f"Subdominio {label}", K.ANONYMOUS, 22, h)
        for e in result.get("emails", []):
            added += _shadow(p, "harvest", e, f"Correo expuesto {e}", K.SEDUCER, 42, None)
    elif tool == "whatweb_fingerprint":
        p = _palace(store, pinned_ip or target, target if target != (pinned_ip or target) else None)
        for tech, vals in result.get("technologies", {}).items():
            if tech in ("HTTPServer", "X-Powered-By", "PHP", "WordPress", "Apache", "nginx", "Joomla", "Drupal") or vals:
                v = " ".join(map(str, vals))
                added += _shadow(p, "whatweb", tech, f"Tecnología {tech} {v}".strip(), K.ANONYMOUS, 28 if v else 18, vals)
    store.save()
    return added


def _osint_palace(store: Store, domain: str) -> dict[str, Any]:
    """Un dominio investigado de forma pasiva es un Palacio más (clave: el dominio)."""
    return _palace(store, domain, None)


def palace_score(p: dict[str, Any]) -> int:
    scores = sorted((f["score"] for f in p["findings"].values()), reverse=True)
    if not scores:
        return 0
    return min(100, scores[0] + 2 * min(len(scores) - 1, 8))  # la peor Sombra manda; el resto suma poco


def palace_rank(p: dict[str, Any]) -> PalaceRank:
    return PalaceRank.of(palace_score(p))


def palace_tier(p: dict[str, Any]) -> ThreatTier:
    return ThreatTier.of(palace_score(p))
