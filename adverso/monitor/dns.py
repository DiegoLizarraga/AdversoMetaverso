"""Lector de mensajes DNS (RFC 1035), lo justo para el monitor (portado de Dns.kt).

Interesa qué nombre se pregunta y qué direcciones responde el resolutor. Todo lo
que llega por la red es hostil: límites en cada lectura, punteros de compresión
acotados y nombres saneados (solo [a-z0-9-_.*]; el resto como \\xNN), para que un
dominio con secuencias de escape no pueda manipular la terminal ni la TUI.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
              33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
_SAFE = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_*")
MAX_QUESTIONS = 8
MAX_ANSWERS = 32
MAX_JUMPS = 16


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int

    @property
    def type_name(self) -> str:
        return type_name(self.qtype)


@dataclass(frozen=True)
class Answer:
    name: str
    rtype: int
    address: str | None  # A/AAAA
    target: str | None = None  # CNAME


@dataclass(frozen=True)
class Message:
    id: int
    flags: int
    questions: list[Question]
    answers: list[Answer] = field(default_factory=list)

    @property
    def is_query(self) -> bool:
        return not self.flags & 0x8000

    @property
    def rcode(self) -> int:
        return self.flags & 0x0F

    @property
    def addresses(self) -> list[str]:
        return [a.address for a in self.answers if a.address]


def type_name(t: int) -> str:
    return TYPE_NAMES.get(t, f"TYPE{t}")


def _label(raw: bytes) -> str:
    return "".join(chr(b) if chr(b) in _SAFE else f"\\x{b:02x}" for b in raw.lower())


def _u16(data: bytes, i: int) -> int:
    return (data[i] << 8) | data[i + 1]


def read_name(data: bytes, pos: int) -> tuple[str, int] | None:
    """Lee un nombre (con compresión) en `pos`. Devuelve (nombre, posición siguiente)."""
    labels: list[str] = []
    next_pos = -1
    jumps = total = 0
    while True:
        if pos >= len(data):
            return None
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:  # puntero
            if pos + 1 >= len(data):
                return None
            jumps += 1
            if jumps > MAX_JUMPS:
                return None
            if next_pos < 0:
                next_pos = pos + 2
            target = ((n & 0x3F) << 8) | data[pos + 1]
            if target >= pos:  # solo hacia atrás: corta bucles
                return None
            pos = target
            continue
        if n & 0xC0:  # tipos de etiqueta reservados
            return None
        if pos + 1 + n > len(data):
            return None
        total += n + 1
        if total > 255:
            return None
        labels.append(_label(data[pos + 1 : pos + 1 + n]))
        pos += 1 + n
    return ".".join(labels), (next_pos if next_pos >= 0 else pos)


def parse(data: bytes) -> Message | None:
    """Mensaje DNS o None si no lo parece. Nunca lanza con datos arbitrarios."""
    try:
        return _parse(data)
    except (IndexError, ValueError):
        return None


def _parse(data: bytes) -> Message | None:
    if len(data) < 12:
        return None
    mid, flags, qd, an = _u16(data, 0), _u16(data, 2), _u16(data, 4), _u16(data, 6)
    if not 1 <= qd <= MAX_QUESTIONS or (flags >> 11) & 0xF not in (0, 2):  # QUERY o STATUS
        return None
    pos = 12
    questions = []
    for _ in range(qd):
        r = read_name(data, pos)
        if r is None or r[1] + 4 > len(data):
            return None
        name, pos = r
        questions.append(Question(name, _u16(data, pos)))
        pos += 4
    answers: list[Answer] = []
    for _ in range(min(an, MAX_ANSWERS)):
        r = read_name(data, pos)
        if r is None or r[1] + 10 > len(data):
            break
        name, pos = r
        rtype, rdlen = _u16(data, pos), _u16(data, pos + 8)
        rdata = pos + 10
        if rdata + rdlen > len(data):
            break
        address = target = None
        if rtype == 1 and rdlen == 4:
            address = str(ipaddress.IPv4Address(data[rdata : rdata + 4]))
        elif rtype == 28 and rdlen == 16:
            address = str(ipaddress.IPv6Address(data[rdata : rdata + 16]))
        elif rtype == 5:
            t = read_name(data, rdata)
            target = t[0] if t else None
        answers.append(Answer(name, rtype, address, target))
        pos = rdata + rdlen
    return Message(mid, flags, questions, answers)
