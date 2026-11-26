"""Lectura de capturas: pcap clásico (tcpdump) y pcapng (Wireshark/tshark).

Produce (marca de tiempo, tipo de enlace, trama). Las capturas también son datos
no confiables: longitudes acotadas y bloques malformados terminan la lectura sin
lanzar.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO, Iterator

MAX_RECORD = 262_144
Frame = tuple[float, int, bytes]


class PcapError(ValueError):
    pass


def read(path: str | Path) -> Iterator[Frame]:
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _pcapng(f)
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _pcap(f)
        else:
            raise PcapError(f"{path}: no es una captura pcap ni pcapng")


def _pcap(f: BinaryIO) -> Iterator[Frame]:
    head = f.read(24)
    if len(head) < 24:
        return
    magic = head[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", head[20:24])[0] & 0x0FFFFFFF
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, _ = struct.unpack(endian + "IIII", rec)
        if incl > MAX_RECORD:
            return
        data = f.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / (1e9 if nano else 1e6), linktype, data


def _pcapng(f: BinaryIO) -> Iterator[Frame]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (tipo de enlace, unidad de tiempo en s)
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        if head[:4] == b"\x0a\x0d\x0d\x0a":  # Section Header Block: fija el orden de bytes
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            length = struct.unpack(endian + "I", head[4:8])[0]
            body = bom + f.read(length - 12) if length >= 12 else b""
            interfaces = []
        else:
            btype, length = struct.unpack(endian + "II", head)
            if length < 12 or length > MAX_RECORD + 64:
                return
            body = f.read(length - 8)
            if len(body) < length - 8:
                return
            body = body[:-4]  # longitud repetida al final
            if btype == 1:  # Interface Description Block
                linktype = struct.unpack_from(endian + "H", body, 0)[0]
                interfaces.append((linktype, _tsresol(body[8:], endian)))
            elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
                iface, hi, lo, caplen = struct.unpack_from(endian + "IIII", body, 0)
                if iface < len(interfaces) and caplen <= len(body) - 20:
                    lt, unit = interfaces[iface]
                    yield ((hi << 32) | lo) * unit, lt, body[20 : 20 + caplen]
            elif btype == 3 and interfaces and len(body) >= 4:  # Simple Packet Block
                orig = struct.unpack_from(endian + "I", body, 0)[0]
                yield 0.0, interfaces[0][0], body[4 : 4 + min(orig, len(body) - 4)]
            continue
        if length < 12:
            return


def _tsresol(options: bytes, endian: str) -> float:
    """Unidad de las marcas de tiempo (opción if_tsresol); por defecto, microsegundos."""
    pos = 0
    while pos + 4 <= len(options):
        code, olen = struct.unpack_from(endian + "HH", options, pos)
        if code == 0:
            break
        if code == 9 and olen >= 1:
            v = options[pos + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        pos += 4 + ((olen + 3) & ~3)
    return 1e-6
