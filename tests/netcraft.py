"""Fabrica paquetes de prueba: DNS, UDP, IPv4/IPv6, enlaces y capturas pcap/pcapng."""

from __future__ import annotations

import ipaddress
import struct


def qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        raw = label.encode("latin-1")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(name: str, qtype: int = 1, qid: int = 0x1234) -> bytes:
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)


def dns_response(name: str, ips: list[str], qid: int = 0x1234, cname: str | None = None) -> bytes:
    """Respuesta con compresión: las respuestas apuntan al nombre de la pregunta (0xC00C)."""
    answers = b""
    count = 0
    if cname:
        target = qname(cname)
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
        count += 1
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        rtype = 1 if addr.version == 4 else 28
        answers += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(addr.packed)) + addr.packed
        count += 1
    head = struct.pack("!HHHHHH", qid, 0x8180, 1, count, 0, 0)
    return head + qname(name) + struct.pack("!HH", 1, 1) + answers


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(src: str, dst: str, seg: bytes, proto: int = 17, frag: int = 0) -> bytes:
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), 0, frag, 64, proto, 0,
                       ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed) + seg


def ipv6(src: str, dst: str, seg: bytes, hop_by_hop: bool = False) -> bytes:
    nxt, ext = 17, b""
    if hop_by_hop:
        nxt, ext = 0, bytes([17, 0]) + b"\x00" * 6
    return struct.pack("!IHBB16s16s", 6 << 28, len(ext) + len(seg), nxt, 64,
                       ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed) + ext + seg


def ether(ip: bytes, vlan: bool = False) -> bytes:
    etype = 0x86DD if ip[0] >> 4 == 6 else 0x0800
    head = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
    if vlan:
        head += struct.pack("!HH", 0x8100, 42)
    return head + struct.pack("!H", etype) + ip


def sll(ip: bytes) -> bytes:
    return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800) + ip


def sll2(ip: bytes) -> bytes:
    return struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, b"\x00" * 8) + ip


def query_frame(src: str, name: str, qid: int = 0x1234, sport: int = 40000, dst: str = "10.0.0.1") -> bytes:
    return ether(ipv4(src, dst, udp(sport, 53, dns_query(name, qid=qid))))


def pcap(frames: list[tuple[float, bytes]], linktype: int = 1) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, f in frames:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(f), len(f)) + f
    return out


def pcapng(frames: list[tuple[int, float, bytes]], linktypes: list[int], nano_iface: int | None = None) -> bytes:
    """frames: (interfaz, tiempo, trama). `nano_iface` usa if_tsresol=9 (nanosegundos)."""
    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    for i, lt in enumerate(linktypes):
        opts = b""
        if i == nano_iface:
            opts = struct.pack("<HH", 9, 1) + b"\x09\x00\x00\x00" + struct.pack("<HH", 0, 0)
        out += block(1, struct.pack("<HHI", lt, 0, 65535) + opts)
    for iface, ts, f in frames:
        units = int(ts * (1e9 if iface == nano_iface else 1e6))
        out += block(6, struct.pack("<IIIII", iface, units >> 32, units & 0xFFFFFFFF, len(f), len(f)) + f)
    return out
