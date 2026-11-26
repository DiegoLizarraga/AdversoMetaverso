"""Del paquete crudo al datagrama UDP: enlace → IPv4/IPv6 → UDP.

Solo lo que el monitor necesita (DNS sobre UDP). Fragmentos IPv4 que no son el
primero y DNS sobre TCP se ignoran. Nunca lanza con datos arbitrarios.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

# Tipos de enlace (LINKTYPE_* de libpcap)
LINK_NULL = 0  # loopback BSD
LINK_ETHERNET = 1
LINK_RAW = 101
LINK_SLL = 113  # Linux "cooked" (tcpdump -i any)
LINK_IPV4 = 228
LINK_IPV6 = 229
LINK_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
_VLAN = (0x8100, 0x88A8, 0x9100)
_IPV6_EXT = (0, 43, 60)  # hop-by-hop, routing, destination options
UDP = 17


#: DNS interno de Docker en redes propias. Una regla DNAT de salida cambia el puerto
#: 53 por uno aleatorio antes de que el paquete pase por `lo`: se reconoce por la IP.
DOCKER_DNS = "127.0.0.11"


@dataclass(frozen=True)
class Datagram:
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes

    @property
    def is_dns(self) -> bool:
        return 53 in (self.sport, self.dport) or DOCKER_DNS in (self.src, self.dst)

    @property
    def to_resolver(self) -> bool:
        """Va hacia un resolutor (consulta), no desde él (respuesta)."""
        return self.dport == 53 or self.dst == DOCKER_DNS


def from_link(linktype: int, frame: bytes) -> Datagram | None:
    try:
        return _from_link(linktype, frame)
    except (IndexError, ValueError, struct.error):
        return None


def _from_link(linktype: int, f: bytes) -> Datagram | None:
    if linktype == LINK_ETHERNET:
        if len(f) < 14:
            return None
        etype, off = struct.unpack_from("!H", f, 12)[0], 14
        while etype in _VLAN and len(f) >= off + 4:
            etype, off = struct.unpack_from("!H", f, off + 2)[0], off + 4
        return from_network(etype, f[off:])
    if linktype == LINK_SLL:
        return from_network(struct.unpack_from("!H", f, 14)[0], f[16:]) if len(f) >= 16 else None
    if linktype == LINK_SLL2:
        return from_network(struct.unpack_from("!H", f, 0)[0], f[20:]) if len(f) >= 20 else None
    if linktype == LINK_NULL:
        if len(f) < 4:
            return None
        family = struct.unpack_from("<I", f, 0)[0]
        if family > 0xFFFF:  # escrito en big-endian
            family = struct.unpack_from(">I", f, 0)[0]
        return from_network(ETH_IPV4 if family == 2 else ETH_IPV6, f[4:]) if family in (2, 10, 24, 28, 30) else None
    if linktype in (LINK_RAW, LINK_IPV4, LINK_IPV6):
        return from_ip(f)
    return None


def from_ip(packet: bytes) -> Datagram | None:
    """IP sin cabecera de enlace (la versión se lee del primer nibble)."""
    if not packet:
        return None
    return from_network(ETH_IPV4 if packet[0] >> 4 == 4 else ETH_IPV6, packet)


def from_network(ethertype: int, p: bytes) -> Datagram | None:
    try:
        if ethertype == ETH_IPV4:
            return _ipv4(p)
        if ethertype == ETH_IPV6:
            return _ipv6(p)
    except (IndexError, ValueError, struct.error):
        pass
    return None


def _ipv4(p: bytes) -> Datagram | None:
    if len(p) < 20 or p[0] >> 4 != 4:
        return None
    ihl = (p[0] & 0x0F) * 4
    total = struct.unpack_from("!H", p, 2)[0]
    frag = struct.unpack_from("!H", p, 6)[0]
    if ihl < 20 or p[9] != UDP or frag & 0x1FFF:  # no UDP, o fragmento que no es el primero
        return None
    end = min(len(p), total) if total >= ihl else len(p)
    return _udp(str(ipaddress.IPv4Address(p[12:16])), str(ipaddress.IPv4Address(p[16:20])), p[ihl:end])


def _ipv6(p: bytes) -> Datagram | None:
    if len(p) < 40 or p[0] >> 4 != 6:
        return None
    nxt, off = p[6], 40
    end = min(len(p), 40 + struct.unpack_from("!H", p, 4)[0])
    for _ in range(4):
        if nxt not in _IPV6_EXT:
            break
        if off + 2 > len(p):
            return None
        nxt, off = p[off], off + (p[off + 1] + 1) * 8
    if nxt != UDP:
        return None
    return _udp(str(ipaddress.IPv6Address(p[8:24])), str(ipaddress.IPv6Address(p[24:40])), p[off:end])


def _udp(src: str, dst: str, seg: bytes) -> Datagram | None:
    if len(seg) < 8:
        return None
    sport, dport, length = struct.unpack_from("!HHH", seg, 0)
    end = min(len(seg), length) if length >= 8 else len(seg)
    return Datagram(src, dst, sport, dport, seg[8:end])
