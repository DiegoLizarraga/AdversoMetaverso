"""Captura en vivo con un socket AF_PACKET (Linux). Pasiva: no envía nada.

Necesita root o CAP_NET_RAW. Con SOCK_DGRAM el núcleo entrega el paquete desde
la cabecera de red, sin la de enlace, así que vale igual para Ethernet, Wi-Fi,
loopback o túneles; sin interfaz, escucha todas.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Iterator

from .packets import Datagram, from_network

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4


class CaptureError(RuntimeError):
    pass


def capture(iface: str | None = None, stop: threading.Event | None = None) -> Iterator[tuple[float, Datagram]]:
    """Datagramas DNS (UDP) hasta que `stop` se active.

    El socket se abre YA, no al empezar a iterar: si faltan permisos o la interfaz
    no existe falla aquí mismo, y quien llama puede decir "escuchando" sabiendo que
    es verdad.
    """
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    except PermissionError as e:
        raise CaptureError("la captura en vivo necesita root o CAP_NET_RAW (prueba con sudo)") from e
    except AttributeError as e:  # AF_PACKET no existe fuera de Linux
        raise CaptureError("la captura en vivo solo funciona en Linux") from e
    if iface:
        try:
            s.bind((iface, 0))
        except OSError as e:
            s.close()
            raise CaptureError(f"no se puede escuchar en {iface}: {e.strerror or e}") from e
    s.settimeout(0.5)
    return _frames(s, stop or threading.Event())


def _frames(s: socket.socket, stop: threading.Event) -> Iterator[tuple[float, Datagram]]:
    with s:
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                raise CaptureError(f"captura interrumpida: {e}") from e
            ifname, proto, pkttype = addr[0], addr[1], addr[2]
            # En loopback cada paquete se ve dos veces (sale y entra): una basta.
            if ifname == "lo" and pkttype == PACKET_OUTGOING:
                continue
            d = from_network(proto, data)
            if d is not None and d.is_dns:
                yield time.time(), d


def interfaces() -> list[str]:
    return [name for _, name in socket.if_nameindex()]

