"""¿Qué proceso local hizo esta consulta? Atribución best-effort por /proc.

La consulta sale de un socket UDP local (IP, puerto). /proc/net/udp{,6} da el
inode de ese socket, y /proc/<pid>/fd lleva del inode al proceso. Los sockets de
DNS viven poco: si al mirar ya se cerró, no hay atribución (se usa la IP). Ver
los fd de procesos de otros usuarios requiere root, igual que capturar.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
from collections import OrderedDict
from pathlib import Path

_SAFE = re.compile(r"[^A-Za-z0-9._+-]")


def _hex_ip(h: str) -> str:
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    # IPv6: cuatro palabras de 32 bits, cada una en orden de la máquina (little-endian)
    return str(ipaddress.IPv6Address(b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))))


def udp_sockets(proc: Path = Path("/proc")) -> dict[tuple[str, int], int]:
    """(IP local, puerto) → inode, para los sockets UDP de este espacio de red."""
    out: dict[tuple[str, int], int] = {}
    for name in ("udp", "udp6"):
        try:
            lines = (proc / "net" / name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                ip_hex, port_hex = parts[1].split(":")
                out[(_hex_ip(ip_hex), int(port_hex, 16))] = int(parts[9])
            except ValueError:
                continue
    return out


def local_addresses(proc: Path = Path("/proc")) -> set[str]:
    """IPs de esta máquina: las LOCAL de la tabla fib (IPv4) y las de if_inet6."""
    addrs = {"127.0.0.1", "::1"}
    try:
        last = None
        for line in (proc / "net" / "fib_trie").read_text().splitlines():
            m = re.search(r"\|--\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                last = m.group(1)
            elif "/32 host LOCAL" in line and last:
                addrs.add(last)
    except OSError:
        pass
    try:
        for line in (proc / "net" / "if_inet6").read_text().splitlines():
            if line.split():
                addrs.add(_hex_ip_plain(line.split()[0]))
    except (OSError, ValueError):
        pass
    return addrs


def _hex_ip_plain(h: str) -> str:
    return str(ipaddress.IPv6Address(bytes.fromhex(h)))


def _clean(name: str) -> str:
    return _SAFE.sub("?", name.strip())[:32] or "?"


class ProcessResolver:
    """Cachea inode → proceso; vuelve a recorrer /proc como mucho cada `min_scan` s."""

    def __init__(self, proc: Path = Path("/proc"), min_scan: float = 0.2) -> None:
        self.proc = proc
        self.min_scan = min_scan
        self._owners: dict[int, tuple[str, str]] = {}  # inode → (pid, nombre)
        self._recent: OrderedDict[str, None] = OrderedDict()  # pids que consultaron hace poco
        self._scanned = 0.0
        self._local: set[str] = set()
        self._local_at = 0.0

    def is_local(self, ip: str) -> bool:
        if time.monotonic() - self._local_at > 30:
            self._local = local_addresses(self.proc)
            self._local_at = time.monotonic()
        return ip in self._local or ip.startswith("127.")

    def _sockets_of(self, pid: str) -> tuple[str, set[int]] | None:
        fd_dir = self.proc / pid / "fd"
        try:
            fds = os.listdir(fd_dir)
            comm = _clean((self.proc / pid / "comm").read_text())
        except OSError:
            return None
        inodes = set()
        for fd in fds:
            try:
                link = os.readlink(fd_dir / fd)
            except OSError:
                continue
            if link.startswith("socket:["):
                inodes.add(int(link[8:-1]))
        return comm, inodes

    def _scan(self) -> None:
        owners: dict[int, tuple[str, str]] = {}
        for pid in os.listdir(self.proc):
            if pid.isdigit() and (found := self._sockets_of(pid)):
                owners.update(dict.fromkeys(found[1], (pid, found[0])))
        self._owners = owners
        self._scanned = time.monotonic()

    def _remember(self, pid: str) -> None:
        self._recent[pid] = None
        self._recent.move_to_end(pid)
        while len(self._recent) > 32:
            self._recent.popitem(last=False)

    def owner(self, ip: str, port: int) -> str | None:
        """Nombre del proceso dueño del socket UDP local (ip, port), si sigue abierto.

        Carrera inevitable: el cliente cierra el socket en cuanto llega la respuesta.
        Para ganarla más veces se miran primero los procesos que ya consultaron hace
        poco (navegadores, demonios: abren un socket nuevo por consulta, pero son los
        mismos), y solo después se recorre todo /proc.
        """
        if not self.is_local(ip):
            return None
        socks = udp_sockets(self.proc)
        # socket propio, comodín, o IPv6 de doble pila (::ffff:a.b.c.d) para consultas IPv4
        inode = next((socks[k] for k in ((ip, port), (f"::ffff:{ip}", port), ("0.0.0.0", port), ("::", port))
                      if k in socks), None)
        if not inode:
            return None
        if inode not in self._owners:
            for pid in reversed(self._recent):
                found = self._sockets_of(pid)
                if found and inode in found[1]:
                    self._owners[inode] = (pid, found[0])
                    break
            else:
                if time.monotonic() - self._scanned >= self.min_scan:
                    self._scan()
        hit = self._owners.get(inode)
        if hit is None:
            return None
        self._remember(hit[0])
        return hit[1]
