"""Monitor pasivo de DNS: cada consulta es una Sombra en el Palacio de quien pregunta.

El Palacio es el proceso local que hizo la consulta (`local/firefox`), `local` si
la consulta salió de esta máquina pero el socket ya se cerró, o la IP del host
de la red que preguntó. El dominio pasa por el Códice de Sombras (core.threat).

Todo se muestra en vivo; al Store solo va lo que llega a `min_score`, por lotes
y en transacción (otros procesos escriben el mismo archivo).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..core.findings import ingest_dns
from ..core.models import Verdict
from ..core.store import Store
from ..core.threat import evaluate
from . import dns
from .packets import Datagram
from .procs import ProcessResolver

DEFAULT_MIN_SCORE = 40
LOCAL = "local"


@dataclass(frozen=True)
class DnsEvent:
    ts: float
    palace: str
    client: str
    server: str
    process: str | None
    domain: str
    qtype: str
    verdict: Verdict


@dataclass
class _Pending:
    palace: str
    domain: str
    verdict: Verdict
    process: str | None
    count: int = 0
    qtypes: set[str] = field(default_factory=set)
    last: float = 0.0


@dataclass
class Stats:
    packets: int = 0
    queries: int = 0
    responses: int = 0
    duplicates: int = 0
    saved: int = 0
    new_shadows: int = 0


class Monitor:
    def __init__(self, store: Store | None = None, min_score: int = DEFAULT_MIN_SCORE,
                 on_event: Callable[[DnsEvent], None] | None = None, resolver: ProcessResolver | None = None,
                 flush_every: float = 2.0, dedup_window: float = 2.0) -> None:
        self.store = store
        self.min_score = min_score
        self.on_event = on_event or (lambda e: None)
        self.resolver = resolver
        self.flush_every = flush_every
        self.dedup_window = dedup_window
        self.stats = Stats()
        self._pending: dict[tuple[str, str], _Pending] = {}
        self._answers: dict[str, set[str]] = {}
        self._recent: OrderedDict[tuple[int, str, int], float] = OrderedDict()
        self._verdicts: OrderedDict[str, Verdict] = OrderedDict()
        self._flushed = time.monotonic()
        self._lock = threading.Lock()  # pendientes y respuestas: los toca el hilo de volcado
        self._flush_lock = threading.Lock()
        self.last_error: str | None = None

    def verdict(self, domain: str) -> Verdict:
        v = self._verdicts.get(domain)
        if v is None:
            v = self._verdicts[domain] = evaluate(domain)
            if len(self._verdicts) > 4096:
                self._verdicts.popitem(last=False)
        return v

    def palace_for(self, ip: str, port: int) -> tuple[str, str | None]:
        if self.resolver is None or not self.resolver.is_local(ip):
            return ip, None
        proc = self.resolver.owner(ip, port)
        return (f"{LOCAL}/{proc}", proc) if proc else (LOCAL, None)

    def feed(self, ts: float, d: Datagram) -> DnsEvent | None:
        """Procesa un datagrama. Devuelve el evento si era una consulta nueva."""
        self.stats.packets += 1
        msg = dns.parse(d.payload)
        if msg is None:
            return None
        if not msg.is_query:
            self.stats.responses += 1
            if msg.questions and msg.addresses:
                with self._lock:  # flush() lo lee desde el hilo de volcado
                    if len(self._answers) > 8192:  # memoria acotada en capturas largas
                        self._answers.clear()
                    ips = self._answers.setdefault(msg.questions[0].name, set())
                    ips.update(msg.addresses[: 8 - len(ips)] if len(ips) < 8 else [])
            return None
        if not d.to_resolver or not msg.questions:
            return None
        q = msg.questions[0]
        if not q.name:
            return None
        # El mismo paquete visto en varias interfaces (puente, NAT) o retransmitido.
        key = (msg.id, q.name, q.qtype)
        seen = self._recent.get(key)
        self._recent[key] = ts
        self._recent.move_to_end(key)
        while self._recent and next(iter(self._recent.values())) < ts - self.dedup_window:
            self._recent.popitem(last=False)
        if seen is not None and ts - seen <= self.dedup_window:
            self.stats.duplicates += 1
            return None
        self.stats.queries += 1
        palace, proc = self.palace_for(d.src, d.sport)
        v = self.verdict(q.name)
        ev = DnsEvent(ts, palace, d.src, d.dst, proc, q.name, q.type_name, v)
        if v.score >= self.min_score:
            with self._lock:
                p = self._pending.setdefault((palace, q.name), _Pending(palace, q.name, v, proc))
                p.count += 1
                p.qtypes.add(q.type_name)
                p.last = ts
        self.on_event(ev)
        if time.monotonic() - self._flushed >= self.flush_every:
            self.flush()
        return ev

    def flush(self) -> int:
        """Vuelca lo pendiente al Store en una transacción. Devuelve las Sombras nuevas."""
        with self._flush_lock:
            self._flushed = time.monotonic()
            with self._lock:
                pending, self._pending = self._pending, {}
                answers = {p.domain: sorted(self._answers.get(p.domain, ())) for p in pending.values()}
            if not pending or self.store is None:
                return 0
            added = 0
            with self.store.transaction():
                for p in pending.values():
                    added += ingest_dns(self.store, p.palace, p.domain, p.verdict, p.count, sorted(p.qtypes),
                                        answers[p.domain], p.process, p.last)
            self.stats.saved += len(pending)
            self.stats.new_shadows += added
            return added

    def _flusher(self, stop: threading.Event) -> None:
        """Vuelca cada `flush_every` s aunque no lleguen paquetes: si no, en una red
        tranquila lo pendiente no aparecería hasta el siguiente paquete."""
        while not stop.wait(max(self.flush_every, 0.05)):
            try:
                self.flush()
            except OSError as e:  # disco lleno, permisos…: se reintenta en la próxima vuelta
                self.last_error = str(e)

    def run(self, frames: Iterable[tuple[float, Datagram]]) -> Stats:
        stop = threading.Event()
        flusher = threading.Thread(target=self._flusher, args=(stop,), name="monitor-flush", daemon=True)
        flusher.start()
        try:
            for ts, d in frames:
                self.feed(ts, d)
        finally:
            stop.set()
            flusher.join(5)
            self.flush()
        return self.stats


def pcap_frames(path: str) -> Iterable[tuple[float, Datagram]]:
    """Datagramas DNS de una captura (pcap o pcapng)."""
    from .packets import from_link
    from .pcap import read

    for ts, linktype, frame in read(path):
        d = from_link(linktype, frame)
        if d is not None and d.is_dns:
            yield ts, d

