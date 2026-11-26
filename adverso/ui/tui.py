"""TUI del Metaverso (Textual): Palacios y Sombras en vivo.

Lee el Store y el registro de auditoría, que escriben otros procesos (el agente,
el servidor MCP de opencode, `adverso monitor`), y se refresca cuando cambian.
Con `--monitor` o `--pcap` además captura DNS en un hilo y lo muestra al vuelo.

Todo texto que viene de fuera (dominios, títulos de hallazgos, banners) se pinta
como `Text`, nunca como markup: un título con "[...]" no puede inyectar estilos.
"""

from __future__ import annotations

import json
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import DataTable, Footer, RichLog, Static

from ..core.findings import palace_rank, palace_score, palace_tier
from ..core.models import ShadowKind, ThreatTier
from ..core.store import Store
from ..reports.card import render_markdown

RED = "#e60012"
TIER_STYLE = {
    "CALMA": "grey70", "SOSPECHA": "cyan", "ALERTA": "yellow", "CAUTELA": f"bold {RED}", "EMERGENCIA": f"bold white on {RED}",
}
AUDIT_SHOWN = {
    "run": "▶", "done": "✓", "denied_scope": "⊘", "confirmation": "?", "timeout": "…", "failed": "✗",
    "invalid_args": "✗", "monitor_start": "◉", "monitor_stop": "◎", "monitor_error": "✗",
}


def tier_text(score: int) -> Text:
    t = ThreatTier.of(score)
    return Text(f"{t.label} {score}", style=TIER_STYLE[t.label])


def shadow_label(kind: str) -> str:
    try:
        return ShadowKind[kind].display
    except KeyError:
        return kind


class MetaversoApp(App[None]):
    TITLE = "METAVERSO"
    ENABLE_COMMAND_PALETTE = False
    CSS = f"""
    Screen {{ background: #0b0b0b; color: #f2f2f2; }}
    #cabecera {{ height: 1; background: {RED}; color: white; text-style: bold; padding: 0 1; }}
    #cuerpo {{ height: 1fr; }}
    #izquierda {{ width: 46%; }}
    #derecha {{ width: 1fr; }}
    DataTable {{ height: 1fr; background: #0b0b0b; scrollbar-color: {RED}; overflow-x: hidden; }}
    DataTable > .datatable--header {{ background: #1a1a1a; color: {RED}; text-style: bold; }}
    DataTable > .datatable--cursor {{ background: {RED}; color: white; text-style: bold; }}
    .titulo {{ height: 1; color: {RED}; text-style: bold italic; padding: 0 1; }}
    #detalle {{ height: 9; border: tall {RED}; padding: 0 1; background: #111111; }}
    #vivo {{ height: 11; border: tall #333333; background: #050505; scrollbar-color: #444444; }}
    """
    BINDINGS = [
        Binding("q", "quit", "Salir"),
        Binding("r", "report", "Informe"),
        Binding("c", "clear_log", "Limpiar registro"),
        Binding("tab", "focus_next", "Cambiar panel", show=False),
    ]

    def __init__(self, state: str | Path = "adverso.json", audit: str | Path | None = "audit.log",
                 monitor: Any = None, frames: Any = None, refresh_every: float = 1.0,
                 stop: threading.Event | None = None) -> None:
        super().__init__()
        self.store = Store(state)
        self.audit_path = Path(audit) if audit else None
        self.monitor = monitor  # adverso.monitor.core.Monitor opcional
        self.frames = frames  # iterable de (ts, Datagram): captura en vivo o pcap
        self.refresh_every = refresh_every
        # Al salir se activa: corta la captura en vivo (live.capture lo comprueba).
        self.stop = stop or threading.Event()
        self.selected: str | None = None
        self._mtime = -1.0
        self._audit_pos = 0
        self._monitor_state = "apagado"

    # --- composición -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(id="cabecera")
        with Horizontal(id="cuerpo"):
            with Vertical(id="izquierda"):
                yield Static("PALACIOS", classes="titulo")
                yield DataTable(id="palacios", cursor_type="row", zebra_stripes=True)
            with Vertical(id="derecha"):
                yield Static("SOMBRAS", id="titulo-sombras", classes="titulo")
                yield DataTable(id="sombras", cursor_type="row", zebra_stripes=True)
                yield Static(id="detalle", markup=False)
        yield Static("EN VIVO", classes="titulo")
        yield RichLog(id="vivo", max_lines=500, markup=False, wrap=False)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#palacios", DataTable).add_columns("", "RANGO", "AMENAZA", "SOMBRAS", "PALACIO")
        self.query_one("#sombras", DataTable).add_columns("NOMBRE", "SOMBRA", "PUNT.", "ORIGEN", "HALLAZGO")
        if self.audit_path and self.audit_path.exists():
            self._audit_pos = self.audit_path.stat().st_size  # solo lo nuevo
        self.refresh_data()
        self.set_interval(self.refresh_every, self.refresh_data)
        if self.monitor is not None and self.frames is not None:
            self._monitor_state = "escuchando"
            self.monitor.on_event = self._from_monitor_thread
            threading.Thread(target=self._run_monitor, name="monitor", daemon=True).start()
        self.query_one("#palacios", DataTable).focus()

    # --- monitor en un hilo -------------------------------------------------------

    def _frames(self) -> Any:
        for item in self.frames:
            if self.stop.is_set():
                return
            yield item

    def _run_monitor(self) -> None:
        try:
            self.monitor.run(self._frames())  # vuelca al Store por su cuenta, también en silencio
            state = "captura terminada"
        except Exception as e:  # CaptureError, PcapError, permisos…
            state = f"error: {e}"
        if not self.stop.is_set():
            try:
                self.call_from_thread(self._set_monitor_state, state)
            except RuntimeError:  # la app se cerró mientras tanto
                pass

    def _from_monitor_thread(self, ev: Any) -> None:
        try:
            self.call_from_thread(self.on_dns_event, ev)
        except RuntimeError:  # la app ya se cerró
            self.stop.set()

    def _set_monitor_state(self, state: str) -> None:
        self._monitor_state = state
        self.log_line(Text(f"monitor: {state}", style="bold yellow" if "error" not in state else f"bold {RED}"))
        self.refresh_data(force=True)

    def on_dns_event(self, ev: Any) -> None:
        v = ev.verdict
        line = Text.assemble(
            (time.strftime("%H:%M:%S ", time.localtime(ev.ts)), "grey50"),
            ("DNS ", "bold"),
            (f"{ev.palace:<22} ", "white"),
            (ev.domain, "bold white" if v.score >= self.monitor.min_score else "grey70"),
            (f" ({ev.qtype}) ", "grey50"),
            tier_text(v.score),
            (f" {v.kind.display}", TIER_STYLE[v.tier.label]),
        )
        self.log_line(line)

    # --- refresco desde disco -----------------------------------------------------

    def refresh_data(self, force: bool = False) -> None:
        try:
            self._tail_audit()
            mtime = self.store.mtime()
            if force or mtime != self._mtime:
                self._mtime = mtime
                self.store.reload()
                self._fill_palaces()
            self._update_header()
        except NoMatches:  # el temporizador saltó mientras la app se cerraba
            pass

    def _update_header(self) -> None:
        palaces = self.store.palaces
        shadows = sum(len(p["findings"]) for p in palaces.values())
        mon = ""
        if self.monitor is not None:
            st = self.monitor.stats
            mon = f"  ·  monitor: {self._monitor_state} · {st.queries} consultas · {st.new_shadows} sombras nuevas"
        self.query_one("#cabecera", Static).update(
            Text(f"◆ METAVERSO  ·  {len(palaces)} palacios · {shadows} sombras{mon}"))

    def _fill_palaces(self) -> None:
        table = self.query_one("#palacios", DataTable)
        ordered = sorted(self.store.palaces.values(), key=palace_score, reverse=True)
        table.clear()
        for p in ordered:
            rank, score = palace_rank(p), palace_score(p)
            name = p["ip"] + (f" ({', '.join(p['names'])})" if p.get("names") else "")
            table.add_row(
                Text(rank.letter, style=f"bold {RED}" if rank.letter in "SA" else "bold"),
                Text(rank.label), tier_text(score), Text(str(len(p["findings"])), justify="right"), Text(name),
                key=p["ip"],
            )
        keys = [p["ip"] for p in ordered]
        if self.selected not in keys:
            self.selected = keys[0] if keys else None
        if self.selected is not None:
            table.move_cursor(row=keys.index(self.selected), animate=False)
        self._fill_shadows()

    def _fill_shadows(self) -> None:
        table = self.query_one("#sombras", DataTable)
        table.clear()
        p = self.store.palaces.get(self.selected or "")
        title = self.query_one("#titulo-sombras", Static)
        if p is None:
            title.update(Text("SOMBRAS"))
            self.query_one("#detalle", Static).update(Text("Sin Palacios todavía. Lanza un reconocimiento o el monitor.", style="grey50"))
            return
        title.update(Text(f"SOMBRAS DE {p['ip']}"))
        for f in sorted(p["findings"].values(), key=lambda f: -f["score"]):
            table.add_row(
                Text(f["codename"], style="bold"), Text(shadow_label(f["kind"])), tier_text(f["score"]),
                Text(f["source"], style="grey50"), Text(f["title"]), key=f["id"],
            )
        self._show_detail(next(iter(sorted(p["findings"].values(), key=lambda f: -f["score"])), None))

    def _show_detail(self, f: dict[str, Any] | None) -> None:
        detail = self.query_one("#detalle", Static)
        if f is None:
            detail.update(Text("Palacio sin Sombras.", style="grey50"))
            return
        text = Text.assemble((f"{f['codename']} · {shadow_label(f['kind'])} · ", f"bold {RED}"), tier_text(f["score"]), "\n")
        text.append(f["title"] + "\n", style="bold")
        ev = f.get("evidence")
        if isinstance(ev, dict):
            for reason in ev.get("motivos", [])[:3]:
                text.append(f"· {reason}\n", style="grey70")
            extra = {k: v for k, v in ev.items() if k != "motivos" and v not in (None, [], "")}
            if extra:
                text.append(json.dumps(extra, ensure_ascii=False)[:300], style="grey50")
        elif ev is not None:
            text.append(json.dumps(ev, ensure_ascii=False, default=str)[:300], style="grey50")
        seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(f.get("last_seen", 0)))
        text.append(f"\núltima vez: {seen} · origen: {f['source']}", style="grey50")
        detail.update(text)

    def _tail_audit(self) -> None:
        if not self.audit_path:
            return
        try:
            size = self.audit_path.stat().st_size
        except FileNotFoundError:
            return
        if size < self._audit_pos:  # rotado o truncado
            self._audit_pos = 0
        if size == self._audit_pos:
            return
        with self.audit_path.open("rb") as fh:
            fh.seek(self._audit_pos)
            chunk = fh.read(size - self._audit_pos)
        complete, _, _ = chunk.rpartition(b"\n")
        self._audit_pos += len(complete) + (1 if complete else 0)
        for raw in complete.splitlines():
            try:
                e = json.loads(raw)
            except ValueError:
                continue
            icon = AUDIT_SHOWN.get(e.get("event"))
            if icon is None:
                continue
            what = " ".join(str(x) for x in (e.get("tool"), e.get("target") or e.get("source")) if x)
            extra = e.get("reason") or e.get("error") or ("aprobada" if e.get("approved") else
                                                         "denegada" if "approved" in e else "")
            style = f"bold {RED}" if e["event"] in ("denied_scope", "failed", "monitor_error") else "white"
            self.log_line(Text.assemble(
                (time.strftime("%H:%M:%S ", time.localtime(e.get("ts", time.time()))), "grey50"),
                ("AGENTE " if e.get("tool") else "", "bold"), (f"{icon} {e['event']} ", style), (what, "white"),
                (f"  {extra}" if extra else "", "grey70"),
            ))

    # --- eventos y acciones -------------------------------------------------------

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        key = event.row_key.value if event.row_key is not None else None
        if event.data_table.id == "palacios":
            if key != self.selected:
                self.selected = key
                self._fill_shadows()
        elif event.data_table.id == "sombras":
            p = self.store.palaces.get(self.selected or "")
            if p is not None and key in p["findings"]:
                self._show_detail(p["findings"][key])

    def log_line(self, text: Text) -> None:
        try:
            self.query_one("#vivo", RichLog).write(text)
        except NoMatches:  # evento del monitor que llega durante el cierre
            pass

    def action_clear_log(self) -> None:
        self.query_one("#vivo", RichLog).clear()

    def action_report(self) -> None:
        path = Path(f"informe-{time.strftime('%Y%m%d-%H%M%S')}.md")
        path.write_text(render_markdown(self.store), encoding="utf8")
        self.notify(f"Informe escrito en {path}", title="Informe")

    def on_unmount(self) -> None:
        self.stop.set()


def run_tui(a: Any) -> int:
    """`adverso tui`: visor en vivo; con --monitor/--pcap, además captura DNS."""
    from ..monitor.core import Monitor, pcap_frames
    from ..monitor.live import CaptureError, capture
    from ..monitor.procs import ProcessResolver
    from ..scope.audit import AuditLog

    stop = threading.Event()
    monitor = frames = None
    source = a.pcap or a.iface or "todas"
    if a.monitor or a.pcap:
        monitor = Monitor(Store(a.state), min_score=a.min_score, resolver=None if a.pcap else ProcessResolver())
        try:
            frames = pcap_frames(a.pcap) if a.pcap else capture(a.iface, stop)
        except CaptureError as e:  # sin root, interfaz inexistente: mejor decirlo antes de abrir la TUI
            print(f"adverso tui: {e}", file=sys.stderr)
            return 2
        AuditLog(a.audit).record("monitor_start", source=source, pcap=bool(a.pcap), min_score=a.min_score, ui="tui")
    app = MetaversoApp(a.state, a.audit, monitor=monitor, frames=frames, stop=stop)
    # kill / cerrar la ventana del terminal: salir como con `q` (y auditar el cierre).
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: app.exit())
    app.run()
    if monitor is not None:
        st = monitor.stats
        AuditLog(a.audit).record("monitor_stop", source=source, queries=st.queries, saved=st.saved,
                                 new_shadows=st.new_shadows, ui="tui")
    return 0
