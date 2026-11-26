import asyncio
import json
import time

import pytest

pytest.importorskip("textual")

from textual.widgets import DataTable, RichLog, Static  # noqa: E402

from adverso.core.findings import ingest  # noqa: E402
from adverso.core.store import Store  # noqa: E402
from adverso.monitor.core import Monitor, pcap_frames  # noqa: E402
from adverso.ui.tui import MetaversoApp  # noqa: E402

import netcraft as nc  # noqa: E402

NMAP = {"hosts": [{"address": "10.0.0.5", "up": True, "hostname": None, "open_ports": [
    {"port": 6379, "protocol": "tcp", "service": "redis"}, {"port": 22, "protocol": "tcp", "service": "ssh"}]}]}


def rows(app, table_id):
    t = app.query_one(f"#{table_id}", DataTable)
    return [[str(c) for c in t.get_row_at(i)] for i in range(t.row_count)]


def log_text(app):
    return "\n".join(line.text for line in app.query_one("#vivo", RichLog).lines)


def run(coro):
    return asyncio.run(coro)


def test_refresca_cuando_otro_proceso_escribe(tmp_path):
    state, audit = tmp_path / "s.json", tmp_path / "a.log"
    ingest(Store(state), "nmap_scan", "10.0.0.5", None, NMAP)

    async def go():
        app = MetaversoApp(state, audit, refresh_every=0.1)
        async with app.run_test(size=(150, 45)) as pilot:
            assert rows(app, "palacios")[0][4] == "10.0.0.5"
            assert [r[4] for r in rows(app, "sombras")][0].startswith("6379/tcp redis")
            # otro proceso (el agente, el monitor) escribe mientras la TUI está abierta
            with Store(state).transaction() as s:
                s.palaces["10.0.0.9"] = {"ip": "10.0.0.9", "names": ["lab"], "findings": {}}
            audit.write_text(json.dumps({"ts": time.time(), "event": "denied_scope", "tool": "nmap_scan",
                                         "target": "8.8.8.8", "reason": "fuera"}) + "\n")
            await pilot.pause(0.4)
            assert {r[4] for r in rows(app, "palacios")} == {"10.0.0.5", "10.0.0.9 (lab)"}
            assert "denied_scope" in log_text(app) and "8.8.8.8" in log_text(app)
            assert "2 palacios" in str(app.query_one("#cabecera", Static).render())
            # bajar al segundo Palacio muestra sus Sombras (ninguna)
            app.query_one("#palacios", DataTable).focus()
            await pilot.press("down")
            await pilot.pause(0.1)
            assert app.selected == "10.0.0.9" and rows(app, "sombras") == []

    run(go())


def test_markup_hostil_no_se_interpreta(tmp_path):
    state = tmp_path / "s.json"
    with Store(state).transaction() as s:
        s.palaces["10.0.0.5"] = {"ip": "10.0.0.5", "names": ["[bold red]x[/]"], "findings": {"f1": {
            "id": "f1", "source": "nikto", "title": "[link=http://evil]clic[/link] [blink]", "kind": "CORRUPT",
            "score": 82, "codename": "NIEBLA", "evidence": {"motivos": ["[reverse]"]}, "last_seen": 0}}}

    async def go():
        app = MetaversoApp(state, None)
        async with app.run_test(size=(150, 45)):
            assert rows(app, "palacios")[0][4] == "10.0.0.5 ([bold red]x[/])"
            assert rows(app, "sombras")[0][4] == "[link=http://evil]clic[/link] [blink]"
            assert "[reverse]" in str(app.query_one("#detalle", Static).render())

    run(go())


def test_reproduce_una_captura_en_vivo(tmp_path):
    state = tmp_path / "s.json"
    frames = [(10.0 + i, nc.query_frame("10.0.0.7", n, qid=i)) for i, n in enumerate(
        ["ads.doubleclick.net", "www.google-analytics.com", "debian.org"])]
    (tmp_path / "c.pcap").write_bytes(nc.pcap(frames))
    mon = Monitor(Store(state), flush_every=0)

    async def go():
        app = MetaversoApp(state, None, monitor=mon, frames=pcap_frames(str(tmp_path / "c.pcap")), refresh_every=0.1)
        async with app.run_test(size=(150, 45)) as pilot:
            for _ in range(30):
                await pilot.pause(0.1)
                if app._monitor_state == "captura terminada" and rows(app, "palacios"):
                    break
            text = log_text(app)
            assert "ads.doubleclick.net" in text and "debian.org" in text and "captura terminada" in text
            assert rows(app, "palacios")[0][4] == "10.0.0.7"
            assert {r[4].split(":")[0] for r in rows(app, "sombras")} == {"ads.doubleclick.net", "www.google-analytics.com"}
            assert "3 consultas" in str(app.query_one("#cabecera", Static).render())

    run(go())


def test_captura_que_falla_se_muestra(tmp_path):
    """Sin root, la captura falla en su hilo: la TUI lo dice y sigue funcionando."""
    from adverso.monitor.live import CaptureError

    def frames():
        raise CaptureError("la captura en vivo necesita root o CAP_NET_RAW (prueba con sudo)")
        yield  # pragma: no cover

    async def go():
        app = MetaversoApp(tmp_path / "s.json", None, monitor=Monitor(None), frames=frames(), refresh_every=0.1)
        async with app.run_test(size=(150, 45)) as pilot:
            await pilot.pause(0.5)
            assert "necesita root" in log_text(app) and app._monitor_state.startswith("error")
            assert "error" in str(app.query_one("#cabecera", Static).render())

    run(go())


def test_tui_monitor_sin_permisos_avisa_antes_de_abrirse(tmp_path, monkeypatch, capsys):
    import argparse

    import adverso.monitor.live as live
    from adverso.ui.tui import run_tui

    def no_root(iface=None, stop=None):
        raise live.CaptureError("la captura en vivo necesita root o CAP_NET_RAW (prueba con sudo)")

    monkeypatch.setattr(live, "capture", no_root)
    a = argparse.Namespace(state=str(tmp_path / "s.json"), audit=str(tmp_path / "a.log"), monitor=True,
                           iface=None, pcap=None, min_score=40)
    assert run_tui(a) == 2 and "necesita root" in capsys.readouterr().err


def test_informe_desde_la_tui(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ingest(Store(tmp_path / "s.json"), "nmap_scan", "10.0.0.5", None, NMAP)

    async def go():
        app = MetaversoApp(tmp_path / "s.json", None)
        async with app.run_test(size=(150, 45)) as pilot:
            await pilot.press("r")
            await pilot.pause(0.1)

    run(go())
    [report] = list(tmp_path.glob("informe-*.md"))
    assert "10.0.0.5" in report.read_text(encoding="utf8")
