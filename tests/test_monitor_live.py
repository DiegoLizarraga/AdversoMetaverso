"""Monitor contra tráfico real: captura en vivo y capturas hechas por tcpdump.

Necesitan Linux, root y dig/tcpdump (el contenedor de docker/ los tiene). Para no
depender de Internet, un "resolutor" local recibe las consultas y no contesta:
dig espera con su socket abierto, que es lo que permite atribuirlo al proceso.
"""

import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from adverso.core.store import Store
from adverso.monitor.core import Monitor, pcap_frames
from adverso.monitor.live import capture
from adverso.monitor.procs import ProcessResolver

pytestmark = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0 or not hasattr(socket, "AF_PACKET") or not shutil.which("dig"),
    reason="necesita Linux, root y dig",
)


@pytest.fixture
def mute_resolver():
    """Escucha en 127.0.0.1:53 y no responde nunca."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 53))
    yield
    s.close()


def dig(name: str, wait: float = 2) -> None:
    subprocess.run(["dig", "@127.0.0.1", "+tries=1", f"+time={int(wait)}", name], capture_output=True, timeout=10)


def test_captura_en_vivo_atribuye_al_proceso(tmp_path, mute_resolver):
    stop = threading.Event()
    events = []
    mon = Monitor(Store(tmp_path / "s.json"), on_event=events.append, resolver=ProcessResolver(), flush_every=0.2)
    frames = capture("lo", stop)  # el socket ya escucha al volver: sin esperas a ciegas
    t = threading.Thread(target=mon.run, args=(frames,), daemon=True)
    t.start()
    dig("ads.doubleclick.net", wait=1)
    stop.set()
    t.join(5)
    hits = [e for e in events if e.domain == "ads.doubleclick.net"]
    assert len(hits) == 1, events  # loopback: una sola vez, no dos
    assert hits[0].palace == "local/dig" and hits[0].verdict.kind.name == "GREEDY"
    assert "local/dig" in Store(tmp_path / "s.json").palaces


def test_monitor_para_limpio_con_sigterm(tmp_path, mute_resolver):
    """kill / docker stop: vuelca lo pendiente y audita el cierre (no muere a medias)."""
    import signal
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    p = subprocess.Popen([sys.executable, "-m", "adverso", "monitor", "--iface", "lo", "--quiet",
                          "--state", str(tmp_path / "s.json"), "--audit", str(tmp_path / "a.log")],
                         cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    first = p.stderr.readline()  # el aviso sale cuando el socket ya está abierto: sin esperas a ciegas
    assert first.startswith("Escuchando DNS en lo"), first
    dig("ads.doubleclick.net", wait=1)
    p.send_signal(signal.SIGTERM)
    out, err = p.communicate(timeout=10)
    assert p.returncode == 0, err
    assert "1 consultas" in err
    assert '"monitor_stop"' in (tmp_path / "a.log").read_text()
    assert Store(tmp_path / "s.json").palaces  # lo pendiente llegó al disco


@pytest.mark.skipif(not shutil.which("tcpdump"), reason="necesita tcpdump")
@pytest.mark.parametrize("iface", ["any", "lo"])  # SLL2 y Ethernet
def test_captura_de_tcpdump(tmp_path, mute_resolver, iface):
    pcap = tmp_path / "c.pcap"
    td = subprocess.Popen(["tcpdump", "-i", iface, "-U", "-w", str(pcap), "udp", "port", "53"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.0)
        dig("x9f3k2l1m0q8z7v6.biz", wait=1)
        time.sleep(0.5)
    finally:
        td.terminate()
        td.wait(5)
    mon = Monitor(Store(tmp_path / "s.json"))
    stats = mon.run(pcap_frames(str(pcap)))
    assert stats.queries == 1 and stats.new_shadows == 1
    [palace] = Store(tmp_path / "s.json").palaces.values()
    [shadow] = palace["findings"].values()
    assert palace["ip"] == "127.0.0.1" and shadow["kind"] == "CORRUPT"
