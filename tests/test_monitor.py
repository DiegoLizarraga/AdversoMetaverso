import os
import random
import struct

import pytest

from adverso.core.store import Store
from adverso.monitor import dns
from adverso.monitor.core import Monitor, pcap_frames
from adverso.monitor.packets import LINK_ETHERNET, LINK_NULL, LINK_RAW, LINK_SLL, LINK_SLL2, Datagram, from_link
from adverso.monitor.pcap import PcapError, read
from adverso.monitor.procs import ProcessResolver, udp_sockets

import netcraft as nc

# --- DNS ---------------------------------------------------------------------


def test_consulta_y_respuesta_con_compresion():
    q = dns.parse(nc.dns_query("Ads.DoubleClick.net", qtype=28))
    assert q.is_query and q.questions == [dns.Question("ads.doubleclick.net", 28)] and q.questions[0].type_name == "AAAA"
    r = dns.parse(nc.dns_response("cdn.example.com", ["1.2.3.4", "2001:db8::1"], cname="edge.example.net"))
    assert not r.is_query and r.addresses == ["1.2.3.4", "2001:db8::1"]
    assert r.answers[0].target == "edge.example.net" and r.answers[1].name == "cdn.example.com"


def test_nombres_hostiles_se_sanean():
    m = dns.parse(nc.dns_query("evil\x1b[2J\x07.example.com"))
    assert m.questions[0].name == r"evil\x1b\x5b2j\x07.example.com"
    assert "\x1b" not in m.questions[0].name


def test_compresion_maliciosa_no_cuelga_ni_lanza():
    head = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    assert dns.parse(head + b"\xc0\x0c" + b"\x00\x01\x00\x01") is None  # puntero a sí mismo
    assert dns.parse(head + b"\xc0\x20" + b"\x00\x01\x00\x01") is None  # puntero hacia delante
    assert dns.parse(head + b"\x3f" + b"a" * 10) is None  # etiqueta truncada
    assert dns.parse(head + b"\x80abc\x00\x00\x01\x00\x01") is None  # tipo de etiqueta reservado
    long_name = ".".join(["a" * 63] * 5)  # > 255 octetos
    assert dns.parse(nc.dns_query(long_name)) is None


def test_basura_aleatoria_nunca_lanza():
    rnd = random.Random(1234)
    valid = nc.dns_response("x.example.com", ["1.1.1.1"])
    for _ in range(3000):
        blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 80)))
        dns.parse(blob)
        mutated = bytearray(valid)
        for _ in range(rnd.randint(1, 6)):
            mutated[rnd.randrange(len(mutated))] = rnd.getrandbits(8)
        dns.parse(bytes(mutated))
        from_link(rnd.choice([LINK_ETHERNET, LINK_SLL, LINK_SLL2, LINK_NULL, LINK_RAW]), blob)


# --- capas de enlace e IP ----------------------------------------------------


@pytest.mark.parametrize("linktype,wrap", [
    (LINK_ETHERNET, nc.ether),
    (LINK_ETHERNET, lambda ip: nc.ether(ip, vlan=True)),
    (LINK_SLL, nc.sll),
    (LINK_SLL2, nc.sll2),
    (LINK_NULL, lambda ip: struct.pack("<I", 2) + ip),
    (LINK_RAW, lambda ip: ip),
])
def test_enlaces(linktype, wrap):
    d = from_link(linktype, wrap(nc.ipv4("10.0.0.7", "10.0.0.1", nc.udp(40000, 53, b"hola"))))
    assert d == Datagram("10.0.0.7", "10.0.0.1", 40000, 53, b"hola")


def test_ipv6_con_cabecera_de_extension_y_fragmentos_ipv4():
    d = from_link(LINK_ETHERNET, nc.ether(nc.ipv6("fe80::1", "2001:db8::53", nc.udp(5353, 53, b"x"), hop_by_hop=True)))
    assert (d.src, d.dst, d.dport, d.payload) == ("fe80::1", "2001:db8::53", 53, b"x")
    frag = nc.ipv4("10.0.0.7", "10.0.0.1", nc.udp(1, 53, b"x"), frag=0x0010)  # no es el primer fragmento
    assert from_link(LINK_RAW, frag) is None
    assert from_link(LINK_RAW, nc.ipv4("10.0.0.7", "10.0.0.1", b"\x00" * 20, proto=6)) is None  # TCP


# --- capturas ----------------------------------------------------------------


def test_pcap_y_pcapng(tmp_path):
    f1 = nc.query_frame("10.0.0.7", "a.example.com")
    (tmp_path / "c.pcap").write_bytes(nc.pcap([(1700000000.25, f1)]))
    [(ts, lt, data)] = list(read(tmp_path / "c.pcap"))
    assert lt == LINK_ETHERNET and data == f1 and abs(ts - 1700000000.25) < 1e-6

    f2 = nc.sll2(nc.ipv4("10.0.0.8", "10.0.0.1", nc.udp(1, 53, nc.dns_query("b.example.com"))))
    (tmp_path / "c.pcapng").write_bytes(nc.pcapng([(0, 1.5, f1), (1, 2.000000001, f2)], [LINK_ETHERNET, LINK_SLL2], nano_iface=1))
    got = list(read(tmp_path / "c.pcapng"))
    assert [(lt, d) for _, lt, d in got] == [(LINK_ETHERNET, f1), (LINK_SLL2, f2)]
    assert abs(got[0][0] - 1.5) < 1e-6 and abs(got[1][0] - 2.000000001) < 1e-9

    (tmp_path / "x.txt").write_text("hola")
    with pytest.raises(PcapError):
        list(read(tmp_path / "x.txt"))
    (tmp_path / "cortada.pcap").write_bytes(nc.pcap([(1.0, f1)])[:-5])
    assert list(read(tmp_path / "cortada.pcap")) == []


# --- monitor -----------------------------------------------------------------


def dg(src, name, qid=1, sport=40000, dport=53, payload=None):
    return Datagram(src, "10.0.0.1", sport, dport, payload or nc.dns_query(name, qid=qid))


def test_monitor_umbral_duplicados_y_persistencia(tmp_path):
    store = Store(tmp_path / "s.json")
    seen = []
    mon = Monitor(store, min_score=40, on_event=seen.append, flush_every=3600)
    mon.feed(1.0, dg("10.0.0.7", "ads.doubleclick.net", qid=1))
    mon.feed(1.1, dg("10.0.0.7", "ads.doubleclick.net", qid=1))  # mismo paquete (puente/NAT)
    mon.feed(2.0, dg("10.0.0.7", "ads.doubleclick.net", qid=2))
    mon.feed(2.5, dg("10.0.0.7", "www.wikipedia.org", qid=3))  # se ve, pero no se guarda
    mon.feed(3.0, Datagram("10.0.0.1", "10.0.0.7", 53, 40000, nc.dns_response("ads.doubleclick.net", ["9.9.9.9"], qid=2)))
    assert [e.domain for e in seen] == ["ads.doubleclick.net", "ads.doubleclick.net", "www.wikipedia.org"]
    assert mon.stats.duplicates == 1 and mon.stats.responses == 1
    assert mon.flush() == 1
    mon.feed(9.0, dg("10.0.0.7", "ads.doubleclick.net", qid=9))
    assert mon.flush() == 0  # ya existía: suma consultas

    p = Store(tmp_path / "s.json").palaces["10.0.0.7"]
    [f] = p["findings"].values()
    assert f["source"] == "monitor" and f["kind"] == "GREEDY" and f["title"] == "ads.doubleclick.net: Publicidad"
    assert f["evidence"]["consultas"] == 3 and f["evidence"]["ips"] == ["9.9.9.9"] and f["evidence"]["tipos"] == ["A"]


def test_monitor_atribuye_a_procesos_locales(tmp_path):
    class FakeResolver:
        def owner(self, ip, port):
            return "firefox" if port == 1111 else None

        def is_local(self, ip):
            return ip.startswith("127.") or ip == "192.168.1.5"

    seen = []
    mon = Monitor(None, on_event=seen.append, resolver=FakeResolver())
    mon.feed(1.0, dg("192.168.1.5", "a.example.com", qid=1, sport=1111))
    mon.feed(1.0, dg("192.168.1.5", "b.example.com", qid=2, sport=2222))
    mon.feed(1.0, dg("192.168.1.9", "c.example.com", qid=3, sport=1111))
    assert [(e.palace, e.process) for e in seen] == [("local/firefox", "firefox"), ("local", None), ("192.168.1.9", None)]


def test_dns_interno_de_docker_con_puerto_cambiado(tmp_path):
    """Docker reescribe 127.0.0.11:53 a un puerto aleatorio antes de que pase por lo."""
    seen = []
    mon = Monitor(None, on_event=seen.append)
    q = Datagram("127.0.0.1", "127.0.0.11", 40000, 45123, nc.dns_query("ads.doubleclick.net"))
    r = Datagram("127.0.0.11", "127.0.0.1", 45123, 40000, nc.dns_response("ads.doubleclick.net", ["1.2.3.4"]))
    assert q.is_dns and q.to_resolver and r.is_dns and not r.to_resolver
    mon.feed(1.0, q)
    mon.feed(1.1, r)
    assert [e.domain for e in seen] == ["ads.doubleclick.net"] and mon.stats.responses == 1


def test_vuelca_aunque_no_lleguen_mas_paquetes(tmp_path):
    """En una red tranquila, lo pendiente no puede esperar al siguiente paquete."""
    import threading
    import time as _t

    store_path = tmp_path / "s.json"
    gate = threading.Event()

    def frames():  # un paquete y después silencio, hasta que el test lo suelte
        yield 1.0, dg("10.0.0.7", "ads.doubleclick.net", qid=1)
        gate.wait(5)

    mon = Monitor(Store(store_path), flush_every=0.1)
    t = threading.Thread(target=mon.run, args=(frames(),), daemon=True)
    t.start()
    deadline = _t.time() + 3
    while _t.time() < deadline and "10.0.0.7" not in Store(store_path).palaces:
        _t.sleep(0.05)
    assert "10.0.0.7" in Store(store_path).palaces  # visible mientras la captura sigue abierta
    gate.set()
    t.join(5)


def test_monitor_ignora_lo_que_no_es_consulta(tmp_path):
    mon = Monitor(None)
    assert mon.feed(1.0, dg("10.0.0.7", "x.com", dport=5353)) is None
    assert mon.feed(1.0, dg("10.0.0.7", "x.com", payload=b"no es dns")) is None
    assert mon.stats.queries == 0


def test_pcap_de_punta_a_punta_por_la_cli(tmp_path, capsys):
    from adverso.ui.cli import main

    frames = [(10.0 + i, nc.query_frame("10.0.0.7", n, qid=i)) for i, n in enumerate(
        ["ads.doubleclick.net", "www.google-analytics.com", "x9f3k2l1m0q8z7v6.biz", "debian.org"])]
    (tmp_path / "c.pcap").write_bytes(nc.pcap(frames))
    rc = main(["monitor", "--pcap", str(tmp_path / "c.pcap"), "--state", str(tmp_path / "s.json"),
               "--audit", str(tmp_path / "a.log")])
    out = capsys.readouterr()
    assert rc == 0 and "ads.doubleclick.net" in out.out and "debian.org" in out.out and "4 consultas" in out.err
    titles = {f["title"].split(":")[0] for f in Store(tmp_path / "s.json").palaces["10.0.0.7"]["findings"].values()}
    assert titles == {"ads.doubleclick.net", "www.google-analytics.com", "x9f3k2l1m0q8z7v6.biz"}
    audit = (tmp_path / "a.log").read_text()
    assert "monitor_start" in audit and "monitor_stop" in audit
    assert list(pcap_frames(str(tmp_path / "c.pcap")))[0][1].dport == 53


# --- /proc -------------------------------------------------------------------


def test_atribucion_por_proc_falso(tmp_path):
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    (proc / "net" / "udp").write_text(head + "  1: 0500A8C0:0457 0100000A:0035 01 00000000:00000000 00:00000000 00000000  1000  0 4242 2\n")
    (proc / "net" / "udp6").write_text(head)
    (proc / "net" / "fib_trie").write_text("Local:\n  +-- 192.168.0.0/16 2 0 2\n     |-- 192.168.0.5\n        /32 host LOCAL\n")
    (proc / "net" / "if_inet6").write_text("00000000000000000000000000000001 01 80 10 80       lo\n")
    fd = proc / "777" / "fd"
    fd.mkdir(parents=True)
    (proc / "777" / "comm").write_text("curl\x1b]0;x\n")
    os.symlink("socket:[4242]", fd / "3")
    assert udp_sockets(proc) == {("192.168.0.5", 1111): 4242}
    r = ProcessResolver(proc, min_scan=0)
    assert r.is_local("192.168.0.5") and r.is_local("::1") and not r.is_local("192.168.0.9")
    assert r.owner("192.168.0.5", 1111) == "curl??0?x"  # nombre saneado
    assert r.owner("192.168.0.5", 2222) is None and r.owner("8.8.8.8", 1111) is None

    # Mismo proceso, socket nuevo (como un navegador): se encuentra sin recorrer todo /proc.
    scans = []
    real_scan = r._scan
    r._scan = lambda: (scans.append(1), real_scan())[1]
    r.min_scan = 3600
    (proc / "net" / "udp").write_text(head + "  1: 0500A8C0:08AE 0100000A:0035 01 00000000:00000000 00:00000000 00000000  1000  0 5151 2\n")
    os.remove(fd / "3")
    os.symlink("socket:[5151]", fd / "4")
    assert r.owner("192.168.0.5", 2222) == "curl??0?x" and scans == []
