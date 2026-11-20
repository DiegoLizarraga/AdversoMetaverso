import pytest

from adverso.agents.base import Agent
from adverso.core.findings import ingest
from adverso.core.store import Store
from adverso.scope.audit import AuditLog
from adverso.scope.guard import Scope
from adverso.tools.base import RawResult, ToolError
from adverso.tools.executor import Executor
from adverso.tools.osint import Dig, TheHarvester, WhatWeb, Whois
from adverso.ui.cli import ask_operator
from adverso.ui.repl import Repl


def test_nombres_invalidos_rechazados():
    for bad in ("-h", "a b", "x;rm -rf /", "a..b", "", "$(id)"):
        with pytest.raises(ToolError):
            Dig().build_command({"domain": bad})
    assert Whois().build_command({"target": "Example.COM."}) == ["whois", "example.com"]


def test_parse_dig_whois_harvester():
    d = Dig().parse("example.com.\t300\tIN\tA\t1.2.3.4\n", "", {})
    assert d["records"] == [{"name": "example.com", "ttl": 300, "type": "A", "data": "1.2.3.4"}]
    w = Whois().parse("Registrar: ACME\nName Server: NS1.X.COM\nName Server: NS2.X.COM\nIrrelevante: x\n", "", {})
    assert w["fields"]["name server"] == ["NS1.X.COM", "NS2.X.COM"] and "irrelevante" not in w["fields"]
    out = "[*] Emails found: 1\n----\nroot@example.com\n\n[*] Hosts found: 2\n---------------------\nwww.example.com:1.1.1.1\napi.example.com\n"
    h = TheHarvester().parse(out, "", {})
    assert h["emails"] == ["root@example.com"] and h["hosts"][0] == {"name": "api.example.com", "ip": None}


def test_whatweb_parse():
    r = WhatWeb().parse('[{"http_status":200,"plugins":{"HTTPServer":{"string":["nginx"]},"Title":{}}}]', "", {})
    assert r == {"http_status": 200, "technologies": {"HTTPServer": ["nginx"], "Title": []}}


def test_pasiva_no_exige_alcance_pero_activa_si(tmp_path):
    scope = Scope.from_entries(["192.168.56.0/24"], lambda h: [])
    ran = []

    class FakeDig(Dig):
        def execute(self, cmd):
            ran.append(cmd)
            return RawResult(0, "example.com. 60 IN A 1.2.3.4\n", "")

    store = Store(tmp_path / "s.json")
    ex = Executor(scope, AuditLog(tmp_path / "a.log"), tools={"dns_lookup": FakeDig(), "whatweb_fingerprint": WhatWeb()}, store=store)
    r = ex.run("dns_lookup", {"domain": "example.com"})
    assert r["ok"] and ran and "example.com" in store.palaces
    assert not ex.run("whatweb_fingerprint", {"url": "http://example.com"})["ok"]  # activa: fuera de alcance


def test_confirmacion_sin_tty_deniega():
    assert ask_operator(Whois(), "x", ["whois"]) is False


def test_confirmacion_timeout_deniega(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    import select
    monkeypatch.setattr(select, "select", lambda *a: ([], [], []))
    assert ask_operator(Whois(), "x", ["whois"], timeout=0.01) is False


def test_repl_comandos(tmp_path):
    store = Store(tmp_path / "s.json")
    ingest(store, "nmap_scan", "10.0.0.5", None, {"hosts": [{"address": "10.0.0.5", "up": True, "hostname": None,
           "open_ports": [{"port": 6379, "protocol": "tcp", "service": "redis"}]}]})
    scope = Scope.from_entries(["10.0.0.0/24"], lambda h: [])
    ex = Executor(scope, AuditLog(tmp_path / "a.log"), store=store)
    out = []
    repl = Repl(Agent(None, ex), ex, store, tmp_path / "a.log", out=out.append)  # type: ignore[arg-type]
    for line in ("/palacios", "/sombras 10.0.0.5", "/alcance", "/herramientas", "/informe", "/nada", "/auditoria"):
        assert repl.handle(line)
    text = "\n".join(out)
    assert "10.0.0.5" in text and "Redis" in text and "10.0.0.0/24" in text and "dns_lookup" in text and "desconocido" in text
    assert repl.handle("/olvida 10.0.0.5") and not store.palaces
    assert repl.handle("/salir") is False
