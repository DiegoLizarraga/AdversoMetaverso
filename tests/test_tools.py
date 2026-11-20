import json

import pytest

from adverso.scope.audit import AuditLog
from adverso.scope.guard import Scope
from adverso.tools.base import RawResult, Tool, ToolError
from adverso.tools.executor import Executor
from adverso.tools.gobuster import Gobuster
from adverso.tools.nikto import Nikto
from adverso.tools.nmap import Nmap

NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="8765"><state state="open"/><service name="http" product="SimpleHTTPServer" version="0.6"/></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
</ports></host></nmaprun>"""

GOBUSTER_OUT = """admin                (Status: 301) [Size: 0] [--> /admin/]
robots.txt           (Status: 200) [Size: 2]
"""

NIKTO_OUT = """- Nikto v2.6.1
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Server: SimpleHTTP/0.6 Python/3.14.8
+ [600720] SimpleHTTP/0.6 appears to be outdated (current is at least 1.2).
+ [006230] /admin/index.html: Admin login page/section found.
+ 8143 requests: 4 errors and 9 items reported on the remote host
+ End Time:           2026-11-13 20:12:22 (GMT-6) (12 seconds)
"""


def test_parse_nmap_solo_puertos_abiertos():
    r = Nmap().parse(NMAP_XML, "", {})
    host = r["hosts"][0]
    assert host["address"] == "127.0.0.1" and host["hostname"] == "localhost"
    assert [p["port"] for p in host["open_ports"]] == [8765]
    assert host["open_ports"][0]["product"] == "SimpleHTTPServer"


def test_nmap_rechaza_flags_arbitrarios():
    n = Nmap()
    with pytest.raises(ToolError):
        n.build_command({"target": "x", "profile": "-sS --script=vuln"})
    with pytest.raises(ToolError):
        n.build_command({"target": "x", "ports": "80; rm -rf /"})
    cmd = n.build_command({"target": "10.0.0.5", "profile": "servicios", "ports": "22,80"})
    assert cmd[-2:] == ["--", "10.0.0.5"] and "-sV" in cmd


def test_parse_gobuster():
    r = Gobuster().parse(GOBUSTER_OUT, "", {})
    assert r["found"][0] == {"path": "admin", "status": 301, "size": 0, "redirect": "/admin/"}
    assert r["found"][1]["status"] == 200


def test_gobuster_target_y_validaciones():
    g = Gobuster()
    assert g.target_of({"url": "http://10.0.0.5:8080/x"}) == "10.0.0.5"
    with pytest.raises(ToolError):
        g.target_of({"url": "file:///etc/passwd"})
    with pytest.raises(ToolError):
        g.build_command({"url": "http://x", "wordlist": "/no/existe.txt"})


def test_parse_nikto_filtra_ruido():
    r = Nikto().parse(NIKTO_OUT, "", {})
    ids = [f["id"] for f in r["findings"]]
    assert ids == [None, "600720", "006230"]  # Server + 2 hallazgos; sin Target/requests/End Time


class FakeNmap(Nmap):
    """Nmap que no ejecuta nada: devuelve XML fijo."""

    def execute(self, cmd):
        self.last_cmd = cmd
        return RawResult(0, NMAP_XML, "")


class FakeGobuster(Gobuster):
    def build_command(self, args, pin=None):
        return ["gobuster", "fake"]

    def execute(self, cmd):
        return RawResult(0, GOBUSTER_OUT, "")


def make_executor(tmp_path, confirm=None):
    scope = Scope.from_entries(["127.0.0.1", "10.0.0.0/24"], lambda h: [])
    audit = AuditLog(tmp_path / "audit.log")
    tools = {t.name: t for t in (FakeNmap(), FakeGobuster())}
    kwargs = {"confirm": confirm} if confirm else {}
    return Executor(scope, audit, tools=tools, **kwargs), audit


def events(audit):
    return [json.loads(l)["event"] for l in audit.path.read_text().splitlines()]


def test_fuera_de_alcance_no_ejecuta_y_se_audita(tmp_path):
    ex, audit = make_executor(tmp_path)
    out = ex.run("nmap_scan", {"target": "8.8.8.8"})
    assert not out["ok"] and "fuera de alcance" in out["error"]
    assert events(audit) == ["denied_scope"]
    assert not hasattr(ex.tools["nmap_scan"], "last_cmd")


def test_dentro_de_alcance_ejecuta_y_audita(tmp_path):
    ex, audit = make_executor(tmp_path)
    out = ex.run("nmap_scan", {"target": "127.0.0.1"})
    assert out["ok"] and out["result"]["hosts"][0]["open_ports"][0]["port"] == 8765
    assert events(audit) == ["run", "done"]


def test_intrusiva_denegada_por_defecto(tmp_path):
    ex, audit = make_executor(tmp_path)
    out = ex.run("gobuster_dir", {"url": "http://10.0.0.5"})
    assert not out["ok"] and "no aprobada" in out["error"]
    assert events(audit) == ["confirmation"]  # nunca llegó a "run"


def test_intrusiva_aprobada_se_ejecuta(tmp_path):
    ex, audit = make_executor(tmp_path, confirm=lambda tool, target, cmd: True)
    out = ex.run("gobuster_dir", {"url": "http://10.0.0.5"})
    assert out["ok"] and len(out["result"]["found"]) == 2
    assert events(audit) == ["confirmation", "run", "done"]


def test_herramienta_desconocida_y_args_invalidos(tmp_path):
    ex, _ = make_executor(tmp_path)
    assert not ex.run("rm_rf", {})["ok"]
    assert not ex.run("nmap_scan", {})["ok"]
    assert not ex.run("nmap_scan", {"target": "127.0.0.1", "profile": "--evil"})["ok"]


def test_schemas_son_function_calling(tmp_path):
    ex, _ = make_executor(tmp_path)
    s = ex.schemas()
    assert {x["function"]["name"] for x in s} == {"nmap_scan", "gobuster_dir"}
    assert "INTRUSIVA" in [x for x in s if x["function"]["name"] == "gobuster_dir"][0]["function"]["description"]


def test_validacion_estricta_de_argumentos():
    n = Nmap()
    for bad in ({"target": "x", "inventado": 1}, {"profile": "rapido"}, {"target": "x", "profile": "nuclear"}, "texto"):
        with pytest.raises(ToolError):
            n.validate(bad)
    with pytest.raises(ToolError):
        Gobuster().validate({"url": "http://x", "threads": 99})
    with pytest.raises(ToolError):
        Gobuster().validate({"url": "http://x", "threads": "5"})
    n.validate({"target": "10.0.0.5", "profile": "servicios", "ports": "22"})


def test_nmap_completo_con_y_sin_ports():
    n = Nmap()
    assert "-p-" in n.build_command({"target": "10.0.0.5", "profile": "completo"})
    cmd = n.build_command({"target": "10.0.0.5", "profile": "completo", "ports": "8765"})
    assert "-p-" not in cmd and cmd.count("-p") == 1


def test_nmap_target_con_puerto_da_pista():
    with pytest.raises(ToolError, match="ports='8765'"):
        Nmap().target_of({"target": "127.0.0.1:8765"})
    assert Nmap().target_of({"target": "fe80::1"}) == "fe80::1"
