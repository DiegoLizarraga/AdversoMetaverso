import json
import subprocess
import sys
from pathlib import Path

from adverso.mcp.bridge import BridgeClient, BridgeServer
from adverso.mcp.server import McpServer
from adverso.scope.audit import AuditLog
from adverso.scope.guard import Scope
from adverso.tools.base import RawResult, Tool
from adverso.tools.executor import Executor

from test_agent import FakeNmap

ROOT = Path(__file__).resolve().parent.parent


class Golpe(Tool):
    """Herramienta intrusiva de pega."""

    name = "golpe"
    intrusive = True
    description = "prueba"
    parameters = {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}
    ran: list = []

    def target_of(self, a):
        return a["target"]

    def build_command(self, a, pin=None):
        return ["golpe", a["target"]]

    def execute(self, cmd):
        Golpe.ran.append(cmd)
        return RawResult(0, "hecho", "")

    def parse(self, out, err, a):
        return {"salida": out}


def rpc(server, method, params=None, id_=1):
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return server.handle(msg)


def make(tmp_path, confirm=None, **kw):
    FakeNmap.calls = 0
    Golpe.ran = []
    ex = Executor(Scope.from_entries(["10.0.0.0/24"], lambda h: []), AuditLog(tmp_path / "a.log"),
                  tools={"nmap_scan": FakeNmap(), "golpe": Golpe()}, **({"confirm": confirm} if confirm else {}))
    return McpServer(ex, **kw)


def test_handshake_y_listado(tmp_path):
    s = make(tmp_path)
    init = rpc(s, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}})
    assert init["result"]["protocolVersion"] == "2025-06-18" and "tools" in init["result"]["capabilities"]
    assert rpc(s, "initialize", {"protocolVersion": "1999-01-01"})["result"]["protocolVersion"] == "2025-11-25"
    assert s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    tools = {t["name"]: t for t in rpc(s, "tools/list")["result"]["tools"]}
    assert tools["nmap_scan"]["inputSchema"]["type"] == "object"
    assert "INTRUSIVA" in tools["golpe"]["description"]
    assert rpc(s, "ping")["result"] == {}
    assert rpc(s, "recursos/raros")["error"]["code"] == -32601
    assert s.handle({"id": 3, "method": "ping"})["error"]["code"] == -32600  # falta jsonrpc


def test_llamada_dentro_y_fuera_de_alcance(tmp_path):
    s = make(tmp_path)
    ok = rpc(s, "tools/call", {"name": "nmap_scan", "arguments": {"target": "10.0.0.5"}})["result"]
    assert ok["isError"] is False and FakeNmap.calls == 1
    assert ok["content"][0]["text"].startswith("<datos_no_confiables>")
    out = rpc(s, "tools/call", {"name": "nmap_scan", "arguments": {"target": "8.8.8.8"}})["result"]
    assert out["isError"] and "fuera de alcance" in out["content"][0]["text"] and FakeNmap.calls == 1


def test_repetidas_y_presupuesto(tmp_path):
    s = make(tmp_path, max_calls=2)
    args = {"name": "nmap_scan", "arguments": {"target": "10.0.0.5"}}
    rpc(s, "tools/call", args)
    assert "repetida" in rpc(s, "tools/call", args)["result"]["content"][0]["text"]
    rpc(s, "tools/call", {"name": "nmap_scan", "arguments": {"target": "10.0.0.6"}})
    over = rpc(s, "tools/call", {"name": "nmap_scan", "arguments": {"target": "10.0.0.7"}})["result"]
    assert "límite" in over["content"][0]["text"] and FakeNmap.calls == 2


def test_intrusiva_sin_canal_se_deniega(tmp_path):
    s = make(tmp_path)
    r = rpc(s, "tools/call", {"name": "golpe", "arguments": {"target": "10.0.0.5"}})["result"]
    assert r["isError"] and "no aprobada" in r["content"][0]["text"] and not Golpe.ran


def test_canal_con_el_padre_aprueba_y_recibe_eventos(tmp_path):
    asked, events = [], []

    def confirm(tool, target, cmd):
        asked.append((tool, target, cmd))
        return target == "10.0.0.5"

    sock = tmp_path / "b.sock"
    with BridgeServer(sock, lambda kind, data: events.append((kind, data)), confirm):
        client = BridgeClient(str(sock))
        s = make(tmp_path, confirm=client.confirm, on_event=client.event)
        yes = rpc(s, "tools/call", {"name": "golpe", "arguments": {"target": "10.0.0.5"}})["result"]
        no = rpc(s, "tools/call", {"name": "golpe", "arguments": {"target": "10.0.0.6"}})["result"]
    assert not yes["isError"] and no["isError"] and Golpe.ran == [["golpe", "10.0.0.5"]]
    assert asked[0] == ("golpe", "10.0.0.5", ["golpe", "10.0.0.5"])
    assert [k for k, _ in events] == ["tool_call", "tool_result", "tool_call", "tool_result"]
    assert events[1][1]["ok"] is True and events[3][1]["ok"] is False
    assert not sock.exists()


def test_canal_caido_deniega(tmp_path):
    assert BridgeClient(str(tmp_path / "no-existe.sock")).confirm(Golpe(), "10.0.0.5", ["golpe"]) is False
    BridgeClient(str(tmp_path / "no-existe.sock")).event("tool_call", name="x")  # no lanza


def test_servidor_stdio_real(tmp_path):
    """`python -m adverso mcp` de punta a punta por stdin/stdout (sin tocar la red)."""
    scope = tmp_path / "scope.toml"
    scope.write_text('[scope]\ntargets = ["10.0.0.0/24"]\n')
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "nmap_scan", "arguments": {"target": "8.8.8.8"}}},
    ]
    stdin = "\n".join(json.dumps(m) for m in msgs) + "\nesto no es json\n"
    p = subprocess.run([sys.executable, "-m", "adverso", "mcp", "--scope", str(scope), "--audit", str(tmp_path / "a.log"),
                        "--state", str(tmp_path / "s.json")], input=stdin, capture_output=True, text=True, cwd=ROOT, timeout=30)
    replies = [json.loads(line) for line in p.stdout.splitlines()]
    assert [r.get("id") for r in replies] == [1, 2, 3, None]  # nada más que protocolo en stdout
    assert {t["name"] for t in replies[1]["result"]["tools"]} >= {"nmap_scan", "dns_lookup", "gobuster_dir"}
    assert replies[2]["result"]["isError"] and "fuera de alcance" in replies[2]["result"]["content"][0]["text"]
    assert replies[3]["error"]["code"] == -32700
    assert "denied_scope" in (tmp_path / "a.log").read_text()
