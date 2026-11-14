import json

from adverso.agents.base import Agent, extract_json
from adverso.scope.audit import AuditLog
from adverso.scope.guard import Scope
from adverso.tools.base import RawResult
from adverso.tools.executor import Executor
from adverso.tools.nmap import Nmap

XML = """<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>"""


class FakeNmap(Nmap):
    calls = 0

    def execute(self, cmd):
        FakeNmap.calls += 1
        return RawResult(0, XML, "")


class ScriptedClient:
    """Modelo de pega: devuelve mensajes predefinidos y guarda lo que recibe."""

    def __init__(self, script, native=True):
        self.script, self.native_tools, self.seen = list(script), native, []

    def chat(self, messages, tools):
        self.seen.append((list(messages), tools))
        return self.script.pop(0)


def call(name, args):
    return {"content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}


def make(tmp_path, client, **kw):
    FakeNmap.calls = 0
    ex = Executor(Scope.from_entries(["10.0.0.0/24"], lambda h: []), AuditLog(tmp_path / "a.log"),
                  tools={"nmap_scan": FakeNmap()})
    return Agent(client, ex, **kw)


def test_modo_nativo_herramienta_y_final(tmp_path):
    c = ScriptedClient([call("nmap_scan", {"target": "10.0.0.5"}), {"content": "Puerto 22 abierto."}])
    r = make(tmp_path, c).run("reconoce 10.0.0.5")
    assert r.completed and r.final == "Puerto 22 abierto." and FakeNmap.calls == 1
    tool_msg = c.seen[1][0][-1]
    assert tool_msg["role"] == "tool" and '"port": 22' in tool_msg["content"]
    assert c.seen[0][1]  # recibió los esquemas de herramientas


def test_agente_no_puede_salirse_del_alcance(tmp_path):
    c = ScriptedClient([call("nmap_scan", {"target": "8.8.8.8"}), {"content": "No pude."}])
    r = make(tmp_path, c).run("escanea 8.8.8.8")
    assert FakeNmap.calls == 0
    denied = [e for e in r.events if e.kind == "tool_result"][0]
    assert not denied.data["ok"] and "fuera de alcance" in denied.data["result"]["error"]


def test_llamada_repetida_se_bloquea(tmp_path):
    same = call("nmap_scan", {"target": "10.0.0.5"})
    c = ScriptedClient([same, same, {"content": "fin"}])
    make(tmp_path, c).run("x")
    assert FakeNmap.calls == 1


def test_modo_texto_json_para_modelos_sin_tools(tmp_path):
    c = ScriptedClient([
        {"content": 'Voy a escanear.\n```json\n{"tool": "nmap_scan", "args": {"target": "10.0.0.5"}}\n```'},
        {"content": '{"final": "SSH en 10.0.0.5"}'},
    ], native=False)
    r = make(tmp_path, c).run("reconoce")
    assert r.completed and r.final == "SSH en 10.0.0.5" and FakeNmap.calls == 1
    assert c.seen[0][1] is None and "nmap_scan" in c.seen[0][0][0]["content"]


def test_modo_texto_reintenta_si_no_es_json(tmp_path):
    c = ScriptedClient([{"content": "hola, no sé"}, {"content": '{"final": "ok"}'}], native=False)
    r = make(tmp_path, c).run("x")
    assert r.completed and r.final == "ok" and r.steps == 2


def test_limite_de_pasos(tmp_path):
    calls = [call("nmap_scan", {"target": "10.0.0.5", "ports": str(p)}) for p in range(1, 6)]
    r = make(tmp_path, ScriptedClient(calls), max_steps=3).run("x")
    assert not r.completed and r.steps == 3


def test_error_del_modelo_no_rompe(tmp_path):
    class Boom:
        native_tools = True

        def chat(self, m, t):
            raise RuntimeError("ollama caído")

    r = make(tmp_path, Boom()).run("x")
    assert not r.completed and "ollama caído" in r.final


def test_extract_json_tolerante():
    assert extract_json('<think>{"a":1}</think> texto {"tool":"x","args":{"k":"}"}} fin') == {"tool": "x", "args": {"k": "}"}}
    assert extract_json("sin json") is None
    assert extract_json('{"roto": ') is None
