import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from adverso.agents.base import Agent
from adverso.agents.ollama import _to_ollama
from adverso.agents.openai_compat import OpenAICompatClient
from adverso.scope.audit import AuditLog
from adverso.scope.guard import Scope
from adverso.tools.executor import Executor

from test_agent import FakeNmap


@pytest.fixture
def fake_api():
    """Servidor /v1 de pega: responde lo que se le encola y guarda cada petición."""
    seen, replies = [], []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
            data = json.dumps(replies.pop(0)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/v1", seen, replies
    srv.shutdown()


def reply(content=None, calls=None):
    return {"choices": [{"message": {"role": "assistant", "content": content, "tool_calls": calls}}]}


def test_bucle_completo_con_api_openai(tmp_path, fake_api, monkeypatch):
    url, seen, replies = fake_api
    replies += [
        reply(calls=[{"id": "c1", "type": "function",
                      "function": {"name": "nmap_scan", "arguments": '{"target": "10.0.0.5"}'}}]),
        reply("<think>bien</think>SSH abierto en 10.0.0.5."),
    ]
    monkeypatch.setenv("CLAVE_TEST", "secreta")
    client = OpenAICompatClient.from_env("modelo-x", url, "CLAVE_TEST")
    FakeNmap.calls = 0
    ex = Executor(Scope.from_entries(["10.0.0.0/24"], lambda h: []), AuditLog(tmp_path / "a.log"),
                  tools={"nmap_scan": FakeNmap()})
    r = Agent(client, ex).run("reconoce 10.0.0.5")

    assert r.completed and r.final == "SSH abierto en 10.0.0.5." and FakeNmap.calls == 1
    assert seen[0]["path"] == "/v1/chat/completions" and seen[0]["auth"] == "Bearer secreta"
    assert seen[0]["body"]["tools"][0]["function"]["name"] == "nmap_scan"
    second = seen[1]["body"]["messages"]
    asst, tool = second[-2], second[-1]
    # el formato OpenAI exige argumentos como texto y el resultado enlazado por id
    assert asst["tool_calls"][0] == {"id": "c1", "type": "function",
                                     "function": {"name": "nmap_scan", "arguments": '{"target": "10.0.0.5"}'}}
    assert tool == {"role": "tool", "tool_call_id": "c1", "content": tool["content"]}
    assert "<datos_no_confiables>" in tool["content"]


def test_sin_clave_no_hay_cabecera(fake_api, monkeypatch):
    url, seen, replies = fake_api
    replies.append(reply("hola"))
    monkeypatch.delenv("ADVERSO_API_KEY", raising=False)
    msg = OpenAICompatClient.from_env("m", url).chat([{"role": "user", "content": "x"}], None)
    assert msg == {"content": "hola", "tool_calls": []}
    assert seen[0]["auth"] is None and "tools" not in seen[0]["body"]


def test_error_de_red_legible():
    with pytest.raises(RuntimeError, match="no se pudo hablar"):
        OpenAICompatClient("m", "http://127.0.0.1:9/v1", timeout=2).chat([], None)


def test_mas_de_tres_llamadas_solo_constan_las_ejecutadas(tmp_path):
    many = [{"id": f"c{i}", "function": {"name": "nmap_scan", "arguments": {"target": "10.0.0.5", "ports": str(i)}}}
            for i in range(5)]

    class C:
        native_tools = True

        def __init__(self):
            self.seen = []
            self.script = [{"content": "", "tool_calls": many}, {"content": "fin"}]

        def chat(self, messages, tools):
            self.seen.append(list(messages))
            return self.script.pop(0)

    c = C()
    FakeNmap.calls = 0
    ex = Executor(Scope.from_entries(["10.0.0.0/24"], lambda h: []), AuditLog(tmp_path / "a.log"),
                  tools={"nmap_scan": FakeNmap()})
    Agent(c, ex).run("x")
    asst = c.seen[1][2]
    tool_ids = [m["tool_call_id"] for m in c.seen[1] if m["role"] == "tool"]
    assert [tc["id"] for tc in asst["tool_calls"]] == tool_ids == ["c0", "c1", "c2"]


def test_traduccion_a_ollama():
    m = {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "function": {"name": "n", "arguments": {"a": 1}}}]}
    assert _to_ollama(m) == {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "n", "arguments": {"a": 1}}}]}
    t = {"role": "tool", "tool_call_id": "c1", "tool_name": "n", "content": "r"}
    assert _to_ollama(t) == {"role": "tool", "tool_name": "n", "content": "r"}
