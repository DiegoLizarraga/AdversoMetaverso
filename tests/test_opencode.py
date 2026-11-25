import json
import shutil

import pytest

from adverso.agents.opencode import AGENT_NAME, OpencodeAgent
from adverso.core.store import Store

from fake_llm import FINAL_PREFIX, FakeLLM


def make(tmp_path, model="ollama/qwen3:8b", url="http://ollama:11434", confirm=None, **kw):
    scope = tmp_path / "scope.toml"
    scope.write_text('[scope]\ntargets = ["127.0.0.0/8"]\n')
    return OpencodeAgent(model=model, ollama_url=url, scope_path=str(scope), audit_path=str(tmp_path / "a.log"),
                         state_path=str(tmp_path / "s.json"), confirm=confirm or (lambda *a: False), **kw)


def test_configuracion_solo_nuestras_herramientas(tmp_path):
    cfg = make(tmp_path, max_steps=4).config("/tmp/x/bridge.sock")
    agent = cfg["agent"][AGENT_NAME]
    # el orden importa: gana la última regla que coincide
    assert list(agent["permission"].items()) == [("*", "deny"), ("adverso_*", "allow")]
    assert agent["steps"] == 4 and agent["model"] == "ollama/qwen3:8b" and "Metaverso" in agent["prompt"]
    cmd = cfg["mcp"]["adverso"]["command"]
    assert cmd[1:4] == ["-m", "adverso", "mcp"] and cmd[cmd.index("--bridge") + 1] == "/tmp/x/bridge.sock"
    assert cmd[cmd.index("--max-calls") + 1] == "12"
    assert cmd[cmd.index("--scope") + 1] == str((tmp_path / "scope.toml").resolve())
    opts = cfg["provider"]["ollama"]["options"]
    assert opts["baseURL"] == "http://ollama:11434/v1" and opts["headerTimeout"] == opts["chunkTimeout"] == 600_000
    assert cfg["autoupdate"] is False and cfg["share"] == "disabled"
    assert cfg["mcp"]["adverso"]["timeout"] >= 30_000


def test_causa_del_fallo_en_los_registros():
    stderr = ('timestamp=x level=ERROR message="stream error" error.error="ProviderHeaderTimeoutError: '
              'Provider response headers timed out after 300000ms"\nlevel=INFO otra cosa\n')
    assert OpencodeAgent.log_error(stderr) == "ProviderHeaderTimeoutError: Provider response headers timed out after 300000ms"
    assert OpencodeAgent.log_error("nada") is None


def test_otros_proveedores_no_se_redefinen(tmp_path):
    assert "provider" not in make(tmp_path, model="openrouter/qwen/qwen3-8b").config("s")


def test_parse_eventos():
    out = "\n".join(json.dumps(e) for e in [
        {"type": "step_start", "part": {"messageID": "m1"}},
        {"type": "text", "part": {"messageID": "m1", "text": "voy a escanear"}},
        {"type": "tool_use", "part": {"tool": "adverso_nmap_scan", "messageID": "m1"}},
        {"type": "text", "part": {"messageID": "m2", "text": "<think>x</think>Informe: "}},
        {"type": "text", "part": {"messageID": "m2", "text": "22/tcp abierto"}},
    ]) + "\nbasura que no es json\n"
    assert OpencodeAgent.parse_output(out) == ("Informe: 22/tcp abierto", None)
    err = json.dumps({"type": "error", "error": {"name": "APIError", "data": {"message": "ECONNREFUSED"}}})
    assert OpencodeAgent.parse_output(err) == ("", "ECONNREFUSED")


def test_sin_opencode_instalado(tmp_path):
    r = make(tmp_path, opencode_bin="/no/existe/opencode").run("x")
    assert not r.completed and "no está instalado" in r.final


needs_opencode = pytest.mark.skipif(shutil.which("opencode") is None, reason="opencode no instalado")


@needs_opencode
def test_opencode_real_fuera_de_alcance(tmp_path, monkeypatch):
    """opencode de verdad + modelo falso: la llamada pasa por NUESTRO Executor."""
    # Lanzado desde un shell en un proyecto con su propio opencode.json: opencode mira
    # $PWD, no el cwd del proceso. Ese opencode.json no debe usarse nunca.
    other = tmp_path / "proyecto_del_usuario"
    other.mkdir()
    (other / "opencode.json").write_text(json.dumps({"agent": {"metaverso": {"permission": {"*": "allow"}}}}))
    monkeypatch.setenv("PWD", str(other))
    seen = []
    with FakeLLM("nmap_scan", {"target": "8.8.8.8"}) as llm:
        agent = make(tmp_path, model="ollama/falso", url=llm.url, on_event=seen.append, timeout=120)
        r = agent.run("reconoce 8.8.8.8")
        assert r.completed, r.final
        tools_offered = {t["function"]["name"] for t in llm.requests[0]["tools"]}
        system = llm.requests[0]["messages"][0]["content"]
    assert r.completed and r.final.startswith(FINAL_PREFIX) and "fuera de alcance" in r.final
    # solo nuestras herramientas, ninguna de opencode (bash, read, edit, webfetch…)
    assert tools_offered == {"adverso_dns_lookup", "adverso_gobuster_dir", "adverso_harvest_domain", "adverso_nikto_scan",
                             "adverso_nmap_scan", "adverso_whatweb_fingerprint", "adverso_whois_lookup"}
    assert "navegador del Metaverso" in system and "<datos_no_confiables>" in system
    assert llm.requests[0]["messages"][1] == {"role": "user", "content": "reconoce 8.8.8.8"}
    kinds = [e.kind for e in seen]
    assert kinds == ["tool_call", "tool_result", "final"] and r.steps == 1
    assert seen[1].data["ok"] is False
    assert "denied_scope" in (tmp_path / "a.log").read_text()


@needs_opencode
def test_opencode_real_aprobacion_vuelve_al_operador(tmp_path):
    """La herramienta intrusiva pide permiso al proceso padre por el socket, y se respeta el no."""
    asked = []

    def confirm(tool, target, cmd):
        asked.append((tool.name, target, cmd[0]))
        return False

    store = Store(tmp_path / "s.json")
    with FakeLLM("nikto_scan", {"url": "http://127.0.0.1:9"}) as llm:
        r = make(tmp_path, model="ollama/falso", url=llm.url, confirm=confirm, store=store, timeout=120).run("audita")
    assert r.completed, r.final
    assert asked == [("nikto_scan", "127.0.0.1", "nikto")]
    assert r.completed and "no aprobada" in r.final
    log = [json.loads(line) for line in (tmp_path / "a.log").read_text().splitlines()]
    assert log[-1]["event"] == "confirmation" and log[-1]["approved"] is False
    assert not any(e["event"] == "run" for e in log)
