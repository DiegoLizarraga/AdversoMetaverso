import json
import multiprocessing as mp

from adverso.core.store import Store


def _writer(path: str, who: str, n: int) -> None:
    s = Store(path)
    for i in range(n):
        with s.transaction():
            s.palaces[f"{who}-{i}"] = {"ip": f"{who}-{i}", "names": [], "findings": {}}


def test_escritores_concurrentes_no_pierden_nada(tmp_path):
    """Varios procesos a la vez (agente, MCP, monitor): ninguna escritura se pisa."""
    path = str(tmp_path / "s.json")
    procs = [mp.Process(target=_writer, args=(path, w, 25)) for w in ("a", "b", "c", "d")]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert all(p.exitcode == 0 for p in procs)
    assert len(Store(path).palaces) == 100


def test_transaccion_ve_datos_frescos_y_respeta_borrados(tmp_path):
    a, b = Store(tmp_path / "s.json"), Store(tmp_path / "s.json")
    with a.transaction():
        a.palaces["x"] = {"ip": "x"}
        a.palaces["y"] = {"ip": "y"}
    with b.transaction():  # b no había visto nada: la transacción relee
        assert set(b.palaces) == {"x", "y"}
        del b.palaces["x"]
    with a.transaction():  # a tenía "x" en memoria, pero no lo resucita
        a.palaces["z"] = {"ip": "z"}
    assert set(json.loads((tmp_path / "s.json").read_text())["palaces"]) == {"y", "z"}


def test_error_en_transaccion_no_escribe(tmp_path):
    s = Store(tmp_path / "s.json")
    with s.transaction():
        s.palaces["ok"] = {}
    try:
        with s.transaction():
            s.palaces["a_medias"] = {}
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert set(Store(tmp_path / "s.json").palaces) == {"ok"}


def test_reentrante_y_mtime(tmp_path):
    s = Store(tmp_path / "s.json")
    assert s.mtime() == 0.0
    with s.transaction():
        with s.transaction():
            s.palaces["n"] = {}
    assert "n" in Store(tmp_path / "s.json").palaces and s.mtime() > 0


def test_archivo_corrupto_se_aparta(tmp_path):
    (tmp_path / "s.json").write_text("{no es json")
    s = Store(tmp_path / "s.json")
    assert s.palaces == {} and list(tmp_path.glob("s.json.corrupto-*"))
