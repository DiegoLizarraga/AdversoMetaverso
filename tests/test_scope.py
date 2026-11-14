import pytest

from adverso.scope.guard import OutOfScope, Scope

FAKE_DNS = {
    "lab.local": ["192.168.56.10"],
    "otro.com": ["8.8.8.8"],
    "mixto.net": ["192.168.56.5", "1.1.1.1"],
    "nuevo.lab": ["192.168.56.77"],
}


def resolver(host):
    return FAKE_DNS.get(host, [])


@pytest.fixture
def scope():
    return Scope.from_entries(["192.168.56.0/24", "lab.local", "*.corp.test", "10.0.0.5"], resolver)


def test_ip_dentro_y_red_contenida(scope):
    assert scope.check("192.168.56.20")
    assert scope.check("192.168.56.0/25")
    assert scope.check("10.0.0.5")


def test_ip_fuera_y_red_mayor_rechazadas(scope):
    for t in ("8.8.8.8", "192.168.0.0/16", "10.0.0.6"):
        with pytest.raises(OutOfScope):
            scope.check(t)


def test_host_autorizado_por_nombre_y_comodin(scope):
    assert scope.check("LAB.local.") == ["192.168.56.10"]
    scope.check("api.corp.test")


def test_host_no_listado_solo_si_todas_sus_ip_caen_dentro(scope):
    assert scope.check("nuevo.lab") == ["192.168.56.77"]
    with pytest.raises(OutOfScope):
        scope.check("mixto.net")
    with pytest.raises(OutOfScope):
        scope.check("otro.com")


def test_no_resuelve_y_no_autorizado(scope):
    with pytest.raises(OutOfScope):
        scope.check("fantasma.example")


def test_inyeccion_de_flags_y_espacios(scope):
    for t in ("-iL /etc/passwd", "--script=x", "", "192.168.56.1 8.8.8.8"):
        with pytest.raises(OutOfScope):
            scope.check(t)


def test_comodin_no_cubre_dominio_parecido(scope):
    with pytest.raises(OutOfScope):
        scope.check("evilcorp.test")
