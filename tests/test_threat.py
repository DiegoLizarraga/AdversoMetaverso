from adverso.core.models import ShadowKind
from adverso.core.threat import evaluate


def test_reconoce_publicidad_del_registro():
    v = evaluate("pubads.g.doubleclick.net")
    assert v.kind is ShadowKind.GREEDY and v.score >= 55


def test_analitica_por_sufijo_y_subdominio():
    assert evaluate("app-measurement.com").kind is ShadowKind.WATCHER
    assert evaluate("region1.app-measurement.com").kind is ShadowKind.WATCHER


def test_infraestructura_no_dispara_alarmas():
    v = evaluate("fonts.gstatic.com")
    assert v.kind is ShadowKind.WANDERER and v.score < 25


def test_desconocido_es_anonimo():
    v = evaluate("mi-servidor-casero.net")
    assert v.kind is ShadowKind.ANONYMOUS and v.score < 45


def test_nombres_generados_por_maquina():
    v = evaluate("x7f3qz9bk2mv8p.example.com")
    assert v.kind in (ShadowKind.CORRUPT, ShadowKind.DEVOURER) and v.score >= 45


def test_fuga_de_datos_por_dns():
    v = evaluate("a" * 20 + "bcdefghijklmnopqrstuv" + ".tunnel.example.org")
    assert v.kind is ShadowKind.DEVOURER and v.score >= 60


def test_host_aleatorio_de_cdn_no_es_corrupto():
    v = evaluate("d3kq5j8m2nvx7p.cloudfront.net")
    assert v.kind is ShadowKind.WANDERER and v.score < 30


def test_puntuacion_acompana_reclasificacion():
    assert evaluate("q7x2k9zb4mvp8n.example.com").score >= 55


def test_palabras_delatoras():
    v = evaluate("telemetry.alguna-app-nueva.io")
    assert v.kind is ShadowKind.WATCHER and any("delator" in r for r in v.reasons)


def test_tld_de_riesgo_suma_sin_reclasificar():
    assert evaluate("algo.tk").score > evaluate("algo.net").score


def test_normaliza_mayusculas_y_punto_final():
    v = evaluate("Graph.FaceBook.CoM.")
    assert v.domain == "graph.facebook.com" and v.kind is ShadowKind.SEDUCER


def test_codename_estable_y_distinto():
    first = evaluate("criteo.com").codename
    assert first == evaluate("criteo.com").codename
    assert first != evaluate("taboola.com").codename
