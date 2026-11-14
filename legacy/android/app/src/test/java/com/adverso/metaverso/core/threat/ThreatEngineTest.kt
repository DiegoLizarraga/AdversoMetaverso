package com.adverso.metaverso.core.threat

import com.adverso.metaverso.core.model.ShadowKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatEngineTest {

    @Test
    fun `reconoce las redes de publicidad del registro`() {
        val verdict = ThreatEngine.evaluate("pubads.g.doubleclick.net")
        assertEquals(ShadowKind.GREEDY, verdict.kind)
        assertTrue(verdict.score >= 55)
    }

    @Test
    fun `reconoce la analitica por sufijo exacto y por subdominio`() {
        assertEquals(ShadowKind.WATCHER, ThreatEngine.evaluate("app-measurement.com").kind)
        assertEquals(ShadowKind.WATCHER, ThreatEngine.evaluate("region1.app-measurement.com").kind)
    }

    @Test
    fun `la infraestructura no dispara alarmas`() {
        val verdict = ThreatEngine.evaluate("fonts.gstatic.com")
        assertEquals(ShadowKind.WANDERER, verdict.kind)
        assertTrue("La infraestructura debe puntuar bajo", verdict.score < 25)
    }

    @Test
    fun `un dominio desconocido queda como anonimo, no como amenaza`() {
        val verdict = ThreatEngine.evaluate("mi-servidor-casero.net")
        assertEquals(ShadowKind.ANONYMOUS, verdict.kind)
        assertTrue(verdict.score < 45)
    }

    @Test
    fun `detecta nombres generados por maquina`() {
        val verdict = ThreatEngine.evaluate("x7f3qz9bk2mv8p.example.com")
        assertTrue(
            "Un nombre aleatorio debe escalar a corrupta: ${verdict.kind}",
            verdict.kind == ShadowKind.CORRUPT || verdict.kind == ShadowKind.DEVOURER,
        )
        assertTrue(verdict.score >= 45)
    }

    @Test
    fun `detecta fuga de datos por DNS`() {
        val leak = "a".repeat(20) + "bcdefghijklmnopqrstuv" + ".tunnel.example.org"
        val verdict = ThreatEngine.evaluate(leak)
        assertEquals(ShadowKind.DEVOURER, verdict.kind)
        assertTrue(verdict.score >= 60)
    }

    @Test
    fun `un host aleatorio de CDN no se marca como corrupto`() {
        // Los CDN generan nombres así por diseño; tratarlos como DGA convertiría
        // media internet en amenaza.
        val verdict = ThreatEngine.evaluate("d3kq5j8m2nvx7p.cloudfront.net")
        assertEquals(ShadowKind.WANDERER, verdict.kind)
        assertTrue("Debe seguir puntuando bajo: ${verdict.score}", verdict.score < 30)
    }

    @Test
    fun `la puntuacion acompana a la reclasificacion`() {
        // Si la heurística escala el tipo, el score tiene que subir con él: es lo
        // que decide el bloqueo.
        val verdict = ThreatEngine.evaluate("q7x2k9zb4mvp8n.example.com")
        assertTrue(
            "Una sombra corrupta debe superar el umbral por defecto: ${verdict.score}",
            verdict.score >= 55,
        )
    }

    @Test
    fun `las palabras delatoras clasifican lo que el registro no conoce`() {
        val verdict = ThreatEngine.evaluate("telemetry.alguna-app-nueva.io")
        assertEquals(ShadowKind.WATCHER, verdict.kind)
        assertTrue(verdict.reasons.any { it.contains("delator") })
    }

    @Test
    fun `el TLD de riesgo suma pero no reclasifica`() {
        val plain = ThreatEngine.evaluate("algo.net")
        val risky = ThreatEngine.evaluate("algo.tk")
        assertTrue(risky.score > plain.score)
    }

    @Test
    fun `normaliza mayusculas y el punto final absoluto`() {
        val a = ThreatEngine.evaluate("Graph.FaceBook.CoM.")
        assertEquals("graph.facebook.com", a.domain)
        assertEquals(ShadowKind.SEDUCER, a.kind)
    }

    @Test
    fun `el nombre de la sombra es estable y distingue dominios`() {
        val first = ThreatEngine.evaluate("criteo.com").codename
        assertEquals(first, ThreatEngine.evaluate("criteo.com").codename)
        assertNotEquals(first, ThreatEngine.evaluate("taboola.com").codename)
    }
}
