# AdversoMetaverso

> No tengo idea de la cognición humana.

Una app de Android que convierte el tráfico de red de tu teléfono en un Palacio
al estilo del Metaverso de *Persona 5*. Cada app que habla con internet es un
**Palacio** gobernado por un deseo distorsionado; cada dominio con el que habla
es una **Sombra**; bloquear un rastreador es **robarle el corazón**.

Debajo del disfraz es un monitor de red y un bloqueador DNS de verdad.

---

## El mapa: metáfora ↔ realidad

| En el Metaverso | En la máquina |
| --- | --- |
| **Navegador del Metaverso** | El `VpnService` local que captura el tráfico |
| **Infiltrar / Salir** | Levantar y cerrar el túnel |
| **Palacio** | Una app (UID) que hace peticiones de red |
| **Deseo distorsionado** | La categoría dominante de lo que esa app filtra: avaricia (publicidad), vigilancia (analítica), vanidad (social)… |
| **Rango del Palacio** (Guarida → Crucero) | Puntuación de amenaza acumulada de la app |
| **Sombra** | Un dominio concreto, con su nombre propio estable |
| **Tipo de Sombra** | Clasificación: codiciosa, vigilante, seductora, corrupta, devoradora, errante, anónima |
| **Robar el corazón / Tesoro confiscado** | Bloquear el dominio devolviendo una dirección nula |
| **Pacto sellado** | Lista blanca: nunca bloquear este dominio |
| **Mementos** | El flujo en vivo de consultas |
| **Códice de Sombras** | El catálogo completo de dominios vistos, editable |
| **Nivel de alerta** | Índice 0–100 del estado de la red ahora mismo |
| **Tarjeta de presentación** | El informe legible de un Palacio, compartible |

---

## Cómo captura el tráfico (y por qué así)

La decisión técnica central del proyecto.

Capturar **todo** el tráfico con un `VpnService` obliga a reimplementar TCP/IP en
espacio de usuario: reensamblado, ventanas, retransmisiones, handshakes. Son
semanas de trabajo y, si ese código tiene un fallo, el teléfono se queda sin
internet.

En su lugar el túnel **anuncia un resolutor DNS propio** (`10.111.222.2`) y
enruta **únicamente esa dirección**. Todo el demás tráfico sale por la red normal,
intacto. A cambio se ve:

- cada nombre de dominio que resuelve el dispositivo,
- **qué app lo pidió** (vía `getConnectionOwnerUid`, Android 10+),
- la latencia de cada consulta y las IPs que devolvió,
- y se puede cortar de raíz devolviendo `0.0.0.0` / `::`.

Es la misma técnica que usan los bloqueadores DNS reales. Riesgo de romper la
conectividad: prácticamente nulo. Cobertura: el *con quién habla* el teléfono,
que es donde está casi toda la información interesante.

```text
app ──consulta DNS──▶ tun0 ──▶ NavigatorVpnService
                                    │
                            ¿pasa el umbral?
                          ┌─────────┴─────────┐
                       sí │                   │ no
                  respuesta nula      socket protegido ──▶ 1.1.1.1
                          │                   │
                          └────▶ tun0 ◀────────┘
```

El resto del tráfico nunca entra al túnel.

### Lo que este enfoque **no** ve

Está documentado a propósito, no es un descuido:

- **DNS privado (DoT/DoH)** del sistema: si está activo, las consultas van
  cifradas a otro resolutor y el Navegador queda ciego. La app lo detecta al
  arrancar el túnel y te avisa.
- **Apps con su propio resolutor codificado** (8.8.8.8 y compañía). Para eso
  existe el *modo agresivo*, que además desvía los resolutores públicos más
  comunes. Está **apagado por defecto** porque rompe DoT hacia esas mismas IPs.
- **IPv6**: el túnel es IPv4. Las consultas por IPv6 pasan de largo.
- **Contenido**: se ven nombres, no cargas útiles. Es un mapa de contactos, no un
  interceptor.
- **Conexiones por IP directa** sin resolver nombre.

El consumo real de bytes por app **sí** se mide, pero por otra vía:
`NetworkStatsManager`, que necesita el permiso especial de *Acceso al uso*. El
DNS dice con quién habla una app; esto dice cuánto le cuenta.

---

## El motor de amenazas

`ThreatEngine` clasifica en dos capas:

1. **Registro conocido** (~100 reglas por sufijo): redes de publicidad,
   atribución de instalaciones, analítica, grabación de sesión, brokers de datos,
   e infraestructura inocua (CDNs, nubes, NTP).
2. **Heurística**, que atrapa lo que ningún registro conoce:
   - entropía de Shannon sobre la etiqueta más larga → dominios generados por
     máquina (DGA),
   - etiquetas enormes → patrón de fuga de datos por DNS,
   - TLDs quemados, punycode, cadenas largas de subdominios,
   - palabras delatoras (`telemetry`, `pixel`, `beacon`…).

Dos detalles que importan y están cubiertos por tests:

- **La puntuación acompaña a la reclasificación.** Si la heurística sube algo a
  Sombra Corrupta, la puntuación sube con ella — es la puntuación la que decide
  el bloqueo, así que etiquetar sin puntuar sería un bloqueo que nunca ocurre.
- **La infraestructura conocida está exenta de la heurística de aleatoriedad.**
  Los CDN generan nombres tipo `d3kq5j8m2n.cloudfront.net` por diseño; sin esta
  excepción, medio internet saldría como amenaza.

---

## Estado actual

**Funciona:**

- Túnel DNS con parseo IPv4/UDP/DNS propio y reenvío por socket protegido
- Atribución de cada consulta a la app dueña del socket
- Bloqueo por sinkhole con umbral configurable (implacable / equilibrado / prudente)
- Listas manuales por dominio: robar corazón y sellar pacto, persistentes
- Bytes enviados/recibidos por app en el día
- Cuatro pantallas: Nav, Palacios, Mementos, Códice + detalle de Palacio
- Tarjeta de presentación generada y compartible
- Aviso automático si el DNS privado deja al Navegador ciego
- 23 tests unitarios sobre el parseo DNS, la construcción de paquetes y el motor

**Verificado:** compila sin avisos, los 23 tests pasan, instala y arranca en
emulador, la UI completa se renderiza, sin ANR, ~3% de frames con jank.

**Sin verificar en ejecución:** el túnel en vivo. Requiere pulsar *INFILTRAR* y
aceptar el diálogo de VPN del sistema a mano.

---

## Siguientes pasos

Por orden de valor:

1. **Persistencia real** (Room). Ahora los agregados viven en memoria y se
   pierden al morir el proceso. Sin esto no hay historia ni "día a día" de verdad.
2. **Calendario**, con la estética del planificador del juego: un día por casilla,
   su nivel de alerta y su resumen.
3. **Una fuente condensada** en `res/font`. Es la mejora visual más grande y más
   barata que le queda: la tipografía de sistema en negra cursiva solo insinúa el
   estilo de Persona 5.
4. **Listas de bloqueo descargables** y actualizables, en vez de las reglas
   incrustadas.
5. **Captura completa de TCP** con extracción de SNI, para ver los destinos que
   no pasan por DNS. Es el salto grande de complejidad.
6. **Sonido y transiciones** de la serie: el "¡Alerta!" cuando aparece una Sombra
   corrupta.

---

## Compilar

Requiere Android Studio 2026.1 o superior (AGP 9.3, Gradle 9.5, SDK 36).

```bash
./gradlew assembleDebug        # APK de depuración
./gradlew testDebugUnitTest    # los 23 tests
```

`local.properties` no está en el repositorio; Android Studio lo genera al abrir
el proyecto.

### Permisos que pide la app

| Permiso | Para qué | Cómo se concede |
| --- | --- | --- |
| `BIND_VPN_SERVICE` | El túnel | Diálogo del sistema al infiltrar |
| `PACKAGE_USAGE_STATS` | Bytes por app | A mano en Ajustes; la app te lleva |
| `QUERY_ALL_PACKAGES` | Poner nombre a los UID | En el manifiesto |
| `POST_NOTIFICATIONS` | Notificación del túnel | Diálogo al abrir |

---

## Estructura

```text
core/
  model/     Sombras, Palacios, rangos, niveles de alerta
  net/       Packets (IPv4/UDP), Dns (RFC 1035 mínimo)
  threat/    ThreatEngine: registro + heurística
  vpn/       NavigatorVpnService: el túnel
  stats/     TrafficLedger: bytes por app
  Metaverse  estado compartido entre servicio y UI
  NavSettings ajustes y listas manuales
ui/
  theme/     paleta, tipografía, siluetas cortadas y rasgadas
  components/ fondo animado, medidor, insignias, paneles
  screens/   Nav · Palacios · detalle · Mementos · Códice
```

`Metaverse` publica instantáneas inmutables cada 250 ms en lugar de emitir por
cada consulta: el túnel escribe a mucha velocidad y la UI tiene que recomponer a
un ritmo humano.
