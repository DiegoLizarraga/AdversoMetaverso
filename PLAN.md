# Plan de trabajo — AdversoMetaverso para Linux (Debian/Kali)

La app Android queda archivada en `legacy/android/`. El proyecto pasa a ser una
herramienta de terminal en **Python** operada por **agentes** (modelo local y
opencode; Claude más adelante) que usan las herramientas de Kali, con la
metáfora de Persona 5: Palacio = host/servicio, Sombra = dominio/hallazgo.

## Decisiones
- Lenguaje: Python ≥ 3.11, TUI con Textual.
- Uso ofensivo: **scope y confirmación**. Lista de objetivos autorizados,
  confirmación humana para acciones intrusivas (hydra, sqlmap, metasploit) y
  registro de auditoría.
- Monitor de red local: incluido como módulo (fase 4).
- Claude: fuera por ahora; solo se deja la interfaz preparada (stub).

## kali-mcp-server: evaluación
Expone 12 herramientas (nmap, nikto, gobuster, dirb, sqlmap, hydra, john, wpscan,
enum4linux, metasploit, server_health, execute_command). No es completo: faltan
masscan, ffuf, nuclei, amass/subfinder, tshark, searchsploit, bettercap…;
devuelve texto crudo; `execute_command` es una puerta abierta; no hay scope,
auditoría ni límites. **Se usará como un backend más tras nuestra capa de
herramientas, no como dependencia directa.**

## Estructura
```
adverso/
  core/     modelos, motor de amenazas, registro, estado (SQLite)
  tools/    una herramienta Kali por módulo: esquema + ejecución + parser JSON
  scope/    objetivos autorizados, política de confirmación, auditoría
  agents/   base (bucle e interfaz), ollama, openai_compat, opencode, claude (stub)
  mcp/      servidor MCP propio (stdio) y canal con el proceso padre
  monitor/  monitor pasivo DNS/conexiones
  ui/       TUI y CLI
  reports/  tarjeta de presentación (md/html)
tests/
docker/   laboratorio: Kali + opencode, Ollama, objetivo (nginx)
legacy/android/   app original (referencia)
```

## Fases
| Fase | Entregable | Hecho cuando |
| --- | --- | --- |
| 0 | Esqueleto, modelo y motor de amenazas portados | Tests portados pasan ✅ |
| 1 | Capa de herramientas (nmap, gobuster, nikto) + guardia de alcance | Escaneo fuera de alcance rechazado; dentro, auditado ✅ |
| 2 | Agente con modelo local | Un modelo pequeño completa un reconocimiento guiado ✅ (qwen3:8b vía Ollama, ~90 s en CPU) |
| 3 | Adaptador opencode + cliente OpenAI-compatible | Misma tarea con otro agente ✅ (opencode 1.19.6 + qwen3:4b-instruct, ~4 min en CPU) |
| 4 | Monitor pasivo y TUI | Palacios y Sombras visibles en vivo |
| 5 | Más herramientas | masscan, ffuf, nuclei, tshark… cubiertas (el servidor MCP propio ya existe: fase 3) |
| 6 | Claude | Al final |

## Notas de la fase 2
- Hardware de desarrollo: 15 GB de RAM, sin GPU. `qwen3:30b` (18 GB) no es viable (agota 280 s sin responder); `qwen3:8b` sí.
- El agente tiene modo nativo (tool calling de Ollama) y modo JSON en texto para modelos sin soporte, como `dolphin-mistral`.
- colibri (motor MoE jerárquico con API OpenAI): candidato para modelos grandes, no probado (ya hay cliente: `--backend openai`).

## Notas de la fase 3
- Tres agentes, mismas garantías: `ollama` y `openai` usan nuestro bucle; `opencode` usa el suyo y recibe las
  herramientas por `adverso mcp`, que envuelve el mismo `Executor`. Las de opencode se deniegan con
  `"permission": {"*": "deny", "adverso_*": "allow"}` (gana la última regla) y no llegan ni a ofrecerse al modelo.
- La confirmación humana no puede ir por el stdin del servidor MCP (es el protocolo): va al proceso padre por un
  socket Unix en un directorio 0700. Los eventos llevan acuse de recibo (sin él, el último se perdía al cerrar).
- opencode 1.19.6, verificado contra el binario (la documentación web describe un esquema "V2" distinto):
  claves `provider`/`mcp`/`agent`/`permission`; `opencode run --format json --pure --title`; la tarea va por stdin
  (como argumento la re-entrecomilla); el `prompt` del agente sustituye al de opencode.
- opencode toma el proyecto de `$PWD`, no del cwd del proceso: lanzado desde un shell usaba el directorio del
  usuario y su `opencode.json`. Se fija `PWD` al directorio temporal (test de regresión incluido).
- Tiempos límite de opencode: 5 s para listar herramientas MCP y 300 s de espera a cabeceras/trozos del proveedor;
  ambos se amplían (en CPU, cargar el modelo y procesar el prompt pasa de 300 s).
- Docker (8 GB): `qwen3:4b` es la variante 2507 Thinking (razona siempre, ~15 min por tarea); `qwen3:4b-instruct`
  hace lo mismo en 3-6 min. `qwen3:8b` no cabe con holgura junto al resto de contenedores.
- Pendiente: probar opencode con un proveedor remoto (sin redefinir `provider`), y con `qwen3:8b` en una máquina con más memoria.
