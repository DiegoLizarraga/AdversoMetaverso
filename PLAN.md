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
  agents/   base (interfaz), local (Ollama/OpenAI-compat), opencode, claude (stub)
  monitor/  monitor pasivo DNS/conexiones
  ui/       TUI y CLI
  reports/  tarjeta de presentación (md/html)
tests/
legacy/android/   app original (referencia)
```

## Fases
| Fase | Entregable | Hecho cuando |
| --- | --- | --- |
| 0 | Esqueleto, modelo y motor de amenazas portados | Tests portados pasan ✅ |
| 1 | Capa de herramientas (nmap, gobuster, nikto) + guardia de alcance | Escaneo fuera de alcance rechazado; dentro, auditado ✅ |
| 2 | Agente con modelo local | Un modelo pequeño completa un reconocimiento guiado |
| 3 | Adaptador opencode | Misma tarea con otro agente |
| 4 | Monitor pasivo y TUI | Palacios y Sombras visibles en vivo |
| 5 | Más herramientas; evaluar servidor MCP propio | masscan, ffuf, nuclei, tshark… cubiertas |
| 6 | Claude | Al final |
