# AdversoMetaverso

Asistente de terminal para **OSINT y hacking con las herramientas de Kali Linux**,
operado por un modelo de lenguaje (local con Ollama). Estética de *Persona 5*:
cada host o dominio es un **Palacio**; cada servicio, ruta o dato expuesto es una **Sombra**.

El modelo nunca toca una herramienta directamente: todo pasa por un `Executor` que
valida argumentos, aplica el alcance, pide confirmación y audita.

## Uso

```bash
cp scope.example.toml scope.toml      # declara TUS objetivos autorizados
python -m adverso doctor              # qué herramientas y modelo tienes
python -m adverso chat                # sesión interactiva (recomendado)
python -m adverso recon "Reconoce 192.168.56.10"   # una sola tarea
python -m adverso palaces | report --out informe.md
```

En `chat`: texto libre = tarea para el agente; `/palacios /sombras /informe /alcance
/herramientas /auditoria /olvida /ayuda /salir` = control directo.

## Agentes (`--backend`)

| Backend | Quién decide | Modelo |
| --- | --- | --- |
| `ollama` (por defecto) | nuestro bucle | API nativa de Ollama (`--url`, por defecto `$ADVERSO_OLLAMA_URL` o `127.0.0.1:11434`) |
| `openai` | nuestro bucle | cualquier `/v1/chat/completions`: llama.cpp, vLLM, LM Studio, colibri… Clave en la variable `ADVERSO_API_KEY` (o la que diga `--api-key-env`), nunca en la línea de órdenes |
| `opencode` | el agente opencode | `--model proveedor/modelo` (sin proveedor = `ollama/`) |

```bash
python -m adverso recon --backend openai --url http://127.0.0.1:8080/v1 --model qwen3 "Reconoce 10.0.0.5"
python -m adverso chat --backend opencode --model qwen3:8b
```

Con `opencode` (verificado con 1.19.6), adverso arranca su propio **servidor MCP**
(`python -m adverso mcp`) como única fuente de herramientas: las de opencode (shell,
edición, web…) quedan denegadas y ni se ofrecen al modelo, y las aprobaciones de acciones
intrusivas vuelven a esta terminal por un socket privado. Cada ejecución corre en un
directorio temporal con su propia configuración: no hereda la configuración global de
opencode ni el `opencode.json` del directorio desde el que lo lances. El servidor MCP sirve
también para cualquier otro cliente MCP; sin ese canal, lo intrusivo se deniega.

`--text-tools` fuerza el protocolo JSON en texto para modelos sin tool calling. Con modelos
"thinking" (p. ej. `qwen3:4b`, que es la variante 2507 Thinking) el razonamiento se descarta
del informe, pero tarda mucho más en CPU: mejor una variante instruct (`qwen3:4b-instruct`).

## Laboratorio en Docker

`docker/` trae un laboratorio cerrado: Kali con las herramientas y opencode, Ollama, y un
objetivo (nginx en `172.30.56.10`), con `docker/scope.lab.toml` como alcance.

```bash
docker compose -f docker/compose.yml build
docker compose -f docker/compose.yml run --rm kali python3 -m pytest -q          # tests
docker compose -f docker/compose.yml --profile agente up -d ollama objetivo
docker compose -f docker/compose.yml exec ollama ollama pull qwen3:4b-instruct
docker compose -f docker/compose.yml run --rm kali python3 -m adverso recon \
    --backend opencode --model qwen3:4b-instruct --scope docker/scope.lab.toml \
    "Reconoce 172.30.56.10 y dime qué servicios expone"
```

Si `http.kali.org` responde 503 al construir, fija otro espejo con `--build-arg KALI_MIRROR=…`.

## Herramientas

| Herramienta | Tipo | Notas |
| --- | --- | --- |
| `dns_lookup` (dig), `whois_lookup`, `harvest_domain` (theHarvester) | **pasiva** | consultan a terceros; sin alcance, con auditoría |
| `nmap_scan`, `whatweb_fingerprint` | activa | exigen alcance; perfiles cerrados, sin flags libres |
| `gobuster_dir`, `nikto_scan` | **intrusiva** | alcance + confirmación humana (60 s, sin respuesta = no) |

## Garantías

- **Alcance:** nada activo se ejecuta fuera de `scope.toml`. Si el objetivo es un nombre,
  la herramienta recibe la IP ya validada (sin carrera DNS) y se rechazan URLs `user@host`.
- **Auditoría** append-only en `audit.log` (JSON Lines).
- **Salida no confiable:** lo que devuelve una herramienta llega al modelo marcado como
  datos, nunca como instrucciones; máximo 3 llamadas por turno. Con opencode, el servidor
  MCP impone un presupuesto equivalente (`--max-steps` × 3) y bloquea las llamadas repetidas.
- **Persistencia:** `adverso.json` (Palacios y Sombras), escritura atómica.

Solo Linux (Kali/Debian): no hay ni habrá soporte para Windows.

La app Android original vive en `legacy/android/`. Hoja de ruta en `PLAN.md`.
