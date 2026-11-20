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
  datos, nunca como instrucciones; máximo 3 llamadas por turno.
- **Persistencia:** `adverso.json` (Palacios y Sombras), escritura atómica.

La app Android original vive en `legacy/android/`. Hoja de ruta en `PLAN.md`.
