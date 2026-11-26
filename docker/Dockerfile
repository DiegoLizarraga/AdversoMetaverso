# Entorno de pruebas: Kali rolling con las herramientas que usa adverso y opencode.
#   docker compose -f docker/compose.yml build
#   docker compose -f docker/compose.yml run --rm kali python3 -m pytest -q
FROM kalilinux/kali-rolling AS base

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
# El redirector http.kali.org a veces responde 503: se puede fijar un espejo.
#   docker compose -f docker/compose.yml build --build-arg KALI_MIRROR=http://http.kali.org/kali
ARG KALI_MIRROR=http://mirrors.ocf.berkeley.edu/kali
RUN sed -i "s#http://http.kali.org/kali#${KALI_MIRROR}#" /etc/apt/sources.list.d/kali.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pytest \
        nmap dnsutils whois whatweb nikto gobuster dirb \
        nodejs npm ca-certificates curl iproute2 \
    # Kali da a nmap capacidades de fichero (cap_net_admin…) que Docker no concede:
    # el exec falla con EPERM. Aquí se corre como root, no hacen falta.
    && setcap -r /usr/lib/nmap/nmap \
    && mkdir -p /usr/share/wordlists \
    && ln -sfn /usr/share/dirb/wordlists /usr/share/wordlists/dirb \
    && rm -rf /var/lib/apt/lists/*

FROM base
# Versión verificada con el adaptador (adverso/agents/opencode.py). npm ≥ 12 bloquea
# los scripts de instalación: el postinstall de opencode-ai baja el binario.
ARG OPENCODE_VERSION=1.19.6
RUN npm install -g --allow-scripts=opencode-ai "opencode-ai@${OPENCODE_VERSION}" && opencode --version

# Fase 4: TUI (Textual), tcpdump para capturas de prueba y rsvg-convert para revisar
# capturas de pantalla de la TUI. Capa aparte, después de opencode: cambiarla no
# obliga a volver a descargar opencode.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-textual tcpdump librsvg2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
