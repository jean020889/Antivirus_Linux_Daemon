# ============================================
# Antivirus Pro EDR - Multi-stage build
# ============================================
FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Dependencias del sistema
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    clamav clamav-daemon clamav-freshclam \
    postgresql-client \
    git unrar p7zip-full libmagic1 \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Venv
WORKDIR /app
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Dependencias Python
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY . /app/

# Directorios
RUN mkdir -p /opt/antivirus_cuarentena /app/logs /app/yara_rules /app/sigma_rules /app/cti_cache && \
    chmod 700 /opt/antivirus_cuarentena

# Script de entrada
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8003 8081

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["daemon"]
