# 🛡️ Antivirus Pro EDR

**Suite de Seguridad Profesional para Linux** — Antivirus + EDR + SOAR + Forensics.

![Estado](https://img.shields.io/badge/estado-producción-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![PostgreSQL](https://img.shields.io/badge/postgresql-14%2B-blue)
![Licencia](https://img.shields.io/badge/licencia-MIT-yellow)

---

## ✨ Características

### Motor de detección
- **ClamAV** (clamd vía socket, 3.6M firmas)
- **YARA** (reglas comunitarias Neo23x0 + YARA-Rules)
- **Sigma** (850+ reglas de comportamiento)
- **Heurística propia** con mapeo MITRE ATT&CK
- **CTI abuse.ch** (URLhaus + ThreatFox)

### Respuesta y remediación
- **SOAR**: kill_process, quarantine_file, block_ip, isolate_endpoint, disable_user
- **Cuarentena cifrada** con AES-256-GCM
- **Captura forense** automatizada (ps, netstat, lsof, dmesg, etc.)
- **Defensas Zip Slip / Zip Bomb**

### Plataforma
- **PostgreSQL forense** (12 tablas, 43 índices)
- **API REST** con FastAPI (puerto 8003)
- **Dashboard web** (FastAPI + WebSocket, puerto 8081)
- **GUI PyQt6** con dark mode
- **Agente multi-endpoint** (heartbeat, telemetría, comandos remotos)
- **CLI de gestión**
- **STIX 2.1 / TAXII 2.1**
- **Exportación SIEM** (CEF sobre syslog)
- **Zero Trust score**

---

## 🚀 Instalación Rápida

### Docker (recomendado)

    git clone <repo> /opt/antivirus-pro
    cd /opt/antivirus-pro
    docker-compose up -d

Accede a:
- **Dashboard web**: http://localhost:8081
- **API**: http://localhost:8003/docs
- **PostgreSQL**: localhost:5433 (user: antivirus, pass: changeme)

### Manual

    sudo apt install -y clamav clamav-daemon clamav-freshclam \
                        python3-venv postgresql git unrar p7zip-full libmagic1

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

    # Configurar DB
    sudo -u postgres psql -f db/schema.sql

    # Actualizar firmas
    sudo freshclam

    # Arrancar
    sudo python3 antivirus.py --daemon

---

## 📖 Uso

### CLI

    # Escaneo puntual
    python3 antivirus.py --scan /home

    # Daemon
    sudo python3 antivirus.py --daemon

    # Procesos
    sudo python3 antivirus.py --scan-processes

    # Actualizar firmas
    python3 antivirus.py --update

### CLI de gestión EDR

    export AV_SERVER=http://localhost:8003
    export AV_API_KEY=tu_api_key

    python3 agent/cli.py endpoints     # Listar endpoints
    python3 agent/cli.py threats       # Listar amenazas
    python3 agent/cli.py stats         # Estadísticas
    python3 agent/cli.py send HOSTNAME scan_now
    python3 agent/cli.py send HOSTNAME kill_process --args '{"pid":1234}'

### API REST

    curl -H "Authorization: Bearer $API_KEY" http://localhost:8003/api/stats
    curl -H "Authorization: Bearer $API_KEY" http://localhost:8003/api/endpoints
    curl -H "Authorization: Bearer $API_KEY" http://localhost:8003/api/threats

---

## 🏗️ Arquitectura

    antivirus-pro/
    ├── antivirus.py                 # Punto de entrada
    ├── config.json                  # Configuración
    ├── Dockerfile
    ├── docker-compose.yml
    ├── db/schema.sql                # Esquema PostgreSQL
    │
    ├── core/                        # Motor
    │   ├── engine.py                # Coordinador multi-motor
    │   ├── scanner.py               # ClamAV
    │   ├── yara_engine.py           # YARA
    │   ├── sigma_engine.py          # Sigma
    │   ├── heuristic.py             # Heurística
    │   ├── cti_abuse.py             # CTI
    │   ├── cti_stix.py              # STIX/TAXII
    │   ├── soar.py                  # SOAR
    │   ├── crypto.py                # AES-256-GCM
    │   ├── zip_defense.py           # Zip Slip/Bomb
    │   ├── zero_trust.py            # Zero Trust score
    │   ├── siem_export.py           # CEF/syslog
    │   ├── telemetry.py             # Telemetría
    │   ├── realtime.py              # Polling RT
    │   ├── scheduler.py             # APScheduler
    │   ├── db.py                    # Capa PostgreSQL
    │   ├── processes.py             # Escaneo procesos
    │   ├── archives.py              # Comprimidos
    │   └── memory_scanner.py        # YARA en memoria
    │
    ├── web/dashboard.py             # Dashboard web
    ├── server/
    │   ├── api.py                   # API principal
    │   ├── api_extended.py          # Endpoints agentes
    │   ├── panels.py                # Paneles PyQt6
    │   ├── widgets.py               # Widgets PyQt6
    │   └── styles/dark.qss          # Dark theme
    │
    ├── agent/
    │   ├── edr_agent.py             # Agente EDR
    │   ├── cli.py                   # CLI de gestión
    │   └── qt_agent.py              # Agente Qt
    │
    ├── systemd/                     # Servicios systemd
    │   ├── antivirus-pro.service
    │   ├── antivirus-api.service
    │   ├── antivirus-dashboard.service
    │   └── antivirus-agent.service
    │
    └── tests/                       # Tests pytest

---

## 🔒 Seguridad

- **Cuarentena cifrada** (AES-256-GCM, PBKDF2 600k iteraciones)
- **Permisos 0600** en archivos en cuarentena
- **systemd hardening**: ProtectSystem, NoNewPrivileges, AmbientCapabilities
- **Defensas Zip Slip/Bomb** en extracción de comprimidos
- **API autenticada** con Bearer tokens
- **Audit log** de todas las acciones

### Advertencias

- NO escanees `/` con `sudo` sin probar antes en `/tmp`
- Revisa la cuarentena antes de borrar (falsos positivos)
- El dashboard NO tiene auth en Docker (añade reverse proxy)
- Cambia TODAS las API keys antes de producción

---

## 🧪 Tests

    pytest tests/ -v
    pytest tests/ --cov=core --cov-report=html

---

## 📄 Licencia

MIT

---

## 🙏 Créditos

- [ClamAV](https://www.clamav.net/)
- [YARA](https://virustotal.github.io/yara/)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [abuse.ch](https://abuse.ch/)
- [MITRE ATT&CK](https://attack.mitre.org/)
