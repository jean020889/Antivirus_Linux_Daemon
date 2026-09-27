# 🛡️ Antivirus Profesional para Linux

**Sistema de seguridad completo con detección por firmas (ClamAV + YARA), heurística, telemetría de kernel (eBPF), motor de reglas Sigma, respuesta automatizada (SOAR), inteligencia de amenazas (STIX/TAXII), exportación SIEM y atestación Zero Trust.**

---

## ⚠️ AVISO LEGAL — SOFTWARE PROPIETARIO

**Este software NO es de código abierto ni de uso libre.**

El uso, ejecución, evaluación o despliegue de este software está **estrictamente condicionado** a la existencia de un contrato o acuerdo comercial válido, formal y vigente firmado con el Autor Original.

- **Autor**: Jean Carlos Vivar Benitez [ORCID: 0009-0004-1739-7945]
- **Contacto comercial**: jean.car.0208@gmail.com
- **Licencia completa**: ver archivo [LICENCE](LICENCE)

**NO está autorizado el uso personal, doméstico, académico, gubernamental o comercial sin acuerdo previo por escrito.**

---

## 📊 Estado del proyecto

- **176 tests automatizados passing** (1 skip: test de integración de eBPF que requiere `sudo`)
- **Benchmark documentado**: ver [BENCHMARKS.md](BENCHMARKS.md)
- **Cobertura honesta**: cada módulo tiene tests unitarios verificados; la cobertura de integración se documenta explícitamente.

---

## ✨ Características

- ✅ **Motor multi-firma**: ClamAV (oficial + terceros) + YARA (reglas comunitarias) + heurística avanzada.
- ✅ **Telemetría de kernel (eBPF)**: captura de `execve`, `openat`, `connect`, `setuid` en tiempo real.
- ✅ **Motor de reglas Sigma**: detección por comportamiento sobre eventos del kernel.
- ✅ **Respuesta automatizada (SOAR)**: kill process, quarantine, block_ip, isolate_endpoint.
- ✅ **Almacén forense SQLite**: búsquedas tipo "¿qué abrió /etc/shadow en las últimas 24h?".
- ✅ **Consumo de feeds CTI**: STIX 2.1 sobre TAXII 2.1.
- ✅ **Exportación SIEM**: formato CEF sobre syslog UDP/TCP.
- ✅ **Atestación Zero Trust**: score de salud consultable por un PDP.
- ✅ **Cifrado FIPS-aware**: AES-256-GCM, PBKDF2-HMAC-SHA256.
- ✅ **Análisis de archivos comprimidos**: defensas contra Zip Slip y Zip Bomb.
- ✅ **Programador de tareas**: múltiples horarios de escaneo automático.
- ✅ **Interfaz gráfica**: PyQt6 con diseño oscuro moderno.

---

## 📦 Instalación

### Requisitos previos

- Linux con kernel >= 4.9 (BTF para eBPF)
- Python 3.10+
- `sudo` con NOPASSWD para `freshclam` e `iptables` (opcional pero recomendado)
- ClamAV instalado y con firmas actualizadas

### Instalación

```bash
cd /ruta/al/proyecto
chmod +x install.sh
./install.sh
```

El instalador configura:
- Entorno virtual con dependencias.
- Firmas de ClamAV oficiales + terceros.
- Repositorios de reglas YARA comunitarias.
- Acceso directo en escritorio y arranque automático.

### Configuración inicial

Copia el archivo de ejemplo y ajusta las rutas personales:

```bash
cp config.example.json config.local.json
nano config.local.json
```

El daemon prefiere `config.local.json` sobre `config.json` automáticamente.

---

## 🖥️ Uso

```bash
source venv/bin/activate
./run.sh
```

### Comandos del daemon

```bash
python antivirus_daemon.py                    # Daemon completo
python antivirus_daemon.py update             # Actualiza firmas
python antivirus_daemon.py scan-memory        # Escanea procesos en memoria
python antivirus_daemon.py scan-folder /ruta  # Escanea una carpeta
python antivirus_daemon.py zt-attest          # Atestación Zero Trust
```

---

## 🧪 Tests

```bash
source venv/bin/activate
pytest tests/ -v --timeout=180
```

Resultado esperado: **176 passed, 1 skipped**.

---

## 🔧 Solución de problemas

| Problema | Solución |
|----------|----------|
| `Permission denied` en `/opt/antivirus_cuarentena` | Edita `config.local.json` y usa una ruta en tu home. |
| `ModuleNotFoundError: apscheduler` | Activa el venv y `pip install -r requirements.txt`. |
| `freshclam` falla con error de log | `sudo rm /var/log/clamav/freshclam.log && sudo touch /var/log/clamav/freshclam.log && sudo chown clamav:clamav /var/log/clamav/freshclam.log && sudo chmod 644 /var/log/clamav/freshclam.log` |
| No se bloquean IPs | Verifica que `iptables` está instalado y que tienes sudo sin contraseña configurado. |

---

## 📚 Documentación

- [LICENCE](LICENCE) — Licencia propietaria comercial completa.
- [Installation_instructions.md](Installation_instructions.md) — Guía detallada de instalación.
- [BENCHMARKS.md](BENCHMARKS.md) — Métricas reproducibles.

---

## 🚨 Reporte de vulnerabilidades

Para reportar vulnerabilidades de seguridad en este software, contacta directamente al autor:

- **Email**: jean.car.0208@gmail.com
- **Asunto sugerido**: [SECURITY] Antivirus Linux - Vulnerabilidad en [componente]

**NO publiques vulnerabilidades en GitHub Issues.** El reporte responsable es obligatorio por contrato.

**Toda contribución, parche o sugerencia enviada al autor implica cesión automática de derechos según lo establecido en la cláusula 2.3 de la LICENCE.**

---

## 📄 Licencia

**PROPIETARIO COMERCIAL. TODOS LOS DERECHOS RESERVADOS.**

Copyright (c) 2026 Jean Carlos Vivar Benitez [ORCID: 0009-0004-1739-7945]

Ver [LICENCE](LICENCE) para términos completos.
FIN_README

echo "✅ README.md creado"

# Verificación
echo ""
echo "=== Primeras 25 líneas ==="
head -25 README.md

echo ""
echo "=== Tamaño ==="
wc -l README.md

echo ""
echo "=== Confirmación: no debe haber GPLv3 ni insignias de código abierto ==="
grep -i "gpl\|open source\|código abierto" README.md && echo "⚠️ aún hay menciones" || echo "✅ sin menciones a GPL/código abierto"
```

**Ejecuta ese bloque y pégame la salida.**

Después de eso:

1. Verificamos el estado con `git status`.
2. Commit con mensaje descriptivo.
3. `git push --force-with-lease origin main`.
4. Verificación en GitHub.
