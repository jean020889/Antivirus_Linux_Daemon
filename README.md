# 🛡️ Antivirus Linux Dragon

**Suite de seguridad completa para Linux con detección por firmas (ClamAV + YARA), heurística, telemetría de kernel (eBPF), motor de reglas Sigma, respuesta automatizada (SOAR), inteligencia de amenazas (STIX/TAXII), exportación SIEM y atestación Zero Trust.**

---

## ⚠️ AVISO LEGAL — SOFTWARE PROPIETARIO

**Este software NO es de código abierto ni de uso libre.**

El uso, ejecución, evaluación o despliegue de este software está estrictamente condicionado a la existencia de un contrato o acuerdo comercial válido, formal y vigente firmado con el Autor Original.

- **Autor**: Jean Carlos Vivar Benitez [ORCID: 0009-0004-1739-7945]
- **Contacto comercial**: jean.car.0208@gmail.com
- **Licencia completa**: ver archivo LICENCE

**NO está autorizado el uso personal, doméstico, académico, gubernamental o comercial sin acuerdo previo por escrito.**

---

## 📊 Estado del proyecto

- **176 tests automatizados passing** (1 skip: test de integración de eBPF)
- **Paquete .deb conforme a Debian Policy** (lintian: 0 errores, 0 warnings)
- **Servicio systemd con hardening**: usuario dedicado, capabilities específicas, ProtectSystem=strict

---

## ✨ Características

- **Motor multi-firma**: ClamAV (oficial + terceros) + YARA + heurística
- **Telemetría de kernel (eBPF)**: captura de execve, openat, connect, setuid
- **Motor de reglas Sigma**: detección por comportamiento sobre eventos del kernel
- **Respuesta automatizada (SOAR)**: kill process, quarantine, block_ip
- **Almacén forense SQLite**: búsquedas tipo "¿qué abrió /etc/shadow?"
- **Consumo de feeds CTI**: STIX 2.1 sobre TAXII 2.1
- **Exportación SIEM**: formato CEF sobre syslog
- **Atestación Zero Trust**: score de salud consultable
- **Cifrado FIPS-aware**: AES-256-GCM, PBKDF2-HMAC-SHA256
- **Análisis de archivos comprimidos**: defensas contra Zip Slip y Zip Bomb
- **Programador de tareas**: múltiples horarios de escaneo automático
- **Interfaz gráfica**: PyQt6 con diseño oscuro moderno

---

## 📦 Instalación

### Requisitos previos

- Linux con kernel >= 4.9 (para eBPF, opcional)
- Python 3.10+
- ClamAV instalado y con firmas actualizadas
- Acceso a sudo para la instalación

### Método 1: Paquete .deb (recomendado para producción)

Descarga el archivo antivirus-linux-dragon_1.0.0-1_all.deb desde la sección Releases del repositorio.

    # Instalar el paquete con apt (resuelve dependencias automáticamente)
    sudo apt install ./antivirus-linux-dragon_1.0.0-1_all.deb

Durante la instalación, debconf te hará 6 preguntas:

1. ¿Autorizar freshclam e iptables sin contraseña? → Sí
2. Usuario al que autorizar → tu usuario humano (ej. asus)
3. ¿Crear usuario de sistema antivirus-dragon? → Sí
4. Directorio de cuarentena → Enter para aceptar el default
5. ¿Habilitar vigilancia en tiempo real? → Sí
6. ¿Habilitar telemetría eBPF? → Sí

El paquete configura automáticamente:

- Usuario de sistema antivirus-dragon (sin shell, sin home real)
- Servicio systemd con hardening
- /etc/sudoers.d/antivirus-linux-dragon con NOPASSWD solo para freshclam e iptables
- Cuarentena en /var/lib/antivirus-linux-dragon/quarantine/
- Lanzador en el menú de aplicaciones
- 2 páginas de manual

Comandos útiles:

    # Arrancar el servicio
    sudo systemctl start antivirus-linux-dragon.service

    # Habilitar al inicio (opcional)
    sudo systemctl enable antivirus-linux-dragon.service

    # Ver estado y logs
    sudo systemctl status antivirus-linux-dragon.service
    sudo journalctl -u antivirus-linux-dragon.service -f

    # Usar la interfaz gráfica
    antivirus-dragon-gui

### Método 2: Script install.sh (desarrollo)

Si prefieres instalar desde el código fuente:

    git clone https://github.com/jean020889/Antivirus_Linux_Daemon.git
    cd Antivirus_Linux_Daemon
    chmod +x install.sh
    ./install.sh

El instalador crea entorno virtual, actualiza firmas de ClamAV, clona repositorios de reglas YARA comunitarias, y configura acceso directo en escritorio.

### Configuración

En instalación vía .deb, la configuración vive en:

    /etc/antivirus-linux-dragon/config.local.json

En instalación vía install.sh, la configuración vive en el directorio del proyecto como config.local.json.

### Verificar la instalación

    # Ver el estado del servicio
    sudo systemctl status antivirus-linux-dragon.service

    # Ver la atestación Zero Trust (score de salud del sistema)
    antivirus-dragon zt-attest

    # Actualizar firmas manualmente
    antivirus-dragon update

    # Escanear una carpeta específica
    antivirus-dragon scan-folder /home/usuario/Descargas

    # Escanear procesos en memoria
    antivirus-dragon scan-memory

### Desinstalación

    # Eliminar el paquete pero CONSERVAR la cuarentena y los logs
    sudo apt remove antivirus-linux-dragon

    # Eliminar absolutamente todo (purga cuarentena y logs)
    sudo apt purge antivirus-linux-dragon

Durante la desinstalación, debconf te preguntará si deseas eliminar sudoers, cuarentena y logs.

### Notas sobre funcionalidad opcional

- **eBPF**: requiere linux-headers-$(uname -r) instalados. Sin ellos, el antivirus funciona con firmas y heurística, pero sin telemetría de kernel.
- **CTI (feeds STIX/TAXII)**: requiere pip install --break-system-packages taxii2-client stix2. Sin ellos, el motor CTI queda deshabilitado pero el resto funciona.
- **ProtectProc=invisible** en el systemd unit oculta /proc/stat al daemon, causando un warning de psutil. Es una decisión de hardening; el antivirus funciona con normalidad.

---

## 🖥️ Uso

### Comandos del daemon

    # Daemon completo (arranca el servicio systemd)
    sudo systemctl start antivirus-linux-dragon.service

    # Modo interactivo (útil para debugging)
    antivirus-dragon

    # Actualizar firmas y salir
    antivirus-dragon update

    # Escanear procesos en memoria y salir
    antivirus-dragon scan-memory

    # Escanear una carpeta y salir
    antivirus-dragon scan-folder /ruta/a/escanear

    # Ver atestación Zero Trust en formato JSON
    antivirus-dragon zt-attest

### Interfaz gráfica

    antivirus-dragon-gui

O desde el menú de aplicaciones del sistema: Sistema → Seguridad → Antivirus Linux Dragon.

---

## 🧪 Tests

    source venv/bin/activate
    pytest tests/ -v --timeout=180

Resultado esperado: 176 passed, 1 skipped.

---

## 🔧 Solución de problemas

| Problema | Solución |
|----------|----------|
| Permission denied en /opt/antivirus_cuarentena | Edita config.local.json y usa una ruta en tu home o en /var/lib/. |
| ModuleNotFoundError: apscheduler | Activa el venv y ejecuta pip install -r requirements.txt. |
| freshclam falla con error de log | sudo rm /var/log/clamav/freshclam.log && sudo touch /var/log/clamav/freshclam.log && sudo chown clamav:clamav /var/log/clamav/freshclam.log && sudo chmod 644 /var/log/clamav/freshclam.log |
| No se bloquean IPs | Verifica que iptables está instalado y que tienes sudo sin contraseña configurado. |
| eBPF no compila | Instala sudo apt install linux-headers-$(uname -r). |
| El servicio consume 100% de CPU | Verifica que estás en la versión 1.0.0-1 con el fix del bucle infinito. |
| No se puede acceder a /var/lib/antivirus-linux-dragon/ | Es por diseño (permisos 750). Usa sudo para inspeccionar. |

---

## 📚 Documentación

- LICENCE — Licencia propietaria comercial completa
- BENCHMARKS.md — Métricas reproducibles de rendimiento
- Installation_instructions.md — Guía detallada de instalación

---

## 🚨 Reporte de vulnerabilidades

Para reportar vulnerabilidades de seguridad en este software, contacta directamente al autor:

- **Email**: jean.car.0208@gmail.com
- **Asunto sugerido**: [SECURITY] Antivirus Linux Dragon - Vulnerabilidad en [componente]

NO publiques vulnerabilidades en GitHub Issues. El reporte responsable es obligatorio por contrato.

---

## 📄 Licencia

**PROPIETARIO COMERCIAL. TODOS LOS DERECHOS RESERVADOS.**

Copyright (c) 2026 Jean Carlos Vivar Benitez [ORCID: 0009-0004-1739-7945]

Ver archivo LICENCE para términos completos.
