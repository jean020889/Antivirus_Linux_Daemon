#!/bin/bash
# ============================================================
#  INSTALADOR DEL ANTIVIRUS PROFESIONAL PARA LINUX
# ============================================================

set -e

echo "🛡️  Instalando Antivirus Profesional..."
echo "========================================="

# 1. Verificar que estamos en el directorio correcto
if [ ! -f "config.json" ]; then
    echo "❌ Error: No se encuentra config.json. Ejecuta este script desde la raíz del proyecto."
    exit 1
fi

# 2. Crear entorno virtual
echo "📦 Creando entorno virtual..."
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias Python
echo "📦 Instalando dependencias Python..."
pip install --upgrade pip
pip install -r requirements.txt 2>/dev/null || pip install apscheduler psutil watchdog python-magic patool yara-python httpx fastapi uvicorn[standard] PyQt6 qdarkstyle

# 4. Crear directorios necesarios
mkdir -p logs
mkdir -p yara_rules

# 5. Crear estructura de cuarentena
mkdir -p ~/antivirus_cuarentena

# 6. Instalar firmas de terceros (con timeout y tolerancia a fallos)
echo "🔄 Instalando firmas de terceros para ClamAV..."
echo "📦 Intentando instalar clamav-unofficial-sigs (timeout de 30 segundos)..."

# Ejecutar con timeout para que no se cuelgue
if timeout 30 sudo apt-get install clamav-unofficial-sigs -y 2>/dev/null; then
    echo "✅ clamav-unofficial-sigs instalado correctamente."
    # Configurar automáticamente
    if [ -f /etc/clamav-unofficial-sigs/user.conf ]; then
        sudo sed -i 's/^# *clamav_update_enabled=.*/clamav_update_enabled="yes"/' /etc/clamav-unofficial-sigs/user.conf
        sudo sed -i 's/^# *malwarepatrol_update_enabled=.*/malwarepatrol_update_enabled="yes"/' /etc/clamav-unofficial-sigs/user.conf
        sudo sed -i 's/^# *sanesecurity_update_enabled=.*/sanesecurity_update_enabled="yes"/' /etc/clamav-unofficial-sigs/user.conf
        sudo sed -i 's/^# *secuser_update_enabled=.*/secuser_update_enabled="yes"/' /etc/clamav-unofficial-sigs/user.conf
        echo "✅ Configuración de clamav-unofficial-sigs completada."
    fi
else
    echo "⚠️  No se pudo instalar clamav-unofficial-sigs (posiblemente no disponible en tus repositorios)."
    echo "   Usaremos la instalación manual de firmas de terceros."
    echo "   Ejecuta después: ./install_thirdparty_manual.sh"
fi

# 7. Clonar repositorios de reglas YARA (masificación)
echo "📚 Clonando repositorios de reglas YARA comunitarias..."
if [ ! -d "yara_rules/Neo23x0" ]; then
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git yara_rules/Neo23x0 || echo "⚠️  No se pudo clonar Neo23x0"
fi
if [ ! -d "yara_rules/YARA-Rules" ]; then
    git clone --depth 1 https://github.com/YARA-Rules/rules.git yara_rules/YARA-Rules || echo "⚠️  No se pudo clonar YARA-Rules"
fi

# 8. Actualizar firmas de ClamAV (oficiales)
echo "🔄 Actualizando firmas de ClamAV oficiales..."
sudo freshclam || echo "⚠️  No se pudo actualizar freshclam"

# 9. Crear script de actualización automática de firmas y reglas
cat << 'INNER_EOF' > update_signatures.sh
#!/bin/bash
# Actualizar firmas de ClamAV (oficiales y de terceros) y reglas YARA
echo "🔄 Actualizando firmas oficiales..."
sudo freshclam

echo "🔄 Actualizando firmas de terceros (SanSec, MalwarePatrol, etc.)..."
if [ -f /usr/sbin/clamav-unofficial-sigs ]; then
    sudo clamav-unofficial-sigs --force
else
    echo "⚠️  clamav-unofficial-sigs no instalado. Ejecuta ./install_thirdparty_manual.sh"
fi

echo "🔄 Actualizando repositorios YARA..."
cd "$(dirname "$0")/yara_rules"
if [ -d "Neo23x0" ]; then
    cd Neo23x0 && git pull --depth 1 && cd ..
fi
if [ -d "YARA-Rules" ]; then
    cd YARA-Rules && git pull --depth 1 && cd ..
fi
echo "✅ Firmas y reglas actualizadas."
INNER_EOF
chmod +x update_signatures.sh

# 10. Crear script para instalación manual de firmas de terceros
cat << 'INNER_EOF' > install_thirdparty_manual.sh
#!/bin/bash
echo "📦 Instalación manual de firmas de terceros para ClamAV..."

# Crear directorio para firmas de terceros
sudo mkdir -p /var/lib/clamav/unofficial-sigs
cd /var/lib/clamav/unofficial-sigs

# Descargar firmas de SanSec (sanesecurity)
echo "Descargando firmas SanSec..."
sudo wget -q -N https://sanesecurity.com/clamav/sanesecurity.ctdb.gz
sudo wget -q -N https://sanesecurity.com/clamav/sanesecurity.hdb
sudo wget -q -N https://sanesecurity.com/clamav/sanesecurity.ndb
sudo wget -q -N https://sanesecurity.com/clamav/sanesecurity.fp

# Descargar firmas de MalwarePatrol
echo "Descargando firmas MalwarePatrol..."
sudo wget -q -N https://www.malwarepatrol.net/clamav/malwarepatrol.ndb

# Descargar firmas de SecuriteInfo
echo "Descargando firmas SecuriteInfo..."
sudo wget -q -N https://www.securiteinfo.com/clamav/securiteinfo.hdb
sudo wget -q -N https://www.securiteinfo.com/clamav/securiteinfo.ndb

# Descargar firmas de Foxhole (opcional)
echo "Descargando firmas Foxhole..."
sudo wget -q -N https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/sigs/foxhole.ndb

# Establecer permisos
sudo chown clamav:clamav /var/lib/clamav/unofficial-sigs/*
sudo chmod 644 /var/lib/clamav/unofficial-sigs/*

echo "✅ Firmas de terceros instaladas manualmente en /var/lib/clamav/unofficial-sigs"
echo "   Para actualizarlas regularmente, ejecuta este script periódicamente."
INNER_EOF
chmod +x install_thirdparty_manual.sh

# 11. Crear script de inicio run.sh
cat << 'INNER_EOF' > run.sh
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python gui/main.py
INNER_EOF
chmod +x run.sh

# 12. Acceso directo en el escritorio
echo "📌 Creando acceso directo en el escritorio..."
ICON_PATH="$PWD/antivirus_linux_deamon.png"
[ ! -f "$ICON_PATH" ] && ICON_PATH="system-software-install"
DESKTOP_DIR="$HOME/Desktop"
[ ! -d "$DESKTOP_DIR" ] && DESKTOP_DIR="$HOME/Escritorio"
if [ -n "$DESKTOP_DIR" ]; then
    cat << INNER_EOF > "$DESKTOP_DIR/antivirus-linux.desktop"
[Desktop Entry]
Name=Antivirus Profesional
Comment=Protege tu sistema Linux
Exec=$PWD/run.sh
Icon=$ICON_PATH
Terminal=false
Type=Application
Categories=System;Security;
StartupNotify=true
INNER_EOF
    chmod +x "$DESKTOP_DIR/antivirus-linux.desktop"
    echo "✅ Acceso directo creado en $DESKTOP_DIR"
fi

# 13. Autostart
echo "🚀 Configurando inicio automático..."
AUTOSTART_DIR="$HOME/.config/autostart"
mkdir -p "$AUTOSTART_DIR"
cat << INNER_EOF > "$AUTOSTART_DIR/antivirus-linux.desktop"
[Desktop Entry]
Name=Antivirus Profesional (Daemon)
Comment=Inicia el antivirus al encender la PC
Exec=$PWD/run.sh
Icon=$ICON_PATH
Terminal=false
Type=Application
Categories=System;Security;
X-GNOME-Autostart-enabled=true
INNER_EOF
chmod +x "$AUTOSTART_DIR/antivirus-linux.desktop"
echo "✅ Autostart configurado."

# 14. Mensaje final
echo ""
echo "✅ ¡Instalación completada!"
echo ""
echo "▶️  Para iniciar el antivirus: ./run.sh"
echo "📌  Para actualizar firmas y reglas: ./update_signatures.sh"
echo "📦  Para instalar firmas de terceros manualmente: ./install_thirdparty_manual.sh"
echo ""
echo "🛡️  Tu antivirus ahora tiene:"
echo "  - Firmas de ClamAV oficiales + de terceros (si se instalaron)"
echo "  - Masificación de reglas YARA (Neo23x0/signature-base, YARA-Rules)"
echo "  - Sistema de puntuación de riesgo"
echo "  - Detección de ransomware (cifrado masivo)"
echo "  - Escáner de procesos en memoria (fileless)"
