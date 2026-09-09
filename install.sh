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

# 6. Actualizar firmas de ClamAV
echo "🔄 Actualizando firmas de ClamAV..."
sudo freshclam || echo "⚠️  No se pudo actualizar firmas. Ejecuta 'sudo freshclam' manualmente."

# 7. Dar permisos de ejecución
chmod +x gui/main.py
chmod +x run.sh

# 8. Mensaje final
echo ""
echo "✅ ¡Instalación completada!"
echo ""
echo "Para iniciar el antivirus:"
echo "  source venv/bin/activate"
echo "  python gui/main.py"
echo ""
echo "O usa el script de inicio:"
echo "  ./run.sh"
echo ""
echo "📖 Consulta INSTALL.md para más información."
