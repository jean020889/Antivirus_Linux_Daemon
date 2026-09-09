#!/bin/bash
# Script para ejecutar la GUI del antivirus

# Obtener la ruta del directorio del proyecto (dos niveles arriba)
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Activar el entorno virtual y ejecutar
cd "$PROJECT_DIR"
source venv/bin/activate
python gui/main.py
