#!/bin/bash
# ============================================================
#  DESINSTALADOR DEL ANTIVIRUS PROFESIONAL PARA LINUX
# ============================================================

echo "🗑️  Desinstalando Antivirus Profesional..."
echo "========================================="

# 1. Preguntar si desea eliminar la cuarentena
read -p "¿Eliminar también la carpeta de cuarentena (~/antivirus_cuarentena)? (s/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Ss]$ ]]; then
    echo "Eliminando cuarentena..."
    rm -rf ~/antivirus_cuarentena
fi

# 2. Preguntar si desea eliminar el entorno virtual
read -p "¿Eliminar el entorno virtual (venv/)? (s/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Ss]$ ]]; then
    echo "Eliminando entorno virtual..."
    rm -rf venv
fi

# 3. Preguntar si desea eliminar logs
read -p "¿Eliminar los logs (logs/)? (s/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Ss]$ ]]; then
    echo "Eliminando logs..."
    rm -rf logs
fi

# 4. Preguntar si desea eliminar todo el proyecto
read -p "¿Eliminar TODO el proyecto (incluyendo código fuente)? (s/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Ss]$ ]]; then
    echo "Eliminando proyecto..."
    cd ..
    rm -rf "$(basename "$PWD")"
    echo "✅ Proyecto eliminado completamente."
else
    echo "✅ Desinstalación completada. Los archivos del proyecto se mantienen."
fi

echo ""
echo "¡Gracias por usar Antivirus Profesional!"
