# 📖 Instrucciones de Instalación y Desinstalación

## Antivirus Profesional para Linux

---

## 📋 Requisitos previos

Antes de comenzar, asegúrate de tener:

- **Sistema operativo**: Ubuntu 22.04 o superior (también funciona en Debian, Linux Mint, Fedora, etc.).
- **Python**: 3.10 o superior.
- **Conexión a Internet**: Para descargar dependencias y actualizar firmas.
- **Permisos sudo**: Necesarios para instalar paquetes del sistema, actualizar ClamAV y gestionar iptables.
- **Archivo de icono**: `antivirus_linux_deamon.png` en la raíz del proyecto (opcional, pero recomendado para el acceso directo).

---

## 🚀 Instalación con `install.sh`

### Paso 1: Clonar o descargar el proyecto

```bash
# Clonar desde GitHub (reemplaza con tu URL)
git clone https://github.com/tu-usuario/antivirus-linux.git
cd antivirus-linux

# O si ya tienes los archivos localmente
cd /home/asus/Documentos/INFORMATICA/PROGRAMACIÓN/PROYECTOS/ANTIVIRUS_LINUX
```

### Paso 2: Dar permisos de ejecución al instalador

```bash
chmod +x install.sh
```

### Paso 3: Ejecutar el instalador

```bash
./install.sh
```

El instalador realizará automáticamente:

| Paso | Descripción |
|------|-------------|
| 1️⃣ | Verifica que `config.json` exista en la raíz. |
| 2️⃣ | Crea un entorno virtual `venv/` con Python 3. |
| 3️⃣ | Instala todas las dependencias Python desde `requirements.txt`. |
| 4️⃣ | Crea las carpetas `logs/` y `yara_rules/`. |
| 5️⃣ | Crea la carpeta de cuarentena en `~/antivirus_cuarentena`. |
| 6️⃣ | Actualiza las firmas de ClamAV con `sudo freshclam`. |
| 7️⃣ | Da permisos de ejecución a `gui/main.py` y `run.sh`. |
| 8️⃣ | Crea un acceso directo en el escritorio. |
| 9️⃣ | Configura el inicio automático al encender la PC. |

### Paso 4: Verificar la instalación

```bash
# Iniciar el antivirus manualmente
./run.sh

# O desde el entorno virtual
source venv/bin/activate
python gui/main.py
```

---

## ⚙️ Configuración adicional (opcional)

### Configurar sudo sin contraseña para freshclam e iptables

Para que el antivirus pueda actualizar firmas y bloquear IPs sin pedir contraseña cada vez:

```bash
sudo visudo
```

Añade la siguiente línea al final del archivo (reemplaza `tu_usuario` por tu nombre de usuario):

```
tu_usuario ALL=(ALL) NOPASSWD: /usr/bin/freshclam, /sbin/iptables
```

Ejemplo para el usuario `asus`:
```
asus ALL=(ALL) NOPASSWD: /usr/bin/freshclam, /sbin/iptables
```

Guarda con `Ctrl+O`, Enter, y sale con `Ctrl+X`.

### Verificar que el acceso directo funciona

El instalador crea un acceso directo en el escritorio llamado `antivirus-linux.desktop`. Haz doble clic sobre él para abrir el antivirus.

Si el icono no se muestra correctamente, verifica que el archivo `antivirus_linux_deamon.png` esté en la raíz del proyecto.

### Verificar el inicio automático

El antivirus se configuró para iniciar automáticamente al encender la PC. Para confirmarlo:

```bash
ls -la ~/.config/autostart/antivirus-linux.desktop
```

Si el archivo existe, el antivirus se iniciará con el sistema.

---

## 🗑️ Desinstalación con `uninstall.sh`

### Paso 1: Dar permisos de ejecución al desinstalador

```bash
chmod +x uninstall.sh
```

### Paso 2: Ejecutar el desinstalador

```bash
./uninstall.sh
```

### Paso 3: Responder las preguntas interactivas

El desinstalador te hará varias preguntas para decidir qué eliminar:

| Pregunta | Acción si respondes **S** (sí) |
|----------|--------------------------------|
| ¿Eliminar la carpeta de cuarentena? | Borra `~/antivirus_cuarentena`. |
| ¿Eliminar el entorno virtual? | Borra la carpeta `venv/`. |
| ¿Eliminar los logs? | Borra la carpeta `logs/`. |
| ¿Eliminar TODO el proyecto? | Borra toda la carpeta del proyecto. |

**Ejemplo de salida esperada:**

```
🗑️  Desinstalando Antivirus Profesional...
=========================================
🗑️  Eliminando acceso directo del escritorio...
🗑️  Eliminando inicio automático...
¿Eliminar la carpeta de cuarentena (~/antivirus_cuarentena)? (s/N): s
Eliminando cuarentena...
¿Eliminar el entorno virtual (venv/)? (s/N): s
Eliminando entorno virtual...
¿Eliminar los logs (logs/)? (s/N): s
Eliminando logs...
¿Eliminar TODO el proyecto (incluyendo código fuente)? (s/N): s
Eliminando proyecto...
✅ Proyecto eliminado completamente.

¡Gracias por usar Antivirus Profesional!
```

### Paso 4: Verificar que todo se eliminó correctamente

```bash
# Verificar que el acceso directo ya no existe
ls ~/Desktop/antivirus-linux.desktop  # Debe mostrar "No such file"

# Verificar que el autostart ya no existe
ls ~/.config/autostart/antivirus-linux.desktop  # Debe mostrar "No such file"

# Verificar que la carpeta del proyecto ya no existe (si elegiste eliminar todo)
ls ~/Documentos/INFORMATICA/PROGRAMACIÓN/PROYECTOS/ANTIVIRUS_LINUX  # Debe mostrar "No such file"
```

---

## 🔧 Solución de problemas comunes

### Error: "Permission denied: '/opt/antivirus_cuarentena'"
**Solución**: Cambia la ruta de cuarentena en `config.json`:
```json
"cuarentena": "/home/tu_usuario/antivirus_cuarentena"
```

### Error: "freshclam: ERROR: Problem with internal logger"
**Solución**: Repara los permisos del log:
```bash
sudo rm /var/log/clamav/freshclam.log
sudo touch /var/log/clamav/freshclam.log
sudo chown clamav:clamav /var/log/clamav/freshclam.log
sudo chmod 644 /var/log/clamav/freshclam.log
sudo freshclam
```

### Error: "ModuleNotFoundError: No module named 'apscheduler'"
**Solución**: Asegúrate de estar dentro del entorno virtual:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Error: "No se pudo crear el acceso directo en el escritorio"
**Solución**: Crea el acceso directo manualmente:
```bash
cat > ~/Desktop/antivirus-linux.desktop << EOF
[Desktop Entry]
Name=Antivirus Profesional
Comment=Protege tu sistema Linux
Exec=$PWD/run.sh
Icon=$PWD/antivirus_linux_deamon.png
Terminal=false
Type=Application
Categories=System;Security;
EOF
chmod +x ~/Desktop/antivirus-linux.desktop
```

### Error: "El antivirus no se inicia automáticamente al encender la PC"
**Solución**: Verifica que el archivo de autostart existe:
```bash
ls ~/.config/autostart/antivirus-linux.desktop
```
Si no existe, créalo manualmente:
```bash
cat > ~/.config/autostart/antivirus-linux.desktop << EOF
[Desktop Entry]
Name=Antivirus Profesional (Daemon)
Comment=Inicia el antivirus al encender la PC
Exec=$PWD/run.sh
Icon=$PWD/antivirus_linux_deamon.png
Terminal=false
Type=Application
Categories=System;Security;
X-GNOME-Autostart-enabled=true
EOF
```

---

## 📌 Resumen de comandos rápidos

| Acción | Comando |
|--------|---------|
| **Instalar** | `chmod +x install.sh && ./install.sh` |
| **Iniciar** | `./run.sh` |
| **Desinstalar** | `chmod +x uninstall.sh && ./uninstall.sh` |

---

## 📞 Soporte

Si encuentras algún problema durante la instalación o desinstalación, abre un issue en el repositorio de GitHub.

---

**¡Protege tu sistema Linux con esta herramienta profesional!** 🛡️


---

## 📌 ¿Qué incluye este archivo?

- ✅ **Instrucciones paso a paso** para instalar con `install.sh`.
- ✅ **Instrucciones paso a paso** para desinstalar con `uninstall.sh`.
- ✅ **Configuración de sudo** para `freshclam` e `iptables`.
- ✅ **Solución de problemas** con los errores más comunes.
- ✅ **Comandos rápidos** y **resumen visual**.
- ✅ **Verificaciones** para confirmar que todo funciona correctamente.

---

## ▶️ Para aplicarlo

Copia y pega el bloque en tu terminal (estando en la raíz del proyecto) y el archivo `Installation_instructions.md` quedará listo para incluir en el repositorio.

¡Tu proyecto ahora tiene documentación profesional! 📚
