#!/usr/bin/env python3
import json, os, sys

CONFIG_PATH = "config.json"

def load_config():
    if not os.path.exists(CONFIG_PATH):
        default = {
            "cuarentena": "/opt/antivirus_cuarentena",
            "logs": "./logs",
            "max_firmas": 300000,
            "temp_extract": "/tmp/av_extract",
            "realtime_dirs": ["/home", "/tmp", "/var/tmp"],
            "scheduled_scans": []
        }
        with open(CONFIG_PATH, 'w') as f:
            json.dump(default, f, indent=2)
        return default
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)
    print("✅ Configuración guardada correctamente.")

def list_tasks(config):
    tasks = config.get('scheduled_scans', [])
    if not tasks:
        print("📭 No hay tareas programadas.")
        return
    print("\n📋 LISTA DE TAREAS PROGRAMADAS:")
    print("-" * 60)
    for t in tasks:
        status = "✅ Activa" if t.get('active', True) else "❌ Inactiva"
        tipo = "Sistema Completo" if t.get('type') == 'full_system' else f"Carpeta: {t.get('folder_path', 'N/A')}"
        print(f"ID: {t.get('id')} | {t.get('name')}")
        print(f"   Hora: {t.get('hour', 0):02d}:{t.get('minute', 0):02d} | {status} | {tipo}")
    print("-" * 60)

def add_task(config):
    tasks = config.get('scheduled_scans', [])
    next_id = max([t.get('id', 0) for t in tasks]) + 1 if tasks else 1
    print("\n🆕 AGREGAR NUEVA TAREA PROGRAMADA")
    name = input("Nombre descriptivo de la tarea: ").strip() or f"Tarea_{next_id}"
    print("Tipo de escaneo:")
    print("  1. Sistema Completo (raíz)")
    print("  2. Carpeta específica")
    tipo_opcion = input("Selecciona (1 o 2): ").strip()
    if tipo_opcion == "1":
        task_type = "full_system"
        folder_path = None
    else:
        task_type = "folder"
        folder_path = input("Ruta de la carpeta: ").strip()
    try:
        hour = int(input("Hora (0-23): ").strip())
        minute = int(input("Minuto (0-59): ").strip())
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
    except ValueError:
        print("❌ Hora inválida.")
        return
    active = input("¿Activar? (s/n): ").strip().lower() == 's'
    new_task = {"id": next_id, "name": name, "type": task_type, "hour": hour, "minute": minute, "active": active}
    if folder_path:
        new_task["folder_path"] = folder_path
    tasks.append(new_task)
    config['scheduled_scans'] = tasks
    save_config(config)
    print(f"✅ Tarea '{name}' agregada con ID {next_id}.")

def delete_task(config):
    list_tasks(config)
    tasks = config.get('scheduled_scans', [])
    if not tasks: return
    try:
        task_id = int(input("ID a eliminar: ").strip())
        for i, t in enumerate(tasks):
            if t.get('id') == task_id:
                if input(f"¿Eliminar '{t.get('name')}'? (s/n): ").strip().lower() == 's':
                    del tasks[i]
                    config['scheduled_scans'] = tasks
                    save_config(config)
                    print("🗑️  Eliminada.")
                return
        print("❌ ID no encontrado.")
    except ValueError:
        print("❌ ID inválido.")

def toggle_task(config):
    list_tasks(config)
    tasks = config.get('scheduled_scans', [])
    if not tasks: return
    try:
        task_id = int(input("ID a activar/desactivar: ").strip())
        for t in tasks:
            if t.get('id') == task_id:
                t['active'] = not t.get('active', True)
                config['scheduled_scans'] = tasks
                save_config(config)
                print(f"✅ Tarea {'ACTIVADA' if t['active'] else 'DESACTIVADA'}.")
                return
        print("❌ ID no encontrado.")
    except ValueError:
        print("❌ ID inválido.")

def main():
    print("\n🛠️  CONFIGURADOR DE HORARIOS - ANTIVIRUS PROFESIONAL")
    print("=" * 50)
    config = load_config()
    while True:
        print("\n📌 OPCIONES:")
        print("  1. Listar tareas")
        print("  2. Agregar nueva tarea")
        print("  3. Eliminar tarea")
        print("  4. Activar/Desactivar tarea")
        print("  5. Salir")
        opcion = input("Selecciona: ").strip()
        if opcion == "1": list_tasks(config)
        elif opcion == "2": add_task(config)
        elif opcion == "3": delete_task(config)
        elif opcion == "4": toggle_task(config)
        elif opcion == "5":
            print("👋 Saliendo.")
            break
        else: print("❌ Opción inválida.")

if __name__ == "__main__":
    main()
