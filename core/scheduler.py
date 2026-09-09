import os, time
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from .scanner import Colors

class ScanScheduler:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.scheduler = BackgroundScheduler(timezone='America/Guayaquil')

    def _full_scan_job(self, task_name):
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[SCHEDULER] Ejecutando: {task_name}{Colors.RESET}")
        os.nice(10)
        for root, dirs, files in os.walk('/'):
            if root in ['/proc', '/sys', '/dev', '/run']:
                continue
            for f in files:
                path = os.path.join(root, f)
                if os.path.isfile(path) and not os.path.islink(path):
                    try:
                        inf, mot = self.engine.scan_file(path)
                        if inf:
                            self.engine.quarantine(path, mot)
                            print(f"{Colors.RED}[FULL] {path} -> {mot}{Colors.RESET}")
                    except:
                        continue
        print(f"{Colors.GREEN}[+] Full scan completado.{Colors.RESET}")

    def _folder_scan_job(self, task_name, folder_path):
        if not os.path.exists(folder_path):
            print(f"{Colors.RED}[!] Carpeta {folder_path} no existe.{Colors.RESET}")
            return
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[SCHEDULER] Ejecutando: {task_name} -> {folder_path}{Colors.RESET}")
        os.nice(10)
        for root, _, files in os.walk(folder_path):
            for f in files:
                path = os.path.join(root, f)
                if os.path.isfile(path) and not os.path.islink(path):
                    try:
                        inf, mot = self.engine.scan_file(path)
                        if inf:
                            self.engine.quarantine(path, mot)
                            print(f"{Colors.RED}[FOLDER] {path} -> {mot}{Colors.RESET}")
                    except:
                        continue
        print(f"{Colors.GREEN}[+] Escaneo de carpeta completado.{Colors.RESET}")

    def start(self):
        tasks = self.config.get('scheduled_scans', [])
        if not tasks:
            print(f"{Colors.YELLOW}[!] No hay tareas programadas.{Colors.RESET}")
            return
        jobs_added = 0
        for task in tasks:
            if not task.get('active', True):
                print(f"{Colors.YELLOW}[i] Tarea '{task.get('name')}' desactivada.{Colors.RESET}")
                continue
            task_id = task.get('id', jobs_added + 1)
            task_name = task.get('name', f'Tarea_{task_id}')
            task_type = task.get('type')
            hour = int(task.get('hour', 0))
            minute = int(task.get('minute', 0))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                print(f"{Colors.RED}[!] Hora inválida para {task_name}.{Colors.RESET}")
                continue
            if task_type == 'full_system':
                self.scheduler.add_job(self._full_scan_job, CronTrigger(hour=hour, minute=minute), args=[task_name], id=f"task_{task_id}")
                print(f"{Colors.GREEN}[+] Programado: {task_name} -> {hour:02d}:{minute:02d} (Full System){Colors.RESET}")
                jobs_added += 1
            elif task_type == 'folder':
                folder_path = task.get('folder_path', '')
                if not folder_path:
                    print(f"{Colors.RED}[!] Falta folder_path para {task_name}.{Colors.RESET}")
                    continue
                self.scheduler.add_job(self._folder_scan_job, CronTrigger(hour=hour, minute=minute), args=[task_name, folder_path], id=f"task_{task_id}")
                print(f"{Colors.GREEN}[+] Programado: {task_name} -> {hour:02d}:{minute:02d} (Carpeta: {folder_path}){Colors.RESET}")
                jobs_added += 1
            else:
                print(f"{Colors.RED}[!] Tipo '{task_type}' desconocido.{Colors.RESET}")
        if jobs_added == 0:
            print(f"{Colors.RED}[!] No se programó ninguna tarea válida.{Colors.RESET}")
        else:
            self.scheduler.start()
            print(f"{Colors.BOLD}{Colors.GREEN}[+] Planificador activo con {jobs_added} tareas.{Colors.RESET}")
