# core/scheduler.py
import os
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; RESET = '\033[0m'; BOLD = '\033[1m'

class ScanScheduler:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.scheduler = BackgroundScheduler()

    def full_scan_job(self):
        print(f"{Colors.BOLD}{Colors.YELLOW}[SCHEDULER] Análisis COMPLETO...{Colors.RESET}")
        os.nice(10)
        for root, dirs, files in os.walk('/'):
            if root in ['/proc', '/sys', '/dev', '/run']:
                dirs.clear()
                continue
            for f in files:
                path = os.path.join(root, f)
                if os.path.isfile(path) and not os.path.islink(path):
                    inf, mot = self.engine.scan_file(path)
                    if inf:
                        self.engine.quarantine(path, mot)
                        print(f"{Colors.RED}[FULL] {path} -> {mot}{Colors.RESET}")

    def folder_scan_job(self):
        folder = self.config.get('folder_scan', {}).get('ruta')
        if not folder or not os.path.exists(folder):
            return
        print(f"{Colors.YELLOW}[SCHEDULER] Escaneando carpeta: {folder}{Colors.RESET}")
        for root, _, files in os.walk(folder):
            for f in files:
                path = os.path.join(root, f)
                if os.path.isfile(path):
                    inf, mot = self.engine.scan_file(path)
                    if inf:
                        self.engine.quarantine(path, mot)

    def start(self):
        full_hour = self.config.get('full_scan_hour', '03:00').split(':')
        self.scheduler.add_job(
            self.full_scan_job,
            CronTrigger(hour=int(full_hour[0]), minute=int(full_hour[1]))
        )

        folder_cfg = self.config.get('folder_scan', {})
        folder_hour = folder_cfg.get('hora', '14:30').split(':')
        self.scheduler.add_job(
            self.folder_scan_job,
            CronTrigger(hour=int(folder_hour[0]), minute=int(folder_hour[1]))
        )

        self.scheduler.start()
        print(f"{Colors.GREEN}[+] Planificador activo. "
              f"Full scan a las {self.config.get('full_scan_hour')}{Colors.RESET}")
