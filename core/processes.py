import psutil, os
from .scanner import ScannerEngine, Colors

class ProcessScanner:
    def __init__(self, engine: ScannerEngine):
        self.engine = engine

    def scan_all(self):
        print(f"{Colors.BOLD}{Colors.BLUE}[+] Escaneando procesos en memoria...{Colors.RESET}")
        infectados = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                pid = proc.info['pid']
                exe = proc.info['exe']
                if exe and os.path.exists(exe):
                    infectado, mot = self.engine.scan_file(exe)
                    if infectado:
                        infectados.append((pid, exe, mot))
                        print(f"{Colors.RED}💀 PROCESO MALICIOSO: PID {pid} -> {exe}{Colors.RESET}")
                        print(f"   {mot}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return infectados
