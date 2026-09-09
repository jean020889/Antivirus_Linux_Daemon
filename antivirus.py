#!/usr/bin/env python3
import sys, os, json, subprocess, threading, signal, time
from core.scanner import ScannerEngine, Colors
from core.scheduler import ScanScheduler
from core.realtime import RealtimeMonitor
from core.processes import ProcessScanner
from core.archives import ArchiveScanner

CONFIG_PATH = "config.json"
PID_FILE = "/tmp/antivirus_daemon.pid"

class AntivirusDaemon:
    def __init__(self):
        with open(CONFIG_PATH, 'r') as f:
            self.config = json.load(f)
        self.update_signatures()
        self.engine = ScannerEngine(self.config)
        self.scheduler = ScanScheduler(self.engine, self.config)
        self.realtime = RealtimeMonitor(self.engine, self.config)
        self.process_scanner = ProcessScanner(self.engine)
        self.archive_scanner = ArchiveScanner(self.engine, self.config.get('temp_extract', '/tmp/av_extract'))
        self.running = True

    def update_signatures(self):
        print(f"{Colors.BLUE}[+] Actualizando firmas ClamAV...{Colors.RESET}")
        try:
            subprocess.run(['sudo', 'freshclam'], check=True, timeout=120)
            print(f"{Colors.GREEN}[+] Firmas actualizadas.{Colors.RESET}")
        except:
            print(f"{Colors.YELLOW}[!] Error en freshclam (puede estar actualizado).{Colors.RESET}")

    def manual_update(self):
        print(f"{Colors.BOLD}Actualización manual solicitada.{Colors.RESET}")
        self.update_signatures()
        self.engine.load_clamav_signatures()

    def run(self):
        threading.Thread(target=self.process_scanner.scan_all, daemon=True).start()
        self.scheduler.start()
        rt_thread = threading.Thread(target=self.realtime.start, daemon=True)
        rt_thread.start()
        print(f"{Colors.BOLD}{Colors.GREEN}🛡️  Antivirus Profesional ACTIVADO. Presiona Ctrl+C para detener.{Colors.RESET}")
        while self.running:
            time.sleep(1)

    def stop(self):
        self.running = False
        print("Apagando antivirus...")
        sys.exit(0)

def main():
    if os.path.exists(PID_FILE):
        print("El antivirus ya está en ejecución.")
        sys.exit(1)
    with open(PID_FILE, 'w') as f: f.write(str(os.getpid()))
    daemon = AntivirusDaemon()
    signal.signal(signal.SIGINT, lambda s, f: daemon.stop())
    signal.signal(signal.SIGTERM, lambda s, f: daemon.stop())
    if len(sys.argv) > 1:
        if sys.argv[1] == "--update":
            daemon.manual_update()
            sys.exit(0)
        elif sys.argv[1] == "--scan-memory":
            daemon.process_scanner.scan_all()
            sys.exit(0)
        elif sys.argv[1] == "--scan-folder":
            folder = sys.argv[2] if len(sys.argv) > 2 else os.getcwd()
            for root, _, files in os.walk(folder):
                for f in files:
                    path = os.path.join(root, f)
                    if os.path.isfile(path):
                        inf, mot = daemon.engine.scan_file(path)
                        if inf: print(f"{Colors.RED}[MANUAL] {path} -> {mot}{Colors.RESET}")
            sys.exit(0)
    daemon.run()

if __name__ == "__main__":
    main()
