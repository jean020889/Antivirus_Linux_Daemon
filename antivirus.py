#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Antivirus Pro - Suite de Seguridad Profesional para Linux
Punto de entrada principal (daemon + CLI)
"""

import os
import sys
import json
import signal
import argparse
import threading
import time
from datetime import datetime

# Añadir el directorio actual al path para imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import ScannerEngine
from core.scheduler import ScanScheduler
from core.realtime import RealtimeMonitor
from core.processes import ProcessScanner
from core.memory_scanner import MemoryScanner

# eBPF es opcional: requiere BCC instalado en el sistema
try:
    from core.ebpf_telemetry import EBPFTelemetry
    HAS_EBPF = True
except ImportError:
    EBPFTelemetry = None
    HAS_EBPF = False


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class AntivirusDaemon:
    """Demonio principal que coordina todos los módulos de seguridad."""

    def __init__(self, config_path="config.json"):
        self.config = self._load_config(config_path)
        self.engine = None
        self.scheduler = None
        self.realtime = None
        self.running = False
        self.threads = []
        self._setup_logging()
        self._setup_signal_handlers()

    def _load_config(self, config_path):
        """Carga la configuración desde JSON."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            print(f"{Colors.GREEN}[+] Configuración cargada desde {config_path}{Colors.RESET}")
            return config
        except FileNotFoundError:
            print(f"{Colors.YELLOW}[!] {config_path} no encontrado. Usando valores por defecto.{Colors.RESET}")
            return {
                "cuarentena": "/opt/antivirus_cuarentena",
                "logs": "./logs",
                "max_firmas": 300000,
                "full_scan_hour": "03:00",
                "realtime_dirs": ["/home", "/tmp"],
                "scan_archives": True,
                "temp_extract": "/tmp/av_extract"
            }
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[!] Error parseando config.json: {e}{Colors.RESET}")
            sys.exit(1)

    def _setup_logging(self):
        """Configura el sistema de logs con rotación."""
        log_dir = self.config.get('logs', './logs')
        os.makedirs(log_dir, exist_ok=True)

        import logging
        from logging.handlers import RotatingFileHandler

        log_file = os.path.join(log_dir, 'antivirus.log')
        handler = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5
        )
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))

        self.logger = logging.getLogger('antivirus-pro')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        self.logger.info("=" * 60)
        self.logger.info("Antivirus Pro iniciado")

    def _setup_signal_handlers(self):
        """Registra manejadores de señales para apagado limpio."""
        signal.signal(signal.SIGTERM, self._shutdown_handler)
        signal.signal(signal.SIGINT, self._shutdown_handler)

    def _shutdown_handler(self, signum, frame):
        """Maneja el apagado del daemon."""
        print(f"\n{Colors.YELLOW}[!] Señal {signum} recibida. Apagando...{Colors.RESET}")
        self.logger.info(f"Señal {signum} recibida. Apagando daemon.")
        self.stop()
        sys.exit(0)

    def start(self):
        """Inicia todos los módulos del daemon."""
        print(f"{Colors.BOLD}{Colors.BLUE}")
        print("=" * 60)
        print("  🛡️  ANTIVIRUS PRO - Suite de Seguridad para Linux")
        print("=" * 60)
        print(f"{Colors.RESET}")

        self.running = True

        # 1. Inicializar motor de escaneo (carga firmas ClamAV + YARA + CTI)
        print(f"{Colors.BLUE}[+] Inicializando motor de escaneo...{Colors.RESET}")
        self.engine = ScannerEngine(self.config)
        self.logger.info(f"Motor iniciado con {self.engine.total_firmas} firmas")

        # 2. Iniciar planificador (full scan + folder scan)
        print(f"{Colors.BLUE}[+] Iniciando planificador de tareas...{Colors.RESET}")
        self.scheduler = ScanScheduler(self.engine, self.config)
        self.scheduler.start()

        # 3. Iniciar vigilancia en tiempo real (inotify)
        if self.config.get('realtime_dirs'):
            print(f"{Colors.BLUE}[+] Iniciando vigilancia en tiempo real...{Colors.RESET}")
            self.realtime = RealtimeMonitor(self.engine, self.config)
            t_realtime = threading.Thread(
                target=self.realtime.start, daemon=True, name="realtime"
            )
            t_realtime.start()
            self.threads.append(t_realtime)

        print(f"{Colors.GREEN}")
        print("=" * 60)
        print("  ✅ Antivirus Pro ejecutándose en modo daemon")
        print(f"  📁 Cuarentena: {self.config.get('cuarentena')}")
        print(f"  📋 Logs: {self.config.get('logs')}/antivirus.log")
        print(f"  ⏰ Full scan programado: {self.config.get('full_scan_hour')}")
        print("=" * 60)
        print(f"{Colors.RESET}")

        # Mantener el proceso vivo
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Detiene todos los módulos limpiamente."""
        print(f"{Colors.YELLOW}[!] Deteniendo servicios...{Colors.RESET}")
        self.running = False

        if self.scheduler:
            try:
                self.scheduler.scheduler.shutdown(wait=False)
                print(f"{Colors.GREEN}[+] Planificador detenido{Colors.RESET}")
            except Exception as e:
                self.logger.error(f"Error deteniendo scheduler: {e}")

        if self.realtime:
            try:
                self.realtime.stop()
                print(f"{Colors.GREEN}[+] Vigilancia en tiempo real detenida{Colors.RESET}")
            except Exception:
                pass

        self.logger.info("Antivirus Pro detenido")
        print(f"{Colors.GREEN}[+] Daemon detenido correctamente.{Colors.RESET}")

    def scan_once(self, path):
        """Ejecuta un escaneo puntual (modo CLI, sin daemon)."""
        print(f"{Colors.BOLD}{Colors.BLUE}[+] Escaneo puntual: {path}{Colors.RESET}")
        self.engine = ScannerEngine(self.config)

        if not os.path.exists(path):
            print(f"{Colors.RED}[!] Ruta no existe: {path}{Colors.RESET}")
            return

        count = 0
        threats = 0
        for root, dirs, files in os.walk(path):
            if root in ['/proc', '/sys', '/dev', '/run']:
                dirs.clear()
                continue
            for f in files:
                full = os.path.join(root, f)
                if not os.path.isfile(full) or os.path.islink(full):
                    continue
                count += 1
                try:
                    infectado, motivo = self.engine.scan_file(full)
                    if infectado:
                        threats += 1
                        print(f"{Colors.RED}💀 {full} -> {motivo}{Colors.RESET}")
                        self.engine.quarantine(full, motivo)
                    else:
                        sys.stdout.write(f"{Colors.GREEN}.{Colors.RESET}")
                        sys.stdout.flush()
                except Exception:
                    continue

        print(f"\n{Colors.BOLD}")
        print(f"Archivos analizados: {count}")
        print(f"Amenazas encontradas: {threats}")
        print(f"{Colors.RESET}")

    def scan_processes(self):
        """Escaneo de procesos en memoria."""
        self.engine = ScannerEngine(self.config)
        ps = ProcessScanner(self.engine)
        ps.scan_all()

    def scan_memory(self):
        """Escaneo fileless con YARA en memoria (requiere root)."""
        self.engine = ScannerEngine(self.config)
        if not self.engine.yara:
            print(f"{Colors.RED}[!] Motor YARA no disponible{Colors.RESET}")
            return
        ms = MemoryScanner(self.engine.yara)
        ms.scan_all_processes()

    def update_signatures(self):
        """Actualiza firmas manualmente."""
        print(f"{Colors.BLUE}[+] Actualizando firmas ClamAV...{Colors.RESET}")
        import subprocess
        try:
            result = subprocess.run(
                ['sudo', 'freshclam'], capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                print(f"{Colors.GREEN}[+] Firmas ClamAV actualizadas{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[!] freshclam: {result.stderr}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

        # Actualizar reglas YARA
        try:
            from core.yara_engine import YaraEngine
            y = YaraEngine(
                rules_dir=self.config.get('yara_rules_dir', './yara_rules')
            )
            y.update_rules()
            print(f"{Colors.GREEN}[+] Reglas YARA actualizadas{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] YARA: {e}{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Antivirus Pro - Suite de Seguridad para Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s --daemon                 # Ejecutar como daemon (todos los módulos)
  %(prog)s --scan /home             # Escaneo puntual de una ruta
  %(prog)s --scan-processes         # Escanear procesos en ejecución
  %(prog)s --scan-memory            # Escaneo fileless (requiere root)
  %(prog)s --update                 # Actualizar firmas manualmente
  %(prog)s --config /ruta/config.json
        """
    )

    parser.add_argument('--daemon', '-d', action='store_true',
                        help='Ejecutar como daemon (todos los módulos)')
    parser.add_argument('--scan', '-s', metavar='RUTA',
                        help='Escaneo puntual de una ruta específica')
    parser.add_argument('--scan-processes', action='store_true',
                        help='Escanear procesos en ejecución')
    parser.add_argument('--scan-memory', action='store_true',
                        help='Escaneo fileless en memoria (requiere root)')
    parser.add_argument('--update', '-u', action='store_true',
                        help='Actualizar firmas manualmente')
    parser.add_argument('--config', '-c', default='config.json',
                        help='Ruta al archivo de configuración (default: config.json)')

    args = parser.parse_args()

    # Verificar que se ejecuta como root para ciertas operaciones
    if args.daemon or args.scan_memory:
        if os.geteuid() != 0:
            print(f"{Colors.YELLOW}[!] Advertencia: Se recomienda ejecutar como root "
                  f"para acceso completo a /proc y /var/lib/clamav{Colors.RESET}")

    app = AntivirusDaemon(args.config)

    if args.update:
        app.update_signatures()
    elif args.scan:
        app.scan_once(args.scan)
    elif args.scan_processes:
        app.scan_processes()
    elif args.scan_memory:
        app.scan_memory()
    elif args.daemon:
        app.start()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()


# ============================================
# EXTENSIÓN: eBPF Telemetry
# ============================================
def _start_ebpf_telemetry(self):
    """Inicia telemetría eBPF (extensión)."""
    try:
        from core.db import DB

        db = DB()

        def handle_event(event):
            """Procesa un evento eBPF."""
            try:
                hostname = os.uname().nodename
                with db.cursor() as cur:
                    cur.execute("SELECT id FROM endpoints WHERE hostname = %s", (hostname,))
                    row = cur.fetchone()
                    if not row:
                        # Auto-registrar
                        ep_id = db.upsert_endpoint(hostname=hostname)
                    else:
                        ep_id = row['id']

                    cur.execute("""
                        INSERT INTO telemetry (endpoint_id, event_type, event_data,
                                              process_pid, process_name, process_exe,
                                              file_path, network_dst_ip, network_dst_port,
                                              timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """, (
                        ep_id,
                        event.get('event_type', 'unknown'),
                        json.dumps(event),
                        event.get('process_pid'),
                        event.get('process_name'),
                        event.get('process_exe'),
                        event.get('file_path'),
                        event.get('network_dst_ip'),
                        event.get('network_dst_port'),
                    ))
            except Exception:
                pass

        self.ebpf = EBPFTelemetry(self.config, on_event=handle_event)
        self.ebpf.start()
        print(f"[+] eBPF telemetry iniciada (mode: {self.ebpf.mode})")
    except Exception as e:
        print(f"[!] eBPF no disponible: {e}")
        self.ebpf = None




# ============================================
# INTEGRACIÓN eBPF - Parche directo a AntivirusDaemon
# ============================================
def _integrate_ebpf(self):
    """Integra eBPF telemetría al daemon."""
    if not HAS_EBPF:
        print("[!] eBPF no disponible (BCC no instalado)")
        return
    try:
        import os as _os
        from core.db import DB
        
        db = DB()
        
        def handle_event(event):
            try:
                hostname = _os.uname().nodename
                with db.cursor() as cur:
                    cur.execute("SELECT id FROM endpoints WHERE hostname = %s", (hostname,))
                    row = cur.fetchone()
                    if row:
                        ep_id = row['id']
                    else:
                        ep_id = db.upsert_endpoint(hostname=hostname)
                    
                    import json
                    cur.execute("""
                        INSERT INTO telemetry (endpoint_id, event_type, event_data,
                                              process_pid, process_name, process_exe,
                                              file_path, network_dst_ip, network_dst_port,
                                              timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """, (
                        ep_id, event.get('event_type', 'unknown'),
                        json.dumps(event),
                        event.get('process_pid'),
                        event.get('process_name'),
                        event.get('process_exe'),
                        event.get('file_path'),
                        event.get('network_dst_ip'),
                        event.get('network_dst_port'),
                    ))
            except Exception:
                pass
        
        self.ebpf = EBPFTelemetry(self.config, on_event=handle_event)
        self.ebpf.start()
        print(f"[+] ✅ eBPF Telemetry iniciada (mode: {self.ebpf.mode})")
    except Exception as e:
        print(f"[!] eBPF falló: {e}")
        self.ebpf = None


# Monkey-patch: extender start() de AntivirusDaemon
_orig_start = AntivirusDaemon.start
def _extended_start(self):
    # Arrancar el start original en un thread secundario
    import threading
    t = threading.Thread(target=_orig_start, args=(self,), daemon=True)
    t.start()
    
    # Esperar 5 segundos a que cargue
    import time
    time.sleep(5)
    
    # Arrancar eBPF
    _integrate_ebpf(self)
    
    # Mantener vivo el proceso principal
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

AntivirusDaemon.start = _extended_start
