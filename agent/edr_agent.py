# agent/edr_agent.py
"""
Agente EDR: se ejecuta en cada endpoint y reporta al servidor central.

Funciones:
- Heartbeat al servidor (cada 60s)
- Escaneo local con ClamAV + YARA + Sigma
- Envío de amenazas detectadas
- Envío de telemetría
- Ejecución de comandos del servidor (kill, quarantine, block_ip)
- Recogida de evidencias forenses
"""
import os
import sys
import json
import time
import socket
import platform
import hashlib
import threading
import subprocess
import signal
import psutil
import requests
from datetime import datetime
from pathlib import Path


class EDRAgent:
    def __init__(self, config_path="/opt/antivirus-pro/agent_config.json"):
        self.config = self._load_config(config_path)
        self.server_url = self.config.get('server_url', 'http://localhost:8002')
        self.api_key = self.config.get('api_key', '')
        self.hostname = socket.gethostname()
        self.running = False
        self.endpoint_id = None

        # Cliente HTTP con retry
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        })

    def _load_config(self, path):
        defaults = {
            "server_url": "http://localhost:8002",
            "api_key": "",
            "heartbeat_interval": 60,
            "telemetry_interval": 30,
            "scan_interval": 3600,
            "scan_paths": ["/tmp", "/var/tmp", "/home"],
        }
        if os.path.exists(path):
            try:
                with open(path) as f:
                    user_config = json.load(f)
                defaults.update(user_config)
            except Exception:
                pass
        return defaults

    # ============================================
    # COMUNICACIÓN CON SERVIDOR
    # ============================================
    def _post(self, endpoint, data):
        """POST al servidor con retry."""
        try:
            r = self.session.post(
                f"{self.server_url}{endpoint}",
                json=data,
                timeout=10
            )
            if r.status_code == 200:
                return r.json()
            else:
                print(f"[!] Server {r.status_code}: {r.text[:200]}")
                return None
        except requests.exceptions.ConnectionError:
            print(f"[!] Sin conexión al servidor")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def _get(self, endpoint):
        try:
            r = self.session.get(f"{self.server_url}{endpoint}", timeout=10)
            if r.status_code == 200:
                return r.json()
            return None
        except Exception:
            return None

    # ============================================
    # HEARTBEAT
    # ============================================
    def _collect_system_info(self):
        """Recoge información del sistema."""
        try:
            return {
                "hostname": self.hostname,
                "ip_address": self._get_ip(),
                "os_name": platform.system(),
                "os_version": platform.release(),
                "kernel_version": platform.version(),
                "agent_version": "2.0.0",
                "cpu_model": platform.processor(),
                "total_ram_mb": int(psutil.virtual_memory().total / 1024 / 1024),
                "mac_address": self._get_mac(),
            }
        except Exception:
            return {"hostname": self.hostname, "agent_version": "2.0.0"}

    def _get_ip(self):
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        return addr.address
        except Exception:
            pass
        return None

    def _get_mac(self):
        try:
            import uuid
            return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff)
                           for i in range(0, 48, 8)][::-1])
        except Exception:
            return None

    def heartbeat(self):
        """Envía heartbeat al servidor."""
        info = self._collect_system_info()
        result = self._post("/api/endpoints/heartbeat", info)
        if result and result.get('endpoint_id'):
            self.endpoint_id = result['endpoint_id']
            print(f"[+] Heartbeat OK, endpoint_id={self.endpoint_id}")
        return result

    # ============================================
    # REPORTE DE AMENAZAS
    # ============================================
    def report_threat(self, threat_data):
        """Reporta una amenaza al servidor."""
        threat_data['hostname'] = self.hostname
        return self._post("/api/threats/report", threat_data)

    # ============================================
    # TELEMETRÍA
    # ============================================
    def report_telemetry(self, events):
        """Reporta eventos de telemetría."""
        if not events:
            return
        return self._post("/api/telemetry/report", {
            "hostname": self.hostname,
            "events": events,
        })

    # ============================================
    # COMANDOS REMOTOS
    # ============================================
    def poll_commands(self):
        """Consulta comandos pendientes del servidor."""
        result = self._get(f"/api/commands/pending?hostname={self.hostname}")
        if not result:
            return []
        return result.get('commands', [])

    def execute_command(self, cmd):
        """Ejecuta un comando remoto."""
        action = cmd.get('command')
        args = cmd.get('command_args', {})
        result = {"command_id": cmd.get('id'), "success": False}

        try:
            if action == 'kill_process':
                pid = args.get('pid')
                os.kill(int(pid), signal.SIGKILL)
                result['success'] = True

            elif action == 'quarantine_file':
                from core.soar import SOAREngine
                soar = SOAREngine({})
                r = soar.quarantine_file(args.get('path'), "Remote SOAR")
                result['success'] = r['success']
                result['output'] = r

            elif action == 'block_ip':
                from core.soar import SOAREngine
                soar = SOAREngine({})
                r = soar.block_ip(args.get('ip'), "Remote SOAR")
                result['success'] = r['success']
                result['output'] = r

            elif action == 'scan_now':
                result['success'] = True
                threading.Thread(target=self.scan_paths, daemon=True).start()

            elif action == 'collect_forensics':
                from core.soar import SOAREngine
                soar = SOAREngine({})
                r = soar.collect_forensics()
                result['success'] = r['success']
                result['output'] = r

            else:
                result['error'] = f"Comando desconocido: {action}"

        except Exception as e:
            result['error'] = str(e)

        # Reportar resultado
        self._post(f"/api/commands/{cmd['id']}/result", result)
        return result

    # ============================================
    # ESCANEO LOCAL
    # ============================================
    def scan_paths(self):
        """Escanea los paths configurados y reporta amenazas."""
        try:
            sys.path.insert(0, '/opt/antivirus-pro')
            from core.scanner import ScannerEngine

            config = {"cuarentena": "/opt/antivirus_cuarentena"}
            engine = ScannerEngine(config)

            for path in self.config.get('scan_paths', []):
                if not os.path.exists(path):
                    continue
                print(f"[+] Escaneando {path}...")
                for root, dirs, files in os.walk(path):
                    # Excluir directorios del sistema
                    dirs[:] = [d for d in dirs if d not in
                              ('proc', 'sys', 'dev', 'run', '.cache')]
                    for f in files:
                        filepath = os.path.join(root, f)
                        if not os.path.isfile(filepath) or os.path.islink(filepath):
                            continue
                        try:
                            detected, reason = engine.scan_file(filepath)
                            if detected:
                                threat = {
                                    "hostname": self.hostname,
                                    "file_path": filepath,
                                    "threat_name": reason,
                                    "detection_engine": "clamav",
                                    "detection_type": "signature",
                                    "severity": "high",
                                    "confidence": 95,
                                }
                                # Quarantine local
                                q_result = engine.quarantine(filepath, reason)
                                if q_result:
                                    threat['quarantined'] = True
                                    threat['quarantine_path'] = q_result
                                # Reportar al servidor
                                self.report_threat(threat)
                                print(f"[!] Amenaza: {filepath} -> {reason}")
                        except Exception:
                            pass
        except Exception as e:
            print(f"[!] Error escaneando: {e}")

    # ============================================
    # LOOPS EN BACKGROUND
    # ============================================
    def _heartbeat_loop(self):
        """Loop de heartbeat."""
        interval = self.config.get('heartbeat_interval', 60)
        while self.running:
            try:
                self.heartbeat()
            except Exception as e:
                print(f"[!] Heartbeat error: {e}")
            time.sleep(interval)

    def _telemetry_loop(self):
        """Loop de telemetría."""
        interval = self.config.get('telemetry_interval', 30)
        seen_procs = set()
        while self.running:
            try:
                events = []
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                    try:
                        pid = proc.info['pid']
                        if pid in seen_procs:
                            continue
                        seen_procs.add(pid)
                        events.append({
                            "event_type": "process_start",
                            "process_pid": pid,
                            "process_name": proc.info['name'],
                            "process_exe": proc.info['exe'],
                            "process_user": proc.info['username'],
                            "process_cmdline": ' '.join(proc.info['cmdline'] or []),
                        })
                    except Exception:
                        continue

                if events:
                    self.report_telemetry(events)

                # Limitar memoria
                if len(seen_procs) > 100000:
                    seen_procs = set(list(seen_procs)[-50000:])
            except Exception as e:
                print(f"[!] Telemetry error: {e}")
            time.sleep(interval)

    def _commands_loop(self):
        """Loop de polling de comandos."""
        while self.running:
            try:
                commands = self.poll_commands()
                for cmd in commands:
                    print(f"[+] Ejecutando: {cmd.get('command')}")
                    self.execute_command(cmd)
            except Exception as e:
                print(f"[!] Commands error: {e}")
            time.sleep(15)

    # ============================================
    # START/STOP
    # ============================================
    def start(self):
        """Arranca el agente."""
        print(f"🛡️  EDR Agent v2.0.0")
        print(f"   Hostname: {self.hostname}")
        print(f"   Servidor: {self.server_url}")

        self.running = True

        # Heartbeat inicial
        self.heartbeat()

        # Lanzar threads
        threads = [
            threading.Thread(target=self._heartbeat_loop, daemon=True),
            threading.Thread(target=self._telemetry_loop, daemon=True),
            threading.Thread(target=self._commands_loop, daemon=True),
        ]
        for t in threads:
            t.start()

        print("[+] Agente ejecutándose")

        # Main loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        print("[+] Agente detenido")


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "/opt/antivirus-pro/agent_config.json"
    agent = EDRAgent(config_path)
    agent.start()


if __name__ == "__main__":
    main()
