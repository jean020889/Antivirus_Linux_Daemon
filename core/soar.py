# core/soar.py
"""
Motor SOAR (Security Orchestration, Automation and Response).

Acciones automatizadas:
- kill_process: mata un proceso malicioso
- quarantine_file: mueve archivo a cuarentena cifrada
- block_ip: bloquea IP con iptables
- isolate_endpoint: aísla el endpoint (bloquea todo el tráfico excepto management)
- disable_user: deshabilita un usuario
- collect_forensics: captura evidencias (ps, netstat, lsof, memoria)

Cada acción se registra en PostgreSQL (tabla responses).
"""

import os
import subprocess
import time
import signal
import json
import shutil
from datetime import datetime

from core.crypto import CryptoEngine


class SOAREngine:
    def __init__(self, config):
        self.config = config
        self.quarantine_dir = self._get_quarantine_dir()
        self.isolated = False
        self.blocked_ips = set()
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def _get_quarantine_dir(self):
        if os.geteuid() == 0:
            return self.config.get('cuarentena', '/opt/antivirus_cuarentena')
        return os.path.expanduser('~/.av_cuarentena')

    # ============================================
    # ACCIONES SOAR
    # ============================================

    def kill_process(self, pid, reason="SOAR action"):
        """Mata un proceso por PID."""
        result = {"action": "kill_process", "pid": pid, "success": False}
        start = time.time()
        try:
            # Intentar SIGTERM primero
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
            # Verificar si sigue vivo
            try:
                os.kill(pid, 0)
                # Sigue vivo, SIGKILL
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

            result["success"] = True
            result["reason"] = reason
            result["duration_ms"] = int((time.time() - start) * 1000)
        except ProcessLookupError:
            result["error"] = "Proceso no existe"
        except PermissionError:
            result["error"] = "Sin permisos (requiere root)"
        except Exception as e:
            result["error"] = str(e)

        self._log_response(result)
        return result

    def kill_process_tree(self, pid, reason="SOAR kill tree"):
        """Mata un proceso y todos sus hijos."""
        result = {"action": "kill_process_tree", "pid": pid, "success": False, "children": []}
        try:
            import psutil
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                    result["children"].append(child.pid)
                except Exception:
                    pass
            parent.kill()
            result["success"] = True
            result["reason"] = reason
        except Exception as e:
            result["error"] = str(e)
        self._log_response(result)
        return result

    def quarantine_file(self, filepath, reason="SOAR quarantine"):
        """Mueve archivo a cuarentena CIFRADO con AES-256-GCM."""
        result = {"action": "quarantine_file", "file": filepath, "success": False}
        try:
            if not os.path.exists(filepath):
                result["error"] = "Archivo no existe"
                self._log_response(result)
                return result

            # Clave de cifrado obligatoria
            password = os.environ.get('AV_QUARANTINE_KEY')
            if not password:
                raise RuntimeError(
                    "Falta AV_QUARANTINE_KEY. Configúrala en .env "
                    "(genera con: python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
                )
            if password in ("changeme", "CAMBIA_ESTO"):
                raise RuntimeError("AV_QUARANTINE_KEY tiene el valor por defecto. Cámbialo.")

            timestamp = int(time.time())
            basename = os.path.basename(filepath)
            dest = os.path.join(self.quarantine_dir, f"{timestamp}_{basename}.enc")

            # Cifrar (CryptoEngine.encrypt_file escribe el .enc)
            CryptoEngine.encrypt_file(filepath, dest, password)
            os.chmod(dest, 0o600)

            # Solo borrar el original si el cifrado tuvo éxito
            try:
                os.remove(filepath)
            except OSError as e:
                result["warning"] = f"No se pudo borrar original: {e}"

            # Log acompañante (sin datos sensibles)
            with open(f"{dest}.log", 'w') as f:
                f.write(f"Original: {filepath}\n")
                f.write(f"Reason: {reason}\n")
                f.write(f"Date: {datetime.now().isoformat()}\n")
                f.write(f"Size: {os.path.getsize(dest)} bytes (encrypted)\n")
                f.write(f"Format: AVP1 (AES-256-GCM, PBKDF2-600k)\n")

            result["success"] = True
            result["dest"] = dest
            result["reason"] = reason
        except Exception as e:
            result["error"] = str(e)
        self._log_response(result)
        return result

    def block_ip(self, ip, reason="SOAR block IP"):
        """Bloquea una IP con iptables."""
        result = {"action": "block_ip", "ip": ip, "success": False}
        try:
            # Verificar si ya está bloqueada
            if ip in self.blocked_ips:
                result["success"] = True
                result["note"] = "Ya bloqueada"
                self._log_response(result)
                return result

            # Añadir regla iptables
            subprocess.run(
                ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ['iptables', '-I', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                check=True, capture_output=True, timeout=10
            )
            self.blocked_ips.add(ip)
            result["success"] = True
            result["reason"] = reason
        except subprocess.CalledProcessError as e:
            result["error"] = f"iptables falló: {e.stderr.decode() if e.stderr else str(e)}"
        except FileNotFoundError:
            result["error"] = "iptables no instalado"
        except Exception as e:
            result["error"] = str(e)
        self._log_response(result)
        return result

    def unblock_ip(self, ip):
        """Desbloquea una IP."""
        result = {"action": "unblock_ip", "ip": ip, "success": False}
        try:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                         capture_output=True, timeout=10)
            subprocess.run(['iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                         capture_output=True, timeout=10)
            self.blocked_ips.discard(ip)
            result["success"] = True
        except Exception as e:
            result["error"] = str(e)
        self._log_response(result)
        return result

    def isolate_endpoint(self, management_ips=None, reason="SOAR isolate"):
        """
        Aísla el endpoint: bloquea TODO excepto IPs de management.
        Útil en caso de compromiso confirmado.
        """
        management_ips = management_ips or []
        result = {"action": "isolate_endpoint", "success": False, "management_ips": management_ips}
        try:
            # Política por defecto: DROP
            subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], check=True, capture_output=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'], check=True, capture_output=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'], check=True, capture_output=True)

            # Permitir loopback
            subprocess.run(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True, capture_output=True)
            subprocess.run(['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'], check=True, capture_output=True)

            # Permitir IPs de management
            for ip in management_ips:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'ACCEPT'], check=True, capture_output=True)
                subprocess.run(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'ACCEPT'], check=True, capture_output=True)

            # Permitir DNS (para que pueda resolver)
            subprocess.run(['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'],
                         check=True, capture_output=True)

            self.isolated = True
            result["success"] = True
            result["reason"] = reason
        except Exception as e:
            result["error"] = str(e)
        self._log_response(result)
        return result

    def unisolate_endpoint(self):
        """Quita el aislamiento."""
        result = {"action": "unisolate_endpoint", "success": False}
        try:
            subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True, capture_output=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True, capture_output=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True, capture_output=True)
            subprocess.run(['iptables', '-F'], check=True, capture_output=True)
            self.isolated = False
            result["success"] = True
        except Exception as e:
            result["error"] = str(e)
        self._log_response(result)
        return result

    def disable_user(self, username, reason="SOAR disable user"):
        """Deshabilita un usuario (lock password)."""
        result = {"action": "disable_user", "user": username, "success": False}
        try:
            subprocess.run(['usermod', '-L', username], check=True, capture_output=True, timeout=10)
            subprocess.run(['usermod', '-s', '/usr/sbin/nologin', username],
                         check=True, capture_output=True, timeout=10)
            result["success"] = True
            result["reason"] = reason
        except Exception as e:
            result["error"] = str(e)
        self._log_response(result)
        return result

    def collect_forensics(self, output_dir=None):
        """Captura evidencias forenses del sistema."""
        output_dir = output_dir or f"/tmp/forensics_{int(time.time())}"
        os.makedirs(output_dir, exist_ok=True)
        result = {"action": "collect_forensics", "success": False, "output_dir": output_dir, "files": []}
        try:
            commands = {
                "ps_aux.txt": ["ps", "aux"],
                "netstat.txt": ["ss", "-tunap"],
                "lsof.txt": ["lsof", "-i", "-n", "-P"],
                "users.txt": ["who", "-a"],
                "last.txt": ["last", "-a"],
                "crontab.txt": ["crontab", "-l"],
                "systemd_units.txt": ["systemctl", "list-units", "--type=service"],
                "iptables.txt": ["iptables", "-L", "-n", "-v"],
                "environment.txt": ["env"],
                "mounts.txt": ["mount"],
                "kernlog.txt": ["dmesg", "-T"],
                "cpuinfo.txt": ["cat", "/proc/cpuinfo"],
                "meminfo.txt": ["cat", "/proc/meminfo"],
            }
            for fname, cmd in commands.items():
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    with open(os.path.join(output_dir, fname), 'w') as f:
                        f.write(proc.stdout)
                    result["files"].append(fname)
                except Exception:
                    pass

            # Copiar cuarentena
            try:
                if os.path.exists(self.quarantine_dir):
                    shutil.copytree(self.quarantine_dir,
                                  os.path.join(output_dir, "quarantine"),
                                  dirs_exist_ok=True)
                    result["files"].append("quarantine/")
            except Exception:
                pass

            # Hash de todos los archivos
            import hashlib
            manifest = {}
            for root, _, files in os.walk(output_dir):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
                        manifest[p] = h
                    except Exception:
                        pass
            with open(os.path.join(output_dir, "manifest.json"), 'w') as f:
                json.dump(manifest, f, indent=2)

            result["success"] = True
        except Exception as e:
            result["error"] = str(e)
        self._log_response(result)
        return result

    def _log_response(self, result):
        """Loguea la acción en PostgreSQL si está disponible."""
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=os.environ.get('AV_DB_HOST', 'localhost'),
                port=os.environ.get('AV_DB_PORT', '5432'),
                database=os.environ.get('AV_DB_NAME', 'antivirus_pro'),
                user=os.environ.get('AV_DB_USER', 'antivirus'),
                password=os.environ.get('AV_DB_PASS', 'changeme')
            )
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO responses (endpoint_id, action, target, action_result, success, executed_at)
                VALUES (
                    (SELECT id FROM endpoints WHERE hostname = %s LIMIT 1),
                    %s, %s, %s, %s, NOW()
                )
            """, (
                os.uname().nodename,
                result.get('action'),
                result.get('pid') or result.get('file') or result.get('ip') or result.get('user'),
                json.dumps(result),
                result.get('success', False)
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass  # No fallar si no hay DB
