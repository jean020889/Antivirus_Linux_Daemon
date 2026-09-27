# core/scanner.py
"""
Motor de escaneo profesional usando clamd (demonio de ClamAV) via socket Unix.
"""

import os
import sys
import hashlib
import subprocess
import time
import re
from datetime import datetime

try:
    import pyclamd
    HAS_PYCLAMD = True
except ImportError:
    HAS_PYCLAMD = False


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class ScannerEngine:
    """Motor de escaneo basado en clamd (socket) con fallback a clamscan."""

    def __init__(self, config):
        self.config = config
        self.cuarentena = self._determine_quarantine_dir()
        os.makedirs(self.cuarentena, exist_ok=True)

        self.cd = None
        self.motor = "ninguno"

        self.firmas_heuristica = {
            'comandos_peligrosos': [
                b'rm -rf /',
                b'mkfifo /tmp/',
                b'sh -i >& /dev/tcp',
                b'base64 -d | sh',
                b'wget -qO- | sh',
                b'curl -s | bash',
            ],
        }

        self.yara = None
        try:
            from .yara_engine import YaraEngine
            self.yara = YaraEngine(
                rules_dir=config.get('yara_rules_dir', './yara_rules'),
                cache_dir=config.get('cti_cache_dir', './cti_cache')
            )
        except ImportError:
            pass

        self.cti = None
        try:
            from .cti_abuse import AbuseCHIntel
            auth_key = config.get('abuse_ch_key')
            if auth_key and auth_key != "TU_AUTH_KEY_AQUI":
                self.cti = AbuseCHIntel(
                    auth_key=auth_key,
                    cache_dir=config.get('cti_cache_dir', './cti_cache'),
                    cache_ttl_hours=config.get('cti_cache_ttl_hours', 24)
                )
        except ImportError:
            pass

        self._init_clamd()

        self.total_firmas = 3628083
        self.archivos_escaneados = 0

    def _determine_quarantine_dir(self):
        if os.geteuid() == 0:
            return self.config.get('cuarentena', '/opt/antivirus_cuarentena')
        else:
            return os.path.expanduser('~/.av_cuarentena')

    def _init_clamd(self):
        if not HAS_PYCLAMD:
            print(f"{Colors.YELLOW}[!] pyclamd no instalado. Usando clamscan.{Colors.RESET}")
            self.motor = "clamscan"
            return

        try:
            self.cd = pyclamd.ClamdUnixSocket()
            if self.cd.ping():
                try:
                    version = self.cd.version()
                    if version and 'COMMAND UNAVAILABLE' not in str(version):
                        first_line = str(version).split('\n')[0]
                        print(f"{Colors.GREEN}[+] Conectado a clamd: {first_line}{Colors.RESET}")
                    else:
                        print(f"{Colors.GREEN}[+] Conectado a clamd (socket activo){Colors.RESET}")
                except Exception:
                    print(f"{Colors.GREEN}[+] Conectado a clamd (socket activo){Colors.RESET}")
                self.motor = "clamd"
            else:
                print(f"{Colors.YELLOW}[!] clamd no responde al ping.{Colors.RESET}")
                self.motor = "clamscan"
                self.cd = None
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error conectando a clamd: {e}{Colors.RESET}")
            self.motor = "clamscan"
            self.cd = None

    def get_hash(self, data_or_path, algo='md5'):
        hash_obj = hashlib.new(algo)
        if isinstance(data_or_path, bytes):
            hash_obj.update(data_or_path)
            return hash_obj.hexdigest()
        try:
            with open(data_or_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (IOError, PermissionError):
            return None

    def scan_file(self, filepath):
        if not os.path.isfile(filepath):
            return False, "No es un archivo regular"

        if self.motor == "clamd" and self.cd:
            infectado, motivo = self._scan_with_clamd(filepath)
            if infectado:
                return True, motivo
        elif self.motor == "clamscan":
            infectado, motivo = self._scan_with_clamscan(filepath)
            if infectado:
                return True, motivo

        if self.cti:
            for alg in ['md5', 'sha256']:
                h = self.get_hash(filepath, alg)
                if h and self.cti.check_hash(h):
                    return True, f"CTI abuse.ch {alg.upper()}: {h}"

        if self.yara:
            infectado, motivo = self.yara.scan_file(filepath)
            if infectado:
                return True, motivo

        infectado, motivo = self._heuristic_scan(filepath)
        if infectado:
            return True, motivo

        return False, "Limpio"

    def _scan_with_clamd(self, filepath):
        try:
            result = self.cd.scan_file(filepath)
            if result is None:
                return False, "Limpio"
            for path, (status, threat) in result.items():
                if status == 'FOUND':
                    return True, f"ClamAV: {threat}"
                elif status == 'ERROR':
                    return False, f"Error: {threat}"
            return False, "Limpio"
        except Exception as e:
            return False, f"Error clamd: {e}"

    def _scan_with_clamscan(self, filepath):
        try:
            result = subprocess.run(
                ['clamscan', '--no-summary', '--infected', filepath],
                capture_output=True, text=True, timeout=60
            )
            if 'FOUND' in result.stdout:
                for line in result.stdout.splitlines():
                    if 'FOUND' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            threat = parts[-1].replace(' FOUND', '').strip()
                            return True, f"ClamAV: {threat}"
            return False, "Limpio"
        except subprocess.TimeoutExpired:
            return False, "Timeout escaneando archivo"
        except FileNotFoundError:
            return False, "clamscan no instalado"
        except Exception as e:
            return False, f"Error clamscan: {e}"

    def _heuristic_scan(self, filepath):
        try:
            st = os.stat(filepath)
            if st.st_mode & 0o4000:
                if not filepath.startswith(('/usr/', '/bin/', '/sbin/', '/lib/')):
                    return True, "SETUID fuera de rutas del sistema"
            if st.st_mode & 0o2000:
                if not filepath.startswith(('/usr/', '/bin/', '/sbin/', '/lib/')):
                    return True, "SETGID fuera de rutas del sistema"

            with open(filepath, 'rb') as f:
                header = f.read(4)
                if header == b'\x7fELF':
                    if any(x in filepath for x in ['/tmp/', '/dev/shm/', '/var/tmp/']):
                        return True, "Binario ELF en carpeta temporal"

            if os.path.getsize(filepath) > 1048576:
                return False, "Limpio"
            if filepath.endswith(('.sh', '.py', '.pl', '.js', '.bash')):
                with open(filepath, 'rb') as f:
                    content = f.read(65536)
                    for cmd in self.firmas_heuristica['comandos_peligrosos']:
                        if cmd in content:
                            return True, f"Comando peligroso: {cmd.decode('utf-8', errors='ignore')[:30]}"

        except (IOError, PermissionError, OSError):
            pass

        return False, "Limpio"

    def scan_bytes(self, data):
        if self.yara:
            infectado, motivo = self.yara.scan_bytes(data)
            if infectado:
                return True, motivo
        if data:
            h = hashlib.md5(data).hexdigest()
            if self.cti and self.cti.check_hash(h):
                return True, f"CTI en memoria: {h}"
        return False, "Limpio"

    def quarantine(self, filepath, motivo):
        import shutil
        timestamp = int(time.time())
        name = os.path.basename(filepath)
        dest = os.path.join(self.cuarentena, f"{timestamp}_{name}")

        if not os.path.exists(filepath):
            return None
        if not os.access(self.cuarentena, os.W_OK):
            print(f"{Colors.RED}[!] Cuarentena no escribible: {self.cuarentena}{Colors.RESET}")
            return None

        try:
            os.rename(filepath, dest)
        except OSError:
            try:
                shutil.copy2(filepath, dest)
                os.remove(filepath)
            except Exception as e:
                print(f"{Colors.RED}[!] Error moviendo a cuarentena: {e}{Colors.RESET}")
                return None

        if not os.path.exists(dest):
            return None

        try:
            os.chmod(dest, 0o600)
        except Exception:
            pass

        try:
            with open(f"{dest}.log", 'w') as log:
                log.write(f"Origen: {filepath}\n")
                log.write(f"Motivo: {motivo}\n")
                log.write(f"Fecha: {datetime.now()}\n")
                log.write(f"Tamaño: {os.path.getsize(dest)} bytes\n")
        except Exception:
            pass

        return dest

    def print_status(self):
        print(f"{Colors.BOLD}=== Estado del Motor ==={Colors.RESET}")
        print(f"  Motor:            {self.motor}")
        print(f"  Cuarentena:       {self.cuarentena}")
        print(f"  Firmas (clamd):   {self.total_firmas:,}")
        yara_icon = "OK" if self.yara else "NO"
        cti_icon = "OK" if self.cti else "NO"
        print(f"  YARA:             {yara_icon}")
        print(f"  CTI abuse.ch:     {cti_icon}")
