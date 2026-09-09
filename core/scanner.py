import os, sys, hashlib, re, subprocess, time
from datetime import datetime
from pathlib import Path
from .yara_scanner import YaraScanner

class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; RESET = '\033[0m'; BOLD = '\033[1m'

class ScannerEngine:
    def __init__(self, config):
        self.config = config
        self.firmas_md5 = set(); self.firmas_sha1 = set()
        self.firmas_hex = []
        self.total_firmas = 0
        self.cuarentena = config.get('cuarentena', '/opt/av_cuarentena')
        os.makedirs(self.cuarentena, exist_ok=True)
        self.load_clamav_signatures()
        # Integración YARA
        self.yara = YaraScanner()

    def load_clamav_signatures(self):
        """Carga firmas desde /var/lib/clamav"""
        clam_paths = ["/var/lib/clamav", "/usr/local/share/clamav"]
        for base in clam_paths:
            if os.path.exists(base):
                self._parse_hdb(Path(base).glob("*.hdb"))
                self._parse_hdb(Path(base).glob("*.hdu"))
                self._parse_ndb(Path(base).glob("*.ndb"))
                break
        print(f"{Colors.BLUE}[+] Cargadas {self.total_firmas} firmas ClamAV.{Colors.RESET}")

    def _parse_hdb(self, files):
        for f in files:
            try:
                with open(f, 'r', errors='ignore') as fd:
                    for line in fd:
                        if ':' in line:
                            h = line.split(':')[0].lower()
                            if len(h) == 32: self.firmas_md5.add(h)
                            elif len(h) == 40: self.firmas_sha1.add(h)
                            self.total_firmas += 1
                            if self.total_firmas > self.config.get('max_firmas', 300000): return
            except: pass

    def _parse_ndb(self, files):
        for f in files:
            try:
                with open(f, 'r', errors='ignore') as fd:
                    for line in fd:
                        parts = line.split(':')
                        if len(parts) >= 4:
                            hex_str = parts[3].split('*')[0]
                            try:
                                self.firmas_hex.append(bytes.fromhex(hex_str))
                                self.total_firmas += 1
                                if self.total_firmas > self.config.get('max_firmas', 300000): return
                            except: pass
            except: pass

    def get_hash(self, data_or_path, algo='md5'):
        hash_obj = hashlib.new(algo)
        if isinstance(data_or_path, bytes):
            hash_obj.update(data_or_path)
            return hash_obj.hexdigest()
        try:
            with open(data_or_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except: return None

    def scan_bytes(self, data):
        if not data: return False, "Sin datos"
        h = hashlib.md5(data).hexdigest()
        if h in self.firmas_md5: return True, f"MD5 en memoria: {h}"
        for sig in self.firmas_hex:
            if sig in data: return True, "Firma NDB en memoria"
        return False, "Limpio"

    def scan_file(self, filepath):
        # 1. Hash
        for alg, set_f in [('md5', self.firmas_md5), ('sha1', self.firmas_sha1)]:
            h = self.get_hash(filepath, alg)
            if h and h in set_f: return True, f"Firma {alg.upper()}"

        # 2. Cadenas NDB
        try:
            with open(filepath, 'rb') as f:
                data = f.read(4194304)
                for sig in self.firmas_hex:
                    if sig in data: return True, "Firma NDB"
        except: pass

        # 3. Heurística
        res, motivo = self.heuristic_scan(filepath)
        if res: return True, motivo

        # 4. YARA (si el archivo es regular y no demasiado grande)
        if os.path.getsize(filepath) < 50 * 1024 * 1024:  # <50 MB
            yara_inf, yara_mot = self.yara.scan_file(filepath)
            if yara_inf:
                return True, yara_mot

        return False, "Limpio"

    def heuristic_scan(self, filepath):
        try:
            st = os.stat(filepath)
            if st.st_mode & 0o4000: return True, "SETUID Rootkit"
            if st.st_mode & 0o2000: return True, "SETGID Rootkit"

            with open(filepath, 'rb') as f:
                if f.read(4) == b'\x7fELF':
                    if any(x in filepath for x in ['/tmp/', '/dev/shm/', '/var/tmp/']):
                        return True, "ELF en tmp"
            
            if filepath.endswith(('.py','.sh','.pl','.js')):
                with open(filepath, 'r', errors='ignore') as f:
                    txt = f.read(4096)
                    if re.search(r'eval\s*\(|base64\s*-d|rm\s+-rf\s+/\s*;', txt):
                        return True, "Script ofuscado"
        except: pass
        return False, "Limpio"

    def quarantine(self, filepath, motivo):
        timestamp = int(time.time())
        name = os.path.basename(filepath)
        dest = os.path.join(self.cuarentena, f"{timestamp}_{name}")
        try:
            os.rename(filepath, dest)
            with open(f"{dest}.log", 'w') as log:
                log.write(f"Origen: {filepath}\nMotivo: {motivo}\nFecha: {datetime.now()}")
            return dest
        except Exception as e:
            print(f"{Colors.RED}Error en cuarentena: {e}{Colors.RESET}")
            return None
