"""
core/scanner.py
Motor de escaneo: firmas en memoria + ClamAV (clamd vía pool) + heurística + YARA.

Orden de evaluación en scan_file (acumulativo, no excluyente):
  1. Firmas en memoria (MD5/SHA1/NDB propias) — rápido, local, siempre.
  2. clamd — concurrente, si está disponible.
  3. Heurística + YARA — siempre.
Cualquier capa que diga "infectado" corta y retorna.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path

from .yara_scanner import YaraScanner

try:
    from .clamd_pool import ClamdPool, ClamdError
except ImportError:
    ClamdPool = None
    ClamdError = Exception


logger = logging.getLogger("antivirus.scanner")


class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; RESET = '\033[0m'; BOLD = '\033[1m'


class ScannerEngine:
    def __init__(self, config):
        self.config = config
        self._signatures_lock = threading.Lock()

        self.firmas_md5: frozenset[str] = frozenset()
        self.firmas_sha1: frozenset[str] = frozenset()
        self.firmas_hex: tuple[bytes, ...] = ()
        self.total_firmas = 0

        self.cuarentena = config.get('cuarentena', '/opt/av_cuarentena')
        os.makedirs(self.cuarentena, exist_ok=True)

        self.yara = YaraScanner()
        self.load_clamav_signatures()

        self.clamd_pool = None
        if ClamdPool is not None:
            try:
                self.clamd_pool = ClamdPool(max_size=config.get('clamd_pool_size', 8))
                if not self.clamd_pool.available:
                    logger.warning("clamd no responde; se usará fallback en memoria.")
                    self.clamd_pool = None
                else:
                    logger.info("ClamdPool activo: %s (max=%d)",
                                self.clamd_pool.socket_path, self.clamd_pool.max_size)
            except Exception as exc:
                logger.warning("ClamdPool no disponible (%s); usando fallback.", exc)
                self.clamd_pool = None

    # ------------------------------------------------------------------ firmas
    def load_clamav_signatures(self) -> int:
        md5: set[str] = set()
        sha1: set[str] = set()
        hex_sigs: list[bytes] = []
        count = 0
        max_firmas = self.config.get('max_firmas', 300000)

        for base in ("/var/lib/clamav", "/usr/local/share/clamav"):
            base_path = Path(base)
            if not base_path.is_dir():
                continue

            for pattern in ("*.hdb", "*.hdu"):
                count = self._parse_hdb(base_path.glob(pattern), md5, sha1, count, max_firmas)
            for pattern in ("*.ndb",):
                count = self._parse_ndb(base_path.glob(pattern), hex_sigs, count, max_firmas)

            unofficial = base_path / "unofficial-sigs"
            if unofficial.is_dir():
                for pattern in ("*.hdb", "*.hdu"):
                    count = self._parse_hdb(unofficial.glob(pattern), md5, sha1, count, max_firmas)
                for pattern in ("*.ndb",):
                    count = self._parse_ndb(unofficial.glob(pattern), hex_sigs, count, max_firmas)

            break

        with self._signatures_lock:
            self.firmas_md5 = frozenset(md5)
            self.firmas_sha1 = frozenset(sha1)
            self.firmas_hex = tuple(hex_sigs)
            self.total_firmas = count

        logger.info("Cargadas %d firmas ClamAV (oficiales + terceros).", count)
        print(f"{Colors.BLUE}[+] Cargadas {count} firmas ClamAV.{Colors.RESET}")
        return count

    def _parse_hdb(self, files, md5_set, sha1_set, count, limit):
        for f in files:
            try:
                with open(f, 'r', errors='ignore') as fd:
                    for line in fd:
                        if ':' not in line:
                            continue
                        h = line.split(':', 1)[0].strip().lower()
                        if len(h) == 32:
                            md5_set.add(h)
                        elif len(h) == 40:
                            sha1_set.add(h)
                        else:
                            continue
                        count += 1
                        if count > limit:
                            return count
            except OSError as exc:
                logger.warning("No se pudo leer %s: %s", f, exc)
        return count

    def _parse_ndb(self, files, hex_list, count, limit):
        for f in files:
            try:
                with open(f, 'r', errors='ignore') as fd:
                    for line in fd:
                        parts = line.split(':')
                        if len(parts) < 4:
                            continue
                        hex_str = parts[3].split('*')[0].strip()
                        if not hex_str:
                            continue
                        try:
                            hex_list.append(bytes.fromhex(hex_str))
                        except ValueError:
                            continue
                        count += 1
                        if count > limit:
                            return count
            except OSError as exc:
                logger.warning("No se pudo leer %s: %s", f, exc)
        return count

    # --------------------------------------------------------------- escaneo
    def get_hash(self, path, algo='md5'):
        if isinstance(path, (bytes, bytearray)):
            return hashlib.new(algo, bytes(path)).hexdigest()
        try:
            hash_obj = hashlib.new(algo)
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except OSError:
            return None

    def scan_bytes(self, data):
        if not data:
            return False, "Sin datos"
        h = hashlib.md5(data).hexdigest()
        if h in self.firmas_md5:
            return True, f"MD5 en memoria: {h}"
        for sig in self.firmas_hex:
            if sig in data:
                return True, "Firma NDB en memoria"
        return False, "Limpio"

    def scan_file(self, filepath):
        """
        Escanea un archivo. Devuelve (infectado, motivo).

        Acumulativo: firmas en memoria → clamd → heurística + YARA.
        La primera capa que detecta corta y retorna.
        """
        # --- 1. Firmas en memoria (IOCs propios, SIEMPRE) ---
        for alg, sigs in (('md5', self.firmas_md5), ('sha1', self.firmas_sha1)):
            if not sigs:
                continue
            h = self.get_hash(filepath, alg)
            if h and h in sigs:
                return True, f"Firma {alg.upper()}"

        try:
            with open(filepath, 'rb') as f:
                data = f.read(4 * 1024 * 1024)
            for sig in self.firmas_hex:
                if sig in data:
                    return True, "Firma NDB"
        except OSError:
            pass

        # --- 2. clamd (si está disponible) ---
        if self.clamd_pool is not None and self.clamd_pool.available:
            try:
                with open(filepath, 'rb') as f:
                    with self.clamd_pool.acquire() as conn:
                        infectado, motivo = conn.scan_fd(f)
                if infectado:
                    return True, f"ClamAV: {motivo}"
            except (ClamdError, OSError, PermissionError) as exc:
                logger.debug("clamd falló en %s (%s); continuando con heurística.", filepath, exc)

        # --- 3. Heurística + YARA (siempre) ---
        return self._heuristic_and_yara(filepath)

    def _heuristic_and_yara(self, filepath):
        res, motivo = self.heuristic_scan(filepath)
        if res:
            return True, motivo

        try:
            if os.path.getsize(filepath) >= 50 * 1024 * 1024:
                return False, "Limpio"
        except OSError:
            return False, "Limpio"

        yara_inf, yara_mot = self.yara.scan_file(filepath)
        if yara_inf:
            return True, yara_mot

        return False, "Limpio"

    def heuristic_scan(self, filepath):
        try:
            st = os.stat(filepath)
        except OSError:
            return False, "Limpio"

        if st.st_mode & 0o4000:
            return True, "SETUID Rootkit"
        if st.st_mode & 0o2000:
            return True, "SETGID Rootkit"

        try:
            with open(filepath, 'rb') as f:
                header = f.read(4)
            if header == b'\x7fELF' and any(
                x in filepath for x in ('/tmp/', '/dev/shm/', '/var/tmp/')
            ):
                return True, "ELF en tmp"
        except OSError:
            pass

        if filepath.endswith(('.py', '.sh', '.pl', '.js')):
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    txt = f.read(4096)
                if re.search(r'eval\s*\(|base64\s*-d|rm\s+-rf\s+/\s*;', txt):
                    return True, "Script ofuscado"
            except OSError:
                pass

        return False, "Limpio"

    # -------------------------------------------------------------- cuarentena
    def quarantine(self, filepath, motivo):
        if not os.path.exists(filepath):
            return None
        timestamp = int(time.time())
        name = os.path.basename(filepath)
        dest = os.path.join(self.cuarentena, f"{timestamp}_{name}")
        try:
            shutil.move(filepath, dest)
            with open(f"{dest}.log", 'w', encoding='utf-8') as log:
                log.write(f"Origen: {filepath}\nMotivo: {motivo}\nFecha: {datetime.now()}")
            return dest
        except (OSError, shutil.Error) as exc:
            logger.error("Error moviendo %s a cuarentena: %s", filepath, exc)
            print(f"{Colors.RED}Error en cuarentena: {exc}{Colors.RESET}")
            return None

    # --------------------------------------------------------------- lifecycle
    def shutdown(self):
        if self.clamd_pool is not None:
            try:
                self.clamd_pool.shutdown()
            except Exception:
                logger.exception("Error cerrando ClamdPool")
            self.clamd_pool = None
