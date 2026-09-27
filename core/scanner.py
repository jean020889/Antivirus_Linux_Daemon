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

# Motor de detección de día cero (opcional)
try:
    from .zero_day_engine import ZeroDayEngine
    HAVE_ZERO_DAY = True
except ImportError:
    ZeroDayEngine = None
    HAVE_ZERO_DAY = False


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

        # Pasar la ruta de las reglas YARA si está configurada.
        # En producción (/usr/lib/...) las reglas viven en
        # /usr/share/antivirus-linux-dragon/yara_rules/ por lo que no
        # podemos usar la ruta relativa por defecto.
        yara_rules_path = config.get(
            "yara_rules_dir",
            str(Path(__file__).resolve().parent.parent / "yara_rules")
        )
        # Motor de detección de día cero (multicapa)
        self.zero_day = None
        if HAVE_ZERO_DAY and config.get("zero_day_enabled", True):
            try:
                self.zero_day = ZeroDayEngine(config)
                logger.info("ZeroDayEngine activado")
            except Exception as exc:
                logger.warning("ZeroDayEngine no inicializado: %s", exc)

        self.yara = YaraScanner(yara_rules_path)
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
        """
        Carga firmas desde /var/lib/clamav.

        Estrategia:
          1. Si existen archivos .cvd/.cld (formato binario comprimido de
             ClamAV), extraerlos con 'sigtool --unpack' a un cache.
          2. Leer los archivos .hdb/.hdu/.ndb/.ndu/.mdb/.mdu del cache
             y de /var/lib/clamav directamente.
          3. Cargar los hashes MD5/SHA1 y los patrones hex en memoria.

        El cache se invalida cuando el .cvd/.cld es más nuevo.
        """
        import subprocess
        import time as _t

        md5: set[str] = set()
        sha1: set[str] = set()
        hex_sigs: list[bytes] = []
        count = 0
        max_firmas = self.config.get('max_firmas', 300000)

        # --- 1. Extraer .cvd/.cld al cache si es necesario ---
        clam_dir = Path("/var/lib/clamav")
        cache_dir = Path(self.config.get(
            'sig_cache_dir',
            '/var/lib/antivirus-linux-dragon/sigs_cache'
        ))

        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback: usar /tmp si no tenemos permisos
            cache_dir = Path("/tmp/antivirus_sigs_cache")
            cache_dir.mkdir(parents=True, exist_ok=True)

        for cvd_file in clam_dir.glob("*.cvd"):
            self._extract_cvd_to_cache(cvd_file, cache_dir)
        for cld_file in clam_dir.glob("*.cld"):
            self._extract_cvd_to_cache(cld_file, cache_dir)

        # --- 2. Recolectar archivos de firmas ---
        # Directorios a escanear (en orden): cache primero, luego /var/lib/clamav
        search_dirs = [cache_dir, clam_dir]

        # Extensiones: hashes MD5/SHA1 y patrones NDB
        hash_extensions = ("*.hdb", "*.hdu", "*.mdb", "*.mdu")
        hex_extensions = ("*.ndb", "*.ndu")

        for base_dir in search_dirs:
            if not base_dir.is_dir():
                continue

            # Firmas de hash (MD5)
            for pattern in hash_extensions:
                for sig_file in base_dir.glob(pattern):
                    count = self._parse_hdb(
                        [sig_file], md5, sha1, count, max_firmas
                    )
                    if count >= max_firmas:
                        break

            # Firmas hex (NDB)
            for pattern in hex_extensions:
                for sig_file in base_dir.glob(pattern):
                    count = self._parse_ndb(
                        [sig_file], hex_sigs, count, max_firmas
                    )
                    if count >= max_firmas:
                        break

            # Firmas de terceros en subdirectorio unofficial-sigs
            unofficial = base_dir / "unofficial-sigs"
            if unofficial.is_dir():
                for pattern in hash_extensions:
                    for sig_file in unofficial.glob(pattern):
                        count = self._parse_hdb(
                            [sig_file], md5, sha1, count, max_firmas
                        )
                for pattern in hex_extensions:
                    for sig_file in unofficial.glob(pattern):
                        count = self._parse_ndb(
                            [sig_file], hex_sigs, count, max_firmas
                        )

        # --- 3. Swap atómico ---
        with self._signatures_lock:
            self.firmas_md5 = frozenset(md5)
            self.firmas_sha1 = frozenset(sha1)
            self.firmas_hex = tuple(hex_sigs)
            self.total_firmas = count

        logger.info("Cargadas %d firmas ClamAV (incluye .cvd extraídos).", count)
        print(f"{Colors.BLUE}[+] Cargadas {count} firmas ClamAV "
              f"(MD5: {len(md5)}, SHA1: {len(sha1)}, hex: {len(hex_sigs)}).{Colors.RESET}")
        return count

    def _extract_cvd_to_cache(self, cvd_path: Path, cache_dir: Path) -> None:
        """
        Extrae un .cvd/.cld al cache usando 'sigtool --unpack'.
        Solo extrae si el .cvd es más nuevo que el cache (idempotente).
        """
        import subprocess

        marker = cache_dir / f".{cvd_path.name}.extracted"
        # Si el cache es más nuevo que el .cvd, no re-extraer
        if marker.exists() and marker.stat().st_mtime >= cvd_path.stat().st_mtime:
            return

        try:
            # sigtool --unpack extrae al directorio actual (cwd)
            result = subprocess.run(
                ["sigtool", f"--unpack={cvd_path}"],
                cwd=str(cache_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                marker.touch()
                logger.info("Extraído %s al cache", cvd_path.name)
            else:
                logger.warning(
                    "Fallo extrayendo %s: %s", cvd_path.name, result.stderr[:200]
                )
        except FileNotFoundError:
            logger.warning("sigtool no encontrado; no se pueden extraer .cvd")
        except subprocess.TimeoutExpired:
            logger.warning("Timeout extrayendo %s", cvd_path.name)
        except Exception as exc:
            logger.warning("Error extrayendo %s: %s", cvd_path.name, exc)


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
        heuristic_verdict = self._heuristic_and_yara(filepath)
        if heuristic_verdict[0]:
            return heuristic_verdict

        # --- 4. Motor de día cero (para archivos que pasaron todo lo anterior) ---
        if self.zero_day is not None:
            try:
                zde_verdict = self.zero_day.evaluate(filepath)
                if zde_verdict.is_malicious:
                    reasons = "; ".join(zde_verdict.reasons[:3])
                    logger.warning(
                        "ZeroDay detectó %s (score %.2f): %s",
                        filepath, zde_verdict.risk_score, reasons
                    )
                    return True, f"ZeroDay (score {zde_verdict.risk_score:.2f}): {reasons}"
            except Exception as exc:
                logger.debug("ZeroDayEngine falló en %s: %s", filepath, exc)

        return False, "Limpio"

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
