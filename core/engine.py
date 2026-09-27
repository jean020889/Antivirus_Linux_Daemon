# core/engine.py
"""
Motor de detección unificado.

Coordina:
- ClamAV (clamd socket)
- YARA (reglas comunitarias)
- Heurística propia (SETUID, ELF, scripts)
- Sigma (reglas de comportamiento)
- CTI abuse.ch (IOCs en tiempo real)

Cada detección se enriquece con:
- Severidad (info/low/medium/high/critical)
- Confianza (0-100)
- Técnica MITRE ATT&CK
- Acciones SOAR recomendadas
"""

import os
import hashlib
import time
from datetime import datetime
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionEngine:
    """Motor de detección unificado."""

    def __init__(self, config):
        self.config = config
        self.cuarentena = self._determine_quarantine_dir()
        os.makedirs(self.cuarentena, exist_ok=True)

        # Motores
        self.scanner = None      # ClamAV + heurística
        self.yara = None         # YARA
        self.cti = None          # CTI abuse.ch
        self.sigma = None        # Sigma
        self.heuristic = None    # Heurística avanzada

        self._init_engines()
        self.stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "by_engine": {"clamav": 0, "yara": 0, "heuristic": 0, "sigma": 0, "cti": 0}
        }

    def _determine_quarantine_dir(self):
        if os.geteuid() == 0:
            return self.config.get('cuarentena', '/opt/antivirus_cuarentena')
        return os.path.expanduser('~/.av_cuarentena')

    def _init_engines(self):
        """Inicializa todos los motores disponibles."""
        # ClamAV + heurística básica (ya existe)
        try:
            from .scanner import ScannerEngine
            self.scanner = ScannerEngine(self.config)
            print(f"[+] Scanner engine: OK")
        except Exception as e:
            print(f"[!] Scanner engine: {e}")

        # YARA
        try:
            from .yara_engine import YaraEngine
            self.yara = YaraEngine(
                rules_dir=self.config.get('yara_rules_dir', '/opt/antivirus-pro/yara_rules'),
                cache_dir=self.config.get('cti_cache_dir', '/opt/antivirus-pro/cti_cache')
            )
            print(f"[+] YARA engine: OK")
        except Exception as e:
            print(f"[!] YARA engine: {e}")

        # CTI abuse.ch
        try:
            from .cti_abuse import AbuseCHIntel
            key = self.config.get('abuse_ch_key')
            if key and key not in ('TU_AUTH_KEY_AQUI', ''):
                self.cti = AbuseCHIntel(auth_key=key,
                    cache_dir=self.config.get('cti_cache_dir', '/opt/antivirus-pro/cti_cache'))
                print(f"[+] CTI engine: OK")
            else:
                print(f"[!] CTI engine: sin API key")
        except Exception as e:
            print(f"[!] CTI engine: {e}")

        # Heurística avanzada
        try:
            from .heuristic import HeuristicEngine
            self.heuristic = HeuristicEngine(self.config)
            print(f"[+] Heuristic engine: OK")
        except Exception as e:
            print(f"[!] Heuristic engine: {e}")

        # Sigma
        try:
            from .sigma_engine import SigmaEngine
            self.sigma = SigmaEngine(self.config)
            print(f"[+] Sigma engine: OK ({self.sigma.rule_count} reglas)")
        except Exception as e:
            print(f"[!] Sigma engine: {e}")

    def scan_file(self, filepath):
        """
        Escaneo multi-motor de un archivo.
        Retorna: (detected: bool, detections: list, metadata: dict)
        """
        self.stats["files_scanned"] += 1
        detections = []
        metadata = self._file_metadata(filepath)

        # 1. ClamAV (motor principal)
        if self.scanner:
            infected, reason = self.scanner.scan_file(filepath)
            if infected:
                detections.append({
                    "engine": "clamav",
                    "threat": reason,
                    "severity": Severity.HIGH.value,
                    "confidence": 95,
                    "mitre": None
                })
                self.stats["by_engine"]["clamav"] += 1

        # 2. YARA
        if self.yara:
            infected, reason = self.yara.scan_file(filepath)
            if infected:
                detections.append({
                    "engine": "yara",
                    "threat": reason,
                    "severity": Severity.MEDIUM.value,
                    "confidence": 75,
                    "mitre": None
                })
                self.stats["by_engine"]["yara"] += 1

        # 3. Heurística
        if self.heuristic:
            h_dets = self.heuristic.scan_file(filepath)
            for det in h_dets:
                detections.append(det)
                self.stats["by_engine"]["heuristic"] += 1

        # 4. CTI (IOC check)
        if self.cti:
            for alg in ('md5', 'sha256'):
                h = self._hash_file(filepath, alg)
                if h and self.cti.check_hash(h):
                    detections.append({
                        "engine": "cti",
                        "threat": f"IOC match: {h[:16]}...",
                        "severity": Severity.HIGH.value,
                        "confidence": 90,
                        "mitre": "T1071"  # Application Layer Protocol
                    })
                    self.stats["by_engine"]["cti"] += 1

        detected = len(detections) > 0
        if detected:
            self.stats["threats_found"] += 1

        return detected, detections, metadata

    def _file_metadata(self, filepath):
        """Extrae metadata forense del archivo."""
        try:
            st = os.stat(filepath)
            return {
                "path": filepath,
                "size": st.st_size,
                "mode": oct(st.st_mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                "md5": self._hash_file(filepath, 'md5'),
                "sha256": self._hash_file(filepath, 'sha256'),
            }
        except Exception:
            return {"path": filepath}

    def _hash_file(self, filepath, algo='md5'):
        try:
            h = hashlib.new(algo)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def get_stats(self):
        return self.stats.copy()


# ============================================
# EXTENSIÓN: Generación de firmas propias
# ============================================
def _init_signature_generator(self):
    """Inicializa el generador de firmas (extensión)."""
    try:
        from .signature_generator import SignatureGenerator
        from .db import DB
        self.sig_gen = SignatureGenerator(DB())
        print(f"[+] Signature generator: OK")
    except Exception as e:
        self.sig_gen = None
        print(f"[!] Signature generator: {e}")


def learn_from_detection(self, filepath, threat_name, engine,
                          severity='high', mitre=None):
    """Aprende de una detección generando firmas propias."""
    if not hasattr(self, 'sig_gen') or not self.sig_gen:
        return None
    try:
        return self.sig_gen.learn_from_detection(
            filepath, threat_name, engine, severity, mitre
        )
    except Exception as e:
        print(f"[!] Error generando firma: {e}")
        return None


# Monkey-patch: extender __init__ para incluir generador
_original_init = DetectionEngine.__init__
def _extended_init(self, config):
    _original_init(self, config)
    _init_signature_generator(self)
DetectionEngine.__init__ = _extended_init

# Añadir métodos
DetectionEngine.learn_from_detection = learn_from_detection


# ============================================
# EXTENSIÓN: Motor Zero-Day
# ============================================
def _init_zeroday(self):
    """Inicializa el motor zero-day (extensión)."""
    try:
        from .zeroday_engine import ZeroDayEngine
        from .anomaly_ml import AnomalyML
        self.zeroday = ZeroDayEngine(self.config)
        self.anomaly_ml = AnomalyML()
        print(f"[+] Zero-Day engine: OK")
        print(f"[+] Anomaly ML: {'OK (sklearn)' if self.anomaly_ml.is_trained() else 'sin entrenar'}")
    except Exception as e:
        self.zeroday = None
        self.anomaly_ml = None
        print(f"[!] Zero-Day: {e}")


def scan_file_zeroday(self, filepath):
    """Escaneo zero-day adicional."""
    if not hasattr(self, 'zeroday') or not self.zeroday:
        return False, [], {}
    try:
        score, reasons, features = self.zeroday.analyze_file(filepath)

        # También usar ML si está entrenado
        ml_score = 0.5
        if hasattr(self, 'anomaly_ml') and self.anomaly_ml and self.anomaly_ml.is_trained():
            ml_score = self.anomaly_ml.score(features)
            if ml_score > 0.75:
                reasons.append(f"ML anomaly score: {ml_score:.2f}")

        # Si la anomalía es alta, es sospechoso
        is_anomaly = score >= 0.7 or ml_score > 0.8
        return is_anomaly, reasons, features
    except Exception as e:
        return False, [], {}


# Extender __init__
_original_init2 = DetectionEngine.__init__
def _extended_init2(self, config):
    _original_init2(self, config)
    _init_zeroday(self)
DetectionEngine.__init__ = _extended_init2

DetectionEngine.scan_file_zeroday = scan_file_zeroday
