# core/signature_generator.py
"""
Generador automático de firmas propias.

Aprende de:
- Archivos detectados como maliciosos (hashes)
- Patrones byte únicos en samples
- Comportamiento de procesos maliciosos
- IOCs de CTI

Las firmas se guardan en PostgreSQL (custom_signatures).
"""
import os
import re
import hashlib
from datetime import datetime


class SignatureGenerator:
    def __init__(self, db=None):
        self.db = db

    # ============================================
    # GENERACIÓN DE FIRMAS
    # ============================================

    def generate_hash_signature(self, filepath, threat_name, severity='high',
                                 mitre=None, family=None):
        """Genera firma por hash (MD5/SHA256)."""
        if not os.path.isfile(filepath):
            return None

        md5 = self._hash_file(filepath, 'md5')
        sha256 = self._hash_file(filepath, 'sha256')

        if not sha256:
            return None

        sig = {
            'sig_type': 'hash',
            'sig_value': sha256,
            'sig_name': f"AutoHash_{threat_name[:50]}",
            'description': f"Hash signature for {threat_name}",
            'severity': severity,
            'confidence': 95,
            'source': 'auto_learn',
            'sample_hash': sha256,
            'sample_path': filepath,
            'mitre_technique': mitre,
        }

        if self.db:
            self.db.upsert_custom_signature(**sig)

        return sig

    def generate_byte_pattern_signature(self, filepath, threat_name,
                                         min_length=16, max_length=64,
                                         severity='medium', mitre=None):
        """Extrae patrón de bytes único del sample."""
        if not os.path.isfile(filepath):
            return None

        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024 * 1024)  # primeros 1MB

            if len(data) < min_length:
                return None

            # Buscar secuencias de bytes con alta entropía
            candidates = self._find_unique_patterns(data, min_length, max_length)

            if not candidates:
                return None

            # Tomar el patrón más largo (mejor unicidad)
            pattern_hex = max(candidates, key=len)

            sig = {
                'sig_type': 'byte_pattern',
                'sig_value': pattern_hex,  # hexadecimal
                'sig_name': f"AutoByte_{threat_name[:40]}",
                'description': f"Byte pattern from {threat_name}",
                'severity': severity,
                'confidence': 70,
                'source': 'auto_learn',
                'mitre_technique': mitre,
            }

            if self.db:
                self.db.upsert_custom_signature(**sig)

            return sig
        except Exception:
            return None

    def generate_yara_rule(self, filepath, threat_name, severity='high', mitre=None):
        """Genera regla YARA automática."""
        if not os.path.isfile(filepath):
            return None

        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024 * 1024)

            # Buscar 3 strings únicos
            strings = self._find_unique_strings(data, min_len=8, max_count=3)

            if len(strings) < 2:
                return None

            # Sanitizar nombre
            rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', f"Auto_{threat_name[:40]}")

            yara_rule = f"""rule {rule_name}
{{
    meta:
        author = "AntivirusPro EDR (auto)"
        description = "{threat_name}"
        severity = "{severity}"
        mitre = "{mitre or 'unknown'}"
        date = "{datetime.now().strftime('%Y-%m-%d')}"

    strings:
"""
            for i, s in enumerate(strings, 1):
                hex_str = s.hex()
                yara_rule += f'        $s{i} = {{ {hex_str} }}\n'

            yara_rule += """
    condition:
        any of them
}
"""

            sig = {
                'sig_type': 'yara',
                'sig_value': yara_rule,
                'sig_name': rule_name,
                'description': f"Auto YARA for {threat_name}",
                'severity': severity,
                'confidence': 75,
                'source': 'auto_learn',
                'mitre_technique': mitre,
            }

            if self.db:
                self.db.upsert_custom_signature(**sig)

            return sig
        except Exception:
            return None

    # ============================================
    # HELPERS
    # ============================================
    def _hash_file(self, filepath, algo='sha256'):
        try:
            h = hashlib.new(algo)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _find_unique_patterns(self, data, min_len, max_len):
        """Encuentra secuencias de bytes con alta entropía."""
        import math

        candidates = []
        window = max_len

        for i in range(0, len(data) - window, window):
            chunk = data[i:i + window]
            entropy = self._calculate_entropy(chunk)

            # Alta entropía + bytes no imprimibles = probable código
            non_printable = sum(1 for b in chunk if b < 32 or b > 126)
            ratio = non_printable / len(chunk)

            if entropy > 5.0 and ratio > 0.5:
                # Buscar la subsecuencia más larga
                for length in range(max_len, min_len - 1, -8):
                    sub = chunk[:length]
                    if len(sub) >= min_len:
                        candidates.append(sub.hex())
                        break

        return candidates

    def _find_unique_strings(self, data, min_len=8, max_count=3):
        """Encuentra strings ASCII únicos."""
        strings = []
        pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'

        for match in re.finditer(pattern, data):
            s = match.group()
            # Filtrar strings comunes
            if any(common in s.lower() for common in [b'the ', b'ing ', b'ion ']):
                continue
            if len(s) >= min_len:
                strings.append(s)
            if len(strings) >= max_count * 3:
                break

        # Ordenar por longitud, tomar los más únicos
        strings.sort(key=len, reverse=True)
        return strings[:max_count]

    def _calculate_entropy(self, data):
        """Calcula la entropía de Shannon."""
        import math
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ============================================
    # APRENDIZAJE DESDE DETECCIONES
    # ============================================
    def learn_from_detection(self, filepath, threat_name, engine,
                              severity='high', mitre=None):
        """
        Aprende de una detección: genera todas las firmas posibles.
        Retorna dict con las firmas generadas.
        """
        result = {
            'hash': None,
            'byte_pattern': None,
            'yara': None,
        }

        # Solo generar firmas si:
        # 1. Es un archivo real
        # 2. Tiene tamaño razonable (< 50MB)
        try:
            size = os.path.getsize(filepath)
            if size > 50 * 1024 * 1024 or size < 16:
                return result
        except Exception:
            return result

        # Generar firmas
        result['hash'] = self.generate_hash_signature(
            filepath, threat_name, severity, mitre
        )

        result['byte_pattern'] = self.generate_byte_pattern_signature(
            filepath, threat_name, severity=severity, mitre=mitre
        )

        if engine in ('yara', 'heuristic', 'sigma'):
            result['yara'] = self.generate_yara_rule(
                filepath, threat_name, severity, mitre
            )

        return result

    # ============================================
    # ESTADÍSTICAS
    # ============================================
    def get_stats(self):
        """Estadísticas de firmas generadas."""
        if not self.db:
            return {}
        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT sig_type, COUNT(*) as count,
                           SUM(detection_count) as total_detections,
                           SUM(false_positive_count) as total_fp
                    FROM custom_signatures
                    GROUP BY sig_type
                """)
                return {r['sig_type']: dict(r) for r in cur.fetchall()}
        except Exception:
            return {}
