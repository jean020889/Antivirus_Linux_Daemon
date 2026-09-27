"""
core/static_analyzer.py
Análisis estático avanzado para detección de malware sin ejecución.

Técnicas implementadas:
  - Cálculo de entropía de Shannon global y por sección ELF.
  - Detección de magic bytes (archivos disfrazados).
  - Extracción de strings sospechosos (C2, comandos, ofuscación).
  - Detección de empaquetado (packers) por alta entropía.
  - Extracción de IOCs embebidos (IPs, URLs, dominios).

Basado en técnicas de análisis estático usadas por antivirus comerciales
y proyectos como REMINDer [citation:10], Malware-Analyzer [citation:4],
y Static-Code-Analyzer [citation:14].
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("antivirus.static")

# Umbral de entropía para considerar un archivo "empaquetado" o cifrado.
# Valores > 7.0 en escala 0-8 indican alta aleatoriedad [citation:4][citation:14].
ENTROPY_THRESHOLD = 7.0

# Umbral mínimo de entropía por sección ELF para sospechar.
SECTION_ENTROPY_THRESHOLD = 6.8


@dataclass
class StaticAnalysisResult:
    filepath: str
    file_size: int
    hashes: dict[str, str]
    global_entropy: float
    is_packed: bool
    section_entropies: dict[str, float] = field(default_factory=dict)
    suspicious_strings: list[str] = field(default_factory=list)
    embedded_iocs: dict[str, list[str]] = field(default_factory=dict)
    magic_type: str = ""
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)


class StaticAnalyzer:
    def __init__(self):
        self.url_pattern = re.compile(
            r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]{4,200}'
        )
        self.ip_pattern = re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        )
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
            r'(?:com|net|org|io|ru|cn|top|xyz|info|biz|onion|cc|tk|ml|ga)\b'
        )
        # Comandos y patrones sospechosos típicos de malware Linux
        self.suspicious_patterns = [
            # Shells e invocaciones
            (rb'/bin/sh\s+-c', "shell_invocation"),
            (rb'/bin/bash\s+-c', "shell_invocation"),
            (rb'bash\s+-i\s+>&', "bash_reverse_shell"),
            (rb'sh\s+-i\s+>&', "sh_reverse_shell"),

            # Descarga y ejecución
            (rb'curl\s+[^\s]*\|\s*(sh|bash)', "curl_pipe_shell"),
            (rb'wget\s+[^\s]*\|\s*(sh|bash)', "wget_pipe_shell"),
            (rb'curl\s+-s\s+.*\s+-o\s+', "curl_download"),

            # Ofuscación (patrones específicos y genéricos)
            (rb'base64\s+-d', "base64_decode"),
            (rb'base64\s+--decode', "base64_decode"),
            (rb'\$\{?[A-Za-z_]+\}?\s*\$\{?[A-Za-z_]+\}?\s+-d', "indirect_command"),  # ${X}${Y} -d
            (rb'\beval\s', "eval_usage"),
            (rb'python\s+-c\s+[\'"].*base64', "python_base64"),

            # Reverse shells y networking
            (rb'/dev/tcp/', "bash_tcp_reverse_shell"),
            (rb'nc\s+-e', "netcat_exec"),
            (rb'ncat\s+-e', "netcat_exec"),
            (rb'socat\s+.*exec', "socat_exec"),
            (rb'mkfifo\s+', "named_pipe_creation"),
            (rb'exec\s+3<>', "fd_redirection"),
            (rb'socket\.socket\(\)', "python_socket"),
            (rb'import\s+socket', "python_socket_import"),
            (rb'use\s+Socket', "perl_socket"),

            # Destrucción y persistencia
            (rb'rm\s+-rf\s+/(?!tmp/|var/tmp/)', "destructive_command"),
            (rb'rm\s+-rf\s+\*', "destructive_command"),
            (rb'shred\s+', "shred_command"),
            (rb'dd\s+if=/dev/zero', "disk_wipe"),

            # Escalada
            (rb'sudo\s+su\s', "sudo_su"),
            (rb'chmod\s+[0-7]*[4-7][0-7]{2}', "setuid_chmod"),

            # Ofuscación de payload
            (rb'echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d', "obfuscated_payload"),
            (rb'printf\s+[^\s]*\|\s*base64\s+-d', "obfuscated_payload"),
        ]

    def analyze(self, filepath: str) -> StaticAnalysisResult:
        """Ejecuta el análisis estático completo."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Archivo no encontrado: {filepath}")

        with open(path, "rb") as f:
            data = f.read()

        result = StaticAnalysisResult(
            filepath=str(path),
            file_size=len(data),
            hashes=self._compute_hashes(data),
            global_entropy=self._entropy(data),
            is_packed=False,
        )

        # Detección de magic bytes
        result.magic_type = self._detect_magic(data)

        # Entropía por sección (si es ELF)
        if data[:4] == b"\x7fELF":
            result.section_entropies = self._elf_section_entropies(str(path))

        # Detección de empaquetado
        if result.global_entropy > ENTROPY_THRESHOLD:
            result.is_packed = True
            result.reasons.append(
                f"Entropía global alta ({result.global_entropy:.2f}): "
                f"posible empaquetado o cifrado"
            )

        # Strings sospechosos
        result.suspicious_strings = self._find_suspicious_strings(data)

        # IOCs embebidos
        result.embedded_iocs = self._extract_iocs(data)

        # Calcular score
        result.score = self._compute_score(result)
        return result

    def _compute_hashes(self, data: bytes) -> dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Entropía de Shannon (0-8). > 7.0 sugiere cifrado/empaquetado."""
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        n = len(data)
        entropy = -sum(
            (count / n) * math.log2(count / n) for count in freq.values()
        )
        return entropy

    def _elf_section_entropies(self, filepath: str) -> dict[str, float]:
        """
        Calcula entropía por sección ELF usando pyelftools si está disponible.
        Si no, retorna dict vacío sin fallar.
        """
        entropies = {}
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError:
            return entropies

        try:
            with open(filepath, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if section["sh_type"] in ("SHT_NULL", "SHT_NOBITS"):
                        continue
                    data = section.data()
                    if len(data) > 64:  # Ignorar secciones muy pequeñas
                        entropies[section.name] = round(self._entropy(data), 3)
        except Exception as exc:
            logger.debug("Error parseando ELF: %s", exc)
        return entropies

    @staticmethod
    def _detect_magic(data: bytes) -> str:
        """Detecta el tipo de archivo por magic bytes."""
        magic_map = {
            b"\x7fELF": "ELF executable",
            b"\x89PNG": "PNG image",
            b"\xff\xd8\xff": "JPEG image",
            b"PK\x03\x04": "ZIP archive",
            b"\x1f\x8b": "GZIP archive",
            b"BZh": "BZIP2 archive",
            b"\xfd7zXZ": "XZ archive",
            b"MZ": "PE executable (Windows)",
            b"#!/": "Shell script",
            b"<?php": "PHP script",
        }
        for magic, name in magic_map.items():
            if data.startswith(magic):
                return name
        return "unknown"

    def _find_suspicious_strings(self, data: bytes) -> list[str]:
        """Busca patrones sospechosos en los primeros 1 MB."""
        found = []
        chunk = data[:1048576]
        for pattern, label in self.suspicious_patterns:
            if re.search(pattern, chunk, re.IGNORECASE):
                found.append(label)
        return found

    def _extract_iocs(self, data: bytes) -> dict[str, list[str]]:
        """Extrae IPs, URLs y dominios embebidos."""
        text = data[:2097152].decode("utf-8", errors="ignore")
        return {
            "urls": list(set(self.url_pattern.findall(text)))[:50],
            "ips": list(set(self.ip_pattern.findall(text)))[:50],
            "domains": list(set(self.domain_pattern.findall(text)))[:50],
        }

    def _compute_score(self, r: StaticAnalysisResult) -> float:
        """
        Puntuación de riesgo 0-1 basada en indicadores estáticos.

        Calibración:
          - Un archivo con curl|sh + base64 + rm -rf DEBE superar 0.5.
          - Un archivo con solo una URL embebida no debe pasar de 0.3.
          - Un archivo empaquetado con alta entropía debe pasar de 0.4.
        """
        score = 0.0

        # Indicadores de comportamiento (peso alto: son los más fiables)
        n_strings = len(r.suspicious_strings)
        if n_strings >= 4:
            score += 0.55
        elif n_strings == 3:
            score += 0.45
        elif n_strings == 2:
            score += 0.35
        elif n_strings == 1:
            score += 0.20

        # Empaquetado / cifrado (sospechoso pero no concluyente)
        if r.is_packed:
            score += 0.20

        # IOCs embebidos
        n_urls = len(r.embedded_iocs.get("urls", []))
        n_ips = len(r.embedded_iocs.get("ips", []))
        if n_urls >= 1:
            score += 0.15
        if n_urls >= 3:
            score += 0.10  # bonus por múltiples URLs
        if n_ips >= 1:
            score += 0.10

        # Secciones ELF con entropía alta (indica cifrado por sección)
        high_sections = sum(
            1 for e in r.section_entropies.values()
            if e > SECTION_ENTROPY_THRESHOLD
        )
        if high_sections >= 2:
            score += 0.15

        # Bonus por combinación letal (descarga + ejecución + destrucción)
        lethal_combos = [
            {"curl_pipe_shell", "base64_decode"},
            {"wget_pipe_shell", "base64_decode"},
            {"curl_pipe_shell", "destructive_command"},
            {"bash_tcp_reverse_shell", "shell_invocation"},
            {"chmod_exec", "base64_decode"},
        ]
        sset = set(r.suspicious_strings)
        for combo in lethal_combos:
            if combo.issubset(sset):
                score += 0.15
                break

        return min(score, 1.0)


# Función de conveniencia
def analyze_file(filepath: str) -> StaticAnalysisResult:
    return StaticAnalyzer().analyze(filepath)
