"""
core/yara_generator.py
Generador automático de reglas YARA a partir de análisis de archivos.

Inspirado en las técnicas de RuleLLM [citation:9] y Adaptive Malware
Classification [citation:13]: extrae strings únicos, imports y patrones
estructurales, y genera reglas YARA listas para usar.

La generación es determinista (sin LLM) para garantizar reproducibilidad
y evitar alucinaciones. En producción, se puede integrar un LLM para
mejorar la calidad semántica de las reglas.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("antivirus.yara_gen")


@dataclass
class GeneratedRule:
    name: str
    rule_text: str
    source_file: str
    indicators: list[str]
    confidence: float


class YaraRuleGenerator:
    """
    Genera reglas YARA a partir de archivos analizados.

    Estrategia:
      1. Extraer strings únicos (no presentes en archivos benignos comunes).
      2. Extraer URLs, IPs y dominios embebidos (IOCs).
      3. Extraer símbolos dinámicos (imports) si es ELF.
      4. Generar regla YARA con esos patrones.
    """

    def __init__(self, output_dir: str | None = None):
        """
        Directorio donde se guardan las reglas YARA generadas.
        Orden de preferencia:
          1. Argumento explícito output_dir
          2. /var/lib/antivirus-linux-dragon/yara_rules_generated (producción)
          3. ./yara_rules/generated (desarrollo)
          4. /tmp/yara_rules_generated (último recurso)
        """
        if output_dir:
            base = Path(output_dir)
        else:
            # Intentar escribir en /var/lib (donde sí tiene permiso el daemon)
            candidates = [
                Path("/var/lib/antivirus-linux-dragon/yara_rules_generated"),
                Path("yara_rules/generated"),
                Path("/tmp/yara_rules_generated"),
            ]
            base = None
            for candidate in candidates:
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    # Probar que se puede escribir
                    test_file = candidate / ".write_test"
                    test_file.touch()
                    test_file.unlink()
                    base = candidate
                    break
                except (PermissionError, OSError):
                    continue
            if base is None:
                # Último recurso absoluto
                import tempfile
                base = Path(tempfile.mkdtemp(prefix="av_yara_"))
                logger.warning("Sin permisos en rutas estándar; usando %s", base)

        self.output_dir = base
        self.generated_rules: list[GeneratedRule] = []

    def generate_from_file(
        self,
        filepath: str,
        rule_name: str | None = None,
        min_string_len: int = 8,
        max_strings: int = 20,
    ) -> GeneratedRule | None:
        """
        Genera una regla YARA a partir de un archivo.

        :param filepath: Archivo de malware (o muestra sospechosa).
        :param rule_name: Nombre de la regla. Si None, se genera del hash.
        :param min_string_len: Longitud mínima de strings a extraer.
        :param max_strings: Máximo de strings por regla.
        """
        path = Path(filepath)
        if not path.is_file():
            logger.error("Archivo no encontrado: %s", filepath)
            return None

        with open(path, "rb") as f:
            data = f.read()

        # 1. Nombre de la regla
        if not rule_name:
            h = hashlib.sha256(data).hexdigest()[:12]
            rule_name = f"Auto_{path.stem}_{h}"

        # 2. Extraer strings candidatos
        strings = self._extract_unique_strings(data, min_string_len, max_strings)

        # 3. Extraer IOCs
        urls = re.findall(rb'https?://[^\s"\']{6,200}', data)
        ips = re.findall(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b', data)

        # 4. Extraer imports ELF
        imports = self._extract_elf_imports(str(path))

        # 5. Construir la regla
        rule_text, indicators = self._build_rule(
            rule_name, strings, urls, ips, imports
        )

        if not indicators:
            logger.warning("No se encontraron indicadores en %s", filepath)
            return None

        # 6. Escribir a disco
        output_path = self.output_dir / f"{rule_name}.yar"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rule_text)

        confidence = self._compute_confidence(strings, urls, ips, imports)
        rule = GeneratedRule(
            name=rule_name,
            rule_text=rule_text,
            source_file=str(path),
            indicators=indicators,
            confidence=confidence,
        )
        self.generated_rules.append(rule)
        logger.info("Regla generada: %s (confianza: %.2f)", rule_name, confidence)
        return rule

    def _extract_unique_strings(
        self, data: bytes, min_len: int, max_count: int
    ) -> list[bytes]:
        """Extrae strings ASCII/UTF-8 únicos y relativamente largos."""
        # Strings ASCII imprimibles
        ascii_strings = re.findall(
            rb'[\x20-\x7e]{%d,200}' % min_len, data
        )
        # Filtrar strings comunes/de sistema
        common = {
            b"the", b"and", b"for", b"this", b"that",
            b"http", b"https", b"function", b"string",
        }
        unique = []
        seen = set()
        for s in ascii_strings:
            if s in seen or s in common:
                continue
            # Descartar strings con muchos espacios
            if s.count(b" ") > len(s) // 2:
                continue
            seen.add(s)
            unique.append(s)
            if len(unique) >= max_count:
                break
        return unique

    def _extract_elf_imports(self, filepath: str) -> list[str]:
        """Extrae símbolos dinámicos importados de un ELF."""
        imports = []
        try:
            from elftools.elf.elffile import ELFFile
            with open(filepath, "rb") as f:
                elf = ELFFile(f)
                if not elf.has_section(".dynsym"):
                    return imports
                dynsym = elf.get_section_by_name(".dynsym")
                for sym in dynsym.iter_symbols():
                    if sym["st_info"]["type"] == "STT_FUNC":
                        imports.append(sym.name)
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("Error extrayendo imports: %s", exc)
        return imports[:30]

    def _build_rule(
        self,
        rule_name: str,
        strings: list[bytes],
        urls: list[bytes],
        ips: list[bytes],
        imports: list[str],
    ) -> tuple[str, list[str]]:
        """Construye el texto de la regla YARA."""
        lines = [
            f"rule {rule_name}",
            "{",
            "    meta:",
            f'        description = "Regla generada automáticamente por Antivirus Linux Dragon"',
            f'        author = "Auto-generator v1.0"',
            f'        confidence = "auto"',
            "",
            "    strings:",
        ]
        indicators = []
        idx = 0

        for s in strings[:15]:
            idx += 1
            hex_bytes = s.hex()
            lines.append(f"        $s{idx} = {{ {hex_bytes} }}")
            indicators.append(f"string:{s[:40].decode('ascii', 'replace')}")

        for u in urls[:5]:
            idx += 1
            lines.append(f'        $u{idx} = "{u.decode("ascii", "replace")}" ascii')
            indicators.append(f"url:{u.decode('ascii', 'replace')}")

        for ip in ips[:5]:
            idx += 1
            lines.append(f'        $ip{idx} = "{ip.decode("ascii", "replace")}" ascii')
            indicators.append(f"ip:{ip.decode('ascii', 'replace')}")

        lines.append("")
        lines.append("    condition:")

        # Condición: al menos 3 strings O cualquier URL/IP
        conditions = []
        if len(strings) >= 3:
            conditions.append("3 of ($s*)")
        elif strings:
            conditions.append(f"{len(strings)} of ($s*)")
        if urls:
            conditions.append("any of ($u*)")
        if ips:
            conditions.append("any of ($ip*)")

        if not conditions:
            lines.append("        false")
        else:
            lines.append("        " + " or ".join(conditions))

        lines.append("}")
        return "\n".join(lines), indicators

    @staticmethod
    def _compute_confidence(
        strings: list[bytes],
        urls: list[bytes],
        ips: list[bytes],
        imports: list[str],
    ) -> float:
        """Calcula la confianza de la regla generada (0-1)."""
        score = 0.0
        if len(strings) >= 5:
            score += 0.4
        elif len(strings) >= 2:
            score += 0.2
        if urls:
            score += 0.2
        if ips:
            score += 0.2
        if imports:
            score += 0.2
        return min(score, 1.0)
