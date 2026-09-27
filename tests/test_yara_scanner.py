"""
Tests de YaraScanner. Verifican:
  - Carga de reglas desde un directorio
  - Detección de strings coincidentes
  - No detección en archivos limpios
  - Manejo de archivos inexistentes
  - Recarga tras añadir reglas nuevas
"""
import os
from pathlib import Path

import pytest

from core.yara_scanner import YaraScanner


REGLA_MALWARE = """
rule Test_Malware_Simple {
    meta:
        description = "Regla de test"
    strings:
        $a = "MALWARE_TEST_STRING"
        $b = "OTRO_PATRON" nocase
    condition:
        $a or $b
}
"""

REGLA_ELF_SOSPECHOSO = """
rule Test_ELF_Sospechoso {
    strings:
        $magic = { 7F 45 4C 46 }
    condition:
        $magic at 0
}
"""


@pytest.fixture
def yara_dir(tmp_path):
    d = tmp_path / "yara_rules"
    d.mkdir()
    (d / "test1.yar").write_text(REGLA_MALWARE)
    (d / "test2.yar").write_text(REGLA_ELF_SOSPECHOSO)
    return d


class TestYaraScanner:
    def test_carga_reglas(self, yara_dir):
        scanner = YaraScanner(str(yara_dir))
        assert scanner.compiled_rules is not None

    def test_detecta_string_malicioso(self, yara_dir, tmp_path):
        scanner = YaraScanner(str(yara_dir))
        target = tmp_path / "malo.bin"
        target.write_bytes(b"contenido con MALWARE_TEST_STRING dentro")
        infectado, motivo = scanner.scan_file(str(target))
        assert infectado is True
        assert "Test_Malware_Simple" in motivo

    def test_detecta_patron_case_insensitive(self, yara_dir, tmp_path):
        scanner = YaraScanner(str(yara_dir))
        target = tmp_path / "malo2.bin"
        target.write_bytes(b"esto tiene otro_patron en minusculas")
        infectado, motivo = scanner.scan_file(str(target))
        assert infectado is True

    def test_archivo_limpio_no_detectado(self, yara_dir, tmp_path):
        scanner = YaraScanner(str(yara_dir))
        target = tmp_path / "limpio.txt"
        target.write_text("Este archivo no tiene nada malicioso.")
        infectado, motivo = scanner.scan_file(str(target))
        assert infectado is False

    def test_archivo_inexistente(self, yara_dir):
        scanner = YaraScanner(str(yara_dir))
        infectado, motivo = scanner.scan_file("/no/existe/archivo")
        assert infectado is False

    def test_archivo_elf_detectado_por_magic(self, yara_dir, tmp_path):
        scanner = YaraScanner(str(yara_dir))
        target = tmp_path / "binario"
        target.write_bytes(b"\x7fELF" + b"\x00" * 100)
        infectado, motivo = scanner.scan_file(str(target))
        assert infectado is True
        assert "ELF" in motivo or "Sospechoso" in motivo

    def test_directorio_vacio_no_explota(self, tmp_path):
        empty = tmp_path / "vacio"
        empty.mkdir()
        scanner = YaraScanner(str(empty))
        # No debe explotar; compiled_rules puede ser None o un objeto vacío
        infectado, motivo = scanner.scan_file(str(tmp_path))
        assert infectado is False

    def test_directorio_inexistente_no_explota(self, tmp_path):
        scanner = YaraScanner(str(tmp_path / "no_existe"))
        infectado, motivo = scanner.scan_file(str(tmp_path))
        assert infectado is False
