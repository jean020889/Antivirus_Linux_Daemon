"""
Tests del ScannerEngine.
"""
import os
import stat
from pathlib import Path

import pytest

from core.scanner import ScannerEngine


class TestSignatureLoading:
    def test_carga_inicial_no_falla(self, base_config):
        engine = ScannerEngine(base_config)
        assert engine.total_firmas >= 0
        assert isinstance(engine.firmas_md5, frozenset)
        assert isinstance(engine.firmas_sha1, frozenset)
        assert isinstance(engine.firmas_hex, tuple)

    def test_reload_no_duplica(self, base_config):
        engine = ScannerEngine(base_config)
        total_1 = engine.total_firmas
        engine.load_clamav_signatures()
        total_2 = engine.total_firmas
        assert total_1 == total_2, (
            f"Recargar firmas duplicó entradas: {total_1} -> {total_2}"
        )

    def test_reload_es_atomico(self, base_config):
        engine = ScannerEngine(base_config)
        engine.load_clamav_signatures()
        assert isinstance(engine.firmas_md5, frozenset)
        assert isinstance(engine.firmas_sha1, frozenset)
        assert isinstance(engine.firmas_hex, tuple)


class TestHashDetection:
    def test_detecta_por_md5(self, base_config, clean_file):
        engine = ScannerEngine(base_config)
        real_md5 = engine.get_hash(clean_file, 'md5')
        assert real_md5 is not None

        with engine._signatures_lock:
            engine.firmas_md5 = frozenset(list(engine.firmas_md5) + [real_md5])

        infectado, motivo = engine.scan_file(str(clean_file))
        assert infectado, "El archivo con hash conocido debería detectarse"
        assert 'MD5' in motivo

    def test_archivo_limpio_no_detectado(self, base_config, clean_file):
        engine = ScannerEngine(base_config)
        infectado, motivo = engine.scan_file(str(clean_file))
        assert not infectado, f"Archivo limpio marcado como infectado: {motivo}"

    def test_hash_de_bytes(self, base_config):
        engine = ScannerEngine(base_config)
        h = engine.get_hash(b"contenido", 'md5')
        assert h is not None and len(h) == 32

    def test_hash_archivo_inexistente_devuelve_none(self, base_config):
        engine = ScannerEngine(base_config)
        assert engine.get_hash("/ruta/que/no/existe/archivo.bin", 'md5') is None


class TestHeuristic:
    def test_setuid_detectado(self, base_config, setuid_file):
        engine = ScannerEngine(base_config)
        infectado, motivo = engine.heuristic_scan(str(setuid_file))
        assert infectado
        assert 'SETUID' in motivo or 'SETGID' in motivo

    def test_elf_en_tmp_detectado(self, base_config):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            tmp_path = f.name
        try:
            engine = ScannerEngine(base_config)
            infectado, motivo = engine.heuristic_scan(tmp_path)
            assert infectado
            assert 'ELF' in motivo
        finally:
            os.unlink(tmp_path)

    def test_script_ofuscado_detectado(self, base_config, temp_dir):
        p = temp_dir / "malicioso.sh"
        p.write_text("#!/bin/bash\neval $(base64 -d <<< aGVsbG8=)\n")
        engine = ScannerEngine(base_config)
        infectado, motivo = engine.heuristic_scan(str(p))
        assert infectado
        assert 'ofuscado' in motivo.lower()

    def test_archivo_inexistente_no_explota(self, base_config):
        engine = ScannerEngine(base_config)
        infectado, motivo = engine.heuristic_scan("/ruta/que/no/existe")
        assert not infectado


class TestQuarantine:
    def test_cuarentena_mueve_archivo(self, base_config, clean_file):
        engine = ScannerEngine(base_config)
        original = str(clean_file)
        destino = engine.quarantine(original, "Test manual")

        assert destino is not None
        assert not os.path.exists(original), "El original debe haber sido movido"
        assert os.path.exists(destino), "El archivo debe estar en cuarentena"
        assert os.path.exists(destino + ".log"), "Debe existir el log"

    def test_log_cuarentena_contiene_motivo(self, base_config, clean_file):
        engine = ScannerEngine(base_config)
        destino = engine.quarantine(str(clean_file), "Motivo de prueba")
        with open(destino + ".log") as f:
            contenido = f.read()
        assert "Motivo de prueba" in contenido
        assert "Origen:" in contenido

    def test_cuarentena_archivo_inexistente_devuelve_none(self, base_config):
        engine = ScannerEngine(base_config)
        resultado = engine.quarantine("/ruta/que/no/existe", "test")
        assert resultado is None


class TestScanFileRobustez:
    def test_archivo_sin_permisos_no_explota(self, base_config, temp_dir):
        p = temp_dir / "sin_permisos.txt"
        p.write_text("contenido")
        os.chmod(p, 0o000)
        try:
            engine = ScannerEngine(base_config)
            infectado, motivo = engine.scan_file(str(p))
            assert isinstance(infectado, bool)
        finally:
            os.chmod(p, 0o644)

    def test_archivo_grande_no_explota(self, base_config, temp_dir):
        p = temp_dir / "grande.bin"
        with open(p, "wb") as f:
            for _ in range(100):
                f.write(b"\x00" * (1024 * 1024))
        engine = ScannerEngine(base_config)
        infectado, motivo = engine.scan_file(str(p))
        assert isinstance(infectado, bool)
