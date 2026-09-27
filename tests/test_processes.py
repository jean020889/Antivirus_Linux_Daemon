"""
Tests de ProcessScanner.

Verifican:
  - scan_all no explota y devuelve lista
  - No se cuelga con procesos sin permisos
"""
import pytest

from core.processes import ProcessScanner
from core.scanner import ScannerEngine


@pytest.fixture
def engine(base_config):
    return ScannerEngine(base_config)


class TestProcessScanner:
    def test_scan_all_no_explota(self, engine):
        scanner = ProcessScanner(engine)
        resultado = scanner.scan_all()
        assert isinstance(resultado, list)
        # No debe contener entradas inválidas
        for item in resultado:
            assert len(item) == 3  # (pid, exe, motivo)
            pid, exe, motivo = item
            assert isinstance(pid, int)
            assert isinstance(exe, str)
            assert isinstance(motivo, str)
