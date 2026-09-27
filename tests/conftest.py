"""Fixtures compartidas para los tests del antivirus."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def eicar_file(temp_dir):
    p = temp_dir / "eicar.com"
    p.write_bytes(
        b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    )
    return p


@pytest.fixture
def clean_file(temp_dir):
    p = temp_dir / "limpio.txt"
    p.write_text("Esto es un archivo perfectamente inofensivo.\n")
    return p


@pytest.fixture
def setuid_file(temp_dir):
    p = temp_dir / "setuid_bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 100)
    os.chmod(p, 0o4755)
    return p


@pytest.fixture
def base_config(temp_dir):
    cuarentena = temp_dir / "cuarentena"
    cuarentena.mkdir(exist_ok=True)
    return {
        "cuarentena": str(cuarentena),
        "max_firmas": 1000,
        "umbral_riesgo": 0.7,
        "clamd_pool_size": 2,
    }
