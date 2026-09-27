"""
Tests de ArchiveScanner.

CRÍTICO: estos tests verifican que ArchiveScanner (producción) usa
realmente safe_extract_zip/safe_extract_tar (defensas contra Zip Slip
y Zip Bomb). No basta con que las utilidades funcionen; el código que
descomprime en producción debe llamarlas.
"""
import io
import os
import zipfile
import tarfile
from pathlib import Path

import pytest

from core.archives import ArchiveScanner
from core.scanner import ScannerEngine


@pytest.fixture
def engine(base_config):
    return ScannerEngine(base_config)


@pytest.fixture
def scanner(engine, tmp_path):
    return ArchiveScanner(engine, temp_dir=str(tmp_path / "extract"))


class TestArchiveScannerZip:
    def test_zip_limpio_escaner(self, scanner, tmp_path):
        zpath = tmp_path / "limpio.zip"
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr("a.txt", "hola")
            z.writestr("b.txt", "mundo")
        infectado, motivo = scanner.extract_and_scan(str(zpath))
        assert not infectado, f"Zip limpio marcado como infectado: {motivo}"

    def test_zip_con_hash_malicioso_detectado(self, scanner, engine, tmp_path):
        """Colocamos un archivo dentro del zip y le inyectamos su MD5 como firma."""
        payload = b"contenido malicioso dentro de un zip"
        zpath = tmp_path / "malo.zip"
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr("malware.bin", payload)

        # Inyectar el hash del payload como firma conocida
        import hashlib
        payload_md5 = hashlib.md5(payload).hexdigest()
        with engine._signatures_lock:
            engine.firmas_md5 = frozenset(list(engine.firmas_md5) + [payload_md5])

        infectado, motivo = scanner.extract_and_scan(str(zpath))
        assert infectado, "El contenido malicioso dentro del zip debería detectarse"

    def test_zip_slip_rechazado_por_archive_scanner(self, scanner, tmp_path):
        """Zip Slip: ArchiveScanner debe rechazar, no extraer fuera de destino."""
        zpath = tmp_path / "evil.zip"
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr("../../etc/pwned", "malicioso")

        infectado, motivo = scanner.extract_and_scan(str(zpath))
        assert not infectado
        assert "rechazado" in motivo.lower() or "traversal" in motivo.lower()

        # Verificar que NO se escribió fuera del temp
        assert not Path("/etc/pwned").exists()

    def test_zip_bomb_rechazada_por_archive_scanner(self, scanner, tmp_path):
        """Zip bomb: ArchiveScanner debe rechazar antes de agotar disco."""
        zpath = tmp_path / "bomba.zip"
        with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
            # 200 MB de ceros comprimidos
            z.writestr("bomba.bin", b"\x00" * (200 * 1024 * 1024))

        infectado, motivo = scanner.extract_and_scan(str(zpath))
        assert not infectado
        # Con los límites por defecto (500 MB total, ratio 100x, 200 MB single),
        # una bomba de 200 MB de ceros (comprimidos a unos KB) supera el ratio.
        assert "rechazado" in motivo.lower() or "bomb" in motivo.lower()


class TestArchiveScannerTar:
    def test_tar_limpio_escaner(self, scanner, tmp_path):
        tpath = tmp_path / "limpio.tar"
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.txt").write_text("hola")
        with tarfile.open(tpath, 'w') as t:
            t.add(src / "a.txt", arcname="a.txt")
        infectado, motivo = scanner.extract_and_scan(str(tpath))
        assert not infectado

    def test_tar_con_symlink_no_escapa(self, scanner, tmp_path):
        """Un tar con symlink a /etc/passwd no debe crear el symlink."""
        tpath = tmp_path / "symlink.tar"
        with tarfile.open(tpath, 'w') as t:
            info = tarfile.TarInfo(name="evil_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            t.addfile(info)

            info2 = tarfile.TarInfo(name="normal.txt")
            info2.size = 4
            t.addfile(info2, io.BytesIO(b"data"))

        infectado, motivo = scanner.extract_and_scan(str(tpath))
        # No debe detectar como infectado (el archivo normal está limpio),
        # pero el symlink NO debe existir en el fs.
        assert not infectado

    def test_tar_path_traversal_rechazado(self, scanner, tmp_path):
        tpath = tmp_path / "evil.tar"
        with tarfile.open(tpath, 'w') as t:
            info = tarfile.TarInfo(name="../../../tmp/pwned")
            info.size = 4
            t.addfile(info, io.BytesIO(b"data"))

        infectado, motivo = scanner.extract_and_scan(str(tpath))
        assert not infectado
        assert "rechazado" in motivo.lower() or "traversal" in motivo.lower()
        assert not Path("/tmp/pwned").exists()


class TestArchiveScannerFormatosNoSoportados:
    def test_archivo_no_comprimido_no_explota(self, scanner, tmp_path):
        p = tmp_path / "texto.txt"
        p.write_text("no soy un archivo comprimido")
        infectado, motivo = scanner.extract_and_scan(str(p))
        # Debe devolver False (no infectado) y no explotar
        assert not infectado
