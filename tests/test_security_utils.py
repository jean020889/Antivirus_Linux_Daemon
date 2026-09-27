"""
Tests de las utilidades de seguridad: ThreadSafeProxy, safe_extract_zip,
safe_extract_tar.
"""
import io
import os
import tarfile
import threading
import time
import zipfile
from pathlib import Path

import pytest

from security_utils import (
    ThreadSafeProxy,
    ZipBombError,
    PathTraversalError,
    safe_extract_zip,
    safe_extract_tar,
    ExtractionLimits,
)


class TestThreadSafeProxy:
    def test_envuelve_metodos_correctamente(self):
        class Contador:
            def __init__(self):
                self.n = 0
            def incrementar(self):
                self.n += 1
                return self.n

        c = ThreadSafeProxy(Contador())
        assert c.incrementar() == 1
        assert c.incrementar() == 2

    def test_atributos_no_callables_pasan_directo(self):
        class ConDatos:
            def __init__(self):
                self.valor = 42

        c = ThreadSafeProxy(ConDatos())
        assert c.valor == 42

    def test_concurrencia_no_corrompe_estado(self):
        class Contador:
            def __init__(self):
                self.n = 0
            def inc(self):
                v = self.n
                time.sleep(0.0001)
                self.n = v + 1

        c = ThreadSafeProxy(Contador())
        threads = [threading.Thread(target=c.inc) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert c.n == 50, f"Estado corrupto: {c.n} != 50"


class TestSafeExtractZip:
    def test_extraccion_normal(self, tmp_path):
        zpath = tmp_path / "normal.zip"
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr("archivo1.txt", "contenido 1")
            z.writestr("subdir/archivo2.txt", "contenido 2")

        dest = tmp_path / "extraido"
        extraidos = safe_extract_zip(str(zpath), str(dest))

        assert len(extraidos) == 2
        assert (dest / "archivo1.txt").read_text() == "contenido 1"
        assert (dest / "subdir" / "archivo2.txt").read_text() == "contenido 2"

    def test_zip_slip_con_punto_punto_rechazado(self, tmp_path):
        zpath = tmp_path / "malicioso.zip"
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr("../../etc/passwd_falso", "malicioso")

        dest = tmp_path / "extraido"
        with pytest.raises(PathTraversalError):
            safe_extract_zip(str(zpath), str(dest))

    def test_zip_slip_con_ruta_absoluta_rechazado(self, tmp_path):
        zpath = tmp_path / "absoluto.zip"
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr("/tmp/evil", "malicioso")

        dest = tmp_path / "extraido"
        with pytest.raises(PathTraversalError):
            safe_extract_zip(str(zpath), str(dest))

    def test_zip_bomb_por_ratio(self, tmp_path):
        zpath = tmp_path / "bomba.zip"
        with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr("bomba.bin", b"\x00" * (10 * 1024 * 1024))

        dest = tmp_path / "extraido"
        limites = ExtractionLimits(max_compression_ratio=10.0)
        with pytest.raises(ZipBombError):
            safe_extract_zip(str(zpath), str(dest), limits=limites)

    def test_zip_bomb_por_cantidad_archivos(self, tmp_path):
        zpath = tmp_path / "muchos.zip"
        with zipfile.ZipFile(zpath, 'w') as z:
            for i in range(100):
                z.writestr(f"f{i}.txt", "x")

        dest = tmp_path / "extraido"
        limites = ExtractionLimits(max_files=10)
        with pytest.raises(ZipBombError):
            safe_extract_zip(str(zpath), str(dest), limits=limites)


class TestSafeExtractTar:
    def test_extraccion_normal(self, tmp_path):
        tpath = tmp_path / "normal.tar"
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.txt").write_text("hola")
        (src / "b.txt").write_text("mundo")

        with tarfile.open(tpath, 'w') as t:
            t.add(src / "a.txt", arcname="a.txt")
            t.add(src / "b.txt", arcname="b.txt")

        dest = tmp_path / "extraido"
        extraidos = safe_extract_tar(str(tpath), str(dest))
        assert len(extraidos) == 2

    def test_tar_con_symlink_ignorado(self, tmp_path):
        tpath = tmp_path / "symlink.tar"
        with tarfile.open(tpath, 'w') as t:
            info = tarfile.TarInfo(name="evil_symlink")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            t.addfile(info)

            info2 = tarfile.TarInfo(name="normal.txt")
            info2.size = 4
            t.addfile(info2, io.BytesIO(b"data"))

        dest = tmp_path / "extraido"
        extraidos = safe_extract_tar(str(tpath), str(dest))
        assert len(extraidos) == 1
        assert not (dest / "evil_symlink").exists()

    def test_tar_path_traversal_rechazado(self, tmp_path):
        tpath = tmp_path / "malo.tar"
        with tarfile.open(tpath, 'w') as t:
            info = tarfile.TarInfo(name="../../../etc/pwned")
            info.size = 4
            t.addfile(info, io.BytesIO(b"data"))

        dest = tmp_path / "extraido"
        with pytest.raises(PathTraversalError):
            safe_extract_tar(str(tpath), str(dest))
