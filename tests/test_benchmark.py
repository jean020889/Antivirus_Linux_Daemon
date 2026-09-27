"""
Benchmark realista de ScannerEngine.

A diferencia de la versión anterior, este benchmark:
  - Usa archivos grandes (1–16 MB) donde el hashing domina el tiempo.
  - Repite cada medición N veces y reporta la MEDIANA (estadística robusta).
  - Mide con clamd real si está disponible; si no, marca skip en esas pruebas.
  - Compara secuencial vs multihilo, y con vs sin proxy.
  - Documenta explícitamente qué mide y qué NO mide.

Los tests solo verifican cordura (completitud). Las métricas se imprimen con -s
y se usan para decidir diseño, no para pass/fail.
"""
import hashlib
import os
import statistics
import threading
import time
from pathlib import Path

import pytest

from core.scanner import ScannerEngine
from core.clamd_pool import ClamdPool, ClamdError
from security_utils import ThreadSafeProxy


REPETICIONES = 5  # cuántas veces repetir cada medición


def _make_engine(tmp_path, n_firmas=500):
    """Engine con firmas sintéticas y cuarentena aislada."""
    config = {
        "cuarentena": str(tmp_path / "cuarentena"),
        "max_firmas": n_firmas,
        "umbral_riesgo": 0.7,
        "clamd_pool_size": 4,
    }
    engine = ScannerEngine(config)
    fake_md5 = frozenset(
        hashlib.md5(f"synthetic_{i}".encode()).hexdigest() for i in range(n_firmas)
    )
    engine.firmas_md5 = fake_md5
    engine.firmas_sha1 = frozenset()
    engine.firmas_hex = ()
    engine.total_firmas = n_firmas
    engine.clamd_pool = None  # desactivar clamd
    return engine


def _make_files(root: Path, n: int, size_bytes: int) -> list[Path]:
    """Genera N archivos de tamaño fijo."""
    root.mkdir(parents=True, exist_ok=True)
    files = []
    payload = os.urandom(size_bytes)
    for i in range(n):
        p = root / f"file_{i:04d}.bin"
        # Contenido distinto por archivo para que el hash no se cachee
        p.write_bytes(payload + str(i).encode())
        files.append(p)
    return files


def _run_sequential(engine, files) -> float:
    t0 = time.perf_counter()
    for f in files:
        engine.scan_file(str(f))
    return time.perf_counter() - t0


def _run_multithread(engine, files, workers) -> tuple[float, list]:
    chunks = [files[i::workers] for i in range(workers)]
    errors = []
    def worker(chunk):
        for f in chunk:
            try:
                engine.scan_file(str(f))
            except Exception as e:
                errors.append((f, e))
    threads = [threading.Thread(target=worker, args=(c,)) for c in chunks]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return time.perf_counter() - t0, errors


def _median_time(fn, repetitions=REPETICIONES):
    """Ejecuta fn() N veces y devuelve (mediana, todas_las_mediciones)."""
    times = [fn() for _ in range(repetitions)]
    return statistics.median(times), times


class TestBenchmarkRealista:
    def test_archivos_1mb_secuencial_vs_multihilo(self, tmp_path, capsys):
        """
        Con archivos de 1 MB, el hashing domina y el paralelismo debería
        mostrar speedup real si el GIL se libera durante hashlib.
        """
        files = _make_files(tmp_path / "files_1mb", n=20, size_bytes=1024 * 1024)

        engine = _make_engine(tmp_path, n_firmas=500)

        # Mediana de 5 corridas secuenciales
        t_seq, all_seq = _median_time(lambda: _run_sequential(engine, files))

        # Mediana de 5 corridas con 4 hilos
        def run_mt():
            t, errs = _run_multithread(engine, files, workers=4)
            assert errs == []
            return t
        t_mt, all_mt = _median_time(run_mt)

        print("\n" + "=" * 64)
        print("BENCHMARK: 20 archivos × 1 MB (mediana de 5 corridas)")
        print("=" * 64)
        print(f"Secuencial:  {t_seq*1000:8.2f} ms  ({20/t_seq:7.1f} files/s)")
        print(f"4 hilos:     {t_mt*1000:8.2f} ms  ({20/t_mt:7.1f} files/s)")
        print(f"Speedup:     {t_seq/t_mt:8.2f}x")
        print(f"Todas las mediciones seq: {[f'{x*1000:.1f}ms' for x in all_seq]}")
        print(f"Todas las mediciones mt:  {[f'{x*1000:.1f}ms' for x in all_mt]}")
        print("=" * 64)

        assert t_seq > 0
        assert t_mt > 0

    def test_archivos_4mb_multihilo_escala(self, tmp_path):
        """Escala de workers con archivos de 4 MB. Aquí el paralelismo debería notarse."""
        files = _make_files(tmp_path / "files_4mb", n=12, size_bytes=4 * 1024 * 1024)

        results = {}
        for workers in (1, 2, 4):
            engine = _make_engine(tmp_path / f"eng_{workers}", n_firmas=500)
            def run():
                t, errs = _run_multithread(engine, files, workers=workers)
                assert errs == []
                return t
            t, _ = _median_time(run, repetitions=3)
            results[workers] = t

        print("\n" + "=" * 64)
        print("ESCALADO: 12 archivos × 4 MB")
        print("=" * 64)
        baseline = results[1]
        for w in (1, 2, 4):
            speedup = baseline / results[w] if results[w] > 0 else 0
            print(f"workers={w:2d}  t={results[w]*1000:8.2f} ms  speedup={speedup:5.2f}x")
        print("=" * 64)

        assert all(t > 0 for t in results.values())

    def test_impacto_proxy_con_archivos_grandes(self, tmp_path):
        """
        Con archivos grandes, el proxy debería mostrar su efecto real:
        serializar el acceso al engine, anulando el paralelismo.
        """
        files = _make_files(tmp_path / "files_proxy", n=12, size_bytes=4 * 1024 * 1024)

        # Sin proxy
        engine_direct = _make_engine(tmp_path / "direct", n_firmas=500)
        def run_direct():
            t, errs = _run_multithread(engine_direct, files, workers=4)
            assert errs == []
            return t
        t_direct, _ = _median_time(run_direct, repetitions=3)

        # Con proxy
        engine_proxy = _make_engine(tmp_path / "proxy", n_firmas=500)
        proxied = ThreadSafeProxy(engine_proxy)
        def run_proxy():
            t, errs = _run_multithread(proxied, files, workers=4)
            assert errs == []
            return t
        t_proxy, _ = _median_time(run_proxy, repetitions=3)

        print("\n" + "=" * 64)
        print("IMPACTO DE ThreadSafeProxy (12 archivos × 4 MB, 4 hilos)")
        print("=" * 64)
        print(f"Sin proxy:  {t_direct*1000:8.2f} ms")
        print(f"Con proxy:  {t_proxy*1000:8.2f} ms")
        if t_direct > 0:
            delta = (t_proxy / t_direct - 1) * 100
            print(f"Overhead:   {delta:+8.1f}%")
        print("=" * 64)

        assert t_direct > 0
        assert t_proxy > 0

    def test_peor_caso_muchos_archivos_pequenos(self, tmp_path):
        """
        Escenario realista: escaneo de /usr/bin con miles de archivos
        pequeños. Aquí el overhead por archivo domina.
        """
        files = _make_files(tmp_path / "files_many", n=500, size_bytes=8 * 1024)

        engine = _make_engine(tmp_path, n_firmas=500)
        t_seq, _ = _median_time(
            lambda: _run_sequential(engine, files),
            repetitions=3,
        )

        print("\n" + "=" * 64)
        print("PEOR CASO: 500 archivos × 8 KB (secuencial, mediana de 3)")
        print("=" * 64)
        print(f"Tiempo total:    {t_seq*1000:8.2f} ms")
        print(f"Throughput:      {500/t_seq:8.1f} files/s")
        print(f"Tiempo/archivo:  {t_seq/500*1e6:8.1f} µs")
        print("=" * 64)

        assert t_seq > 0


@pytest.mark.skipif(
    not Path("/var/run/clamav/clamd.ctl").exists(),
    reason="clamd no disponible; skip de benchmarks con clamd real",
)
class TestBenchmarkConClamd:
    """
    Benchmarks que SÍ miden el efecto del ClamdPool.
    Solo corren si clamd está arriba. Requieren permisos de lectura sobre
    /var/run/clamav/clamd.ctl (grupo clamav).
    """

    def test_pool_vs_directo(self, tmp_path):
        files = _make_files(tmp_path / "files_clamd", n=20, size_bytes=1024 * 1024)

        # Con pool
        engine_pool = _make_engine(tmp_path / "pool", n_firmas=500)
        try:
            engine_pool.clamd_pool = ClamdPool(max_size=4)
        except ClamdError as e:
            pytest.skip(f"clamd no responde: {e}")

        def run_pool():
            t, errs = _run_multithread(engine_pool, files, workers=4)
            assert errs == []
            return t
        t_pool, _ = _median_time(run_pool, repetitions=3)

        print("\n" + "=" * 64)
        print("BENCHMARK CON clamd REAL (20 archivos × 1 MB, 4 hilos)")
        print("=" * 64)
        print(f"Con ClamdPool:  {t_pool*1000:8.2f} ms  ({20/t_pool:7.1f} files/s)")
        print("=" * 64)

        engine_pool.shutdown()
        assert t_pool > 0
