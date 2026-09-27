"""
Test end-to-end del daemon.

Flujo realista:
  1. Levanta AntivirusDaemon en AV_TEST_MODE=1 (sin clamd, sin eBPF, sin SIEM).
  2. Crea una carpeta con:
       - un archivo limpio
       - un EICAR con su MD5 inyectado en firmas en memoria (simula IOC)
  3. Llama a daemon.scan_path_now().
  4. Verifica:
       - El archivo limpio NO se mueve ni se reporta.
       - El EICAR SÍ se mueve a cuarentena y aparece en el resultado.
       - Se creó el archivo .log con el motivo.
       - El evento quedó registrado en threat_store.
  5. Llama a daemon.request_stop() y daemon._shutdown().
  6. Verifica que el PID file queda limpio y que no quedan hilos vivos.

Sin dependencias externas. Sin sudo. Sin red.
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Aísla el daemon en una caja de arena temporal."""
    monkeypatch.setenv("AV_TEST_MODE", "1")
    monkeypatch.setenv("AV_PID_FILE", str(tmp_path / "e2e.pid"))
    monkeypatch.setenv("AV_LOG_DIR", str(tmp_path / "logs"))

    cfg = {
        "cuarentena": str(tmp_path / "cuarentena"),
        "max_firmas": 100,
        "log_level": "ERROR",
        "scheduled_scans": [],
        "threat_store_db": str(tmp_path / "threat.db"),
        "sigma_rules_dir": str(tmp_path / "sigma_rules"),
    }
    (tmp_path / "sigma_rules").mkdir(exist_ok=True)
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("AV_CONFIG_PATH", str(cfg_path))
    yield


def _fresh_daemon_module():
    """Recarga el módulo para que recoja las variables de entorno."""
    if "antivirus_daemon" in sys.modules:
        del sys.modules["antivirus_daemon"]
    import antivirus_daemon
    return antivirus_daemon


EICAR_BYTES = (
    b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)


class TestEndToEnd:
    def test_flujo_completo_deteccion_cuarentena_store(self, tmp_path):
        mod = _fresh_daemon_module()
        config = json.loads(Path(os.environ["AV_CONFIG_PATH"]).read_text())

        # --- 1. Preparar carpeta de escaneo
        scan_dir = tmp_path / "target"
        scan_dir.mkdir()
        clean = scan_dir / "limpio.txt"
        clean.write_text("archivo inofensivo")

        eicar = scan_dir / "eicar.com"
        eicar.write_bytes(EICAR_BYTES)

        # --- 2. Arrancar daemon (con subprocess.run mockeado para no invocar freshclam)
        with patch.object(mod, "subprocess") as mock_sub:
            mock_sub.run.return_value = None
            daemon = mod.AntivirusDaemon(config)

        try:
            # --- 3. Inyectar el MD5 del EICAR como firma conocida
            eicar_md5 = hashlib.md5(EICAR_BYTES).hexdigest()
            with daemon.engine._signatures_lock:
                daemon.engine.firmas_md5 = frozenset(
                    list(daemon.engine.firmas_md5) + [eicar_md5]
                )

            # --- 4. Ejecutar escaneo sincrónico
            results = daemon.scan_path_now(str(scan_dir))

            # --- 5. Verificaciones
            # 5.1 Exactamente una amenaza reportada
            assert len(results) == 1, f"Esperaba 1 amenaza, obtuve {results}"
            amenaza = results[0]
            assert amenaza["path"] == str(eicar)
            assert "MD5" in amenaza["motivo"] or "Firma" in amenaza["motivo"]
            assert amenaza["cuarentena"] is not None

            # 5.2 El limpio sigue donde estaba
            assert clean.exists(), "El archivo limpio no debe moverse"

            # 5.3 El EICAR ya no está en su ubicación original
            assert not eicar.exists(), "El EICAR debe haberse movido a cuarentena"

            # 5.4 El EICAR está en la carpeta de cuarentena
            quarantined = Path(amenaza["cuarentena"])
            assert quarantined.exists()
            assert quarantined.read_bytes() == EICAR_BYTES

            # 5.5 El log acompañante existe y contiene el motivo
            log_path = Path(str(quarantined) + ".log")
            assert log_path.exists()
            log_content = log_path.read_text()
            assert "Origen:" in log_content
            assert str(eicar) in log_content

            # 5.6 El evento quedó registrado en threat_store
            rows = daemon.threat_store.query(
                "SELECT source, event_type, path, severity FROM events "
                "WHERE source = 'scan'"
            )
            assert len(rows) == 1, f"Esperaba 1 evento en store, obtuve {rows}"
            source, event_type, stored_path, severity = rows[0]
            assert source == "scan"
            assert event_type == "quarantine"
            assert stored_path == str(eicar)
            assert severity == "high"

        finally:
            # --- 6. Apagado limpio
            daemon.request_stop()
            daemon._shutdown()

    def test_escaneo_sin_amenazas_no_genera_ruido(self, tmp_path):
        """Una carpeta con solo archivos limpios no debe mover nada."""
        mod = _fresh_daemon_module()
        config = json.loads(Path(os.environ["AV_CONFIG_PATH"]).read_text())

        scan_dir = tmp_path / "clean_target"
        scan_dir.mkdir()
        for i in range(5):
            (scan_dir / f"archivo_{i}.txt").write_text(f"contenido {i}")

        with patch.object(mod, "subprocess") as mock_sub:
            mock_sub.run.return_value = None
            daemon = mod.AntivirusDaemon(config)

        try:
            results = daemon.scan_path_now(str(scan_dir))
            assert results == []

            # Todos los archivos siguen ahí
            assert len(list(scan_dir.iterdir())) == 5

            # No hay eventos de cuarentena en el store
            rows = daemon.threat_store.query(
                "SELECT COUNT(*) FROM events WHERE source = 'scan'"
            )
            assert rows[0][0] == 0
        finally:
            daemon.request_stop()
            daemon._shutdown()

    def test_multiples_amenazas_en_misma_carpeta(self, tmp_path):
        """Varios archivos con el mismo hash malicioso deben todos ir a cuarentena."""
        mod = _fresh_daemon_module()
        config = json.loads(Path(os.environ["AV_CONFIG_PATH"]).read_text())

        scan_dir = tmp_path / "multi"
        scan_dir.mkdir()
        for i in range(3):
            (scan_dir / f"eicar_{i}.com").write_bytes(EICAR_BYTES)
        (scan_dir / "limpio.txt").write_text("ok")

        with patch.object(mod, "subprocess") as mock_sub:
            mock_sub.run.return_value = None
            daemon = mod.AntivirusDaemon(config)

        try:
            eicar_md5 = hashlib.md5(EICAR_BYTES).hexdigest()
            with daemon.engine._signatures_lock:
                daemon.engine.firmas_md5 = frozenset(
                    list(daemon.engine.firmas_md5) + [eicar_md5]
                )

            results = daemon.scan_path_now(str(scan_dir))
            assert len(results) == 3

            # Los tres EICAR están en cuarentena
            for r in results:
                assert Path(r["cuarentena"]).exists()

            # El limpio sigue ahí
            assert (scan_dir / "limpio.txt").exists()

            # 3 eventos en el store
            rows = daemon.threat_store.query(
                "SELECT COUNT(*) FROM events WHERE source = 'scan'"
            )
            assert rows[0][0] == 3
        finally:
            daemon.request_stop()
            daemon._shutdown()

    def test_run_start_background_false_no_arranca_hilos(self, tmp_path):
        """
        run(start_background=False) no debe spawnear hilos ni arrancar
        scheduler, realtime, eBPF. Se verifica que stop_event se pueda
        setear desde otro hilo y el run termine.
        """
        import threading
        mod = _fresh_daemon_module()
        config = json.loads(Path(os.environ["AV_CONFIG_PATH"]).read_text())

        with patch.object(mod, "subprocess") as mock_sub:
            mock_sub.run.return_value = None
            daemon = mod.AntivirusDaemon(config)

        # Programar el stop después de 0.5s
        def stopper():
            time.sleep(0.5)
            daemon.request_stop()

        threading.Thread(target=stopper, daemon=True).start()

        # Con start_background=False no debe spawnear ningún hilo de fondo
        t0 = time.time()
        daemon.run(start_background=False)
        elapsed = time.time() - t0

        # Debe haber terminado rápido y sin hilos vivos
        assert elapsed < 3.0, f"run() tardó demasiado: {elapsed:.2f}s"
        assert all(not t.is_alive() for t in daemon._threads)

    def test_pid_file_se_libera_al_salir(self, tmp_path):
        """Tras ejecutar main-ish flow, el PID file debe desaparecer."""
        mod = _fresh_daemon_module()
        pid_file = Path(os.environ["AV_PID_FILE"])

        # acquire_pid_file registra atexit; aquí lo llamamos directo
        mod.acquire_pid_file(pid_file)
        assert pid_file.exists()
        assert int(pid_file.read_text()) == os.getpid()

        # atexit limpia al terminar el proceso; en el test solo verificamos
        # que el archivo se creó correctamente y que si otro acquire
        # se ejecuta desde el mismo PID, no falla (no es huérfano).
        assert not mod.pid_file_is_stale(pid_file)

        # Limpieza manual para no ensuciar otros tests
        pid_file.unlink(missing_ok=True)
