"""
Tests de antivirus_daemon.py.

Foco:
  - pid_file_is_stale: detección correcta de PIDs huérfanos
  - acquire_pid_file: maneja colisiones, limpia huérfanos, registra atexit
  - build_arg_parser: subcomandos y argumentos
  - load_config: JSON inválido, archivo inexistente
  - AntivirusDaemon: init con AV_TEST_MODE, shutdown ordenado
"""
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Aísla el entorno para no tocar archivos reales del usuario."""
    monkeypatch.setenv("AV_TEST_MODE", "1")
    monkeypatch.setenv("AV_PID_FILE", str(tmp_path / "test.pid"))
    monkeypatch.setenv("AV_LOG_DIR", str(tmp_path / "logs"))
    # Config temporal mínimo
    cfg = {
        "cuarentena": str(tmp_path / "cuarentena"),
        "max_firmas": 100,
        "log_level": "ERROR",
        "scheduled_scans": [],
    }
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("AV_CONFIG_PATH", str(cfg_path))
    yield


def _reload_daemon_module():
    """Recarga el módulo para que recoja las variables de entorno nuevas."""
    if "antivirus_daemon" in sys.modules:
        del sys.modules["antivirus_daemon"]
    import antivirus_daemon
    return antivirus_daemon


class TestPidFileStale:
    def test_pid_file_inexistente_es_stale(self, tmp_path):
        mod = _reload_daemon_module()
        assert mod.pid_file_is_stale(tmp_path / "no_existe.pid") is True

    def test_pid_file_con_pid_propio_no_es_stale(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "test.pid"
        p.write_text(str(os.getpid()))
        assert mod.pid_file_is_stale(p) is False

    def test_pid_file_con_pid_inexistente_es_stale(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "test.pid"
        # PID muy alto que casi seguro no existe
        p.write_text("999999")
        assert mod.pid_file_is_stale(p) is True

    def test_pid_file_con_contenido_basura_es_stale(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "test.pid"
        p.write_text("no_es_un_numero")
        assert mod.pid_file_is_stale(p) is True

    def test_pid_file_vacio_es_stale(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "test.pid"
        p.write_text("")
        assert mod.pid_file_is_stale(p) is True


class TestAcquirePidFile:
    def test_crea_pid_file_si_no_existe(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "test.pid"
        mod.acquire_pid_file(p)
        assert p.exists()
        assert int(p.read_text()) == os.getpid()

    def test_falla_si_pid_activo(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "test.pid"
        p.write_text(str(os.getpid()))  # este proceso existe
        with pytest.raises(SystemExit):
            mod.acquire_pid_file(p)

    def test_limpia_pid_huerfano(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "test.pid"
        p.write_text("999999")  # casi seguro inexistente
        mod.acquire_pid_file(p)
        assert int(p.read_text()) == os.getpid()


class TestLoadConfig:
    def test_json_valido(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "config.json"
        p.write_text('{"clave": "valor"}')
        cfg = mod.load_config(p)
        assert cfg == {"clave": "valor"}

    def test_archivo_inexistente_sale(self, tmp_path):
        mod = _reload_daemon_module()
        with pytest.raises(SystemExit):
            mod.load_config(tmp_path / "no_existe.json")

    def test_json_invalido_sale(self, tmp_path):
        mod = _reload_daemon_module()
        p = tmp_path / "config.json"
        p.write_text("{esto no es json}")
        with pytest.raises(SystemExit):
            mod.load_config(p)


class TestArgParser:
    def test_sin_argumentos(self):
        mod = _reload_daemon_module()
        args = mod.build_arg_parser().parse_args([])
        assert args.command is None

    def test_subcomando_update(self):
        mod = _reload_daemon_module()
        args = mod.build_arg_parser().parse_args(["update"])
        assert args.command == "update"

    def test_subcomando_scan_memory(self):
        mod = _reload_daemon_module()
        args = mod.build_arg_parser().parse_args(["scan-memory"])
        assert args.command == "scan-memory"

    def test_subcomando_scan_folder_con_ruta(self):
        mod = _reload_daemon_module()
        args = mod.build_arg_parser().parse_args(["scan-folder", "/tmp"])
        assert args.command == "scan-folder"
        assert args.folder == "/tmp"

    def test_subcomando_scan_folder_sin_ruta(self):
        mod = _reload_daemon_module()
        args = mod.build_arg_parser().parse_args(["scan-folder"])
        # default es cwd
        assert args.folder == os.getcwd()

    def test_subcomando_zt_attest(self):
        mod = _reload_daemon_module()
        args = mod.build_arg_parser().parse_args(["zt-attest"])
        assert args.command == "zt-attest"


class TestDaemonInit:
    def test_init_no_explota_en_test_mode(self, tmp_path):
        mod = _reload_daemon_module()
        cfg_path = Path(os.environ["AV_CONFIG_PATH"])
        config = json.loads(cfg_path.read_text())
        config["cuarentena"] = str(tmp_path / "cuarentena_test")
        config["threat_store_db"] = str(tmp_path / "threat.db")

        with patch.object(mod, "subprocess"):
            daemon = mod.AntivirusDaemon(config)

        assert daemon.engine is not None
        assert daemon.scheduler is not None
        assert daemon.threat_store is not None
        assert daemon.sigma is not None
        assert daemon.soar is not None
        # En test mode, estos deben ser None
        assert daemon.telemetry is None
        assert daemon.siem is None
        assert daemon.cti is None
        daemon.threat_store.close()

    def test_request_stop_marca_event(self, tmp_path):
        mod = _reload_daemon_module()
        config = json.loads(Path(os.environ["AV_CONFIG_PATH"]).read_text())
        config["cuarentena"] = str(tmp_path / "cuarentena_test")
        config["threat_store_db"] = str(tmp_path / "threat.db")

        with patch.object(mod, "subprocess"):
            daemon = mod.AntivirusDaemon(config)

        assert not daemon.stop_event.is_set()
        daemon.request_stop()
        assert daemon.stop_event.is_set()
        daemon.threat_store.close()


class TestShutdown:
    def test_shutdown_no_explota_sin_componentes(self, tmp_path):
        mod = _reload_daemon_module()
        config = json.loads(Path(os.environ["AV_CONFIG_PATH"]).read_text())
        config["cuarentena"] = str(tmp_path / "cuarentena_test")
        config["threat_store_db"] = str(tmp_path / "threat.db")

        with patch.object(mod, "subprocess"):
            daemon = mod.AntivirusDaemon(config)
        # Nunca arrancamos run(); llamar _shutdown directamente no debe explotar.
        daemon._shutdown()

    def test_manual_update_llama_freshclam(self, tmp_path):
        mod = _reload_daemon_module()
        config = json.loads(Path(os.environ["AV_CONFIG_PATH"]).read_text())
        config["cuarentena"] = str(tmp_path / "cuarentena_test")
        config["threat_store_db"] = str(tmp_path / "threat.db")

        with patch.object(mod, "subprocess") as mock_sub:
            daemon = mod.AntivirusDaemon(config)
            mock_sub.run.reset_mock()
            daemon.manual_update()
            # Debe haber llamado a subprocess.run al menos una vez (freshclam)
            assert mock_sub.run.call_count >= 1
        daemon.threat_store.close()
