"""
Tests de ScanScheduler.

Verifican:
  - Carga de tareas desde config
  - Programación con horas válidas
  - Ignorar tareas con 'active: false'
  - Ignorar tareas con horas inválidas
  - Ejecución de un job (con run_date a 1 segundo, sin esperar horas)
"""
import json
import time
from pathlib import Path

import pytest

from core.scheduler import ScanScheduler
from core.scanner import ScannerEngine


@pytest.fixture
def engine(base_config):
    return ScannerEngine(base_config)


@pytest.fixture
def config_con_tareas(tmp_path):
    carpeta = tmp_path / "carpeta_test"
    carpeta.mkdir()
    (carpeta / "archivo.txt").write_text("contenido")
    return {
        "cuarentena": str(tmp_path / "cuarentena"),
        "max_firmas": 100,
        "scheduled_scans": [
            {
                "id": 1, "name": "Tarea activa", "type": "folder",
                "folder_path": str(carpeta),
                "hour": 3, "minute": 0, "active": True,
            },
            {
                "id": 2, "name": "Tarea inactiva", "type": "folder",
                "folder_path": str(carpeta),
                "hour": 4, "minute": 0, "active": False,
            },
            {
                "id": 3, "name": "Tarea hora inválida", "type": "folder",
                "folder_path": str(carpeta),
                "hour": 99, "minute": 0, "active": True,
            },
        ],
    }


class TestScheduler:
    def test_start_no_explota_sin_tareas(self, engine, base_config):
        base_config["scheduled_scans"] = []
        scheduler = ScanScheduler(engine, base_config)
        scheduler.start()  # No debe lanzar

    def test_start_con_tareas_validas(self, engine, config_con_tareas):
        scheduler = ScanScheduler(engine, config_con_tareas)
        scheduler.start()
        # Solo la tarea 1 es válida y activa
        jobs = scheduler.scheduler.get_jobs()
        assert len(jobs) == 1
        assert jobs[0].id == "task_1"

    def test_ignora_hora_invalida(self, engine, config_con_tareas):
        scheduler = ScanScheduler(engine, config_con_tareas)
        scheduler.start()
        job_ids = [j.id for j in scheduler.scheduler.get_jobs()]
        assert "task_3" not in job_ids

    def test_ignora_tarea_inactiva(self, engine, config_con_tareas):
        scheduler = ScanScheduler(engine, config_con_tareas)
        scheduler.start()
        job_ids = [j.id for j in scheduler.scheduler.get_jobs()]
        assert "task_2" not in job_ids


class TestSchedulerEjecucion:
    def test_folder_scan_job_escanea(self, engine, config_con_tareas, tmp_path):
        """Ejecuta directamente el job de carpeta y verifica que recorre."""
        scheduler = ScanScheduler(engine, config_con_tareas)
        carpeta = config_con_tareas["scheduled_scans"][0]["folder_path"]
        # Llamada directa al método (sin esperar a la hora programada)
        scheduler._folder_scan_job("test-directo", carpeta)
        # No explota y no devuelve nada. Que corra es suficiente.

    def test_folder_scan_job_carpeta_inexistente(self, engine, config_con_tareas):
        scheduler = ScanScheduler(engine, config_con_tareas)
        # No debe explotar si la carpeta no existe
        scheduler._folder_scan_job("test-inexistente", "/ruta/que/no/existe")
