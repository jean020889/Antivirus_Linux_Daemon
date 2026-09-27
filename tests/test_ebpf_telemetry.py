"""
Tests de EBPFTelemetry.

COBERTURA HONESTA:
  ✅ Parser de buffer binario (KernelEvent.from_buffer)
  ✅ Constantes de struct (tamaño, formato)
  ✅ Ciclo de vida (start/stop con bcc mockeado)
  ✅ Cola: put_nowait, events(), backpressure
  ✅ Fallback cuando bcc no está instalado

  ❌ NO cubierto (requiere kernel real + sudo):
     - Carga efectiva del programa BPF
     - Captura real de tracepoints
     - Lectura de task_struct del kernel
  Ver INSTALL.md para el test de integración manual.
"""
import struct
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from core.ebpf_telemetry import (
    KernelEvent,
    EBPFTelemetry,
    EVENT_STRUCT_FORMAT,
    EVENT_STRUCT_SIZE,
    TYPE_MAP,
    HAVE_BCC,
    _cstr,
)


def build_event_bytes(
    ts_ns=1_000_000_000,
    pid=1234,
    ppid=1,
    uid=1000,
    type_num=1,
    comm=b"bash",
    path=b"/usr/bin/bash",
):
    """Construye un buffer binario igual al que envía el kernel."""
    comm_padded = comm.ljust(16, b"\x00")[:16]
    path_padded = path.ljust(256, b"\x00")[:256]
    return struct.pack(
        EVENT_STRUCT_FORMAT,
        ts_ns, pid, ppid, uid, type_num, comm_padded, path_padded,
    )


class TestStructLayout:
    def test_struct_size_coincide_con_bpf(self):
        # 8 (ts) + 4*4 (pid,ppid,uid,type) + 16 (comm) + 256 (path)
        assert EVENT_STRUCT_SIZE == 296

    def test_type_map_cubre_todos_los_tipos(self):
        for n in (1, 2, 3, 4):
            assert n in TYPE_MAP


class TestCStr:
    def test_corta_en_primer_nul(self):
        assert _cstr(b"bash\x00garbage") == "bash"

    def test_bytes_sin_nul(self):
        assert _cstr(b"bash") == "bash"

    def test_bytes_vacios(self):
        assert _cstr(b"\x00\x00\x00") == ""

    def test_bytes_no_utf8_no_explota(self):
        # Debe reemplazar bytes inválidos, no lanzar
        result = _cstr(b"\xff\xfe\xfd")
        assert isinstance(result, str)


class TestKernelEventParser:
    def test_buffer_correcto_produce_evento(self):
        buf = build_event_bytes(
            ts_ns=999, pid=42, ppid=1, uid=1000, type_num=1,
            comm=b"bash", path=b"/usr/bin/bash",
        )
        event = KernelEvent.from_buffer(buf)
        assert event.ts_ns == 999
        assert event.pid == 42
        assert event.ppid == 1
        assert event.uid == 1000
        assert event.type == "exec"
        assert event.comm == "bash"
        assert event.path == "/usr/bin/bash"

    def test_buffer_demasiado_corto_explota(self):
        with pytest.raises(ValueError):
            KernelEvent.from_buffer(b"corto")

    def test_buffer_mas_grande_ignora_extra(self):
        buf = build_event_bytes(pid=1) + b"\x00" * 100
        event = KernelEvent.from_buffer(buf)
        assert event.pid == 1

    def test_todos_los_tipos(self):
        for num, name in TYPE_MAP.items():
            buf = build_event_bytes(type_num=num)
            event = KernelEvent.from_buffer(buf)
            assert event.type == name

    def test_tipo_desconocido(self):
        buf = build_event_bytes(type_num=99)
        event = KernelEvent.from_buffer(buf)
        assert event.type == "unknown"

    def test_is_root_para_uid_cero(self):
        buf = build_event_bytes(uid=0)
        assert KernelEvent.from_buffer(buf).is_root is True

    def test_is_root_para_uid_no_cero(self):
        buf = build_event_bytes(uid=1000)
        assert KernelEvent.from_buffer(buf).is_root is False

    def test_comm_con_null_embebido(self):
        buf = build_event_bytes(comm=b"ba\x00sh")
        event = KernelEvent.from_buffer(buf)
        assert event.comm == "ba"

    def test_path_muy_largo_se_trunca_a_255(self):
        """Defensa: aunque el buffer tenga 256 bytes útiles sin NUL,
        el parser trunca a 255 para garantizar terminación lógica."""
        # 256 caracteres exactos sin NUL intermedio
        path_256 = b"/" + b"a" * 255
        assert len(path_256) == 256
        buf = build_event_bytes(path=path_256)
        event = KernelEvent.from_buffer(buf)
        assert len(event.path) == 255

    def test_comm_muy_largo_se_trunca_a_15(self):
        """char[16] → 15 útiles tras el truncado defensivo."""
        comm_16 = b"x" * 16
        buf = build_event_bytes(comm=comm_16)
        event = KernelEvent.from_buffer(buf)
        assert len(event.comm) == 15


class TestTelemetryLifecycle:
    def test_start_sin_bcc_devuelve_false(self):
        tel = EBPFTelemetry()
        with patch("core.ebpf_telemetry.HAVE_BCC", False):
            assert tel.start() is False
        assert tel.available is False

    def test_start_con_bcc_mockeado(self):
        tel = EBPFTelemetry()
        fake_bpf = MagicMock()
        # Simular open_perf_buffer sin eventos
        fake_bpf.__getitem__ = MagicMock(return_value=MagicMock())
        with patch("core.ebpf_telemetry.HAVE_BCC", True):
            with patch("core.ebpf_telemetry.BPF", return_value=fake_bpf):
                assert tel.start() is True
                assert tel.available is True
                time.sleep(0.1)
                tel.stop()
        assert tel.available is False

    def test_start_falla_si_bpf_no_compila(self):
        tel = EBPFTelemetry()
        with patch("core.ebpf_telemetry.HAVE_BCC", True):
            with patch("core.ebpf_telemetry.BPF", side_effect=RuntimeError("no kernel support")):
                assert tel.start() is False

    def test_stop_sin_start_no_explota(self):
        tel = EBPFTelemetry()
        tel.stop()  # No debe lanzar


class TestEventQueue:
    def test_put_y_get_evento(self):
        tel = EBPFTelemetry()
        buf = build_event_bytes(pid=777)
        tel.buffer.put_nowait(KernelEvent.from_buffer(buf))
        # Consumir vía events() con timeout corto
        gen = tel.events(timeout=0.2)
        event = next(gen)
        assert event.pid == 777
        tel.stop()

    def test_backpressure_retorna_false_y_no_explota(self):
        """Si el buffer está lleno, _enqueue_event devuelve False y contabiliza
        el drop, sin lanzar excepción."""
        tel = EBPFTelemetry(buffer_size=2)
        ev1 = KernelEvent(0, 1, 0, 0, "exec", "a", "b")
        ev2 = KernelEvent(0, 2, 0, 0, "exec", "a", "b")
        ev3 = KernelEvent(0, 3, 0, 0, "exec", "a", "b")

        assert tel._enqueue_event(ev1) is True
        assert tel._enqueue_event(ev2) is True
        # El tercero debe fallar silenciosamente
        assert tel._enqueue_event(ev3) is False
        assert tel.events_received == 3
        assert tel.events_dropped == 1

    def test_enqueue_evento_normal(self):
        tel = EBPFTelemetry(buffer_size=10)
        ev = KernelEvent(0, 1, 0, 0, "exec", "a", "b")
        assert tel._enqueue_event(ev) is True
        assert tel.events_received == 1
        assert tel.events_dropped == 0

    def test_events_generador_termina_al_stop(self):
        tel = EBPFTelemetry()
        received = []

        def consumer():
            for ev in tel.events(timeout=0.1):
                received.append(ev)
                if len(received) >= 1:
                    break

        t = threading.Thread(target=consumer, daemon=True)
        t.start()
        time.sleep(0.05)
        tel.buffer.put_nowait(KernelEvent(0, 1, 0, 0, "exec", "x", "y"))
        t.join(timeout=2)
        assert len(received) == 1
        tel.stop()


# ---------------------------------------------------------------- integración
@pytest.mark.skipif(not HAVE_BCC, reason="bcc no instalado; test de integración omitido")
class TestIntegrationRequiereKernel:
    """
    Estos tests SOLO corren si bcc está instalado. Aun así, cargar el BPF
    requiere permisos (sudo). Por eso están marcados como skip cuando no
    se cumplen las condiciones.

    Para correrlos manualmente con privilegios:
        sudo -E venv/bin/python -m pytest tests/test_ebpf_telemetry.py::TestIntegrationRequiereKernel -v -s
    """

    def test_carga_bpf_real(self):
        import os
        if os.geteuid() != 0:
            pytest.skip("Requiere root para cargar BPF")
        tel = EBPFTelemetry()
        assert tel.start() is True
        time.sleep(0.5)
        tel.stop()
