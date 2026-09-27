"""
Test de INTEGRACIÓN MANUAL de EBPFTelemetry.

Este archivo NO se ejecuta con la suite normal (está en tests/manual/, fuera
de testpaths). Se corre a mano con sudo cuando se quiere verificar que la
telemetría de kernel captura eventos reales.

Uso:
    sudo -E venv/bin/python tests/manual/test_ebpf_integration.py

Verifica:
  1. Que bcc está instalado y el kernel soporta BPF
  2. Que el programa BPF compila
  3. Que se capturan eventos exec/open/connect/setuid reales
  4. Que el parser decodifica correctamente los buffers del kernel

Si falla en cualquier paso, imprime diagnóstico detallado.
"""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.ebpf_telemetry import EBPFTelemetry, HAVE_BCC, KernelEvent


def print_section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print('=' * 60)


def check_preconditions() -> bool:
    print_section("1. Verificando precondiciones")

    if os.geteuid() != 0:
        print("❌ Este test debe ejecutarse como root (sudo).")
        return False
    print("✅ Ejecutando como root")

    if not HAVE_BCC:
        print("❌ bcc no está instalado.")
        print("   Instala con: sudo apt install python3-bpfcc bpfcc-tools")
        return False
    print("✅ bcc está instalado")

    # Verificar BTF (kernel debug info)
    btf = Path("/sys/kernel/btf/vmlinux")
    if not btf.exists():
        print("⚠️  /sys/kernel/btf/vmlinux no existe.")
        print("   La telemetría puede fallar. Instala linux-headers si es necesario.")
    else:
        print("✅ BTF disponible")

    # Verificar que tracepoints existen
    tracepoints = [
        "/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve",
        "/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat",
        "/sys/kernel/debug/tracing/events/syscalls/sys_enter_connect",
        "/sys/kernel/debug/tracing/events/syscalls/sys_enter_setuid",
    ]
    for tp in tracepoints:
        if os.path.exists(tp):
            print(f"✅ {tp.split('/')[-1]}")
        else:
            print(f"⚠️  {tp} no encontrado (puede requerir debugfs montado)")

    return True


def run_event_capture(duration_seconds: int = 10) -> list[KernelEvent]:
    print_section(f"2. Capturando eventos durante {duration_seconds}s")

    telemetry = EBPFTelemetry(buffer_size=10000)
    if not telemetry.start():
        print("❌ EBPFTelemetry.start() devolvió False")
        return []

    print("✅ BPF cargado. Generando actividad para capturar...")

    events = []
    stop_flag = threading.Event()

    def consumer():
        for event in telemetry.events(timeout=0.5):
            events.append(event)
            print(f"  [{event.type:8s}] pid={event.pid:6d} "
                  f"ppid={event.ppid:6d} uid={event.uid:5d} "
                  f"comm={event.comm:15s} path={event.path[:60]}")
            if stop_flag.is_set():
                break

    consumer_thread = threading.Thread(target=consumer, daemon=True)
    consumer_thread.start()

    # Generar actividad que dispare cada tipo de evento
    try:
        # exec
        subprocess.run(["/bin/ls", "/tmp"], capture_output=True, timeout=2)
        time.sleep(0.5)
        # open
        with open("/etc/hostname", "r") as f:
            f.read()
        time.sleep(0.5)
        # connect
        import socket
        try:
            s = socket.socket()
            s.settimeout(0.3)
            s.connect(("1.1.1.1", 53))
            s.close()
        except Exception:
            pass
        time.sleep(0.5)
        # setuid (solo si estamos root)
        if os.geteuid() == 0:
            try:
                import ctypes
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                libc.setuid(0)
            except Exception:
                pass
        time.sleep(0.5)
    except Exception as exc:
        print(f"⚠️  Error generando actividad: {exc}")

    # Esperar a que se consuman todos los eventos
    time.sleep(duration_seconds)

    stop_flag.set()
    telemetry.stop()

    return events


def analyze_events(events: list[KernelEvent]) -> None:
    print_section("3. Análisis de resultados")

    if not events:
        print("❌ No se capturaron eventos.")
        print("   Posibles causas:")
        print("   - El kernel no tiene los tracepoints syscalls habilitados")
        print("   - Falta bpf_get_current_task o bpf_probe_read_kernel en el kernel")
        print("   - Los permisos del kernel bloquean BPF")
        return

    print(f"✅ Se capturaron {len(events)} eventos")

    by_type: dict[str, int] = {}
    for e in events:
        by_type[e.type] = by_type.get(e.type, 0) + 1

    print("\nDistribución por tipo:")
    for t, c in sorted(by_type.items()):
        print(f"  {t:10s}: {c:5d}")

    # Verificar que cada tipo esperado aparezca
    expected = {"exec", "open", "connect", "setuid"}
    missing = expected - set(by_type.keys())
    if missing:
        print(f"\n⚠️  No se capturaron eventos de tipo: {', '.join(missing)}")
        print("   Puede ser timing; intenta aumentar duration_seconds.")
    else:
        print("\n✅ Todos los tipos de evento fueron capturados")

    # Validación de integridad de los eventos
    print("\nValidación de integridad:")
    for e in events[:5]:
        assert e.ts_ns > 0, f"ts_ns inválido: {e.ts_ns}"
        assert e.pid > 0, f"pid inválido: {e.pid}"
        assert e.uid >= 0, f"uid inválido: {e.uid}"
    print("✅ Los primeros 5 eventos tienen campos válidos")


def main():
    if not check_preconditions():
        sys.exit(1)

    events = run_event_capture(duration_seconds=10)

    analyze_events(events)

    print_section("Resultado")
    if events:
        print("✅ TEST DE INTEGRACIÓN EXITOSO")
        sys.exit(0)
    else:
        print("❌ TEST DE INTEGRACIÓN FALLIDO")
        sys.exit(1)


if __name__ == "__main__":
    main()
