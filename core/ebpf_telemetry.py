"""
core/ebpf_telemetry.py
Telemetría de kernel vía eBPF usando bcc.

Captura en tiempo real, desde tracepoints del kernel:
  - sys_enter_execve    → ejecución de procesos
  - sys_enter_openat    → apertura de archivos
  - sys_enter_connect   → conexiones de red salientes
  - sys_enter_setuid    → cambios de privilegios

Arquitectura:
  - El programa BPF (string en BPF_PROGRAM) define el struct event_t.
  - El parser KernelEvent.from_buffer decodifica el struct binario.
  - El parser está desacoplado de bcc para permitir tests sin kernel.
  - Si bcc no está disponible, start() devuelve False y events() no
    produce nada; el daemon debe usar un fallback (psutil) en su lugar.

Limitaciones conocidas:
  - El struct event_t tiene un layout binario específico. Si se cambia
    en BPF_PROGRAM, hay que actualizar KernelEvent.from_buffer.
  - ppid se lee de task->real_parent->tgid, que puede fallar en kernels
    muy recientes; se documenta como 0 si falla.
  - La cola buffer tiene tamaño fijo; si se llena, se descartan eventos
    (backpressure). No hay muestreo aún.
"""

from __future__ import annotations

import ctypes
import logging
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass
from queue import Queue, Empty
from typing import Iterator

logger = logging.getLogger("antivirus.ebpf")

try:
    from bcc import BPF
    HAVE_BCC = True
except ImportError:
    BPF = None  # type: ignore[assignment]
    HAVE_BCC = False


# ---------------------------------------------------------------- BPF program
# Debe coincidir con KernelEvent.from_buffer: struct event_t
#   u64 ts_ns     → 8 bytes (offset 0)
#   u32 pid       → 4 bytes (offset 8)
#   u32 ppid      → 4 bytes (offset 12)
#   u32 uid       → 4 bytes (offset 16)
#   u32 type      → 4 bytes (offset 20)
#   char comm[16] → 16 bytes (offset 24)
#   char path[256]→ 256 bytes (offset 40)
# Total: 296 bytes
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u64 ts_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 type;          // 1=exec, 2=open, 3=connect, 4=setuid
    char comm[16];
    char path[256];
};

BPF_PERF_OUTPUT(events);

static __always_inline void fill_common(struct event_t *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    u32 ppid = 0;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    e->ppid = ppid;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t e = {};
    fill_common(&e);
    e.type = 1;
    bpf_probe_read_user_str(&e.path, sizeof(e.path), (void *)args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t e = {};
    fill_common(&e);
    e.type = 2;
    bpf_probe_read_user_str(&e.path, sizeof(e.path), (void *)args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t e = {};
    fill_common(&e);
    e.type = 3;
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct event_t e = {};
    fill_common(&e);
    e.type = 4;
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


# ---------------------------------------------------------------- event parser
EVENT_STRUCT_FORMAT = "<QIIII16s256s"
EVENT_STRUCT_SIZE = struct.calcsize(EVENT_STRUCT_FORMAT)
assert EVENT_STRUCT_SIZE == 296, f"Layout inesperado: {EVENT_STRUCT_SIZE}"

TYPE_MAP = {1: "exec", 2: "open", 3: "connect", 4: "setuid"}


@dataclass(frozen=True)
class KernelEvent:
    ts_ns: int
    pid: int
    ppid: int
    uid: int
    type: str
    comm: str
    path: str

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    @classmethod
    def from_buffer(cls, data: bytes) -> "KernelEvent":
        """
        Decodifica un buffer binario proveniente de perf_submit.
        Debe tener al menos EVENT_STRUCT_SIZE bytes; se ignoran los extra.

        Los campos char[N] se normalizan: se cortan en el primer NUL y se
        decodifican como UTF-8 con errores reemplazados.
        """
        if len(data) < EVENT_STRUCT_SIZE:
            raise ValueError(
                f"Buffer demasiado corto: {len(data)} < {EVENT_STRUCT_SIZE}"
            )
        unpacked = struct.unpack_from(EVENT_STRUCT_FORMAT, data, 0)
        ts_ns, pid, ppid, uid, type_num, comm_raw, path_raw = unpacked
        return cls(
            ts_ns=ts_ns,
            pid=pid,
            ppid=ppid,
            uid=uid,
            type=TYPE_MAP.get(type_num, "unknown"),
            comm=_cstr(comm_raw, max_len=15),   # char[16] → 15 + NUL
            path=_cstr(path_raw, max_len=255),  # char[256] → 255 + NUL
        )


def _cstr(raw: bytes, max_len: int | None = None) -> str:
    """
    Corta en el primer NUL y decodifica.
    Si max_len está definido, trunca el resultado a ese número de caracteres.
    Esto es defensa en profundidad: aunque el struct declare char[256],
    un buffer sin NUL puede entregar 256 bytes útiles que confundan a
    consumidores posteriores (YARA, Sigma, IOCs).
    """
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    s = raw.decode("utf-8", errors="replace")
    if max_len is not None and len(s) > max_len:
        s = s[:max_len]
    return s


# ---------------------------------------------------------------- telemetry
class EBPFTelemetry:
    def __init__(self, buffer_size: int = 10000):
        self.buffer: Queue[KernelEvent] = Queue(maxsize=buffer_size)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._bpf = None
        self.available = False
        self.events_received = 0
        self.events_dropped = 0

    def _enqueue_event(self, event: KernelEvent) -> bool:
        """
        Encola un evento. Devuelve True si se encoló, False si el buffer
        está lleno (backpressure). Nunca lanza.
        """
        self.events_received += 1
        try:
            self.buffer.put_nowait(event)
            return True
        except Exception:
            self.events_dropped += 1
            return False

    def start(self) -> bool:
        if not HAVE_BCC:
            logger.warning("bcc no instalado; telemetría eBPF deshabilitada.")
            return False
        try:
            self._bpf = BPF(text=BPF_PROGRAM)
        except Exception as exc:
            logger.error("No se pudo compilar el programa BPF: %s", exc)
            return False

        def _handle(cpu, data, size):
            try:
                # Copiar exactamente 'size' bytes del buffer del perf ring.
                # bytes(data) puede intentar leer más allá del buffer y
                # provocar MemoryError en algunas versiones de bcc.
                raw = ctypes.string_at(data, size)
                event = KernelEvent.from_buffer(raw)
                self._enqueue_event(event)
            except Exception:
                logger.exception("Error procesando evento BPF")

        try:
            self._bpf["events"].open_perf_buffer(_handle)
        except Exception as exc:
            logger.error("No se pudo abrir el perf buffer: %s", exc)
            return False

        self._thread = threading.Thread(target=self._poll_loop, name="ebpf-poll", daemon=True)
        self._thread.start()
        self.available = True
        logger.info("Telemetría eBPF activa: exec, open, connect, setuid.")
        return True

    def _poll_loop(self):
        while not self._stop.is_set():
            try:
                self._bpf.perf_buffer_poll(timeout=200)
            except Exception:
                logger.exception("Error en perf_buffer_poll")
                time.sleep(1)

    def events(self, timeout: float = 0.5) -> Iterator[KernelEvent]:
        while not self._stop.is_set():
            try:
                yield self.buffer.get(timeout=timeout)
            except Empty:
                continue

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._bpf:
            try:
                self._bpf.cleanup()
            except Exception:
                pass
        self.available = False
