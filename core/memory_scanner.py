# core/memory_scanner.py
import ctypes
import ctypes.util
import psutil

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p),
                ("iov_len", ctypes.c_size_t)]

class MemoryScanner:
    def __init__(self, yara_engine):
        self.yara = yara_engine
        self.PROCESS_VM_READV = 310
        self.MAX_READ = 4 * 1024 * 1024

    def _read_process_memory(self, pid, address, size):
        buf = ctypes.create_string_buffer(size)
        local_iov = IOVec(ctypes.cast(buf, ctypes.c_void_p), size)
        remote_iov = IOVec(ctypes.c_void_p(address), size)
        nread = libc.syscall(
            self.PROCESS_VM_READV,
            pid,
            ctypes.byref(local_iov), 1,
            ctypes.byref(remote_iov), 1,
            0
        )
        if nread == -1:
            return None
        return buf.raw[:nread]

    def scan_process(self, pid):
        try:
            proc = psutil.Process(pid)
            maps = proc.memory_maps()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

        detecciones = []
        for region in maps:
            if 'r' not in region.perms:
                continue
            try:
                start_hex, end_hex = region.addr.split('-')
                start = int(start_hex, 16)
                end = int(end_hex, 16)
                size = min(end - start, self.MAX_READ)
            except (ValueError, AttributeError):
                continue

            data = self._read_process_memory(pid, start, size)
            if not data:
                continue

            infectado, motivo = self.yara.scan_bytes(data)
            if infectado:
                detecciones.append({
                    "pid": pid,
                    "region": region.addr,
                    "path": region.path,
                    "motivo": motivo
                })
        return detecciones

    def scan_all_processes(self):
        todas = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                det = self.scan_process(proc.info['pid'])
                if det:
                    todas.extend(det)
                    print(f"[!] Fileless en PID {proc.info['pid']} "
                          f"({proc.info['name']}): {det}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return todas
