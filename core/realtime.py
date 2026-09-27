import os, time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .scanner import ScannerEngine, Colors
from .archives import ArchiveScanner

class EventHandler(FileSystemEventHandler):
    def __init__(self, engine: ScannerEngine, archive_scanner):
        self.engine = engine
        self.archive_scanner = archive_scanner
        self._recent_scans = {}  # path -> timestamp del último escaneo

    def on_created(self, event):
        self._scan(event)
    def on_modified(self, event):
        self._scan(event)

    def _scan(self, event):
        # En watchdog, 'is_directory' existe en todos los tipos de evento.
        # 'is_file' solo existe en FileCreatedEvent y similares, no en
        # FileModifiedEvent. Por eso usamos 'not event.is_directory'.
        if event.is_directory:
            return
        if not hasattr(event, "src_path"):
            return
        path = event.src_path
        if os.path.islink(path):
            return

        # Excluir rutas del propio antivirus y del sistema
        for excluded in EXCLUDED_PATHS:
            if path.startswith(excluded + "/") or path == excluded:
                return

        # Excluir extensiones de logs/temporales
        ext = os.path.splitext(path)[1].lower()
        if ext in EXCLUDED_EXTENSIONS or path.endswith(tuple(EXCLUDED_EXTENSIONS)):
            return

        # Rate limiting: ignorar si ya escaneamos este path en el último segundo
        now = time.time()
        last = self._recent_scans.get(path, 0)
        if now - last < 1.0:
            return
        self._recent_scans[path] = now
        # Limpiar entradas viejas cada 100 escaneos
        if len(self._recent_scans) > 1000:
            cutoff = now - 60
            self._recent_scans = {k: v for k, v in self._recent_scans.items() if v > cutoff}

        try:
            infected, mot = self.engine.scan_file(path)
        except Exception as exc:
            logger.warning("Error escaneando %s: %s", path, exc)
            return
        if infected:
            print(f"\n{Colors.RED}🔥 [REAL-TIME] Amenaza en {path}{Colors.RESET}")
            self.engine.quarantine(path, mot)
        elif self.archive_scanner:
            is_inf, _ = self.archive_scanner.extract_and_scan(path)
            if is_inf:
                self.engine.quarantine(path, "Contenido comprimido malicioso")

# Rutas que NUNCA deben ser vigiladas: logs del propio antivirus,
# sockets, archivos temporales del sistema, cuarentena del propio
# antivirus. Sin esto, el daemon se escanea a sí mismo y entra en un
# bucle infinito (escribe log -> se detecta -> escanea -> escribe log...).
EXCLUDED_PATHS = frozenset({
    "/var/lib/antivirus-linux-dragon",
    "/var/log/antivirus-linux-dragon",
    "/run/antivirus-linux-dragon",
    "/etc/antivirus-linux-dragon",
    "/proc",
    "/sys",
    "/dev",
    "/run",
})

# Extensiones que NUNCA deben escanearse en tiempo real:
# son logs, sockets, archivos temporales, o archivos de sistema.
EXCLUDED_EXTENSIONS = frozenset({
    ".log", ".log.1", ".log.2", ".log.3", ".log.gz",
    ".sock", ".socket", ".pid", ".lock", ".swp", ".swx",
    ".tmp", ".cache",
})


class RealtimeMonitor:
    def __init__(self, engine: ScannerEngine, config):
        self.engine = engine
        self.config = config
        self.observer = Observer()
        self.handler = EventHandler(engine, ArchiveScanner(engine, config.get('temp_extract', '/tmp/av_extract')))
        # Directorios excluidos: los del propio antivirus + sistema
        self.excluded_paths = EXCLUDED_PATHS
        self.excluded_extensions = EXCLUDED_EXTENSIONS

    def start(self):
        dirs = self.config.get('realtime_dirs', ['/home', '/tmp'])
        for d in dirs:
            # Saltar directorios excluidos
            if d in EXCLUDED_PATHS:
                print(f"[i] Saltando directorio excluido: {d}")
                continue
            if os.path.exists(d) and os.path.isdir(d):
                # Verificar que no esté dentro de un path excluido
                skip = False
                for excluded in EXCLUDED_PATHS:
                    if d.startswith(excluded + "/") or d == excluded:
                        print(f"[i] Saltando directorio dentro de exclusión: {d}")
                        skip = True
                        break
                if skip:
                    continue
                self.observer.schedule(self.handler, d, recursive=True)
                print(f"{Colors.GREEN}[+] Vigilando en tiempo real: {d}{Colors.RESET}")
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """Detiene el observador watchdog de forma ordenada."""
        try:
            if self.observer.is_alive():
                self.observer.stop()
                self.observer.join(timeout=5)
                print("[+] Vigilancia en tiempo real detenida.")
        except Exception as exc:
            print(f"[!] Error deteniendo observador: {exc}")
