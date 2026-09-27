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
            # Excluir por nombre de directorio en la ruta
            if f"/{excluded}/" in path or path.endswith(f"/{excluded}"):
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
            # MODO SOLO-ALERTAR: el realtime NO mueve archivos a cuarentena
            # automáticamente. Los falsos positivos en archivos de usuario
            # (cookies, caches, configuración de apps) rompen el sistema si
            # se mueven automáticamente.
            #
            # En su lugar, se emite una alerta a la GUI (pestaña Pre-cuarentena)
            # donde el usuario decide con un informe detallado si autoriza
            # la cuarentena o no.
            logger.warning(
                "[REAL-TIME] Amenaza detectada (NO movida a cuarentena): %s -> %s",
                path, mot
            )
            print(f"\n{Colors.RED}⚠️  [REAL-TIME] Amenaza detectada: {path}{Colors.RESET}")
            print(f"{Colors.YELLOW}    Motivo: {mot}{Colors.RESET}")
            print(f"{Colors.YELLOW}    Acción: enviada a Pre-cuarentena para revisión manual.{Colors.RESET}")

            # Si el engine tiene un callback de alerta (para la GUI), invocarlo
            callback = getattr(self.engine, "_realtime_alert_callback", None)
            if callable(callback):
                try:
                    callback(path, mot)
                except Exception as exc:
                    logger.warning("Callback de alerta falló: %s", exc)

            # Comprobación adicional de ZIP sospechoso (solo informativo)
            if self.archive_scanner:
                try:
                    is_inf, arc_mot = self.archive_scanner.extract_and_scan(path)
                    if is_inf:
                        logger.warning(
                            "[REAL-TIME] Contenido comprimido malicioso en %s: %s",
                            path, arc_mot
                        )
                except Exception:
                    pass

# ============================================================
#  Exclusión de rutas y extensiones del watcher en tiempo real
# ============================================================
# Rutas que NUNCA deben vigilarse: logs del propio antivirus,
# sockets, archivos temporales del sistema, cuarentena, y directorios
# de configuración/datos de aplicaciones (causan falsos positivos).
EXCLUDED_PATHS = frozenset({
    # Directorios del propio antivirus y del sistema
    "/var/lib/antivirus-linux-dragon",
    "/var/log/antivirus-linux-dragon",
    "/run/antivirus-linux-dragon",
    "/etc/antivirus-linux-dragon",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/crash",

    # Directorios de configuración y datos de aplicaciones.
    # NO son malware por definición, y escanearlos produce falsos
    # positivos (cookies, bases SQLite, caches, PNGs de apps, etc.)
    ".config",
    ".local/share",
    ".var/app",
    ".mozilla",
    ".thunderbird",
    ".cache",
    ".local",

    # Directorios que causan overflow de inotify por su volumen
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".npm",
    ".cargo",
    ".rustup",
    ".pyenv",
    ".nvm",
    ".gradle",
    ".m2",
    "site-packages",
    "dist-packages",
    ".Trash",
    "snap",
    ".snap",
})

# Extensiones que NUNCA deben escanearse en tiempo real:
# logs, sockets, archivos temporales, multimedia, ofimática, bases
# de datos y archivos del entorno gráfico.
EXCLUDED_EXTENSIONS = frozenset({
    # Logs y archivos temporales
    ".log", ".log.1", ".log.2", ".log.3", ".log.gz",
    ".sock", ".socket", ".pid", ".lock", ".swp", ".swx",
    ".tmp", ".cache",

    # Multimedia (no pueden contener malware ejecutable en Linux)
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".ico",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".webm", ".flac", ".wav", ".ogg",

    # Ofimática y documentos
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",

    # Texto plano y datos
    ".txt", ".md", ".rst", ".csv", ".json", ".xml", ".html", ".css",

    # Fuentes
    ".ttf", ".otf", ".woff", ".woff2",

    # Bases de datos de apps
    ".sqlite", ".sqlite3", ".db", ".ldb", ".mdb",
    "-journal", "-wal", "-shm",

    # Entorno gráfico
    ".xsession-errors",
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
