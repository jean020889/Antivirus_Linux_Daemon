import os, time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .scanner import ScannerEngine, Colors
from .archives import ArchiveScanner

class EventHandler(FileSystemEventHandler):
    def __init__(self, engine: ScannerEngine, archive_scanner):
        self.engine = engine
        self.archive_scanner = archive_scanner

    def on_created(self, event):
        self._scan(event)
    def on_modified(self, event):
        self._scan(event)

    def _scan(self, event):
        if event.is_file and not os.path.islink(event.src_path):
            path = event.src_path
            infected, mot = self.engine.scan_file(path)
            if infected:
                print(f"\n{Colors.RED}🔥 [REAL-TIME] Amenaza en {path}{Colors.RESET}")
                self.engine.quarantine(path, mot)
            elif self.archive_scanner:
                is_inf, _ = self.archive_scanner.extract_and_scan(path)
                if is_inf:
                    self.engine.quarantine(path, "Contenido comprimido malicioso")

class RealtimeMonitor:
    def __init__(self, engine: ScannerEngine, config):
        self.engine = engine
        self.config = config
        self.observer = Observer()
        self.handler = EventHandler(engine, ArchiveScanner(engine, config.get('temp_extract', '/tmp/av_extract')))

    def start(self):
        dirs = self.config.get('realtime_dirs', ['/home', '/tmp'])
        for d in dirs:
            if os.path.exists(d) and os.path.isdir(d):
                self.observer.schedule(self.handler, d, recursive=True)
                print(f"{Colors.GREEN}[+] Vigilando en tiempo real: {d}{Colors.RESET}")
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()
