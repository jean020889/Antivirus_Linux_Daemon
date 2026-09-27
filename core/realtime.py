# core/realtime.py
"""
Vigilancia en tiempo real por polling (100% fiable, sin dependencias externas).

Escanea directorios periódicamente buscando archivos nuevos o modificados
recientemente. Es más lento que inotify pero funciona en cualquier sistema.
"""

import os
import time
import threading
from .archives import ArchiveScanner


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class RealtimeMonitor:
    """
    Vigilancia por polling: escanea directorios cada N segundos
    buscando archivos con mtime reciente.
    """

    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self._running = False
        self._scan_interval = 5   # segundos entre ciclos
        self._mtime_window = 30   # considerar archivos modificados en últimos N seg
        self._recently_scanned = {}  # path -> timestamp último escaneo
        self._known_mtimes = {}      # path -> mtime para detectar cambios
        self.archive_scanner = ArchiveScanner(
            engine,
            config.get('temp_extract', '/tmp/av_extract')
        )

    def _scan_file(self, path):
        """Escanea un archivo y lo pone en cuarentena si es malicioso."""
        if not os.path.isfile(path) or os.path.islink(path):
            return

        try:
            infectado, motivo = self.engine.scan_file(path)
            if infectado:
                print(f"{Colors.RED}🔥 [REALTIME] Amenaza: {path}{Colors.RESET}")
                print(f"{Colors.YELLOW}   └─ {motivo}{Colors.RESET}")
                result = self.engine.quarantine(path, motivo)
                if result:
                    print(f"{Colors.GREEN}   └─ ✅ Aislado: {result}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}   └─ ❌ No se pudo aislar{Colors.RESET}")
            else:
                # Archivos comprimidos: análisis profundo
                ext = os.path.splitext(path)[1].lower()
                if ext in ('.zip', '.tar', '.gz', '.bz2', '.rar', '.7z', '.xz', '.tgz'):
                    is_inf, arch_motivo = self.archive_scanner.extract_and_scan(path)
                    if is_inf:
                        print(f"{Colors.RED}🔥 [REALTIME-ARCH] Amenaza: {path}{Colors.RESET}")
                        print(f"{Colors.YELLOW}   └─ {arch_motivo}{Colors.RESET}")
                        self.engine.quarantine(path, f"Comprimido malicioso: {arch_motivo}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error escaneando {path}: {e}{Colors.RESET}")

    def _walk_and_scan(self, dirs, first_run=False):
        """Recorre los directorios y escanea archivos nuevos o modificados."""
        now = time.time()
        files_scanned = 0

        for d in dirs:
            if not os.path.exists(d):
                continue

            try:
                for root, subdirs, files in os.walk(d):
                    # Excluir directorios del sistema
                    subdirs[:] = [s for s in subdirs if not s.startswith('.')
                                  and s not in ('proc', 'sys', 'dev', 'run', 'node_modules')]

                    for f in files:
                        path = os.path.join(root, f)
                        try:
                            mtime = os.path.getmtime(path)
                        except OSError:
                            continue

                        # En la primera pasada, solo registrar mtimes
                        if first_run:
                            self._known_mtimes[path] = mtime
                            continue

                        # ¿Es nuevo o modificado?
                        last_mtime = self._known_mtimes.get(path, 0)
                        if mtime > last_mtime:
                            self._known_mtimes[path] = mtime
                            self._scan_file(path)
                            files_scanned += 1
                        elif path not in self._known_mtimes:
                            # Archivo nuevo
                            self._known_mtimes[path] = mtime
                            self._scan_file(path)
                            files_scanned += 1

            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error recorriendo {d}: {e}{Colors.RESET}")

        # Limpiar caché si crece demasiado (más de 500k entradas)
        if len(self._known_mtimes) > 500000:
            print(f"{Colors.YELLOW}[!] Limpiando caché de mtimes ({len(self._known_mtimes)} entradas){Colors.RESET}")
            # Mantener solo los últimos 100k
            items = sorted(self._known_mtimes.items(), key=lambda x: x[1], reverse=True)
            self._known_mtimes = dict(items[:100000])

        if files_scanned > 0:
            print(f"{Colors.BLUE}[REALTIME] {files_scanned} archivos escaneados en este ciclo{Colors.RESET}")

    def start(self):
        """BLOQUEANTE: ejecuta el loop de polling en el thread actual."""
        self._running = True

        dirs = self.config.get('realtime_dirs', ['/tmp', '/var/tmp'])
        print(f"{Colors.BOLD}{Colors.BLUE}[+] Vigilancia por polling (cada {self._scan_interval}s){Colors.RESET}")
        print(f"{Colors.BLUE}[+] Directorios: {dirs}{Colors.RESET}")

        # Primera pasada: registrar estado inicial (sin escanear)
        print(f"{Colors.BLUE}[+] Registrando estado inicial...{Colors.RESET}")
        self._walk_and_scan(dirs, first_run=True)
        print(f"{Colors.GREEN}[+] {len(self._known_mtimes)} archivos registrados{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Vigilancia activa{Colors.RESET}")

        # Loop de polling
        cycle = 0
        while self._running:
            try:
                time.sleep(self._scan_interval)
                cycle += 1
                self._walk_and_scan(dirs, first_run=False)
            except Exception as e:
                print(f"{Colors.RED}[!] Error en ciclo {cycle}: {e}{Colors.RESET}")
                time.sleep(self._scan_interval)

    def stop(self):
        """Detiene la vigilancia."""
        self._running = False
        print(f"{Colors.GREEN}[+] Vigilancia detenida{Colors.RESET}")
