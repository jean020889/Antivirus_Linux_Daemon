#!/usr/bin/env python3
"""
antivirus_daemon.py
Orquestador local sobre ClamAV: scheduler de escaneos, monitor en tiempo
real, escaneo de procesos, archivos comprimidos, telemetría kernel,
motor Sigma, almacén forense, respuesta SOAR, feeds CTI, SIEM y ZT.

Modo de prueba:
  AV_TEST_MODE=1 → sustituye componentes pesados (eBPF, clamd, SIEM, CTI)
  por stubs para poder ejecutar tests sin privilegios ni servicios externos.
"""

from __future__ import annotations

import argparse
import atexit
import json
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from core.scanner import ScannerEngine, Colors
from core.scheduler import ScanScheduler
from core.realtime import RealtimeMonitor
from core.processes import ProcessScanner
from core.archives import ArchiveScanner
from core.threat_store import ThreatStore
from core.sigma_engine import SigmaEngine
from core.soar import SOAR

# Componentes opcionales: solo se cargan si están disponibles.
try:
    from core.siem_forwarder import SIEMForwarder
except ImportError:
    SIEMForwarder = None

try:
    from core.zt_health import ZTHealthAttestation
except ImportError:
    ZTHealthAttestation = None

try:
    from core.cti_feed import CTIClient
except ImportError:
    CTIClient = None

try:
    from core.ebpf_telemetry import EBPFTelemetry
except ImportError:
    EBPFTelemetry = None

SCRIPT_DIR = Path(__file__).resolve().parent
def _default_config_path() -> Path:
    """Prefiere config.local.json (no versionado) sobre config.json."""
    env = os.environ.get("AV_CONFIG_PATH")
    if env:
        return Path(env)
    local = SCRIPT_DIR / "config.local.json"
    if local.exists():
        return local
    return SCRIPT_DIR / "config.json"

CONFIG_PATH = _default_config_path()
PID_FILE = Path(os.environ.get("AV_PID_FILE", "/tmp/antivirus_daemon.pid"))
LOG_DIR = Path(os.environ.get("AV_LOG_DIR", Path.home() / ".local/share/antivirus"))
TEST_MODE = os.environ.get("AV_TEST_MODE") == "1"

logger = logging.getLogger("antivirus")


# ---------------------------------------------------------------- logging
def setup_logging(level: str = "INFO") -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "daemon.log"

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)

    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


# ---------------------------------------------------------------- config
def _expand_paths(cfg: dict) -> dict:
    """
    Expande '~' en todas las rutas de configuración. Esto permite que
    config.example.json use '~/...' sin hardcodear /home/<usuario>.
    """
    def expand(value):
        if isinstance(value, str) and (value.startswith("~") or value.startswith("$HOME")):
            return os.path.expanduser(os.path.expandvars(value))
        return value

    def walk(obj):
        if isinstance(obj, dict):
            return {k: walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [walk(v) for v in obj]
        return expand(obj)

    return walk(cfg)


def load_config(path: Path) -> dict:
    if not path.exists():
        logger.error("No se encontró el archivo de configuración: %s", path)
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return _expand_paths(cfg)
    except json.JSONDecodeError as exc:
        logger.error("config.json contiene JSON inválido: %s", exc)
        sys.exit(1)
    except OSError as exc:
        logger.error("No se pudo leer %s: %s", path, exc)
        sys.exit(1)


# ---------------------------------------------------------------- pid file
def pid_file_is_stale(pid_file: Path) -> bool:
    """True si el PID file existe pero el proceso ya no está vivo."""
    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def acquire_pid_file(pid_file: Path) -> None:
    if pid_file.exists() and not pid_file_is_stale(pid_file):
        logger.error("El antivirus ya está en ejecución (PID file: %s).", pid_file)
        sys.exit(1)
    if pid_file.exists():
        logger.warning("PID file huérfano detectado, se elimina: %s", pid_file)
        pid_file.unlink(missing_ok=True)

    pid_file.write_text(str(os.getpid()))

    def _cleanup() -> None:
        pid_file.unlink(missing_ok=True)

    atexit.register(_cleanup)


# ---------------------------------------------------------------- daemon
class AntivirusDaemon:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

        self.update_signatures()

        # ScannerEngine es thread-safe por diseño:
        #   - firmas en memoria inmutables tras swap atómico bajo lock
        #   - conexiones clamd vienen del ClamdPool (una por hilo)
        #   - no hay estado mutable compartido entre scan_file()s
        # Benchmark demostró que envolverlo en ThreadSafeProxy añade
        # +154% de overhead sin aportar seguridad real. Por eso NO se usa proxy.
        self.engine = ScannerEngine(self.config)

        self.scheduler = ScanScheduler(self.engine, self.config)
        self.realtime = RealtimeMonitor(self.engine, self.config)
        self.process_scanner = ProcessScanner(self.engine)
        self.archive_scanner = ArchiveScanner(
            self.engine, self.config.get("temp_extract", "/tmp/av_extract")
        )

        # Componentes avanzados
        self.threat_store = ThreatStore(self.config.get("threat_store_db"))
        self.sigma = SigmaEngine(self.config.get("sigma_rules_dir", "sigma_rules"))

        siem_cfg = self.config.get("siem", {})
        self.siem = None
        if not TEST_MODE and siem_cfg.get("enabled") and SIEMForwarder is not None:
            self.siem = SIEMForwarder(
                host=siem_cfg.get("host", "127.0.0.1"),
                port=siem_cfg.get("port", 514),
                protocol=siem_cfg.get("protocol", "udp"),
                fmt=siem_cfg.get("format", "cef"),
            )

        self.soar = SOAR(self.engine, siem_forwarder=self.siem,
                         policy=self.config.get("soar_policy"))

        # CTI solo si está instalado y no estamos en test mode
        self.cti = None
        if not TEST_MODE and CTIClient is not None:
            try:
                self.cti = CTIClient(self.config.get("cti_feeds"))
            except Exception as exc:
                logger.warning("CTIClient no inicializado: %s", exc)

        # eBPF solo si está disponible
        self.telemetry = None
        if not TEST_MODE and EBPFTelemetry is not None:
            try:
                self.telemetry = EBPFTelemetry()
            except Exception as exc:
                logger.warning("EBPFTelemetry no inicializado: %s", exc)

        # ZT health
        self.zt = None
        if ZTHealthAttestation is not None:
            self.zt = ZTHealthAttestation(self.engine, self.threat_store, self.config)

    # --------------------------------------------- signatures
    def update_signatures(self) -> None:
        logger.info("Actualizando firmas ClamAV...")
        try:
            result = subprocess.run(
                ["sudo", "-n", "freshclam"],
                check=True,
                timeout=120,
                capture_output=True,
                text=True,
            )
            logger.info("Firmas actualizadas correctamente.")
        except subprocess.CalledProcessError as exc:
            logger.warning(
                "freshclam terminó con error (código %s): %s",
                exc.returncode,
                (exc.stderr or "").strip() or "sin detalle",
            )
        except subprocess.TimeoutExpired:
            logger.warning("freshclam superó el tiempo límite de 120s.")
        except FileNotFoundError:
            logger.error("'sudo' o 'freshclam' no están instalados o no están en PATH.")

    def manual_update(self) -> None:
        logger.info("Actualización manual solicitada.")
        self.update_signatures()
        self.engine.load_clamav_signatures()

    # --------------------------------------------- lifecycle
    def _spawn(self, target, name: str) -> threading.Thread:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        return t

    def run(self, start_background: bool = True) -> None:
        """
        Arranca el daemon.

        start_background=True (default, producción):
            Arranca todos los subsistemas: scheduler, realtime, eBPF, SIEM,
            CTI, SOAR-expiry.
        start_background=False (modo test E2E):
            Solo arranca el scheduler (en modo diferido) y deja el motor y
            el threat_store listos. Sin hilos, sin dependencias externas.
            Útil para probar el flujo de detección→cuarentena→store.
        """
        if start_background:
            self._spawn(self.process_scanner.scan_all, "process-scanner")
            self.scheduler.start()
            self._spawn(self.realtime.start, "realtime-monitor")

            if self.telemetry is not None:
                if self.telemetry.start():
                    self._spawn(self._telemetry_loop, "ebpf-telemetry")
                else:
                    logger.warning("Telemetría eBPF no disponible; cobertura reducida.")

            if self.siem is not None and not self.siem.start():
                logger.warning("SIEM no disponible; se pierde correlación central.")

            if self.cti is not None:
                try:
                    self.cti.start()
                except Exception as exc:
                    logger.warning("CTI no iniciado: %s", exc)

            self._spawn(self._soar_expiry_loop, "soar-expiry")
        else:
            logger.info("run(start_background=False): modo test, sin subsistemas.")

        logger.info("Antivirus activado.")
        print(f"{Colors.BOLD}{Colors.GREEN}🛡️  Antivirus activado. Presiona Ctrl+C para detener.{Colors.RESET}")

        while not self.stop_event.is_set():
            time.sleep(1)

        self._shutdown()

    def _telemetry_loop(self) -> None:
        """Consume eventos del kernel, evalúa Sigma y dispara SOAR."""
        if self.telemetry is None:
            return
        logger.info("Loop de telemetría iniciado.")
        for event in self.telemetry.events(timeout=0.5):
            if self.stop_event.is_set():
                break
            evt_dict = {
                "EventType": event.type,
                "Image": event.comm,
                "CommandLine": event.path,
                "TargetFilename": event.path,
                "User": str(event.uid),
                "pid": event.pid,
                "path": event.path,
                "comm": event.comm,
                "uid": event.uid,
            }
            self.threat_store.add_event(
                source="ebpf", event_type=event.type,
                pid=event.pid, uid=event.uid, comm=event.comm, path=event.path,
            )
            for rule in self.sigma.evaluate(evt_dict):
                logger.warning("SIGMA HIT: %s | pid=%d comm=%s path=%s",
                               rule.title, event.pid, event.comm, event.path)
                self.threat_store.add_event(
                    source="sigma", event_type="alert",
                    pid=event.pid, uid=event.uid, comm=event.comm, path=event.path,
                    severity=rule.level, rule_id=rule.id, rule_title=rule.title,
                )
                if self.siem:
                    self.siem.send({
                        "rule_id": rule.id, "rule_title": rule.title,
                        "severity": rule.level, "pid": event.pid,
                        "comm": event.comm, "path": event.path,
                        "event_type": event.type,
                    })
                self.soar.respond(
                    {"pid": event.pid, "path": event.path,
                     "rule_title": rule.title, "remote": None},
                    severity=rule.level,
                )

    def _soar_expiry_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.soar.unblock_expired()
            except Exception:
                logger.exception("Error desbloqueando IPs")
            self.stop_event.wait(60)

    def scan_path_now(self, folder: str) -> list[dict]:
        """
        Escanea una carpeta sincrónicamente y devuelve la lista de amenazas
        detectadas y puestas en cuarentena.

        Cada entrada es:
            {"path": str, "motivo": str, "cuarentena": str|None}

        Uso principal: tests end-to-end y diagnóstico manual.
        """
        results = []
        folder_path = Path(folder)
        if not folder_path.is_dir():
            logger.error("scan_path_now: ruta inválida %s", folder)
            return results

        for root, _dirs, files in os.walk(folder_path, followlinks=False):
            for name in files:
                full = os.path.join(root, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                try:
                    infectado, motivo = self.engine.scan_file(full)
                except Exception as exc:
                    logger.warning("Error escaneando %s: %s", full, exc)
                    continue

                if not infectado:
                    continue

                dest = self.engine.quarantine(full, motivo)
                self.threat_store.add_event(
                    source="scan",
                    event_type="quarantine",
                    pid=None,
                    comm=None,
                    path=full,
                    severity="high",
                    rule_title=motivo,
                )
                results.append({
                    "path": full,
                    "motivo": motivo,
                    "cuarentena": dest,
                })
        return results

    def _shutdown(self) -> None:
        logger.info("Deteniendo antivirus...")

        # Componentes que exponen stop()
        for name, component in (
            ("scheduler", self.scheduler),
            ("realtime", self.realtime),
            ("engine", self.engine),
            ("telemetry", self.telemetry),
            ("siem", self.siem),
            ("cti", self.cti),
        ):
            if component is None:
                continue
            stopper = getattr(component, "stop", None) or getattr(component, "shutdown", None)
            if callable(stopper):
                try:
                    stopper()
                except Exception:
                    logger.exception("Error al detener %s", name)
            else:
                logger.warning("%s no expone stop()/shutdown()", name)

        for t in self._threads:
            t.join(timeout=5)
            if t.is_alive():
                logger.warning("El hilo '%s' no terminó dentro del timeout.", t.name)

        try:
            self.threat_store.close()
        except Exception:
            pass

        logger.info("Antivirus detenido.")

    def request_stop(self) -> None:
        self.stop_event.set()


# ---------------------------------------------------------------- CLI
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Antivirus local sobre ClamAV.")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("update", help="Actualiza firmas y sale.")
    sub.add_parser("scan-memory", help="Escanea procesos en memoria y sale.")

    scan_folder_parser = sub.add_parser("scan-folder", help="Escanea una carpeta y sale.")
    scan_folder_parser.add_argument(
        "folder", nargs="?", default=os.getcwd(),
        help="Carpeta a escanear (por defecto: cwd)."
    )

    sub.add_parser("zt-attest", help="Imprime la atestación Zero Trust y sale.")

    return parser


def scan_folder(daemon: AntivirusDaemon, folder: str) -> None:
    folder_path = Path(folder)
    if not folder_path.is_dir():
        logger.error("La ruta indicada no es una carpeta válida: %s", folder)
        sys.exit(1)

    for root, _dirs, files in os.walk(folder_path, followlinks=False):
        for name in files:
            path = os.path.join(root, name)
            if os.path.islink(path):
                continue
            try:
                if not os.path.isfile(path):
                    continue
                infected, motive = daemon.engine.scan_file(path)
                if infected:
                    print(f"{Colors.RED}[MANUAL] {path} -> {motive}{Colors.RESET}")
            except (OSError, PermissionError) as exc:
                logger.warning("No se pudo escanear %s: %s", path, exc)


# ---------------------------------------------------------------- main
def main() -> None:
    args = build_arg_parser().parse_args()

    config = load_config(CONFIG_PATH)
    setup_logging(config.get("log_level", "INFO"))

    acquire_pid_file(PID_FILE)

    daemon = AntivirusDaemon(config)

    signal.signal(signal.SIGINT, lambda s, f: daemon.request_stop())
    signal.signal(signal.SIGTERM, lambda s, f: daemon.request_stop())

    if args.command == "update":
        daemon.manual_update()
        sys.exit(0)
    elif args.command == "scan-memory":
        daemon.process_scanner.scan_all()
        sys.exit(0)
    elif args.command == "scan-folder":
        scan_folder(daemon, args.folder)
        sys.exit(0)
    elif args.command == "zt-attest":
        if daemon.zt is not None:
            import json as _json
            print(_json.dumps(daemon.zt.attest(), indent=2))
        else:
            logger.error("ZTHealthAttestation no disponible.")
        sys.exit(0)

    daemon.run()


if __name__ == "__main__":
    main()
