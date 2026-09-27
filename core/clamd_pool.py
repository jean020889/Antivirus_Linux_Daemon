"""
core/clamd_pool.py
Pool de conexiones a clamd sobre socket Unix.

clamd atiende múltiples conexiones concurrentes de forma nativa (vía
MaxThreads en clamd.conf). Este pool mantiene una conexión reutilizable
por hilo activo, eliminando la serialización sin crear una conexión
nueva por archivo escaneado.
"""

from __future__ import annotations

import logging
import socket
import threading
from contextlib import contextmanager
from pathlib import Path
from queue import Empty, LifoQueue
from typing import Iterator

logger = logging.getLogger("antivirus.clamd_pool")

DEFAULT_SOCKET_PATHS = (
    Path("/var/run/clamav/clamd.ctl"),
    Path("/run/clamav/clamd.ctl"),
    Path("/var/run/clamav/clamd.sock"),
    Path("/tmp/clamd.sock"),
)

CONNECT_TIMEOUT_SECONDS = 5.0
SCAN_TIMEOUT_SECONDS = 60.0
CHUNK_SIZE = 65536


class ClamdError(Exception):
    """Error de comunicación con clamd."""


class ClamdConnection:
    """Una conexión clamd. NO thread-safe: se presta desde el pool."""

    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path
        self._sock: socket.socket | None = None
        self._connect()

    def _connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            sock.connect(str(self.socket_path))
        except OSError:
            sock.close()
            raise
        self._sock = sock

    def ping(self) -> bool:
        try:
            self._sock.sendall(b"zPING\0")
            resp = self._sock.recv(64)
            return resp.strip(b"\0\n") == b"PONG"
        except OSError:
            return False

    def scan_fd(self, fileobj) -> tuple[bool, str]:
        assert self._sock is not None
        self._sock.settimeout(SCAN_TIMEOUT_SECONDS)
        try:
            self._sock.sendall(b"zINSTREAM\0")
            while True:
                chunk = fileobj.read(CHUNK_SIZE)
                if not chunk:
                    break
                self._sock.sendall(len(chunk).to_bytes(4, "big"))
                self._sock.sendall(chunk)
            self._sock.sendall(b"\0\0\0\0")

            response = bytearray()
            while not response.endswith(b"\0"):
                part = self._sock.recv(4096)
                if not part:
                    break
                response.extend(part)
        except OSError as exc:
            self.close()
            raise ClamdError(f"Fallo de I/O con clamd: {exc}") from exc

        text = response.decode("utf-8", errors="replace").strip("\0\n ")
        if text.endswith("FOUND"):
            return True, text
        if text.endswith("OK"):
            return False, text
        raise ClamdError(f"Respuesta inesperada de clamd: {text}")

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


class ClamdPool:
    """Pool LIFO de conexiones clamd. Tamaño máximo configurable."""

    def __init__(self, socket_path: Path | None = None, max_size: int = 8) -> None:
        self.socket_path = socket_path or self._detect_socket()
        self.max_size = max_size
        self._pool: LifoQueue[ClamdConnection] = LifoQueue(maxsize=max_size)
        self._created = 0
        self._lock = threading.Lock()
        self._available = self._probe()

    @staticmethod
    def _detect_socket() -> Path:
        for candidate in DEFAULT_SOCKET_PATHS:
            if candidate.exists():
                return candidate
        raise ClamdError(
            "No se encontró el socket de clamd. ¿Está corriendo clamav-daemon? "
            f"Rutas probadas: {[str(p) for p in DEFAULT_SOCKET_PATHS]}"
        )

    def _probe(self) -> bool:
        try:
            conn = ClamdConnection(self.socket_path)
            ok = conn.ping()
            conn.close()
            return ok
        except (OSError, ClamdError):
            return False

    @property
    def available(self) -> bool:
        return self._available

    @contextmanager
    def acquire(self) -> Iterator[ClamdConnection]:
        conn: ClamdConnection | None = None
        try:
            conn = self._pool.get_nowait()
        except Empty:
            with self._lock:
                if self._created < self.max_size:
                    self._created += 1
                    try:
                        conn = ClamdConnection(self.socket_path)
                    except OSError as exc:
                        self._created -= 1
                        raise ClamdError(f"No se pudo conectar a clamd: {exc}") from exc

        if conn is None:
            try:
                conn = self._pool.get(timeout=SCAN_TIMEOUT_SECONDS)
            except Empty as exc:
                raise ClamdError("Timeout esperando conexión libre del pool") from exc

        try:
            yield conn
        except (ClamdError, OSError):
            conn.close()
            with self._lock:
                self._created -= 1
            raise
        else:
            try:
                self._pool.put_nowait(conn)
            except Exception:
                conn.close()
                with self._lock:
                    self._created -= 1

    def shutdown(self) -> None:
        while True:
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Empty:
                break
        with self._lock:
            self._created = 0
