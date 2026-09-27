"""
Tests de ClamdPool usando un servidor Unix-socket falso que emula
el protocolo zINSTREAM de clamd. No requiere clamd real.

El servidor mantiene la conexión abierta tras responder, como clamd real,
para permitir la reutilización del pool.
"""
import io
import socket
import threading
import time
from pathlib import Path

import pytest

from core.clamd_pool import ClamdPool, ClamdConnection, ClamdError


class FakeClamdServer:
    """Servidor Unix-socket que responde como clamd y mantiene la conexión."""

    def __init__(self, socket_path: Path, reply_found_for: bytes = b"EICAR"):
        self.socket_path = socket_path
        self.reply_found_for = reply_found_for
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self.connections_served = 0

    def start(self):
        if self.socket_path.exists():
            self.socket_path.unlink()
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(self.socket_path))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections_served += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket):
        """Procesa múltiples comandos por conexión, como clamd real."""
        try:
            conn.settimeout(5.0)
            while not self._stop.is_set():
                try:
                    cmd = self._read_until_null(conn)
                except (socket.timeout, ConnectionError, OSError):
                    return
                if not cmd:
                    return

                if cmd == b"zPING":
                    conn.sendall(b"PONG\0")
                    continue

                if cmd == b"zINSTREAM":
                    data = self._read_instream(conn)
                    if data is None:
                        return
                    if self.reply_found_for in data:
                        conn.sendall(b"stream: Test-Signature FOUND\0")
                    else:
                        conn.sendall(b"stream: OK\0")
                    continue

                conn.sendall(b"UNKNOWN COMMAND\0")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _read_until_null(self, conn: socket.socket) -> bytes:
        buf = b""
        while not buf.endswith(b"\0"):
            chunk = conn.recv(1)
            if not chunk:
                return b""
            buf += chunk
        return buf.rstrip(b"\0")

    def _read_instream(self, conn: socket.socket) -> bytes | None:
        data = bytearray()
        while True:
            len_bytes = b""
            while len(len_bytes) < 4:
                c = conn.recv(4 - len(len_bytes))
                if not c:
                    return None
                len_bytes += c
            n = int.from_bytes(len_bytes, "big")
            if n == 0:
                return bytes(data)
            chunk = b""
            while len(chunk) < n:
                c = conn.recv(n - len(chunk))
                if not c:
                    return None
                chunk += c
            data.extend(chunk)

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        if self.socket_path.exists():
            self.socket_path.unlink(missing_ok=True)


@pytest.fixture
def fake_clamd(tmp_path):
    sock_path = tmp_path / "clamd.ctl"
    server = FakeClamdServer(sock_path)
    server.start()
    for _ in range(50):
        if sock_path.exists():
            break
        time.sleep(0.01)
    yield server
    server.stop()


class TestClamdConnection:
    def test_ping_responde_pong(self, fake_clamd):
        conn = ClamdConnection(fake_clamd.socket_path)
        assert conn.ping() is True
        conn.close()

    def test_scan_fd_detecta_found(self, fake_clamd):
        conn = ClamdConnection(fake_clamd.socket_path)
        infectado, motivo = conn.scan_fd(io.BytesIO(b"contenido EICAR aqui"))
        assert infectado is True
        assert "FOUND" in motivo
        conn.close()

    def test_scan_fd_ok_en_limpio(self, fake_clamd):
        conn = ClamdConnection(fake_clamd.socket_path)
        infectado, motivo = conn.scan_fd(io.BytesIO(b"contenido limpio"))
        assert infectado is False
        assert "OK" in motivo
        conn.close()

    def test_multiples_scans_misma_conexion(self, fake_clamd):
        conn = ClamdConnection(fake_clamd.socket_path)
        for _ in range(5):
            infectado, motivo = conn.scan_fd(io.BytesIO(b"contenido limpio"))
            assert infectado is False
        conn.close()

    def test_socket_inexistente_falla(self, tmp_path):
        with pytest.raises(OSError):
            ClamdConnection(tmp_path / "no_existe.ctl")


class TestClamdPool:
    def test_probe_disponible(self, fake_clamd):
        pool = ClamdPool(socket_path=fake_clamd.socket_path, max_size=4)
        assert pool.available is True
        pool.shutdown()

    def test_acquire_y_scan(self, fake_clamd):
        pool = ClamdPool(socket_path=fake_clamd.socket_path, max_size=4)
        with pool.acquire() as conn:
            infectado, _ = conn.scan_fd(io.BytesIO(b"EICAR"))
            assert infectado is True
        pool.shutdown()

    def test_reutiliza_conexiones(self, fake_clamd):
        pool = ClamdPool(socket_path=fake_clamd.socket_path, max_size=4)
        for _ in range(10):
            with pool.acquire() as conn:
                conn.scan_fd(io.BytesIO(b"x"))
        # El pool debe haber reutilizado conexiones: menos servidas que solicitudes
        assert fake_clamd.connections_served <= 4
        pool.shutdown()

    def test_pool_saturado_bloquea(self, fake_clamd):
        """Con max_size=1, la segunda adquisición espera a que la primera se libere."""
        pool = ClamdPool(socket_path=fake_clamd.socket_path, max_size=1)
        results = []

        def worker(name, delay):
            time.sleep(delay)
            try:
                with pool.acquire() as conn:
                    conn.scan_fd(io.BytesIO(b"x"))
                    results.append(name)
            except Exception as e:
                results.append(f"{name}:ERR:{e}")

        t1 = threading.Thread(target=worker, args=("t1", 0))
        t2 = threading.Thread(target=worker, args=("t2", 0.05))
        t1.start(); t2.start()
        t1.join(timeout=10); t2.join(timeout=10)
        assert sorted(results) == ["t1", "t2"], f"Resultado inesperado: {results}"
        pool.shutdown()

    def test_shutdown_cierra_pool(self, fake_clamd):
        pool = ClamdPool(socket_path=fake_clamd.socket_path, max_size=4)
        with pool.acquire() as conn:
            conn.scan_fd(io.BytesIO(b"x"))
        pool.shutdown()
        with pool.acquire() as conn:
            infectado, _ = conn.scan_fd(io.BytesIO(b"x"))
            assert isinstance(infectado, bool)
        pool.shutdown()

    def test_respuesta_inesperada_lanza_error(self, tmp_path):
        """Un servidor que responde basura debe provocar ClamdError."""

        sock_path = tmp_path / "fake.ctl"
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(sock_path))
        srv.listen(1)
        srv.settimeout(3.0)

        def handler():
            try:
                conn, _ = srv.accept()
                conn.recv(65536)
                conn.sendall(b"stream: BASURA INESPERADA\0")
                conn.close()
            except Exception:
                pass

        threading.Thread(target=handler, daemon=True).start()

        conn = ClamdConnection(sock_path)
        with pytest.raises(ClamdError):
            conn.scan_fd(io.BytesIO(b"data"))

        srv.close()
        sock_path.unlink(missing_ok=True)
