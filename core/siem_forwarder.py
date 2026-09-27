"""
core/siem_forwarder.py
Exportador de eventos a SIEM en formato CEF (ArcSight) o JSON sobre Syslog UDP/TCP.

Compatible con Splunk, QRadar, Elastic, Wazuh vía syslog.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
from queue import Queue, Empty

logger = logging.getLogger("antivirus.siem")


class SIEMForwarder:
    def __init__(self, host: str = "127.0.0.1", port: int = 514,
                 protocol: str = "udp", fmt: str = "cef", vendor: str = "AntivirusLinux"):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.fmt = fmt.lower()
        self.vendor = vendor
        self.queue: Queue[dict] = Queue(maxsize=10000)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="siem-forwarder", daemon=True)
        self._sock = None

    def start(self):
        try:
            if self.protocol == "udp":
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.connect((self.host, self.port))
        except OSError as exc:
            logger.error("SIEM: no se pudo abrir socket a %s:%d: %s", self.host, self.port, exc)
            return False
        self._thread.start()
        return True

    def send(self, event: dict):
        try:
            self.queue.put_nowait(event)
        except Exception:
            pass

    def _loop(self):
        while not self._stop.is_set():
            try:
                event = self.queue.get(timeout=1)
            except Empty:
                continue
            try:
                payload = self._cef(event) if self.fmt == "cef" else json.dumps(event)
                encoded = payload.encode("utf-8")
                if self.protocol == "udp":
                    self._sock.sendto(encoded, (self.host, self.port))
                else:
                    self._sock.sendall(encoded)
            except Exception:
                logger.exception("SIEM: error enviando evento")

    def _cef(self, event: dict) -> str:
        sev_map = {"critical": 10, "high": 7, "medium": 5, "low": 3}
        sev = sev_map.get(event.get("severity", "low"), 3)
        rule_id = event.get("rule_id", "generic")
        name = event.get("rule_title", event.get("event_type", "event"))
        ext = " ".join(f"{k}={v}" for k, v in event.items()
                       if k not in ("rule_id", "rule_title", "severity"))
        return f"CEF:0|{self.vendor}|Antivirus|1.0|{rule_id}|{name}|{sev}|{ext}"

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
