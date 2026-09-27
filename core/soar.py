"""
core/soar.py
Respuesta automatizada ante incidentes (SOAR-lite).

Acciones:
  - kill_process(pid)        → SIGKILL
  - quarantine_file(path)    → mover a cuarentena
  - block_remote_ip(ip)      → iptables con expiración
  - isolate_endpoint()       → bloquear OUTPUT excepto loopback
  - notify_siem(event)       → enviar al SIEM

Política configurable: mapeo (severidad) → [acciones].
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

logger = logging.getLogger("antivirus.soar")


@dataclass
class ResponseAction:
    action: str
    params: dict


class SOAR:
    def __init__(self, engine, siem_forwarder=None, policy: dict | None = None):
        self.engine = engine
        self.siem = siem_forwarder
        self.policy = policy or self._default_policy()
        self._blocked_ips: dict[str, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _default_policy() -> dict:
        return {
            "critical": ["kill_process", "quarantine_file", "block_remote_ip", "notify_siem"],
            "high": ["quarantine_file", "block_remote_ip", "notify_siem"],
            "medium": ["notify_siem"],
            "low": ["notify_siem"],
        }

    def respond(self, event: dict, severity: str = "medium") -> list[str]:
        actions = self.policy.get(severity, [])
        applied = []
        for action in actions:
            try:
                if self._dispatch(action, event):
                    applied.append(action)
            except Exception:
                logger.exception("Fallo ejecutando acción SOAR %s", action)
        return applied

    def _dispatch(self, action: str, event: dict) -> bool:
        if action == "kill_process" and event.get("pid"):
            return self.kill_process(int(event["pid"]))
        if action == "quarantine_file" and event.get("path"):
            return self.quarantine_file(event["path"], event.get("rule_title", "SOAR auto"))
        if action == "block_remote_ip" and event.get("remote"):
            ip = event["remote"].split(":")[0]
            return self.block_ip(ip, minutes=60)
        if action == "notify_siem":
            if self.siem:
                self.siem.send(event)
                return True
            return False
        return False

    def kill_process(self, pid: int) -> bool:
        try:
            os.kill(pid, signal.SIGKILL)
            logger.warning("SOAR: proceso %d terminado (SIGKILL)", pid)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            logger.error("SOAR: sin permisos para matar PID %d", pid)
            return False

    def quarantine_file(self, path: str, motivo: str) -> bool:
        if not os.path.exists(path):
            return False
        return self.engine.quarantine(path, motivo) is not None

    def block_ip(self, ip: str, minutes: int = 60) -> bool:
        if not ip or ip.startswith("127.") or ip == "::1":
            return False
        try:
            subprocess.run(["sudo", "-n", "iptables", "-I", "INPUT",
                            "-s", ip, "-j", "DROP"], check=True, timeout=10)
            subprocess.run(["sudo", "-n", "iptables", "-I", "OUTPUT",
                            "-d", ip, "-j", "DROP"], check=True, timeout=10)
            with self._lock:
                self._blocked_ips[ip] = time.time() + minutes * 60
            logger.warning("SOAR: IP %s bloqueada por %d minutos", ip, minutes)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.error("SOAR: no se pudo bloquear %s: %s", ip, exc)
            return False

    def unblock_expired(self):
        now = time.time()
        with self._lock:
            expired = [ip for ip, exp in self._blocked_ips.items() if exp < now]
            for ip in expired:
                try:
                    subprocess.run(["sudo", "-n", "iptables", "-D", "INPUT",
                                    "-s", ip, "-j", "DROP"], timeout=10)
                    subprocess.run(["sudo", "-n", "iptables", "-D", "OUTPUT",
                                    "-d", ip, "-j", "DROP"], timeout=10)
                except Exception:
                    pass
                del self._blocked_ips[ip]

    def isolate_endpoint(self) -> bool:
        try:
            subprocess.run(["sudo", "-n", "iptables", "-I", "OUTPUT", "1",
                            "!", "-o", "lo", "-j", "DROP"], check=True, timeout=10)
            logger.critical("SOAR: endpoint aislado de la red.")
            return True
        except Exception as exc:
            logger.error("SOAR: fallo al aislar endpoint: %s", exc)
            return False
