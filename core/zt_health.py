"""
core/zt_health.py
Atestación de salud del endpoint para arquitectura Zero Trust.

Expone un dict con el estado de seguridad que un Policy Decision Point
(PDP) puede consultar antes de conceder acceso a recursos.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("antivirus.zt_health")


def _run(cmd: list[str], timeout: int = 5) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as exc:
        return -1, str(exc)


class ZTHealthAttestation:
    def __init__(self, engine, threat_store, config: dict | None = None):
        self.engine = engine
        self.store = threat_store
        self.config = config or {}

    def snapshot(self) -> dict:
        return {
            "ts": time.time(),
            "hostname": platform.node(),
            "kernel": platform.release(),
            "uptime_s": self._uptime(),
            "antivirus_active": True,
            "clamd_running": self._clamd_running(),
            "clamav_signatures_age_days": self._freshclam_age_days(),
            "iptables_active": self._iptables_active(),
            "ssh_root_login_disabled": self._ssh_root_login_disabled(),
            "unattended_upgrades": self._unattended_upgrades(),
            "recent_critical_alerts_24h": self._recent_critical_alerts(),
            "disk_encryption": self._disk_encryption(),
            "score": 0,
            "attestation_hash": "",
        }

    def _uptime(self) -> int:
        try:
            with open("/proc/uptime") as f:
                return int(float(f.read().split()[0]))
        except Exception:
            return -1

    def _clamd_running(self) -> bool:
        rc, _ = _run(["systemctl", "is-active", "clamav-daemon"])
        if rc == 0:
            return True
        return Path("/var/run/clamav/clamd.ctl").exists()

    def _freshclam_age_days(self) -> float:
        paths = ["/var/lib/clamav/daily.cvd", "/var/lib/clamav/daily.cld"]
        for p in paths:
            if os.path.exists(p):
                return (time.time() - os.path.getmtime(p)) / 86400
        return -1

    def _iptables_active(self) -> bool:
        rc, out = _run(["sudo", "-n", "iptables", "-L", "-n"])
        return rc == 0 and "Chain INPUT" in out and "DROP" in out

    def _ssh_root_login_disabled(self) -> bool:
        conf = Path("/etc/ssh/sshd_config")
        if not conf.exists():
            return False
        try:
            for line in conf.read_text().splitlines():
                line = line.strip()
                if line.lower().startswith("permitrootlogin"):
                    return "no" in line.lower()
        except OSError:
            pass
        return False

    def _unattended_upgrades(self) -> bool:
        rc, _ = _run(["systemctl", "is-enabled", "unattended-upgrades"])
        return rc == 0

    def _recent_critical_alerts(self) -> int:
        try:
            rows = self.store.query(
                "SELECT COUNT(*) FROM events WHERE severity = 'critical' AND ts > ?",
                (time.time() - 86400,),
            )
            return int(rows[0][0]) if rows else 0
        except Exception:
            return -1

    def _disk_encryption(self) -> bool:
        rc, out = _run(["lsblk", "-o", "NAME,FSTYPE", "-n"])
        return rc == 0 and "crypto_LUKS" in out

    def score_and_sign(self, snapshot: dict) -> dict:
        s = 0
        s += 20 if snapshot["clamd_running"] else 0
        s += 20 if 0 <= snapshot["clamav_signatures_age_days"] < 2 else 0
        s += 15 if snapshot["iptables_active"] else 0
        s += 10 if snapshot["ssh_root_login_disabled"] else 0
        s += 10 if snapshot["unattended_upgrades"] else 0
        s += 10 if snapshot["disk_encryption"] else 0
        s += 15 if snapshot["recent_critical_alerts_24h"] == 0 else 0
        snapshot["score"] = s

        canonical = json.dumps({k: v for k, v in snapshot.items()
                                if k != "attestation_hash"}, sort_keys=True).encode()
        snapshot["attestation_hash"] = hashlib.sha256(canonical).hexdigest()
        return snapshot

    def attest(self) -> dict:
        return self.score_and_sign(self.snapshot())
