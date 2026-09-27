"""
core/threat_store.py
Almacén forense local de eventos de seguridad en SQLite.

Persiste eventos de kernel, red, escaneos y alertas con índices por
timestamp, PID, tipo y severidad. Permite búsquedas tipo:
  - ¿Qué procesos abrieron /etc/shadow en las últimas 24h?
  - ¿Qué conexiones hizo el PID 1234?
  - ¿Qué reglas Sigma dispararon esta semana?
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger("antivirus.threat_store")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    pid INTEGER,
    uid INTEGER,
    comm TEXT,
    path TEXT,
    remote TEXT,
    severity TEXT,
    rule_id TEXT,
    rule_title TEXT,
    payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
"""


class ThreatStore:
    def __init__(self, db_path: str | None = None):
        if db_path is None:
            base = Path.home() / ".local/share/antivirus"
            base.mkdir(parents=True, exist_ok=True)
            db_path = str(base / "threat_store.db")
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        logger.info("ThreatStore inicializado: %s", db_path)

    def add_event(self, source: str, event_type: str, *, pid=None, uid=None,
                  comm=None, path=None, remote=None, severity=None,
                  rule_id=None, rule_title=None, payload: dict | None = None):
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (ts, source, event_type, pid, uid, comm, path, "
                "remote, severity, rule_id, rule_title, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), source, event_type, pid, uid, comm, path, remote,
                 severity, rule_id, rule_title,
                 json.dumps(payload) if payload else None),
            )
            self._conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def search_path(self, path: str, since_seconds: int = 86400) -> list[tuple]:
        since = time.time() - since_seconds
        return self.query(
            "SELECT ts, pid, comm, event_type, path FROM events "
            "WHERE path LIKE ? AND ts > ? ORDER BY ts DESC LIMIT 500",
            (f"%{path}%", since),
        )

    def search_process(self, pid: int) -> list[tuple]:
        return self.query(
            "SELECT ts, source, event_type, path, remote, severity "
            "FROM events WHERE pid = ? ORDER BY ts DESC LIMIT 1000",
            (pid,),
        )

    def recent_alerts(self, limit: int = 100) -> list[tuple]:
        return self.query(
            "SELECT ts, severity, rule_title, comm, path FROM events "
            "WHERE severity IS NOT NULL ORDER BY ts DESC LIMIT ?",
            (limit,),
        )

    def close(self):
        with self._lock:
            self._conn.close()
