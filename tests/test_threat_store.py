"""
Tests de ThreatStore.
"""
import time
from pathlib import Path

import pytest

from core.threat_store import ThreatStore


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test.db"
    s = ThreatStore(str(db))
    yield s
    s.close()


class TestThreatStore:
    def test_add_event(self, store):
        store.add_event(
            source="test", event_type="exec",
            pid=1234, comm="bash", path="/bin/bash",
        )
        rows = store.query("SELECT COUNT(*) FROM events")
        assert rows[0][0] == 1

    def test_add_alert_con_severidad(self, store):
        store.add_event(
            source="sigma", event_type="alert",
            pid=1234, comm="bash", severity="high",
            rule_id="rule-1", rule_title="Suspicious shell",
        )
        alerts = store.recent_alerts()
        assert len(alerts) == 1

    def test_search_path(self, store):
        store.add_event(source="test", event_type="open",
                        pid=1, comm="cat", path="/etc/shadow")
        store.add_event(source="test", event_type="open",
                        pid=2, comm="cat", path="/etc/hosts")
        results = store.search_path("/etc/shadow")
        assert len(results) == 1

    def test_search_process(self, store):
        store.add_event(source="test", event_type="exec", pid=999, comm="evil")
        store.add_event(source="test", event_type="open", pid=999, comm="evil",
                        path="/etc/passwd")
        results = store.search_process(999)
        assert len(results) == 2

    def test_query_con_current_timestamp(self, store):
        store.add_event(source="test", event_type="exec", pid=1, comm="test")
        # Verificar que el timestamp se guardó recientemente
        rows = store.query("SELECT ts FROM events ORDER BY ts DESC LIMIT 1")
        ts = rows[0][0]
        assert abs(time.time() - ts) < 5

    def test_db_path_creado(self, tmp_path):
        db = tmp_path / "sub" / "otro.db"
        # Crear el directorio padre primero
        db.parent.mkdir(parents=True, exist_ok=True)
        s = ThreatStore(str(db))
        assert db.exists()
        s.close()
