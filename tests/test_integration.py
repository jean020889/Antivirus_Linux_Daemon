# tests/test_integration.py
"""Tests de integración (requieren PostgreSQL)."""
import os
import sys
import pytest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def db_available():
    try:
        from core.db import DB
        db = DB()
        with db.cursor() as cur:
            cur.execute("SELECT 1")
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not db_available(),
    reason="PostgreSQL no disponible"
)


class TestDatabase:
    def test_connection(self):
        from core.db import DB
        db = DB()
        with db.cursor() as cur:
            cur.execute("SELECT 1 as x")
            assert cur.fetchone()['x'] == 1

    def test_upsert_endpoint(self):
        from core.db import DB
        db = DB()
        hostname = f"test-host-{int(datetime.now().timestamp())}"
        ep_id = db.upsert_endpoint(hostname=hostname, ip='127.0.0.1')
        assert ep_id > 0

        # Segunda vez → debe actualizar
        ep_id_2 = db.upsert_endpoint(hostname=hostname, ip='127.0.0.2')
        assert ep_id == ep_id_2

    def test_get_stats(self):
        from core.db import DB
        db = DB()
        stats = db.get_stats()
        assert 'endpoints' in stats
        assert 'threats_total' in stats
        assert isinstance(stats['endpoints'], int)


class TestAPI:
    def test_health_endpoint(self):
        import requests
        try:
            r = requests.get("http://localhost:8003/", timeout=5)
            assert r.status_code == 200
            data = r.json()
            assert data['service'] == 'Antivirus Pro - Servidor Central'
        except requests.ConnectionError:
            pytest.skip("API no está corriendo")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
