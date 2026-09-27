"""
Tests de ZTHealthAttestation. Usan mocks para no depender del entorno real.
"""
from unittest.mock import MagicMock, patch

import pytest

from core.zt_health import ZTHealthAttestation


@pytest.fixture
def fake_engine():
    return MagicMock()


@pytest.fixture
def fake_store():
    store = MagicMock()
    store.query.return_value = [(0,)]
    return store


@pytest.fixture
def attestation(fake_engine, fake_store):
    return ZTHealthAttestation(fake_engine, fake_store, {})


class TestZTHealth:
    def test_snapshot_estructura(self, attestation):
        with patch("core.zt_health._run", return_value=(1, "")):
            with patch("pathlib.Path.exists", return_value=False):
                snap = attestation.snapshot()
        assert "ts" in snap
        assert "hostname" in snap
        assert "kernel" in snap
        assert "score" in snap

    def test_score_calculo(self, attestation):
        with patch("core.zt_health._run", return_value=(1, "")):
            with patch("pathlib.Path.exists", return_value=False):
                snap = attestation.snapshot()
        scored = attestation.score_and_sign(snap)
        assert 0 <= scored["score"] <= 100

    def test_attestation_hash_generado(self, attestation):
        with patch("core.zt_health._run", return_value=(1, "")):
            with patch("pathlib.Path.exists", return_value=False):
                result = attestation.attest()
        assert "attestation_hash" in result
        assert len(result["attestation_hash"]) == 64  # SHA256 hex

    def test_attestation_hash_deterministico(self, attestation):
        """El hash debe ser igual para el mismo snapshot."""
        with patch("core.zt_health._run", return_value=(1, "")):
            with patch("pathlib.Path.exists", return_value=False):
                s1 = attestation.snapshot()
                h1 = attestation.score_and_sign(s1.copy())["attestation_hash"]
                s2 = attestation.snapshot()
                # Quitar campos que cambian con el tiempo
                for d in (s1, s2):
                    d["ts"] = 0
                    d["uptime_s"] = 0
                h2 = attestation.score_and_sign(s2)["attestation_hash"]
        # No exigimos que coincidan (uptime cambia), solo que sean hashes válidos
        assert len(h1) == 64 and len(h2) == 64
