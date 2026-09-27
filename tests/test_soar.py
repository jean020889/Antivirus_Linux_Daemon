"""
Tests de SOAR con mocks (no modifican el sistema real).
"""
from unittest.mock import MagicMock, patch

import pytest

from core.soar import SOAR


@pytest.fixture
def fake_engine():
    engine = MagicMock()
    engine.quarantine.return_value = "/cuarentena/archivo"
    return engine


@pytest.fixture
def fake_siem():
    siem = MagicMock()
    return siem


class TestSOAR:
    def test_policy_default_existe(self, fake_engine):
        soar = SOAR(fake_engine)
        assert "critical" in soar.policy
        assert "kill_process" in soar.policy["critical"]

    def test_respond_dispara_kill_process(self, fake_engine):
        soar = SOAR(fake_engine, policy={"critical": ["kill_process"]})
        with patch("os.kill") as mock_kill:
            applied = soar.respond({"pid": 1234}, severity="critical")
        assert "kill_process" in applied
        mock_kill.assert_called_once()

    def test_respond_dispara_quarantine(self, fake_engine):
        soar = SOAR(fake_engine, policy={"high": ["quarantine_file"]})
        with patch("os.path.exists", return_value=True):
            applied = soar.respond({"path": "/tmp/evil"}, severity="high")
        assert "quarantine_file" in applied
        fake_engine.quarantine.assert_called_once()

    def test_respond_dispara_notify_siem(self, fake_engine, fake_siem):
        soar = SOAR(fake_engine, siem_forwarder=fake_siem,
                    policy={"medium": ["notify_siem"]})
        applied = soar.respond({"event": "test"}, severity="medium")
        assert "notify_siem" in applied
        fake_siem.send.assert_called_once()

    def test_block_ip_usa_iptables(self, fake_engine):
        soar = SOAR(fake_engine)
        with patch("subprocess.run") as mock_run:
            result = soar.block_ip("1.2.3.4", minutes=10)
        assert result is True
        # Debe haber llamado a iptables (INPUT y OUTPUT)
        assert mock_run.call_count == 2

    def test_block_ip_ignora_loopback(self, fake_engine):
        soar = SOAR(fake_engine)
        assert soar.block_ip("127.0.0.1") is False
        assert soar.block_ip("::1") is False

    def test_block_ip_registra_para_expirar(self, fake_engine):
        soar = SOAR(fake_engine)
        with patch("subprocess.run"):
            soar.block_ip("1.2.3.4", minutes=10)
        assert "1.2.3.4" in soar._blocked_ips

    def test_kill_process_inexistente(self, fake_engine):
        soar = SOAR(fake_engine)
        with patch("os.kill", side_effect=ProcessLookupError):
            result = soar.kill_process(999999)
        assert result is False
