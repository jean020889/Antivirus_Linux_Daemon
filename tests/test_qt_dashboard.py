# tests/test_qt_dashboard.py
import pytest
from PyQt6.QtWidgets import QApplication
from server.qt_dashboard import ServerDashboard

@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app

@pytest.fixture
def dashboard(qapp, monkeypatch):
    def mock_get(*args, **kwargs):
        class MockResponse:
            status_code = 200
            def json(self):
                return [{
                    "hostname": "test-pc", "ip_address": "192.168.1.10",
                    "os_version": "Ubuntu 22.04", "last_seen": "2026-09-27",
                    "status": "active", "detected_at": "2026-09-27",
                    "file_path": "/tmp/test", "threat_name": "Test",
                    "detection_type": "yara", "severity": "high",
                    "scan_type": "full", "started_at": "2026-09-27",
                    "finished_at": "2026-09-27", "threats_found": 1
                }]
        return MockResponse()
    monkeypatch.setattr("requests.get", mock_get)
    return ServerDashboard("http://localhost:8000", "test-key")

def test_dashboard_initializes(dashboard, qtbot):
    qtbot.addWidget(dashboard)
    assert dashboard.windowTitle() == "Antivirus Pro - Consola Central"

def test_endpoints_table_populates(dashboard, qtbot):
    qtbot.addWidget(dashboard)
    dashboard.refresh_all()
    assert dashboard.endpoints_table.rowCount() == 1
    assert dashboard.endpoints_table.item(0, 0).text() == "test-pc"

def test_threats_table_populates(dashboard, qtbot):
    qtbot.addWidget(dashboard)
    dashboard.refresh_all()
    assert dashboard.threats_table.rowCount() == 1
