# tests/test_qt_dashboard.py
import pytest
from PyQt6.QtWidgets import QApplication
from server.qt_dashboard import ServerDashboard


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def dashboard(qapp):
    return ServerDashboard("http://localhost:8000", "test-key")


def test_dashboard_initializes(dashboard, qtbot):
    qtbot.addWidget(dashboard)
    assert "Antivirus Pro" in dashboard.windowTitle()


def test_sidebar_has_all_nav_buttons(dashboard, qtbot):
    qtbot.addWidget(dashboard)
    assert len(dashboard.sidebar.buttons) == 8


def test_navigate_to_switches_panel(dashboard, qtbot):
    qtbot.addWidget(dashboard)
    dashboard.navigate_to(0)
    assert dashboard.stack.currentIndex() == 0
    assert "Dashboard" in dashboard.page_title.text()


def test_refresh_all_does_not_crash(dashboard, qtbot):
    qtbot.addWidget(dashboard)
    dashboard.refresh_all()


def test_page_title_uses_navigation_titles(dashboard, qtbot):
    qtbot.addWidget(dashboard)
    dashboard.navigate_to(0)
    assert "Dashboard" in dashboard.page_title.text()
