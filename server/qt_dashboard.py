# server/qt_dashboard.py
"""Antivirus Pro EDR - Dashboard PyQt6 con dark mode."""
import sys
import os

# Asegurar path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QFrame, QLabel, QPushButton, QStackedWidget,
                             QStatusBar)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QIcon

from server.widgets import NavButton
from server.panels import (DashboardPanel, ThreatsPanel, EndpointsPanel,
                            AlertsPanel, ForensicsPanel)
try:
    from server.panels_advanced import ZeroDayPanel, ClusterPanel, ForensicsTimelinePanel
    HAS_ADVANCED = True
except ImportError:
    HAS_ADVANCED = False
from core.db import DB


class Sidebar(QFrame):
    def __init__(self, on_navigate):
        super().__init__()
        self.setObjectName("Sidebar")
        self.setFixedWidth(220)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo
        logo = QLabel("🛡️  EDR Pro")
        logo.setObjectName("Logo")
        layout.addWidget(logo)

        # Botones
        self.buttons = []
        items = [
            ("📊", "Dashboard", 0),
            ("🚨", "Amenazas", 1),
            ("💻", "Endpoints", 2),
            ("🔔", "Alertas", 3),
            ("🔍", "Forensia", 4),
            ("🧠", "Zero-Day", 5),
            ("🕐", "Timeline", 6),
            ("🌐", "Cluster", 7),
        ]
        for icon, text, idx in items:
            btn = NavButton(icon, text)
            btn.clicked.connect(lambda checked, i=idx: on_navigate(i))
            layout.addWidget(btn)
            self.buttons.append(btn)

        self.buttons[0].setChecked(True)

        layout.addStretch()

        # Footer
        version = QLabel("v2.0.0 EDR")
        version.setStyleSheet("color: #6e7681; padding: 12px; font-size: 11px;")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)

    def set_active(self, idx):
        for i, btn in enumerate(self.buttons):
            btn.setChecked(i == idx)


class ServerDashboard(QMainWindow):
    def __init__(self, api_url=None, api_key=None):
        super().__init__()
        self.setWindowTitle("🛡️  Antivirus Pro EDR")
        self.resize(1400, 900)

        # Cargar estilo dark
        qss_path = os.path.join(os.path.dirname(__file__), "styles", "dark.qss")
        if os.path.exists(qss_path):
            with open(qss_path) as f:
                self.setStyleSheet(f.read())

        # DB
        try:
            self.db = DB()
        except Exception as e:
            print(f"[!] DB no disponible: {e}")
            self.db = None

        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        self.sidebar = Sidebar(self.navigate_to)
        main_layout.addWidget(self.sidebar)

        # Contenido
        content = QFrame()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setObjectName("Header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 12, 24, 12)

        self.page_title = QLabel("📊 Dashboard")
        self.page_title.setObjectName("Title")
        header_layout.addWidget(self.page_title)

        header_layout.addStretch()

        # Última actualización
        self.last_update = QLabel("Actualizado: --")
        self.last_update.setStyleSheet("color: #8b949e; font-size: 12px;")
        header_layout.addWidget(self.last_update)

        content_layout.addWidget(header)

        # Stack de paneles
        self.stack = QStackedWidget()
        if self.db:
            self.stack.addWidget(DashboardPanel(self.db))
            self.stack.addWidget(ThreatsPanel(self.db))
            self.stack.addWidget(EndpointsPanel(self.db))
            self.stack.addWidget(AlertsPanel(self.db))
            self.stack.addWidget(ForensicsPanel(self.db))
            
            if HAS_ADVANCED:
                self.stack.addWidget(ZeroDayPanel(self.db))
                self.stack.addWidget(ForensicsTimelinePanel(self.db))
                self.stack.addWidget(ClusterPanel(self.db))
        else:
            err = QLabel("❌ No hay conexión a PostgreSQL.\n\n"
                         "Verifica: sudo systemctl status postgresql")
            err.setAlignment(Qt.AlignmentFlag.AlignCenter)
            err.setStyleSheet("font-size: 18px; color: #f85149; padding: 50px;")
            self.stack.addWidget(err)

        content_layout.addWidget(self.stack, 1)
        main_layout.addWidget(content, 1)

        # Status bar
        status = QStatusBar()
        self.setStatusBar(status)
        status.showMessage("🟢 Conectado a PostgreSQL | 🛡️  Motor: clamd + YARA + Sigma")

        # Timer para actualizar hora
        self._timer = QTimer()
        self._timer.timeout.connect(self._update_time)
        self._timer.start(1000)

    def _update_time(self):
        from datetime import datetime
        self.last_update.setText(f"Actualizado: {datetime.now().strftime('%H:%M:%S')}")

    def navigate_to(self, idx):
        self.stack.setCurrentIndex(idx)
        self.sidebar.set_active(idx)

        titles = ["📊 Dashboard", "🚨 Amenazas", "💻 Endpoints", "🔔 Alertas", "🔍 Forensia",
                  "🧠 Zero-Day", "🕐 Timeline", "🌐 Cluster"]
        if idx < len(titles):
            self.page_title.setText(titles[idx])

        # Refresh panel si tiene método
        panel = self.stack.currentWidget()
        if hasattr(panel, 'refresh'):
            try:
                panel.refresh()
            except Exception:
                pass


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Antivirus Pro EDR")
    app.setStyle("Fusion")

    window = ServerDashboard()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
