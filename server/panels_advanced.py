# server/panels_advanced.py
"""Paneles avanzados para PyQt6 (ML, Zero-Day, Cluster)."""
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QFrame, QComboBox, QProgressBar,
                             QTextEdit, QSplitter, QTabWidget)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor

from server.widgets import Card, DataTable, StatusBadge


class ZeroDayPanel(QWidget):
    """Panel de detección Zero-Day."""

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh()

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(15000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("🧠 Detección Zero-Day (ML)")
        title.setObjectName("Title")
        layout.addWidget(title)

        # KPIs
        grid = QGridLayout()
        self.card_anomalies = Card("Anomalías Detectadas", "0", "red")
        self.card_ml_score = Card("Score ML Promedio", "0%", "yellow")
        self.card_unknown = Card("Malware Desconocido", "0", "red")
        self.card_baseline = Card("Baseline (samples)", "0", "blue")

        grid.addWidget(self.card_anomalies, 0, 0)
        grid.addWidget(self.card_ml_score, 0, 1)
        grid.addWidget(self.card_unknown, 0, 2)
        grid.addWidget(self.card_baseline, 0, 3)
        layout.addLayout(grid)

        # Tabla de anomalías
        self.table = DataTable(["Fecha", "Archivo", "Score", "Razones", "Decisión"])
        layout.addWidget(self.table)

    def refresh(self):
        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) as c, AVG(anomaly_score) as avg_score
                    FROM behavior_analysis
                    WHERE created_at > NOW() - INTERVAL '24 hours'
                """)
                row = cur.fetchone()
                if row:
                    self.card_anomalies.set_value(row['c'] or 0)
                    avg = row['avg_score'] or 0
                    self.card_ml_score.set_value(f"{int(avg * 100)}%")
        except Exception:
            pass


class ClusterPanel(QWidget):
    """Panel de estado del cluster."""

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh()

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(10000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("🌐 Cluster")
        title.setObjectName("Title")
        layout.addWidget(title)

        # KPIs
        grid = QGridLayout()
        self.card_nodes = Card("Nodos Activos", "0", "green")
        self.card_jobs_pending = Card("Jobs Pendientes", "0", "yellow")
        self.card_jobs_running = Card("Jobs en Curso", "0", "blue")
        self.card_jobs_completed = Card("Jobs Completados (24h)", "0", "green")

        grid.addWidget(self.card_nodes, 0, 0)
        grid.addWidget(self.card_jobs_pending, 0, 1)
        grid.addWidget(self.card_jobs_running, 0, 2)
        grid.addWidget(self.card_jobs_completed, 0, 3)
        layout.addLayout(grid)

        # Tabla de nodos
        nodes_label = QLabel("Nodos del Cluster")
        nodes_label.setStyleSheet("font-size: 16px; font-weight: bold; padding-top: 16px;")
        layout.addWidget(nodes_label)

        self.nodes_table = DataTable(["Node ID", "Hostname", "Rol", "Estado", "Último Heartbeat"])
        layout.addWidget(self.nodes_table)

    def refresh(self):
        try:
            with self.db.cursor() as cur:
                # KPIs
                cur.execute("""
                    SELECT COUNT(*) as c FROM cluster_nodes
                    WHERE last_heartbeat > NOW() - INTERVAL '60 seconds'
                """)
                self.card_nodes.set_value(cur.fetchone()['c'] or 0)

                cur.execute("SELECT COUNT(*) as c FROM cluster_jobs WHERE status='pending'")
                self.card_jobs_pending.set_value(cur.fetchone()['c'] or 0)

                cur.execute("SELECT COUNT(*) as c FROM cluster_jobs WHERE status='running'")
                self.card_jobs_running.set_value(cur.fetchone()['c'] or 0)

                cur.execute("""
                    SELECT COUNT(*) as c FROM cluster_jobs
                    WHERE status='completed' AND finished_at > NOW() - INTERVAL '24 hours'
                """)
                self.card_jobs_completed.set_value(cur.fetchone()['c'] or 0)

                # Tabla de nodos
                cur.execute("""
                    SELECT node_id, hostname, role, status, last_heartbeat
                    FROM cluster_nodes
                    ORDER BY last_heartbeat DESC
                """)
                rows = cur.fetchall()

            self.nodes_table.clear_rows()
            for n in rows:
                self.nodes_table.add_row([
                    n['node_id'],
                    n['hostname'],
                    n['role'],
                    n['status'],
                    str(n['last_heartbeat'])[:19],
                ])
        except Exception as e:
            pass


class ForensicsTimelinePanel(QWidget):
    """Panel de timeline forense."""

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("🕐 Timeline Forense")
        title.setObjectName("Title")
        layout.addWidget(title)

        # Filtros
        filters = QHBoxLayout()
        filters.addWidget(QLabel("Evento:"))
        self.type_filter = QComboBox()
        self.type_filter.addItems([
            "Todos", "execve", "openat", "connect",
            "audit_execve", "audit_openat", "audit_connect",
        ])
        self.type_filter.currentTextChanged.connect(self.refresh)
        filters.addWidget(self.type_filter)

        refresh_btn = QPushButton("🔄 Actualizar")
        refresh_btn.clicked.connect(self.refresh)
        filters.addWidget(refresh_btn)

        filters.addStretch()
        layout.addLayout(filters)

        # Timeline
        self.timeline = QTextEdit()
        self.timeline.setReadOnly(True)
        self.timeline.setStyleSheet("font-family: monospace; font-size: 12px;")
        layout.addWidget(self.timeline)

    def refresh(self):
        try:
            etype = self.type_filter.currentText()
            with self.db.cursor() as cur:
                q = """
                    SELECT t.timestamp, t.event_type, t.process_name,
                           t.process_exe, t.file_path, t.network_dst_ip,
                           t.network_dst_port, e.hostname
                    FROM telemetry t
                    LEFT JOIN endpoints e ON t.endpoint_id = e.id
                    WHERE t.timestamp > NOW() - INTERVAL '1 hour'
                """
                params = []
                if etype != "Todos":
                    q += " AND t.event_type = %s"
                    params.append(etype)
                q += " ORDER BY t.timestamp DESC LIMIT 500"
                cur.execute(q, params)
                rows = cur.fetchall()

            self.timeline.clear()
            self.timeline.append(f"<b>Timeline - Últimos 500 eventos - 1h</b><br>")
            for r in rows:
                ts = str(r['timestamp'])[11:19]
                evt = r['event_type']
                proc = r['process_name'] or '-'
                detail = ''
                if r['file_path']:
                    detail = f"file={r['file_path'][-40:]}"
                elif r['network_dst_ip']:
                    detail = f"net={r['network_dst_ip']}:{r['network_dst_port']}"

                color = '#f85149' if 'exec' in evt else '#d29922' if 'connect' in evt else '#58a6ff'
                self.timeline.append(
                    f"<span style='color:{color}'>[{ts}]</span> "
                    f"<b>{evt}</b> [{proc}] {detail}"
                )
        except Exception as e:
            self.timeline.setText(f"Error: {e}")
