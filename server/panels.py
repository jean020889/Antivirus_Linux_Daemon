# server/panels.py
"""Paneles del dashboard EDR."""
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QFrame, QLineEdit, QComboBox,
                             QMessageBox, QTextEdit, QSplitter)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

from .widgets import Card, DataTable, StatusBadge, NavButton


class DashboardPanel(QWidget):
    """Panel principal con KPIs y actividad reciente."""

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh()

        # Auto-refresh cada 10s
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(10000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Título
        title = QLabel("📊 Dashboard")
        title.setObjectName("Title")
        layout.addWidget(title)

        # Grid de KPIs
        kpi_grid = QGridLayout()
        kpi_grid.setSpacing(16)

        self.card_endpoints = Card("Endpoints Activos", "0", "blue")
        self.card_threats_24h = Card("Amenazas (24h)", "0", "red")
        self.card_alerts_open = Card("Alertas Abiertas", "0", "yellow")
        self.card_health = Card("Salud Global", "0%", "green")

        kpi_grid.addWidget(self.card_endpoints, 0, 0)
        kpi_grid.addWidget(self.card_threats_24h, 0, 1)
        kpi_grid.addWidget(self.card_alerts_open, 0, 2)
        kpi_grid.addWidget(self.card_health, 0, 3)
        layout.addLayout(kpi_grid)

        # Splitter con detalles
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Tabla de amenazas recientes
        threats_frame = QFrame()
        threats_frame.setObjectName("Card")
        threats_layout = QVBoxLayout(threats_frame)
        threats_layout.addWidget(QLabel("🚨 Amenazas Recientes"))
        self.threats_table = DataTable(["Fecha", "Endpoint", "Archivo", "Amenaza", "Severidad"])
        threats_layout.addWidget(self.threats_table)
        splitter.addWidget(threats_frame)

        # Actividad reciente
        activity_frame = QFrame()
        activity_frame.setObjectName("Card")
        activity_layout = QVBoxLayout(activity_frame)
        activity_layout.addWidget(QLabel("📋 Actividad"))
        self.activity_text = QTextEdit()
        self.activity_text.setReadOnly(True)
        activity_layout.addWidget(self.activity_text)
        splitter.addWidget(activity_frame)

        layout.addWidget(splitter, 1)

    def refresh(self):
        """Actualiza todos los KPIs desde la BD."""
        try:
            stats = self.db.get_stats()
            self.card_endpoints.set_value(stats.get('endpoints', 0))
            self.card_threats_24h.set_value(stats.get('threats_24h', 0))
            self.card_alerts_open.set_value(stats.get('alerts_open', 0))

            # Salud: promedio de health_score
            try:
                with self.db.cursor() as cur:
                    cur.execute("SELECT AVG(health_score) as avg FROM endpoints WHERE status='active'")
                    avg = cur.fetchone()['avg']
                    if avg:
                        self.card_health.set_value(f"{int(avg)}%")
            except Exception:
                pass

            # Amenazas recientes
            self.threats_table.clear_rows()
            threats = self.db.list_threats(limit=20)
            colors = {
                4: {"critical": "#f85149", "high": "#d29922", "medium": "#1f6feb",
                    "low": "#6e7681"}.get("medium", "#c9d1d9")
            }
            for t in threats:
                fecha = str(t.get('detected_at', ''))[:19]
                self.threats_table.add_row([
                    fecha,
                    t.get('hostname', ''),
                    (t.get('file_path', '') or '')[-50:],
                    t.get('threat_name', ''),
                    t.get('severity', 'medium')
                ])

            # Actividad
            self.activity_text.clear()
            self.activity_text.append(f"✅ Sistema activo")
            self.activity_text.append(f"📡 Endpoints: {stats.get('endpoints', 0)}")
            self.activity_text.append(f"🛡️  Amenazas totales: {stats.get('threats_total', 0)}")
            self.activity_text.append(f"⚡ Amenazas 24h: {stats.get('threats_24h', 0)}")
            self.activity_text.append(f"🔔 Alertas abiertas: {stats.get('alerts_open', 0)}")
            self.activity_text.append(f"🌐 IOCs cargados: {stats.get('cti_iocs', 0)}")
            self.activity_text.append("")
            self.activity_text.append("Por severidad:")
            for sev, count in stats.get('by_severity', {}).items():
                self.activity_text.append(f"  • {sev}: {count}")
            self.activity_text.append("")
            self.activity_text.append("Por motor:")
            for eng, count in stats.get('by_engine', {}).items():
                self.activity_text.append(f"  • {eng}: {count}")
        except Exception as e:
            self.activity_text.append(f"❌ Error: {e}")


class ThreatsPanel(QWidget):
    """Panel de amenazas con filtros."""

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("🚨 Amenazas")
        title.setObjectName("Title")
        layout.addWidget(title)

        # Filtros
        filters = QHBoxLayout()
        filters.addWidget(QLabel("Severidad:"))
        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["Todas", "critical", "high", "medium", "low", "info"])
        self.sev_filter.currentTextChanged.connect(self.refresh)
        filters.addWidget(self.sev_filter)

        filters.addWidget(QLabel("Buscar:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Archivo, amenaza, endpoint...")
        self.search_input.textChanged.connect(self.refresh)
        filters.addWidget(self.search_input)

        refresh_btn = QPushButton("🔄 Actualizar")
        refresh_btn.clicked.connect(self.refresh)
        filters.addWidget(refresh_btn)

        filters.addStretch()
        layout.addLayout(filters)

        # Tabla
        self.table = DataTable(["ID", "Fecha", "Endpoint", "Archivo", "Amenaza",
                                "Motor", "Severidad", "MITRE", "Estado"])
        layout.addWidget(self.table)

    def refresh(self):
        try:
            sev = self.sev_filter.currentText()
            sev = None if sev == "Todas" else sev
            search = self.search_input.text().lower()

            threats = self.db.list_threats(limit=500, severity=sev)
            self.table.clear_rows()

            for t in threats:
                row_text = f"{t.get('file_path','')} {t.get('threat_name','')} {t.get('hostname','')}".lower()
                if search and search not in row_text:
                    continue
                self.table.add_row([
                    t.get('id'),
                    str(t.get('detected_at', ''))[:19],
                    t.get('hostname', ''),
                    (t.get('file_path', '') or '')[-60:],
                    t.get('threat_name', ''),
                    t.get('detection_engine', ''),
                    t.get('severity', ''),
                    t.get('mitre_technique', ''),
                    "🔒 Cuarentena" if t.get('quarantined') else "Abierta",
                ])
        except Exception as e:
            print(f"[!] ThreatsPanel refresh: {e}")


class EndpointsPanel(QWidget):
    """Panel de endpoints."""

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

        title = QLabel("💻 Endpoints")
        title.setObjectName("Title")
        layout.addWidget(title)

        refresh_btn = QPushButton("🔄 Actualizar")
        refresh_btn.clicked.connect(self.refresh)
        layout.addWidget(refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)

        self.table = DataTable(["ID", "Hostname", "IP", "SO", "Kernel",
                                "Agente", "Salud", "Último visto", "Estado"])
        layout.addWidget(self.table)

    def refresh(self):
        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT id, hostname, host(ip_address) as ip, os_name, kernel_version,
                           agent_version, health_score, last_seen, status
                    FROM endpoints ORDER BY last_seen DESC
                """)
                rows = cur.fetchall()

            self.table.clear_rows()
            for e in rows:
                self.table.add_row([
                    e['id'],
                    e['hostname'],
                    e['ip'] or '-',
                    e['os_name'] or '-',
                    (e['kernel_version'] or '-')[:30],
                    e['agent_version'] or '-',
                    f"{e['health_score']}%" if e['health_score'] else '-',
                    str(e['last_seen'])[:19],
                    e['status'],
                ])
        except Exception as e:
            print(f"[!] EndpointsPanel: {e}")


class AlertsPanel(QWidget):
    """Panel de alertas."""

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("🔔 Alertas")
        title.setObjectName("Title")
        layout.addWidget(title)

        toolbar = QHBoxLayout()
        self.status_filter = QComboBox()
        self.status_filter.addItems(["Todas", "open", "acknowledged", "resolved"])
        self.status_filter.currentTextChanged.connect(self.refresh)
        toolbar.addWidget(QLabel("Estado:"))
        toolbar.addWidget(self.status_filter)

        ack_btn = QPushButton("✅ Reconocer")
        ack_btn.clicked.connect(lambda: self._update_status("acknowledged"))
        toolbar.addWidget(ack_btn)

        resolve_btn = QPushButton("✔️  Resolver")
        resolve_btn.setObjectName("Primary")
        resolve_btn.clicked.connect(lambda: self._update_status("resolved"))
        toolbar.addWidget(resolve_btn)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.table = DataTable(["ID", "Fecha", "Endpoint", "Regla", "Nivel", "Estado", "Descripción"])
        layout.addWidget(self.table)

    def refresh(self):
        try:
            status = self.status_filter.currentText()
            status = None if status == "Todas" else status

            with self.db.cursor() as cur:
                q = """SELECT a.id, a.created_at, e.hostname, a.rule_name, a.rule_level,
                              a.status, a.description
                       FROM alerts a LEFT JOIN endpoints e ON a.endpoint_id = e.id"""
                params = []
                if status:
                    q += " WHERE a.status = %s"
                    params.append(status)
                q += " ORDER BY a.created_at DESC LIMIT 500"
                cur.execute(q, params)
                rows = cur.fetchall()

            self.table.clear_rows()
            for a in rows:
                self.table.add_row([
                    a['id'],
                    str(a['created_at'])[:19],
                    a['hostname'] or '-',
                    a['rule_name'],
                    a['rule_level'],
                    a['status'],
                    (a['description'] or '')[:80],
                ])
        except Exception as e:
            print(f"[!] AlertsPanel: {e}")

    def _update_status(self, status):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Aviso", "Selecciona una alerta")
            return
        alert_id = self.table.item(row, 0).text()
        self.db.update_alert_status(int(alert_id), status, user='admin')
        self.refresh()


class ForensicsPanel(QWidget):
    """Panel de forensia: búsquedas tipo '¿qué abrió /etc/shadow?'."""

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("🔍 Forensia")
        title.setObjectName("Title")
        layout.addWidget(title)

        # Búsqueda
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Buscar:"))
        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Ej: file_path = '/etc/shadow' OR process_name = 'bash'")
        search_layout.addWidget(self.query_input)

        self.search_type = QComboBox()
        self.search_type.addItems(["Telemetría", "Amenazas", "Respuestas SOAR"])
        search_layout.addWidget(self.search_type)

        search_btn = QPushButton("🔍 Buscar")
        search_btn.setObjectName("Primary")
        search_btn.clicked.connect(self.search)
        search_layout.addWidget(search_btn)

        layout.addLayout(search_layout)

        # Tabla resultados
        self.results = DataTable(["Fecha", "Tipo", "Proceso", "Usuario", "Archivo", "IP", "MITRE"])
        layout.addWidget(self.results)

        # Botón de exportar forense
        export_btn = QPushButton("📦 Capturar Evidencias (SOAR)")
        export_btn.clicked.connect(self._collect_forensics)
        layout.addWidget(export_btn)

    def search(self):
        try:
            query = self.query_input.text().strip()
            stype = self.search_type.currentText()

            if stype == "Telemetría":
                with self.db.cursor() as cur:
                    q = "SELECT timestamp, event_type, process_name, process_user, file_path, network_dst_ip, mitre_technique FROM telemetry"
                    if query:
                        q += f" WHERE {query}"
                    q += " ORDER BY timestamp DESC LIMIT 1000"
                    cur.execute(q)
                    rows = cur.fetchall()
                self.results.clear_rows()
                for r in rows:
                    self.results.add_row([
                        str(r['timestamp'])[:19],
                        r['event_type'],
                        r['process_name'] or '-',
                        r['process_user'] or '-',
                        (r['file_path'] or '-')[-50:],
                        str(r['network_dst_ip'] or '-'),
                        r['mitre_technique'] or '-',
                    ])
            elif stype == "Amenazas":
                threats = self.db.list_threats(limit=1000)
                self.results.clear_rows()
                for t in threats:
                    self.results.add_row([
                        str(t['detected_at'])[:19],
                        t['threat_name'],
                        t.get('detection_engine', '-'),
                        '-',
                        (t['file_path'] or '-')[-50:],
                        '-',
                        t.get('mitre_technique', '-'),
                    ])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Query inválida: {e}")

    def _collect_forensics(self):
        try:
            from core.soar import SOAREngine
            soar = SOAREngine({})
            result = soar.collect_forensics()
            if result['success']:
                QMessageBox.information(self, "Evidencias",
                    f"Capturadas en: {result['output_dir']}\n{len(result['files'])} archivos")
            else:
                QMessageBox.warning(self, "Error", str(result.get('error')))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
