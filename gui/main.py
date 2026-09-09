#!/usr/bin/env python3
import sys, os, json, subprocess, time, shutil, threading
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
import qdarkstyle

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.scanner import ScannerEngine
from core.scheduler import ScanScheduler
from core.network_monitor import NetworkMonitor
from core.behavior_monitor import BehaviorMonitor
from core.alert_system import AlertSystem

# ========== WORKERS ==========
class ScanWorker(QObject):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    threat_detected = pyqtSignal(dict)
    finished = pyqtSignal(object)

    def __init__(self, engine, path):
        super().__init__()
        self.engine = engine
        self.path = path

    @pyqtSlot()
    def run(self):
        total = 0
        infected = 0
        for root, _, files in os.walk(self.path):
            if root in ["/proc", "/sys", "/dev", "/run"]:
                continue
            for f in files:
                full_path = os.path.join(root, f)
                if os.path.isfile(full_path) and not os.path.islink(full_path):
                    total += 1
                    inf, mot = self.engine.scan_file(full_path)
                    if inf:
                        infected += 1
                        es_sistema = any(full_path.startswith(d) for d in ['/bin','/usr/bin','/etc','/lib','/boot'])
                        programa = self._obtener_programa(full_path)
                        self.threat_detected.emit({
                            'filepath': full_path,
                            'motivo': mot,
                            'es_sistema': es_sistema,
                            'programa': programa,
                            'tipo': 'Sistema' if es_sistema else 'Externo'
                        })
                    if total % 100 == 0:
                        self.progress.emit((total % 1000) // 10)
        self.log.emit(f"[SCAN] Completado: {total} archivos, {infected} amenazas")
        self.finished.emit((total, infected))

    def _obtener_programa(self, path):
        try:
            if path.startswith('/usr/bin/') or path.startswith('/bin/'):
                res = subprocess.run(['dpkg', '-S', path], capture_output=True, text=True)
                if res.returncode == 0:
                    return res.stdout.split(':')[0].strip()
        except: pass
        return os.path.basename(path)

class UpdateWorker(QObject):
    finished = pyqtSignal(object)
    @pyqtSlot()
    def run(self):
        try:
            res = subprocess.run(['sudo', 'freshclam'], capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                self.finished.emit("Firmas actualizadas correctamente")
            else:
                self.finished.emit(f"Error en freshclam (código {res.returncode}):\\n{res.stderr}")
        except Exception as e:
            self.finished.emit(f"Excepción: {str(e)}")

# ========== VENTANA PRINCIPAL ==========
class AntivirusGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = self._load_config()
        self.engine = ScannerEngine(self.config)
        self.scheduler = ScanScheduler(self.engine, self.config)
        self.is_active = True
        self.pre_cuarentena = []
        self.alert_history = []
        self.behavior_monitor = BehaviorMonitor()
        self.alert_system = AlertSystem(self)
        self._initUI()
        self._start_behavior_monitor()

    def _load_config(self):
        with open('config.json', 'r') as f:
            return json.load(f)
    def _save_config(self):
        with open('config.json', 'w') as f:
            json.dump(self.config, f, indent=2)

    def _initUI(self):
        self.setWindowTitle("🛡️ Antivirus Profesional - Edición Futurista")
        self.setGeometry(100, 100, 1300, 750)
        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt6())

        menubar = self.menuBar()
        file_menu = menubar.addMenu("&Archivo")
        file_menu.addAction("Salir", self.close)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # Cabecera
        header = QHBoxLayout()
        header.addWidget(QLabel("🛡️", styleSheet="font-size:40px;"))
        header.addWidget(QLabel("Antivirus Profesional v5.0", styleSheet="font-size:28px;font-weight:bold;color:#00ffcc;"))
        header.addStretch()
        self.toggle_btn = QPushButton("⏸️ Pausar Antivirus")
        self.toggle_btn.clicked.connect(self._toggle)
        self.toggle_btn.setStyleSheet("background:#ffaa00;padding:8px 16px;border-radius:8px;font-weight:bold;")
        header.addWidget(self.toggle_btn)
        main_layout.addLayout(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabBar::tab{background:#2b2b2b;color:#ccc;padding:12px 20px;margin:2px;border-radius:8px;} QTabBar::tab:selected{background:#3a3a3a;color:#00ffcc;}")
        self.tab_dashboard = QWidget()
        self.tab_scanner = QWidget()
        self.tab_scheduler = QWidget()
        self.tab_pre = QWidget()
        self.tab_q = QWidget()
        self.tab_network = QWidget()
        self.tab_alerts = QWidget()  # NUEVA: pestaña de alertas
        self.tab_logs = QWidget()

        self.tabs.addTab(self.tab_dashboard, "📊 Dashboard")
        self.tabs.addTab(self.tab_scanner, "🔍 Escáner")
        self.tabs.addTab(self.tab_scheduler, "⏰ Programador")
        self.tabs.addTab(self.tab_pre, "⚠️ Pre-Cuarentena")
        self.tabs.addTab(self.tab_q, "🗑️ Cuarentena")
        self.tabs.addTab(self.tab_network, "🌐 Red")
        self.tabs.addTab(self.tab_alerts, "🚨 Alertas")
        self.tabs.addTab(self.tab_logs, "📜 Logs")
        main_layout.addWidget(self.tabs)

        self._init_dashboard()
        self._init_scanner()
        self._init_scheduler()
        self._init_pre()
        self._init_quarantine()
        self._init_network()
        self._init_alerts()  # NUEVO
        self._init_logs()

        self.statusBar().showMessage("Listo")
        self.statusBar().setStyleSheet("color:#00ffcc;")
        self._refresh_dashboard()
        self._refresh_scheduler()
        self._refresh_pre()
        self._refresh_quarantine()
        self._refresh_alerts()
        self._load_logs()

    # ========== DASHBOARD ==========
    def _init_dashboard(self):
        layout = QGridLayout(self.tab_dashboard)
        layout.setSpacing(20)
        self.card_total = self._create_card("📄 Archivos Analizados", "0")
        self.card_threats = self._create_card("💀 Amenazas", "0", "#ff5555")
        self.card_q = self._create_card("🗑️ En Cuarentena", "0", "#ffaa00")
        self.card_status = self._create_card("🛡️ Estado", "Activo", "#00ffcc")
        self.card_alerts = self._create_card("🚨 Alertas", "0", "#ff6600")  # NUEVO
        for i, card in enumerate([self.card_total, self.card_threats, self.card_q, self.card_status, self.card_alerts]):
            layout.addWidget(card, 0, i)

        # Botón rápido para ir al Programador
        btn_scheduler = QPushButton("⏰ Configurar Horarios")
        btn_scheduler.clicked.connect(lambda: self.tabs.setCurrentIndex(2))
        btn_scheduler.setStyleSheet("background:#3a5a7a;padding:10px;border-radius:8px;")
        layout.addWidget(btn_scheduler, 1, 0, 1, 2)

        # Actualizar firmas
        gb = QGroupBox("Actualizar Firmas")
        gb.setStyleSheet("QGroupBox{font-weight:bold;color:#00ffcc;}")
        hb = QHBoxLayout()
        self.update_btn = QPushButton("🔄 Actualizar ahora")
        self.update_btn.clicked.connect(self._update_signatures)
        self.update_btn.setStyleSheet("background:#3a7a5a;padding:10px;border-radius:8px;")
        self.update_progress = QProgressBar(); self.update_progress.hide()
        hb.addWidget(self.update_btn); hb.addWidget(self.update_progress)
        gb.setLayout(hb)
        layout.addWidget(gb, 1, 2, 1, 2)

        # Últimas amenazas
        gb2 = QGroupBox("Últimas Amenazas Detectadas")
        gb2.setStyleSheet("QGroupBox{font-weight:bold;color:#ff5555;}")
        self.recent_list = QListWidget()
        self.recent_list.setStyleSheet("background:#1e1e1e;color:#ff9999;")
        gb2.setLayout(QVBoxLayout()); gb2.layout().addWidget(self.recent_list)
        layout.addWidget(gb2, 2, 0, 1, 4)
        self._update_status()

    def _create_card(self, title, value, color="#00ffcc"):
        card = QGroupBox(title)
        card.setStyleSheet(f"QGroupBox{{font-weight:bold;color:{color};background:#2a2a2a;border:1px solid {color};border-radius:12px;padding:15px;}} QLabel{{font-size:32px;font-weight:bold;color:{color};}}")
        layout = QVBoxLayout()
        label = QLabel(value)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        card.setLayout(layout)
        card.label = label
        return card

    def _update_status(self):
        if self.is_active:
            self.card_status.label.setText("🟢 Activo")
            self.card_status.setStyleSheet(self.card_status.styleSheet().replace("#ff5555", "#00ffcc"))
        else:
            self.card_status.label.setText("🔴 Pausado")
            self.card_status.setStyleSheet(self.card_status.styleSheet().replace("#00ffcc", "#ff5555"))

    def _refresh_dashboard(self):
        total = 0; threats = 0
        try:
            with open("logs/scan.log", "r") as f:
                for line in f:
                    if "[SCAN]" in line and "archivos" in line:
                        import re
                        m = re.search(r'(\d+) archivos', line)
                        if m: total += int(m.group(1))
                    if "AMENAZA" in line:
                        threats += 1
        except: pass
        self.card_total.label.setText(str(total))
        self.card_threats.label.setText(str(threats))

        q_dir = self.config.get("cuarentena", "")
        if os.path.exists(q_dir):
            q_count = len([f for f in os.listdir(q_dir) if os.path.isfile(os.path.join(q_dir, f)) and not f.endswith(".log")])
            self.card_q.label.setText(str(q_count))
        else:
            self.card_q.label.setText("0")

        self.card_alerts.label.setText(str(len(self.alert_history)))

        self.recent_list.clear()
        try:
            with open("logs/scan.log", "r") as f:
                lines = f.readlines()
                for line in reversed(lines[-10:]):
                    if "AMENAZA" in line:
                        self.recent_list.addItem(line.strip())
        except: pass
        self._update_status()

    # ========== ESCÁNER ==========
    def _init_scanner(self):
        layout = QVBoxLayout(self.tab_scanner)
        hb = QHBoxLayout()
        self.path_input = QLineEdit("/home/asus")
        browse_btn = QPushButton("📂 Examinar")
        browse_btn.clicked.connect(self._browse)
        hb.addWidget(QLabel("Ruta:")); hb.addWidget(self.path_input); hb.addWidget(browse_btn)
        layout.addLayout(hb)

        self.scan_btn = QPushButton("🚀 Iniciar Escaneo")
        self.scan_btn.clicked.connect(self._start_scan)
        self.scan_btn.setStyleSheet("background:#2a7a5a;padding:12px;border-radius:8px;font-weight:bold;")
        layout.addWidget(self.scan_btn)

        self.scan_progress = QProgressBar()
        layout.addWidget(self.scan_progress)

        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        self.scan_results.setStyleSheet("background:#1e1e1e;color:#00ffcc;font-family:monospace;")
        layout.addWidget(self.scan_results)

    def _browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta")
        if folder: self.path_input.setText(folder)

    def _start_scan(self):
        if not self.is_active:
            QMessageBox.warning(self, "Pausado", "El antivirus está en pausa.")
            return
        path = self.path_input.text()
        if not os.path.exists(path):
            QMessageBox.warning(self, "Error", "Ruta no existe")
            return
        self.scan_results.clear()
        self.scan_btn.setEnabled(False)
        self.scan_progress.setValue(0)
        self.pre_cuarentena.clear()

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(self.engine, path)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_worker.progress.connect(self.scan_progress.setValue)
        self.scan_worker.log.connect(self.scan_results.append)
        self.scan_worker.threat_detected.connect(self._add_pre)
        self.scan_worker.finished.connect(self._scan_finished)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_thread.start()

    def _add_pre(self, threat):
        self.pre_cuarentena.append(threat)
        self._refresh_pre()

    def _scan_finished(self, result):
        self.scan_btn.setEnabled(True)
        self.scan_progress.setValue(100)
        if isinstance(result, Exception):
            self.scan_results.append(f"❌ Error: {result}")
        else:
            total, infected = result
            self.scan_results.append(f"✅ Finalizado. {total} archivos, {infected} amenazas.")
            self._refresh_dashboard()
            self._refresh_pre()

    # ========== PROGRAMADOR ==========
    def _init_scheduler(self):
        layout = QVBoxLayout(self.tab_scheduler)
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("➕ Agregar Tarea")
        add_btn.clicked.connect(self._add_task)
        refresh_btn = QPushButton("🔄 Refrescar")
        refresh_btn.clicked.connect(self._refresh_scheduler)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(refresh_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.task_table = QTableWidget()
        self.task_table.setColumnCount(7)
        self.task_table.setHorizontalHeaderLabels(["ID", "Nombre", "Tipo", "Hora", "Activa", "Editar", "Eliminar"])
        self.task_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.task_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.task_table)
        self._refresh_scheduler()

    def _refresh_scheduler(self):
        tasks = self.config.get("scheduled_scans", [])
        self.task_table.setRowCount(len(tasks))
        for i, task in enumerate(tasks):
            self.task_table.setItem(i, 0, QTableWidgetItem(str(task.get("id", ""))))
            self.task_table.setItem(i, 1, QTableWidgetItem(task.get("name", "")))
            self.task_table.setItem(i, 2, QTableWidgetItem(task.get("type", "")))
            self.task_table.setItem(i, 3, QTableWidgetItem(f"{task.get('hour', 0):02d}:{task.get('minute', 0):02d}"))
            self.task_table.setItem(i, 4, QTableWidgetItem("✅" if task.get("active", True) else "❌"))
            edit_btn = QPushButton("✏️")
            edit_btn.clicked.connect(lambda checked, row=i: self._edit_task(row))
            self.task_table.setCellWidget(i, 5, edit_btn)
            del_btn = QPushButton("🗑️")
            del_btn.clicked.connect(lambda checked, row=i: self._delete_task(row))
            self.task_table.setCellWidget(i, 6, del_btn)

    def _add_task(self):
        dialog = TaskDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_task = dialog.get_task()
            tasks = self.config.get("scheduled_scans", [])
            tasks.append(new_task)
            self.config["scheduled_scans"] = tasks
            self._save_config()
            self._refresh_scheduler()
            QMessageBox.information(self, "Éxito", "Tarea agregada correctamente")

    def _edit_task(self, row):
        tasks = self.config.get("scheduled_scans", [])
        if row >= len(tasks): return
        task = tasks[row]
        dialog = TaskDialog(self, task)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            updated = dialog.get_task()
            tasks[row] = updated
            self.config["scheduled_scans"] = tasks
            self._save_config()
            self._refresh_scheduler()
            QMessageBox.information(self, "Éxito", "Tarea actualizada")

    def _delete_task(self, row):
        tasks = self.config.get("scheduled_scans", [])
        if row >= len(tasks): return
        reply = QMessageBox.question(self, "Confirmar", f"¿Eliminar tarea '{tasks[row].get('name')}'?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            del tasks[row]
            self.config["scheduled_scans"] = tasks
            self._save_config()
            self._refresh_scheduler()

    # ========== PRE-CUARENTENA ==========
    def _init_pre(self):
        layout = QVBoxLayout(self.tab_pre)
        hb = QHBoxLayout()
        self.select_all_pre = QPushButton("☑️ Seleccionar todos")
        self.select_all_pre.clicked.connect(self._select_all_pre)
        self.move_q_btn = QPushButton("📦 Mover a Cuarentena")
        self.move_q_btn.clicked.connect(self._move_to_q)
        self.clear_pre_btn = QPushButton("🗑️ Limpiar lista")
        self.clear_pre_btn.clicked.connect(self._clear_pre)
        hb.addWidget(self.select_all_pre); hb.addWidget(self.move_q_btn); hb.addWidget(self.clear_pre_btn); hb.addStretch()
        layout.addLayout(hb)

        self.pre_table = QTableWidget()
        self.pre_table.setColumnCount(5)
        self.pre_table.setHorizontalHeaderLabels(["Archivo", "Motivo", "Tipo", "Programa", "Sel."])
        self.pre_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.pre_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.pre_table)
        self._refresh_pre()

    def _refresh_pre(self):
        self.pre_table.setRowCount(len(self.pre_cuarentena))
        for i, item in enumerate(self.pre_cuarentena):
            self.pre_table.setItem(i, 0, QTableWidgetItem(os.path.basename(item['filepath'])))
            self.pre_table.setItem(i, 1, QTableWidgetItem(item['motivo']))
            self.pre_table.setItem(i, 2, QTableWidgetItem(item['tipo']))
            self.pre_table.setItem(i, 3, QTableWidgetItem(item['programa']))
            cb = QCheckBox(); cb.setChecked(True)
            self.pre_table.setCellWidget(i, 4, cb)

    def _select_all_pre(self):
        for i in range(self.pre_table.rowCount()):
            cb = self.pre_table.cellWidget(i, 4)
            if cb: cb.setChecked(True)

    def _move_to_q(self):
        selected = []
        for i in range(self.pre_table.rowCount()):
            cb = self.pre_table.cellWidget(i, 4)
            if cb and cb.isChecked():
                selected.append(self.pre_cuarentena[i])
        if not selected:
            QMessageBox.warning(self, "Selección", "No seleccionaste ninguna amenaza.")
            return
        informe = "📋 INFORME DE AMENAZAS\n" + "="*50 + "\n"
        for idx, t in enumerate(selected, 1):
            informe += f"\n🔹 #{idx}\n   Archivo: {t['filepath']}\n   Motivo: {t['motivo']}\n   Tipo: {t['tipo']}\n   Programa: {t['programa']}\n   Fecha: {datetime.now()}\n"
        reply = QMessageBox.question(self, "Confirmar", informe + "\n¿Mover estos archivos a cuarentena?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.No: return
        movidos = 0
        for threat in selected:
            dest = self.engine.quarantine(threat['filepath'], threat['motivo'])
            if dest:
                movidos += 1
                self.pre_cuarentena.remove(threat)
                self._log(f"[CUARENTENA] {threat['filepath']} -> {threat['motivo']}")
        QMessageBox.information(self, "Cuarentena", f"Se movieron {movidos} archivos.")
        self._refresh_pre()
        self._refresh_quarantine()
        self._refresh_dashboard()

    def _clear_pre(self):
        reply = QMessageBox.question(self, "Limpiar", "¿Eliminar todos de pre-cuarentena sin mover?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.pre_cuarentena.clear()
            self._refresh_pre()

    # ========== CUARENTENA ==========
    def _init_quarantine(self):
        layout = QVBoxLayout(self.tab_q)
        hb = QHBoxLayout()
        refresh_q = QPushButton("🔄 Refrescar"); refresh_q.clicked.connect(self._refresh_quarantine)
        select_all_q = QPushButton("☑️ Seleccionar todos"); select_all_q.clicked.connect(self._select_all_q)
        restore_btn = QPushButton("↩️ Restaurar seleccionados"); restore_btn.clicked.connect(self._restore_q)
        delete_btn = QPushButton("🗑️ Eliminar seleccionados"); delete_btn.clicked.connect(self._delete_q)
        hb.addWidget(refresh_q); hb.addWidget(select_all_q); hb.addWidget(restore_btn); hb.addWidget(delete_btn); hb.addStretch()
        layout.addLayout(hb)

        self.q_table = QTableWidget()
        self.q_table.setColumnCount(4)
        self.q_table.setHorizontalHeaderLabels(["Archivo", "Origen", "Motivo", "Sel."])
        self.q_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.q_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.q_table)
        self._refresh_quarantine()

    def _refresh_quarantine(self):
        self.q_table.setRowCount(0)
        q_dir = self.config.get("cuarentena", "")
        if not os.path.exists(q_dir): return
        files = [f for f in os.listdir(q_dir) if os.path.isfile(os.path.join(q_dir, f)) and not f.endswith(".log")]
        self.q_table.setRowCount(len(files))
        for i, fname in enumerate(files):
            filepath = os.path.join(q_dir, fname)
            logpath = filepath + ".log"
            origen = "Desconocido"; motivo = "Sin motivo"
            if os.path.exists(logpath):
                with open(logpath, 'r') as lf:
                    for line in lf:
                        if line.startswith("Origen:"): origen = line.split(":",1)[1].strip()
                        elif line.startswith("Motivo:"): motivo = line.split(":",1)[1].strip()
            self.q_table.setItem(i, 0, QTableWidgetItem(fname))
            self.q_table.setItem(i, 1, QTableWidgetItem(origen))
            self.q_table.setItem(i, 2, QTableWidgetItem(motivo))
            cb = QCheckBox(); cb.setChecked(False)
            self.q_table.setCellWidget(i, 3, cb)

    def _select_all_q(self):
        for i in range(self.q_table.rowCount()):
            cb = self.q_table.cellWidget(i, 3)
            if cb: cb.setChecked(True)

    def _restore_q(self):
        self._action_q("restaurar")
    def _delete_q(self):
        self._action_q("eliminar")

    def _action_q(self, accion):
        q_dir = self.config.get("cuarentena", "")
        if not os.path.exists(q_dir): return
        selected = []
        for i in range(self.q_table.rowCount()):
            cb = self.q_table.cellWidget(i, 3)
            if cb and cb.isChecked():
                selected.append(self.q_table.item(i, 0).text())
        if not selected:
            QMessageBox.warning(self, "Selección", "No seleccionaste ningún archivo.")
            return
        if accion == "restaurar":
            reply = QMessageBox.question(self, "Restaurar", f"¿Restaurar {len(selected)} archivo(s)?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No: return
            for fname in selected:
                src = os.path.join(q_dir, fname)
                logpath = src + ".log"
                origen = None
                if os.path.exists(logpath):
                    with open(logpath, 'r') as lf:
                        for line in lf:
                            if line.startswith("Origen:"):
                                origen = line.split(":",1)[1].strip()
                                break
                if origen and os.path.exists(os.path.dirname(origen)):
                    try:
                        shutil.move(src, origen)
                        if os.path.exists(logpath): os.remove(logpath)
                    except: pass
                else:
                    dest = os.path.join(os.path.expanduser("~"), fname)
                    try:
                        shutil.move(src, dest)
                        if os.path.exists(logpath): os.remove(logpath)
                    except: pass
            QMessageBox.information(self, "Restaurado", f"Se restauraron {len(selected)} archivos.")
        else:
            reply = QMessageBox.question(self, "Eliminar", f"¿Eliminar permanentemente {len(selected)} archivo(s)?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No: return
            for fname in selected:
                src = os.path.join(q_dir, fname)
                logpath = src + ".log"
                try:
                    os.remove(src)
                    if os.path.exists(logpath): os.remove(logpath)
                except: pass
            QMessageBox.information(self, "Eliminado", f"Se eliminaron {len(selected)} archivos.")
        self._refresh_quarantine()
        self._refresh_dashboard()

    # ========== RED ==========
    def _init_network(self):
        layout = QVBoxLayout(self.tab_network)
        scan_net_btn = QPushButton("🔍 Escanear conexiones sospechosas")
        scan_net_btn.clicked.connect(self._scan_network)
        scan_net_btn.setStyleSheet("background:#2a5a7a;padding:10px;border-radius:8px;font-weight:bold;")
        layout.addWidget(scan_net_btn)

        self.network_table = QTableWidget()
        self.network_table.setColumnCount(6)
        self.network_table.setHorizontalHeaderLabels(["Timestamp", "PID", "Proceso", "Local", "Remoto", "Motivo"])
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.network_table)

        self.network_status = QLabel("Presiona 'Escanear' para analizar las conexiones activas.")
        self.network_status.setStyleSheet("color:#aaa;padding:5px;")
        layout.addWidget(self.network_status)

    def _scan_network(self):
        self.network_status.setText("🔄 Escaneando conexiones...")
        self.network_table.setRowCount(0)
        QApplication.processEvents()
        try:
            monitor = NetworkMonitor()
            sospechosas = monitor.scan()
            if not sospechosas:
                self.network_status.setText("✅ No se encontraron conexiones sospechosas.")
                self.network_table.setRowCount(1)
                self.network_table.setItem(0, 0, QTableWidgetItem("---"))
                self.network_table.setItem(0, 1, QTableWidgetItem("---"))
                self.network_table.setItem(0, 2, QTableWidgetItem("No hay conexiones sospechosas"))
                self.network_table.setItem(0, 3, QTableWidgetItem("---"))
                self.network_table.setItem(0, 4, QTableWidgetItem("---"))
                self.network_table.setItem(0, 5, QTableWidgetItem("---"))
                return
            self.network_table.setRowCount(len(sospechosas))
            for i, conn in enumerate(sospechosas):
                self.network_table.setItem(i, 0, QTableWidgetItem(conn['timestamp']))
                self.network_table.setItem(i, 1, QTableWidgetItem(str(conn['pid'])))
                self.network_table.setItem(i, 2, QTableWidgetItem(conn['proceso']))
                self.network_table.setItem(i, 3, QTableWidgetItem(conn['local']))
                self.network_table.setItem(i, 4, QTableWidgetItem(conn['remote']))
                self.network_table.setItem(i, 5, QTableWidgetItem(conn['motivo']))
            self.network_status.setText(f"✅ Escaneo completado. {len(sospechosas)} conexiones sospechosas.")
        except Exception as e:
            self.network_status.setText(f"❌ Error: {e}")
            QMessageBox.critical(self, "Error", f"No se pudo escanear: {e}")

    # ========== ALERTAS (NUEVO) ==========
    def _init_alerts(self):
        layout = QVBoxLayout(self.tab_alerts)
        refresh_alerts_btn = QPushButton("🔄 Refrescar Alertas")
        refresh_alerts_btn.clicked.connect(self._refresh_alerts)
        refresh_alerts_btn.setStyleSheet("background:#3a5a7a;padding:8px;border-radius:8px;")
        layout.addWidget(refresh_alerts_btn)

        self.alert_table = QTableWidget()
        self.alert_table.setColumnCount(6)
        self.alert_table.setHorizontalHeaderLabels(["Timestamp", "Tipo", "Severidad", "Proceso", "Descripción", "IP"])
        self.alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.alert_table)
        self._refresh_alerts()

    def _refresh_alerts(self):
        self.alert_table.setRowCount(len(self.alert_history))
        for i, alert in enumerate(reversed(self.alert_history)):  # Más recientes primero
            self.alert_table.setItem(i, 0, QTableWidgetItem(alert.get('timestamp', '')))
            self.alert_table.setItem(i, 1, QTableWidgetItem(alert.get('type', '')))
            self.alert_table.setItem(i, 2, QTableWidgetItem(alert.get('severity', '')))
            self.alert_table.setItem(i, 3, QTableWidgetItem(alert.get('name', '') or alert.get('proceso', '')))
            self.alert_table.setItem(i, 4, QTableWidgetItem(alert.get('desc', '')))
            self.alert_table.setItem(i, 5, QTableWidgetItem(alert.get('ip', 'N/A')))
        self.card_alerts.label.setText(str(len(self.alert_history)))

    # ========== LOGS ==========
    def _init_logs(self):
        layout = QVBoxLayout(self.tab_logs)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background:#1e1e1e;color:#00ffcc;font-family:monospace;")
        layout.addWidget(self.log_text)

    def _load_logs(self):
        try:
            with open("logs/scan.log", "r") as f:
                self.log_text.setText(f.read())
        except:
            self.log_text.setText("No hay logs aún.")

    def _log(self, msg):
        ts = datetime.now().strftime("%A, %d de %B de %Y %I:%M:%S %p")
        line = f"[{ts}] {msg}"
        os.makedirs("logs", exist_ok=True)
        with open("logs/scan.log", "a") as f:
            f.write(line + "\n")
        self.log_text.append(line)

    # ========== MONITOREO DE COMPORTAMIENTO (NUEVO) ==========
    def _start_behavior_monitor(self):
        """Inicia un hilo para monitorear comportamiento sospechoso."""
        def monitor_loop():
            while True:
                if self.is_active:
                    try:
                        # Escanear procesos
                        events = self.behavior_monitor.scan_processes()
                        for event in events:
                            self.alert_history.append(event)
                            self._refresh_alerts()
                            self._refresh_dashboard()
                            # Mostrar alerta emergente
                            self.alert_system.show_alert(event)

                        # Escanear red con comportamiento
                        nm = NetworkMonitor()
                        net_events = nm.scan_behavior()
                        for net_event in net_events:
                            # Convertir a formato de alerta
                            alert = {
                                'type': 'NETWORK_BEHAVIOR',
                                'timestamp': net_event['timestamp'],
                                'pid': net_event['pid'],
                                'name': net_event['proceso'],
                                'cmdline': f"Conexión desde {net_event['remote']}",
                                'desc': net_event.get('desc', 'Conexión sospechosa'),
                                'severity': 'ALTA',
                                'ip': net_event.get('ip'),
                                'proceso': net_event['proceso'],
                                'local': net_event['local'],
                                'remote': net_event['remote'],
                                'motivo': net_event['motivo']
                            }
                            self.alert_history.append(alert)
                            self._refresh_alerts()
                            self._refresh_dashboard()
                            self.alert_system.show_alert(alert)
                    except Exception as e:
                        self._log(f"[ERROR] En monitor de comportamiento: {e}")
                time.sleep(15)  # Escanear cada 15 segundos
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        self._log("[MONITOR] Monitoreo de comportamiento iniciado.")

    # ========== TOGGLE ==========
    def _toggle(self):
        self.is_active = not self.is_active
        if self.is_active:
            self.toggle_btn.setText("⏸️ Pausar Antivirus")
            self.toggle_btn.setStyleSheet("background:#ffaa00;padding:8px 16px;border-radius:8px;font-weight:bold;")
            self.statusBar().showMessage("Antivirus activado")
            self._log("Antivirus activado")
        else:
            self.toggle_btn.setText("▶️ Activar Antivirus")
            self.toggle_btn.setStyleSheet("background:#ff5555;padding:8px 16px;border-radius:8px;font-weight:bold;")
            self.statusBar().showMessage("Antivirus en pausa")
            self._log("Antivirus en pausa")
        self._update_status()

    # ========== UPDATE ==========
    def _update_signatures(self):
        self.update_btn.setEnabled(False)
        self.update_progress.show()
        self.statusBar().showMessage("Actualizando firmas...")
        self.update_thread = QThread()
        self.update_worker = UpdateWorker()
        self.update_worker.moveToThread(self.update_thread)
        self.update_worker.finished.connect(self._update_finished)
        self.update_worker.finished.connect(self.update_thread.quit)
        self.update_worker.finished.connect(self.update_worker.deleteLater)
        self.update_thread.finished.connect(self.update_thread.deleteLater)
        self.update_thread.started.connect(self.update_worker.run)
        self.update_thread.start()

    def _update_finished(self, result):
        self.update_btn.setEnabled(True)
        self.update_progress.hide()
        self.statusBar().showMessage("Listo")
        if "Error" in str(result):
            QMessageBox.critical(self, "Actualización", str(result))
        else:
            QMessageBox.information(self, "Actualización", str(result))
            self.engine.load_clamav_signatures()
            self._refresh_dashboard()

    def closeEvent(self, event):
        self._save_config()
        event.accept()

# ========== DIÁLOGO PARA TAREAS ==========
class TaskDialog(QDialog):
    def __init__(self, parent=None, task=None):
        super().__init__(parent)
        self.task = task or {}
        self.setWindowTitle("Agregar/Editar Tarea")
        self.setModal(True)
        self.setMinimumWidth(400)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Nombre:"))
        self.name_edit = QLineEdit(self.task.get("name", ""))
        layout.addWidget(self.name_edit)

        layout.addWidget(QLabel("Tipo:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["full_system", "folder"])
        self.type_combo.setCurrentText(self.task.get("type", "folder"))
        layout.addWidget(self.type_combo)

        layout.addWidget(QLabel("Ruta (solo para tipo folder):"))
        self.folder_edit = QLineEdit(self.task.get("folder_path", ""))
        layout.addWidget(self.folder_edit)

        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("Hora:"))
        self.hour_spin = QSpinBox(); self.hour_spin.setRange(0, 23); self.hour_spin.setValue(self.task.get("hour", 0))
        h_layout.addWidget(self.hour_spin)
        h_layout.addWidget(QLabel(":"))
        self.minute_spin = QSpinBox(); self.minute_spin.setRange(0, 59); self.minute_spin.setValue(self.task.get("minute", 0))
        h_layout.addWidget(self.minute_spin)
        layout.addLayout(h_layout)

        self.active_cb = QCheckBox("Activa")
        self.active_cb.setChecked(self.task.get("active", True))
        layout.addWidget(self.active_cb)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def get_task(self):
        return {
            "id": self.task.get("id", int(time.time())),
            "name": self.name_edit.text(),
            "type": self.type_combo.currentText(),
            "folder_path": self.folder_edit.text() if self.type_combo.currentText() == "folder" else None,
            "hour": self.hour_spin.value(),
            "minute": self.minute_spin.value(),
            "active": self.active_cb.isChecked()
        }

# ========== MAIN ==========
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt6())
    window = AntivirusGUI()
    window.show()
    sys.exit(app.exec())
