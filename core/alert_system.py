import os
import subprocess
from PyQt6.QtWidgets import QMessageBox, QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout
from PyQt6.QtCore import QTimer

class AlertSystem:
    def __init__(self, parent):
        self.parent = parent
        self.blocked_ips = set()  # IPs bloqueadas permanentemente

    def show_alert(self, event):
        """
        Muestra una alerta visual (diálogo o notificación) para un evento.
        """
        if not self.parent.is_active:
            return  # No mostrar alertas si el antivirus está pausado

        # Si es una alerta de red con IP, mostrar diálogo interactivo
        if event.get('type') == 'NETWORK_BEHAVIOR' and event.get('ip'):
            self.show_network_alert(event)
        else:
            # Alertas normales (comportamiento, etc.)
            self.show_notification(event)

    def show_notification(self, event):
        """
        Muestra una notificación emergente (no bloqueante) usando QMessageBox.
        """
        severity = event.get('severity', 'MEDIA')
        emoji = {
            'CRÍTICA': '🚨',
            'ALTA': '⚠️',
            'MEDIA': '🔶',
            'BAJA': '🔷'
        }.get(severity, 'ℹ️')

        msg = QMessageBox(self.parent)
        msg.setIcon(QMessageBox.Icon.Warning if severity in ['CRÍTICA', 'ALTA'] else QMessageBox.Icon.Information)
        msg.setWindowTitle(f"{emoji} Alerta de Seguridad - {severity}")
        msg.setText(f"{event.get('desc', 'Evento sospechoso')}\n\n"
                    f"PID: {event.get('pid')}\n"
                    f"Proceso: {event.get('name')}\n"
                    f"Comando: {event.get('cmdline', 'N/A')}\n"
                    f"Hora: {event.get('timestamp')}")
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        # No bloqueamos la GUI, usamos QTimer para mostrarlo sin interrumpir
        QTimer.singleShot(100, msg.exec)

    def show_network_alert(self, event):
        """
        Muestra un diálogo interactivo para conexiones sospechosas.
        Ofrece opciones: Bloquear IP, Permitir, Bloquear temporalmente.
        """
        ip = event.get('ip')
        if not ip:
            return

        # Si la IP ya está bloqueada, no mostrar de nuevo
        if ip in self.blocked_ips:
            return

        dialog = QDialog(self.parent)
        dialog.setWindowTitle("🚨 Conexión Sospechosa Detectada")
        dialog.setModal(True)
        dialog.setMinimumWidth(500)

        layout = QVBoxLayout(dialog)

        # Información
        info = QLabel(
            f"<h3>⚠️ Alerta de Red</h3>"
            f"<p><b>IP:</b> {ip}</p>"
            f"<p><b>Proceso:</b> {event.get('proceso', 'Desconocido')} (PID: {event.get('pid')})</p>"
            f"<p><b>Puerto local:</b> {event.get('local', 'N/A')}</p>"
            f"<p><b>Puerto remoto:</b> {event.get('remote', 'N/A')}</p>"
            f"<p><b>Motivo:</b> {event.get('motivo', 'Comportamiento sospechoso')}</p>"
            f"<p><b>Hora:</b> {event.get('timestamp')}</p>"
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # Botones
        btn_layout = QHBoxLayout()

        # Bloquear permanentemente
        block_btn = QPushButton("🚫 Bloquear IP (permanente)")
        block_btn.setStyleSheet("background:#ff5555;color:white;")
        block_btn.clicked.connect(lambda: self._block_ip(ip, dialog, event))

        # Bloquear temporalmente (5 minutos)
        temp_block_btn = QPushButton("⏳ Bloquear 5 min")
        temp_block_btn.setStyleSheet("background:#ffaa00;color:white;")
        temp_block_btn.clicked.connect(lambda: self._temp_block_ip(ip, dialog, event))

        # Permitir (ignorar esta vez)
        allow_btn = QPushButton("✅ Permitir (solo esta vez)")
        allow_btn.setStyleSheet("background:#00cc66;color:white;")
        allow_btn.clicked.connect(lambda: self._allow_ip(ip, dialog))

        # Cerrar sin acción
        close_btn = QPushButton("❌ Ignorar (no bloquear)")
        close_btn.clicked.connect(dialog.reject)

        btn_layout.addWidget(block_btn)
        btn_layout.addWidget(temp_block_btn)
        btn_layout.addWidget(allow_btn)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        dialog.exec()

    def _block_ip(self, ip, dialog, event):
        """Bloquea permanentemente una IP usando iptables."""
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            self.blocked_ips.add(ip)
            self.parent._log(f"[FIREWALL] IP {ip} bloqueada permanentemente")
            QMessageBox.information(self.parent, "IP Bloqueada", f"La IP {ip} ha sido bloqueada permanentemente.")
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(self.parent, "Error", f"No se pudo bloquear la IP: {e}")

    def _temp_block_ip(self, ip, dialog, event):
        """Bloquea temporalmente (5 minutos) una IP."""
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            self.parent._log(f"[FIREWALL] IP {ip} bloqueada temporalmente (5 min)")
            QMessageBox.information(self.parent, "IP Bloqueada", f"La IP {ip} ha sido bloqueada por 5 minutos.")
            # Programar desbloqueo después de 5 minutos
            QTimer.singleShot(300000, lambda: self._unblock_ip(ip))  # 5 minutos
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(self.parent, "Error", f"No se pudo bloquear la IP: {e}")

    def _unblock_ip(self, ip):
        """Elimina las reglas de iptables para desbloquear la IP."""
        try:
            subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
            subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            self.parent._log(f"[FIREWALL] IP {ip} desbloqueada después de 5 min")
        except Exception:
            pass

    def _allow_ip(self, ip, dialog):
        """Permite la IP (solo esta vez)."""
        dialog.accept()
        self.parent._log(f"[FIREWALL] IP {ip} permitida manualmente")
        QMessageBox.information(self.parent, "IP Permitida", f"La IP {ip} ha sido permitida. No se bloqueará esta vez.")
