# agent/qt_agent.py
from PyQt6.QtCore import QObject, QTimer, pyqtSignal, QUrl
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest
import json
import psutil
import platform

class AntivirusAgent(QObject):
    threat_detected = pyqtSignal(dict)
    scan_completed = pyqtSignal(dict)

    def __init__(self, server_url, api_key):
        super().__init__()
        self.server_url = server_url
        self.api_key = api_key
        self.network = QNetworkAccessManager()
        self.timer = QTimer()
        self.timer.timeout.connect(self.heartbeat)
        self.timer.start(60000)

    def heartbeat(self):
        data = {
            "hostname": platform.node(),
            "ip_address": self._get_ip(),
            "os_version": platform.platform(),
            "agent_version": "2.0.0",
            "status": "active"
        }
        self._post("/api/endpoints/heartbeat", data)

    def report_threat(self, threat: dict):
        threat["hostname"] = platform.node()
        self._post("/api/threats/report", threat)
        self.threat_detected.emit(threat)

    def _post(self, endpoint, data):
        request = QNetworkRequest(QUrl(f"{self.server_url}{endpoint}"))
        request.setRawHeader(b"Authorization", f"Bearer {self.api_key}".encode())
        request.setHeader(
            QNetworkRequest.KnownHeaders.ContentTypeHeader,
            "application/json"
        )
        self.network.post(request, json.dumps(data).encode())

    def _get_ip(self):
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2 and not addr.address.startswith("127."):
                    return addr.address
        return "0.0.0.0"
