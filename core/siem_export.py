# core/siem_export.py
"""
Exportación a SIEM en formato CEF sobre syslog.
Compatible con Splunk, ArcSight, QRadar, Wazuh.
"""
import socket
import re
from datetime import datetime


class CEFExporter:
    """Exporta eventos en formato CEF (Common Event Format)."""

    def __init__(self, syslog_host="127.0.0.1", syslog_port=514, protocol="udp"):
        self.host = syslog_host
        self.port = syslog_port
        self.protocol = protocol

    def _escape(self, s):
        """Escapa caracteres especiales CEF."""
        if s is None:
            return ""
        return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")

    def format_cef(self, event):
        """Formatea un evento en CEF."""
        version = "CEF:0"
        device_vendor = "AntivirusPro"
        device_product = "EDR"
        device_version = "2.0"
        signature_id = self._escape(event.get("rule_id", "unknown"))
        name = self._escape(event.get("name", "Detection"))
        severity = str(event.get("severity_num", 5))
        extensions = []

        ext_map = {
            "src": event.get("src_ip"),
            "dst": event.get("dst_ip"),
            "spt": event.get("src_port"),
            "dpt": event.get("dst_port"),
            "suser": event.get("user"),
            "dproc": event.get("process"),
            "fname": event.get("file"),
            "fileHash": event.get("sha256"),
            "msg": event.get("message"),
            "end": event.get("timestamp"),
            "cs1Label": "mitre_technique",
            "cs1": event.get("mitre"),
            "host": event.get("hostname"),
        }

        for k, v in ext_map.items():
            if v:
                extensions.append(f"{k}={self._escape(v)}")

        return f"{version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{' '.join(extensions)}"

    def send(self, event):
        """Envía evento al SIEM vía syslog."""
        cef = self.format_cef(event)
        try:
            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(cef.encode('utf-8'), (self.host, self.port))
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.host, self.port))
                sock.sendall(cef.encode('utf-8') + b"\n")
                sock.close()
            return True
        except Exception as e:
            print(f"[!] SIEM export error: {e}")
            return False
