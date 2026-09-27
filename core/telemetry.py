# core/telemetry.py
"""
Captura de telemetría local.

Captura eventos de:
- Procesos (psutil)
- Archivos (polling)
- Red (/proc/net)
- Usuarios (who, w)

NO usa eBPF (requiere root + kernel module).
Usa usuariospace (psutil + /proc).
"""

import os
import time
import psutil
from datetime import datetime


class TelemetryCollector:
    def __init__(self, config):
        self.config = config
        self.seen_pids = set()
        self.seen_connections = set()

    def collect_processes(self):
        """Captura procesos actuales."""
        events = []
        now = time.time()

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid', 'create_time']):
            try:
                pid = proc.info['pid']
                if pid in self.seen_pids:
                    continue
                self.seen_pids.add(pid)

                events.append({
                    "event_type": "process_start",
                    "timestamp": datetime.now().isoformat(),
                    "process_pid": pid,
                    "process_name": proc.info['name'],
                    "process_exe": proc.info.get('exe'),
                    "process_cmdline": ' '.join(proc.info.get('cmdline') or []),
                    "process_user": proc.info.get('username'),
                    "parent_pid": proc.info.get('ppid'),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Limitar tamaño de seen_pids (evitar memory leak)
        if len(self.seen_pids) > 100000:
            self.seen_pids = set(list(self.seen_pids)[-50000:])

        return events

    def collect_connections(self):
        """Captura conexiones de red establecidas."""
        events = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status != 'ESTABLISHED':
                    continue
                key = (conn.laddr, conn.raddr, conn.pid)
                if key in self.seen_connections:
                    continue
                self.seen_connections.add(key)

                process_name = None
                if conn.pid:
                    try:
                        process_name = psutil.Process(conn.pid).name()
                    except Exception:
                        pass

                events.append({
                    "event_type": "network_connection",
                    "timestamp": datetime.now().isoformat(),
                    "network_src_ip": conn.laddr.ip if conn.laddr else None,
                    "network_src_port": conn.laddr.port if conn.laddr else None,
                    "network_dst_ip": conn.raddr.ip if conn.raddr else None,
                    "network_dst_port": conn.raddr.port if conn.raddr else None,
                    "process_pid": conn.pid,
                    "process_name": process_name,
                })
        except (psutil.AccessDenied, PermissionError):
            pass

        if len(self.seen_connections) > 10000:
            self.seen_connections = set(list(self.seen_connections)[-5000:])

        return events

    def collect_users(self):
        """Captura usuarios logueados."""
        events = []
        for user in psutil.users():
            events.append({
                "event_type": "user_login",
                "timestamp": datetime.fromtimestamp(user.started).isoformat(),
                "process_user": user.name,
                "network_src_ip": user.host,
            })
        return events
