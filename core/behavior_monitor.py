import psutil
import os
import time
import subprocess
from datetime import datetime

class BehaviorMonitor:
    def __init__(self):
        self.suspicious_events = []
        self.known_shells = ['bash', 'zsh', 'sh', 'dash', 'fish', 'tmux', 'screen']
        self.file_ops = ['cp', 'mv', 'rsync', 'scp', 'rm', 'mkdir', 'rmdir', 'chmod', 'chown']
        self.sudo_cmd = 'sudo'

    def scan_processes(self):
        """
        Escanea procesos activos y detecta comportamientos sospechosos.
        Retorna lista de eventos con tipo, pid, comando, etc.
        """
        current_events = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid', 'create_time']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name']
                cmdline = info['cmdline']
                ppid = info['ppid']

                # 1. Detectar shell en segundo plano (sin terminal)
                if name in self.known_shells and not self._has_terminal(proc):
                    try:
                        parent = psutil.Process(ppid)
                        # Si el padre es un demonio o servicio, puede ser legítimo
                        if parent.name() not in ['init', 'systemd', 'sshd', 'cron', 'at', 'gdm', 'lightdm']:
                            event = {
                                'type': 'SHELL_BACKGROUND',
                                'pid': pid,
                                'name': name,
                                'cmdline': ' '.join(cmdline),
                                'ppid': ppid,
                                'parent': parent.name(),
                                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                'severity': 'ALTA',
                                'desc': f"Shell '{name}' ejecutándose en segundo plano (sin terminal)"
                            }
                            current_events.append(event)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # 2. Detectar sudo sin terminal (posible escalada)
                if name == 'sudo' and not self._has_terminal(proc):
                    event = {
                        'type': 'SUDO_BACKGROUND',
                        'pid': pid,
                        'name': name,
                        'cmdline': ' '.join(cmdline),
                        'ppid': ppid,
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'severity': 'CRÍTICA',
                        'desc': f"Uso de sudo en segundo plano: {' '.join(cmdline)}"
                    }
                    current_events.append(event)

                # 3. Detectar operaciones de archivos (cp, mv, rm) sin terminal
                if name in self.file_ops and not self._has_terminal(proc):
                    # Si el proceso padre no es interactivo, es sospechoso
                    try:
                        parent = psutil.Process(ppid)
                        if parent.name() not in ['bash', 'zsh', 'sh', 'dash']:
                            event = {
                                'type': 'FILE_OPERATION',
                                'pid': pid,
                                'name': name,
                                'cmdline': ' '.join(cmdline),
                                'ppid': ppid,
                                'parent': parent.name(),
                                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                'severity': 'MEDIA',
                                'desc': f"Operación de archivo sin terminal: {' '.join(cmdline)}"
                            }
                            current_events.append(event)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return current_events

    def _has_terminal(self, proc):
        """Verifica si un proceso tiene una terminal asociada."""
        try:
            return proc.terminal() is not None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
