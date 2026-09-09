import psutil
import socket
from datetime import datetime

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 1337, 31337, 9001, 12345, 54321,
    44445, 50000, 50050, 60000
}

class NetworkMonitor:
    def __init__(self):
        self.suspicious_connections = []

    def get_connections(self):
        try:
            return psutil.net_connections(kind='inet')
        except Exception as e:
            print(f"[NetworkMonitor] Error: {e}")
            return []

    def is_suspicious(self, conn):
        if conn.raddr:
            port = conn.raddr.port
            if port in SUSPICIOUS_PORTS:
                return True, f"Puerto sospechoso: {port}"
        return False, None

    def scan(self):
        self.suspicious_connections = []
        connections = self.get_connections()
        for conn in connections:
            if conn.status not in ['ESTABLISHED', 'LISTEN']:
                continue
            es_sospechosa, motivo = self.is_suspicious(conn)
            if es_sospechosa:
                try:
                    pid = conn.pid
                    proceso = psutil.Process(pid) if pid else None
                    nombre_proceso = proceso.name() if proceso else "Desconocido"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    nombre_proceso = "Desconocido (sin permiso)"
                self.suspicious_connections.append({
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'pid': conn.pid,
                    'proceso': nombre_proceso,
                    'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                    'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'status': conn.status,
                    'motivo': motivo
                })
        return self.suspicious_connections

    def scan_behavior(self):
        """
        Escanea conexiones y procesos para detectar comportamientos sospechosos.
        """
        import psutil
        suspicious = []
        # Obtener conexiones
        connections = self.get_connections()
        for conn in connections:
            if conn.status not in ['ESTABLISHED', 'LISTEN']:
                continue
            # Asociar proceso
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                if proc:
                    cmdline = proc.cmdline()
                    # Detectar conexiones desde procesos con comportamientos sospechosos
                    if self._is_suspicious_process(proc):
                        suspicious.append({
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'pid': conn.pid,
                            'proceso': proc.name(),
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                            'status': conn.status,
                            'motivo': f"Comportamiento sospechoso: {cmdline}",
                            'ip': conn.raddr.ip if conn.raddr else None
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return suspicious

    def _is_suspicious_process(self, proc):
        """
        Detecta si un proceso tiene comportamiento sospechoso (shell sin terminal, sudo, etc.)
        """
        try:
            # Si el proceso tiene una terminal, es interactivo, no sospechoso
            if proc.terminal():
                return False
            name = proc.name()
            cmdline = ' '.join(proc.cmdline())
            # Shell sin terminal
            if name in ['bash', 'zsh', 'sh', 'dash', 'fish']:
                return True
            # sudo sin terminal
            if name == 'sudo' or 'sudo' in cmdline:
                return True
            # Comandos de archivos en segundo plano
            if any(op in name for op in ['cp', 'mv', 'rm', 'rsync', 'scp']):
                return True
        except:
            pass
        return False

    def scan_behavior(self):
        """
        Escanea conexiones y procesos para detectar comportamientos sospechosos.
        Retorna eventos de red con información de proceso.
        """
        import psutil
        suspicious = []
        connections = self.get_connections()
        for conn in connections:
            if conn.status not in ['ESTABLISHED', 'LISTEN']:
                continue
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    if self._is_suspicious_process(proc):
                        suspicious.append({
                            'type': 'NETWORK_BEHAVIOR',
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'pid': conn.pid,
                            'proceso': proc.name(),
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                            'status': conn.status,
                            'motivo': f"Comportamiento sospechoso: {' '.join(proc.cmdline())}",
                            'ip': conn.raddr.ip if conn.raddr else None,
                            'severity': 'ALTA',
                            'desc': f"Proceso {proc.name()} (PID {conn.pid}) con conexión sospechosa a {conn.raddr.ip if conn.raddr else 'N/A'}"
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        return suspicious

    def _is_suspicious_process(self, proc):
        """
        Detecta si un proceso tiene comportamiento sospechoso:
        - Shell sin terminal
        - Uso de sudo sin terminal
        - Operaciones de archivos sin terminal
        """
        try:
            # Si tiene terminal, no es sospechoso
            if proc.terminal():
                return False

            name = proc.name()
            # Shells sin terminal
            if name in ['bash', 'zsh', 'sh', 'dash', 'fish']:
                return True

            # Sudo sin terminal
            if name == 'sudo':
                return True

            # Operaciones de archivos sin terminal
            if name in ['cp', 'mv', 'rsync', 'scp', 'rm', 'mkdir', 'rmdir', 'chmod', 'chown']:
                return True

            return False
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
