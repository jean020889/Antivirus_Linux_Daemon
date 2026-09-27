# core/heuristic.py
"""
Heurística avanzada con mapeo MITRE ATT&CK.

Detecta:
- Binarios ELF en rutas sospechosas (T1036)
- Scripts con ofuscación (T1027)
- Setuid/setgid no estándar (T1548)
- Persistencia en cron/systemd (T1053)
- Reverse shells (T1059)
- Mineros de criptomonedas (T1496)
- Rootkits (T1014)
"""

import os
import re
import stat


class HeuristicEngine:
    def __init__(self, config):
        self.config = config
        self.suspicious_paths = [
            '/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/',
            '/var/run/', '/dev/', '/proc/'
        ]
        self.system_paths = ['/usr/', '/bin/', '/sbin/', '/lib/', '/lib64/']

        # Patrones de scripts maliciosos
        self.script_patterns = [
            (r'base64\s*-d\s*\|', 'Base64 decode pipe', 'T1027', 'high'),
            (r'curl\s+[^\|]+\|\s*(bash|sh)', 'Curl pipe to shell', 'T1059', 'critical'),
            (r'wget\s+[^\|]+\|\s*(bash|sh)', 'Wget pipe to shell', 'T1059', 'critical'),
            (r'bash\s+-i\s+>&\s+/dev/tcp/', 'Bash reverse shell', 'T1059', 'critical'),
            (r'nc\s+-e\s+/bin/(sh|bash)', 'Netcat reverse shell', 'T1059', 'critical'),
            (r'python[23]?\s+-c\s+[\'"]import\s+socket', 'Python reverse shell', 'T1059', 'critical'),
            (r'perl\s+-e\s+[\'"]use\s+Socket', 'Perl reverse shell', 'T1059', 'critical'),
            (r'eval\s*\(\s*base64_decode', 'PHP eval base64', 'T1027', 'high'),
            (r'rm\s+-rf\s+/\s*;', 'RM root deletion', 'T1485', 'critical'),
            (r'chmod\s+[47][0-7]{3}\s', 'Chmod setuid', 'T1548', 'high'),
            (r'stratum\+tcp://', 'Crypto miner stratum', 'T1496', 'high'),
            (r'xmrig|minerd|cpuminer|kworker', 'Crypto miner binary', 'T1496', 'high'),
        ]

        # Persistencia
        self.persistence_paths = [
            '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/',
            '/var/spool/cron/', '/etc/systemd/system/',
            '/etc/rc.local', '~/.bashrc', '~/.profile', '~/.bash_profile',
            '/etc/profile.d/'
        ]

        # Binarios ELF conocidos como sospechosos en ciertas rutas
        self.lolbins = [
            'curl', 'wget', 'nc', 'netcat', 'socat', 'ncat',
            'python', 'perl', 'ruby', 'php', 'node',
            'bash', 'sh', 'dash', 'zsh',
            'dd', 'tar', 'base64', 'xxd', 'openssl',
            'at', 'batch', 'systemd-run'
        ]

    def scan_file(self, filepath):
        """Retorna lista de detecciones."""
        detections = []

        # 1. Permisos SETUID/SETGID fuera del sistema
        try:
            st = os.stat(filepath)
            mode = st.st_mode
            if mode & stat.S_ISUID:
                if not any(filepath.startswith(p) for p in self.system_paths):
                    detections.append({
                        "engine": "heuristic",
                        "threat": "SETUID en ruta no estándar",
                        "severity": "high",
                        "confidence": 80,
                        "mitre": "T1548"
                    })
            if mode & stat.S_ISGID:
                if not any(filepath.startswith(p) for p in self.system_paths):
                    detections.append({
                        "engine": "heuristic",
                        "threat": "SETGID en ruta no estándar",
                        "severity": "medium",
                        "confidence": 70,
                        "mitre": "T1548"
                    })
        except OSError:
            pass

        # 2. Archivos en rutas sospechosas
        for path in self.suspicious_paths:
            if path in filepath:
                # Verificar si es ELF
                try:
                    with open(filepath, 'rb') as f:
                        header = f.read(4)
                        if header == b'\x7fELF':
                            detections.append({
                                "engine": "heuristic",
                                "threat": f"Binario ELF en {path}",
                                "severity": "medium",
                                "confidence": 60,
                                "mitre": "T1036"
                            })
                            break
                except (IOError, PermissionError):
                    pass

        # 3. Scripts con patrones sospechosos
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ('.sh', '.py', '.pl', '.php', '.js', '.bash'):
            try:
                with open(filepath, 'rb') as f:
                    content = f.read(131072)  # 128 KB
                    try:
                        text = content.decode('utf-8', errors='ignore')
                    except Exception:
                        return detections

                for pattern, desc, mitre, severity in self.script_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        detections.append({
                            "engine": "heuristic",
                            "threat": f"Script sospechoso: {desc}",
                            "severity": severity,
                            "confidence": 75,
                            "mitre": mitre
                        })
                        break  # Un solo match por archivo
            except (IOError, PermissionError):
                pass

        # 4. Archivos de persistencia
        for p in self.persistence_paths:
            if p in filepath:
                detections.append({
                    "engine": "heuristic",
                    "threat": f"Modificación en ruta de persistencia: {p}",
                    "severity": "low",
                    "confidence": 40,
                    "mitre": "T1053"
                })
                break

        return detections

    def scan_process(self, proc):
        """Escanea un proceso (psutil.Process)."""
        detections = []
        try:
            name = proc.name()
            exe = proc.exe()
            cmdline = ' '.join(proc.cmdline())

            # LOLBins con reverse shell pattern
            if name in self.lolbins and any(p in cmdline for p in ['-e', '-c', '>&']):
                detections.append({
                    "engine": "heuristic",
                    "threat": f"LOLBin sospechoso: {name}",
                    "severity": "medium",
                    "confidence": 60,
                    "mitre": "T1059"
                })

            # Procesos en /tmp
            if exe and '/tmp/' in exe:
                detections.append({
                    "engine": "heuristic",
                    "threat": f"Proceso ejecutándose desde /tmp: {exe}",
                    "severity": "high",
                    "confidence": 80,
                    "mitre": "T1036"
                })
        except Exception:
            pass

        return detections
