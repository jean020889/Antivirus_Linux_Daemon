
# core/evasion_detector.py
"""
Detector de evasión v3.0 - FIX definitivo de módulos built-in.
"""
import os
import re
import glob
import subprocess


class EvasionDetector:
    def __init__(self, config=None):
        self.config = config or {}
        self.known_rootkits = [
            'diamorphine', 'reptile', 'azazel', 'jynx2', 'bdvl',
            'libprocesshider', 'vlany', 'umbreon', 'beurk',
        ]
        # Precalcular índice de módulos conocidos del kernel
        self._builtin_modules = None
        self._ko_modules = None

    def _load_module_index(self):
        """Carga índice de TODOS los módulos conocidos (built-in + .ko)."""
        if self._builtin_modules is not None:
            return

        self._builtin_modules = set()
        self._ko_modules = set()

        kernel_release = os.uname().release
        modules_dir = f'/lib/modules/{kernel_release}'

        # 1. Cargar built-in (con conversión de guiones)
        builtin_files = glob.glob('/lib/modules/*/modules.builtin')
        for bf in builtin_files:
            try:
                with open(bf) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        # "kernel/sound/core/snd-seq-dummy.ko" → "snd_seq_dummy"
                        basename = os.path.basename(line)
                        # Quitar extensión
                        name = basename.split('.')[0]
                        # Convertir guiones a guiones bajos
                        normalized = name.replace('-', '_')
                        self._builtin_modules.add(normalized)
            except Exception:
                pass

        # 2. Cargar .ko files (también normalizando)
        for ext in ['ko', 'ko.xz', 'ko.zst', 'ko.gz', 'ko.bz2']:
            for path in glob.glob(f'/lib/modules/**/*.{ext}', recursive=True):
                basename = os.path.basename(path)
                name = basename.split('.')[0]
                normalized = name.replace('-', '_')
                self._ko_modules.add(normalized)

    def scan_all(self):
        findings = []
        findings.extend(self.detect_hidden_processes())
        findings.extend(self.detect_hidden_kernel_modules())
        findings.extend(self.detect_ld_preload())
        findings.extend(self.detect_ptrace())
        findings.extend(self.detect_kernel_taint())
        findings.extend(self.detect_modified_proc())
        return findings

    def detect_hidden_processes(self):
        findings = []
        try:
            proc_pids = {int(p) for p in os.listdir('/proc') if p.isdigit()}
            ps_out = subprocess.run(['ps', '-eo', 'pid', '--no-headers'],
                                   capture_output=True, text=True, timeout=10).stdout
            ps_pids = {int(l.strip()) for l in ps_out.splitlines() if l.strip().isdigit()}
            for pid in proc_pids - ps_pids:
                try:
                    with open(f'/proc/{pid}/cmdline', 'rb') as f:
                        cmdline = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore')
                    findings.append({
                        "type": "hidden_process", "severity": "critical", "pid": pid,
                        "cmdline": cmdline[:200],
                        "description": f"Proceso oculto (PID {pid})",
                        "mitre": "T1014",
                    })
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    def detect_hidden_kernel_modules(self):
        """Detecta módulos sospechosos con verificación de built-in CORRECTA."""
        findings = []

        # Cargar índice de módulos conocidos
        self._load_module_index()

        # Módulos virtuales (creados dinámicamente)
        virtual_modules = {
            'binfmt_misc', 'configfs', 'debugfs', 'dummy',
            'fuse', 'loop', 'overlay', 'pppoe', 'pppox', 'rfkill',
            'tls', 'sunrpc', 'veth', 'wireguard', 'bonding',
            'garp', 'mrp', 'stp', 'llc', '8021q', 'br_netfilter',
            'nf_nat', 'nf_conntrack',
        }

        try:
            with open('/proc/modules') as f:
                modules_text = f.read()

            # 1. Rootkits conocidos
            for rootkit in self.known_rootkits:
                if rootkit.lower() in modules_text.lower():
                    findings.append({
                        "type": "known_rootkit", "severity": "critical",
                        "name": rootkit,
                        "description": f"ROOTKIT CONOCIDO cargado: {rootkit}",
                        "mitre": "T1014",
                    })

            # 2. Módulos sin archivo
            for line in modules_text.splitlines():
                parts = line.split()
                if not parts:
                    continue
                module = parts[0]

                if module in virtual_modules:
                    continue

                # Verificar en built-in Y .ko (con normalización)
                if module in self._builtin_modules:
                    continue
                if module in self._ko_modules:
                    continue

                # Si no está en ninguno, es sospechoso
                findings.append({
                    "type": "unsigned_module", "severity": "medium",
                    "name": module,
                    "description": f"Módulo desconocido: {module}",
                    "mitre": "T1014",
                })
        except Exception:
            pass

        return findings

    def detect_ld_preload(self):
        findings = []
        if os.path.exists('/etc/ld.so.preload'):
            try:
                with open('/etc/ld.so.preload') as f:
                    content = f.read().strip()
                if content:
                    findings.append({
                        "type": "ld_preload_global", "severity": "high",
                        "content": content,
                        "description": f"/etc/ld.so.preload no vacío",
                        "mitre": "T1574.006",
                    })
            except Exception:
                pass
        return findings

    def detect_ptrace(self):
        findings = []
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    status_file = f'/proc/{pid_dir}/status'
                    if not os.path.exists(status_file):
                        continue
                    with open(status_file) as f:
                        status = f.read()
                    m = re.search(r'TracerPid:\s*(\d+)', status)
                    if m and int(m.group(1)) != 0:
                        findings.append({
                            "type": "ptrace_attached", "severity": "high",
                            "pid": int(pid_dir),
                            "description": f"PID {pid_dir} siendo traceado",
                            "mitre": "T1055",
                        })
                except Exception:
                    continue
        except Exception:
            pass
        return findings

    def detect_kernel_taint(self):
        findings = []
        try:
            with open('/proc/sys/kernel/tainted') as f:
                taint = int(f.read().strip())
            if taint & 0x2000:
                findings.append({
                    "type": "kernel_tainted_unsigned", "severity": "high",
                    "taint_value": taint,
                    "description": "Kernel con módulo sin firma",
                    "mitre": "T1014",
                })
        except Exception:
            pass
        return findings

    def detect_modified_proc(self):
        findings = []
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    exe_link = f'/proc/{pid_dir}/exe'
                    if os.path.islink(exe_link):
                        target = os.readlink(exe_link)
                        if '(deleted)' in target:
                            try:
                                comm = open(f'/proc/{pid_dir}/comm').read().strip()
                            except Exception:
                                comm = '?'
                            findings.append({
                                "type": "deleted_executable", "severity": "high",
                                "pid": int(pid_dir),
                                "description": f"{comm} ejecuta binario eliminado",
                                "mitre": "T1070.004",
                            })
                except Exception:
                    continue
        except Exception:
            pass
        return findings

    def get_score(self):
        findings = self.scan_all()
        score = 100
        for f in findings:
            sev = f.get('severity', 'medium')
            impact = {'critical': 20, 'high': 10, 'medium': 5, 'low': 2}.get(sev, 5)
            score -= impact
        return max(0, score), findings
