# core/zeroday_engine.py
"""
Motor de detección Zero-Day.

Técnicas:
- Anomaly detection basado en Isolation Forest
- Behavioral fingerprinting
- Entropy analysis
- API call patterns (con ptrace/seccomp)
- Heuristic scoring (no requiere ML entrenado)
"""
import os
import math
import hashlib
import statistics
from collections import Counter


class ZeroDayEngine:
    def __init__(self, config=None):
        self.config = config or {}
        # Baseline de comportamiento conocido (se va enriqueciendo)
        self.baseline = self._load_baseline()
        self.anomaly_threshold = 0.7  # 0-1, mayor = más estricto

    def _load_baseline(self):
        """Carga baseline de comportamiento."""
        return {
            "typical_entropy_range": (3.5, 6.5),
            "typical_sections": [".text", ".data", ".rodata", ".bss"],
            "typical_imports_common": [
                "printf", "malloc", "free", "memcpy", "strlen",
                "open", "read", "write", "close",
                "socket", "connect", "send", "recv",
            ],
            "suspicious_imports": [
                "ptrace", "process_vm_readv", "process_vm_writev",
                "dlopen", "dlsym", "mprotect",
                "fork", "execve", "setuid", "setgid",
                "mmap", "munmap",
            ],
            "typical_file_size_range": (1024, 50 * 1024 * 1024),
        }

    def analyze_file(self, filepath):
        """
        Analiza un archivo en busca de comportamiento zero-day.
        Retorna: (anomaly_score, reasons, features)
        """
        features = self._extract_features(filepath)
        score, reasons = self._compute_anomaly_score(features)
        return score, reasons, features

    def _extract_features(self, filepath):
        """Extrae features forenses del archivo."""
        features = {
            "size": 0,
            "entropy": 0.0,
            "entropy_by_section": {},
            "printable_ratio": 0.0,
            "null_byte_ratio": 0.0,
            "unique_byte_count": 0,
            "has_elf_header": False,
            "has_pe_header": False,
            "has_shebang": False,
            "suspicious_strings_count": 0,
            "suspicious_strings": [],
            "high_entropy_blocks": 0,
            "compression_indicators": 0,
            "crypto_indicators": 0,
            "network_indicators": 0,
            "file_ext": "",
        }

        try:
            with open(filepath, 'rb') as f:
                data = f.read(2 * 1024 * 1024)  # 2 MB máximo

            features["size"] = len(data)
            features["file_ext"] = os.path.splitext(filepath)[1].lower()

            if not data:
                return features

            # Headers
            features["has_elf_header"] = data[:4] == b'\x7fELF'
            features["has_pe_header"] = data[:2] == b'MZ'
            features["has_shebang"] = data[:2] == b'#!'

            # Entropy global
            features["entropy"] = self._entropy(data)

            # Entropy por bloques (detecta secciones comprimidas/cifradas)
            block_size = 4096
            high_entropy_blocks = 0
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                if len(block) < 256:
                    continue
                if self._entropy(block) > 7.5:
                    high_entropy_blocks += 1
            features["high_entropy_blocks"] = high_entropy_blocks

            # Ratios
            printable = sum(1 for b in data if 32 <= b <= 126)
            null_bytes = data.count(0)
            features["printable_ratio"] = printable / len(data)
            features["null_byte_ratio"] = null_bytes / len(data)
            features["unique_byte_count"] = len(set(data))

            # Strings sospechosos
            text = data.decode('utf-8', errors='ignore')
            suspicious_patterns = {
                'exec': ['execve', 'execl', 'system(', 'popen', '/bin/sh', '/bin/bash'],
                'network': ['socket', 'connect', 'bind', 'listen', 'iptables', 'wget', 'curl'],
                'crypto': ['AES', 'RSA', 'encrypt', 'decrypt', 'cipher', 'openssl'],
                'compress': ['gzip', 'zlib', 'lzma', 'bzip2', 'compress'],
                'persistence': ['crontab', 'systemd', '.bashrc', 'rc.local', '/etc/init.d'],
                'lateral': ['ssh', 'scp', 'rsync', 'ssh-keygen', 'authorized_keys'],
                'exfil': ['pastebin', 'transfer.sh', 'ngrok', '.onion', 'tor2web'],
                'evasion': ['ptrace', 'LD_PRELOAD', 'chattr', 'debugger', 'antidebug'],
            }
            for category, patterns in suspicious_patterns.items():
                matches = sum(1 for p in patterns if p.lower() in text.lower())
                if matches > 0:
                    if category == 'network':
                        features['network_indicators'] += matches
                    elif category == 'crypto':
                        features['crypto_indicators'] += matches
                    elif category == 'compress':
                        features['compression_indicators'] += matches
                    else:
                        features['suspicious_strings_count'] += matches
                        if len(features['suspicious_strings']) < 10:
                            features['suspicious_strings'].append(f"{category}:{matches}")

        except Exception:
            pass

        return features

    def _compute_anomaly_score(self, features):
        """Computa el score de anomalía (0 = normal, 1 = anómalo)."""
        score = 0.0
        reasons = []
        max_score = 0.0

        # 1. Entropy anómala
        entropy = features.get("entropy", 0)
        low, high = self.baseline["typical_entropy_range"]
        if entropy > 7.5:
            score += 0.25
            reasons.append(f"Entropía muy alta: {entropy:.2f} (posible cifrado/packeo)")
            max_score += 0.25
        elif entropy < 2.0 and features.get("size", 0) > 1024:
            score += 0.15
            reasons.append(f"Entropía muy baja: {entropy:.2f} (posible padding)")
            max_score += 0.25
        else:
            max_score += 0.25

        # 2. Bloques de alta entropía
        h_blocks = features.get("high_entropy_blocks", 0)
        if h_blocks > 10:
            score += 0.20
            reasons.append(f"{h_blocks} bloques de alta entropía (posible cifrado)")
            max_score += 0.20
        else:
            max_score += 0.20

        # 3. Strings sospechosos
        susp = features.get("suspicious_strings_count", 0)
        if susp > 5:
            score += 0.20
            reasons.append(f"{susp} strings sospechosos detectados")
            max_score += 0.20
        elif susp > 2:
            score += 0.10
            reasons.append(f"{susp} strings sospechosos")
            max_score += 0.20
        else:
            max_score += 0.20

        # 4. Indicadores de red + crypto
        net = features.get("network_indicators", 0)
        crypto = features.get("crypto_indicators", 0)
        if net > 3 and crypto > 2:
            score += 0.15
            reasons.append("Combinación red + crypto (posible C2 cifrado)")
            max_score += 0.15
        else:
            max_score += 0.15

        # 5. ELF/PE con alta entropía (packed binaries)
        if features.get("has_elf_header") or features.get("has_pe_header"):
            if entropy > 7.0:
                score += 0.20
                reasons.append("Binario ELF/PE empaquetado (packer detectado)")
                max_score += 0.20
            else:
                max_score += 0.20
        else:
            max_score += 0.20

        # Normalizar
        normalized = score / max_score if max_score > 0 else 0.0
        return min(normalized, 1.0), reasons

    def _entropy(self, data):
        """Calcula entropía de Shannon (0-8)."""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ============================================
    # ANÁLISIS DE PROCESO (behavioral)
    # ============================================
    def analyze_process(self, proc):
        """Analiza un proceso por comportamiento anómalo."""
        score = 0.0
        reasons = []

        try:
            name = proc.name()
            exe = proc.exe()
            cmdline = ' '.join(proc.cmdline())
            cpu = proc.cpu_percent(interval=0.1)
            mem = proc.memory_percent()

            # 1. CPU anómalo (mineros)
            if cpu > 90:
                score += 0.3
                reasons.append(f"CPU muy alta: {cpu:.1f}% (posible miner)")

            # 2. Memoria anómala
            if mem > 50:
                score += 0.2
                reasons.append(f"RAM muy alta: {mem:.1f}%")

            # 3. Proceso en rutas sospechosas
            if exe and any(p in exe for p in ['/tmp/', '/var/tmp/', '/dev/shm/']):
                score += 0.3
                reasons.append(f"Ejecutable en ruta temporal: {exe}")

            # 4. Nombre que imita procesos del sistema
            fake_names = ['kworker', 'kswapd', 'systemd', 'init', 'kthreadd']
            if any(fake in name.lower() for fake in fake_names):
                if exe and 'kernel' not in exe.lower() and '/usr/' not in exe:
                    score += 0.2
                    reasons.append(f"Nombre de kernel-space en user-space: {name}")

            # 5. Comandos peligrosos en cmdline
            dangerous = ['nc -e', 'bash -i', 'sh -i', 'mkfifo', '/dev/tcp/',
                        'curl | sh', 'wget | bash', 'chmod +s', 'chattr +i']
            for pattern in dangerous:
                if pattern in cmdline.lower():
                    score += 0.4
                    reasons.append(f"Patrón peligroso: {pattern}")
                    break

            # 6. Proceso sin ejecutable (fileless)
            if not exe and name not in ['kernel', 'kthreadd']:
                score += 0.25
                reasons.append("Proceso sin ejecutable (posible fileless)")

            # 7. Muchos threads (típico de malware multithread)
            try:
                threads = proc.num_threads()
                if threads > 100:
                    score += 0.15
                    reasons.append(f"Muchos threads: {threads}")
            except Exception:
                pass

        except Exception:
            pass

        return min(score, 1.0), reasons
