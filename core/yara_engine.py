# core/yara_engine.py
import yara
import os
import hashlib
import subprocess
from pathlib import Path

class YaraEngine:
    def __init__(self, rules_dir="./yara_rules", cache_dir="./cti_cache"):
        self.rules_dir = rules_dir
        self.cache_dir = cache_dir
        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)
        self.rules = None
        self.rules_hash = None
        self._load_rules()

    def _load_rules(self):
        rule_files = {}
        for rule_path in Path(self.rules_dir).rglob("*.yar*"):
            key = hashlib.md5(str(rule_path).encode()).hexdigest()[:8]
            rule_files[key] = str(rule_path)

        if not rule_files:
            print("[!] No se encontraron reglas YARA")
            return

        try:
            self.rules = yara.compile(filepaths=rule_files)
            self.rules_hash = hashlib.sha256(
                str(sorted(rule_files.values())).encode()
            ).hexdigest()[:16]
            print(f"[+] {len(rule_files)} reglas YARA compiladas")
        except yara.SyntaxError as e:
            print(f"[!] Error compilando YARA: {e}")

    def update_rules(self):
        repos = [
            ("https://github.com/Neo23x0/signature-base.git", "signature-base"),
            ("https://github.com/Yara-Rules/rules.git", "yara-rules"),
        ]
        for repo_url, name in repos:
            target = os.path.join(self.rules_dir, name)
            if not os.path.exists(target):
                subprocess.run(["git", "clone", "--depth=1", repo_url, target])
            else:
                subprocess.run(["git", "-C", target, "pull"])
        self._load_rules()

    def scan_file(self, filepath):
        if not self.rules:
            return False, "Sin reglas YARA"
        try:
            matches = self.rules.match(filepath, timeout=30)
            if matches:
                reglas = ", ".join([m.rule for m in matches[:3]])
                return True, f"YARA: {reglas}"
        except yara.TimeoutError:
            return False, "YARA timeout"
        except Exception:
            pass
        return False, "Limpio"

    def scan_bytes(self, data):
        if not self.rules:
            return False, "Sin reglas YARA"
        try:
            matches = self.rules.match(data=data, timeout=30)
            if matches:
                reglas = ", ".join([m.rule for m in matches[:3]])
                return True, f"YARA-MEM: {reglas}"
        except Exception:
            pass
        return False, "Limpio"
