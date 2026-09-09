import os
import yara
from pathlib import Path

class YaraScanner:
    def __init__(self, rules_path="yara_rules/"):
        self.rules_path = Path(rules_path)
        self.compiled_rules = None
        self.load_rules()

    def load_rules(self):
        if not self.rules_path.exists():
            print(f"[YARA] Carpeta de reglas no encontrada: {self.rules_path}")
            return
        rule_files = {}
        for rule_file in self.rules_path.glob("*.yar"):
            rule_files[rule_file.stem] = str(rule_file)
        if not rule_files:
            print("[YARA] No se encontraron archivos .yar")
            return
        try:
            self.compiled_rules = yara.compile(filepaths=rule_files)
            print(f"[YARA] Reglas compiladas desde {len(rule_files)} archivos.")
        except Exception as e:
            print(f"[YARA] Error al compilar: {e}")

    def scan_file(self, filepath):
        if not self.compiled_rules:
            return False, "Reglas YARA no cargadas."
        if not os.path.exists(filepath):
            return False, "Archivo no encontrado."
        try:
            matches = self.compiled_rules.match(filepath)
            if matches:
                return True, f"YARA: {matches[0].rule}"
            return False, "Sin coincidencias YARA"
        except Exception as e:
            return False, f"Error YARA: {e}"

    def scan_data(self, data):
        if not self.compiled_rules:
            return False, "Reglas YARA no cargadas."
        try:
            matches = self.compiled_rules.match(data=data)
            if matches:
                return True, f"YARA (memoria): {matches[0].rule}"
            return False, "Sin coincidencias YARA"
        except Exception as e:
            return False, f"Error YARA: {e}"
