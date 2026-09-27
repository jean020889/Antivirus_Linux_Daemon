# core/sigma_rules_loader.py
"""Descarga reglas Sigma comunitarias desde GitHub."""
import os
import subprocess


class SigmaRulesLoader:
    def __init__(self, rules_dir="/opt/antivirus-pro/sigma_rules"):
        self.rules_dir = rules_dir
        os.makedirs(rules_dir, exist_ok=True)

    def update(self):
        """Descarga/actualiza reglas Sigma."""
        repos = [
            ("https://github.com/SigmaHQ/sigma.git", "sigma"),
        ]
        for url, name in repos:
            target = os.path.join(self.rules_dir, name)
            if os.path.exists(target):
                print(f"[+] Actualizando {name}...")
                subprocess.run(["git", "-C", target, "pull"], capture_output=True)
            else:
                print(f"[+] Clonando {name}...")
                subprocess.run(["git", "clone", "--depth=1", url, target], capture_output=True)

        # Copiar solo las reglas de Linux
        linux_rules_src = os.path.join(self.rules_dir, "sigma", "rules", "linux")
        linux_rules_dst = os.path.join(self.rules_dir, "linux")
        if os.path.exists(linux_rules_src):
            import shutil
            if os.path.exists(linux_rules_dst):
                shutil.rmtree(linux_rules_dst)
            shutil.copytree(linux_rules_src, linux_rules_dst)
            count = sum(1 for _, _, files in os.walk(linux_rules_dst) for f in files if f.endswith(('.yml', '.yaml')))
            print(f"[+] {count} reglas Sigma de Linux copiadas")
        else:
            print("[!] No se encontraron reglas de Linux")

    def count_rules(self):
        count = 0
        for root, _, files in os.walk(self.rules_dir):
            for f in files:
                if f.endswith(('.yml', '.yaml')):
                    count += 1
        return count
