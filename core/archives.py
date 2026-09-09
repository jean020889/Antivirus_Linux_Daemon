import os, shutil, subprocess
from .scanner import ScannerEngine
import magic

class ArchiveScanner:
    def __init__(self, engine: ScannerEngine, temp_dir="/tmp/av_extract"):
        self.engine = engine
        self.temp_dir = temp_dir
        os.makedirs(temp_dir, exist_ok=True)

    def extract_and_scan(self, filepath):
        mime = magic.from_file(filepath, mime=True)
        extract_path = os.path.join(self.temp_dir, os.path.basename(filepath) + "_ext")
        os.makedirs(extract_path, exist_ok=True)
        try:
            if 'zip' in mime:
                shutil.unpack_archive(filepath, extract_path, 'zip')
            elif 'gzip' in mime or 'x-tar' in mime:
                shutil.unpack_archive(filepath, extract_path, 'tar')
            elif 'rar' in mime:
                subprocess.run(['unrar', 'x', filepath, extract_path], capture_output=True)
            elif '7z' in mime:
                subprocess.run(['7z', 'x', filepath, f'-o{extract_path}'], capture_output=True)
            else:
                return False, "Formato no soportado"
            for root, _, files in os.walk(extract_path):
                for f in files:
                    full = os.path.join(root, f)
                    res, mot = self.engine.scan_file(full)
                    if res:
                        self.engine.quarantine(filepath, f"Contenido comprimido malicioso: {mot}")
                        return True, f"Malware dentro del comprimido: {mot}"
            return False, "Limpio"
        except Exception as e:
            return False, f"Error al extraer: {e}"
        finally:
            shutil.rmtree(extract_path, ignore_errors=True)
