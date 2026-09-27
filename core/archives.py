# core/archives.py
import os
import shutil
import subprocess

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

class ArchiveScanner:
    def __init__(self, engine, temp_dir="/tmp/av_extract"):
        self.engine = engine
        self.temp_dir = temp_dir
        os.makedirs(temp_dir, exist_ok=True)

    def extract_and_scan(self, filepath):
        if not HAS_MAGIC:
            return False, "python-magic no instalado"
        try:
            mime = magic.from_file(filepath, mime=True)
        except Exception:
            return False, "No se pudo detectar el tipo"

        extract_path = os.path.join(self.temp_dir, os.path.basename(filepath) + "_ext")
        os.makedirs(extract_path, exist_ok=True)

        try:
            if 'zip' in mime:
                shutil.unpack_archive(filepath, extract_path, 'zip')
            elif 'gzip' in mime or 'x-tar' in mime:
                shutil.unpack_archive(filepath, extract_path, 'tar')
            elif 'rar' in mime:
                subprocess.run(['unrar', 'x', filepath, extract_path],
                               capture_output=True)
            elif '7z' in mime or 'x-7z' in mime:
                subprocess.run(['7z', 'x', filepath, f'-o{extract_path}'],
                               capture_output=True)
            else:
                return False, "Formato no soportado"

            for root, _, files in os.walk(extract_path):
                for f in files:
                    full = os.path.join(root, f)
                    res, mot = self.engine.scan_file(full)
                    if res:
                        self.engine.quarantine(filepath,
                            f"Contenido comprimido malicioso: {mot}")
                        return True, f"Malware dentro del comprimido: {mot}"
            return False, "Limpio"
        except Exception as e:
            return False, f"Error al extraer: {e}"
        finally:
            shutil.rmtree(extract_path, ignore_errors=True)
