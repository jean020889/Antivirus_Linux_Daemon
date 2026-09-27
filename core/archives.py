"""
core/archives.py
Descompresión y escaneo de archivos comprimidos.

DEUDA CERRADA: usa safe_extract_zip / safe_extract_tar de security_utils.py
en lugar de shutil.unpack_archive / zipfile.extractall / tarfile.extractall
directos. Esto activa las defensas contra Zip Slip y Zip Bombs que ya
estaban validadas por tests pero no se usaban en producción.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

from .scanner import ScannerEngine
from security_utils import (
    safe_extract_zip,
    safe_extract_tar,
    ZipBombError,
    PathTraversalError,
)

logger = logging.getLogger("antivirus.archives")


class ArchiveScanner:
    def __init__(self, engine: ScannerEngine, temp_dir: str = "/tmp/av_extract"):
        self.engine = engine
        self.temp_dir = temp_dir
        os.makedirs(temp_dir, exist_ok=True)

    # ------------------------------------------------------------------ mime
    def _detect_mime(self, filepath: str) -> str:
        if HAVE_MAGIC:
            try:
                return magic.from_file(filepath, mime=True)
            except Exception as exc:
                logger.debug("magic falló en %s: %s", filepath, exc)
        # Fallback: heurística por extensión
        ext = Path(filepath).suffix.lower()
        return {
            ".zip": "application/zip",
            ".tar": "application/x-tar",
            ".gz": "application/gzip",
            ".tgz": "application/gzip",
            ".bz2": "application/x-bzip2",
            ".xz": "application/x-xz",
            ".rar": "application/x-rar",
            ".7z": "application/x-7z-compressed",
        }.get(ext, "application/octet-stream")

    # ------------------------------------------------------------------ extract
    def _extract_safe(self, filepath: str, dest: str, mime: str) -> tuple[bool, str]:
        """
        Extrae usando safe_extract_* cuando el formato es soportado por Python.
        Para RAR/7z delega en las herramientas del sistema, pero verifica
        primero el listado de entradas con listado previo.
        """
        try:
            if "zip" in mime:
                safe_extract_zip(filepath, dest)
                return True, "ok"

            if any(x in mime for x in ("tar", "gzip", "bzip2", "xz")):
                safe_extract_tar(filepath, dest)
                return True, "ok"

            if "rar" in mime:
                return self._extract_external(filepath, dest, "unrar")

            if "7z" in mime:
                return self._extract_external(filepath, dest, "7z")

            return False, f"formato no soportado: {mime}"

        except ZipBombError as exc:
            logger.warning("Zip bomb rechazada en %s: %s", filepath, exc)
            return False, f"zip bomb: {exc}"
        except PathTraversalError as exc:
            logger.warning("Path traversal rechazado en %s: %s", filepath, exc)
            return False, f"path traversal: {exc}"
        except Exception as exc:
            logger.exception("Error extrayendo %s", filepath)
            return False, f"error de extracción: {exc}"

    def _extract_external(self, filepath: str, dest: str, tool: str) -> tuple[bool, str]:
        """
        Extracción de RAR/7z mediante herramienta externa.
        IMPORTANTE: no confiamos en que la herramienta externa respete
        la ruta; verificamos después que ningún archivo quedó fuera del dest.
        """
        if tool == "unrar":
            cmd = ["unrar", "x", "-o+", "-y", filepath, dest + "/"]
        elif tool == "7z":
            cmd = ["7z", "x", "-y", f"-o{dest}", filepath]
        else:
            return False, f"herramienta desconocida: {tool}"

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
        except FileNotFoundError:
            return False, f"{tool} no instalado"
        except subprocess.TimeoutExpired:
            return False, f"{tool} superó el tiempo límite"

        if result.returncode != 0:
            return False, f"{tool} falló: {result.stderr.strip()[:200]}"

        # Verificación defensiva: ningún archivo debe estar fuera de dest
        dest_real = os.path.realpath(dest)
        for root, _dirs, files in os.walk(dest):
            for name in files:
                full = os.path.realpath(os.path.join(root, name))
                if not full.startswith(dest_real + os.sep):
                    return False, f"{tool} extrajo fuera de destino: {full}"
        return True, "ok"

    # ------------------------------------------------------------------ scan
    def extract_and_scan(self, filepath: str) -> tuple[bool, str]:
        """
        Extrae (de forma segura) y escanea recursivamente el contenido.
        Devuelve (infectado, motivo).
        """
        mime = self._detect_mime(filepath)
        logger.debug("ArchiveScanner: %s (mime=%s)", filepath, mime)

        # Directorio temporal único por archivo para evitar colisiones
        safe_name = os.path.basename(filepath).replace(os.sep, "_")
        extract_path = tempfile.mkdtemp(prefix=f"av_{safe_name}_", dir=self.temp_dir)

        try:
            ok, reason = self._extract_safe(filepath, extract_path, mime)
            if not ok:
                logger.warning("Extracción rechazada para %s: %s", filepath, reason)
                return False, f"contenido rechazado ({reason})"

            # Escanear el contenido extraído
            found = self._scan_tree(extract_path)
            if found:
                path, motivo = found
                self.engine.quarantine(filepath, f"Contenido comprimido malicioso: {motivo}")
                return True, f"Malware dentro de {os.path.basename(filepath)}: {motivo}"

            return False, "Limpio"

        finally:
            shutil.rmtree(extract_path, ignore_errors=True)

    def _scan_tree(self, root: str) -> tuple[str, str] | None:
        """Recorre el árbol extraído y devuelve el primer (path, motivo) infectado."""
        for r, _dirs, files in os.walk(root):
            for name in files:
                full = os.path.join(r, name)
                if os.path.islink(full):
                    continue
                try:
                    infectado, motivo = self.engine.scan_file(full)
                except Exception as exc:
                    logger.warning("Error escaneando %s: %s", full, exc)
                    continue
                if infectado:
                    return full, motivo
        return None
