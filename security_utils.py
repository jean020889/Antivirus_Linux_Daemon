"""
security_utils.py
Utilidades de robustez para el daemon de antivirus:

- ThreadSafeProxy: sincroniza el acceso concurrente a objetos compartidos.
- safe_extract_zip / safe_extract_tar: extracción con límites contra zip
  bombs y path traversal / Zip Slip.
"""

from __future__ import annotations

import logging
import os
import tarfile
import threading
import zipfile
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("antivirus.security_utils")


class ThreadSafeProxy:
    """Envuelve un objeto y serializa todas las llamadas a sus métodos con un RLock."""

    def __init__(self, target: Any) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_lock", threading.RLock())

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        attr = getattr(target, name)
        if not callable(attr):
            return attr

        lock = object.__getattribute__(self, "_lock")

        def _locked_call(*args, **kwargs):
            with lock:
                return attr(*args, **kwargs)

        return _locked_call


@dataclass(frozen=True)
class ExtractionLimits:
    max_total_uncompressed_bytes: int = 500 * 1024 * 1024
    max_files: int = 10_000
    max_compression_ratio: float = 100.0
    max_single_file_bytes: int = 200 * 1024 * 1024


class ZipBombError(Exception):
    """Se lanza cuando un archivo comprimido excede algún límite de seguridad."""


class PathTraversalError(Exception):
    """Se lanza cuando una entrada intenta escribir fuera del directorio destino."""


def _resolve_safe_path(dest_dir: str, member_name: str) -> str:
    dest_dir_real = os.path.realpath(dest_dir)
    target = os.path.realpath(os.path.join(dest_dir_real, member_name))
    if not (target == dest_dir_real or target.startswith(dest_dir_real + os.sep)):
        raise PathTraversalError(f"Ruta fuera del destino permitido: {member_name}")
    return target


def safe_extract_zip(
    archive_path: str, dest_dir: str, limits: ExtractionLimits = ExtractionLimits()
) -> list[str]:
    os.makedirs(dest_dir, exist_ok=True)
    extracted: list[str] = []
    total_uncompressed = 0

    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise ZipBombError(
                f"{archive_path}: {len(infos)} entradas excede el límite de {limits.max_files}"
            )

        for info in infos:
            if info.is_dir():
                continue

            if info.file_size > limits.max_single_file_bytes:
                raise ZipBombError(
                    f"{archive_path}: entrada '{info.filename}' excede el tamaño individual máximo"
                )

            compressed = max(info.compress_size, 1)
            ratio = info.file_size / compressed
            if ratio > limits.max_compression_ratio:
                raise ZipBombError(
                    f"{archive_path}: entrada '{info.filename}' con ratio de compresión "
                    f"sospechoso ({ratio:.1f}x)"
                )

            total_uncompressed += info.file_size
            if total_uncompressed > limits.max_total_uncompressed_bytes:
                raise ZipBombError(
                    f"{archive_path}: tamaño total descomprimido excede el límite permitido"
                )

            safe_path = _resolve_safe_path(dest_dir, info.filename)
            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
            with zf.open(info) as src, open(safe_path, "wb") as dst:
                dst.write(src.read())
            extracted.append(safe_path)

    return extracted


def safe_extract_tar(
    archive_path: str, dest_dir: str, limits: ExtractionLimits = ExtractionLimits()
) -> list[str]:
    os.makedirs(dest_dir, exist_ok=True)
    extracted: list[str] = []
    total_uncompressed = 0

    with tarfile.open(archive_path) as tf:
        members = tf.getmembers()
        if len(members) > limits.max_files:
            raise ZipBombError(
                f"{archive_path}: {len(members)} entradas excede el límite de {limits.max_files}"
            )

        for member in members:
            if not member.isfile():
                continue
            if member.issym() or member.islnk():
                logger.warning("Symlink ignorado en %s: %s", archive_path, member.name)
                continue

            if member.size > limits.max_single_file_bytes:
                raise ZipBombError(
                    f"{archive_path}: entrada '{member.name}' excede el tamaño individual máximo"
                )

            total_uncompressed += member.size
            if total_uncompressed > limits.max_total_uncompressed_bytes:
                raise ZipBombError(
                    f"{archive_path}: tamaño total descomprimido excede el límite permitido"
                )

            safe_path = _resolve_safe_path(dest_dir, member.name)
            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
            extracted_file = tf.extractfile(member)
            if extracted_file is None:
                continue
            with open(safe_path, "wb") as dst:
                dst.write(extracted_file.read())
            extracted.append(safe_path)

    return extracted
