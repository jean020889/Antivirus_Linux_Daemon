# core/zip_defense.py
"""
Defensas contra Zip Slip y Zip Bomb.

Zip Slip: archivos con rutas ../ que escriben fuera del directorio destino.
Zip Bomb: archivos comprimidos que expanden a tamaños enormes.
"""
import os
import zipfile
import tarfile


class ZipSecurityError(Exception):
    pass


class SafeExtractor:
    MAX_EXTRACT_SIZE = 500 * 1024 * 1024  # 500 MB
    MAX_FILE_SIZE = 100 * 1024 * 1024     # 100 MB por archivo
    MAX_COMPRESSION_RATIO = 100           # 100:1
    MAX_FILES = 10000

    @staticmethod
    def safe_extract_zip(zip_path, extract_dir):
        """Extrae un ZIP con protecciones."""
        os.makedirs(extract_dir, exist_ok=True)
        real_extract_dir = os.path.realpath(extract_dir)

        total_size = 0
        total_compressed = 0
        file_count = 0

        with zipfile.ZipFile(zip_path, 'r') as zf:
            for info in zf.infolist():
                file_count += 1
                if file_count > SafeExtractor.MAX_FILES:
                    raise ZipSecurityError(f"Zip con demasiados archivos (> {SafeExtractor.MAX_FILES})")

                # Zip Slip: ruta resuelta debe estar dentro del extract_dir
                target_path = os.path.realpath(os.path.join(extract_dir, info.filename))
                if not target_path.startswith(real_extract_dir + os.sep) and target_path != real_extract_dir:
                    raise ZipSecurityError(f"Zip Slip detectado: {info.filename}")

                # Tamaño por archivo
                if info.file_size > SafeExtractor.MAX_FILE_SIZE:
                    raise ZipSecurityError(f"Archivo demasiado grande: {info.filename} ({info.file_size} bytes)")

                # Tamaño total
                total_size += info.file_size
                total_compressed += info.compress_size

                if total_size > SafeExtractor.MAX_EXTRACT_SIZE:
                    raise ZipSecurityError(f"Extracción excede {SafeExtractor.MAX_EXTRACT_SIZE} bytes")

                # Ratio de compresión (Zip Bomb)
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > SafeExtractor.MAX_COMPRESSION_RATIO:
                    raise ZipSecurityError(f"Zip Bomb sospechosa: ratio {ratio:.1f}:1 en {info.filename}")

            # Extraer
            for info in zf.infolist():
                zf.extract(info, extract_dir)

        return {
            "extracted": file_count,
            "total_size": total_size,
            "total_compressed": total_compressed,
            "ratio": total_size / max(total_compressed, 1)
        }

    @staticmethod
    def safe_extract_tar(tar_path, extract_dir):
        """Extrae un TAR con protecciones."""
        os.makedirs(extract_dir, exist_ok=True)
        real_extract_dir = os.path.realpath(extract_dir)

        total_size = 0
        file_count = 0

        with tarfile.open(tar_path, 'r:*') as tf:
            for member in tf.getmembers():
                file_count += 1
                if file_count > SafeExtractor.MAX_FILES:
                    raise ZipSecurityError(f"Tar con demasiados archivos (> {SafeExtractor.MAX_FILES})")

                # Zip Slip
                target_path = os.path.realpath(os.path.join(extract_dir, member.name))
                if not target_path.startswith(real_extract_dir + os.sep) and target_path != real_extract_dir:
                    raise ZipSecurityError(f"Tar Slip detectado: {member.name}")

                # Symlinks peligrosos
                if member.issym() or member.islnk():
                    link_target = os.path.realpath(os.path.join(extract_dir, member.linkname))
                    if not link_target.startswith(real_extract_dir + os.sep):
                        raise ZipSecurityError(f"Symlink peligroso: {member.name} -> {member.linkname}")

                total_size += member.size
                if total_size > SafeExtractor.MAX_EXTRACT_SIZE:
                    raise ZipSecurityError(f"Extracción excede {SafeExtractor.MAX_EXTRACT_SIZE} bytes")

            # Extraer con filtro
            try:
                tf.extractall(extract_dir, filter='data')  # Python 3.12+
            except TypeError:
                tf.extractall(extract_dir)  # Fallback

        return {"extracted": file_count, "total_size": total_size}
