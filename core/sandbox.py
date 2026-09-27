"""
core/sandbox.py
Sandbox de detonación aislada para análisis dinámico de malware.

CARACTERÍSTICAS DE SEGURIDAD:
  - Contenedor Docker efímero (--rm).
  - Sin acceso a red (--network=none).
  - Filesystem raíz read-only.
  - /tmp como tmpfs efímero.
  - Sin capabilities (--cap-drop=ALL).
  - Sin nuevos privilegios (--security-opt=no-new-privileges).
  - Timeout estricto.
  - Límites de CPU y memoria.

El script se copia dentro del contenedor, se le da permiso de
ejecución y se ejecuta con `timeout`. Se captura stdout/stderr
para análisis posterior.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("antivirus.sandbox")

SANDBOX_IMAGE = "antivirus-sandbox:latest"
SANDBOX_TIMEOUT = 30
SANDBOX_MEMORY = "256m"
SANDBOX_CPUS = "1.0"


@dataclass
class SandboxResult:
    filepath: str
    executed: bool
    exit_code: int | None
    duration: float
    stdout: str = ""
    stderr: str = ""
    syscalls: list[str] = field(default_factory=list)
    network_attempts: list[str] = field(default_factory=list)
    file_operations: list[str] = field(default_factory=list)
    error: str = ""


class Sandbox:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and self._docker_available()
        if not self.enabled:
            logger.warning("Sandbox deshabilitado (Docker no disponible)")

    @staticmethod
    def _docker_available() -> bool:
        if shutil.which("docker") is None:
            return False
        try:
            r = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5,
            )
            return r.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def detonate(self, filepath: str) -> SandboxResult:
        """
        Ejecuta un archivo en un contenedor Docker aislado y captura
        su comportamiento.
        """
        path = Path(filepath).resolve()
        if not path.is_file():
            return SandboxResult(
                filepath=str(path), executed=False, exit_code=None,
                duration=0.0, error="Archivo no encontrado",
            )

        if not self.enabled:
            return SandboxResult(
                filepath=str(path), executed=False, exit_code=None,
                duration=0.0, error="Sandbox no disponible",
            )

        start = time.time()

        # Crear directorio temporal con permisos accesibles al contenedor
        tmpdir = tempfile.mkdtemp(prefix="av_sandbox_")
        try:
            Path(tmpdir).chmod(0o755)  # El contenedor debe poder leerlo
            src = Path(tmpdir) / path.name
            shutil.copy2(path, src)
            src.chmod(0o755)

            # Script que copia, marca ejecutable y ejecuta con timeout
            inner_cmd = (
                f"cp /work/{path.name} /tmp/sample && "
                f"chmod +x /tmp/sample && "
                f"cd /tmp && "
                f"timeout {SANDBOX_TIMEOUT} "
                f"strace -f -e trace=all -o /tmp/strace.out /tmp/sample; "
                f"cat /tmp/strace.out"
            )

            cmd = [
                "docker", "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--tmpfs", "/tmp:rw,exec,nosuid,size=128m,mode=1777",
                "--memory", SANDBOX_MEMORY,
                "--cpus", SANDBOX_CPUS,
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "-v", f"{tmpdir}:/work:ro",
                "-w", "/work",
                SANDBOX_IMAGE,
                "sh", "-c", inner_cmd,
            ]

            try:
                r = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=SANDBOX_TIMEOUT + 30,
                )
                duration = time.time() - start

                # strace -o escribe a un archivo; cat lo muestra en stdout.
                # El parser debe buscar en stdout Y stderr por si acaso.
                combined_output = r.stdout + "\n" + r.stderr
                syscalls = self._extract_syscalls(combined_output)
                net_attempts = self._extract_network(combined_output)
                file_ops = self._extract_file_ops(combined_output)

                # Detectar si el contenedor arrancó pero falló
                error = ""
                if r.returncode == 126:
                    error = "Permiso denegado al ejecutar el archivo en sandbox"
                elif r.returncode == 127:
                    error = "Comando no encontrado (posible shebang roto)"
                elif r.returncode == 124:
                    error = "Timeout: el archivo excedió el tiempo máximo"

                return SandboxResult(
                    filepath=str(path),
                    executed=True,
                    exit_code=r.returncode,
                    duration=duration,
                    stdout=r.stdout[:8192],
                    stderr=r.stderr[:8192],
                    syscalls=syscalls,
                    network_attempts=net_attempts,
                    file_operations=file_ops,
                    error=error,
                )
            except subprocess.TimeoutExpired:
                return SandboxResult(
                    filepath=str(path), executed=False, exit_code=None,
                    duration=time.time() - start,
                    error="Timeout absoluto en sandbox",
                )
            except OSError as exc:
                return SandboxResult(
                    filepath=str(path), executed=False, exit_code=None,
                    duration=time.time() - start,
                    error=f"Error Docker: {exc}",
                )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @staticmethod
    def _extract_syscalls(output: str) -> list[str]:
        """
        Extrae nombres de syscalls del output de strace.

        Formato de strace:
            execve("/bin/sh", ["/bin/sh"], 0x7fff...) = 0
            openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
            read(3, "...", 832) = 832
        """
        if not output:
            return []
        # Buscar todas las líneas de strace
        found = re.findall(r'\b([a-z_][a-z0-9_]+)\(', output)
        # Filtrar ruido de inicialización (los primeros syscalls de ld.so)
        noise = {
            "brk", "arch_prctl", "set_tid_address",
            "set_robust_list", "rseq", "prlimit64",
        }
        unique = list(dict.fromkeys(found))
        return [s for s in unique if s not in noise and len(s) > 3][:100]

    @staticmethod
    def _extract_network(stderr: str) -> list[str]:
        """Extrae IPs de intentos de conexión."""
        ips = re.findall(r'inet_addr\("([^"]+)"\)', stderr)
        ips += re.findall(r'connect.*?(\d+\.\d+\.\d+\.\d+)', stderr)
        return list(dict.fromkeys(ips))[:20]

    @staticmethod
    def _extract_file_ops(output: str) -> list[str]:
        """
        Extrae operaciones de archivos del output de strace.

        Formatos soportados:
          openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
          open("/etc/passwd", O_RDONLY) = 3
          unlink("/tmp/evil") = 0
          chmod("/tmp/x", 0777) = 0
        """
        if not output:
            return []
        ops = []
        # openat con AT_FDCWD
        ops.extend(re.findall(
            r'\bopenat\(AT_FDCWD,\s*"([^"]+)"',
            output,
        ))
        # open directo
        ops.extend(re.findall(
            r'\bopen\("([^"]+)"',
            output,
        ))
        # Otras operaciones con path como primer argumento string
        for op in ("unlink", "unlinkat", "rename", "chmod", "chown",
                   "mkdir", "rmdir", "creat", "access", "stat", "lstat"):
            ops.extend(re.findall(
                rf'\b{op}\([^"]*"([^"]+)"',
                output,
            ))
        # Deduplicar manteniendo orden
        seen = set()
        unique = []
        for o in ops:
            if o not in seen and len(o) > 1:
                seen.add(o)
                unique.append(o)
        return unique[:50]
