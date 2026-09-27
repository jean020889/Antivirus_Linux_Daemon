#!/usr/bin/env python3
"""
scripts/collect_benign_syscalls.py
Recolecta secuencias de syscalls de procesos benignos para entrenar
el detector de anomalías ML del Antivirus Linux Dragon.

Uso:
    sudo python3 scripts/collect_benign_syscalls.py --duration 300 \
        --output data/benign_syscalls.json

Ejecuta una serie de comandos benignos comunes bajo strace y captura
sus syscalls. El resultado se usa para entrenar el SyscallAnomalyDetector.
"""
import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

BENIGN_COMMANDS = [
    ["ls", "-la", "/tmp"],
    ["cat", "/etc/hostname"],
    ["ps", "aux"],
    ["df", "-h"],
    ["free", "-m"],
    ["uptime"],
    ["find", "/tmp", "-name", "*.txt", "-maxdepth", "2"],
    ["grep", "-r", "root", "/etc/passwd"],
    ["head", "-n", "10", "/etc/services"],
    ["tail", "-n", "10", "/var/log/syslog"],
    ["whoami"],
    ["id"],
    ["uname", "-a"],
    ["date"],
    ["echo", "hola mundo"],
    ["wc", "-l", "/etc/passwd"],
    ["sort", "/etc/passwd"],
    ["awk", "-F:", "{print $1}", "/etc/passwd"],
    ["sed", "-n", "1,3p", "/etc/passwd"],
    ["cut", "-d:", "-f1,3", "/etc/passwd"],
]


def capture_syscalls(cmd: list[str]) -> list[str]:
    """Captura syscalls de un comando usando strace."""
    strace_out = "/tmp/strace_collect.txt"
    try:
        subprocess.run(
            ["strace", "-f", "-e", "trace=all", "-o", strace_out] + cmd,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"  ⚠️  {cmd[0]}: {exc}")
        return []

    syscalls = []
    try:
        with open(strace_out) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("---") or "+++" in line:
                    continue
                # Extraer nombre de syscall antes del paréntesis
                idx = line.find("(")
                if idx > 0:
                    # El nombre puede tener prefijo "[pid] " si es multi-hilo
                    prefix_end = line.rfind(" ", 0, idx)
                    syscall = line[prefix_end + 1:idx].strip()
                    if syscall and syscall.isidentifier():
                        syscalls.append(syscall)
    except OSError as exc:
        print(f"  ⚠️  Error leyendo strace: {exc}")

    try:
        Path(strace_out).unlink()
    except OSError:
        pass

    return syscalls


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=60,
                        help="Duración total en segundos (default: 60)")
    parser.add_argument("--output", default="data/benign_syscalls.json")
    args = parser.parse_args()

    if shutil.which("strace") is None:
        print("❌ strace no está instalado.")
        print("   Instálalo con: sudo apt install strace")
        return 1

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    sequences = []
    start = time.time()
    print(f"=== Recolectando syscalls benignos durante {args.duration}s ===")
    print(f"    Salida: {output}")
    print()

    while time.time() - start < args.duration:
        for cmd in BENIGN_COMMANDS:
            seq = capture_syscalls(cmd)
            if len(seq) >= 10:
                sequences.append(seq)
                print(f"  [{len(sequences):3d}] {cmd[0]:10s} → {len(seq)} syscalls")
            # Salir si ya tenemos suficientes
            if len(sequences) >= 500:
                break
        time.sleep(0.5)
        if len(sequences) >= 500:
            break

    with open(output, "w") as f:
        json.dump(sequences, f)

    print()
    print(f"✅ {len(sequences)} secuencias guardadas en {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
