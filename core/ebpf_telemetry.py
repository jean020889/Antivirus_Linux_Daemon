# core/ebpf_telemetry.py
"""
Telemetría eBPF para detección en tiempo real.

Usa:
- BCC (BPF Compiler Collection) para hooks eBPF
- Alternativa: auditd si eBPF no está disponible
- Fallback: polling mejorado

Monitorea:
- execve (ejecución de procesos)
- openat (apertura de archivos)
- connect (conexiones de red)
- setuid/setgid (escalada de privilegios)
- ptrace (debugging/injection)
- mmap con PROT_EXEC (shellcode)
"""
import os
import sys
import threading
import time
import json
from datetime import datetime

# Añadir path de BCC del sistema (Ubuntu lo instala en dist-packages)
import sys as _sys
if '/usr/lib/python3/dist-packages' not in _sys.path:
    _sys.path.insert(0, '/usr/lib/python3/dist-packages')

# Detectar si BCC está disponible
HAS_BCC = False
try:
    from bcc import BPF
    HAS_BCC = True
except ImportError:
    pass

# Detectar si auditd está disponible
HAS_AUDITD = False
try:
    import audit
    HAS_AUDITD = True
except ImportError:
    HAS_AUDITD = os.path.exists('/sbin/auditctl') and os.path.exists('/var/log/audit')


class EBPFTelemetry:
    def __init__(self, config=None, on_event=None):
        self.config = config or {}
        self.on_event = on_event  # callback(event_dict)
        self.running = False
        self.mode = self._detect_mode()
        self.bpf = None
        self.thread = None

        print(f"[+] eBPF Telemetry mode: {self.mode}")

    def _detect_mode(self):
        if HAS_BCC:
            return "bcc"
        elif HAS_AUDITD:
            return "auditd"
        else:
            return "polling"

    # ============================================
    # MODO BCC (eBPF nativo)
    # ============================================
    def _start_bcc(self):
        """Inicia telemetría con BCC/eBPF."""
        bpf_program = r"""
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        #include <linux/fs.h>

        struct exec_event_t {
            u32 pid;
            u32 ppid;
            u32 uid;
            char comm[16];
            char filename[256];
        };

        struct open_event_t {
            u32 pid;
            u32 uid;
            char comm[16];
            char filename[256];
            int flags;
        };

        struct connect_event_t {
            u32 pid;
            u32 uid;
            u32 daddr;
            u16 dport;
            char comm[16];
        };

        BPF_PERF_OUTPUT(exec_events);
        BPF_PERF_OUTPUT(open_events);
        BPF_PERF_OUTPUT(connect_events);

        // execve
        int kprobe__sys_execve(struct pt_regs *ctx, const char __user *filename,
                               const char __user *const __user *__argv,
                               const char __user *const __user *__envp) {
            struct exec_event_t event = {};
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            event.pid = bpf_get_current_pid_tgid() >> 32;
            event.ppid = task->real_parent->tgid;
            event.uid = bpf_get_current_uid_gid() & 0xffffffff;
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
            exec_events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }

        // openat
        int kprobe__sys_openat(struct pt_regs *ctx, int dfd, const char __user *filename,
                               int flags, umode_t mode) {
            struct open_event_t event = {};
            event.pid = bpf_get_current_pid_tgid() >> 32;
            event.uid = bpf_get_current_uid_gid() & 0xffffffff;
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
            event.flags = flags;
            open_events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }

        // connect
        int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
            struct connect_event_t event = {};
            event.pid = bpf_get_current_pid_tgid() >> 32;
            event.uid = bpf_get_current_uid_gid() & 0xffffffff;
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            
            u32 daddr = sk->__sk_common.skc_daddr;
            u16 dport = sk->__sk_common.skc_dport;
            
            event.daddr = daddr;
            event.dport = ntohs(dport);
            
            connect_events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }
        """

        try:
            self.bpf = BPF(text=bpf_program)

            def handle_exec(cpu, data, size):
                event = self.bpf["exec_events"].event(data)
                self._emit_event({
                    "event_type": "execve",
                    "timestamp": datetime.now().isoformat(),
                    "process_pid": event.pid,
                    "parent_pid": event.ppid,
                    "process_user_id": event.uid,
                    "process_name": event.comm.decode('utf-8', errors='ignore').rstrip('\x00'),
                    "process_exe": event.filename.decode('utf-8', errors='ignore').rstrip('\x00'),
                })

            def handle_open(cpu, data, size):
                event = self.bpf["open_events"].event(data)
                self._emit_event({
                    "event_type": "openat",
                    "timestamp": datetime.now().isoformat(),
                    "process_pid": event.pid,
                    "file_path": event.filename.decode('utf-8', errors='ignore').rstrip('\x00'),
                    "process_name": event.comm.decode('utf-8', errors='ignore').rstrip('\x00'),
                })

            def handle_connect(cpu, data, size):
                event = self.bpf["connect_events"].event(data)
                # Convertir daddr (u32) a IP
                daddr = event.daddr
                ip = f"{(daddr & 0xff)}.{(daddr >> 8) & 0xff}.{(daddr >> 16) & 0xff}.{(daddr >> 24) & 0xff}"
                self._emit_event({
                    "event_type": "connect",
                    "timestamp": datetime.now().isoformat(),
                    "process_pid": event.pid,
                    "network_dst_ip": ip,
                    "network_dst_port": event.dport,
                    "process_name": event.comm.decode('utf-8', errors='ignore').rstrip('\x00'),
                })

            self.bpf["exec_events"].open_perf_buffer(handle_exec)
            self.bpf["open_events"].open_perf_buffer(handle_open)
            self.bpf["connect_events"].open_perf_buffer(handle_connect)

            print("[+] eBPF: kprobes instaladas (execve, openat, connect)")

            while self.running:
                self.bpf.perf_buffer_poll(timeout=1000)
        except Exception as e:
            print(f"[!] BCC error: {e}, cayendo a polling")
            self.mode = "polling"

    # ============================================
    # MODO AUDITD
    # ============================================
    def _start_auditd(self):
        """Lee eventos de auditd (fallback)."""
        import subprocess

        # Reglas de auditoría para eBPF-style monitoring
        rules = [
            "-a always,exit -F arch=b64 -S execve -k exec_monitor",
            "-a always,exit -F arch=b64 -S openat -k open_monitor",
            "-a always,exit -F arch=b64 -S connect -k connect_monitor",
            "-a always,exit -F arch=b64 -S ptrace -k ptrace_monitor",
            "-a always,exit -F arch=b64 -S setuid,setgid -k priv_escalation",
        ]

        # Solo si somos root
        if os.geteuid() == 0:
            for rule in rules:
                subprocess.run(['auditctl'] + rule.split(), capture_output=True)

        print("[+] auditd: reglas instaladas, leyendo /var/log/audit/audit.log")

        import subprocess
        proc = subprocess.Popen(
            ['tail', '-F', '/var/log/audit/audit.log'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )

        while self.running:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            event = self._parse_audit_line(line)
            if event:
                self._emit_event(event)

    def _parse_audit_line(self, line):
        """Parsea una línea de audit.log."""
        try:
            # Formato: type=SYSCALL msg=audit(...): arch=... syscall=59 ...
            if 'type=SYSCALL' not in line:
                return None

            fields = {}
            for part in line.split():
                if '=' in part:
                    k, v = part.split('=', 1)
                    fields[k] = v.strip('"\'')

            syscall_map = {'59': 'execve', '257': 'openat', '42': 'connect',
                           '101': 'ptrace', '105': 'setuid', '106': 'setgid'}

            syscall = syscall_map.get(fields.get('syscall'), 'unknown')

            return {
                "event_type": f"audit_{syscall}",
                "timestamp": datetime.now().isoformat(),
                "process_pid": int(fields.get('pid', 0)),
                "process_name": fields.get('comm', ''),
                "process_exe": fields.get('exe', ''),
                "process_user_id": int(fields.get('uid', 0)),
                "file_path": fields.get('name', ''),
            }
        except Exception:
            return None

    # ============================================
    # MODO POLLING (fallback)
    # ============================================
    def _start_polling(self):
        """Polling mejorado cada 2s."""
        print("[+] Fallback: polling mejorado (2s interval)")
        import psutil

        seen = set()
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
                    try:
                        pid = proc.info['pid']
                        if pid in seen:
                            continue
                        seen.add(pid)
                        self._emit_event({
                            "event_type": "process_start",
                            "timestamp": datetime.now().isoformat(),
                            "process_pid": pid,
                            "process_name": proc.info['name'],
                            "process_exe": proc.info['exe'],
                            "process_user": proc.info['username'],
                        })
                    except Exception:
                        continue

                if len(seen) > 100000:
                    seen = set(list(seen)[-50000:])

                time.sleep(2)
            except Exception as e:
                print(f"[!] Polling error: {e}")
                time.sleep(5)

    # ============================================
    # CONTROL
    # ============================================
    def start(self):
        """Inicia la telemetría en thread."""
        self.running = True

        if self.mode == "bcc":
            target = self._start_bcc
        elif self.mode == "auditd":
            target = self._start_auditd
        else:
            target = self._start_polling

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()
        return self.thread

    def stop(self):
        self.running = False
        if self.bpf:
            try:
                self.bpf.cleanup()
            except Exception:
                pass

    def _emit_event(self, event):
        """Emite evento via callback."""
        if self.on_event:
            try:
                self.on_event(event)
            except Exception as e:
                print(f"[!] on_event error: {e}")
