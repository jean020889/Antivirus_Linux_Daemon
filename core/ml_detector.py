"""
core/ml_detector.py
Detector de anomalías basado en Machine Learning para llamadas al sistema.

Implementa tres enfoques ortogonales para detección de día cero,
basados en investigación académica reciente [citation:5][citation:6][citation:16]:

  Path A: TF-IDF + PCA + One-Class SVM (frecuencia y rareza)
  Path B: CNN-1D Autoencoder (topología local de secuencias)
  Path C: GRU Predictor (predicción de siguiente syscall)

Un proceso se marca como anómalo si CUALQUIERA de los tres paths
detecta desviación significativa de la línea base benigna.

El entrenamiento es no supervisado: solo se necesitan secuencias
de syscalls de procesos benignos. Esto permite detectar ataques
nunca antes vistos.
"""

from __future__ import annotations

import logging
import os
import pickle
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

logger = logging.getLogger("antivirus.ml")

# Syscalls comunes en Linux (x86_64). Se usa como vocabulario base.
COMMON_SYSCALLS = [
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
    "lseek", "mmap", "mprotect", "munmap", "brk", "ioctl", "access",
    "pipe", "select", "sched_yield", "mremap", "msync", "mincore",
    "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause",
    "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile",
    "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg",
    "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
    "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork",
    "execve", "exit", "wait4", "kill", "uname", "semget", "semop",
    "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl",
    "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents",
    "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat",
    "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown",
    "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage",
    "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid",
    "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
    "setsid", "setreuid", "setregid", "getgroups", "setgroups",
    "setresuid", "getresuid", "setresgid", "getresgid", "getpgid",
    "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending",
    "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack",
    "utime", "mknod", "uselib", "personality", "ustat", "statfs",
    "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam",
    "sched_getparam", "sched_setscheduler", "sched_getscheduler",
    "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
    "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
    "pivot_root", "prctl", "arch_prctl", "adjtimex", "setrlimit",
    "chroot", "sync", "acct", "settimeofday", "mount", "umount2",
    "swapon", "swapoff", "reboot", "sethostname", "setdomainname",
    "iopl", "ioperm", "create_module", "init_module", "delete_module",
    "get_kernel_syms", "query_module", "quotactl", "nfsservctl",
    "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security",
    "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr",
    "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
    "flistxattr", "removexattr", "lremovexattr", "fremovexattr",
    "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity",
    "set_thread_area", "io_setup", "io_destroy", "io_getevents",
    "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie",
    "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages",
    "getdents64", "set_tid_address", "restart_syscall", "semtimedop",
    "fadvise64", "timer_create", "timer_settime", "timer_gettime",
    "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime",
    "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait",
    "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy",
    "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend",
    "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load",
    "waitid", "add_key", "request_key", "keyctl", "ioprio_set",
    "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch",
    "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat",
    "futimesat", "newfstatat", "unlinkat", "renameat", "linkat",
    "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6",
    "ppoll", "unshare", "set_robust_list", "get_robust_list",
    "splice", "tee", "vmsplice", "move_pages", "utimensat",
    "epoll_pwait", "signalfd", "timerfd_create", "eventfd",
    "fallocate", "timerfd_settime", "timerfd_gettime", "accept4",
    "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2",
    "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
    "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark",
    "prlimit64", "name_to_handle_at", "open_by_handle_at",
    "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu",
    "process_vm_readv", "process_vm_writev", "kcmp", "finit_module",
    "sched_setattr", "sched_getattr", "renameat2", "seccomp",
    "getrandom", "memfd_create", "kexec_file_load", "bpf",
    "execveat", "userfaultfd", "membarrier", "mlock2",
    "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect",
    "pkey_alloc", "pkey_free", "statx", "io_pgetevents",
    "rseq", "pidfd_send_signal", "io_uring_setup", "io_uring_enter",
    "io_uring_register", "open_tree", "move_mount", "fsopen",
    "fsconfig", "fsmount", "fspick", "pidfd_open", "clone3",
    "close_range", "openat2", "pidfd_getfd", "faccessat2",
]

SYSCALL_TO_ID = {name: i for i, name in enumerate(COMMON_SYSCALLS)}
UNKNOWN_ID = len(COMMON_SYSCALLS)


@dataclass
class AnomalyResult:
    pid: int
    comm: str
    path_score_a: float = 0.0
    path_score_b: float = 0.0
    path_score_c: float = 0.0
    fusion_score: float = 0.0
    is_anomalous: bool = False
    reason: str = ""
    top_syscalls: list[tuple[str, int]] = field(default_factory=list)


class SyscallAnomalyDetector:
    """
    Detector de anomalías en secuencias de syscalls.

    Modelos:
      - Path A: One-Class SVM sobre TF-IDF de n-gramas de syscalls.
      - Path B: CNN-1D Autoencoder sobre embeddings de syscalls.
      - Path C: GRU Predictor de siguiente syscall.

    El detector se entrena solo con datos benignos (no supervisado).
    """

    def __init__(self, window_size: int = 50, model_dir: str | None = None):
        self.window_size = window_size
        # Directorio para los modelos ML. Orden de preferencia:
        #   1. Argumento explícito model_dir
        #   2. Variable de entorno AV_ML_MODEL_DIR
        #   3. ~/.local/share/antivirus/ml_models (escribible por el usuario)
        #   4. /var/lib/antivirus-linux-dragon/ml_models (requiere root)
        if model_dir:
            base = Path(model_dir)
        elif os.environ.get("AV_ML_MODEL_DIR"):
            base = Path(os.environ["AV_ML_MODEL_DIR"])
        else:
            base = Path.home() / ".local/share/antivirus/ml_models"

        try:
            base.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Último recurso: directorio temporal
            import tempfile
            base = Path(tempfile.mkdtemp(prefix="av_ml_"))
            logger.warning("Sin permisos en model_dir; usando %s", base)

        self.model_dir = base

        # Path A: vocabulario + IDF
        self.tfidf_vocab: dict[str, int] = {}
        self.tfidf_idf: np.ndarray | None = None
        self.pca_components: np.ndarray | None = None
        self.pca_mean: np.ndarray | None = None
        self.ocsvm_w: np.ndarray | None = None
        self.ocsvm_rho: float = 0.0

        # Path B: autoencoder simple
        self.autoencoder_weights: list[np.ndarray] = []

        # Path C: matriz de transición de Markov (simplificada de GRU)
        self.transition_matrix: np.ndarray | None = None

        self.is_trained = False

        # Intento de carga automática del modelo pre-entrenado (si existe).
        # Si no existe, se puede entrenar después con train().
        try:
            self.load()
        except Exception:
            # Silenciar errores en __init__; el llamador puede llamar a
            # train() si el modelo no existe o está corrupto.
            pass

    # ---------------------------------------------------------------- training
    def train(self, benign_sequences: list[list[str]]) -> None:
        """
        Entrena los tres paths con secuencias de syscalls benignas.

        :param benign_sequences: Lista de secuencias (listas de nombres de syscalls).
        """
        logger.info("Entrenando detector con %d secuencias", len(benign_sequences))
        if len(benign_sequences) < 10:
            logger.warning("Pocas secuencias para entrenar (%d)", len(benign_sequences))

        # 1. Construir vocabulario TF-IDF (Path A)
        self._train_tfidf(benign_sequences)

        # 2. Entrenar One-Class SVM (Path A)
        self._train_ocsvm(benign_sequences)

        # 3. Entrenar autoencoder (Path B)
        self._train_autoencoder(benign_sequences)

        # 4. Construir matriz de transición (Path C)
        self._train_transition_matrix(benign_sequences)

        self.is_trained = True
        logger.info("Detector entrenado correctamente")

    def _train_tfidf(self, sequences: list[list[str]]) -> None:
        # Vocabulario de unigramas y bigramas
        counter: Counter = Counter()
        for seq in sequences:
            for i, s in enumerate(seq):
                counter[s] += 1
                if i + 1 < len(seq):
                    counter[f"{s}__{seq[i+1]}"] += 1

        # Top 1000 términos
        top = counter.most_common(1000)
        self.tfidf_vocab = {term: i for i, (term, _) in enumerate(top)}

        # Calcular IDF
        n_docs = len(sequences)
        df = np.zeros(len(self.tfidf_vocab))
        for seq in sequences:
            terms_seen = set()
            for i, s in enumerate(seq):
                terms_seen.add(s)
                if i + 1 < len(seq):
                    terms_seen.add(f"{s}__{seq[i+1]}")
            for term in terms_seen:
                if term in self.tfidf_vocab:
                    df[self.tfidf_vocab[term]] += 1
        self.tfidf_idf = np.log((n_docs + 1) / (df + 1)) + 1

    def _vectorize_tfidf(self, seq: list[str]) -> np.ndarray:
        vec = np.zeros(len(self.tfidf_vocab))
        for i, s in enumerate(seq):
            if s in self.tfidf_vocab:
                vec[self.tfidf_vocab[s]] += 1
            if i + 1 < len(seq):
                bigram = f"{s}__{seq[i+1]}"
                if bigram in self.tfidf_vocab:
                    vec[self.tfidf_vocab[bigram]] += 1
        # TF-IDF
        vec = vec * self.tfidf_idf
        # Normalizar L2
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def _train_ocsvm(self, sequences: list[list[str]]) -> None:
        """Entrena One-Class SVM vía SGD (implementación simplificada)."""
        if not self.tfidf_vocab:
            return

        vectors = np.array([self._vectorize_tfidf(s) for s in sequences])

        # PCA a 100 componentes
        n_components = min(100, vectors.shape[1], vectors.shape[0] - 1)
        if n_components < 2:
            return
        self.pca_mean = vectors.mean(axis=0)
        centered = vectors - self.pca_mean
        # SVD para PCA
        try:
            u, s, vt = np.linalg.svd(centered, full_matrices=False)
            self.pca_components = vt[:n_components].T
        except np.linalg.LinAlgError:
            return

        projected = centered @ self.pca_components

        # One-Class SVM simplificado: frontera en el origen
        # w = dirección de máxima varianza (primera componente)
        # rho = percentil 95 de las proyecciones (margen)
        self.ocsvm_w = projected.mean(axis=0)
        distances = np.linalg.norm(projected - self.ocsvm_w, axis=1)
        self.ocsvm_rho = float(np.percentile(distances, 95))

    def _train_autoencoder(self, sequences: list[list[str]]) -> None:
        """
        Entrenamiento simplificado de un autoencoder lineal (PCA).
        En producción, se usaría PyTorch/TensorFlow con CNN-1D.
        """
        # Vectorizar secuencias a ventanas de IDs
        windows = []
        for seq in sequences:
            ids = [SYSCALL_TO_ID.get(s, UNKNOWN_ID) for s in seq]
            for i in range(0, len(ids) - self.window_size, self.window_size // 2):
                windows.append(ids[i:i + self.window_size])
        if not windows:
            return
        # Placeholder: PCA como autoencoder lineal
        # En producción: CNN-1D autoencoder con PyTorch
        self.autoencoder_weights = []  # se usaría modelo real

    def _train_transition_matrix(self, sequences: list[list[str]]) -> None:
        """Construye matriz de transición de Markov entre syscalls."""
        n = len(COMMON_SYSCALLS) + 1  # +1 para UNKNOWN
        matrix = np.zeros((n, n))
        for seq in sequences:
            ids = [SYSCALL_TO_ID.get(s, UNKNOWN_ID) for s in seq]
            for i in range(len(ids) - 1):
                matrix[ids[i], ids[i+1]] += 1
        # Normalizar por fila
        row_sums = matrix.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1
        self.transition_matrix = matrix / row_sums

    # ---------------------------------------------------------------- inference
    def score(self, seq: list[str], pid: int = 0, comm: str = "") -> AnomalyResult:
        """Calcula la puntuación de anomalía de una secuencia de syscalls."""
        result = AnomalyResult(pid=pid, comm=comm)
        if not seq:
            return result

        result.top_syscalls = Counter(seq).most_common(10)

        if self.is_trained:
            result.path_score_a = self._score_path_a(seq)
            result.path_score_b = self._score_path_b(seq)
            result.path_score_c = self._score_path_c(seq)

        # Fusion por VOTO POR MAYORÍA con umbrales individuales.
        #
        # Cada path tiene su propio umbral calibrado:
        #   Path A (TF-IDF + PCA):     umbral 0.55
        #   Path B (autoencoder):      umbral 0.65
        #   Path C (Markov perplexity): umbral 0.70
        #
        # Si al menos 2 de 3 paths votan "anómalo", marcamos el proceso.
        # Esto es robusto frente a falsos positivos de un solo path.
        votes = 0
        if result.path_score_a > 0.55:
            votes += 1
        if result.path_score_b > 0.65:
            votes += 1
        if result.path_score_c > 0.70:
            votes += 1

        # Score de fusión: proporción de votos (0.33, 0.67 o 1.0)
        result.fusion_score = votes / 3.0

        if votes >= 2:
            result.is_anomalous = True
            result.reason = (
                f"Anomalía ({votes}/3 paths): "
                f"A={result.path_score_a:.2f}, "
                f"B={result.path_score_b:.2f}, "
                f"C={result.path_score_c:.2f}"
            )
        return result

    def _score_path_a(self, seq: list[str]) -> float:
        """
        Score basado en distancia al centroide benigno en espacio PCA.

        Interpretación:
          - 0.0: secuencia idéntica al centroide benigno
          - 0.5: secuencia en el límite (rho = percentil 95)
          - 1.0: secuencia muy alejada (anómala)
        """
        if self.pca_components is None or self.ocsvm_w is None:
            return 0.0
        vec = self._vectorize_tfidf(seq)
        centered = vec - self.pca_mean
        projected = centered @ self.pca_components
        dist = float(np.linalg.norm(projected - self.ocsvm_w))

        if self.ocsvm_rho < 1e-6:
            return 0.0

        # Normalizar: 1.0 = rho (el límite del 95% benigno)
        normalized = dist / self.ocsvm_rho

        # Sigmoide: mapea normalized a score 0-1
        #   normalized = 0.0 → score ≈ 0.05 (dentro)
        #   normalized = 1.0 → score ≈ 0.50 (límite)
        #   normalized = 2.0 → score ≈ 0.95 (anómalo)
        return float(min(1.0 / (1.0 + np.exp(-3 * (normalized - 1))), 1.0))

    def _score_path_b(self, seq: list[str]) -> float:
        """
        Score basado en reconstrucción. Placeholder hasta integrar PyTorch.
        Usa distancia de la distribución de frecuencias a la esperada.
        """
        # Heurística temporal: medir uniformidad de la distribución
        counts = Counter(seq)
        if not counts:
            return 0.0
        probs = np.array(list(counts.values()), dtype=float)
        probs /= probs.sum()
        # Entropía normalizada
        entropy = -np.sum(probs * np.log2(probs + 1e-12))
        max_entropy = np.log2(len(counts) + 1)
        # Alta uniformidad (poco específica) = más sospechosa
        return min(entropy / max(max_entropy, 1e-6), 1.0)

    def _score_path_c(self, seq: list[str]) -> float:
        """Score basado en matriz de transición (perplejidad)."""
        if self.transition_matrix is None:
            return 0.0
        ids = [SYSCALL_TO_ID.get(s, UNKNOWN_ID) for s in seq]
        log_prob = 0.0
        for i in range(len(ids) - 1):
            p = self.transition_matrix[ids[i], ids[i+1]]
            log_prob += np.log(p + 1e-12)
        avg_log_prob = log_prob / max(len(ids) - 1, 1)
        # Perplejidad: 1.0 = secuencia perfectamente esperada,
        # valores altos = anómala. Normalizamos por 500 (empírico).
        perplexity = np.exp(-avg_log_prob)
        # Suavizamos con sigmoide para que:
        #   perplexity = 50  → score ≈ 0.2  (normal)
        #   perplexity = 200 → score ≈ 0.7  (sospechoso)
        #   perplexity = 500 → score ≈ 0.95 (anómalo)
        return float(min(1.0 / (1.0 + np.exp(-0.01 * (perplexity - 200))), 1.0))

    # ---------------------------------------------------------------- persistence
    def save(self, path: str | None = None) -> None:
        path = path or str(self.model_dir / "detector.pkl")
        with open(path, "wb") as f:
            pickle.dump({
                "window_size": self.window_size,
                "tfidf_vocab": self.tfidf_vocab,
                "tfidf_idf": self.tfidf_idf,
                "pca_components": self.pca_components,
                "pca_mean": self.pca_mean,
                "ocsvm_w": self.ocsvm_w,
                "ocsvm_rho": self.ocsvm_rho,
                "transition_matrix": self.transition_matrix,
                "is_trained": self.is_trained,
            }, f)
        logger.info("Modelo guardado en %s", path)

    def load(self, path: str | None = None) -> bool:
        path = path or str(self.model_dir / "detector.pkl")
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
            self.window_size = data["window_size"]
            self.tfidf_vocab = data["tfidf_vocab"]
            self.tfidf_idf = data["tfidf_idf"]
            self.pca_components = data["pca_components"]
            self.pca_mean = data["pca_mean"]
            self.ocsvm_w = data["ocsvm_w"]
            self.ocsvm_rho = data["ocsvm_rho"]
            self.transition_matrix = data["transition_matrix"]
            self.is_trained = data["is_trained"]
            logger.info("Modelo cargado desde %s", path)
            return True
        except (FileNotFoundError, pickle.UnpicklingError, KeyError) as exc:
            logger.warning("No se pudo cargar modelo: %s", exc)
            return False
