# core/cache.py
"""
Sistema de caché para mejorar rendimiento.

- Cache LRU en memoria
- Cache persistente en PostgreSQL
- Cache de firmas (evita recargar de disco)
- Cache de resultados de escaneo (mtime-based)
"""
import os
import time
import hashlib
from collections import OrderedDict
from threading import Lock


class LRUCache:
    """Cache LRU thread-safe."""

    def __init__(self, max_size=10000, ttl=3600):
        self.max_size = max_size
        self.ttl = ttl
        self.cache = OrderedDict()
        self.lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key):
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None

            value, timestamp = self.cache[key]
            if time.time() - timestamp > self.ttl:
                del self.cache[key]
                self.misses += 1
                return None

            # Mover al final (más reciente)
            self.cache.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key, value):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = (value, time.time())

            # Evict si excede max_size
            while len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0

    def stats(self):
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(hit_rate * 100, 2),
        }


class ScanCache:
    """Cache de resultados de escaneo basado en (path, mtime, size)."""

    def __init__(self, max_size=100000, ttl=86400):
        self.cache = LRUCache(max_size=max_size, ttl=ttl)

    def _key(self, filepath):
        """Clave: path + mtime + size."""
        try:
            st = os.stat(filepath)
            key = f"{filepath}:{st.st_mtime}:{st.st_size}"
            return hashlib.md5(key.encode()).hexdigest()
        except Exception:
            return None

    def get(self, filepath):
        key = self._key(filepath)
        if not key:
            return None
        return self.cache.get(key)

    def set(self, filepath, result):
        key = self._key(filepath)
        if key:
            self.cache.set(key, result)

    def stats(self):
        return self.cache.stats()


class SignatureCache:
    """Cache de firmas compiladas."""

    def __init__(self):
        self.yara_rules = None
        self.compiled_regex = {}
        self.hex_patterns = []
        self.lock = Lock()

    def set_yara(self, compiled):
        with self.lock:
            self.yara_rules = compiled

    def get_yara(self):
        return self.yara_rules

    def get_regex(self, pattern):
        with self.lock:
            if pattern not in self.compiled_regex:
                import re
                try:
                    self.compiled_regex[pattern] = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    return None
            return self.compiled_regex[pattern]


# Singletons globales
_scan_cache = None
_sig_cache = None
_cache_lock = Lock()


def get_scan_cache():
    global _scan_cache
    with _cache_lock:
        if _scan_cache is None:
            _scan_cache = ScanCache()
    return _scan_cache


def get_signature_cache():
    global _sig_cache
    with _cache_lock:
        if _sig_cache is None:
            _sig_cache = SignatureCache()
    return _sig_cache
