"""
core/cti_feed.py
Consumidor de feeds de inteligencia de amenazas en STIX 2.1 vía TAXII 2.1.

Soporta múltiples servidores (Anomali Limo, CIRCL, feeds privados).
Extrae IOCs (indicators) y los expone en IOCStore para consulta rápida:
  - IPs maliciosas
  - Dominios maliciosos
  - Hashes SHA-256 de archivos
  - URLs maliciosas

Uso básico:
    cti = CTIClient(feeds=[("https://limo.anomali.com/api/v1/taxii2/taxii/", "guest", "guest")])
    cti.start(interval_seconds=3600)
    ...
    if cti.store.is_malicious_ip("1.2.3.4"):
        soar.block_ip("1.2.3.4")

Si taxii2-client no está instalado, CTIClient funciona igual pero
start() devuelve False y el store queda vacío.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger("antivirus.cti")

try:
    from taxii2client.v21 import Server
    HAVE_TAXII = True
except ImportError:
    # Fallback para permitir tests sin la dependencia instalada.
    # El código que use Server real debe comprobar HAVE_TAXII primero.
    Server = None  # type: ignore[assignment]
    HAVE_TAXII = False


@dataclass
class IOCStore:
    """Contenedor thread-safe de IOCs extraídos de feeds CTI."""
    ipv4: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    sha256: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)

    def is_malicious_ip(self, ip: str) -> bool:
        return ip in self.ipv4

    def is_malicious_domain(self, domain: str) -> bool:
        return domain.lower() in self.domains

    def is_malicious_hash(self, sha256_hash: str) -> bool:
        return sha256_hash.lower() in self.sha256

    def is_malicious_url(self, url: str) -> bool:
        return url in self.urls

    def total(self) -> int:
        return len(self.ipv4) + len(self.domains) + len(self.sha256) + len(self.urls)


# Feeds públicos por defecto (Anomali Limo: guest/guest)
DEFAULT_FEEDS = [
    ("https://limo.anomali.com/api/v1/taxii2/taxii/", "guest", "guest"),
]


class CTIClient:
    def __init__(self, feeds: list | None = None):
        self.feeds = feeds if feeds is not None else DEFAULT_FEEDS
        self.store = IOCStore()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.last_update_ts: float = 0.0
        self.last_error: str | None = None

    # ----------------------------------------------------------- public API
    def start(self, interval_seconds: int = 3600) -> bool:
        """
        Arranca el hilo de actualización periódica.
        Devuelve True si el hilo se lanzó, False si taxii2-client no está instalado.
        """
        if not HAVE_TAXII:
            logger.warning("taxii2-client no instalado; CTI deshabilitado.")
            return False
        if self._thread and self._thread.is_alive():
            logger.warning("CTI ya está corriendo.")
            return True
        self._thread = threading.Thread(
            target=self._loop,
            args=(interval_seconds,),
            name="cti-feed",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def update_now(self) -> int:
        """
        Fuerza una actualización sincrónica. Devuelve el total de IOCs
        tras la actualización.
        """
        for feed in self.feeds:
            try:
                self._fetch_feed(*feed)
            except Exception as exc:
                self.last_error = str(exc)
                logger.exception("Fallo al consumir feed %s", feed[0])
        self.last_update_ts = time.time()
        return self.store.total()

    # ----------------------------------------------------------- internal
    def _loop(self, interval: int) -> None:
        while not self._stop.is_set():
            self.update_now()
            self._stop.wait(interval)

    def _fetch_feed(self, url: str, user: str = "", password: str = "") -> None:
        """Recorre las colecciones de un servidor TAXII y consume sus objetos."""
        server = Server(url, user=user, password=password)
        roots = server.api_roots
        if not roots:
            logger.warning("TAXII server sin api_roots: %s", url)
            return

        for api_root in roots:
            try:
                collections = list(api_root.collections)
            except Exception as exc:
                logger.warning("No se pudieron listar colecciones de %s: %s", url, exc)
                continue

            for collection in collections:
                try:
                    bundle = collection.get_objects()
                except Exception as exc:
                    logger.debug("Error leyendo colección %s: %s", getattr(collection, "id", "?"), exc)
                    continue

                for obj in bundle.get("objects", []):
                    self._ingest_stix_object(obj)

        logger.info("CTI actualizado: %d IPs, %d dominios, %d hashes, %d URLs",
                    len(self.store.ipv4), len(self.store.domains),
                    len(self.store.sha256), len(self.store.urls))

    def _ingest_stix_object(self, obj: dict) -> None:
        """Extrae IOCs de un objeto STIX 2.1 de tipo 'indicator'."""
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            return
        pattern = obj.get("pattern", "")
        if not isinstance(pattern, str):
            return

        with self._lock:
            if "ipv4-addr:value" in pattern:
                ip = self._extract(pattern, "ipv4-addr:value")
                if ip:
                    self.store.ipv4.add(ip)

            elif "domain-name:value" in pattern:
                d = self._extract(pattern, "domain-name:value")
                if d:
                    self.store.domains.add(d.lower())

            elif "file:hashes.'SHA-256'" in pattern or 'file:hashes."SHA-256"' in pattern:
                h = self._extract(pattern, "file:hashes.'SHA-256'") or \
                    self._extract(pattern, 'file:hashes."SHA-256"')
                if h:
                    self.store.sha256.add(h.lower())

            elif "url:value" in pattern:
                u = self._extract(pattern, "url:value")
                if u:
                    self.store.urls.add(u)

    @staticmethod
    def _extract(pattern: str, key: str) -> str | None:
        """
        Extrae el valor de un patrón STIX del tipo:
            [ipv4-addr:value = '1.2.3.4']
        Devuelve None si no se encuentra.
        """
        marker_double = f'{key} = "'
        marker_single = f"{key} = '"
        for marker in (marker_double, marker_single):
            i = pattern.find(marker)
            if i < 0:
                continue
            quote = marker[-1]
            j = pattern.find(quote, i + len(marker))
            if j > i:
                return pattern[i + len(marker):j]
        return None
