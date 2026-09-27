"""
core/cti_feed.py
Consumidor de feeds de inteligencia de amenazas.

Soporta dos tipos de feeds:
  1. Feeds REST públicos sin autenticación (Feodo Tracker, Spamhaus DROP).
  2. Feeds REST con Auth-Key gratuita (URLhaus, ThreatFox de abuse.ch).

Extrae IOCs y los expone en IOCStore para consulta rápida:
  - IPs maliciosas (IPv4)
  - Dominios maliciosos
  - Hashes SHA-256
  - URLs maliciosas

Los feeds sin auth están activos por defecto. Los feeds con auth requieren
una Auth-Key gratuita de abuse.ch (https://auth.abuse.ch/).

Uso:
    cti = CTIClient()
    cti.update_now()
    if cti.store.is_malicious_ip("1.2.3.4"): ...
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from dataclasses import dataclass, field

import requests

logger = logging.getLogger("antivirus.cti")

REQUEST_TIMEOUT = 30


# ============================================================
#  IOC STORE
# ============================================================
@dataclass
class IOCStore:
    """Contenedor thread-safe de IOCs extraídos de feeds CTI."""
    ipv4: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    sha256: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    cidr_ranges: list = field(default_factory=list)  # rangos Spamhaus

    def is_malicious_ip(self, ip: str) -> bool:
        if ip in self.ipv4:
            return True
        # Verificar rangos CIDR (Spamhaus DROP)
        try:
            addr = ipaddress.ip_address(ip)
            for net in self.cidr_ranges:
                if addr in net:
                    return True
        except ValueError:
            pass
        return False

    def is_malicious_domain(self, domain: str) -> bool:
        return domain.lower() in self.domains

    def is_malicious_hash(self, sha256_hash: str) -> bool:
        return sha256_hash.lower() in self.sha256

    def is_malicious_url(self, url: str) -> bool:
        return url in self.urls

    def total(self) -> int:
        return (
            len(self.ipv4)
            + len(self.domains)
            + len(self.sha256)
            + len(self.urls)
            + len(self.cidr_ranges)
        )


# ============================================================
#  FEEDS POR DEFECTO
# ============================================================
# Feeds sin autenticación (siempre activos)
DEFAULT_FEEDS_NO_AUTH = [
    {
        "name": "Feodo Tracker (abuse.ch)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "type": "feodo_json",
    },
    {
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "spamhaus_drop",
    },
]

# Feeds con Auth-Key gratuita de abuse.ch (https://auth.abuse.ch/)
# Deja auth_key vacío para deshabilitarlos.
DEFAULT_FEEDS_AUTH = [
    {
        "name": "URLhaus (abuse.ch)",
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "type": "urlhaus_json",
        "auth_key": "",  # <-- pega tu Auth-Key aquí
    },
    {
        "name": "ThreatFox (abuse.ch)",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "type": "threatfox_json",
        "auth_key": "",  # <-- pega tu Auth-Key aquí
    },
]


# ============================================================
#  CTI CLIENT
# ============================================================
class CTIClient:
    def __init__(self, feeds: list | None = None):
        """
        :param feeds: lista de dicts con la configuración de feeds. Si es
                      None, se usan DEFAULT_FEEDS_NO_AUTH + DEFAULT_FEEDS_AUTH.
        """
        if feeds is None:
            feeds = list(DEFAULT_FEEDS_NO_AUTH)
            # Solo añadir feeds con auth si tienen auth_key
            for f in DEFAULT_FEEDS_AUTH:
                if f.get("auth_key"):
                    feeds.append(f)

        self.feeds = feeds
        self.store = IOCStore()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.last_update_ts: float = 0.0
        self.last_error: str | None = None
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "AntivirusLinuxDragon/1.0 (+https://github.com/jean020889/Antivirus_Linux_Daemon)"
        })

    # ----------------------------------------------------------- public API
    def start(self, interval_seconds: int = 3600) -> bool:
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
        """Fuerza una actualización sincrónica. Devuelve total de IOCs."""
        for feed in self.feeds:
            name = feed.get("name", feed.get("url", "?"))
            try:
                self._fetch_feed(feed)
                logger.info("Feed OK: %s", name)
            except Exception as exc:
                self.last_error = str(exc)[:200]
                logger.warning("Fallo al consumir feed %s: %s", name, self.last_error)
        self.last_update_ts = time.time()
        return self.store.total()

    # ----------------------------------------------------------- internal
    def _loop(self, interval: int) -> None:
        while not self._stop.is_set():
            self.update_now()
            self._stop.wait(interval)

    def _fetch_feed(self, feed: dict) -> None:
        feed_type = feed.get("type")
        url = feed["url"]
        auth_key = feed.get("auth_key", "")

        headers = {}
        if auth_key:
            headers["Auth-Key"] = auth_key

        # ThreatFox usa POST en lugar de GET
        if feed_type == "threatfox_json":
            payload = {"query": "get_iocs", "days": 1}
            response = self._session.post(
                url,
                data=payload,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
        else:
            response = self._session.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

        response.raise_for_status()

        # Dispatch según tipo
        if feed_type == "feodo_json":
            self._parse_feodo(response.json())
        elif feed_type == "spamhaus_drop":
            self._parse_spamhaus(response.text)
        elif feed_type == "urlhaus_json":
            self._parse_urlhaus(response.json())
        elif feed_type == "threatfox_json":
            self._parse_threatfox(response.json())
        else:
            logger.warning("Tipo de feed desconocido: %s", feed_type)

    # ----------------------------------------------------------- parsers
    def _parse_feodo(self, data) -> None:
        """Feodo Tracker: JSON con array de objetos {ip_address, malware, ...}"""
        if not isinstance(data, list):
            logger.warning("Feodo: formato inesperado, esperaba lista")
            return
        count = 0
        with self._lock:
            for entry in data:
                ip = entry.get("ip_address")
                if ip:
                    self.store.ipv4.add(ip)
                    count += 1
        logger.info("  Feodo: +%d IPs (total IPs: %d)", count, len(self.store.ipv4))

    def _parse_spamhaus(self, text: str) -> None:
        """Spamhaus DROP: texto plano con líneas '<CIDR> ; <referencia>'"""
        count = 0
        with self._lock:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                cidr = line.split(";")[0].strip()
                if not cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    self.store.cidr_ranges.append(net)
                    count += 1
                except ValueError:
                    continue
        logger.info("  Spamhaus: +%d rangos CIDR (total: %d)", count, len(self.store.cidr_ranges))

    def _parse_urlhaus(self, data: dict) -> None:
        """URLhaus: JSON con lista de URLs maliciosas."""
        urls = data.get("urls", [])
        count = 0
        with self._lock:
            for entry in urls:
                url = entry.get("url")
                if url:
                    self.store.urls.add(url)
                    count += 1
                # Hostnames / IPs relacionados
                host = entry.get("host")
                if host:
                    self.store.domains.add(host.lower())
        logger.info("  URLhaus: +%d URLs", count)

    def _parse_threatfox(self, data: dict) -> None:
        """ThreatFox: JSON con query_status + data[]."""
        if data.get("query_status") != "ok":
            logger.warning("ThreatFox: query_status=%s", data.get("query_status"))
            return
        iocs = data.get("data", [])
        count_ip = count_dom = count_hash = count_url = 0
        with self._lock:
            for entry in iocs:
                ioc_type = entry.get("ioc_type", "")
                ioc_value = entry.get("ioc", "")
                if not ioc_value:
                    continue
                if ioc_type == "ip:port":
                    ip = ioc_value.split(":")[0]
                    self.store.ipv4.add(ip)
                    count_ip += 1
                elif ioc_type == "domain":
                    self.store.domains.add(ioc_value.lower())
                    count_dom += 1
                elif ioc_type in ("sha256_hash", "md5_hash"):
                    if ioc_type == "sha256_hash":
                        self.store.sha256.add(ioc_value.lower())
                        count_hash += 1
                elif ioc_type == "url":
                    self.store.urls.add(ioc_value)
                    count_url += 1
        logger.info(
            "  ThreatFox: +%d IPs, +%d dominios, +%d hashes, +%d URLs",
            count_ip, count_dom, count_hash, count_url,
        )
