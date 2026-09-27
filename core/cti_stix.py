# core/cti_stix.py
"""
CTI con STIX 2.1 sobre TAXII 2.1.
Integra con threat intel feeds modernos.
"""
import json
import requests
from datetime import datetime


class STIXClient:
    """Cliente STIX 2.1 / TAXII 2.1."""

    def __init__(self, taxii_url, collection_id, api_key=None):
        self.taxii_url = taxii_url.rstrip('/')
        self.collection_id = collection_id
        self.headers = {
            "Accept": "application/taxii+json;version=2.1",
            "Content-Type": "application/taxii+json;version=2.1",
        }
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"

    def get_objects(self, added_after=None, limit=100):
        """Obtiene objetos STIX de una colección TAXII."""
        url = f"{self.taxii_url}/collections/{self.collection_id}/objects/"
        params = {"limit": limit}
        if added_after:
            params["added_after"] = added_after

        try:
            r = requests.get(url, headers=self.headers, params=params, timeout=30)
            r.raise_for_status()
            return r.json().get("objects", [])
        except Exception as e:
            print(f"[!] TAXII error: {e}")
            return []

    def parse_indicators(self, objects):
        """Parsea objetos STIX a IOCs."""
        iocs = []
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            # Extraer de patterns STIX como: [ipv4-addr:value = '1.2.3.4']
            import re
            m = re.search(r"(\w[\w-]*):value\s*=\s*'([^']+)'", pattern)
            if not m:
                continue
            ioc_type, ioc_value = m.groups()
            iocs.append({
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "source": "stix_taxii",
                "threat_type": obj.get("labels", [None])[0],
                "confidence": int(obj.get("confidence", 50)),
                "first_seen": obj.get("created"),
                "last_seen": obj.get("modified"),
                "metadata": obj.get("external_references", []),
            })
        return iocs
