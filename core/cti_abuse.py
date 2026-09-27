# core/cti_abuse.py
import requests
import json
import os
from datetime import datetime, timedelta

class AbuseCHIntel:
    def __init__(self, auth_key, cache_dir="./cti_cache", cache_ttl_hours=24):
        self.auth_key = auth_key
        self.cache_dir = cache_dir
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        os.makedirs(cache_dir, exist_ok=True)
        self.iocs = {"urls": set(), "hashes_md5": set(), "hashes_sha256": set()}
        self._load_cache()

    def _cache_path(self, name):
        return os.path.join(self.cache_dir, f"{name}.json")

    def _is_cache_fresh(self, path):
        if not os.path.exists(path):
            return False
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        return datetime.now() - mtime < self.cache_ttl

    def _load_cache(self):
        for key in ["urls", "hashes"]:
            path = self._cache_path(key)
            if self._is_cache_fresh(path):
                try:
                    with open(path) as f:
                        data = json.load(f)
                        if key == "urls":
                            self.iocs["urls"] = set(data)
                        else:
                            self.iocs["hashes_md5"] = set(data.get("md5", []))
                            self.iocs["hashes_sha256"] = set(data.get("sha256", []))
                except: pass

    def _save_cache(self):
        with open(self._cache_path("urls"), "w") as f:
            json.dump(list(self.iocs["urls"]), f)
        with open(self._cache_path("hashes"), "w") as f:
            json.dump({
                "md5": list(self.iocs["hashes_md5"]),
                "sha256": list(self.iocs["hashes_sha256"])
            }, f)

    def update(self):
        headers = {"Auth-Key": self.auth_key}

        try:
            r = requests.get(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers=headers, timeout=30
            )
            if r.status_code == 200:
                for entry in r.json().get("urls", []):
                    self.iocs["urls"].add(entry.get("url"))
                    if entry.get("md5_hash"):
                        self.iocs["hashes_md5"].add(entry["md5_hash"])
        except Exception as e:
            print(f"[!] URLhaus error: {e}")

        try:
            r = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                headers=headers,
                json={"query": "get_iocs", "days": 1},
                timeout=30
            )
            if r.status_code == 200:
                for entry in r.json().get("data", []):
                    ioc = entry.get("ioc", "")
                    if entry.get("ioc_type") == "url":
                        self.iocs["urls"].add(ioc)
                    elif entry.get("ioc_type") in ("md5_hash", "sha256_hash"):
                        if len(ioc) == 32:
                            self.iocs["hashes_md5"].add(ioc)
                        elif len(ioc) == 64:
                            self.iocs["hashes_sha256"].add(ioc)
        except Exception as e:
            print(f"[!] ThreatFox error: {e}")

        self._save_cache()
        print(f"[+] CTI actualizado: {len(self.iocs['urls'])} URLs, "
              f"{len(self.iocs['hashes_md5'])} MD5, "
              f"{len(self.iocs['hashes_sha256'])} SHA256")

    def check_hash(self, hash_value):
        h = hash_value.lower()
        if len(h) == 32:
            return h in self.iocs["hashes_md5"]
        elif len(h) == 64:
            return h in self.iocs["hashes_sha256"]
        return False

    def check_url(self, url):
        return url in self.iocs["urls"]
