"""
Tests de CTIClient e IOCStore.

Foco:
  - IOCStore: consultas is_malicious_* y total()
  - Parser de patrones STIX: extracción correcta de IPv4, dominio, SHA-256, URL
  - _ingest_stix_object: ignora tipos no-indicator, ignora patterns vacíos
  - update_now(): recorre feeds y actualiza store
  - start()/stop(): ciclo de vida del hilo
  - Resiliencia: un feed que falla no aborta los demás
"""
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from core.cti_feed import CTIClient, IOCStore, HAVE_TAXII


class TestIOCStore:
    def test_vacio_por_defecto(self):
        store = IOCStore()
        assert store.total() == 0
        assert not store.is_malicious_ip("1.2.3.4")
        assert not store.is_malicious_domain("evil.com")
        assert not store.is_malicious_hash("abc")
        assert not store.is_malicious_url("http://evil.com")

    def test_agrega_y_consulta(self):
        store = IOCStore()
        store.ipv4.add("1.2.3.4")
        store.domains.add("evil.com")
        store.sha256.add("ABC123".lower())
        store.urls.add("http://evil.com/payload")
        assert store.is_malicious_ip("1.2.3.4")
        assert store.is_malicious_domain("evil.com")
        assert store.is_malicious_hash("abc123")
        assert store.is_malicious_url("http://evil.com/payload")
        assert store.total() == 4

    def test_dominio_case_insensitive(self):
        store = IOCStore()
        store.domains.add("evil.com")
        assert store.is_malicious_domain("EVIL.COM")
        assert store.is_malicious_domain("Evil.Com")


class TestParserSTIX:
    def setup_method(self):
        self.client = CTIClient(feeds=[])

    def test_extrae_ipv4(self):
        pattern = "[ipv4-addr:value = '1.2.3.4']"
        assert CTIClient._extract(pattern, "ipv4-addr:value") == "1.2.3.4"

    def test_extrae_ipv4_con_comillas_dobles(self):
        pattern = '[ipv4-addr:value = "5.6.7.8"]'
        assert CTIClient._extract(pattern, "ipv4-addr:value") == "5.6.7.8"

    def test_extrae_dominio(self):
        pattern = "[domain-name:value = 'evil.example.com']"
        assert CTIClient._extract(pattern, "domain-name:value") == "evil.example.com"

    def test_extrae_sha256(self):
        pattern = "[file:hashes.'SHA-256' = 'abc123def456']"
        assert CTIClient._extract(pattern, "file:hashes.'SHA-256'") == "abc123def456"

    def test_extrae_url(self):
        pattern = "[url:value = 'http://malicious.com/payload.bin']"
        assert CTIClient._extract(pattern, "url:value") == "http://malicious.com/payload.bin"

    def test_pattern_sin_match_devuelve_none(self):
        assert CTIClient._extract("pattern sin valor", "ipv4-addr:value") is None


class TestIngestSTIXObject:
    def setup_method(self):
        self.client = CTIClient(feeds=[])

    def test_ingiere_ipv4(self):
        self.client._ingest_stix_object({
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
        })
        assert "1.2.3.4" in self.client.store.ipv4

    def test_ingiere_dominio(self):
        self.client._ingest_stix_object({
            "type": "indicator",
            "pattern": "[domain-name:value = 'bad.com']",
        })
        assert "bad.com" in self.client.store.domains

    def test_ingiere_sha256(self):
        self.client._ingest_stix_object({
            "type": "indicator",
            "pattern": "[file:hashes.'SHA-256' = 'DEADBEEF']",
        })
        # Debe normalizarse a minúsculas
        assert "deadbeef" in self.client.store.sha256

    def test_ingiere_url(self):
        self.client._ingest_stix_object({
            "type": "indicator",
            "pattern": "[url:value = 'http://evil.com/x']",
        })
        assert "http://evil.com/x" in self.client.store.urls

    def test_ignora_objeto_no_indicator(self):
        self.client._ingest_stix_object({
            "type": "malware",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
        })
        assert self.client.store.total() == 0

    def test_ignora_pattern_vacio(self):
        self.client._ingest_stix_object({
            "type": "indicator",
            "pattern": "",
        })
        assert self.client.store.total() == 0

    def test_ignora_pattern_que_no_es_string(self):
        self.client._ingest_stix_object({
            "type": "indicator",
            "pattern": None,
        })
        assert self.client.store.total() == 0


class TestFetchFeed:
    def test_fetch_feed_con_bundle_sintetico(self):
        """Parchea Server para devolver un bundle con IOCs."""
        client = CTIClient(feeds=[])

        fake_indicator = {
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '10.20.30.40']",
        }
        fake_indicator2 = {
            "type": "indicator",
            "pattern": "[domain-name:value = 'malicious.example']",
        }

        mock_collection = MagicMock()
        mock_collection.id = "fake-collection"
        mock_collection.get_objects.return_value = {
            "objects": [fake_indicator, fake_indicator2],
        }

        mock_api_root = MagicMock()
        mock_api_root.collections = [mock_collection]

        mock_server = MagicMock()
        mock_server.api_roots = [mock_api_root]

        with patch("core.cti_feed.Server", return_value=mock_server):
            with patch("core.cti_feed.HAVE_TAXII", True):
                client._fetch_feed("https://fake.example/taxii/", "u", "p")

        assert "10.20.30.40" in client.store.ipv4
        assert "malicious.example" in client.store.domains


class TestCTILifecycle:
    def test_start_sin_taxii_devuelve_false(self):
        client = CTIClient(feeds=[])
        with patch("core.cti_feed.HAVE_TAXII", False):
            assert client.start() is False

    def test_start_y_stop_con_mock(self):
        client = CTIClient(feeds=[])
        # Mockeamos _fetch_feed para que no haga red real
        with patch.object(client, "_fetch_feed", return_value=None):
            with patch("core.cti_feed.HAVE_TAXII", True):
                assert client.start(interval_seconds=1) is True
                time.sleep(0.2)
                client.stop()
        # Tras stop, el hilo no debe estar vivo
        assert not (client._thread and client._thread.is_alive())

    def test_update_now_llama_fetch(self):
        client = CTIClient(feeds=[("https://fake.example/", "u", "p")])
        with patch.object(client, "_fetch_feed") as mock_fetch:
            client.update_now()
            mock_fetch.assert_called_once_with("https://fake.example/", "u", "p")

    def test_update_now_actualiza_timestamp(self):
        client = CTIClient(feeds=[])
        before = client.last_update_ts
        client.update_now()
        assert client.last_update_ts > before

    def test_update_now_resiliente_a_feed_caido(self):
        """Un feed que falla no debe abortar el resto."""
        client = CTIClient(feeds=[
            ("https://falla.example/", "u", "p"),
            ("https://ok.example/", "u", "p"),
        ])
        calls = []
        def fake_fetch(url, user, pw):
            calls.append(url)
            if "falla" in url:
                raise RuntimeError("feed caído")
        with patch.object(client, "_fetch_feed", side_effect=fake_fetch):
            client.update_now()
        # Ambos fueron intentados
        assert calls == ["https://falla.example/", "https://ok.example/"]
        assert client.last_error is not None

    def test_double_start_no_lanza(self):
        client = CTIClient(feeds=[])
        with patch.object(client, "_fetch_feed", return_value=None):
            with patch("core.cti_feed.HAVE_TAXII", True):
                assert client.start(interval_seconds=10) is True
                assert client.start(interval_seconds=10) is True
                client.stop()
