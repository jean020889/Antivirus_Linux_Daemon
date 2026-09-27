"""
Tests de FIPSCrypto. Verifican que el wrapper funciona independientemente
de si el backend FIPS está activo.
"""
import os

import pytest

from core.crypto_fips import FIPSCrypto


@pytest.fixture
def crypto():
    return FIPSCrypto()


class TestFIPSCrypto:
    def test_aes_gcm_roundtrip(self, crypto):
        key = os.urandom(32)
        plaintext = b"mensaje secreto"
        nonce, ct = crypto.aes_gcm_encrypt(key, plaintext)
        recovered = crypto.aes_gcm_decrypt(key, nonce, ct)
        assert recovered == plaintext

    def test_aes_gcm_rechaza_clave_corta(self, crypto):
        with pytest.raises(ValueError):
            crypto.aes_gcm_encrypt(b"corta", b"data")

    def test_aes_gcm_detecta_manipulacion(self, crypto):
        key = os.urandom(32)
        nonce, ct = crypto.aes_gcm_encrypt(key, b"data")
        # Manipular el ciphertext
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(Exception):
            crypto.aes_gcm_decrypt(key, nonce, tampered)

    def test_aes_gcm_con_aad(self, crypto):
        key = os.urandom(32)
        nonce, ct = crypto.aes_gcm_encrypt(key, b"data", aad=b"metadata")
        recovered = crypto.aes_gcm_decrypt(key, nonce, ct, aad=b"metadata")
        assert recovered == b"data"

    def test_derive_key_deterministico(self, crypto):
        salt = os.urandom(16)
        k1 = crypto.derive_key(b"password", salt, iterations=1000)
        k2 = crypto.derive_key(b"password", salt, iterations=1000)
        assert k1 == k2
        assert len(k1) == 32

    def test_derive_key_distinto_salt(self, crypto):
        k1 = crypto.derive_key(b"password", os.urandom(16), iterations=1000)
        k2 = crypto.derive_key(b"password", os.urandom(16), iterations=1000)
        assert k1 != k2

    def test_sha256(self, crypto):
        h = crypto.sha256(b"test")
        assert len(h) == 64
        assert h == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
