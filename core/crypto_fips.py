"""
core/crypto_fips.py
Wrapper criptográfico FIPS-140-3 aware.

Usa el backend 'cryptography' y verifica si el proveedor FIPS está activo.
Si no lo está, registra la degradación (requisito de auditoría).
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("antivirus.crypto")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class FIPSCrypto:
    def __init__(self):
        self.fips_enabled = self._detect_fips()
        if not self.fips_enabled:
            logger.warning(
                "FIPS 140-3 NO activo. Para cumplimiento, instala y habilita "
                "un proveedor FIPS y exporta OPENSSL_CONF apuntando a la config FIPS."
            )

    @staticmethod
    def _detect_fips() -> bool:
        try:
            from cryptography.hazmat.backends.openssl.backend import backend
            return getattr(backend, "_fips_enabled", False)
        except Exception:
            return False

    def aes_gcm_encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requiere clave de 32 bytes")
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
        return nonce, ct

    def aes_gcm_decrypt(self, key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
        return AESGCM(key).decrypt(nonce, ct, aad)

    def derive_key(self, password: bytes, salt: bytes, iterations: int = 600_000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        return kdf.derive(password)

    def sha256(self, data: bytes) -> str:
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize().hex()
