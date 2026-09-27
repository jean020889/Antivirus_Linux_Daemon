# core/crypto.py
"""
Cifrado FIPS-aware:
- AES-256-GCM (confidencialidad + integridad)
- PBKDF2-HMAC-SHA256 (derivación de clave)
- 600,000 iteraciones (recomendación OWASP 2023)
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class CryptoEngine:
    ITERATIONS = 600000
    SALT_SIZE = 16
    NONCE_SIZE = 12

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=CryptoEngine.ITERATIONS,
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, password: str):
        """Cifra un archivo con AES-256-GCM."""
        salt = os.urandom(CryptoEngine.SALT_SIZE)
        key = CryptoEngine.derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(CryptoEngine.NONCE_SIZE)

        with open(input_path, 'rb') as f:
            plaintext = f.read()

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        with open(output_path, 'wb') as f:
            f.write(b"AVP1")  # Magic header
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        return output_path

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, password: str):
        """Descifra un archivo cifrado con encrypt_file."""
        with open(input_path, 'rb') as f:
            magic = f.read(4)
            if magic != b"AVP1":
                raise ValueError("Formato inválido")
            salt = f.read(CryptoEngine.SALT_SIZE)
            nonce = f.read(CryptoEngine.NONCE_SIZE)
            ciphertext = f.read()

        key = CryptoEngine.derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        with open(output_path, 'wb') as f:
            f.write(plaintext)

        return output_path
