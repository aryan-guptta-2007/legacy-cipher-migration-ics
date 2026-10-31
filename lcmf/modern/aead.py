"""AEAD engines with one interface: AES-256-GCM via two interchangeable back ends.

* ``library``     - pyca/cryptography (OpenSSL, constant time, AES-NI).  This is
                    the production path of the gateway.
* ``educational`` - the from-scratch implementation in :mod:`aes_modes`; it
                    produces bit-identical output and is used for verification
                    and teaching.

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .aes_core import AES
from .aes_modes import AuthenticationError, gcm_decrypt, gcm_encrypt

TAG_LEN = 16
NONCE_LEN = 12


class AEADEngine:
    name = "abstract"

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.key = key

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Return ciphertext || 16-byte tag."""
        raise NotImplementedError

    def open(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        """Verify and decrypt ``ciphertext || tag``; raise AuthenticationError on failure."""
        raise NotImplementedError


class LibraryAESGCM(AEADEngine):
    name = "library"

    def __init__(self, key: bytes):
        super().__init__(key)
        self._aead = AESGCM(key)

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._aead.encrypt(nonce, plaintext, aad)

    def open(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        try:
            return self._aead.decrypt(nonce, data, aad)
        except InvalidTag:
            raise AuthenticationError("GCM tag mismatch") from None


class EducationalAESGCM(AEADEngine):
    name = "educational"

    def __init__(self, key: bytes):
        super().__init__(key)
        self._aes = AES(key)          # key schedule expanded once

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        ct, tag = gcm_encrypt(self._aes, nonce, plaintext, aad)
        return ct + tag

    def open(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        if len(data) < TAG_LEN:
            raise AuthenticationError("ciphertext shorter than tag")
        return gcm_decrypt(self._aes, nonce, data[:-TAG_LEN], data[-TAG_LEN:], aad)


ENGINES = {"library": LibraryAESGCM, "educational": EducationalAESGCM}


def get_engine(name: str, key: bytes) -> AEADEngine:
    try:
        return ENGINES[name](key)
    except KeyError:
        raise ValueError(f"unknown AEAD engine {name!r}; choose from {sorted(ENGINES)}") from None
