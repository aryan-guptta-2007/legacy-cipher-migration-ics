"""Key management: per-device, per-direction AES-256 keys derived with HKDF.

A single high-entropy master key (32 random bytes) is provisioned to the
gateway and the SCADA master.  Working keys are derived with HKDF-SHA256
(RFC 5869) so that compromise of one device key exposes nothing else, and
rotation only requires bumping the ``key_id``.

``LegacyDerivedKeyStore`` reproduces a tempting migration shortcut - hashing
the old legacy keyword into an AES key - and is used only by experiment TV7
to show why that shortcut inherits the legacy key space.

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

UPLINK = "up"      # field -> control centre (telemetry)
DOWNLINK = "down"  # control centre -> field (commands)


class KeyStore:
    def __init__(self, master_key: bytes | None = None, key_id: int = 1):
        self.master_key = master_key if master_key is not None else os.urandom(32)
        if len(self.master_key) < 32:
            raise ValueError("master key must be at least 256 bits")
        self.current_key_id = key_id
        self._cache: dict[tuple[int, int, str], bytes] = {}

    def derive(self, device_id: int, direction: str, key_id: int | None = None) -> bytes:
        key_id = self.current_key_id if key_id is None else key_id
        cache_key = (key_id, device_id, direction)
        if cache_key not in self._cache:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=key_id.to_bytes(4, "big"),
                info=f"LCMF-v1|dev={device_id}|dir={direction}".encode(),
            )
            self._cache[cache_key] = hkdf.derive(self.master_key)
        return self._cache[cache_key]

    def rotate(self) -> int:
        """Start using a new key generation; old generations remain derivable."""
        self.current_key_id += 1
        return self.current_key_id

    @property
    def effective_key_bits(self) -> int:
        return len(self.master_key) * 8


class LegacyDerivedKeyStore(KeyStore):
    """INSECURE: AES key = SHA-256(legacy keyword).  For experiment TV7 only."""

    def __init__(self, legacy_keyword: str, key_id: int = 1):
        self.legacy_keyword = legacy_keyword
        super().__init__(hashlib.sha256(legacy_keyword.encode()).digest(), key_id)

    def derive(self, device_id: int, direction: str, key_id: int | None = None) -> bytes:
        return hashlib.sha256(self.legacy_keyword.encode()).digest()
