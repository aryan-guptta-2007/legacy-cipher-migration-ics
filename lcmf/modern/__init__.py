"""Modern cryptography engine: AES (from scratch + library), modes, keys, nonces, replay.

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from .aead import EducationalAESGCM, LibraryAESGCM, get_engine
from .aes_core import AES
from .aes_modes import AuthenticationError
from .keystore import DOWNLINK, UPLINK, KeyStore, LegacyDerivedKeyStore
from .nonce import NonceManager
from .replay import ReplayWindow

__all__ = [
    "AES", "AuthenticationError", "EducationalAESGCM", "LibraryAESGCM", "get_engine",
    "KeyStore", "LegacyDerivedKeyStore", "UPLINK", "DOWNLINK", "NonceManager", "ReplayWindow",
]
