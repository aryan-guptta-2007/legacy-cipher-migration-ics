"""Legacy (classical) cipher suite used by simulated historical RTUs.

Owner: Member 1 (Legacy Cipher Suite & Cryptanalysis)
"""
from __future__ import annotations

from .base import Alphabet, CipherError, ClassicalCipher, NullCipher, Z26, Z36
from .monoalphabetic import AdditiveCipher, AffineCipher, CaesarCipher, mod_inverse, units
from .polyalphabetic import PlayfairCipher, VigenereCipher
from .transposition import ColumnarTranspositionCipher


def make_cipher(spec: dict) -> ClassicalCipher:
    """Build a cipher from a registry spec such as ``{"type": "affine", "a": 5, "b": 8}``."""
    kind = spec["type"].lower()
    alphabet = spec.get("alphabet", Z36)
    if kind in ("none", "plaintext"):
        return NullCipher(alphabet)
    if kind == "caesar":
        return CaesarCipher(alphabet)
    if kind == "additive":
        return AdditiveCipher(spec["key"], alphabet)
    if kind == "affine":
        return AffineCipher(spec["a"], spec["b"], alphabet)
    if kind == "vigenere":
        return VigenereCipher(spec["key"], alphabet)
    if kind == "playfair":
        return PlayfairCipher(spec["key"], alphabet)
    if kind == "columnar":
        return ColumnarTranspositionCipher(spec["key"], alphabet)
    raise CipherError(f"unknown cipher type {spec['type']!r}")


__all__ = [
    "Alphabet", "CipherError", "ClassicalCipher", "NullCipher", "Z26", "Z36",
    "AdditiveCipher", "AffineCipher", "CaesarCipher", "mod_inverse", "units",
    "PlayfairCipher", "VigenereCipher", "ColumnarTranspositionCipher", "make_cipher",
]
