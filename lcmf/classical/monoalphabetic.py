"""Monoalphabetic substitution ciphers: Additive (shift), Caesar and Affine.

Every plaintext symbol is replaced by exactly one ciphertext symbol, so the
symbol-frequency profile of the plaintext survives encryption.  This is the
root weakness exploited in :mod:`lcmf.analysis.cryptanalysis`.

Owner: Member 1 (Legacy Cipher Suite & Cryptanalysis)
"""
from __future__ import annotations

from math import gcd

from .base import Alphabet, CipherError, ClassicalCipher, Z36


def mod_inverse(a: int, m: int) -> int:
    """Multiplicative inverse of ``a`` modulo ``m`` (extended Euclid)."""
    a %= m
    if gcd(a, m) != 1:
        raise CipherError(f"{a} has no inverse modulo {m}")
    old_r, r = a, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % m


def units(m: int) -> list[int]:
    """All a in [1, m) with gcd(a, m) = 1 - the valid Affine multipliers."""
    return [a for a in range(1, m) if gcd(a, m) == 1]


class AdditiveCipher(ClassicalCipher):
    """Shift cipher: C = (P + k) mod m."""

    name = "Additive"
    family = "monoalphabetic"

    def __init__(self, key: int, alphabet: "str | Alphabet" = Z36):
        super().__init__(alphabet)
        self.key = key % self.alphabet.m

    def _shift(self, text: str, k: int) -> str:
        a = self.alphabet
        return "".join(a.symbol(a.index(ch) + k) for ch in a.normalise(text))

    def encrypt(self, plaintext: str) -> str:
        return self._shift(plaintext, self.key)

    def decrypt(self, ciphertext: str) -> str:
        return self._shift(ciphertext, -self.key)

    @property
    def key_space(self) -> int:
        return self.alphabet.m

    def describe_key(self) -> str:
        return f"k={self.key}"


class CaesarCipher(AdditiveCipher):
    """Julius Caesar's fixed shift of three.

    Caesar is the additive cipher with the key frozen into the algorithm, so
    once the method is known there is nothing secret left (key space = 1).
    """

    name = "Caesar"

    def __init__(self, alphabet: "str | Alphabet" = Z36, shift: int = 3):
        super().__init__(shift, alphabet)

    @property
    def key_space(self) -> int:
        return 1


class AffineCipher(ClassicalCipher):
    """Affine cipher: C = (a*P + b) mod m with gcd(a, m) = 1."""

    name = "Affine"
    family = "monoalphabetic"

    def __init__(self, a: int, b: int, alphabet: "str | Alphabet" = Z36):
        super().__init__(alphabet)
        m = self.alphabet.m
        if gcd(a % m, m) != 1:
            raise CipherError(f"multiplier a={a} is not coprime with m={m}")
        self.a = a % m
        self.b = b % m
        self.a_inv = mod_inverse(self.a, m)

    def encrypt(self, plaintext: str) -> str:
        al = self.alphabet
        return "".join(al.symbol(self.a * al.index(ch) + self.b) for ch in al.normalise(plaintext))

    def decrypt(self, ciphertext: str) -> str:
        al = self.alphabet
        return "".join(al.symbol(self.a_inv * (al.index(ch) - self.b)) for ch in al.normalise(ciphertext))

    @property
    def key_space(self) -> int:
        return len(units(self.alphabet.m)) * self.alphabet.m

    def describe_key(self) -> str:
        return f"a={self.a}, b={self.b}"
