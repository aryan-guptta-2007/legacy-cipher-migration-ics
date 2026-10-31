"""Keyed columnar transposition (irregular, no padding).

Historical links frequently combined substitution with transposition.  A
transposition only permutes positions, so the multiset of symbols - and hence
the frequency profile - is identical in plaintext and ciphertext.

Owner: Member 1 (Legacy Cipher Suite & Cryptanalysis)
"""
from __future__ import annotations

from math import factorial
from typing import Sequence

from .base import Alphabet, CipherError, ClassicalCipher, Z36


def key_order(key: "str | Sequence[int]") -> list[int]:
    """Column read-out order: stable rank of each key symbol."""
    if isinstance(key, str):
        key = key.upper()
    if len(key) < 2:
        raise CipherError("transposition key must have at least two columns")
    return sorted(range(len(key)), key=lambda i: (key[i], i))


class ColumnarTranspositionCipher(ClassicalCipher):
    name = "Columnar"
    family = "transposition"

    def __init__(self, key: "str | Sequence[int]", alphabet: "str | Alphabet" = Z36):
        super().__init__(alphabet)
        self.key = key
        self.order = key_order(key)
        self.cols = len(self.order)

    def encrypt(self, plaintext: str) -> str:
        text = self.alphabet.normalise(plaintext)
        return "".join(text[c::self.cols] for c in self.order)

    def decrypt(self, ciphertext: str) -> str:
        text = self.alphabet.normalise(ciphertext)
        n, k = len(text), self.cols
        rows, extra = divmod(n, k)
        columns: dict[int, str] = {}
        pos = 0
        for c in self.order:
            length = rows + (1 if c < extra else 0)
            columns[c] = text[pos:pos + length]
            pos += length
        out = []
        for r in range(rows + (1 if extra else 0)):
            for c in range(k):
                if r < len(columns[c]):
                    out.append(columns[c][r])
        return "".join(out)

    @property
    def key_space(self) -> int:
        return factorial(self.cols)

    def describe_key(self) -> str:
        return f"key={self.key!r} (cols={self.cols})"
