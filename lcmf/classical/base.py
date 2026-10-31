"""Common interface for the classical (legacy) cipher suite.

All classical ciphers in LCMF operate over an explicit alphabet.  Two
alphabets are provided:

* ``Z26`` - the textbook A-Z alphabet, used to verify the implementations
  against published test vectors.
* ``Z36`` - A-Z followed by 0-9.  Legacy telemetry is numeric, so the
  gateway uses this 36-symbol alphabet; it mirrors the alphanumeric
  teleprinter code sets used by historical RTU links.

Owner: Member 1 (Legacy Cipher Suite & Cryptanalysis)
"""
from __future__ import annotations

from abc import ABC, abstractmethod

Z26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
Z36 = Z26 + "0123456789"


class CipherError(ValueError):
    """Raised for invalid keys or symbols outside the cipher alphabet."""


class Alphabet:
    """An ordered set of symbols with O(1) symbol <-> index lookup."""

    def __init__(self, symbols: str):
        if len(set(symbols)) != len(symbols):
            raise CipherError("alphabet contains duplicate symbols")
        self.symbols = symbols
        self.m = len(symbols)
        self._index = {ch: i for i, ch in enumerate(symbols)}

    def index(self, ch: str) -> int:
        try:
            return self._index[ch]
        except KeyError:
            raise CipherError(f"symbol {ch!r} is not in the alphabet") from None

    def symbol(self, i: int) -> str:
        return self.symbols[i % self.m]

    def __contains__(self, ch: str) -> bool:
        return ch in self._index

    def normalise(self, text: str, drop_invalid: bool = False) -> str:
        """Upper-case ``text``; drop or reject symbols outside the alphabet."""
        text = text.upper()
        if drop_invalid:
            return "".join(ch for ch in text if ch in self._index)
        for ch in text:
            if ch not in self._index:
                raise CipherError(f"symbol {ch!r} is not in the alphabet")
        return text

    def __repr__(self) -> str:
        return f"Alphabet(m={self.m})"


def as_alphabet(alphabet: "str | Alphabet") -> Alphabet:
    return alphabet if isinstance(alphabet, Alphabet) else Alphabet(alphabet)


class ClassicalCipher(ABC):
    """Base class: every legacy cipher exposes the same four members."""

    name: str = "cipher"
    family: str = "classical"  # monoalphabetic | polyalphabetic | transposition

    def __init__(self, alphabet: "str | Alphabet" = Z36):
        self.alphabet = as_alphabet(alphabet)

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string made only of alphabet symbols."""

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Invert :meth:`encrypt`."""

    @property
    @abstractmethod
    def key_space(self) -> int:
        """Number of distinct keys for this cipher over its alphabet."""

    def describe_key(self) -> str:
        return "-"

    def __repr__(self) -> str:
        return f"{self.name}({self.describe_key()})"


class NullCipher(ClassicalCipher):
    """Unencrypted legacy link (many historical RTUs sent clear text)."""

    name = "Plaintext"
    family = "none"

    def encrypt(self, plaintext: str) -> str:
        return self.alphabet.normalise(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return self.alphabet.normalise(ciphertext)

    @property
    def key_space(self) -> int:
        return 1
