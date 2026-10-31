"""Polyalphabetic ciphers: Vigenere and Playfair.

* Vigenere uses a repeating keyword, so the same plaintext symbol maps to
  different ciphertext symbols depending on its position (period = key length).
* Playfair is digraphic: pairs of symbols are substituted using a keyed
  square, hiding single-symbol frequencies but leaking digram structure.

The Playfair square is 5x5 for the textbook Z26 alphabet (I/J merged) and
6x6 for the Z36 telemetry alphabet, so digits are enciphered losslessly.

Owner: Member 1 (Legacy Cipher Suite & Cryptanalysis)
"""
from __future__ import annotations

from math import factorial, isqrt

from .base import Alphabet, CipherError, ClassicalCipher, Z26, Z36, as_alphabet


class VigenereCipher(ClassicalCipher):
    """C_i = (P_i + K_(i mod L)) mod m."""

    name = "Vigenere"
    family = "polyalphabetic"

    def __init__(self, key: str, alphabet: "str | Alphabet" = Z36):
        super().__init__(alphabet)
        key = self.alphabet.normalise(key, drop_invalid=True)
        if not key:
            raise CipherError("Vigenere key must contain at least one alphabet symbol")
        self.key = key
        self._shifts = [self.alphabet.index(ch) for ch in key]

    def _apply(self, text: str, sign: int) -> str:
        al, ks, n = self.alphabet, self._shifts, len(self._shifts)
        return "".join(al.symbol(al.index(ch) + sign * ks[i % n]) for i, ch in enumerate(al.normalise(text)))

    def encrypt(self, plaintext: str) -> str:
        return self._apply(plaintext, +1)

    def decrypt(self, ciphertext: str) -> str:
        return self._apply(ciphertext, -1)

    @property
    def key_space(self) -> int:
        return self.alphabet.m ** len(self.key)

    def describe_key(self) -> str:
        return f"key={self.key!r} (L={len(self.key)})"


class PlayfairCipher(ClassicalCipher):
    """Digraphic substitution over an n x n keyed square."""

    name = "Playfair"
    family = "polyalphabetic"

    def __init__(self, keyword: str, alphabet: "str | Alphabet" = Z36,
                 filler: str = "X", alt_filler: str = "Q"):
        base = as_alphabet(alphabet)
        self.merge_j = base.symbols == Z26
        square_symbols = Z26.replace("J", "") if self.merge_j else base.symbols
        super().__init__(base)
        n = isqrt(len(square_symbols))
        if n * n != len(square_symbols):
            raise CipherError("Playfair needs an alphabet whose size is a perfect square (or Z26)")
        self.size = n
        self.filler, self.alt_filler = filler, alt_filler
        self.keyword = self._clean(keyword, drop_invalid=True)
        seen: list[str] = []
        for ch in self.keyword + square_symbols:
            if ch not in seen:
                seen.append(ch)
        self.square = [seen[r * n:(r + 1) * n] for r in range(n)]
        self.pos = {ch: divmod(i, n) for i, ch in enumerate(seen)}

    # -- helpers ---------------------------------------------------------
    def _clean(self, text: str, drop_invalid: bool = False) -> str:
        text = self.alphabet.normalise(text, drop_invalid=drop_invalid)
        return text.replace("J", "I") if self.merge_j else text

    def _filler_for(self, ch: str) -> str:
        return self.alt_filler if ch == self.filler else self.filler

    def digrams(self, plaintext: str) -> list[tuple[str, str]]:
        """Split into digrams, separating doubled letters and padding odd length."""
        text = self._clean(plaintext)
        pairs, i = [], 0
        while i < len(text):
            a = text[i]
            b = text[i + 1] if i + 1 < len(text) else None
            if b is None or a == b:
                pairs.append((a, self._filler_for(a)))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        return pairs

    def _sub(self, a: str, b: str, d: int) -> str:
        n, sq = self.size, self.square
        ra, ca = self.pos[a]
        rb, cb = self.pos[b]
        if ra == rb:                      # same row -> shift along the row
            return sq[ra][(ca + d) % n] + sq[rb][(cb + d) % n]
        if ca == cb:                      # same column -> shift down the column
            return sq[(ra + d) % n][ca] + sq[(rb + d) % n][cb]
        return sq[ra][cb] + sq[rb][ca]    # rectangle -> swap columns

    # -- public API ------------------------------------------------------
    def encrypt(self, plaintext: str) -> str:
        return "".join(self._sub(a, b, +1) for a, b in self.digrams(plaintext))

    def decrypt(self, ciphertext: str) -> str:
        """Return the prepared plaintext (fillers included); see :meth:`strip_fillers`."""
        text = self._clean(ciphertext)
        if len(text) % 2:
            raise CipherError("Playfair ciphertext must have even length")
        out = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i + 1]
            if a == b:
                raise CipherError("invalid Playfair ciphertext: repeated symbol inside a digram")
            out.append(self._sub(a, b, -1))
        return "".join(out)

    def strip_fillers(self, text: str) -> str:
        """Remove fillers inserted between doubled letters and the end pad."""
        f = self.filler
        out = []
        for i, ch in enumerate(text):
            if ch == f and i % 2 == 1 and 0 < i < len(text) - 1 and text[i - 1] == text[i + 1]:
                continue
            out.append(ch)
        if out and out[-1] == f and len(text) % 2 == 0:
            out.pop()
        return "".join(out)

    @property
    def key_space(self) -> int:
        return factorial(self.size * self.size)

    def describe_key(self) -> str:
        return f"keyword={self.keyword!r} ({self.size}x{self.size})"

    def square_text(self) -> str:
        return "\n".join(" ".join(row) for row in self.square)
