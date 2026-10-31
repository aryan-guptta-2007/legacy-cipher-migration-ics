"""AES (Rijndael) block cipher implemented from first principles - FIPS-197.

This educational implementation exists so that every step of AES can be
inspected and verified against the FIPS-197 Appendix B/C test vectors.
The production path of the gateway uses the constant-time, audited
``cryptography`` library; this module is cross-checked against it.

* GF(2^8) arithmetic with the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
* S-box derived mathematically (multiplicative inverse + affine transform)
* Key expansion for 128/192/256-bit keys (Nr = 10/12/14 rounds)

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from __future__ import annotations


def xtime(a: int) -> int:
    """Multiply by x (i.e. {02}) in GF(2^8)."""
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def gf_mul(a: int, b: int) -> int:
    """Russian-peasant multiplication in GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def gf_inverse(a: int) -> int:
    """a^254 = a^-1 in GF(2^8); 0 maps to 0 by convention."""
    if a == 0:
        return 0
    result, power, exp = 1, a, 254
    while exp:
        if exp & 1:
            result = gf_mul(result, power)
        power = gf_mul(power, power)
        exp >>= 1
    return result


def _build_sbox() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    for x in range(256):
        b = gf_inverse(x)
        # affine transform: b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63
        s = b
        for shift in range(1, 5):
            s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
        sbox[x] = s ^ 0x63
    inv = [0] * 256
    for x, s in enumerate(sbox):
        inv[s] = x
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()
# Pre-computed multiplication tables used by (Inv)MixColumns.
MUL = {c: [gf_mul(x, c) for x in range(256)] for c in (2, 3, 9, 11, 13, 14)}

RCON = [0x00]
for _ in range(14):
    RCON.append(1 if len(RCON) == 1 else xtime(RCON[-1]))


class AES:
    """AES block cipher. ``key`` must be 16, 24 or 32 bytes."""

    BLOCK_SIZE = 16

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.key = bytes(key)
        self.nk = len(key) // 4
        self.nr = self.nk + 6
        self.round_keys = self._expand_key(self.key)

    # -- key schedule ----------------------------------------------------
    def _expand_key(self, key: bytes) -> list[list[int]]:
        nk, nr = self.nk, self.nr
        words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]                 # RotWord
                temp = [SBOX[b] for b in temp]             # SubWord
                temp[0] ^= RCON[i // nk]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            words.append([a ^ b for a, b in zip(words[i - nk], temp)])
        # Group into (nr + 1) round keys of 16 bytes, column-major like the state.
        return [sum(words[4 * r:4 * r + 4], []) for r in range(nr + 1)]

    # -- round transformations (state = 16 bytes, column-major) ---------
    @staticmethod
    def _add_round_key(state: list[int], rk: list[int]) -> None:
        for i in range(16):
            state[i] ^= rk[i]

    @staticmethod
    def _sub_bytes(state: list[int], box: list[int]) -> None:
        for i in range(16):
            state[i] = box[state[i]]

    @staticmethod
    def _shift_rows(s: list[int]) -> list[int]:
        # row r is shifted left by r positions; index = row + 4*col
        return [s[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]

    @staticmethod
    def _inv_shift_rows(s: list[int]) -> list[int]:
        return [s[(r + 4 * ((c - r) % 4))] for c in range(4) for r in range(4)]

    @staticmethod
    def _mix_columns(s: list[int]) -> None:
        m2, m3 = MUL[2], MUL[3]
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c:4 * c + 4]
            s[4 * c + 0] = m2[a0] ^ m3[a1] ^ a2 ^ a3
            s[4 * c + 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
            s[4 * c + 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
            s[4 * c + 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]

    @staticmethod
    def _inv_mix_columns(s: list[int]) -> None:
        m9, m11, m13, m14 = MUL[9], MUL[11], MUL[13], MUL[14]
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c:4 * c + 4]
            s[4 * c + 0] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
            s[4 * c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
            s[4 * c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
            s[4 * c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]

    # -- block operations ------------------------------------------------
    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, self.round_keys[0])
        for rnd in range(1, self.nr):
            self._sub_bytes(state, SBOX)
            state = self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[rnd])
        self._sub_bytes(state, SBOX)
        state = self._shift_rows(state)
        self._add_round_key(state, self.round_keys[self.nr])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, self.round_keys[self.nr])
        for rnd in range(self.nr - 1, 0, -1):
            state = self._inv_shift_rows(state)
            self._sub_bytes(state, INV_SBOX)
            self._add_round_key(state, self.round_keys[rnd])
            self._inv_mix_columns(state)
        state = self._inv_shift_rows(state)
        self._sub_bytes(state, INV_SBOX)
        self._add_round_key(state, self.round_keys[0])
        return bytes(state)

    def round_key_hex(self, rnd: int) -> str:
        return bytes(self.round_keys[rnd]).hex()
