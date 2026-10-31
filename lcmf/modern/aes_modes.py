"""Block-cipher modes of operation built on :class:`lcmf.modern.aes_core.AES`.

* ECB  (NIST SP 800-38A) - deliberately included to *demonstrate* its
  pattern leakage during a naive migration (experiment TV5).
* CBC  (SP 800-38A) with PKCS#7 padding.
* CTR  (SP 800-38A) - confidentiality only, malleable (experiment TV4).
* GCM  (SP 800-38D) - authenticated encryption, the mode the gateway uses.

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from __future__ import annotations

import hmac

from .aes_core import AES


class AuthenticationError(Exception):
    """Raised when an AEAD tag does not verify (tampering or wrong key)."""


# -- padding ---------------------------------------------------------------
def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block:
        raise ValueError("invalid padded length")
    n = data[-1]
    if not 1 <= n <= block or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-n]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# -- ECB -------------------------------------------------------------------
def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    aes, data = AES(key), pkcs7_pad(plaintext)
    return b"".join(aes.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    aes = AES(key)
    data = b"".join(aes.decrypt_block(ciphertext[i:i + 16]) for i in range(0, len(ciphertext), 16))
    return pkcs7_unpad(data)


# -- CBC -------------------------------------------------------------------
def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes, data, prev, out = AES(key), pkcs7_pad(plaintext), iv, []
    for i in range(0, len(data), 16):
        prev = aes.encrypt_block(_xor(data[i:i + 16], prev))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes, prev, out = AES(key), iv, []
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        out.append(_xor(aes.decrypt_block(block), prev))
        prev = block
    return pkcs7_unpad(b"".join(out))


# -- CTR -------------------------------------------------------------------
def ctr_xcrypt(key: bytes, counter_block: bytes, data: bytes) -> bytes:
    """Encrypt or decrypt (same operation); the counter is the full 128-bit block."""
    aes, ctr, out = AES(key), int.from_bytes(counter_block, "big"), []
    for i in range(0, len(data), 16):
        ks = aes.encrypt_block(ctr.to_bytes(16, "big"))
        out.append(_xor(data[i:i + 16], ks))
        ctr = (ctr + 1) % (1 << 128)
    return b"".join(out)


# -- GCM (SP 800-38D) ------------------------------------------------------
_R = 0xE1 << 120


def gf128_mul(x: int, y: int) -> int:
    """Multiplication in GF(2^128) with GCM's bit ordering (SP 800-38D Alg. 1)."""
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def ghash(h: int, data: bytes) -> int:
    y = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16].ljust(16, b"\x00")
        y = gf128_mul(y ^ int.from_bytes(block, "big"), h)
    return y


def _inc32(block: bytes) -> bytes:
    ctr = (int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF
    return block[:12] + ctr.to_bytes(4, "big")


def _gctr(aes: AES, icb: bytes, data: bytes) -> bytes:
    out, cb = [], icb
    for i in range(0, len(data), 16):
        out.append(_xor(data[i:i + 16], aes.encrypt_block(cb)))
        cb = _inc32(cb)
    return b"".join(out)


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 16)


def _gcm_setup(aes: AES, iv: bytes) -> tuple[int, bytes]:
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        s = _pad16(iv) + b"\x00" * 8 + (len(iv) * 8).to_bytes(8, "big")
        j0 = ghash(h, s).to_bytes(16, "big")
    return h, j0


def _gcm_tag(aes: AES, h: int, j0: bytes, aad: bytes, ct: bytes) -> bytes:
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    s = ghash(h, _pad16(aad) + _pad16(ct) + lengths)
    return _xor(aes.encrypt_block(j0), s.to_bytes(16, "big"))


def gcm_encrypt(key: "bytes | AES", iv: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Return ``(ciphertext, 16-byte tag)``.  ``key`` may be a pre-expanded :class:`AES`."""
    aes = key if isinstance(key, AES) else AES(key)
    h, j0 = _gcm_setup(aes, iv)
    ct = _gctr(aes, _inc32(j0), plaintext)
    return ct, _gcm_tag(aes, h, j0, aad, ct)


def gcm_decrypt(key: "bytes | AES", iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    aes = key if isinstance(key, AES) else AES(key)
    h, j0 = _gcm_setup(aes, iv)
    if not hmac.compare_digest(_gcm_tag(aes, h, j0, aad, ciphertext), tag):
        raise AuthenticationError("GCM tag mismatch")
    return _gctr(aes, _inc32(j0), ciphertext)
