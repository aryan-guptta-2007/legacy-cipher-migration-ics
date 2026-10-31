"""Secure Telemetry Envelope (STE v1) - the modern, AES-256-GCM wire format.

::

    offset size field        notes
    0      2    magic        b"LC"
    2      1    version      1
    3      1    msg_type     1 = telemetry, 2 = command
    4      1    flags        bit0 = payload originated on a legacy link (bridged)
                             bit1 = sealed natively by the field device
    5      2    key_id       key generation (rotation)
    7      2    device_id
    9      8    seq          64-bit message counter (anti-replay)
    17     8    timestamp_ms sender clock (freshness)
    25     12   nonce        sender_id(4) || counter(8)
    37     n    ciphertext   AES-256-GCM
    37+n   16   tag          authenticates header (AAD) + ciphertext

The whole 37-byte header is passed as Associated Data, so the routing
fields cannot be altered without breaking the tag.

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ..modern.aead import NONCE_LEN, TAG_LEN, AEADEngine

MAGIC = b"LC"
VERSION = 1
MSG_TELEMETRY = 1
MSG_COMMAND = 2
FLAG_LEGACY_ORIGIN = 0x01
FLAG_NATIVE = 0x02

HEADER = struct.Struct(">2sBBBHHQQ12s")
HEADER_LEN = HEADER.size                 # 37
OVERHEAD = HEADER_LEN + TAG_LEN          # 53 bytes added to every payload


class EnvelopeError(ValueError):
    """Structurally invalid envelope (before any cryptographic check)."""


@dataclass(frozen=True)
class EnvelopeHeader:
    msg_type: int
    flags: int
    key_id: int
    device_id: int
    seq: int
    timestamp_ms: int
    nonce: bytes
    version: int = VERSION

    def pack(self) -> bytes:
        if len(self.nonce) != NONCE_LEN:
            raise EnvelopeError("nonce must be 12 bytes")
        return HEADER.pack(MAGIC, self.version, self.msg_type, self.flags, self.key_id,
                           self.device_id, self.seq, self.timestamp_ms, self.nonce)


def parse_header(data: bytes) -> tuple[EnvelopeHeader, bytes, bytes]:
    """Split ``data`` into (header, aad bytes, ciphertext||tag)."""
    if len(data) < HEADER_LEN + TAG_LEN:
        raise EnvelopeError("envelope too short")
    magic, version, msg_type, flags, key_id, dev, seq, ts, nonce = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise EnvelopeError("bad magic")
    if version != VERSION:
        raise EnvelopeError(f"unsupported envelope version {version}")
    hdr = EnvelopeHeader(msg_type, flags, key_id, dev, seq, ts, nonce, version)
    return hdr, data[:HEADER_LEN], data[HEADER_LEN:]


def seal(engine: AEADEngine, header: EnvelopeHeader, payload: bytes) -> bytes:
    aad = header.pack()
    return aad + engine.seal(header.nonce, payload, aad)


def open_body(engine: AEADEngine, header: EnvelopeHeader, aad: bytes, body: bytes) -> bytes:
    """Authenticate and decrypt; raises :class:`AuthenticationError` on any tampering."""
    return engine.open(header.nonce, body, aad)
