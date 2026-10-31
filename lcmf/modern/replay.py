"""Anti-replay protection: sliding bitmap window + timestamp freshness.

Modelled on the IPsec ESP anti-replay window (RFC 4303 section 3.4.3): the
receiver tracks the highest authenticated sequence number per device and a
bitmap of the last ``size`` numbers, so reordered frames are accepted once
and duplicates or very old frames are rejected.

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from __future__ import annotations


class ReplayWindow:
    def __init__(self, size: int = 64, max_skew_ms: int = 30_000):
        self.size = size
        self.max_skew_ms = max_skew_ms
        self._state: dict[tuple[int, str], tuple[int, int]] = {}  # (device, dir) -> (highest, bitmap)

    def check(self, device_id: int, seq: int, timestamp_ms: int, now_ms: int,
              direction: str = "up") -> tuple[bool, str]:
        """Return (ok, reason) WITHOUT updating state.  Call :meth:`commit` after auth succeeds."""
        if abs(now_ms - timestamp_ms) > self.max_skew_ms:
            return False, "stale or future timestamp"
        highest, bitmap = self._state.get((device_id, direction), (0, 0))
        if seq > highest:
            return True, "new"
        offset = highest - seq
        if offset >= self.size:
            return False, "sequence number outside replay window"
        if bitmap >> offset & 1:
            return False, "replayed sequence number"
        return True, "reordered"

    def commit(self, device_id: int, seq: int, direction: str = "up") -> None:
        highest, bitmap = self._state.get((device_id, direction), (0, 0))
        mask = (1 << self.size) - 1
        if seq > highest:
            bitmap = ((bitmap << (seq - highest)) | 1) & mask
            highest = seq
        else:
            bitmap |= 1 << (highest - seq)
        self._state[(device_id, direction)] = (highest, bitmap)

    def highest(self, device_id: int, direction: str = "up") -> int:
        return self._state.get((device_id, direction), (0, 0))[0]
