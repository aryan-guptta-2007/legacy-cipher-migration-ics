"""Deterministic GCM nonce construction with crash-safe counters.

Nonce (96 bits) = sender_id (32 bits) || message counter (64 bits), the
deterministic construction of NIST SP 800-38D section 8.2.1.  A nonce must
never repeat under one key.  Constrained field devices that keep the counter
only in RAM restart from zero after a reboot - the nonce-reuse hazard
studied in experiment TV6.  ``persist_path`` enables the mitigation: the
counter is reserved in blocks and the high-water mark is written to disk
*before* any nonce from the block is used.

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from __future__ import annotations

import json
import os


class NonceManager:
    def __init__(self, sender_id: int, persist_path: str | None = None, reserve: int = 1000):
        self.sender_id = sender_id & 0xFFFFFFFF
        self.persist_path = persist_path
        self.reserve = reserve
        self._counter = 0
        self._reserved_until = 0
        self.reboots = 0
        if persist_path and os.path.exists(persist_path):
            with open(persist_path, encoding="utf-8") as fh:
                self._counter = self._reserved_until = json.load(fh)["high_water"]

    def _persist(self, value: int) -> None:
        tmp = f"{self.persist_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"sender_id": self.sender_id, "high_water": value}, fh)
        os.replace(tmp, self.persist_path)

    def next(self) -> tuple[int, bytes]:
        """Return ``(counter, 12-byte nonce)``; the counter doubles as the sequence number."""
        self._counter += 1
        if self.persist_path and self._counter > self._reserved_until:
            self._reserved_until = self._counter + self.reserve
            self._persist(self._reserved_until)
        if self._counter >= 1 << 64:
            raise OverflowError("nonce counter exhausted - rotate the key")
        return self._counter, self.sender_id.to_bytes(4, "big") + self._counter.to_bytes(8, "big")

    def simulate_reboot(self) -> None:
        """Lose RAM state.  Without persistence the counter restarts at zero."""
        self.reboots += 1
        if self.persist_path and os.path.exists(self.persist_path):
            with open(self.persist_path, encoding="utf-8") as fh:
                self._counter = self._reserved_until = json.load(fh)["high_water"]
        else:
            self._counter = self._reserved_until = 0

    @property
    def counter(self) -> int:
        return self._counter
