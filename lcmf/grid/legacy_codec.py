"""Legacy Telemetry Frame (LTF) codec - the historical wire format.

A legacy RTU reports one fixed-width, alphanumeric (Z36) record per poll::

    RTU01SEQ0042VLT11023CUR1873FRQ5001PWR03397BRKCCHK517
    |tag+id|seq   |voltage |current|freq  |power  |brk|checksum

* 52 symbols, fixed field positions, fixed tags - exactly the structure
  that hands an eavesdropper large amounts of *known plaintext*.
* The 3-digit checksum (sum of symbol indices mod 1000) detects line noise
  but is not cryptographic: anyone can recompute it.
* The symbol 'X' never occurs, so it is free to act as the Playfair filler.

Commands (control centre -> RTU) use ``RTU01CMDOPENSEQ0007CHK123``.

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

import re

from ..classical import ClassicalCipher, PlayfairCipher, Z36
from .telemetry import Command, TelemetryReading

# (tag, width, symbol class)   classes: D = digit, B = breaker (C/O)
TELEMETRY_FIELDS = [("RTU", 2, "D"), ("SEQ", 4, "D"), ("VLT", 5, "D"), ("CUR", 4, "D"),
                    ("FRQ", 4, "D"), ("PWR", 5, "D"), ("BRK", 1, "B"), ("CHK", 3, "D")]
TELEMETRY_RE = re.compile(
    r"^RTU(\d{2})SEQ(\d{4})VLT(\d{5})CUR(\d{4})FRQ(\d{4})PWR(\d{5})BRK([CO])CHK(\d{3})$")
COMMAND_RE = re.compile(r"^RTU(\d{2})CMD(OPEN|CLOS)SEQ(\d{4})CHK(\d{3})$")
DIGITS = set("0123456789")


class FrameError(ValueError):
    """Malformed frame or checksum failure."""


def _build_template() -> list[set[str]]:
    template: list[set[str]] = []
    for tag, width, cls in TELEMETRY_FIELDS:
        template.extend({ch} for ch in tag)
        template.extend((DIGITS if cls == "D" else {"C", "O"}) for _ in range(width))
    return template


#: Public, per-position description of a valid frame (what an attacker knows).
TELEMETRY_TEMPLATE = _build_template()
FRAME_LEN = len(TELEMETRY_TEMPLATE)          # 52
CHECKSUM_POS = FRAME_LEN - 3


def checksum(body: str) -> str:
    return f"{sum(Z36.index(ch) for ch in body) % 1000:03d}"


def encode_telemetry(r: TelemetryReading) -> str:
    body = (f"RTU{r.device_id:02d}SEQ{r.seq % 10000:04d}VLT{r.voltage_v:05d}CUR{r.current_da:04d}"
            f"FRQ{r.freq_chz:04d}PWR{r.power_kw:05d}BRK{'C' if r.breaker_closed else 'O'}CHK")
    frame = body + checksum(body)
    if len(frame) != FRAME_LEN:
        raise FrameError("field overflow - value too wide for the legacy frame")
    return frame


def decode_telemetry(frame: str, timestamp_ms: int = 0) -> TelemetryReading:
    m = TELEMETRY_RE.match(frame)
    if not m:
        raise FrameError("frame does not match the legacy telemetry format")
    if checksum(frame[:CHECKSUM_POS]) != m.group(8):
        raise FrameError("legacy checksum mismatch")
    dev, seq, v, i, f, p, brk, _ = m.groups()
    return TelemetryReading(int(dev), int(seq), int(v), int(i), int(f), int(p), brk == "C", timestamp_ms)


def is_valid_telemetry(frame: str) -> bool:
    try:
        decode_telemetry(frame)
        return True
    except FrameError:
        return False


def template_score(text: str) -> float:
    """Fraction of positions that satisfy the public frame template (0..1)."""
    if not text:
        return 0.0
    hits = sum(1 for ch, allowed in zip(text, TELEMETRY_TEMPLATE) if ch in allowed)
    return hits / max(len(text), FRAME_LEN)


def encode_command(c: Command) -> str:
    body = f"RTU{c.device_id:02d}CMD{c.action}SEQ{c.seq % 10000:04d}CHK"
    return body + checksum(body)


def decode_command(frame: str, timestamp_ms: int = 0) -> Command:
    m = COMMAND_RE.match(frame)
    if not m:
        raise FrameError("frame does not match the legacy command format")
    if checksum(frame[:-3]) != m.group(4):
        raise FrameError("legacy checksum mismatch")
    return Command(int(m.group(1)), m.group(2), int(m.group(3)), timestamp_ms)


def legacy_encrypt(cipher: ClassicalCipher, frame: str) -> str:
    return cipher.encrypt(frame)


def legacy_decrypt(cipher: ClassicalCipher, ciphertext: str) -> str:
    """Decrypt a legacy frame; Playfair fillers are removed (frames never contain 'X')."""
    text = cipher.decrypt(ciphertext)
    if isinstance(cipher, PlayfairCipher):
        text = text.replace(cipher.filler, "")
    return text
