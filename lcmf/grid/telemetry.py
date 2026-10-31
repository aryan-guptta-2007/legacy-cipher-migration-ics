"""Telemetry and command data model shared by RTUs, gateway and SCADA.

All quantities are fixed-point integers so that translation between the
legacy text frame and the modern binary payload is exact (no float drift):

====================  =========  ==========================
field                 unit       example
====================  =========  ==========================
voltage_v             volt       11023  (11.023 kV feeder)
current_da            0.1 A      1873   (187.3 A)
freq_chz              0.01 Hz    5001   (50.01 Hz)
power_kw              kW         3397
====================  =========  ==========================

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, replace

ACTIONS = ("OPEN", "CLOS")


@dataclass(frozen=True)
class TelemetryReading:
    device_id: int
    seq: int                 # legacy 4-digit sequence number (0..9999)
    voltage_v: int
    current_da: int
    freq_chz: int
    power_kw: int
    breaker_closed: bool
    timestamp_ms: int = 0

    PAYLOAD = struct.Struct(">IHHIBH")   # 15-byte modern payload

    @property
    def current_a(self) -> float:
        return self.current_da / 10

    @property
    def frequency_hz(self) -> float:
        return self.freq_chz / 100

    def to_payload(self) -> bytes:
        return self.PAYLOAD.pack(self.voltage_v, self.current_da, self.freq_chz,
                                 self.power_kw, int(self.breaker_closed), self.seq)

    @classmethod
    def from_payload(cls, device_id: int, timestamp_ms: int, payload: bytes) -> "TelemetryReading":
        v, i, f, p, brk, seq = cls.PAYLOAD.unpack(payload)
        return cls(device_id, seq, v, i, f, p, bool(brk), timestamp_ms)

    def evolve(self, **changes) -> "TelemetryReading":
        return replace(self, **changes)

    def same_measurement(self, other: "TelemetryReading") -> bool:
        """Equality ignoring the timestamp (which the gateway re-stamps)."""
        return asdict(self.evolve(timestamp_ms=0)) == asdict(other.evolve(timestamp_ms=0))

    def as_dict(self) -> dict:
        d = asdict(self)
        d.update(current_a=self.current_a, frequency_hz=self.frequency_hz)
        return d


@dataclass(frozen=True)
class Command:
    device_id: int
    action: str              # OPEN | CLOS  (breaker control)
    seq: int
    timestamp_ms: int = 0

    PAYLOAD = struct.Struct(">4sH")

    def __post_init__(self):
        if self.action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")

    def to_payload(self) -> bytes:
        return self.PAYLOAD.pack(self.action.encode(), self.seq % 10000)

    @classmethod
    def from_payload(cls, device_id: int, timestamp_ms: int, payload: bytes) -> "Command":
        action, seq = cls.PAYLOAD.unpack(payload)
        return cls(device_id, action.decode(), seq, timestamp_ms)
