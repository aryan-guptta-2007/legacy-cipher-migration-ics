"""Field-side simulation: feeder physics, legacy RTUs and upgraded (native AES) RTUs.

The feeder model produces physically consistent 11 kV distribution telemetry:
a daily load curve drives current and active power, the bus voltage sags
under load, and a shared system frequency performs a mean-reverting random
walk around 50 Hz.  ``P = sqrt(3) * V * I * pf`` holds for every sample, which
is what the gateway's plausibility filter later relies on.

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

import random
from math import sqrt

from ..classical import ClassicalCipher
from ..gateway import envelope as ste
from ..modern.aead import get_engine
from ..modern.aes_modes import AuthenticationError
from ..modern.nonce import NonceManager
from ..modern.replay import ReplayWindow
from .legacy_codec import FrameError, decode_command, encode_telemetry, legacy_decrypt, legacy_encrypt
from .telemetry import Command, TelemetryReading

HOUR_MS = 3_600_000
# Normalised daily load curve (residential + commercial mix), one value per hour.
LOAD_PROFILE = [0.42, 0.38, 0.36, 0.35, 0.36, 0.42, 0.55, 0.70, 0.78, 0.80, 0.82, 0.83,
                0.82, 0.80, 0.79, 0.80, 0.85, 0.95, 1.00, 0.98, 0.90, 0.78, 0.62, 0.50]


class GridFrequency:
    """System frequency shared by all feeders (centi-Hz), mean-reverting random walk."""

    def __init__(self, seed: int = 0, nominal_chz: int = 5000):
        self.rng = random.Random(seed)
        self.nominal = nominal_chz
        self.offset = 0.0
        self._last_t: int | None = None
        self._value = nominal_chz

    def at(self, t_ms: int) -> int:
        if t_ms != self._last_t:
            self.offset = max(-8.0, min(8.0, 0.85 * self.offset + self.rng.gauss(0, 1.2)))
            self._value = round(self.nominal + self.offset)
            self._last_t = t_ms
        return self._value


class FeederModel:
    def __init__(self, rated_kw: int, nominal_v: int = 11_000, pf: float = 0.95, seed: int = 0):
        self.rated_kw = rated_kw
        self.nominal_v = nominal_v
        self.pf = pf
        self.rng = random.Random(seed)

    def load_factor(self, t_ms: int) -> float:
        hour = (t_ms / HOUR_MS) % 24
        h0 = int(hour)
        frac = hour - h0
        return LOAD_PROFILE[h0] * (1 - frac) + LOAD_PROFILE[(h0 + 1) % 24] * frac

    def sample(self, t_ms: int, breaker_closed: bool) -> tuple[int, int, int]:
        """Return (voltage_v, current_da, power_kw)."""
        factor = self.load_factor(t_ms)
        if not breaker_closed:
            return round(self.nominal_v * 1.02 + self.rng.gauss(0, 10)), 0, 0
        voltage = round(self.nominal_v * (1.02 - 0.05 * factor) + self.rng.gauss(0, 15))
        load_kw = self.rated_kw * factor * (1 + self.rng.gauss(0, 0.015))
        current_a = load_kw * 1000 / (sqrt(3) * voltage * self.pf)
        current_da = round(current_a * 10)
        power_kw = round(sqrt(3) * voltage * (current_da / 10) * self.pf / 1000)
        return voltage, current_da, power_kw


class RTU:
    """Legacy Remote Terminal Unit: classical cipher, no authentication, no freshness."""

    native = False

    def __init__(self, device_id: int, name: str, cipher: ClassicalCipher, feeder: FeederModel,
                 frequency: GridFrequency, seq_start: int = 0):
        self.device_id = device_id
        self.name = name
        self.cipher = cipher
        self.feeder = feeder
        self.frequency = frequency
        self.seq = seq_start
        self.breaker_closed = True
        self.executed: list[Command] = []

    def measure(self, t_ms: int) -> TelemetryReading:
        self.seq = (self.seq + 1) % 10_000
        v, i, p = self.feeder.sample(t_ms, self.breaker_closed)
        return TelemetryReading(self.device_id, self.seq, v, i, self.frequency.at(t_ms), p,
                                self.breaker_closed, t_ms)

    def transmit(self, t_ms: int) -> tuple[TelemetryReading, str, str]:
        """Return (reading, plaintext frame, legacy ciphertext)."""
        reading = self.measure(t_ms)
        plaintext = encode_telemetry(reading)
        return reading, plaintext, legacy_encrypt(self.cipher, plaintext)

    def receive_command(self, frame: str) -> tuple[bool, str]:
        """Legacy RTUs execute any well-formed command - there is no authentication."""
        try:
            cmd = decode_command(legacy_decrypt(self.cipher, frame))
        except (FrameError, ValueError) as exc:
            return False, f"rejected: {exc}"
        if cmd.device_id != self.device_id:
            return False, "rejected: addressed to another RTU"
        self.breaker_closed = cmd.action == "CLOS"
        self.executed.append(cmd)
        return True, f"executed {cmd.action}"


class SecureRTU(RTU):
    """Upgraded RTU (end state of the migration): seals and verifies envelopes itself."""

    native = True

    def __init__(self, device_id: int, name: str, uplink_key: bytes, downlink_key: bytes,
                 feeder: FeederModel, frequency: GridFrequency, engine: str = "library",
                 key_id: int = 1, cipher: ClassicalCipher | None = None):
        super().__init__(device_id, name, cipher, feeder, frequency)
        self.up = get_engine(engine, uplink_key)
        self.down = get_engine(engine, downlink_key)
        self.key_id = key_id
        self.nonces = NonceManager(0x5E000000 | device_id)
        self.replay = ReplayWindow()

    def transmit_secure(self, t_ms: int) -> tuple[TelemetryReading, bytes]:
        reading = self.measure(t_ms)
        seq, nonce = self.nonces.next()
        header = ste.EnvelopeHeader(ste.MSG_TELEMETRY, ste.FLAG_NATIVE, self.key_id,
                                    self.device_id, seq, t_ms, nonce)
        return reading, ste.seal(self.up, header, reading.to_payload())

    def receive_envelope(self, data: bytes, now_ms: int) -> tuple[bool, str]:
        try:
            header, aad, body = ste.parse_header(data)
        except ste.EnvelopeError as exc:
            return False, f"rejected: {exc}"
        if header.device_id != self.device_id or header.msg_type != ste.MSG_COMMAND:
            return False, "rejected: not a command for this RTU"
        ok, why = self.replay.check(self.device_id, header.seq, header.timestamp_ms, now_ms, "down")
        if not ok:
            return False, f"rejected: {why}"
        try:
            payload = ste.open_body(self.down, header, aad, body)
        except AuthenticationError:
            return False, "rejected: authentication failed"
        self.replay.commit(self.device_id, header.seq, "down")
        cmd = Command.from_payload(self.device_id, header.timestamp_ms, payload)
        self.breaker_closed = cmd.action == "CLOS"
        self.executed.append(cmd)
        return True, f"executed {cmd.action}"
