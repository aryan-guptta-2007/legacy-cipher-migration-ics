"""SCADA master station (control centre front-end processor + historian).

Receives both kinds of traffic during the transition:

* bytes -> Secure Telemetry Envelope: structural parse, policy, anti-replay,
  AES-256-GCM verification, then the reading is stored.
* str   -> legacy frame: accepted only if the migration policy allows the
  legacy path for that device; decrypted with the device's legacy cipher.

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ..classical import CipherError, ClassicalCipher
from ..gateway import envelope as ste
from ..gateway.policy import MigrationPolicy
from ..modern.aead import AEADEngine, get_engine
from ..modern.aes_modes import AuthenticationError
from ..modern.keystore import DOWNLINK, UPLINK, KeyStore
from ..modern.nonce import NonceManager
from ..modern.replay import ReplayWindow
from .legacy_codec import FrameError, decode_telemetry, encode_command, legacy_decrypt, legacy_encrypt
from .telemetry import Command, TelemetryReading

SCADA_SENDER_ID = 0x5CADA000


@dataclass
class Delivery:
    accepted: bool
    reason: str
    path: str                     # "secure" | "legacy"
    device_id: int
    reading: TelemetryReading | None = None


class ScadaMaster:
    def __init__(self, keystore: KeyStore, policy: MigrationPolicy,
                 legacy_ciphers: dict[int, ClassicalCipher], engine: str = "library",
                 historian_limit: int = 50_000):
        self.keystore = keystore
        self.policy = policy
        self.legacy_ciphers = legacy_ciphers
        self.engine_name = engine
        self.replay = ReplayWindow()
        self.historian: list[TelemetryReading] = []
        self.historian_limit = historian_limit
        self.latest: dict[int, TelemetryReading] = {}
        self.stats: Counter = Counter()
        self._engines: dict[tuple[int, str, int], AEADEngine] = {}
        self._cmd_nonces: dict[int, NonceManager] = {}
        self._legacy_cmd_seq: Counter = Counter()

    def _engine(self, device_id: int, direction: str, key_id: int) -> AEADEngine:
        k = (device_id, direction, key_id)
        if k not in self._engines:
            self._engines[k] = get_engine(self.engine_name, self.keystore.derive(device_id, direction, key_id))
        return self._engines[k]

    def _store(self, reading: TelemetryReading, path: str) -> Delivery:
        self.latest[reading.device_id] = reading
        self.historian.append(reading)
        if len(self.historian) > self.historian_limit:
            del self.historian[: len(self.historian) - self.historian_limit]
        self.stats[f"accepted_{path}"] += 1
        return Delivery(True, "accepted", path, reading.device_id, reading)

    def _reject(self, path: str, device_id: int, reason: str) -> Delivery:
        self.stats[f"rejected_{path}"] += 1
        return Delivery(False, reason, path, device_id)

    # -- receive ---------------------------------------------------------
    def receive(self, frame: "bytes | str", now_ms: int) -> Delivery:
        if isinstance(frame, (bytes, bytearray)):
            return self._receive_secure(bytes(frame), now_ms)
        return self._receive_legacy(frame, now_ms)

    def _receive_secure(self, data: bytes, now_ms: int) -> Delivery:
        try:
            header, aad, body = ste.parse_header(data)
        except ste.EnvelopeError as exc:
            return self._reject("secure", -1, f"malformed envelope: {exc}")
        dev = header.device_id
        ok, why = self.policy.accepts_secure(dev)
        if not ok:
            return self._reject("secure", dev, why)
        if header.msg_type != ste.MSG_TELEMETRY:
            return self._reject("secure", dev, "unexpected message type")
        ok, why = self.replay.check(dev, header.seq, header.timestamp_ms, now_ms, UPLINK)
        if not ok:
            return self._reject("secure", dev, why)
        try:
            payload = ste.open_body(self._engine(dev, UPLINK, header.key_id), header, aad, body)
        except AuthenticationError:
            return self._reject("secure", dev, "authentication failed (tampered or forged)")
        self.replay.commit(dev, header.seq, UPLINK)
        self.policy.on_secure_frame(dev)
        return self._store(TelemetryReading.from_payload(dev, header.timestamp_ms, payload), "secure")

    def _receive_legacy(self, frame: str, now_ms: int) -> Delivery:
        # Legacy frames carry the device id inside the (encrypted) body, so the
        # front-end processor identifies the link by trying each known cipher -
        # in the real world this is the physical port / modem line.
        claimed = self._identify_legacy(frame)
        if claimed is None:
            return self._reject("legacy", -1, "undecodable legacy frame")
        dev, reading = claimed
        ok, why = self.policy.accepts_legacy(dev)
        if not ok:
            return self._reject("legacy", dev, why)
        return self._store(reading.evolve(timestamp_ms=now_ms), "legacy")

    def _identify_legacy(self, frame: str) -> tuple[int, TelemetryReading] | None:
        for dev, cipher in self.legacy_ciphers.items():
            try:
                reading = decode_telemetry(legacy_decrypt(cipher, frame))
            except (CipherError, FrameError):
                continue
            if reading.device_id == dev:
                return dev, reading
        return None

    # -- commands --------------------------------------------------------
    def issue_command(self, device_id: int, action: str, now_ms: int, legacy: bool = False) -> "bytes | str":
        """Seal a breaker command (STE) or, for unmigrated devices, a legacy frame."""
        if legacy:
            self._legacy_cmd_seq[device_id] += 1
            cmd = Command(device_id, action, self._legacy_cmd_seq[device_id], now_ms)
            return legacy_encrypt(self.legacy_ciphers[device_id], encode_command(cmd))
        if device_id not in self._cmd_nonces:
            self._cmd_nonces[device_id] = NonceManager(SCADA_SENDER_ID | device_id)
        seq, nonce = self._cmd_nonces[device_id].next()
        cmd = Command(device_id, action, seq, now_ms)
        header = ste.EnvelopeHeader(ste.MSG_COMMAND, 0, self.keystore.current_key_id, device_id,
                                    seq, now_ms, nonce)
        return ste.seal(self._engine(device_id, DOWNLINK, header.key_id), header, cmd.to_payload())
