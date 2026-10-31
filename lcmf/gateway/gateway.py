"""Protocol-Translation Gateway (bump-in-the-wire) - the core of LCMF.

Uplink   legacy RTU frame --(1) legacy decrypt --(2) parse + checksum
         --(3) identity / freshness / plausibility checks --(4) AES-256-GCM seal
         --> Secure Telemetry Envelope to the SCADA master.
Downlink STE command --(1) replay check --(2) GCM verify/decrypt
         --(3) legacy command encode --(4) legacy encrypt --> RTU.

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

import os
import time
from collections import Counter
from dataclasses import dataclass, field

from ..classical import CipherError, ClassicalCipher, make_cipher
from ..grid.legacy_codec import (FrameError, decode_telemetry, encode_command, legacy_decrypt,
                                 legacy_encrypt)
from ..grid.telemetry import Command, TelemetryReading
from ..modern.aead import AEADEngine, get_engine
from ..modern.aes_modes import AuthenticationError
from ..modern.keystore import DOWNLINK, UPLINK, KeyStore
from ..modern.nonce import NonceManager
from ..modern.replay import ReplayWindow
from . import envelope as ste
from .plausibility import PlausibilityFilter

# Device migration states
LEGACY_DIRECT = "LEGACY_DIRECT"   # not yet migrated: talks legacy straight to SCADA
BRIDGED = "BRIDGED"               # legacy RTU behind the translation gateway
NATIVE_AES = "NATIVE_AES"         # upgraded RTU that seals envelopes itself


@dataclass
class DeviceProfile:
    device_id: int
    name: str
    cipher_spec: dict
    state: str = BRIDGED


@dataclass
class UplinkResult:
    ok: bool
    reason: str
    device_id: int
    plaintext: str = ""
    reading: TelemetryReading | None = None
    envelope: bytes | None = None
    timings_us: dict = field(default_factory=dict)


@dataclass
class DownlinkResult:
    ok: bool
    reason: str
    device_id: int
    command: Command | None = None
    legacy_frame: str | None = None


def legacy_seq_is_newer(new: int, last: int, modulus: int = 10_000) -> bool:
    """Serial-number arithmetic for the 4-digit legacy counter (RFC 1982 style)."""
    diff = (new - last) % modulus
    return 0 < diff < modulus // 2


class ProtocolTranslationGateway:
    def __init__(self, gateway_id: int, keystore: KeyStore, profiles: list[DeviceProfile],
                 engine: str = "library", plausibility: PlausibilityFilter | None = None,
                 legacy_seq_check: bool = True, state_dir: str | None = None):
        self.gateway_id = gateway_id
        self.keystore = keystore
        self.engine_name = engine
        self.profiles = {p.device_id: p for p in profiles}
        self.ciphers: dict[int, ClassicalCipher] = {p.device_id: make_cipher(p.cipher_spec) for p in profiles}
        self.plausibility = plausibility
        self.legacy_seq_check = legacy_seq_check
        self.state_dir = state_dir
        self.nonces: dict[int, NonceManager] = {}
        self.replay = ReplayWindow()
        self.last_reading: dict[int, TelemetryReading] = {}
        self.stats: Counter = Counter()
        self._engines: dict[tuple[int, str, int], AEADEngine] = {}

    # -- helpers ---------------------------------------------------------
    def _engine(self, device_id: int, direction: str, key_id: int) -> AEADEngine:
        k = (device_id, direction, key_id)
        if k not in self._engines:
            self._engines[k] = get_engine(self.engine_name, self.keystore.derive(device_id, direction, key_id))
        return self._engines[k]

    def nonce_manager(self, device_id: int) -> NonceManager:
        if device_id not in self.nonces:
            path = None
            if self.state_dir:
                os.makedirs(self.state_dir, exist_ok=True)
                path = os.path.join(self.state_dir, f"gw{self.gateway_id}_dev{device_id}_up.json")
            self.nonces[device_id] = NonceManager(self.gateway_id, persist_path=path)
        return self.nonces[device_id]

    def _reject(self, device_id: int, reason: str, **kw) -> UplinkResult:
        self.stats["uplink_rejected"] += 1
        self.stats[f"reject:{reason.split(':')[0]}"] += 1
        return UplinkResult(False, reason, device_id, **kw)

    # -- uplink: legacy -> secure ---------------------------------------
    def translate_uplink(self, device_id: int, legacy_frame: str, now_ms: int) -> UplinkResult:
        t0 = time.perf_counter_ns()
        cipher = self.ciphers.get(device_id)
        if cipher is None:
            return self._reject(device_id, "unknown device")
        try:
            plaintext = legacy_decrypt(cipher, legacy_frame)
        except CipherError as exc:
            return self._reject(device_id, f"legacy decrypt failed: {exc}")
        t1 = time.perf_counter_ns()
        try:
            reading = decode_telemetry(plaintext, timestamp_ms=now_ms)
        except FrameError as exc:
            return self._reject(device_id, f"bad legacy frame: {exc}", plaintext=plaintext)
        if reading.device_id != device_id:
            return self._reject(device_id, "device id mismatch", plaintext=plaintext)
        previous = self.last_reading.get(device_id)
        if self.legacy_seq_check and previous is not None and not legacy_seq_is_newer(reading.seq, previous.seq):
            return self._reject(device_id, "legacy replay: sequence number not newer", plaintext=plaintext)
        if self.plausibility is not None:
            ok, issues = self.plausibility.check(reading, previous)
            if not ok:
                return self._reject(device_id, "implausible reading: " + "; ".join(issues), plaintext=plaintext)
        t2 = time.perf_counter_ns()
        seq, nonce = self.nonce_manager(device_id).next()
        header = ste.EnvelopeHeader(ste.MSG_TELEMETRY, ste.FLAG_LEGACY_ORIGIN, self.keystore.current_key_id,
                                    device_id, seq, now_ms, nonce)
        env = ste.seal(self._engine(device_id, UPLINK, header.key_id), header, reading.to_payload())
        t3 = time.perf_counter_ns()
        self.last_reading[device_id] = reading
        self.stats["uplink_ok"] += 1
        timings = {"legacy_decrypt": (t1 - t0) / 1e3, "parse_validate": (t2 - t1) / 1e3,
                   "aes_seal": (t3 - t2) / 1e3, "total": (t3 - t0) / 1e3}
        return UplinkResult(True, "translated", device_id, plaintext, reading, env, timings)

    # -- downlink: secure -> legacy -------------------------------------
    def translate_downlink(self, data: bytes, now_ms: int) -> DownlinkResult:
        try:
            header, aad, body = ste.parse_header(data)
        except ste.EnvelopeError as exc:
            return DownlinkResult(False, f"malformed envelope: {exc}", -1)
        dev = header.device_id
        if header.msg_type != ste.MSG_COMMAND or dev not in self.ciphers:
            return DownlinkResult(False, "not a command for a bridged device", dev)
        ok, why = self.replay.check(dev, header.seq, header.timestamp_ms, now_ms, DOWNLINK)
        if not ok:
            self.stats["downlink_rejected"] += 1
            return DownlinkResult(False, why, dev)
        try:
            payload = ste.open_body(self._engine(dev, DOWNLINK, header.key_id), header, aad, body)
        except AuthenticationError:
            self.stats["downlink_rejected"] += 1
            return DownlinkResult(False, "authentication failed", dev)
        self.replay.commit(dev, header.seq, DOWNLINK)
        cmd = Command.from_payload(dev, header.timestamp_ms, payload)
        frame = legacy_encrypt(self.ciphers[dev], encode_command(cmd))
        self.stats["downlink_ok"] += 1
        return DownlinkResult(True, "translated", dev, cmd, frame)
