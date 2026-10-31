"""End-to-end smart-grid scenario: RTUs -> legacy links -> gateway -> WAN -> SCADA.

The default scenario models one distribution utility part-way through a
migration: eight feeders, each historically protected by a different legacy
scheme.  The migration mode decides how every device is connected:

==================  =====================================================
mode                device states
==================  =====================================================
LEGACY_ONLY         all devices talk legacy directly to SCADA (Phase 0)
HYBRID_*            devices 1-6 bridged by the gateway, 7 still legacy,
                    8 upgraded to a native-AES RTU (Phases 1-2)
STRICT_AES          devices 1-7 bridged, 8 native (Phase 3)
==================  =====================================================

Every link is a :class:`Channel`; attacker taps can observe, modify, drop
or inject frames on any of them.

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

from typing import Callable

from ..classical import make_cipher
from ..gateway import BRIDGED, LEGACY_DIRECT, NATIVE_AES, DeviceProfile, ProtocolTranslationGateway
from ..gateway.plausibility import PlausibilityFilter
from ..gateway.policy import MigrationMode, MigrationPolicy
from ..modern.keystore import DOWNLINK, UPLINK, KeyStore
from .scada import ScadaMaster
from .simulator import RTU, FeederModel, GridFrequency, SecureRTU

START_MS = 1_768_464_000_000          # 2026-01-15 08:00:00 UTC
POLL_INTERVAL_MS = 2_000              # SCADA integrity-poll cycle

#: (device_id, name, legacy cipher spec, rated kW)
DEFAULT_DEVICES = [
    (1, "Substation A / Feeder 1", {"type": "caesar"}, 4200),
    (2, "Substation A / Feeder 2", {"type": "additive", "key": 17}, 3600),
    (3, "Substation B / Feeder 3", {"type": "affine", "a": 5, "b": 8}, 5100),
    (4, "Substation B / Feeder 4", {"type": "vigenere", "key": "GRIDLOCK"}, 4800),
    (5, "Substation C / Feeder 5", {"type": "playfair", "key": "SUBSTATION"}, 3900),
    (6, "Substation C / Feeder 6", {"type": "columnar", "key": "BREAKER"}, 4500),
    (7, "Pumping Station / Feeder 7", {"type": "none"}, 3000),
    (8, "Solar Park / Feeder 8", {"type": "vigenere", "key": "HELIOS"}, 6000),
]


def device_states(mode: MigrationMode) -> dict[int, str]:
    if mode is MigrationMode.LEGACY_ONLY:
        return {d[0]: LEGACY_DIRECT for d in DEFAULT_DEVICES}
    states = {d[0]: BRIDGED for d in DEFAULT_DEVICES}
    states[8] = NATIVE_AES
    if mode is not MigrationMode.STRICT_AES:
        states[7] = LEGACY_DIRECT
    return states


Tap = Callable[[object], object]


class Channel:
    """A communication link.  Taps run in order; a tap returning None drops the frame."""

    def __init__(self, name: str):
        self.name = name
        self.taps: list[Tap] = []
        self.frames = 0
        self.bytes = 0

    def add_tap(self, tap: Tap) -> Tap:
        self.taps.append(tap)
        return tap

    def send(self, frame):
        for tap in self.taps:
            frame = tap(frame)
            if frame is None:
                return None
        self.frames += 1
        self.bytes += len(frame)
        return frame


class Recorder:
    """Passive eavesdropper tap."""

    def __init__(self):
        self.frames: list = []

    def __call__(self, frame):
        self.frames.append(frame)
        return frame


class GridNetwork:
    def __init__(self, mode: "MigrationMode | str" = MigrationMode.HYBRID_PINNED, seed: int = 7,
                 engine: str = "library", plausibility: bool = True, legacy_seq_check: bool = True,
                 master_key: bytes | None = None, start_ms: int = START_MS, state_dir: str | None = None):
        self.mode = MigrationMode(mode)
        self.t_ms = start_ms
        self.keystore = KeyStore(master_key)
        self.states = device_states(self.mode)
        self.profiles = [DeviceProfile(d, name, spec, self.states[d]) for d, name, spec, _ in DEFAULT_DEVICES]
        self.frequency = GridFrequency(seed)
        self.rtus: dict[int, RTU] = {}
        for dev, name, spec, rated in DEFAULT_DEVICES:
            feeder = FeederModel(rated, seed=seed * 100 + dev)
            if self.states[dev] == NATIVE_AES:
                self.rtus[dev] = SecureRTU(dev, name, self.keystore.derive(dev, UPLINK),
                                           self.keystore.derive(dev, DOWNLINK), feeder, self.frequency, engine)
            else:
                self.rtus[dev] = RTU(dev, name, make_cipher(spec), feeder, self.frequency, seq_start=dev * 1000)
        bridged = [p for p in self.profiles if p.state == BRIDGED]
        self.gateway = ProtocolTranslationGateway(
            gateway_id=0x6A7E0001, keystore=self.keystore, profiles=bridged, engine=engine,
            plausibility=PlausibilityFilter() if plausibility else None, legacy_seq_check=legacy_seq_check,
            state_dir=state_dir)
        migrated = {d for d, s in self.states.items() if s != LEGACY_DIRECT}
        self.policy = MigrationPolicy(self.mode, migrated if self.mode is MigrationMode.HYBRID_PINNED else None)
        self.scada = ScadaMaster(self.keystore, self.policy,
                                 {d: make_cipher(spec) for d, _, spec, _ in DEFAULT_DEVICES}, engine)
        self.legacy_links = {d: Channel(f"legacy-link-{d}") for d in self.rtus}
        self.wan = Channel("wan")

    # -- one polling cycle -------------------------------------------------
    def poll_device(self, dev: int) -> dict:
        rtu, state = self.rtus[dev], self.states[dev]
        event = {"t_ms": self.t_ms, "device_id": dev, "name": rtu.name, "state": state,
                 "cipher": self.profiles[dev - 1].cipher_spec["type"] if state != NATIVE_AES else "aes-256-gcm"}
        if state == NATIVE_AES:
            reading, env = rtu.transmit_secure(self.t_ms)
            event.update(plaintext=None, legacy_frame=None, envelope=env.hex(), legacy_bytes=0)
            wire = self.wan.send(env)
        else:
            reading, plaintext, frame = rtu.transmit(self.t_ms)
            event.update(plaintext=plaintext, legacy_frame=frame, legacy_bytes=len(frame))
            if state == LEGACY_DIRECT:
                wire = self.wan.send(frame)
                event["envelope"] = None
            else:
                frame = self.legacy_links[dev].send(frame)
                if frame is None:
                    event.update(gateway="dropped on legacy link", accepted=False, reason="dropped")
                    return event
                result = self.gateway.translate_uplink(dev, frame, self.t_ms)
                event.update(gateway=result.reason, gateway_ok=result.ok, timings_us=result.timings_us)
                if not result.ok:
                    event.update(accepted=False, reason=f"gateway: {result.reason}", envelope=None)
                    return event
                event["envelope"] = result.envelope.hex()
                wire = self.wan.send(result.envelope)
        event["truth"] = reading.as_dict()
        if wire is None:
            event.update(accepted=False, reason="dropped on WAN")
            return event
        delivery = self.scada.receive(wire, self.t_ms)
        event.update(accepted=delivery.accepted, reason=delivery.reason, path=delivery.path,
                     wire_bytes=len(wire), received=delivery.reading.as_dict() if delivery.reading else None)
        return event

    def step(self) -> list[dict]:
        events = [self.poll_device(dev) for dev in sorted(self.rtus)]
        self.t_ms += POLL_INTERVAL_MS
        return events

    def run(self, polls: int) -> list[dict]:
        events: list[dict] = []
        for _ in range(polls):
            events.extend(self.step())
        return events

    # -- commands ----------------------------------------------------------
    def send_command(self, dev: int, action: str) -> dict:
        state, rtu = self.states[dev], self.rtus[dev]
        msg = self.scada.issue_command(dev, action, self.t_ms, legacy=state == LEGACY_DIRECT)
        msg = self.wan.send(msg)
        if state == BRIDGED:
            result = self.gateway.translate_downlink(msg, self.t_ms)
            if not result.ok:
                return {"device_id": dev, "action": action, "ok": False, "reason": f"gateway: {result.reason}"}
            ok, why = rtu.receive_command(self.legacy_links[dev].send(result.legacy_frame))
        elif state == NATIVE_AES:
            ok, why = rtu.receive_envelope(msg, self.t_ms)
        else:
            ok, why = rtu.receive_command(msg)
        return {"device_id": dev, "action": action, "ok": ok, "reason": why,
                "breaker_closed": rtu.breaker_closed}
