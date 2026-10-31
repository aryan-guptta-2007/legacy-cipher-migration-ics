"""System-level transition vulnerabilities (TV1, TV2, TV3, TV8).

Each experiment builds a fresh :class:`GridNetwork`, places an adversary tap
on a specific link and measures how often the attack succeeds under the
relevant migration configurations.  All experiments are deterministic for a
given seed so the report numbers are reproducible.

TV1  Legacy last mile: eavesdropping + false-data injection laundered by the gateway
TV2  Downgrade attack while the control centre accepts both protocols
TV3  Replay on the WAN and "freshness laundering" across the gateway
TV8  Bandwidth / latency overhead of the secure envelope on legacy links

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

import statistics

from ..classical import AffineCipher, VigenereCipher
from ..gateway import OVERHEAD, parse_header
from ..gateway.envelope import HEADER_LEN
from ..gateway.policy import MigrationMode
from ..grid.legacy_codec import FRAME_LEN, decode_telemetry, encode_telemetry, legacy_decrypt
from ..grid.network import DEFAULT_DEVICES, GridNetwork, Recorder
from ..grid.telemetry import TelemetryReading
from ..modern.aead import TAG_LEN
from .cryptanalysis import break_affine, break_vigenere


def _rate(hits: int, total: int) -> float:
    return round(100.0 * hits / total, 2) if total else 0.0


# --------------------------------------------------------------------- TV1
def tv1_last_mile_injection(trials: int = 60, seed: int = 11) -> dict:
    """Attacker on the RTU<->gateway serial link of device 4 (Vigenere)."""
    dev = 4
    out: dict = {"id": "TV1", "title": "Legacy last-mile exposure and trust laundering",
                 "device": dev, "trials": trials, "scenarios": []}

    for filt in (False, True):
        for kind in ("gross", "stealthy"):
            net = GridNetwork(MigrationMode.HYBRID_PINNED, seed=seed, plausibility=filt)
            # Phase A - passive eavesdropping on the legacy link
            rec = net.legacy_links[dev].add_tap(Recorder())
            net.run(5)
            net.legacy_links[dev].taps.clear()
            attack = break_vigenere(rec.frames)
            cipher = VigenereCipher(attack.key)
            stolen = [decode_telemetry(legacy_decrypt(cipher, f)) for f in rec.frames]
            # Confidentiality: what fraction of readings SCADA received over AES did the
            # last-mile eavesdropper already read in clear?
            secured = [r for r in net.scada.historian if r.device_id == dev]
            exposed = sum(any(s.same_measurement(r.evolve(timestamp_ms=s.timestamp_ms)) for s in stolen)
                          for r in secured)
            forged_values: set[int] = set()

            # Phase B - active man-in-the-middle rewrites every frame
            def forge(frame: str) -> str:
                r = decode_telemetry(legacy_decrypt(cipher, frame))
                if kind == "gross":       # 9.0 kV: deep under-voltage, triggers load shedding
                    f = r.evolve(voltage_v=9_000)
                else:                     # -3 % with power scaled: physically consistent
                    f = r.evolve(voltage_v=round(r.voltage_v * 0.97), power_kw=round(r.power_kw * 0.97))
                forged_values.add(f.voltage_v)
                return cipher.encrypt(encode_telemetry(f))

            net.legacy_links[dev].add_tap(forge)
            accepted = 0
            for _ in range(trials):
                ev = net.poll_device(dev)
                net.t_ms += 2_000
                if ev.get("accepted") and ev["received"]["voltage_v"] in forged_values:
                    accepted += 1
            out["scenarios"].append({
                "defence": "gateway + plausibility filter" if filt else "gateway only",
                "attack": kind, "key_recovered": attack.key, "frames_to_break": attack.frames_used,
                "aes_delivered_readings_exposed_pct": _rate(exposed, len(secured)),
                "forged_accepted_pct": _rate(accepted, trials)})

    # Native AES RTU (device 8): the attacker can only tamper with sealed envelopes.
    net = GridNetwork(MigrationMode.HYBRID_PINNED, seed=seed)

    def flip(frame):
        if isinstance(frame, bytes) and parse_header(frame)[0].device_id == 8:
            b = bytearray(frame)
            b[HEADER_LEN] ^= 0x01
            return bytes(b)
        return frame

    net.wan.add_tap(flip)
    accepted = 0
    for _ in range(trials):
        ev = net.poll_device(8)
        net.t_ms += 2_000
        accepted += bool(ev.get("accepted"))
    out["scenarios"].append({"defence": "native AES-GCM at the RTU (end-to-end)", "attack": "tamper",
                             "key_recovered": None, "frames_to_break": None,
                             "aes_delivered_readings_exposed_pct": 0.0,
                             "forged_accepted_pct": _rate(accepted, trials)})
    return out


# --------------------------------------------------------------------- TV2
def tv2_downgrade(trials: int = 60, seed: int = 12) -> dict:
    """Strip the envelopes of migrated device 3 and inject forged legacy frames instead."""
    dev = 3
    out: dict = {"id": "TV2", "title": "Downgrade attack during hybrid operation", "device": dev,
                 "trials": trials, "modes": []}
    # The attacker recorded device 3's legacy traffic before it was migrated (Phase 0).
    old = GridNetwork(MigrationMode.LEGACY_ONLY, seed=seed)
    history = [old.rtus[dev].transmit(old.t_ms + 2_000 * i)[2] for i in range(3)]
    legacy_key = break_affine(history).key
    cipher = AffineCipher(*legacy_key)

    for mode in (MigrationMode.HYBRID_PERMISSIVE, MigrationMode.HYBRID_PINNED, MigrationMode.STRICT_AES):
        net = GridNetwork(mode, seed=seed)

        def downgrade(frame, net=net):
            if isinstance(frame, bytes) and parse_header(frame)[0].device_id == dev:
                truth = net.rtus[dev]
                fake = TelemetryReading(dev, truth.seq, 11_000, 0, 5000, 0, False)  # "breaker open"
                return cipher.encrypt(encode_telemetry(fake))
            return frame

        net.wan.add_tap(downgrade)
        accepted, legit_legacy_ok, legit_legacy_total = 0, 0, 0
        for _ in range(trials):
            for ev in net.step():
                if ev["device_id"] == dev:
                    accepted += bool(ev.get("accepted") and ev.get("path") == "legacy")
                elif ev["device_id"] == 7 and ev["state"] == "LEGACY_DIRECT":
                    legit_legacy_total += 1
                    legit_legacy_ok += bool(ev.get("accepted"))
        out["modes"].append({"mode": mode.value, "forged_accepted_pct": _rate(accepted, trials),
                             "unmigrated_device_supported": legit_legacy_total > 0,
                             "unmigrated_device_accept_pct": _rate(legit_legacy_ok, legit_legacy_total)
                             if legit_legacy_total else None})
    out["legacy_key_recovered"] = list(legacy_key)
    return out


# --------------------------------------------------------------------- TV3
def tv3_replay(trials: int = 60, seed: int = 13) -> dict:
    out: dict = {"id": "TV3", "title": "Replay and freshness laundering", "trials": trials, "cases": []}

    # (a) WAN replay of legacy frames (Phase 0 control centre)
    net = GridNetwork(MigrationMode.LEGACY_ONLY, seed=seed)
    rec = net.wan.add_tap(Recorder())
    net.run(trials)
    replayed = [f for f in rec.frames if isinstance(f, str)][:trials]
    ok = sum(net.scada.receive(f, net.t_ms).accepted for f in replayed)
    out["cases"].append({"case": "WAN replay of legacy frames", "defence": "none (legacy)",
                         "replay_accepted_pct": _rate(ok, len(replayed))})

    # (b) WAN replay of secure envelopes: immediately (duplicate) and later (stale)
    net = GridNetwork(MigrationMode.STRICT_AES, seed=seed)
    rec = net.wan.add_tap(Recorder())
    reasons: dict[str, int] = {}
    ok = attempts = 0

    def replay(frame) -> None:
        nonlocal ok, attempts
        d = net.scada.receive(frame, net.t_ms)
        ok += d.accepted
        attempts += 1
        reasons[d.reason] = reasons.get(d.reason, 0) + 1

    for _ in range(trials):
        net.step()
        replay(rec.frames[-1])                       # instant duplicate of a fresh envelope
    for frame in [f for f in rec.frames if isinstance(f, bytes)][:trials]:
        replay(frame)                                # stale replay at the end of the capture
    out["cases"].append({"case": "WAN replay of secure envelopes", "defence": "64-bit seq + window + timestamp",
                         "replay_accepted_pct": _rate(ok, attempts), "attempts": attempts,
                         "rejection_reasons": reasons})

    # (c) replay on the legacy last mile, laundered into fresh envelopes by the gateway
    for check in (False, True):
        net = GridNetwork(MigrationMode.HYBRID_PINNED, seed=seed, legacy_seq_check=check)
        dev = 2
        rec = net.legacy_links[dev].add_tap(Recorder())
        net.run(10)
        old_frames = list(rec.frames)
        net.legacy_links[dev].taps.clear()
        it = iter(old_frames * (trials // len(old_frames) + 1))
        net.legacy_links[dev].add_tap(lambda _f: next(it))
        ok = 0
        for _ in range(trials):
            ev = net.poll_device(dev)
            net.t_ms += 2_000
            ok += bool(ev.get("accepted"))
        out["cases"].append({"case": "Last-mile replay through the gateway",
                             "defence": "legacy sequence tracking at gateway" if check else "stateless gateway",
                             "replay_accepted_pct": _rate(ok, trials)})
    return out


# --------------------------------------------------------------------- TV8
BAUD_RATES = (1_200, 9_600, 19_200, 115_200)


def tv8_overhead(polls: int = 300, seed: int = 18) -> dict:
    payload = TelemetryReading.PAYLOAD.size
    ste_size = HEADER_LEN + payload + TAG_LEN
    legacy_size = FRAME_LEN
    link = []
    for baud in BAUD_RATES:
        byte_ms = 10_000 / baud            # 8N1 framing: 10 bits per byte
        link.append({"baud": baud, "legacy_ms": round(legacy_size * byte_ms, 2),
                     "ste_ms": round(ste_size * byte_ms, 2),
                     "scan_8_devices_legacy_ms": round(8 * legacy_size * byte_ms, 1),
                     "scan_8_devices_ste_ms": round(8 * ste_size * byte_ms, 1)})
    latency = {}
    for engine in ("library", "educational"):
        net = GridNetwork(MigrationMode.STRICT_AES, seed=seed, engine=engine)
        per_cipher: dict[str, list[float]] = {}
        for ev in net.run(polls if engine == "library" else polls // 3):
            if ev.get("timings_us"):
                per_cipher.setdefault(ev["cipher"], []).append(ev["timings_us"]["total"])
        latency[engine] = {c: {"median_us": round(statistics.median(v), 1),
                               "p95_us": round(sorted(v)[int(0.95 * (len(v) - 1))], 1),
                               "samples": len(v)} for c, v in per_cipher.items()}
    return {"id": "TV8", "title": "Bandwidth and latency overhead", "legacy_frame_bytes": legacy_size,
            "payload_bytes": payload, "ste_bytes": ste_size, "ste_overhead_bytes": OVERHEAD,
            "size_increase_pct": round(100 * (ste_size - legacy_size) / legacy_size, 1),
            "link": link, "gateway_latency": latency, "scan_cycle_ms": 2_000,
            "devices": len(DEFAULT_DEVICES)}


def run_all() -> list[dict]:
    return [tv1_last_mile_injection(), tv2_downgrade(), tv3_replay(), tv8_overhead()]
