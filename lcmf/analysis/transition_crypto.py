"""Cryptographic transition vulnerabilities (TV4, TV5, TV6, TV7).

These experiments show that "switching to AES" is not sufficient by itself:
the mode of operation, nonce management and key provenance decide whether
the migrated link is actually secure.

TV4  Malleability: blind tampering of legacy and unauthenticated AES (CBC/CTR) vs GCM
TV5  ECB pattern leakage of low-entropy status telemetry
TV6  GCM nonce reuse after a gateway reboot (non-persistent counters)
TV7  AES keys derived from legacy keywords inherit the legacy key space

Owner: Member 2 (Modern Cryptography Engine & Secure Envelope)
"""
from __future__ import annotations

import hashlib
import math
import random
import shutil
import struct
import tempfile
import time
from collections import Counter

from ..classical import Z36
from ..gateway import DeviceProfile, ProtocolTranslationGateway, parse_header
from ..gateway.envelope import open_body
from ..gateway.policy import MigrationMode
from ..grid.legacy_codec import FrameError, decode_telemetry, legacy_decrypt
from ..grid.network import GridNetwork, Recorder
from ..modern import aes_modes
from ..modern.aead import LibraryAESGCM
from ..modern.aes_modes import AuthenticationError
from ..modern.keystore import UPLINK, KeyStore, LegacyDerivedKeyStore
from .cryptanalysis import WORDLIST, break_vigenere

BRK_POS = 45                 # breaker symbol in the legacy frame
CHK_TENS, CHK_UNITS = 50, 51
BRK_OFFSET = 12              # breaker byte in the 15-byte modern payload


def _rate(hits: int, total: int) -> float:
    return round(100.0 * hits / total, 2) if total else 0.0


# --------------------------------------------------------------------- TV4
def tv4_malleability(trials: int = 200, seed: int = 14) -> dict:
    """Goal of the attacker: make SCADA show breaker OPEN while it is CLOSED, without any key."""
    rng = random.Random(seed)
    net = GridNetwork(MigrationMode.LEGACY_ONLY, seed=seed)
    rtu = net.rtus[4]                                   # Vigenere-protected RTU
    key = rng.randbytes(32)
    gcm = LibraryAESGCM(key)
    hits = Counter()
    for i in range(trials):
        reading, _, ct = rtu.transmit(net.t_ms + 2_000 * i)
        target = reading.evolve(breaker_closed=False)

        # Legacy additive cipher: 'C'(2) -> 'O'(14) is +12; patch checksum by +12 (tens +1, units +2).
        c = list(ct)
        for pos, delta in ((BRK_POS, 12), (CHK_TENS, 1), (CHK_UNITS, 2)):
            c[pos] = Z36[(Z36.index(c[pos]) + delta) % 36]
        try:
            got = decode_telemetry(legacy_decrypt(rtu.cipher, "".join(c)), reading.timestamp_ms)
            hits["legacy_vigenere"] += got == target
        except FrameError:
            pass

        payload = reading.to_payload()
        # AES-CTR without integrity: flip the breaker bit in the ciphertext.
        ctr0 = rng.randbytes(16)
        ct_ctr = bytearray(aes_modes.ctr_xcrypt(key, ctr0, payload))
        ct_ctr[BRK_OFFSET] ^= 0x01
        hits["aes_ctr"] += aes_modes.ctr_xcrypt(key, ctr0, bytes(ct_ctr)) == target.to_payload()

        # AES-CBC without integrity: flip the matching IV bit (first block).
        iv = bytearray(rng.randbytes(16))
        ct_cbc = aes_modes.cbc_encrypt(key, bytes(iv), payload)
        iv[BRK_OFFSET] ^= 0x01
        hits["aes_cbc"] += aes_modes.cbc_decrypt(key, bytes(iv), ct_cbc) == target.to_payload()

        # AES-GCM (the STE): same bit flip, tag must fail.
        nonce = rng.randbytes(12)
        sealed = bytearray(gcm.seal(nonce, payload, b"hdr"))
        sealed[BRK_OFFSET] ^= 0x01
        try:
            hits["aes_gcm"] += gcm.open(nonce, bytes(sealed), b"hdr") == target.to_payload()
        except AuthenticationError:
            pass
    rows = [
        {"scheme": "Legacy Vigenere (+checksum patch)", "integrity": "non-cryptographic checksum",
         "tamper_success_pct": _rate(hits["legacy_vigenere"], trials)},
        {"scheme": "AES-256-CBC, no MAC (IV bit flip)", "integrity": "none",
         "tamper_success_pct": _rate(hits["aes_cbc"], trials)},
        {"scheme": "AES-256-CTR, no MAC (bit flip)", "integrity": "none",
         "tamper_success_pct": _rate(hits["aes_ctr"], trials)},
        {"scheme": "AES-256-GCM (STE)", "integrity": "128-bit GMAC tag",
         "tamper_success_pct": _rate(hits["aes_gcm"], trials)},
    ]
    return {"id": "TV4", "title": "Malleability of legacy and unauthenticated AES", "trials": trials,
            "rows": rows}


# --------------------------------------------------------------------- TV5
STATUS = struct.Struct(">HBB11x")   # 15-byte status word: device, breaker, alarm flags


def breaker_timeline(minutes: int = 1440) -> list[tuple[int, int]]:
    """(breaker_closed, alarm) per minute: two switching operations and one protection trip."""
    timeline = []
    for m in range(minutes):
        closed, alarm = 1, 0
        if 600 <= m < 645 or 920 <= m < 930:     # planned maintenance windows
            closed = 0
        if 1145 <= m < 1152:                     # protection trip
            closed, alarm = 0, 1
        timeline.append((closed, alarm))
    return timeline


def tv5_ecb_leakage(minutes: int = 1440, seed: int = 15) -> dict:
    rng = random.Random(seed)
    key = rng.randbytes(32)
    gcm = LibraryAESGCM(key)
    timeline = breaker_timeline(minutes)
    ecb, gcm_ct = [], []
    for m, (closed, alarm) in enumerate(timeline):
        pt = STATUS.pack(1, closed, alarm)
        ecb.append(aes_modes.ecb_encrypt(key, pt))
        gcm_ct.append(gcm.seal(m.to_bytes(12, "big"), pt, b""))

    def attacker_accuracy(cts: list[bytes]) -> tuple[float, float]:
        """Attacker rule: the most frequent ciphertext is the normal (closed) state."""
        normal = Counter(cts).most_common(1)[0][0]
        pred_closed = [ct == normal for ct in cts]
        truth = [c == 1 for c, _ in timeline]
        tp = sum(p and t for p, t in zip(pred_closed, truth))
        tn = sum((not p) and (not t) for p, t in zip(pred_closed, truth))
        pos, neg = sum(truth), len(truth) - sum(truth)
        alarms = len(truth) - sum(pred_closed)              # minutes flagged as "outage"
        balanced = 0.5 * (tp / pos + tn / neg)
        return round(100 * balanced, 2), round(100 * tn / alarms, 2) if alarms else 0.0

    ecb_bal, ecb_prec = attacker_accuracy(ecb)
    gcm_bal, gcm_prec = attacker_accuracy(gcm_ct)
    return {"id": "TV5", "title": "ECB pattern leakage", "messages": minutes,
            "abnormal_minutes": sum(1 for c, _ in timeline if not c),
            "rows": [
                {"mode": "AES-256-ECB", "distinct_ciphertexts": len(set(ecb)),
                 "attacker_balanced_accuracy_pct": ecb_bal, "outage_alarm_precision_pct": ecb_prec},
                {"mode": "AES-256-GCM", "distinct_ciphertexts": len(set(gcm_ct)),
                 "attacker_balanced_accuracy_pct": gcm_bal, "outage_alarm_precision_pct": gcm_prec},
            ]}


# --------------------------------------------------------------------- TV6
def tv6_nonce_reuse(polls: int = 120, reboot_every: int = 30, seed: int = 16) -> dict:
    rows = []
    for persistent in (False, True):
        state_dir = tempfile.mkdtemp(prefix="lcmf_nonce_") if persistent else None
        try:
            net = GridNetwork(MigrationMode.STRICT_AES, seed=seed, state_dir=state_dir)
            rec = net.wan.add_tap(Recorder())
            post_total = post_ok = reboots = 0
            for p in range(polls):
                if p and p % reboot_every == 0:
                    for nm in net.gateway.nonces.values():
                        nm.simulate_reboot()
                    reboots += 1
                for ev in net.step():
                    if reboots and ev["state"] == "BRIDGED":
                        post_total += 1
                        post_ok += bool(ev.get("accepted"))
            seen: dict[tuple[int, int, bytes], bytes] = {}
            collisions, recovered_bytes, total_bytes = 0, 0, 0
            for frame in rec.frames:
                if not isinstance(frame, bytes):
                    continue
                hdr, aad, body = parse_header(frame)
                k = (hdr.device_id, hdr.key_id, hdr.nonce)
                if k in seen:
                    collisions += 1
                    # Attacker knows (or predicts) the earlier plaintext P1:  P2 = C1 xor C2 xor P1
                    engine = LibraryAESGCM(net.keystore.derive(hdr.device_id, UPLINK, hdr.key_id))
                    prev = seen[k]
                    p_hdr, p_aad, p_body = parse_header(prev)
                    p1 = open_body(engine, p_hdr, p_aad, p_body)
                    p2_true = open_body(engine, hdr, aad, body)
                    c1, c2 = p_body[:-16], body[:-16]
                    p2_guess = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, p1))
                    recovered_bytes += sum(x == y for x, y in zip(p2_guess, p2_true))
                    total_bytes += len(p2_true)
                else:
                    seen[k] = frame
            rows.append({"counter_storage": "persistent (reserved blocks)" if persistent else "RAM only",
                         "reboots": reboots, "envelopes": len(seen) + collisions,
                         "nonce_collisions": collisions,
                         "plaintext_recovered_pct": _rate(recovered_bytes, total_bytes) if total_bytes else 0.0,
                         "post_reboot_delivery_pct": _rate(post_ok, post_total)})
        finally:
            if state_dir:
                shutil.rmtree(state_dir, ignore_errors=True)
    return {"id": "TV6", "title": "AES-GCM nonce reuse after reboot", "polls": polls,
            "reboot_every_polls": reboot_every, "rows": rows}


# --------------------------------------------------------------------- TV7
def _dictionary_attack(envelope: bytes, words: list[str]) -> tuple[str | None, int, float]:
    hdr, aad, body = parse_header(envelope)
    t0 = time.perf_counter()
    for i, w in enumerate(words, 1):
        try:
            open_body(LibraryAESGCM(hashlib.sha256(w.encode()).digest()), hdr, aad, body)
            return w, i, (time.perf_counter() - t0) * 1000
        except AuthenticationError:
            continue
    return None, len(words), (time.perf_counter() - t0) * 1000


def tv7_legacy_derived_keys(seed: int = 17) -> dict:
    dev, keyword = 4, "GRIDLOCK"
    net = GridNetwork(MigrationMode.LEGACY_ONLY, seed=seed)
    frames = [net.rtus[dev].transmit(net.t_ms + 2_000 * i)[2] for i in range(3)]
    profile = [DeviceProfile(dev, "Feeder 4", {"type": "vigenere", "key": keyword})]
    rows = []
    for label, ks in (("SHA-256(legacy keyword)", LegacyDerivedKeyStore(keyword)),
                      ("HKDF-SHA256(random 256-bit master)", KeyStore(random.Random(seed).randbytes(32)))):
        gw = ProtocolTranslationGateway(1, ks, profile, plausibility=None)
        env = gw.translate_uplink(dev, frames[0], net.t_ms).envelope
        # Pivot: break the legacy cipher, hash the recovered keyword, open the envelope.
        legacy = break_vigenere(frames[:1])
        hdr, aad, body = parse_header(env)
        try:
            open_body(LibraryAESGCM(hashlib.sha256(legacy.key.encode()).digest()), hdr, aad, body)
            pivot = True
        except AuthenticationError:
            pivot = False
        word, guesses, ms = _dictionary_attack(env, WORDLIST)
        bits = math.log2(len(WORDLIST)) if word else float(ks.effective_key_bits)
        rows.append({"key_derivation": label, "pivot_from_broken_legacy_key": pivot,
                     "dictionary_hit": word, "guesses": guesses, "attack_ms": round(ms, 2),
                     "effective_key_bits": round(bits, 1)})
    return {"id": "TV7", "title": "AES keys derived from legacy secrets", "device": dev,
            "wordlist_size": len(WORDLIST), "rows": rows}


def run_all() -> list[dict]:
    return [tv4_malleability(), tv5_ecb_leakage(), tv6_nonce_reuse(), tv7_legacy_derived_keys()]
