"""Experiment runner: produces every number used in the report and the slides.

``python -m lcmf experiments`` writes ``results/*.json``:

validation.json      published test vectors + round-trip / cross-engine checks
cryptanalysis.json   key recovery for every legacy cipher, key spaces, statistics
transition.json      TV1-TV8 transition-vulnerability experiments
benchmark.json       micro-benchmarks
integrity.json       end-to-end delivery and data integrity in all migration modes
summary.json         objectives -> measured results -> met / not met

Owner: Member 2 (experiment runner and validation); uses modules of all members.
"""
from __future__ import annotations

import json
import math
import os
import random
import time

from ..classical import (AdditiveCipher, AffineCipher, CaesarCipher, ColumnarTranspositionCipher,
                         PlayfairCipher, VigenereCipher, Z26, make_cipher)
from ..gateway.policy import MigrationMode
from ..grid.legacy_codec import encode_telemetry, legacy_decrypt
from ..grid.network import DEFAULT_DEVICES, GridNetwork
from ..grid.telemetry import TelemetryReading
from ..modern import aes_modes
from ..modern.aead import EducationalAESGCM, LibraryAESGCM
from ..modern.aes_core import AES
from . import benchmark, cryptanalysis as ca, transition_crypto, transition_system

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RESULTS_DIR = os.path.join(ROOT, "results")

ENGLISH_SAMPLE = (
    "The control centre of a modern electricity utility receives thousands of measurements every "
    "second from substations spread across the region. Operators rely on these readings to balance "
    "generation with demand, to detect faults on feeders and to restore supply after an outage. For "
    "decades the links between remote terminal units and the master station were protected, if at "
    "all, by simple substitution schemes that were chosen for their low cost rather than their "
    "strength. An adversary who records enough of this traffic can recover the key with nothing more "
    "than pencil, paper and the frequency of the letters in ordinary English text. Replacing these "
    "schemes with authenticated encryption is therefore an essential part of grid modernisation, but "
    "the transition itself introduces new risks that must be understood and managed carefully."
)


def _vec(module: str, name: str, expected: str, got: str) -> dict:
    return {"module": module, "test": name, "expected": expected, "got": got, "pass": expected == got}


# ------------------------------------------------------------------ validation
def validation() -> dict:
    v = [
        _vec("Caesar", "ATTACKATDAWN (Z26)", "DWWDFNDWGDZQ", CaesarCipher(Z26).encrypt("ATTACKATDAWN")),
        _vec("Additive", "HELLO, k=15 (Z26)", "WTAAD", AdditiveCipher(15, Z26).encrypt("HELLO")),
        _vec("Affine", "AFFINECIPHER, a=5 b=8", "IHHWVCSWFRCP", AffineCipher(5, 8, Z26).encrypt("AFFINECIPHER")),
        _vec("Vigenere", "ATTACKATDAWN, LEMON", "LXFOPVEFRNHR", VigenereCipher("LEMON", Z26).encrypt("ATTACKATDAWN")),
        _vec("Playfair", "HIDETHEGOLD..., PLAYFAIREXAMPLE", "BMODZBXDNABEKUDMUIXMMOUVIF",
             PlayfairCipher("PLAYFAIR EXAMPLE", Z26).encrypt("HIDETHEGOLDINTHETREESTUMP")),
        _vec("Columnar", "WEAREDISCOVERED..., ZEBRAS", "EVLNACDTESEAROFODEECWIREE",
             ColumnarTranspositionCipher("ZEBRAS", Z26).encrypt("WEAREDISCOVEREDFLEEATONCE")),
    ]
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    for bits, key, exp in [
        (128, "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (192, "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"),
    ]:
        aes = AES(bytes.fromhex(key))
        ct = aes.encrypt_block(pt)
        v.append(_vec(f"AES-{bits}", "FIPS-197 App. C encrypt", exp, ct.hex()))
        v.append(_vec(f"AES-{bits}", "FIPS-197 App. C decrypt", pt.hex(), aes.decrypt_block(ct).hex()))
    v.append(_vec("AES-128", "FIPS-197 App. B", "3925841d02dc09fbdc118597196a0b32",
                  AES(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")).encrypt_block(
                      bytes.fromhex("3243f6a8885a308d313198a2e0370734")).hex()))
    ct, tag = aes_modes.gcm_encrypt(bytes(16), bytes(12), bytes(16))
    v.append(_vec("AES-GCM", "GCM spec test case 2 (C||T)",
                  "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf", (ct + tag).hex()))
    k3 = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    p3 = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
    ct, tag = aes_modes.gcm_encrypt(k3, bytes.fromhex("cafebabefacedbaddecaf888"), p3)
    v.append(_vec("AES-GCM", "GCM spec test case 3 (tag)", "4d5c2af327cd64a62cf35abd2ba6fab4", tag.hex()))

    # Round trips over random telemetry frames for every legacy cipher.
    rng = random.Random(1)
    frames = [encode_telemetry(TelemetryReading(rng.randint(1, 99), rng.randint(0, 9999), rng.randint(0, 99999),
                                                rng.randint(0, 9999), rng.randint(0, 9999),
                                                rng.randint(0, 99999), rng.random() < 0.5))
              for _ in range(10_000)]
    roundtrip = []
    for _, _, spec, _ in DEFAULT_DEVICES[:7]:
        c = make_cipher(spec)
        fails = sum(legacy_decrypt(c, c.encrypt(f)) != f for f in frames)
        roundtrip.append({"cipher": c.name, "frames": len(frames), "failures": fails})

    # Educational GCM must be bit-identical to the library.
    agree = 0
    for i in range(500):
        key, nonce = rng.randbytes(32), rng.randbytes(12)
        msg, aad = rng.randbytes(i % 97), rng.randbytes(i % 41)
        lib, edu = LibraryAESGCM(key), EducationalAESGCM(key)
        sealed = lib.seal(nonce, msg, aad)
        agree += sealed == edu.seal(nonce, msg, aad) and edu.open(nonce, sealed, aad) == msg
    return {"vectors": v, "roundtrip": roundtrip, "gcm_cross_check": {"cases": 500, "identical": agree}}


# ------------------------------------------------------------------ cryptanalysis
def _captures(n: int, seed: int = 21) -> dict[int, list[str]]:
    net = GridNetwork(MigrationMode.LEGACY_ONLY, seed=seed)
    caps: dict[int, list[str]] = {d: [] for d in net.rtus}
    for i in range(n):
        for d, rtu in net.rtus.items():
            caps[d].append(rtu.transmit(net.t_ms + 2_000 * i)[2])
    return caps


def cryptanalysis(seed: int = 21) -> dict:
    caps = _captures(60, seed)
    attacks = [
        (1, "Caesar", "Additive shift 3 (fixed)", 1, ca.break_additive),
        (2, "Additive", "k = 17", 36, ca.break_additive),
        (3, "Affine", "a = 5, b = 8", 12 * 36, ca.break_affine),
        (4, "Vigenere", "GRIDLOCK (L = 8)", 36 ** 8, ca.break_vigenere),
        (5, "Playfair", "SUBSTATION (6x6)", math.factorial(36), ca.break_playfair_dictionary),
        (6, "Columnar", "BREAKER (7 columns)", math.factorial(7), ca.break_columnar),
    ]
    rows = []
    for dev, name, key, space, fn in attacks:
        res = fn(caps[dev][:10])
        rows.append({"device": dev, "cipher": name, "true_key": key, "key_space": str(space),
                     "key_space_bits": round(math.log2(space), 1) if space > 1 else 0.0,
                     **{k: v for k, v in res.as_dict().items() if k != "cipher"}})

    # Known-plaintext attacks (the tags are known plaintext in every frame).
    net = GridNetwork(MigrationMode.LEGACY_ONLY, seed=seed)
    rtu3, rtu4 = net.rtus[3], net.rtus[4]
    _, p3, c3 = rtu3.transmit(net.t_ms)
    _, p4, c4 = rtu4.transmit(net.t_ms)
    kpa = {"affine": list(ca.affine_known_plaintext(p3[:3], c3[:3]) or ()),
           "vigenere": ca.vigenere_known_plaintext(p4, c4, 8)}

    # Playfair digram codebook coverage as an attacker observes more known-plaintext frames.
    pf = PlayfairCipher("SUBSTATION")
    net = GridNetwork(MigrationMode.LEGACY_ONLY, seed=seed + 1)
    pairs = []
    for i in range(220):
        _, p, c = net.rtus[5].transmit(net.t_ms + 2_000 * i)
        pairs.append((p, c))
    train, test = pairs[:200], pairs[200:]
    curve = []
    for k in (1, 2, 5, 10, 20, 50, 100, 200):
        book = ca.PlayfairCodebook()
        for p, c in train[:k]:
            book.learn(p, c)
        cov = sum(book.decrypt_partial(c)[1] for _, c in test) / len(test)
        curve.append({"frames_observed": k, "digram_coverage_pct": round(100 * cov, 1),
                      "codebook_entries": len(book.table)})
    assert pf.encrypt(pairs[0][0]) == pairs[0][1]

    # Frequency statistics: substitution preserves the profile, Vigenere flattens it, AES is uniform.
    plain = [legacy_decrypt(make_cipher(DEFAULT_DEVICES[3][2]), c) for c in caps[4]]
    profiles = {"Plaintext frames": ca.symbol_frequencies(plain),
                "Caesar": ca.symbol_frequencies(caps[1]),
                "Affine": ca.symbol_frequencies(caps[3]),
                "Vigenere": ca.symbol_frequencies(caps[4]),
                "Columnar": ca.symbol_frequencies(caps[6])}
    ioc = {name: round(ca.index_of_coincidence("".join(texts)), 4)
           for name, texts in {"Plaintext frames": plain, "Caesar": caps[1], "Affine": caps[3],
                               "Vigenere": caps[4], "Playfair": caps[5], "Columnar": caps[6]}.items()}
    lib = LibraryAESGCM(bytes(range(32)))
    aes_bytes = b"".join(lib.seal(i.to_bytes(12, "big"), TelemetryReading(4, i, 11_000 + i % 50, 1_800, 5_000,
                                                                           3_300, True).to_payload(), b"")
                         for i in range(400))
    byte_hist = [aes_bytes.count(bytes([b])) for b in range(256)]

    # Textbook frequency analysis on English (Z26).
    eng = "".join(ch for ch in ENGLISH_SAMPLE.upper() if ch in Z26)
    c_eng = CaesarCipher(Z26, 3).encrypt(eng)
    v_eng = VigenereCipher("TRANSFORMER", Z26).encrypt(eng)
    shift, _ = ca.break_caesar_english(c_eng)
    t0 = time.perf_counter()
    vkey, vplain = ca.break_vigenere_english(v_eng)
    textbook = {"letters": len(eng), "caesar_shift_recovered": shift,
                "vigenere_period_friedman": ca.friedman_period(v_eng),
                "vigenere_key_recovered": vkey, "vigenere_plaintext_correct": vplain == eng,
                "vigenere_ms": round((time.perf_counter() - t0) * 1000, 2),
                "kasiski_top_factors": ca.kasiski_distances(v_eng).most_common(5)}
    return {"attacks": rows, "known_plaintext": kpa, "playfair_codebook": curve,
            "frequency_profiles": profiles, "index_of_coincidence": ioc,
            "aes_gcm_byte_histogram": byte_hist, "textbook_english": textbook}


# ------------------------------------------------------------------ integrity
def integrity(polls: int = 450) -> list[dict]:
    rows = []
    for mode in MigrationMode:
        net = GridNetwork(mode, seed=31)
        events = net.run(polls)
        delivered = [e for e in events if e.get("accepted")]
        corrupt = sum(1 for e in delivered
                      if {k: v for k, v in e["received"].items() if k != "timestamp_ms"}
                      != {k: v for k, v in e["truth"].items() if k != "timestamp_ms"})
        rows.append({"mode": mode.value, "frames": len(events), "delivered": len(delivered),
                     "delivered_pct": round(100 * len(delivered) / len(events), 2), "corrupted": corrupt,
                     "secure_path": net.scada.stats.get("accepted_secure", 0),
                     "legacy_path": net.scada.stats.get("accepted_legacy", 0)})
    return rows


# ------------------------------------------------------------------ objectives
def objectives(val: dict, crypt: dict, trans: list[dict], bench: dict, integ: list[dict]) -> list[dict]:
    tv = {t["id"]: t for t in trans}
    vec_ok = sum(x["pass"] for x in val["vectors"])
    classical_vec = [x for x in val["vectors"] if not x["module"].startswith("AES")]
    aes_vec = [x for x in val["vectors"] if x["module"].startswith("AES")]
    rt_fail = sum(r["failures"] for r in val["roundtrip"])
    gw_lat = tv["TV8"]["gateway_latency"]["library"]
    worst_median = max(v["median_us"] for v in gw_lat.values())
    attacks = crypt["attacks"]
    secure_block = [
        next(s for s in tv["TV1"]["scenarios"] if s["defence"].startswith("native"))["forged_accepted_pct"],
        next(m for m in tv["TV2"]["modes"] if m["mode"] == "HYBRID_PINNED")["forged_accepted_pct"],
        next(m for m in tv["TV2"]["modes"] if m["mode"] == "STRICT_AES")["forged_accepted_pct"],
        tv["TV3"]["cases"][1]["replay_accepted_pct"],
        tv["TV3"]["cases"][3]["replay_accepted_pct"],
        next(r for r in tv["TV4"]["rows"] if "GCM" in r["scheme"])["tamper_success_pct"],
    ]
    link9600 = next(x for x in tv["TV8"]["link"] if x["baud"] == 9600)
    return [
        {"id": "O1", "objective": "Implement six legacy ciphers correctly",
         "target": "100 % of textbook vectors; 0 round-trip failures on 10,000 frames per cipher",
         "measured": f"{sum(x['pass'] for x in classical_vec)}/{len(classical_vec)} vectors; "
                     f"{rt_fail} failures in {sum(r['frames'] for r in val['roundtrip']):,} round trips",
         "met": all(x["pass"] for x in classical_vec) and rt_fail == 0},
        {"id": "O2", "objective": "Implement AES-128/192/256 and GCM from first principles",
         "target": "100 % of FIPS-197 / GCM vectors; bit-identical to library on 500 cases",
         "measured": f"{sum(x['pass'] for x in aes_vec)}/{len(aes_vec)} vectors; "
                     f"{val['gcm_cross_check']['identical']}/500 identical",
         "met": all(x["pass"] for x in aes_vec) and val["gcm_cross_check"]["identical"] == 500},
        {"id": "O3", "objective": "Translate legacy telemetry to AES-GCM without data loss or delay",
         "target": "0 corrupted readings in all 4 modes; median gateway latency < 1 ms",
         "measured": f"{sum(r['corrupted'] for r in integ)} corrupted of "
                     f"{sum(r['delivered'] for r in integ):,}; worst median {worst_median:.1f} us",
         "met": sum(r["corrupted"] for r in integ) == 0 and worst_median < 1000},
        {"id": "O4", "objective": "Break every legacy cipher from captured traffic",
         "target": "key recovered from <= 3 frames in < 1 s for each cipher",
         "measured": f"{sum(a['success'] for a in attacks)}/{len(attacks)} keys; max "
                     f"{max(a['frames_used'] for a in attacks)} frames; max "
                     f"{max(a['elapsed_ms'] for a in attacks):.0f} ms",
         "met": all(a["success"] and a["frames_used"] <= 3 and a["elapsed_ms"] < 1000 for a in attacks)},
        {"id": "O5", "objective": "Secure configuration blocks forged, replayed, tampered and downgraded frames",
         "target": "0 % acceptance in every STRICT / PINNED / GCM scenario",
         "measured": f"max acceptance {max(secure_block):.1f} % across {len(secure_block)} scenarios",
         "met": max(secure_block) == 0},
        {"id": "O6", "objective": "Identify and quantify transition vulnerabilities with mitigations",
         "target": ">= 8 vulnerabilities, each with a measured mitigation",
         "measured": f"{len(trans)} vulnerabilities (TV1-TV8) measured", "met": len(trans) >= 8},
        {"id": "O7", "objective": "Keep the secure envelope within legacy-link budgets",
         "target": "overhead <= 64 B/frame; 8-device scan at 9600 baud < 2 s cycle",
         "measured": f"{tv['TV8']['ste_overhead_bytes']} B overhead; scan {link9600['scan_8_devices_ste_ms']:.0f} ms",
         "met": tv["TV8"]["ste_overhead_bytes"] <= 64 and link9600["scan_8_devices_ste_ms"] < 2000},
    ]


def _write(name: str, data, out_dir: str) -> str:
    path = os.path.join(out_dir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    return path


def run_all(out_dir: str = RESULTS_DIR, log=print) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.perf_counter()
    log("[1/6] validation vectors and round trips ...")
    val = validation()
    log("[2/6] cryptanalysis of legacy ciphers ...")
    crypt = cryptanalysis()
    log("[3/6] transition vulnerabilities TV1-TV8 ...")
    trans = sorted(transition_system.run_all() + transition_crypto.run_all(), key=lambda t: t["id"])
    log("[4/6] benchmarks ...")
    bench = benchmark.run_all()
    log("[5/6] end-to-end integrity in all migration modes ...")
    integ = integrity()
    log("[6/6] objectives ...")
    summary = {"objectives": objectives(val, crypt, trans, bench, integ),
               "runtime_s": round(time.perf_counter() - t0, 1), "environment": bench["environment"]}
    for name, data in (("validation.json", val), ("cryptanalysis.json", crypt), ("transition.json", trans),
                       ("benchmark.json", bench), ("integrity.json", integ), ("summary.json", summary)):
        _write(name, data, out_dir)
    return summary
