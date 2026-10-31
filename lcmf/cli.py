"""Command-line interface.

    python -m lcmf demo                     guided end-to-end demonstration (viva)
    python -m lcmf simulate --mode STRICT_AES --polls 5
    python -m lcmf cipher affine --a 5 --b 8 encrypt "RTU01SEQ0001"
    python -m lcmf attack                   break every legacy cipher from captured frames
    python -m lcmf transition               run TV1-TV8 and print the findings
    python -m lcmf experiments              regenerate results/*.json

Owner: Member 3 (integration)
"""
from __future__ import annotations

import argparse
import sys
import textwrap

from . import __version__

WIDTH = 96


def _setup_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def banner(title: str) -> None:
    print("\n" + "=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def table(rows: list[dict], cols: list[tuple[str, str, int]]) -> None:
    """cols = [(key, header, width)]"""
    print("  ".join(h.ljust(w)[:w] for _, h, w in cols))
    print("  ".join("-" * w for _, _, w in cols))
    for r in rows:
        print("  ".join(str(r.get(k, "")).ljust(w)[:w] for k, _, w in cols))


def pause(enabled: bool) -> None:
    if enabled:
        try:
            input("\n  [press Enter to continue] ")
        except EOFError:
            pass


# ---------------------------------------------------------------------- demo
def cmd_demo(args) -> None:
    from .analysis import cryptanalysis as ca, transition_crypto as tc, transition_system as ts
    from .classical import make_cipher
    from .gateway import parse_header
    from .grid.network import DEFAULT_DEVICES, GridNetwork
    from .modern.aes_core import AES

    step = args.interactive
    banner(f"LCMF v{__version__} - Legacy Cipher Migration Framework for ICS: guided demonstration")
    print(textwrap.fill("Scenario: a distribution utility with eight 11 kV feeders. Each RTU still speaks a "
                        "historical cipher. The protocol-translation gateway wraps their telemetry into "
                        "AES-256-GCM envelopes, and we measure what can still go wrong during the migration.",
                        WIDTH))

    banner("Module 1 - Legacy cipher suite on one telemetry frame")
    net = GridNetwork("HYBRID_PINNED", seed=args.seed)
    from .grid.legacy_codec import encode_telemetry
    reading = net.rtus[1].measure(net.t_ms)
    frame = encode_telemetry(reading)
    print(f"  plaintext frame : {frame}")
    for _, _, spec, _ in DEFAULT_DEVICES[:6]:
        c = make_cipher(spec)
        print(f"  {c.name:<9} {c.describe_key():<34} -> {c.encrypt(frame)}")
    pause(step)

    banner("Module 2 - AES-256 from first principles (FIPS-197 Appendix C.3)")
    aes = AES(bytes(range(32)))
    ct = aes.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"))
    print(f"  key        000102...1f\n  plaintext  00112233445566778899aabbccddeeff\n  ciphertext {ct.hex()}")
    print(f"  expected   8ea2b7ca516745bfeafc49904b496089   -> {'PASS' if ct.hex() == '8ea2b7ca516745bfeafc49904b496089' else 'FAIL'}")
    pause(step)

    banner("Module 3 - Protocol-translation gateway (HYBRID_PINNED migration phase)")
    events = net.step()
    for e in events:
        print(f"\n  Device {e['device_id']} [{e['state']}] {e['name']}  cipher={e['cipher']}")
        if e.get("legacy_frame"):
            print(f"    legacy wire  : {e['legacy_frame']}")
            print(f"    plaintext    : {e['plaintext']}")
        if e.get("envelope"):
            hdr = parse_header(bytes.fromhex(e["envelope"]))[0]
            print(f"    STE ({len(e['envelope']) // 2} B)  : {e['envelope'][:74]}...")
            print(f"    STE header   : dev={hdr.device_id} seq={hdr.seq} key_id={hdr.key_id} nonce={hdr.nonce.hex()}")
        r = e.get("received") or {}
        print(f"    SCADA        : {'ACCEPTED' if e['accepted'] else 'REJECTED'} via {e.get('path')} "
              f"-> V={r.get('voltage_v')} V  I={r.get('current_a')} A  f={r.get('frequency_hz')} Hz  "
              f"P={r.get('power_kw')} kW")
    pause(step)

    banner("Module 4 - Downlink: SCADA breaker command through the gateway")
    for dev in (4, 7, 8):
        res = net.send_command(dev, "OPEN")
        print(f"  OPEN -> device {dev} ({net.states[dev]}): {res['reason']}; breaker_closed={res['breaker_closed']}")
        net.t_ms += 2_000
        net.send_command(dev, "CLOS")
    pause(step)

    banner("Module 5 - Cryptanalysis: an eavesdropper breaks every legacy cipher")
    old = GridNetwork("LEGACY_ONLY", seed=args.seed)
    caps = {d: [old.rtus[d].transmit(old.t_ms + 2_000 * i)[2] for i in range(5)] for d in old.rtus}
    rows = []
    for dev, fn in ((1, ca.break_additive), (2, ca.break_additive), (3, ca.break_affine), (4, ca.break_vigenere),
                    (5, ca.break_playfair_dictionary), (6, ca.break_columnar)):
        r = fn(caps[dev])
        rows.append({"dev": dev, "cipher": old.profiles[dev - 1].cipher_spec["type"], "key": r.key,
                     "ok": "BROKEN" if r.success else "-", "frames": r.frames_used, "tried": r.candidates_tried,
                     "ms": f"{r.elapsed_ms:.1f}"})
    table(rows, [("dev", "Dev", 3), ("cipher", "Cipher", 9), ("key", "Recovered key", 24), ("ok", "Result", 7),
                 ("frames", "Frames", 6), ("tried", "Keys tried", 10), ("ms", "Time ms", 8)])
    pause(step)

    banner("Module 6 - Transition vulnerabilities (attack success, lower is better)")
    tv1 = ts.tv1_last_mile_injection(trials=20)
    for s in tv1["scenarios"]:
        print(f"  TV1 last-mile FDIA [{s['attack']:<8}] {s['defence']:<42} forged accepted {s['forged_accepted_pct']:6.1f} %")
    for m in ts.tv2_downgrade(trials=20)["modes"]:
        print(f"  TV2 downgrade      {m['mode']:<51} forged accepted {m['forged_accepted_pct']:6.1f} %")
    for c in ts.tv3_replay(trials=20)["cases"]:
        print(f"  TV3 {c['case'][:34]:<34} {c['defence'][:26]:<26} replay accepted {c['replay_accepted_pct']:6.1f} %")
    for r in tc.tv4_malleability(trials=50)["rows"]:
        print(f"  TV4 tamper         {r['scheme']:<51} success         {r['tamper_success_pct']:6.1f} %")
    for r in tc.tv5_ecb_leakage()["rows"]:
        print(f"  TV5 pattern leak   {r['mode']:<51} attacker acc.   {r['attacker_balanced_accuracy_pct']:6.1f} %")
    for r in tc.tv6_nonce_reuse(polls=60, reboot_every=20)["rows"]:
        print(f"  TV6 nonce reuse    {r['counter_storage']:<51} collisions      {r['nonce_collisions']:6d}")
    for r in tc.tv7_legacy_derived_keys()["rows"]:
        print(f"  TV7 key derivation {r['key_derivation']:<51} dictionary hit  {str(r['dictionary_hit']):>6}")
    tv8 = ts.tv8_overhead(polls=60)
    print(f"  TV8 overhead       legacy {tv8['legacy_frame_bytes']} B -> STE {tv8['ste_bytes']} B "
          f"(+{tv8['size_increase_pct']} %), median gateway latency "
          f"{max(v['median_us'] for v in tv8['gateway_latency']['library'].values()):.0f} us")
    banner("Demonstration complete - see results/ and docs/ for the full evaluation")


# ---------------------------------------------------------------------- simulate
def cmd_simulate(args) -> None:
    from .grid.network import GridNetwork
    net = GridNetwork(args.mode, seed=args.seed, engine=args.engine)
    banner(f"Simulation: mode={args.mode} engine={args.engine} polls={args.polls}")
    rows = []
    for e in net.run(args.polls):
        r = e.get("received") or {}
        rows.append({"t": (e["t_ms"] // 1000) % 86_400, "dev": e["device_id"], "state": e["state"],
                     "cipher": e["cipher"], "path": e.get("path"), "ok": "OK" if e["accepted"] else "REJ",
                     "v": r.get("voltage_v"), "i": r.get("current_a"), "f": r.get("frequency_hz"),
                     "p": r.get("power_kw"), "bytes": e.get("wire_bytes")})
    table(rows, [("t", "t(s)", 6), ("dev", "Dev", 3), ("state", "State", 13), ("cipher", "Legacy", 11),
                 ("path", "Path", 6), ("ok", "SCADA", 5), ("v", "V", 6), ("i", "I(A)", 6), ("f", "f(Hz)", 6),
                 ("p", "P(kW)", 6), ("bytes", "Wire B", 6)])
    print(f"\nSCADA: {dict(net.scada.stats)}   Gateway: {dict(net.gateway.stats)}")


# ---------------------------------------------------------------------- cipher
def cmd_cipher(args) -> None:
    from .classical import Z26, Z36, make_cipher
    from .grid.legacy_codec import legacy_decrypt
    spec = {"type": args.type, "alphabet": Z26 if args.z26 else Z36}
    if args.type in ("additive",):
        spec["key"] = int(args.key)
    elif args.type in ("vigenere", "playfair", "columnar"):
        spec["key"] = args.key
    elif args.type == "affine":
        spec.update(a=args.a, b=args.b)
    c = make_cipher(spec)
    text = c.alphabet.normalise(args.text, drop_invalid=True)
    out = c.encrypt(text) if args.op == "encrypt" else legacy_decrypt(c, text)
    print(f"{c!r}  key space = {c.key_space:,}\n{args.op}: {text}\n    -> {out}")


# ---------------------------------------------------------------------- attack
def cmd_attack(args) -> None:
    from .analysis.experiments import cryptanalysis
    banner("Cryptanalysis of the legacy cipher suite (captured traffic, public frame format)")
    res = cryptanalysis(seed=args.seed)
    table(res["attacks"], [("cipher", "Cipher", 9), ("true_key", "True key", 22), ("key_space_bits", "Key bits", 8),
                           ("method", "Attack", 44), ("key", "Recovered", 22), ("frames_used", "Frames", 6)])
    tb = res["textbook_english"]
    print(f"\nTextbook (English, {tb['letters']} letters): Caesar shift {tb['caesar_shift_recovered']}, "
          f"Vigenere period {tb['vigenere_period_friedman']} key {tb['vigenere_key_recovered']}")
    print("Playfair digram codebook coverage: " +
          ", ".join(f"{p['frames_observed']} frames -> {p['digram_coverage_pct']} %" for p in res["playfair_codebook"]))


# ---------------------------------------------------------------------- transition
def cmd_transition(args) -> None:
    import json
    from .analysis import transition_crypto, transition_system
    banner("Transition vulnerabilities TV1-TV8")
    for tv in sorted(transition_system.run_all() + transition_crypto.run_all(), key=lambda t: t["id"]):
        print(f"\n{tv['id']}  {tv['title']}")
        body = {k: v for k, v in tv.items() if k not in ("id", "title")}
        print(textwrap.indent(json.dumps(body, indent=2, default=str), "    "))


def cmd_experiments(args) -> None:
    from .analysis.experiments import RESULTS_DIR, run_all
    banner("Running all experiments")
    summary = run_all(args.out or RESULTS_DIR)
    print()
    table(summary["objectives"], [("id", "ID", 3), ("objective", "Objective", 46), ("measured", "Measured", 52),
                                  ("met", "Met", 5)])
    print(f"\nResults written to {args.out or RESULTS_DIR}  ({summary['runtime_s']} s)")


def main(argv: list[str] | None = None) -> None:
    _setup_console()
    p = argparse.ArgumentParser(prog="lcmf", description="Legacy Cipher Migration Framework for ICS")
    p.add_argument("--version", action="version", version=f"lcmf {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("demo", help="guided end-to-end demonstration")
    d.add_argument("--interactive", action="store_true", help="pause between modules")
    d.add_argument("--seed", type=int, default=7)
    d.set_defaults(func=cmd_demo)

    s = sub.add_parser("simulate", help="run the smart-grid simulation")
    s.add_argument("--mode", default="HYBRID_PINNED",
                   choices=["LEGACY_ONLY", "HYBRID_PERMISSIVE", "HYBRID_PINNED", "STRICT_AES"])
    s.add_argument("--polls", type=int, default=3)
    s.add_argument("--engine", default="library", choices=["library", "educational"])
    s.add_argument("--seed", type=int, default=7)
    s.set_defaults(func=cmd_simulate)

    c = sub.add_parser("cipher", help="encrypt/decrypt with a legacy cipher")
    c.add_argument("type", choices=["caesar", "additive", "affine", "vigenere", "playfair", "columnar"])
    c.add_argument("op", choices=["encrypt", "decrypt"])
    c.add_argument("text")
    c.add_argument("--key", default="3")
    c.add_argument("--a", type=int, default=5)
    c.add_argument("--b", type=int, default=8)
    c.add_argument("--z26", action="store_true", help="use the A-Z textbook alphabet")
    c.set_defaults(func=cmd_cipher)

    a = sub.add_parser("attack", help="break every legacy cipher")
    a.add_argument("--seed", type=int, default=21)
    a.set_defaults(func=cmd_attack)

    sub.add_parser("transition", help="run TV1-TV8").set_defaults(func=cmd_transition)

    e = sub.add_parser("experiments", help="regenerate results/*.json")
    e.add_argument("--out", default=None)
    e.set_defaults(func=cmd_experiments)

    args = p.parse_args(argv)
    args.func(args)
