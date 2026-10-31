"""Generate every figure used in the report and presentation from results/*.json.

    python scripts/generate_figures.py          -> docs/figures/*.png

Owner: Member 1 (result visualisation).

Charts follow one visual system: categorical slots in fixed order (blue,
orange, aqua), thin marks, recessive grid, direct labels, a single y-axis.
"""
from __future__ import annotations

import json
import math
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
RES = os.path.join(ROOT, "results")
OUT = os.path.join(ROOT, "docs", "figures")

# ---- visual system ---------------------------------------------------------
SURFACE = "#fcfcfb"
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
BLUE, ORANGE, AQUA, RED, VIOLET = "#2a78d6", "#eb6834", "#1baf7a", "#e34948", "#6250d6"
TINT = {"blue": "#e4effb", "orange": "#fde9e0", "aqua": "#dcf3ea", "gray": "#f0efec", "red": "#fbe3e3",
        "violet": "#e9e6fa"}
EDGE = {"blue": BLUE, "orange": ORANGE, "aqua": "#14865d", "gray": MUTED, "red": RED, "violet": VIOLET}

plt.rcParams.update({
    "font.family": "Arial", "font.size": 9, "axes.edgecolor": AXIS, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.titlesize": 10, "axes.titleweight": "bold",
    "axes.titlecolor": INK, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE, "axes.spines.top": False, "axes.spines.right": False,
    "legend.frameon": False, "legend.fontsize": 8.5,
})


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as fh:
        return json.load(fh)


def save(fig, name):
    os.makedirs(OUT, exist_ok=True)
    fig.savefig(os.path.join(OUT, name), dpi=220, bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)
    print("  wrote", name)


def style_axis(ax, grid_axis="x"):
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)


# ---- diagram helpers ---------------------------------------------------------
def box(ax, x, y, w, h, text, tone="blue", size=8.5, bold=False, align="center", radius=0.012, lw=1.0):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={radius}",
                                facecolor=TINT[tone], edgecolor=EDGE[tone], linewidth=lw))
    tx = x + w / 2 if align == "center" else x + 0.01
    ax.text(tx, y + h / 2, text, ha=align, va="center", fontsize=size, color=INK,
            fontweight="bold" if bold else "normal", linespacing=1.25)


def zone(ax, x, y, w, h, title, tone):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.015",
                                facecolor="none", edgecolor=EDGE[tone], linewidth=1.2, linestyle=(0, (4, 3))))
    ax.text(x + 0.008, y + h - 0.012, title, ha="left", va="top", fontsize=9, color=EDGE[tone], fontweight="bold")


def arrow(ax, x1, y1, x2, y2, text="", color=INK2, style="-|>", ls="-", size=7.5, offset=(0, 0.018), rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=10, color=color,
                                 linewidth=1.0, linestyle=ls, connectionstyle=f"arc3,rad={rad}"))
    if text:
        ax.text((x1 + x2) / 2 + offset[0], (y1 + y2) / 2 + offset[1], text, ha="center", va="center",
                fontsize=size, color=INK2, backgroundcolor=SURFACE)


def canvas(w=10, h=5.5):
    fig = plt.figure(figsize=(w, h))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    return fig, ax


# ============================================================================ diagrams
def fig_architecture():
    fig, ax = canvas(10, 6.0)
    zone(ax, 0.01, 0.03, 0.24, 0.93, "FIELD (substations)", "orange")
    zone(ax, 0.30, 0.355, 0.36, 0.605, "PROTOCOL-TRANSLATION GATEWAY", "blue")
    zone(ax, 0.73, 0.03, 0.26, 0.93, "CONTROL CENTRE", "aqua")

    box(ax, 0.025, 0.70, 0.21, 0.17, "Legacy RTUs 1-6\nCaesar, Additive, Affine,\nVigenere, Playfair, Columnar\n(grid.simulator.RTU)", "orange", 7.8)
    box(ax, 0.025, 0.215, 0.21, 0.12, "Legacy RTU 7\nplaintext, not yet migrated\n(LEGACY_DIRECT)", "orange", 7.8)
    box(ax, 0.025, 0.05, 0.21, 0.12, "Upgraded RTU 8\nnative AES-256-GCM\n(grid.simulator.SecureRTU)", "aqua", 7.8)
    ax.text(0.13, 0.62, "legacy serial links\n(classical ciphers)", ha="center", fontsize=7.5, color=ORANGE)

    gx, gw, gh = 0.315, 0.33, 0.07
    steps = ["Legacy decryptor  (classical.*)", "Frame codec + checksum  (grid.legacy_codec)",
             "Identity / legacy-seq / plausibility checks\n(gateway.gateway, gateway.plausibility)",
             "STE sealer: AES-256-GCM, header as AAD\n(gateway.envelope, modern.aead)",
             "Key store HKDF-SHA256 + nonce manager\n(modern.keystore, modern.nonce)",
             "Downlink: verify command, re-encode legacy\n(translate_downlink, modern.replay)"]
    ys = [0.80 - i * (gh + 0.016) for i in range(len(steps))]
    for text, y in zip(steps, ys):
        box(ax, gx, y, gw, gh, text, "blue", 7.4)
    for y in ys[:3]:
        arrow(ax, gx + gw / 2, y, gx + gw / 2, y - 0.016, color=BLUE)

    box(ax, 0.745, 0.76, 0.23, 0.12, "Migration policy\nLEGACY_ONLY / HYBRID_* /\nSTRICT_AES (gateway.policy)", "aqua", 7.5)
    box(ax, 0.745, 0.54, 0.23, 0.12, "Secure ingress: replay window\n+ GCM verify (modern.replay)", "aqua", 7.5)
    box(ax, 0.745, 0.36, 0.23, 0.12, "SCADA master + historian\n(grid.scada.ScadaMaster)", "aqua", 7.5)
    box(ax, 0.745, 0.215, 0.23, 0.12, "Legacy ingress\n(only if policy allows)", "aqua", 7.5)
    arrow(ax, 0.86, 0.76, 0.86, 0.66, "rules", INK2, offset=(0.03, 0.0))
    arrow(ax, 0.86, 0.54, 0.86, 0.48, color=INK2)
    arrow(ax, 0.86, 0.335, 0.86, 0.36, color=INK2)

    a1y = ys[0] + gh / 2
    arrow(ax, 0.236, a1y, 0.315, a1y, "", ORANGE, ls="--")
    sealer_y = ys[3] + gh / 2
    arrow(ax, 0.645, sealer_y + 0.01, 0.745, sealer_y + 0.01, "", BLUE)
    ax.text(0.695, 0.70, "WAN\nSTE 68 B", ha="center", fontsize=7.2, color=BLUE)
    # bypass corridor below the gateway
    arrow(ax, 0.236, 0.275, 0.745, 0.275, "", ORANGE, ls="--")
    ax.text(0.48, 0.29, "legacy frames bypass the gateway (Phases 0-2)", fontsize=7.2, color=ORANGE, ha="center")
    ax.plot([0.236, 0.70, 0.70], [0.11, 0.11, sealer_y - 0.03], color="#14865d", linewidth=1.0)
    arrow(ax, 0.70, sealer_y - 0.03, 0.745, sealer_y - 0.03, "", "#14865d")
    ax.text(0.48, 0.125, "STE sealed at the RTU (end-to-end)", fontsize=7.2, color="#14865d", ha="center")
    down_y = ys[5] + gh / 2
    arrow(ax, 0.745, 0.42, 0.645, down_y, "", BLUE)
    ax.text(0.695, 0.445, "commands", fontsize=7.2, color=BLUE, ha="center")
    for label, (x, y) in (("A1", (0.275, a1y + 0.04)), ("A2", (0.695, sealer_y + 0.055))):
        ax.add_patch(plt.Circle((x, y), 0.017, facecolor=TINT["red"], edgecolor=RED, linewidth=1.0))
        ax.text(x, y, label, ha="center", va="center", fontsize=7, color=RED, fontweight="bold")
    ax.text(0.48, 0.195, "A1 = adversary on the legacy last mile    A2 = adversary on the WAN",
            fontsize=7.3, color=RED, ha="center", va="center")
    save(fig, "fig_architecture.png")


def fig_dfd0():
    fig, ax = canvas(9, 4.2)
    pw, ph = 0.24, 0.40                         # central process (rounded rectangle, DFD style)
    px, py = 0.5 - pw / 2, 0.30
    box(ax, px, py, pw, ph, "0\nLCMF Migration\nGateway System", "blue", 10, bold=True, radius=0.04, lw=1.4)
    ents = [("Legacy RTU", 0.02, 0.56), ("Upgraded RTU", 0.02, 0.25), ("SCADA master /\noperator", 0.80, 0.56),
            ("Security\nanalyst", 0.80, 0.25), ("Key\nprovisioning", 0.42, 0.84)]
    for t, x, y in ents:
        box(ax, x, y, 0.18, 0.13, t, "gray", 8.5, bold=True, radius=0.004)
    lx0, lx1, rx0, rx1 = 0.20, px, px + pw, 0.80

    def flow(x1, x2, y, text, color, above=True):
        arrow(ax, x1, y, x2, y, "", color)
        ax.text((x1 + x2) / 2, y + (0.025 if above else -0.025), text, ha="center",
                va="bottom" if above else "top", fontsize=7.8, color=INK2)

    flow(lx0, lx1, 0.65, "legacy-encrypted telemetry", ORANGE)
    flow(lx1, lx0, 0.60, "legacy commands", ORANGE, above=False)
    flow(lx0, lx1, 0.315, "STE telemetry", "#14865d")
    flow(rx0, rx1, 0.65, "authenticated readings", BLUE)
    flow(rx1, rx0, 0.60, "breaker commands", BLUE, above=False)
    flow(rx1, rx0, 0.34, "experiment config", INK2)
    flow(rx0, rx1, 0.29, "results, figures", INK2, above=False)
    arrow(ax, 0.5, 0.84, 0.5, py + ph, "", INK2)
    ax.text(0.515, 0.77, "master key", fontsize=7.8, color=INK2, va="center")
    save(fig, "fig_dfd0.png")


def fig_uplink_flow():
    fig, ax = canvas(10, 3.9)
    top = [("RTU measures\nV, I, f, P, breaker", "orange"), ("Encode legacy\nframe (52 symbols)", "orange"),
           ("Legacy encrypt\n(classical cipher)", "orange"), ("Gateway: legacy\ndecrypt", "blue"),
           ("Parse + checksum\n+ device id", "blue"), ("Legacy-seq and\nplausibility checks", "blue")]
    bot = [("Allocate seq +\nnonce (persistent)", "blue"), ("AES-256-GCM seal\nheader = AAD", "blue"),
           ("WAN", "gray"), ("SCADA: policy\naccepts secure?", "aqua"), ("Replay window +\ntimestamp", "aqua"),
           ("GCM verify +\nstore in historian", "aqua")]
    w, h, gap = 0.135, 0.2, 0.031
    for row, (items, y) in enumerate(((top, 0.68), (bot, 0.2))):
        for i, (t, tone) in enumerate(items):
            x = 0.02 + i * (w + gap)
            box(ax, x, y, w, h, t, tone, 8)
            if i < len(items) - 1:
                arrow(ax, x + w, y + h / 2, x + w + gap, y + h / 2, color=INK2)
    arrow(ax, 0.02 + 5 * (w + gap) + w / 2, 0.68, 0.02 + w / 2, 0.40, "", INK2, rad=0.0)
    for i, why in ((3, "reject: decrypt error"), (4, "reject: format / checksum"), (5, "reject: replay / implausible")):
        ax.text(0.02 + i * (w + gap) + w / 2, 0.925, why, ha="center", fontsize=7, color=RED)
    for i, why in ((9, "reject: policy"), (10, "reject: replayed / stale"), (11, "reject: tag mismatch")):
        ax.text(0.02 + (i - 6) * (w + gap) + w / 2, 0.08, why, ha="center", fontsize=7, color=RED)
    save(fig, "fig_uplink_flow.png")


def fig_frame_format():
    from lcmf.grid.legacy_codec import TELEMETRY_FIELDS
    fig, ax = canvas(10, 2.3)
    frame = "RTU04SEQ0042VLT11023CUR1873FRQ5001PWR03397BRKCCHK517"
    n = len(frame)
    cw = 0.96 / n
    pos = 0
    for tag, width, _ in TELEMETRY_FIELDS:
        for j, ch in enumerate(tag):
            x = 0.02 + (pos + j) * cw
            ax.add_patch(Rectangle((x, 0.48), cw, 0.22, facecolor=TINT["orange"], edgecolor=SURFACE, linewidth=1.2))
            ax.text(x + cw / 2, 0.59, ch, ha="center", va="center", fontsize=8, color=INK, family="Consolas")
        for j in range(width):
            x = 0.02 + (pos + len(tag) + j) * cw
            ax.add_patch(Rectangle((x, 0.48), cw, 0.22, facecolor=TINT["blue"], edgecolor=SURFACE, linewidth=1.2))
            ax.text(x + cw / 2, 0.59, frame[pos + len(tag) + j], ha="center", va="center", fontsize=8,
                    color=INK, family="Consolas")
        label = {"RTU": "device id", "SEQ": "sequence", "VLT": "voltage V", "CUR": "current 0.1 A",
                 "FRQ": "freq 0.01 Hz", "PWR": "power kW", "BRK": "breaker", "CHK": "checksum"}[tag]
        x0 = 0.02 + pos * cw
        x1 = 0.02 + (pos + len(tag) + width) * cw
        ax.plot([x0 + 0.002, x1 - 0.002], [0.42, 0.42], color=MUTED, linewidth=0.8)
        ax.text((x0 + x1) / 2, 0.33, label, ha="center", fontsize=7.5, color=INK2)
        pos += len(tag) + width
    ax.add_patch(Rectangle((0.02, 0.85), 0.02, 0.07, facecolor=TINT["orange"], edgecolor=EDGE["orange"]))
    ax.text(0.045, 0.885, "fixed tag = known plaintext (24 of 52 symbols)", va="center", fontsize=8, color=INK2)
    ax.add_patch(Rectangle((0.42, 0.85), 0.02, 0.07, facecolor=TINT["blue"], edgecolor=EDGE["blue"]))
    ax.text(0.445, 0.885, "variable field (digits, or C/O for the breaker)", va="center", fontsize=8, color=INK2)
    ax.text(0.02, 0.12, "Checksum = (sum of Z36 symbol indices of the body) mod 1000 - detects noise, "
            "not tampering, and is blind to transposed symbols.", fontsize=7.8, color=INK2)
    save(fig, "fig_frame_format.png")


def fig_envelope():
    fig, ax = canvas(10, 2.4)
    fields = [("magic", 2), ("ver", 1), ("type", 1), ("flags", 1), ("key_id", 2), ("dev_id", 2), ("seq", 8),
              ("timestamp_ms", 8), ("nonce", 12), ("ciphertext", 15), ("tag", 16)]
    total = sum(b for _, b in fields)
    x = 0.02
    unit = 0.96 / total
    for name, b in fields:
        tone = "gray" if name not in ("ciphertext", "tag", "nonce") else {"ciphertext": "blue", "tag": "aqua",
                                                                          "nonce": "violet"}[name]
        ax.add_patch(Rectangle((x, 0.45), b * unit, 0.25, facecolor=TINT[tone], edgecolor=SURFACE, linewidth=1.5))
        ax.text(x + b * unit / 2, 0.61, name, ha="center", va="center", fontsize=7.4 if b > 2 else 6.5,
                color=INK, rotation=0 if b > 2 else 90)
        ax.text(x + b * unit / 2, 0.50, f"{b}", ha="center", va="center", fontsize=6.8, color=INK2)
        x += b * unit
    def brace(x0, x1, y, text, color):
        ax.plot([x0, x0, x1, x1], [y + 0.03, y, y, y + 0.03], color=color, linewidth=1)
        ax.text((x0 + x1) / 2, y - 0.07, text, ha="center", fontsize=8, color=color)
    brace(0.02, 0.02 + 37 * unit, 0.36, "header = Associated Data (37 B, authenticated, sent in clear)", INK2)
    brace(0.02 + 37 * unit, 0.02 + 52 * unit, 0.36, "", BLUE)
    ax.text(0.02 + 44.5 * unit, 0.22, "encrypted\npayload 15 B", ha="center", fontsize=7.6, color=BLUE)
    brace(0.02 + 52 * unit, 0.98, 0.36, "128-bit GMAC tag", "#14865d")
    ax.text(0.02, 0.86, "Secure Telemetry Envelope (STE v1): 68 bytes for one reading - overhead 53 B "
            "(37 B header + 16 B tag)", fontsize=8.5, color=INK, fontweight="bold")
    save(fig, "fig_envelope.png")


def fig_migration():
    from lcmf.gateway.policy import MigrationMode
    from lcmf.grid.network import DEFAULT_DEVICES, device_states
    fig, ax = canvas(10, 3.9)
    modes = list(MigrationMode)
    tone = {"LEGACY_DIRECT": "orange", "BRIDGED": "blue", "NATIVE_AES": "aqua"}
    label = {"LEGACY_DIRECT": "legacy direct", "BRIDGED": "bridged", "NATIVE_AES": "native AES"}
    x0, cw, ch = 0.2, 0.19, 0.075
    for j, m in enumerate(modes):
        ax.text(x0 + j * cw + cw / 2, 0.93, f"Phase {j}\n{m.value}", ha="center", va="center", fontsize=8,
                fontweight="bold", color=INK)
        states = device_states(m)
        for i, (dev, name, spec, _) in enumerate(DEFAULT_DEVICES):
            y = 0.80 - i * (ch + 0.012)
            s = states[dev]
            box(ax, x0 + j * cw + 0.006, y - ch, cw - 0.012, ch, label[s], tone[s], 7.6, radius=0.006)
    for i, (dev, name, spec, _) in enumerate(DEFAULT_DEVICES):
        y = 0.80 - i * (ch + 0.012) - ch / 2
        ax.text(0.19, y, f"RTU {dev}  ({spec['type']})", ha="right", va="center", fontsize=8, color=INK2)
    rules = ["accepts legacy only", "accepts both (downgrade risk)", "migrated devices pinned", "secure only"]
    for j, r in enumerate(rules):
        ax.text(x0 + j * cw + cw / 2, 0.035, r, ha="center", fontsize=7.4, color=INK2, style="italic")
    save(fig, "fig_migration.png")


def fig_aes_round():
    fig, ax = canvas(10, 3.6)
    ys = 0.55
    seq = [("Plaintext\n128-bit state", "gray", 0.02, 0.10), ("AddRoundKey\nK0", "violet", 0.145, 0.10),
           ("SubBytes\n(S-box, GF(2^8)\ninverse + affine)", "blue", 0.29, 0.12),
           ("ShiftRows\nrow r << r", "blue", 0.435, 0.10), ("MixColumns\nGF(2^8) matrix", "blue", 0.56, 0.11),
           ("AddRoundKey\nK1..K13", "violet", 0.695, 0.10), ("Final round:\nSubBytes, ShiftRows,\nAddRoundKey K14", "blue", 0.82, 0.16)]
    for t, tone, x, w in seq:
        box(ax, x, ys, w, 0.24, t, tone, 7.8)
    xs = [(0.12, 0.145), (0.245, 0.29), (0.41, 0.435), (0.535, 0.56), (0.67, 0.695), (0.795, 0.82)]
    for a, b in xs:
        arrow(ax, a, ys + 0.12, b, ys + 0.12)
    arrow(ax, 0.745, ys + 0.24, 0.35, ys + 0.24, "", INK2, rad=0.35)
    ax.text(0.55, 0.86, "repeat for rounds 1-13 (AES-256: Nr = 14)", ha="center", fontsize=8, color=INK2)
    box(ax, 0.10, 0.10, 0.80, 0.18, "Key expansion: 256-bit key -> 60 words (Nk = 8) using RotWord, SubWord, Rcon\n"
        "-> 15 round keys K0..K14   (modern.aes_core.AES._expand_key)", "violet", 8)
    for x in (0.195, 0.745, 0.9):
        arrow(ax, min(x, 0.79), 0.28, x, ys, "", VIOLET, ls="--")
    save(fig, "fig_aes_round.png")


def fig_gcm():
    fig, ax = canvas(10, 3.9)
    box(ax, 0.02, 0.72, 0.16, 0.14, "J0 = nonce || 0^31 || 1\n(96-bit nonce)", "violet", 7.8)
    box(ax, 0.24, 0.72, 0.14, 0.14, "inc32(J0)", "violet", 7.8)
    box(ax, 0.44, 0.72, 0.14, 0.14, "E_K (AES-256)", "blue", 7.8)
    box(ax, 0.64, 0.72, 0.14, 0.14, "XOR plaintext\n-> ciphertext C", "blue", 7.8)
    box(ax, 0.02, 0.38, 0.16, 0.14, "AAD = 37-byte\nSTE header", "gray", 7.8)
    box(ax, 0.24, 0.38, 0.34, 0.14, "GHASH_H( AAD || C || len(AAD) || len(C) )\nH = E_K(0^128),  multiply in GF(2^128)", "aqua", 7.8)
    box(ax, 0.64, 0.38, 0.14, 0.14, "XOR E_K(J0)", "blue", 7.8)
    box(ax, 0.84, 0.38, 0.14, 0.14, "Tag T\n(128 bits)", "aqua", 7.8)
    for a, b, y in ((0.18, 0.24, 0.79), (0.38, 0.44, 0.79), (0.58, 0.64, 0.79), (0.18, 0.24, 0.45), (0.58, 0.64, 0.45),
                    (0.78, 0.84, 0.45)):
        arrow(ax, a, y, b, y)
    arrow(ax, 0.71, 0.72, 0.41, 0.52, "C feeds GHASH", INK2, offset=(0.05, 0.02))
    ax.text(0.02, 0.18, "Receiver recomputes T over the received header and ciphertext; any change to either "
            "-> tag mismatch -> frame rejected.\nNonce must never repeat under one key: a repeat leaks "
            "P1 xor P2 and the authentication key H (experiment TV6).", fontsize=8, color=INK2)
    save(fig, "fig_gcm.png")


def fig_class_diagram():
    fig, ax = canvas(10, 4.3)
    pk = [
        ("lcmf.classical  (Member 1)", "orange", 0.01, 0.53, 0.32, 0.44,
         "ClassicalCipher  <<abstract>>\n  encrypt(), decrypt(), key_space\n"
         "NullCipher\nAdditiveCipher  <-  CaesarCipher\nAffineCipher  (a, b, a_inv)\n"
         "VigenereCipher  (key, period)\nPlayfairCipher  (n x n square)\nColumnarTranspositionCipher\n"
         "make_cipher(spec)"),
        ("lcmf.modern + gateway.envelope  (Member 2)", "violet", 0.35, 0.53, 0.32, 0.44,
         "AES  (key schedule, encrypt/decrypt_block)\naes_modes: ECB, CBC, CTR, GCM, GHASH\n"
         "AEADEngine  <-  LibraryAESGCM, EducationalAESGCM\nKeyStore  (HKDF)  <-  LegacyDerivedKeyStore\n"
         "NonceManager  (persistent counter)\nReplayWindow  (64-bit bitmap)\nEnvelopeHeader, seal(), open_body()"),
        ("lcmf.grid + lcmf.gateway  (Member 3)", "blue", 0.69, 0.53, 0.30, 0.44,
         "TelemetryReading, Command\nlegacy_codec: encode/decode\nFeederModel, GridFrequency\n"
         "RTU  <-  SecureRTU\nProtocolTranslationGateway\nMigrationPolicy, PlausibilityFilter\n"
         "ScadaMaster\nGridNetwork, Channel, Recorder"),
        ("lcmf.analysis  (Members 1, 2, 3)", "aqua", 0.01, 0.04, 0.48, 0.42,
         "cryptanalysis (M1): break_additive, break_affine,\n  break_vigenere, break_playfair_dictionary,\n"
         "  break_columnar, PlayfairCodebook, IoC, chi-squared\n"
         "transition_crypto (M2): TV4 malleability, TV5 ECB,\n  TV6 nonce reuse, TV7 legacy-derived keys\n"
         "transition_system (M3): TV1 last mile, TV2 downgrade,\n  TV3 replay, TV8 overhead"),
        ("tooling", "gray", 0.51, 0.04, 0.48, 0.42,
         "experiments.run_all()  ->  results/*.json\nbenchmark (micro-benchmarks)\ncli: demo, simulate, cipher,\n"
         "  attack, transition, experiments\ntests/: 63 unit + integration tests\nscripts/generate_figures.py"),
    ]
    for title, tone, x, y, w, h, body in pk:
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.01",
                                    facecolor=TINT[tone], edgecolor=EDGE[tone], linewidth=1.1))
        ax.add_patch(Rectangle((x, y + h - 0.07), w, 0.07, facecolor=EDGE[tone], edgecolor=EDGE[tone]))
        ax.text(x + 0.01, y + h - 0.035, title, va="center", fontsize=8.5, color="white", fontweight="bold")
        ax.text(x + 0.012, y + h - 0.09, body, va="top", fontsize=7.6, color=INK, linespacing=1.4, family="Consolas")
    arrow(ax, 0.33, 0.75, 0.35, 0.75, "", INK2)
    arrow(ax, 0.67, 0.75, 0.69, 0.75, "", INK2)
    save(fig, "fig_class_diagram.png")


def fig_gantt(team):
    tasks = [("Problem study and literature review", 1, 2, "All"), ("Requirements and feasibility", 2, 3, "All"),
             ("System design and protocol formats", 3, 4, "All"),
             ("Classical cipher suite", 4, 6, "M1"), ("AES engine, modes and envelope", 4, 7, "M2"),
             ("Grid simulator, gateway, SCADA", 5, 8, "M3"), ("Cryptanalysis of legacy ciphers", 6, 8, "M1"),
             ("Crypto transition experiments TV4-TV7", 8, 10, "M2"),
             ("System transition experiments TV1-3, TV8", 8, 10, "M3"),
             ("Testing and integration", 9, 11, "All"), ("Report and presentation", 10, 12, "All")]
    color = {"M1": BLUE, "M2": ORANGE, "M3": AQUA, "All": MUTED}
    fig, ax = plt.subplots(figsize=(9, 3.8))
    for i, (t, s, e, who) in enumerate(tasks):
        ax.barh(i, e - s + 1, left=s - 0.5, height=0.62, color=color[who], edgecolor=SURFACE, linewidth=2)
    ax.set_yticks(range(len(tasks)), [t for t, *_ in tasks])
    ax.invert_yaxis()
    ax.set_xticks(range(1, 13), [f"W{w}" for w in range(1, 13)])
    ax.set_xlim(0.5, 12.5)
    style_axis(ax, "x")
    def short(i):
        n = team[i]["name"]
        return f"Member {i + 1}" if n.startswith("[") else n
    names = {"M1": short(0), "M2": short(1), "M3": short(2), "All": "All members"}
    handles = [plt.Rectangle((0, 0), 1, 1, color=color[k]) for k in ("M1", "M2", "M3", "All")]
    ax.legend(handles, [names[k] for k in ("M1", "M2", "M3", "All")], ncol=4, loc="lower center",
              bbox_to_anchor=(0.4, 1.0))
    save(fig, "fig_gantt.png")


# ============================================================================ charts
def fig_keyspace(crypt):
    rows = crypt["attacks"]
    labels = [f"{r['cipher']}" for r in rows] + ["AES-256 (STE)"]
    bits = [r["key_space_bits"] for r in rows] + [256]
    notes = [f"broken: {r['frames_used']} frame{'s' if r['frames_used'] > 1 else ''}, "
             f"{r['elapsed_ms']:.1f} ms" if r["elapsed_ms"] < 10 else
             f"broken: {r['frames_used']} frame{'s' if r['frames_used'] > 1 else ''}, {r['elapsed_ms']:.0f} ms"
             for r in rows] + ["no practical attack"]
    fig, ax = plt.subplots(figsize=(8.6, 3.4))
    y = np.arange(len(labels))
    ax.barh(y, [max(b, 0.6) for b in bits], height=0.55, color=[BLUE] * len(rows) + [AQUA], edgecolor=SURFACE)
    for i, (b, n) in enumerate(zip(bits, notes)):
        ax.text(max(b, 0.6) + 3, i, f"{b:g} bits  -  {n}", va="center", fontsize=8, color=INK2)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 340)
    ax.set_xlabel("key space (log2 of number of keys)")
    style_axis(ax, "x")
    ax.set_title("Nominal key space vs. measured break effort", loc="left")
    save(fig, "fig_keyspace.png")


def fig_frequency(crypt):
    from lcmf.classical import Z36
    prof = crypt["frequency_profiles"]
    ioc = crypt["index_of_coincidence"]
    panels = [("Plaintext frames", prof["Plaintext frames"], ioc["Plaintext frames"]),
              ("Caesar ciphertext", prof["Caesar"], ioc["Caesar"]),
              ("Vigenere ciphertext", prof["Vigenere"], ioc["Vigenere"])]
    fig, axes = plt.subplots(1, 4, figsize=(10, 2.6), gridspec_kw={"width_ratios": [1, 1, 1, 1.15]})
    for ax, (title, counts, ic) in zip(axes, panels):
        total = sum(counts)
        ax.bar(range(36), [100 * c / total for c in counts], width=0.75, color=BLUE)
        ax.set_title(f"{title}\nIoC = {ic:.3f}", fontsize=8.5)
        ax.set_xticks([0, 13, 26, 35], ["A", "N", "0", "9"])
        ax.set_ylim(0, 22)
        style_axis(ax, "y")
    axes[0].set_ylabel("% of symbols")
    hist = crypt["aes_gcm_byte_histogram"]
    total = sum(hist)
    axes[3].bar(range(256), [100 * h / total for h in hist], width=1.0, color=AQUA)
    axes[3].set_title("AES-256-GCM bytes\nflat (uniform 0.39 %)", fontsize=8.5)
    axes[3].set_xticks([0, 128, 255])
    axes[3].set_ylim(0, 1.2)
    style_axis(axes[3], "y")
    fig.tight_layout()
    save(fig, "fig_frequency.png")


def fig_playfair(crypt):
    curve = crypt["playfair_codebook"]
    x = [p["frames_observed"] for p in curve]
    y = [p["digram_coverage_pct"] for p in curve]
    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    ax.plot(x, y, color=BLUE, linewidth=2, marker="o", markersize=5, markeredgecolor=SURFACE, markeredgewidth=1.5)
    ax.set_xscale("log")
    ax.set_xticks(x, [str(v) for v in x])
    ax.set_ylim(0, 105)
    ax.set_xlabel("known-plaintext frames observed by the attacker")
    ax.set_ylabel("digrams of unseen frames decrypted (%)")
    for xi, yi in zip(x, y):
        if xi in (1, 10, 50, 200):
            ax.annotate(f"{yi:.0f} %", (xi, yi), textcoords="offset points", xytext=(0, 8), ha="center",
                        fontsize=8, color=INK2)
    style_axis(ax, "y")
    ax.set_title("Playfair codebook attack: no key needed", loc="left")
    save(fig, "fig_playfair.png")


def fig_transition(trans):
    tv = {t["id"]: t for t in trans}
    s1 = {s["defence"]: s for s in tv["TV1"]["scenarios"] if s["attack"] in ("gross", "tamper")}
    m2 = {m["mode"]: m for m in tv["TV2"]["modes"]}
    c3 = tv["TV3"]["cases"]
    r4 = {r["scheme"]: r for r in tv["TV4"]["rows"]}
    r6 = tv["TV6"]["rows"]
    r7 = tv["TV7"]["rows"]
    rows = [
        ("TV1 false data via legacy last mile", s1["gateway only"]["forged_accepted_pct"],
         s1["native AES-GCM at the RTU (end-to-end)"]["forged_accepted_pct"], "gateway only", "native AES RTU"),
        ("TV2 downgrade to legacy", m2["HYBRID_PERMISSIVE"]["forged_accepted_pct"],
         m2["HYBRID_PINNED"]["forged_accepted_pct"], "hybrid permissive", "hybrid pinned"),
        ("TV3 WAN replay", c3[0]["replay_accepted_pct"], c3[1]["replay_accepted_pct"], "legacy frames", "STE window"),
        ("TV3 last-mile replay", c3[2]["replay_accepted_pct"], c3[3]["replay_accepted_pct"], "stateless gateway",
         "legacy-seq tracking"),
        ("TV4 blind tampering", r4["AES-256-CTR, no MAC (bit flip)"]["tamper_success_pct"],
         r4["AES-256-GCM (STE)"]["tamper_success_pct"], "AES-CTR, no MAC", "AES-GCM"),
        ("TV6 plaintext recovery after reboot", r6[0]["plaintext_recovered_pct"], r6[1]["plaintext_recovered_pct"],
         "RAM counter", "persistent counter"),
        ("TV7 AES key found by dictionary", 100.0 if r7[0]["dictionary_hit"] else 0.0,
         100.0 if r7[1]["dictionary_hit"] else 0.0, "SHA-256(keyword)", "HKDF random master"),
    ]
    fig, ax = plt.subplots(figsize=(9.2, 4.4))
    y = np.arange(len(rows))
    h = 0.36
    ax.barh(y - h / 2 - 0.01, [r[1] for r in rows], height=h, color=ORANGE, label="vulnerable configuration",
            edgecolor=SURFACE)
    ax.barh(y + h / 2 + 0.01, [max(r[2], 0.0) for r in rows], height=h, color=BLUE, label="mitigated configuration",
            edgecolor=SURFACE)
    for i, r in enumerate(rows):
        ax.text(r[1] + 1.5, i - h / 2 - 0.01, f"{r[1]:.0f} %  {r[3]}", va="center", fontsize=7.6, color=INK2)
        ax.text(r[2] + 1.5, i + h / 2 + 0.01, f"{r[2]:.0f} %  {r[4]}", va="center", fontsize=7.6, color=INK2)
    ax.set_yticks(y, [r[0] for r in rows])
    ax.invert_yaxis()
    ax.set_xlim(0, 145)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("attack success (%)")
    style_axis(ax, "x")
    ax.legend(loc="lower left", bbox_to_anchor=(0.0, 1.0), ncol=2)
    ax.set_title("Transition vulnerabilities: attack success before and after mitigation", loc="left", pad=22)
    save(fig, "fig_transition.png")


def fig_overhead(trans):
    t8 = next(t for t in trans if t["id"] == "TV8")
    link = t8["link"]
    labels = [f"{l['baud']:,} baud" for l in link]
    leg = [l["scan_8_devices_legacy_ms"] for l in link]
    ste = [l["scan_8_devices_ste_ms"] for l in link]
    fig, ax = plt.subplots(figsize=(7.2, 3.2))
    x = np.arange(len(labels))
    w = 0.36
    ax.bar(x - w / 2 - 0.01, leg, w, color=ORANGE, label=f"legacy frame ({t8['legacy_frame_bytes']} B)")
    ax.bar(x + w / 2 + 0.01, ste, w, color=BLUE, label=f"secure envelope ({t8['ste_bytes']} B)")
    for i in range(len(x)):
        ax.text(x[i] - w / 2, leg[i] + 60, f"{leg[i]:.0f}", ha="center", fontsize=7.6, color=INK2)
        ax.text(x[i] + w / 2, ste[i] + 60, f"{ste[i]:.0f}", ha="center", fontsize=7.6, color=INK2)
    ax.axhline(t8["scan_cycle_ms"], color=INK2, linewidth=1, linestyle=(0, (4, 3)))
    ax.text(3.45, t8["scan_cycle_ms"] + 80, "2 s scan cycle", ha="right", fontsize=8, color=INK2)
    ax.set_xticks(x, labels)
    ax.set_ylabel("time to poll 8 RTUs (ms)")
    style_axis(ax, "y")
    ax.legend(loc="upper right")
    ax.set_title("Serial-link time per scan: legacy vs. secure envelope", loc="left")
    save(fig, "fig_overhead.png")


def fig_latency(trans):
    t8 = next(t for t in trans if t["id"] == "TV8")
    lat = t8["gateway_latency"]["library"]
    names = list(lat)
    med = [lat[n]["median_us"] for n in names]
    p95 = [lat[n]["p95_us"] for n in names]
    fig, ax = plt.subplots(figsize=(7.2, 3.0))
    x = np.arange(len(names))
    w = 0.36
    ax.bar(x - w / 2 - 0.01, med, w, color=BLUE, label="median")
    ax.bar(x + w / 2 + 0.01, p95, w, color=AQUA, label="95th percentile")
    for i in range(len(x)):
        ax.text(x[i] - w / 2, med[i] + 2, f"{med[i]:.0f}", ha="center", fontsize=7.4, color=INK2)
        ax.text(x[i] + w / 2, p95[i] + 2, f"{p95[i]:.0f}", ha="center", fontsize=7.4, color=INK2)
    ax.set_xticks(x, [n.capitalize() for n in names])
    ax.set_ylabel("gateway uplink latency (us)")
    style_axis(ax, "y")
    ax.legend(loc="upper right")
    ax.set_title("Per-frame gateway latency by legacy cipher (library AES-GCM)", loc="left")
    save(fig, "fig_latency.png")


def fig_ecb_image():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    fig0 = plt.figure(figsize=(4, 1.5), dpi=80)
    fig0.text(0.5, 0.5, "SCADA", ha="center", va="center", fontsize=60, fontweight="bold", color="black")
    fig0.canvas.draw()
    img = np.asarray(fig0.canvas.buffer_rgba())[:, :, 0]
    plt.close(fig0)
    img = np.where(img < 128, 40, 220).astype(np.uint8)
    h, w = img.shape
    w -= w % 16
    img = np.ascontiguousarray(img[:, :w])
    key, nonce = bytes(range(32)), bytes(16)
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(img.tobytes())
    ctr = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor().update(img.tobytes())
    fig, axes = plt.subplots(1, 3, figsize=(10, 1.9))
    for ax, data, title in ((axes[0], img, "Plaintext bitmap"),
                            (axes[1], np.frombuffer(ecb, np.uint8).reshape(h, w), "AES-256-ECB: shape still visible"),
                            (axes[2], np.frombuffer(ctr, np.uint8).reshape(h, w), "AES-256-GCM (CTR core): noise")):
        ax.imshow(data, cmap="gray", vmin=0, vmax=255, interpolation="nearest")
        ax.set_title(title, fontsize=8.5)
        ax.axis("off")
    save(fig, "fig_ecb.png")


def main():
    team_path = os.path.join(ROOT, "docs", "build", "team_config.json")
    team = [{"name": f"Member {i}"} for i in (1, 2, 3)]
    if os.path.exists(team_path):
        with open(team_path, encoding="utf-8") as fh:
            team = json.load(fh)["members"]
    crypt, trans = load("cryptanalysis.json"), load("transition.json")
    print("Generating figures ->", OUT)
    fig_architecture(); fig_dfd0(); fig_uplink_flow(); fig_frame_format(); fig_envelope(); fig_migration()
    fig_aes_round(); fig_gcm(); fig_class_diagram(); fig_gantt(team)
    fig_keyspace(crypt); fig_frequency(crypt); fig_playfair(crypt); fig_transition(trans)
    fig_overhead(trans); fig_latency(trans); fig_ecb_image()


if __name__ == "__main__":
    main()
