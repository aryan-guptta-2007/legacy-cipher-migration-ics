"""Cryptanalysis of the legacy ciphers on captured telemetry traffic.

The attacker model follows Kerckhoffs's principle: the cipher family and the
public legacy frame format (tags, field widths, checksum rule) are known; the
key is not.  Because every frame is highly structured, the frame grammar acts
as a perfect "plaintext recogniser", turning exhaustive search and
constraint propagation into practical attacks:

==============  ============================================  =============
cipher          attack                                        data needed
==============  ============================================  =============
Caesar/Additive exhaustive key search (36 keys)               1 frame
Affine          exhaustive search (432 keys) / known-pt solve 1 frame
Vigenere        per-residue constraint propagation over the   1-3 frames
                frame template + checksum confirmation
Playfair        keyword dictionary search; digram codebook    1 frame / KPA
Columnar        exhaustive permutation search (L <= 7)        1 frame
==============  ============================================  =============

Classical textbook tools (frequency analysis, chi-squared, index of
coincidence, Friedman test) are also provided for English text.

Owner: Member 1 (Legacy Cipher Suite & Cryptanalysis)
"""
from __future__ import annotations

import itertools
import time
from collections import Counter
from dataclasses import asdict, dataclass
from math import gcd, prod
from typing import Callable, Iterable

from ..classical import (AdditiveCipher, AffineCipher, CipherError, ClassicalCipher,
                         ColumnarTranspositionCipher, PlayfairCipher, VigenereCipher, Z26, Z36,
                         mod_inverse, units)
from ..grid.legacy_codec import (FRAME_LEN, TELEMETRY_TEMPLATE, decode_telemetry, is_valid_telemetry,
                                 legacy_decrypt)

ENGLISH_FREQ = {  # relative letter frequencies of English (percent)
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70, "F": 2.23, "G": 2.02, "H": 6.09,
    "I": 6.97, "J": 0.15, "K": 0.77, "L": 4.03, "M": 2.41, "N": 6.75, "O": 7.51, "P": 1.93,
    "Q": 0.10, "R": 5.99, "S": 6.33, "T": 9.06, "U": 2.76, "V": 0.98, "W": 2.36, "X": 0.15,
    "Y": 1.97, "Z": 0.07,
}

#: Keyword candidates an attacker would try first: utility / ICS jargon and common words.
WORDLIST = """
ADMIN PASSWORD SECRET SCADA GRID POWER ENERGY ELECTRIC VOLTAGE CURRENT FEEDER BREAKER RELAY
SUBSTATION TRANSFORMER GENERATOR TURBINE CONTROL CENTRE CENTER MASTER REMOTE TERMINAL RTU PLC
HMI MODBUS DNP TELEMETRY SIGNAL NETWORK UTILITY STATION SWITCH SWITCHGEAR BUSBAR CIRCUIT
OVERLOAD FREQUENCY PHASOR METER SMART SECURE SECURITY CIPHER CRYPTO KEY KEYWORD LEGACY
SYSTEM OPERATOR DISPATCH LOAD SUPPLY DEMAND PEAK BASE HYDRO THERMAL NUCLEAR SOLAR WIND
HELIOS APOLLO ZEUS ATLAS TITAN ORION PHOENIX MERCURY JUPITER SATURN NEPTUNE PLUTO
ALPHA BRAVO CHARLIE DELTA ECHO FOXTROT GOLF HOTEL INDIA JULIET KILO LIMA MIKE NOVEMBER
OSCAR PAPA QUEBEC ROMEO SIERRA TANGO UNIFORM VICTOR WHISKEY XRAY YANKEE ZULU
GRIDLOCK BLACKOUT BROWNOUT OUTAGE RESTORE ISLAND SYNCHRO ROTOR STATOR ARMATURE WATT
AMPERE OHM VOLT KILOVOLT MEGAWATT CAPACITOR REACTOR INSULATOR CONDUCTOR TOWER PYLON
CABLE LINE DISTRIBUTION TRANSMISSION SERVICE FIELD DEVICE MONITOR ALARM EVENT TRIP CLOSE
OPEN RESET FAULT PROTECTION RECLOSER SECTIONALIZER FUSE ISOLATOR EARTH GROUND NEUTRAL
WELCOME LETMEIN QWERTY DRAGON MONKEY SUNSHINE PRINCESS FOOTBALL BASEBALL SHADOW MICHAEL
COMPUTER INTERNET SERVER DEFAULT GUEST USER ROOT SUPPORT CHANGEME TEST DEMO EXAMPLE
PLAYFAIR VIGENERE CAESAR ENIGMA LORENZ PURPLE ULTRA MAGIC BOMBE COLOSSUS
""".split()


@dataclass
class AttackResult:
    cipher: str
    method: str
    success: bool
    key: object
    frames_used: int
    candidates_tried: int
    elapsed_ms: float
    notes: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["key"] = str(self.key)
        return d


def _try_decrypt(cipher: ClassicalCipher, ciphertext: str) -> str | None:
    try:
        return legacy_decrypt(cipher, ciphertext)
    except CipherError:
        return None


def _valid(cipher: ClassicalCipher, ciphertext: str) -> bool:
    text = _try_decrypt(cipher, ciphertext)
    return text is not None and is_valid_telemetry(text)


def _coherent(cipher: ClassicalCipher, ciphertexts: list[str]) -> bool:
    """Protocol semantics: one device per link and consecutive legacy sequence numbers.

    Needed because the legacy checksum is a plain sum and therefore cannot
    detect transposed digits - a wrong transposition key can still yield
    checksum-valid frames such as ``RTU60...SEQ6010``.
    """
    frames = [decode_telemetry(legacy_decrypt(cipher, c)) for c in ciphertexts]
    return all(f.device_id == frames[0].device_id for f in frames) and all(
        (b.seq - a.seq) % 10_000 == 1 for a, b in zip(frames, frames[1:]))


def exhaustive_search(name: str, method: str, keys: Iterable, factory: Callable[[object], ClassicalCipher],
                      ciphertexts: list[str]) -> AttackResult:
    """Try every key on frame 1; disambiguate survivors with further frames."""
    t0 = time.perf_counter()
    tried, survivors = 0, []
    for key in keys:
        tried += 1
        try:
            cipher = factory(key)
        except CipherError:
            continue
        if _valid(cipher, ciphertexts[0]):
            survivors.append((key, cipher))
    used = 1
    while len(survivors) > 1 and used < len(ciphertexts):
        used += 1
        survivors = [(k, c) for k, c in survivors
                     if _valid(c, ciphertexts[used - 1]) and _coherent(c, ciphertexts[:used])]
    elapsed = (time.perf_counter() - t0) * 1000
    if not survivors:
        return AttackResult(name, method, False, None, used, tried, elapsed, "no key produced a valid frame")
    key, _ = survivors[0]
    return AttackResult(name, method, len(survivors) == 1, key, used, tried, elapsed,
                        f"{len(survivors)} candidate(s) remain")


# ---------------------------------------------------------------- monoalphabetic
def break_additive(ciphertexts: list[str]) -> AttackResult:
    return exhaustive_search("Additive/Caesar", "exhaustive key search", range(36),
                             lambda k: AdditiveCipher(k), ciphertexts)


def break_affine(ciphertexts: list[str]) -> AttackResult:
    keys = [(a, b) for a in units(36) for b in range(36)]
    return exhaustive_search("Affine", "exhaustive key search", keys,
                             lambda k: AffineCipher(*k), ciphertexts)


def affine_known_plaintext(plaintext: str, ciphertext: str, alphabet: str = Z36) -> tuple[int, int] | None:
    """Solve c = a*p + b (mod m) from known plaintext/ciphertext symbol pairs."""
    m = len(alphabet)
    pairs = [(alphabet.index(p), alphabet.index(c)) for p, c in zip(plaintext, ciphertext)]

    def consistent(a: int, b: int) -> bool:
        return all((a * p + b) % m == c for p, c in pairs)

    for (p1, c1), (p2, c2) in itertools.combinations(pairs, 2):
        dp = (p1 - p2) % m
        if gcd(dp, m) == 1:
            a = (c1 - c2) * mod_inverse(dp, m) % m
            b = (c1 - a * p1) % m
            if gcd(a, m) == 1 and consistent(a, b):
                return a, b
    for a in units(m):  # fallback when no pair has an invertible difference
        b = (pairs[0][1] - a * pairs[0][0]) % m
        if consistent(a, b):
            return a, b
    return None


# ---------------------------------------------------------------- Vigenere
def _residue_candidates(frames: list[str], period: int) -> list[set[int]]:
    A = Z36
    cands = []
    for r in range(period):
        allowed_keys = set(range(36))
        for frame in frames:
            for i in range(r, min(FRAME_LEN, len(frame)), period):
                c = A.index(frame[i])
                allowed = TELEMETRY_TEMPLATE[i]
                allowed_keys = {k for k in allowed_keys if A[(c - k) % 36] in allowed}
        cands.append(allowed_keys)
        if not allowed_keys:
            break
    return cands


def break_vigenere(ciphertexts: list[str], max_period: int = 20, max_combos: int = 50_000) -> AttackResult:
    """Template-constrained attack: each key symbol must map every frame onto the public template."""
    t0 = time.perf_counter()
    tried = 0
    for n_frames in range(1, len(ciphertexts) + 1):
        frames = ciphertexts[:n_frames]
        for period in range(1, max_period + 1):
            cands = _residue_candidates(frames, period)
            if len(cands) < period or not all(cands):
                tried += 1
                continue
            space = prod(len(s) for s in cands)
            if space > max_combos:
                tried += 1
                continue
            hits = []
            for combo in itertools.product(*[sorted(s) for s in cands]):
                tried += 1
                key = "".join(Z36[k] for k in combo)
                cipher = VigenereCipher(key)
                if all(_valid(cipher, f) for f in frames):
                    hits.append(key)
                    if len(hits) > 1:
                        break
            if len(hits) == 1:
                return AttackResult("Vigenere", "template constraint propagation + checksum", True,
                                    hits[0], n_frames, tried, (time.perf_counter() - t0) * 1000,
                                    f"period {period}")
            if hits:
                break  # ambiguous at this period: gather another frame
    return AttackResult("Vigenere", "template constraint propagation + checksum", False, None,
                        len(ciphertexts), tried, (time.perf_counter() - t0) * 1000, "not resolved")


def vigenere_known_plaintext(plaintext: str, ciphertext: str, period: int, alphabet: str = Z36) -> str:
    m = len(alphabet)
    return "".join(alphabet[(alphabet.index(ciphertext[i]) - alphabet.index(plaintext[i])) % m]
                   for i in range(period))


# ---------------------------------------------------------------- Playfair
def break_playfair_dictionary(ciphertexts: list[str], wordlist: list[str] | None = None) -> AttackResult:
    words = wordlist or WORDLIST
    return exhaustive_search("Playfair", f"keyword dictionary ({len(words)} words)", words,
                             lambda w: PlayfairCipher(w), ciphertexts)


class PlayfairCodebook:
    """Known-plaintext digram codebook: decrypts without ever learning the square."""

    def __init__(self):
        self._prep = PlayfairCipher("")      # digram preparation is key-independent
        self.table: dict[str, str] = {}

    def learn(self, plaintext: str, ciphertext: str) -> None:
        pairs = self._prep.digrams(plaintext)
        for k, (a, b) in enumerate(pairs):
            self.table[ciphertext[2 * k:2 * k + 2]] = a + b

    def decrypt_partial(self, ciphertext: str) -> tuple[str, float]:
        out, known = [], 0
        for i in range(0, len(ciphertext), 2):
            dg = ciphertext[i:i + 2]
            if dg in self.table:
                out.append(self.table[dg])
                known += 1
            else:
                out.append("??")
        total = len(ciphertext) // 2
        return "".join(out), known / total if total else 0.0


# ---------------------------------------------------------------- Columnar
def break_columnar(ciphertexts: list[str], max_cols: int = 7) -> AttackResult:
    keys = (perm for n in range(2, max_cols + 1) for perm in itertools.permutations(range(n)))
    res = exhaustive_search("Columnar", f"exhaustive permutation search (L<={max_cols})", keys,
                            lambda p: ColumnarTranspositionCipher(p), ciphertexts)
    if res.key is not None:
        res.key = ColumnarTranspositionCipher(res.key).order
    return res


# ---------------------------------------------------------------- statistics
def symbol_frequencies(texts: Iterable[str], alphabet: str = Z36) -> list[int]:
    counts = Counter()
    for t in texts:
        counts.update(t)
    return [counts.get(ch, 0) for ch in alphabet]


def index_of_coincidence(text: str) -> float:
    n = len(text)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in Counter(text).values()) / (n * (n - 1))


def chi_squared_english(text: str) -> float:
    n = len(text)
    counts = Counter(text)
    return sum((counts.get(ch, 0) - n * f / 100) ** 2 / (n * f / 100) for ch, f in ENGLISH_FREQ.items())


def break_caesar_english(ciphertext: str) -> tuple[int, str]:
    """Frequency analysis: choose the shift whose decryption is most English-like."""
    text = "".join(ch for ch in ciphertext.upper() if ch in Z26)
    best = min(range(26), key=lambda k: chi_squared_english(AdditiveCipher(k, Z26).decrypt(text)))
    return best, AdditiveCipher(best, Z26).decrypt(text)


def friedman_period(ciphertext: str, max_period: int = 20) -> int:
    """Smallest period whose columns have English-like index of coincidence (~0.066)."""
    text = "".join(ch for ch in ciphertext.upper() if ch in Z26)
    scores = {}
    for p in range(1, max_period + 1):
        cols = [text[i::p] for i in range(p)]
        scores[p] = sum(index_of_coincidence(c) for c in cols) / p
    for p in range(1, max_period + 1):
        if scores[p] > 0.058:
            return p
    return max(scores, key=scores.get)


def kasiski_distances(ciphertext: str, n: int = 3) -> Counter:
    """Kasiski examination: GCD-friendly distances between repeated n-grams."""
    text = "".join(ch for ch in ciphertext.upper() if ch in Z26)
    seen: dict[str, int] = {}
    factors = Counter()
    for i in range(len(text) - n + 1):
        gram = text[i:i + n]
        if gram in seen:
            d = i - seen[gram]
            factors.update(f for f in range(2, 21) if d % f == 0)
        seen[gram] = i
    return factors


def break_vigenere_english(ciphertext: str, max_period: int = 20) -> tuple[str, str]:
    """Textbook attack: Friedman test for the period, chi-squared per column."""
    text = "".join(ch for ch in ciphertext.upper() if ch in Z26)
    period = friedman_period(text, max_period)
    key = ""
    for i in range(period):
        col = text[i::period]
        k = min(range(26), key=lambda s: chi_squared_english(AdditiveCipher(s, Z26).decrypt(col)))
        key += Z26[k]
    return key, VigenereCipher(key, Z26).decrypt(text)
