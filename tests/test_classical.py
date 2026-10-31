"""Unit tests - legacy cipher suite (Member 1)."""
import random

import pytest

from lcmf.classical import (AdditiveCipher, AffineCipher, CaesarCipher, CipherError,
                            ColumnarTranspositionCipher, NullCipher, PlayfairCipher, VigenereCipher,
                            Z26, Z36, make_cipher, mod_inverse, units)
from lcmf.grid.legacy_codec import encode_telemetry, legacy_decrypt
from lcmf.grid.telemetry import TelemetryReading


# -- published textbook vectors ----------------------------------------------
def test_caesar_vector():
    assert CaesarCipher(Z26).encrypt("ATTACKATDAWN") == "DWWDFNDWGDZQ"


def test_additive_vector():
    assert AdditiveCipher(15, Z26).encrypt("HELLO") == "WTAAD"


def test_affine_vector():
    assert AffineCipher(5, 8, Z26).encrypt("AFFINECIPHER") == "IHHWVCSWFRCP"


def test_vigenere_vector():
    assert VigenereCipher("LEMON", Z26).encrypt("ATTACKATDAWN") == "LXFOPVEFRNHR"


def test_playfair_vector():
    pf = PlayfairCipher("PLAYFAIR EXAMPLE", Z26)
    assert pf.encrypt("HIDETHEGOLDINTHETREESTUMP") == "BMODZBXDNABEKUDMUIXMMOUVIF"
    assert pf.strip_fillers(pf.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF")) == "HIDETHEGOLDINTHETREESTUMP"


def test_columnar_vector():
    c = ColumnarTranspositionCipher("ZEBRAS", Z26)
    assert c.encrypt("WEAREDISCOVEREDFLEEATONCE") == "EVLNACDTESEAROFODEECWIREE"
    assert c.decrypt("EVLNACDTESEAROFODEECWIREE") == "WEAREDISCOVEREDFLEEATONCE"


# -- algebra and key handling ---------------------------------------------------
def test_mod_inverse_and_units():
    assert mod_inverse(5, 36) == 29 and (5 * 29) % 36 == 1
    assert len(units(26)) == 12 and len(units(36)) == 12


def test_affine_rejects_non_invertible_multiplier():
    with pytest.raises(CipherError):
        AffineCipher(6, 1)          # gcd(6, 36) = 6


def test_symbols_outside_alphabet_are_rejected():
    with pytest.raises(CipherError):
        AdditiveCipher(3).encrypt("RTU01-SEQ")


def test_key_spaces():
    assert CaesarCipher().key_space == 1
    assert AdditiveCipher(5).key_space == 36
    assert AffineCipher(5, 8).key_space == 432
    assert VigenereCipher("GRID").key_space == 36 ** 4
    assert ColumnarTranspositionCipher("BREAKER").key_space == 5040


def test_playfair_square_is_6x6_for_z36():
    pf = PlayfairCipher("SUBSTATION")
    assert pf.size == 6 and len({ch for row in pf.square for ch in row}) == 36


def test_make_cipher_factory():
    assert isinstance(make_cipher({"type": "none"}), NullCipher)
    assert make_cipher({"type": "affine", "a": 7, "b": 3}).describe_key() == "a=7, b=3"
    with pytest.raises(CipherError):
        make_cipher({"type": "enigma"})


# -- round trips on telemetry (property test) -----------------------------------
SPECS = [{"type": "caesar"}, {"type": "additive", "key": 17}, {"type": "affine", "a": 5, "b": 8},
         {"type": "vigenere", "key": "GRIDLOCK"}, {"type": "playfair", "key": "SUBSTATION"},
         {"type": "columnar", "key": "BREAKER"}, {"type": "none"}]


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s["type"])
def test_roundtrip_random_telemetry(spec):
    rng = random.Random(spec["type"])
    cipher = make_cipher(spec)
    for _ in range(500):
        frame = encode_telemetry(TelemetryReading(rng.randint(1, 99), rng.randint(0, 9999), rng.randint(0, 99999),
                                                  rng.randint(0, 9999), rng.randint(0, 9999),
                                                  rng.randint(0, 99999), rng.random() < 0.5))
        assert legacy_decrypt(cipher, cipher.encrypt(frame)) == frame


def test_roundtrip_random_z36_strings_for_shift_ciphers():
    rng = random.Random(0)
    for _ in range(200):
        s = "".join(rng.choice(Z36) for _ in range(rng.randint(1, 80)))
        for c in (AdditiveCipher(rng.randint(0, 35)), AffineCipher(rng.choice(units(36)), rng.randint(0, 35)),
                  VigenereCipher("".join(rng.choice(Z36) for _ in range(rng.randint(1, 12)))),
                  ColumnarTranspositionCipher([rng.random() for _ in range(rng.randint(2, 9))])):
            assert c.decrypt(c.encrypt(s)) == s
