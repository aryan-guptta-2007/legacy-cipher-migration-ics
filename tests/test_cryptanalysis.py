"""Tests - cryptanalysis of the legacy ciphers (Member 1)."""
import pytest

from lcmf.analysis import cryptanalysis as ca
from lcmf.analysis.experiments import ENGLISH_SAMPLE
from lcmf.classical import CaesarCipher, VigenereCipher, Z26
from lcmf.grid.network import GridNetwork


@pytest.fixture(scope="module")
def captures():
    net = GridNetwork("LEGACY_ONLY", seed=5)
    caps = {d: [] for d in net.rtus}
    for i in range(6):
        for d, rtu in net.rtus.items():
            caps[d].append(rtu.transmit(net.t_ms + 2_000 * i)[2])
    return caps


def test_break_caesar_and_additive(captures):
    assert ca.break_additive(captures[1]).key == 3
    assert ca.break_additive(captures[2]).key == 17


def test_break_affine(captures):
    res = ca.break_affine(captures[3])
    assert res.success and res.key == (5, 8) and res.frames_used == 1


def test_break_vigenere(captures):
    assert ca.break_vigenere(captures[4]).key == "GRIDLOCK"
    assert ca.break_vigenere(captures[8]).key == "HELIOS"


def test_break_playfair_dictionary(captures):
    assert ca.break_playfair_dictionary(captures[5]).key == "SUBSTATION"


def test_break_columnar(captures):
    from lcmf.classical import ColumnarTranspositionCipher
    res = ca.break_columnar(captures[6])
    assert res.success and res.key == ColumnarTranspositionCipher("BREAKER").order


def test_known_plaintext_solvers():
    from lcmf.classical import AffineCipher
    assert ca.affine_known_plaintext("RTU", AffineCipher(11, 30).encrypt("RTU")) == (11, 30)
    v = VigenereCipher("GRIDLOCK")
    p = "RTU04SEQ0001VLT11000"
    assert ca.vigenere_known_plaintext(p, v.encrypt(p), 8) == "GRIDLOCK"


def test_textbook_english_attacks():
    eng = "".join(ch for ch in ENGLISH_SAMPLE.upper() if ch in Z26)
    assert ca.break_caesar_english(CaesarCipher(Z26).encrypt(eng))[0] == 3
    key, plain = ca.break_vigenere_english(VigenereCipher("TRANSFORMER", Z26).encrypt(eng))
    assert key == "TRANSFORMER" and plain == eng


def test_playfair_codebook_learns_digrams(captures):
    from lcmf.classical import PlayfairCipher
    pf = PlayfairCipher("SUBSTATION")
    book = ca.PlayfairCodebook()
    plain = ca.legacy_decrypt(pf, captures[5][0])
    book.learn(plain, captures[5][0])
    text, cov = book.decrypt_partial(captures[5][0])
    assert cov == 1.0
