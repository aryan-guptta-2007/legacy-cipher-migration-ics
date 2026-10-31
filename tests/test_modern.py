"""Unit tests - modern cryptography engine and secure envelope (Member 2)."""
import os

import pytest

from lcmf.gateway import envelope as ste
from lcmf.modern import aes_modes
from lcmf.modern.aead import EducationalAESGCM, LibraryAESGCM, get_engine
from lcmf.modern.aes_core import AES, INV_SBOX, SBOX, gf_mul
from lcmf.modern.aes_modes import AuthenticationError
from lcmf.modern.keystore import DOWNLINK, UPLINK, KeyStore, LegacyDerivedKeyStore
from lcmf.modern.nonce import NonceManager
from lcmf.modern.replay import ReplayWindow

FIPS_PT = bytes.fromhex("00112233445566778899aabbccddeeff")


@pytest.mark.parametrize("key,expected", [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
], ids=["AES-128", "AES-192", "AES-256"])
def test_fips197_appendix_c(key, expected):
    aes = AES(bytes.fromhex(key))
    ct = aes.encrypt_block(FIPS_PT)
    assert ct.hex() == expected
    assert aes.decrypt_block(ct) == FIPS_PT


def test_fips197_appendix_b_and_key_schedule():
    aes = AES(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert aes.encrypt_block(bytes.fromhex("3243f6a8885a308d313198a2e0370734")).hex() == \
        "3925841d02dc09fbdc118597196a0b32"
    assert aes.round_key_hex(10) == "d014f9a8c9ee2589e13f0cc8b6630ca6"   # FIPS-197 App. A.1


def test_sbox_is_derived_correctly():
    assert SBOX[0x00] == 0x63 and SBOX[0x53] == 0xED and SBOX[0xFF] == 0x16
    assert all(INV_SBOX[SBOX[x]] == x for x in range(256))
    assert gf_mul(0x57, 0x83) == 0xC1                                     # FIPS-197 section 4.2


def test_gcm_spec_test_cases():
    ct, tag = aes_modes.gcm_encrypt(bytes(16), bytes(12), bytes(16))
    assert ct.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"
    ct, tag = aes_modes.gcm_encrypt(bytes(16), bytes(12), b"")
    assert tag.hex() == "58e2fccefa7e3061367f1d57a4e7455a"


def test_educational_gcm_matches_library():
    for i in range(50):
        key, nonce = os.urandom(32), os.urandom(12)
        msg, aad = os.urandom(i * 3), os.urandom(i % 20)
        lib, edu = LibraryAESGCM(key), EducationalAESGCM(key)
        assert lib.seal(nonce, msg, aad) == edu.seal(nonce, msg, aad)
        assert edu.open(nonce, lib.seal(nonce, msg, aad), aad) == msg


@pytest.mark.parametrize("engine", ["library", "educational"])
def test_gcm_detects_tampering(engine):
    e = get_engine(engine, os.urandom(32))
    nonce = os.urandom(12)
    sealed = bytearray(e.seal(nonce, b"breaker=closed", b"header"))
    sealed[0] ^= 1
    with pytest.raises(AuthenticationError):
        e.open(nonce, bytes(sealed), b"header")
    with pytest.raises(AuthenticationError):
        e.open(nonce, e.seal(nonce, b"x", b"header"), b"other header")


def test_cbc_ctr_ecb_roundtrip():
    key, iv = os.urandom(32), os.urandom(16)
    for n in (0, 1, 15, 16, 17, 100):
        msg = os.urandom(n)
        assert aes_modes.cbc_decrypt(key, iv, aes_modes.cbc_encrypt(key, iv, msg)) == msg
        assert aes_modes.ctr_xcrypt(key, iv, aes_modes.ctr_xcrypt(key, iv, msg)) == msg
        assert aes_modes.ecb_decrypt(key, aes_modes.ecb_encrypt(key, msg)) == msg


def test_ecb_leaks_equal_blocks():
    key = os.urandom(16)
    ct = aes_modes.ecb_encrypt(key, b"A" * 32)
    assert ct[:16] == ct[16:32]


def test_keystore_separates_devices_directions_and_generations():
    ks = KeyStore(bytes(32))
    k = ks.derive(1, UPLINK)
    assert len(k) == 32
    assert k != ks.derive(2, UPLINK) != ks.derive(1, DOWNLINK)
    ks.rotate()
    assert ks.derive(1, UPLINK) != k and ks.derive(1, UPLINK, key_id=1) == k


def test_legacy_derived_keystore_is_deterministic():
    assert LegacyDerivedKeyStore("GRIDLOCK").derive(1, UPLINK) == LegacyDerivedKeyStore("GRIDLOCK").derive(9, DOWNLINK)


def test_nonce_unique_and_persistent(tmp_path):
    nm = NonceManager(7)
    nonces = {nm.next()[1] for _ in range(1000)}
    assert len(nonces) == 1000
    nm.simulate_reboot()
    assert nm.next()[0] == 1                         # RAM-only counter restarts -> reuse hazard
    path = str(tmp_path / "ctr.json")
    nm = NonceManager(7, persist_path=path, reserve=10)
    used = {nm.next()[1] for _ in range(25)}
    nm.simulate_reboot()
    assert all(nm.next()[1] not in used for _ in range(50))


def test_replay_window():
    rw = ReplayWindow(size=8, max_skew_ms=1000)
    for seq in (1, 2, 5):
        assert rw.check(1, seq, 0, 0)[0]
        rw.commit(1, seq)
    assert rw.check(1, 2, 0, 0) == (False, "replayed sequence number")
    assert rw.check(1, 4, 0, 0)[0]                   # reordered, unseen
    rw.commit(1, 20)
    assert rw.check(1, 5, 0, 0) == (False, "sequence number outside replay window")
    assert rw.check(1, 21, 0, 5000) == (False, "stale or future timestamp")


def test_envelope_layout_and_header_authentication():
    eng = LibraryAESGCM(os.urandom(32))
    hdr = ste.EnvelopeHeader(ste.MSG_TELEMETRY, ste.FLAG_LEGACY_ORIGIN, 1, 4, 99, 123456, os.urandom(12))
    env = ste.seal(eng, hdr, b"p" * 15)
    assert len(env) == 15 + ste.OVERHEAD == 68
    parsed, aad, body = ste.parse_header(env)
    assert parsed == hdr and ste.open_body(eng, parsed, aad, body) == b"p" * 15
    forged = bytearray(env)
    forged[8] ^= 0x01                                 # change device id in the header
    p2, aad2, body2 = ste.parse_header(bytes(forged))
    with pytest.raises(AuthenticationError):
        ste.open_body(eng, p2, aad2, body2)
    with pytest.raises(ste.EnvelopeError):
        ste.parse_header(b"XX" + env[2:])
