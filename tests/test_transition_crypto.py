"""Tests - cryptographic transition vulnerabilities TV4-TV7 (Member 2)."""
from lcmf.analysis import transition_crypto as tc


def test_tv4_to_tv7():
    tv4 = {r["scheme"]: r["tamper_success_pct"] for r in tc.tv4_malleability(trials=40)["rows"]}
    assert tv4["AES-256-GCM (STE)"] == 0.0 and tv4["AES-256-CTR, no MAC (bit flip)"] == 100.0
    tv5 = tc.tv5_ecb_leakage()["rows"]
    assert tv5[0]["distinct_ciphertexts"] == 3 and tv5[1]["distinct_ciphertexts"] == 1440
    tv6 = tc.tv6_nonce_reuse(polls=40, reboot_every=10)["rows"]
    assert tv6[0]["nonce_collisions"] > 0 and tv6[1]["nonce_collisions"] == 0
    tv7 = tc.tv7_legacy_derived_keys()["rows"]
    assert tv7[0]["dictionary_hit"] == "GRIDLOCK" and tv7[1]["dictionary_hit"] is None
