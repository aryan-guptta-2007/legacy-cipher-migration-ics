"""Tests - system transition vulnerabilities TV1-TV3 (Member 3)."""
from lcmf.analysis import transition_system as ts


def test_tv1_trust_laundering():
    r = {(s["defence"], s["attack"]): s["forged_accepted_pct"] for s in ts.tv1_last_mile_injection(trials=10)["scenarios"]}
    assert r[("gateway only", "gross")] == 100.0
    assert r[("gateway + plausibility filter", "gross")] == 0.0
    assert r[("gateway + plausibility filter", "stealthy")] == 100.0
    assert r[("native AES-GCM at the RTU (end-to-end)", "tamper")] == 0.0


def test_tv2_downgrade_blocked_by_pinning():
    r = {m["mode"]: m["forged_accepted_pct"] for m in ts.tv2_downgrade(trials=10)["modes"]}
    assert r == {"HYBRID_PERMISSIVE": 100.0, "HYBRID_PINNED": 0.0, "STRICT_AES": 0.0}


def test_tv3_replay():
    cases = ts.tv3_replay(trials=12)["cases"]
    assert [c["replay_accepted_pct"] for c in cases] == [100.0, 0.0, 100.0, 0.0]
