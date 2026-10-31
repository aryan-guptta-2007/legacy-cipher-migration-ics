"""Integration tests - simulator, gateway, policy and SCADA (Member 3)."""
import pytest

from lcmf.gateway import (BRIDGED, MigrationMode, MigrationPolicy, PlausibilityFilter,
                          ProtocolTranslationGateway, DeviceProfile, legacy_seq_is_newer, parse_header)
from lcmf.grid.legacy_codec import (FRAME_LEN, FrameError, decode_command, decode_telemetry, encode_command,
                                    encode_telemetry, is_valid_telemetry)
from lcmf.grid.network import GridNetwork
from lcmf.grid.telemetry import Command, TelemetryReading
from lcmf.modern.keystore import KeyStore

R = TelemetryReading(4, 42, 11_023, 1_873, 5_001, 3_397, True)


def test_legacy_frame_format():
    frame = encode_telemetry(R)
    assert frame.startswith("RTU04SEQ0042VLT11023CUR1873FRQ5001PWR03397BRKCCHK")
    assert len(frame) == FRAME_LEN == 52 and "X" not in frame
    assert decode_telemetry(frame) == R
    bad = frame[:20] + ("1" if frame[20] != "1" else "2") + frame[21:]
    with pytest.raises(FrameError):
        decode_telemetry(bad)


def test_command_frame_and_payloads():
    c = Command(3, "OPEN", 7)
    assert decode_command(encode_command(c)) == c
    assert Command.from_payload(3, 0, c.to_payload()) == c
    assert TelemetryReading.from_payload(4, 0, R.to_payload()) == R


def test_legacy_sequence_arithmetic():
    assert legacy_seq_is_newer(5, 4) and legacy_seq_is_newer(0, 9999)
    assert not legacy_seq_is_newer(4, 4) and not legacy_seq_is_newer(3, 4)


def test_plausibility_filter():
    f = PlausibilityFilter()
    assert f.check(R)[0]
    assert not f.check(R.evolve(voltage_v=9_000))[0]
    assert not f.check(R.evolve(breaker_closed=False))[0]          # current through open breaker
    assert not f.check(R.evolve(power_kw=9_000))[0]                # impossible power factor
    assert not f.check(R.evolve(voltage_v=11_700), previous=R)[0]  # 677 V step


def test_gateway_uplink_and_downlink():
    ks = KeyStore(bytes(32))
    gw = ProtocolTranslationGateway(1, ks, [DeviceProfile(4, "F4", {"type": "vigenere", "key": "GRIDLOCK"})],
                                    plausibility=PlausibilityFilter())
    cipher = gw.ciphers[4]
    res = gw.translate_uplink(4, cipher.encrypt(encode_telemetry(R)), 1_000)
    assert res.ok and res.reading.same_measurement(R)
    hdr, _, _ = parse_header(res.envelope)
    assert hdr.device_id == 4 and hdr.seq == 1 and len(res.envelope) == 68
    # replayed legacy frame is refused by legacy sequence tracking
    again = gw.translate_uplink(4, cipher.encrypt(encode_telemetry(R)), 3_000)
    assert not again.ok and "replay" in again.reason
    # garbage and wrong-device frames are refused
    assert not gw.translate_uplink(4, "ABC", 5_000).ok
    assert not gw.translate_uplink(4, cipher.encrypt(encode_telemetry(R.evolve(device_id=5, seq=43))), 5_000).ok


@pytest.mark.parametrize("mode", list(MigrationMode))
def test_end_to_end_integrity(mode):
    net = GridNetwork(mode, seed=3)
    events = net.run(40)
    assert all(e["accepted"] for e in events)
    for e in events:
        rx = {k: v for k, v in e["received"].items() if k != "timestamp_ms"}
        tx = {k: v for k, v in e["truth"].items() if k != "timestamp_ms"}
        assert rx == tx


def test_paths_follow_migration_mode():
    assert GridNetwork("LEGACY_ONLY").step()[0]["path"] == "legacy"
    ev = {e["device_id"]: e for e in GridNetwork("HYBRID_PINNED").step()}
    assert ev[1]["path"] == "secure" and ev[7]["path"] == "legacy" and ev[8]["state"] == "NATIVE_AES"
    assert all(e["path"] == "secure" for e in GridNetwork("STRICT_AES").step())


def test_policy_rules():
    p = MigrationPolicy(MigrationMode.HYBRID_PINNED, migrated={3})
    assert not p.accepts_legacy(3)[0] and p.accepts_legacy(7)[0]
    p.on_secure_frame(7)
    assert not p.accepts_legacy(7)[0]
    assert MigrationPolicy("HYBRID_PERMISSIVE").accepts_legacy(3)[0]
    assert not MigrationPolicy("STRICT_AES").accepts_legacy(7)[0]
    assert not MigrationPolicy("LEGACY_ONLY").accepts_secure(1)[0]


@pytest.mark.parametrize("dev", [4, 7, 8])
def test_breaker_commands_reach_every_kind_of_rtu(dev):
    net = GridNetwork("HYBRID_PINNED")
    assert net.send_command(dev, "OPEN")["breaker_closed"] is False
    net.t_ms += 2_000
    assert net.send_command(dev, "CLOS")["breaker_closed"] is True
    ev = [e for e in net.step() if e["device_id"] == dev][0]
    assert ev["accepted"]


def test_tampered_command_envelope_is_refused():
    net = GridNetwork("STRICT_AES")
    env = bytearray(net.scada.issue_command(4, "OPEN", net.t_ms))
    env[-1] ^= 1
    assert not net.gateway.translate_downlink(bytes(env), net.t_ms).ok
    assert net.rtus[4].breaker_closed
