"""Physics-based plausibility filter (defence-in-depth for the legacy last mile).

Cryptography at the gateway cannot tell a genuine legacy frame from one an
attacker forged after breaking the legacy cipher.  The filter checks every
decoded reading against engineering limits of an 11 kV feeder:

* range limits on voltage, frequency and current,
* rate-of-change limit on voltage between consecutive polls,
* power-factor consistency  P = sqrt(3) * V * I * pf  with 0.75 <= pf <= 1.02,
* breaker-state consistency (no current through an open breaker).

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

from dataclasses import dataclass
from math import sqrt

from ..grid.telemetry import TelemetryReading


@dataclass
class PlausibilityLimits:
    v_min: int = 9_900            # -10 % of 11 kV
    v_max: int = 12_100           # +10 %
    f_min: int = 4_950            # 49.50 Hz
    f_max: int = 5_050            # 50.50 Hz
    i_max_da: int = 8_000         # 800 A
    max_dv: int = 550             # 5 % step between polls
    pf_min: float = 0.75
    pf_max: float = 1.02


class PlausibilityFilter:
    def __init__(self, limits: PlausibilityLimits | None = None):
        self.limits = limits or PlausibilityLimits()

    def check(self, r: TelemetryReading, previous: TelemetryReading | None = None) -> tuple[bool, list[str]]:
        lim, issues = self.limits, []
        if not lim.v_min <= r.voltage_v <= lim.v_max:
            issues.append(f"voltage {r.voltage_v} V outside [{lim.v_min}, {lim.v_max}]")
        if not lim.f_min <= r.freq_chz <= lim.f_max:
            issues.append(f"frequency {r.frequency_hz:.2f} Hz outside limits")
        if r.current_da > lim.i_max_da:
            issues.append(f"current {r.current_a:.1f} A above rating")
        if (previous is not None and previous.breaker_closed == r.breaker_closed
                and abs(r.voltage_v - previous.voltage_v) > lim.max_dv):
            issues.append(f"voltage step {r.voltage_v - previous.voltage_v:+d} V exceeds {lim.max_dv} V")
        if not r.breaker_closed and r.current_da > 10:
            issues.append("current flowing through an open breaker")
        if r.breaker_closed and r.current_da > 50 and r.voltage_v > 0:
            pf = r.power_kw * 1000 / (sqrt(3) * r.voltage_v * r.current_a)
            if not lim.pf_min <= pf <= lim.pf_max:
                issues.append(f"power factor {pf:.2f} physically inconsistent")
        return not issues, issues
