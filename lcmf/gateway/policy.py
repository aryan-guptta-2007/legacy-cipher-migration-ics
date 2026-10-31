"""Migration policy enforced at the control centre during the transition.

=====================  ==============================================================
mode                   behaviour
=====================  ==============================================================
LEGACY_ONLY            Phase 0 - historical baseline, legacy frames only.
HYBRID_PERMISSIVE      Phase 1 - secure *and* legacy frames from any device.
                       Convenient, but open to downgrade attacks (TV2).
HYBRID_PINNED          Phase 2 - a device that is registered as migrated, or has
                       ever sent a valid secure frame, is pinned: legacy frames
                       claiming to be from it are rejected (HSTS-style).
STRICT_AES             Phase 3 - end state, only authenticated envelopes.
=====================  ==============================================================

Owner: Member 3 (Smart-Grid Simulation, Gateway & Evaluation)
"""
from __future__ import annotations

from enum import Enum


class MigrationMode(str, Enum):
    LEGACY_ONLY = "LEGACY_ONLY"
    HYBRID_PERMISSIVE = "HYBRID_PERMISSIVE"
    HYBRID_PINNED = "HYBRID_PINNED"
    STRICT_AES = "STRICT_AES"


class MigrationPolicy:
    def __init__(self, mode: MigrationMode | str, migrated: set[int] | None = None):
        self.mode = MigrationMode(mode)
        self.pinned: set[int] = set(migrated or ())

    def accepts_legacy(self, device_id: int) -> tuple[bool, str]:
        if self.mode in (MigrationMode.LEGACY_ONLY, MigrationMode.HYBRID_PERMISSIVE):
            return True, "legacy path permitted"
        if self.mode is MigrationMode.HYBRID_PINNED:
            if device_id in self.pinned:
                return False, "device is pinned to secure transport (downgrade blocked)"
            return True, "legacy path permitted for unmigrated device"
        return False, "strict mode: legacy frames rejected"

    def accepts_secure(self, device_id: int) -> tuple[bool, str]:
        if self.mode is MigrationMode.LEGACY_ONLY:
            return False, "secure envelopes not supported in legacy-only mode"
        return True, "secure path permitted"

    def on_secure_frame(self, device_id: int) -> None:
        if self.mode is MigrationMode.HYBRID_PINNED:
            self.pinned.add(device_id)
