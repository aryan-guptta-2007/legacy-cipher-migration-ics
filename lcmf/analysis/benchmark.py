"""Micro-benchmarks for the cipher suite, the AES engines and the gateway.

Owner: Member 2 (Modern Cryptography Engine & Experiment Validation)
"""
from __future__ import annotations

import os
import platform
import statistics
import time
from typing import Callable

from ..classical import make_cipher
from ..grid.legacy_codec import encode_telemetry
from ..grid.network import DEFAULT_DEVICES
from ..grid.telemetry import TelemetryReading
from ..modern.aead import EducationalAESGCM, LibraryAESGCM
from ..modern.aes_core import AES

SAMPLE = TelemetryReading(4, 42, 11_023, 1_873, 5_001, 3_397, True)


def per_op_us(fn: Callable[[], object], n: int, repeats: int = 5) -> float:
    """Median over ``repeats`` batches of the mean time per call, in microseconds."""
    batches = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        for _ in range(n):
            fn()
        batches.append((time.perf_counter_ns() - t0) / n / 1e3)
    return round(statistics.median(batches), 2)


def bench_classical(n: int = 2_000) -> list[dict]:
    frame = encode_telemetry(SAMPLE)
    rows = []
    for _, _, spec, _ in DEFAULT_DEVICES[:7]:
        cipher = make_cipher(spec)
        ct = cipher.encrypt(frame)
        rows.append({"cipher": cipher.name, "encrypt_us": per_op_us(lambda: cipher.encrypt(frame), n),
                     "decrypt_us": per_op_us(lambda: cipher.decrypt(ct), n)})
    return rows


def bench_aes(n: int = 2_000) -> list[dict]:
    key, nonce, aad = os.urandom(32), os.urandom(12), os.urandom(37)
    payload = SAMPLE.to_payload()
    lib, edu = LibraryAESGCM(key), EducationalAESGCM(key)
    sealed = lib.seal(nonce, payload, aad)
    aes = AES(key)
    block = os.urandom(16)
    return [
        {"operation": "AES-256 block encrypt (educational)", "us": per_op_us(lambda: aes.encrypt_block(block), n)},
        {"operation": "AES-256 key expansion (educational)", "us": per_op_us(lambda: AES(key), n // 4)},
        {"operation": "AES-256-GCM seal 15 B (library)", "us": per_op_us(lambda: lib.seal(nonce, payload, aad), n)},
        {"operation": "AES-256-GCM open 15 B (library)", "us": per_op_us(lambda: lib.open(nonce, sealed, aad), n)},
        {"operation": "AES-256-GCM seal 15 B (educational)", "us": per_op_us(lambda: edu.seal(nonce, payload, aad), n // 10)},
        {"operation": "AES-256-GCM open 15 B (educational)", "us": per_op_us(lambda: edu.open(nonce, sealed, aad), n // 10)},
    ]


def environment() -> dict:
    import cryptography
    return {"python": platform.python_version(), "platform": platform.platform(),
            "processor": platform.processor() or platform.machine(), "cryptography": cryptography.__version__}


def run_all() -> dict:
    return {"environment": environment(), "classical": bench_classical(), "aes": bench_aes()}
