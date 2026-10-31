# Viva and Presentation Guide

Target length: about 18 minutes of presentation + 4 minutes of live demo + questions.
Each member presents the module they own, so the "contribution" criterion is visible to the panel.

> **Note for the live demo:** timings (milliseconds, microseconds) change slightly on every run and on
> every machine, so the live numbers will not match the report exactly - that is expected. All success
> rates, key recoveries, frame counts and byte sizes are deterministic (fixed seeds) and will match.
> Demo from your own laptop with dependencies already installed; `run_demo.bat` needs internet for `pip`.

## Running order

| Slides | Presenter | Time | Key message |
|---|---|---|---|
| 1-3 | Member 1 | 3 min | Grid telemetry still runs on legacy links; devices live 15-30 years, so migration is gradual |
| 4-5 | Member 2 / Member 3 | 2 min | Problem statement, measurable objectives, existing approaches and the gap |
| 6-9 | **Member 1** | 4 min | Six legacy ciphers; the frame grammar is free known plaintext; every key recovered from <= 2 frames |
| 10-13 | **Member 2** | 4 min | AES/GCM from first principles, 68-byte envelope, why "just use AES" fails (TV4-TV7) |
| 14-18 | **Member 3** | 4 min | Architecture, migration phases, downgrade, last mile, performance |
| 19-20 | All, Member 3 at keyboard | 4 min | Summary chart, then live demo |
| 21-24 | All | 2 min | Objectives met, playbook, contributions, questions |

## Demo script (Member 3 types, the others narrate their part)

1. `python -m lcmf demo --interactive` - press Enter between modules.
   * Module 1 (Member 1): the same frame under six ciphers.
   * Module 2 (Member 2): AES-256 FIPS-197 vector PASS.
   * Module 3 (Member 3): legacy wire -> plaintext -> 68-byte envelope -> SCADA ACCEPTED.
   * Module 5 (Member 1): every legacy key recovered.
   * Module 6 (Members 2 and 3): TV1-TV8 summary.
2. Backup if time allows: `python -m pytest` (all tests pass), `python -m lcmf attack`.

## Likely questions and short answers

**Why not just replace every RTU?** Field devices cost money, need outages and live 15-30 years; a
gateway protects the WAN immediately while RTUs are replaced over time. Our TV1 result shows exactly what
the gateway cannot fix (the last mile), so utilities know which RTUs to replace first.

**Why AES-GCM and not AES-CBC?** GCM is authenticated: TV4 shows CBC and CTR without a MAC let an attacker
flip the breaker bit 100% of the time; GCM rejected 100% of modifications. GCM is single-pass and also
authenticates the header (AAD).

**What is the header used as AAD for?** Device id, sequence number, timestamp and key id must be readable
for routing and replay checks, so they are sent in clear - but authenticated, so they cannot be changed.

**How do you guarantee nonces never repeat?** Nonce = 32-bit sender id || 64-bit counter. The counter is
reserved in blocks and written to disk before use, so after a reboot it resumes above any used value. TV6
shows RAM-only counters produced hundreds of nonce collisions; persistent counters produced none.

**Playfair has 2^138 keys - more than AES-128. How did you break it?** The key was a dictionary word, so we
searched 178 candidate words; and with known plaintext a digram codebook decrypts most of a new frame
without the key at all. Key space is not security.

**How does the Vigenere attack work?** For each candidate period, each key symbol is constrained
independently: it must map every captured symbol in its residue class to a symbol allowed by the public
frame template (tag letters or digits). This leaves one shift per position after a handful of checks.

**Why a 36-symbol alphabet?** Telemetry is numeric; Z36 = A-Z0-9 keeps every classical cipher lossless,
and a 6x6 Playfair square holds all 36 symbols (the 5x5 square cannot encode digits).

**What is a downgrade attack here?** During migration the control centre must still accept legacy frames
from unmigrated devices. An attacker strips a migrated device's envelope and sends a legacy frame instead.
HYBRID_PERMISSIVE accepted 100%; pinning migrated devices (HYBRID_PINNED) accepted 0% while still serving
the unmigrated RTU.

**What is "trust laundering"?** If the attacker forges a legacy frame behind the gateway, the gateway seals
it into a valid AES envelope - the MAC certifies false data. Plausibility checks stop gross forgeries but
not physically consistent ones; only native AES in the RTU closes it.

**Did you write AES yourselves? Is that safe?** Yes, for learning and verification (validated against FIPS
197 and GCM test vectors and bit-identical to the library). Production uses the audited, constant-time
`cryptography` library; both engines share one interface.

**Is the overhead acceptable?** 53 bytes and tens of microseconds per frame. An 8-RTU scan at 9,600 baud
takes about 0.57 s, inside a 2 s cycle; at 1,200 baud even legacy frames already overrun the cycle.

**How are the results reproducible?** Every experiment uses a fixed seed and writes JSON; figures, report
tables and slides are generated from those files - no number is typed by hand.

**What are the limitations?** Simulated environment, file-based key storage, plausibility filter cannot
detect consistent false data, and the Playfair attack assumes dictionary keys or known plaintext.

**Future work?** Embedded hardware gateway on real serial links, Modbus/DNP3 adapters with IEC 62351,
HSM-stored keys, ML/state-estimation anomaly detection, post-quantum key establishment.
