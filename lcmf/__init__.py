"""LCMF - Legacy Cipher Migration Framework for Industrial Control Systems.

A protocol-translation gateway that wraps legacy, classically encrypted
smart-grid telemetry into AES-256-GCM envelopes, together with the tools to
study the security of the transition itself.

Packages
--------
classical  legacy cipher suite (Caesar, Additive, Affine, Vigenere, Playfair, Columnar)
modern     AES from scratch, modes (ECB/CBC/CTR/GCM), AEAD engines, keys, nonces, replay
grid       telemetry model, legacy frame codec, RTU/feeder simulator, SCADA master, network
gateway    secure envelope, protocol-translation gateway, migration policy, plausibility
analysis   cryptanalysis, transition-vulnerability experiments, benchmarks
"""
__version__ = "1.0.0"
