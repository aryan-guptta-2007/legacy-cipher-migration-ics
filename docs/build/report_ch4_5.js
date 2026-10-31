// Chapters 4-5: System Design & Methodology, Implementation.
"use strict";
const { extract, countLines } = require("./lib");

module.exports = function chapters4to5(c, R, team, extra) {
  const out = [];
  const add = (...xs) => xs.forEach((x) => (Array.isArray(x) ? out.push(...x) : out.push(x)));
  const TV = Object.fromEntries(R.trans.map((t) => [t.id, t]));

  // =================================================================== CHAPTER 4
  add(c.chapterHeading(4, "System Design and Methodology"));
  add(c.h2("4.1", "Methodology"));
  add(c.p("The project follows an iterative *build-attack-mitigate-measure* methodology, adapted from design-science research. Each cycle produces an artefact, subjects it to an adversary, and records quantitative evidence:"));
  add(c.numbered([
    "**Model the legacy system faithfully** - classical ciphers, the legacy frame format and feeder physics - so that attacks and overheads are realistic.",
    "**Build the migration artefact** - the secure envelope, the gateway and the migration policies.",
    "**Attack** the legacy system and every intermediate configuration a real migration passes through (positions A1 and A2 of the threat model).",
    "**Mitigate** each successful attack with a concrete design change implemented in the framework.",
    "**Measure** attack success, latency, overhead and data integrity against the objectives of Section 1.4, using fixed random seeds.",
    "**Iterate** until every objective is met, then regenerate all reported numbers automatically from the results files.",
  ]));
  add(c.p("A key methodological decision is a *single source of truth*: experiments write JSON files, and the figures, this report and the presentation are generated from those files. No number in Chapter 6 is transcribed by hand, which keeps the design, implementation and documentation synchronised."));

  add(c.h2("4.2", "System Architecture"));
  add(c.p("{fig:arch} shows the architecture. The **field zone** contains legacy RTUs 1-6, each protected by a different classical cipher; RTU 7, which still sends unencrypted frames and has not yet been migrated; and RTU 8, an upgraded device that seals envelopes itself. The **protocol-translation gateway** sits at the substation boundary and performs the uplink pipeline (legacy decryption, parsing, validation, AES-256-GCM sealing) and the downlink pipeline (command verification and legacy re-encoding). The **control centre** applies the migration policy, verifies envelopes and stores readings. Every box is annotated with the Python module that implements it."));
  add(c.figure("arch", "fig_architecture.png", "System architecture of LCMF with adversary positions A1 and A2", 6.0));
  add(c.p("{fig:dfd0} gives the context-level data-flow diagram (DFD level 0). The system exchanges legacy-encrypted telemetry and commands with legacy RTUs, envelopes with upgraded RTUs, authenticated readings and commands with the SCADA operator, and experiment configuration and results with the security analyst; a master key is provisioned once."));
  add(c.figure("dfd0", "fig_dfd0.png", "Data-flow diagram, level 0 (context diagram)", 5.6));

  add(c.h2("4.3", "Data Design"));
  add(c.h3("4.3.1", "Legacy telemetry frame"));
  add(c.p("Legacy RTUs send one fixed-width record per poll over the 36-symbol alphabet Z36 = {A-Z, 0-9} ({fig:frame}). The frame is 52 symbols long; 24 symbols are constant tags, which hands an eavesdropper a large amount of known plaintext. A three-digit checksum (the sum of symbol indices modulo 1000) detects line noise but is not cryptographic. The symbol X never occurs in a frame, which allows it to be used as the Playfair filler without ambiguity."));
  add(c.figure("frame", "fig_frame_format.png", "Legacy Telemetry Frame (LTF): fixed tags (known plaintext) and variable fields", 6.0));
  add(c.table("ltf", "Fields of the legacy telemetry frame",
    ["Tag", "Width", "Content", "Unit / encoding", "Example"],
    [
      ["RTU", "2", "Device identifier", "decimal", "04"],
      ["SEQ", "4", "Legacy sequence number", "decimal, wraps at 10,000", "0042"],
      ["VLT", "5", "Line voltage", "volt", "11023"],
      ["CUR", "4", "Feeder current", "0.1 A", "1873 (187.3 A)"],
      ["FRQ", "4", "System frequency", "0.01 Hz", "5001 (50.01 Hz)"],
      ["PWR", "5", "Active power", "kW", "03397"],
      ["BRK", "1", "Breaker status", "C = closed, O = open", "C"],
      ["CHK", "3", "Checksum", "sum of indices mod 1000", "517"],
    ], [1, 0.9, 2.2, 2.6, 1.8]));
  add(c.p("Commands use the frame ~RTU04CMDOPENSEQ0007CHKnnn~ with the actions OPEN and CLOS."));
  add(c.h3("4.3.2", "Modern payload"));
  add(c.p("Inside the secure envelope, a reading is serialised as a compact 15-byte big-endian structure (~>IHHIBH~): voltage (4 bytes), current (2), frequency (2), power (4), breaker (1) and the legacy sequence number (2). All quantities are fixed-point integers, so translation between the two formats is exact."));
  add(c.h3("4.3.3", "Secure Telemetry Envelope (STE)"));
  add(c.p("{fig:envelope} shows the 68-byte envelope. The 37-byte header carries the routing and freshness fields in clear and is passed to GCM as associated data, so that the device identifier, sequence number, timestamp and key generation cannot be altered without invalidating the tag. The overhead over the raw payload is 53 bytes (37-byte header plus 16-byte tag)."));
  add(c.figure("envelope", "fig_envelope.png", "Byte layout of the Secure Telemetry Envelope (STE v1)", 6.0));

  add(c.h2("4.4", "Design of the Legacy Cipher Subsystem"));
  add(c.p("All six ciphers implement one abstract interface, ~ClassicalCipher~, with ~encrypt~, ~decrypt~ and ~key_space~, and are parameterised by an ~Alphabet~ object. This lets the same code be verified against textbook vectors over Z26 and then used on telemetry over Z36. {tab:ciphers} summarises the configured ciphers and their key spaces over Z36."));
  add(c.table("ciphers", "Legacy ciphers configured in the simulated network",
    ["RTU", "Cipher", "Key used", "Key space over Z36", "Design note"],
    [
      ["1", "Caesar", "shift 3 (fixed)", "1", "Additive cipher with the key frozen into the algorithm"],
      ["2", "Additive", "k = 17", "36", "C = (P + k) mod 36"],
      ["3", "Affine", "a = 5, b = 8", "12 x 36 = 432", "a must be a unit mod 36"],
      ["4", "Vigenere", "GRIDLOCK", "36^8 (about 2^41)", "Key restarts at every frame"],
      ["5", "Playfair", "SUBSTATION", "36! (about 2^138)", "6x6 square, X filler, Q if X is doubled"],
      ["6", "Columnar", "BREAKER", "7! = 5,040", "Irregular (no padding), stable key ranking"],
      ["7", "None", "-", "1", "Unencrypted legacy link"],
      ["8", "Vigenere / AES", "HELIOS, later AES-256-GCM", "36^6 / 2^256", "Upgraded to a native-AES RTU in Phase 1"],
    ], [0.6, 1.3, 1.8, 1.9, 3.2]));
  add(c.p("Two design choices deserve explanation. First, the classical 5x5 Playfair merges I and J and cannot represent digits; the project therefore uses a 6x6 square over Z36, which is lossless for telemetry. Second, the columnar transposition is *irregular* - the last row is not padded - so ciphertext length equals plaintext length and decryption is exact."));

  add(c.h2("4.5", "Design of the Modern Cryptography Engine"));
  add(c.p("AES is implemented from first principles so that its correctness can be inspected and verified ({fig:aes}). The S-box is not copied as a table but *derived*: each byte is inverted in GF(2^8) by computing a^254 and then passed through the affine transformation. MixColumns uses precomputed multiplication tables, and the key schedule supports 128-, 192- and 256-bit keys."));
  add(c.figure("aes", "fig_aes_round.png", "AES-256 encryption: round structure and key expansion as implemented in aes_core.py", 6.0));
  add(c.p("GCM is implemented according to SP 800-38D ({fig:gcm}). The GHASH multiplication in GF(2^128) follows Algorithm 1 of the standard, with the reduction constant R = 0xE1 || 0^120. The gateway's production path uses the same mode through the pyca/cryptography library (OpenSSL with AES-NI); both engines expose an identical ~seal~/~open~ interface and can be swapped by configuration."));
  add(c.figure("gcm", "fig_gcm.png", "AES-GCM encryption and tag computation", 6.0));
  add(c.p("**Nonce construction.** A GCM nonce must never repeat under a key. The deterministic construction of SP 800-38D Section 8.2.1 is used:"));
  add(c.equation("nonce", "nonce (96 bits) = sender_id (32 bits) || message counter (64 bits)"));
  add(c.p("The counter doubles as the envelope sequence number. To survive reboots, the nonce manager reserves counter blocks and writes the high-water mark to disk *before* using any value from the block, so a restarted device resumes above every value it might already have used."));
  add(c.p("**Key hierarchy.** One 256-bit random master key is provisioned to the gateway and the SCADA master. Working keys are derived per device, per direction and per key generation with HKDF-SHA256 [@rfc5869]:"));
  add(c.equation("hkdf", "K(dev, dir, gen) = HKDF-SHA256( IKM = master, salt = gen, info = \"LCMF-v1|dev=<id>|dir=<up|down>\" )"));
  add(c.p("Compromise of one device key therefore exposes nothing else, and key rotation only increments the generation number carried in the envelope header. **Anti-replay.** The receiver keeps, per device and direction, the highest authenticated sequence number and a 64-bit bitmap of recently seen numbers, as in IPsec ESP [@rfc4303]; envelopes with timestamps more than 30 s from the receiver clock are also rejected."));

  add(c.h2("4.6", "Gateway Pipeline and Migration Policy"));
  add(c.p("{fig:flow} shows the uplink pipeline. A frame is rejected at the first failing stage, and the rejection reason is recorded. The downlink performs the reverse: it checks the envelope's freshness, verifies the tag, decodes the command, re-encodes it as a legacy command frame and encrypts it with the target RTU's legacy cipher."));
  add(c.figure("flow", "fig_uplink_flow.png", "Uplink processing pipeline from RTU to SCADA historian, with rejection points", 6.0));
  add(c.p("A real migration does not switch all devices at once. LCMF models four phases ({fig:migration}); in each phase every device is either *legacy direct* (talks legacy to SCADA), *bridged* (legacy RTU behind the gateway) or *native AES* (upgraded RTU). The control centre enforces the corresponding policy ({tab:policy})."));
  add(c.figure("migration", "fig_migration.png", "Migration phases and the state of each device", 6.0));
  add(c.table("policy", "Migration policies enforced at the control centre",
    ["Mode", "Legacy frames accepted from", "Secure envelopes", "Purpose / risk"],
    [
      ["LEGACY_ONLY", "every device", "rejected", "Phase 0 baseline"],
      ["HYBRID_PERMISSIVE", "every device", "accepted", "Convenient, but open to downgrade (TV2)"],
      ["HYBRID_PINNED", "only devices not yet migrated; a device is pinned once registered or once it sends a valid envelope", "accepted", "Safe transition (HSTS-like pinning)"],
      ["STRICT_AES", "no device", "accepted", "Phase 3 end state"],
    ], [1.8, 3.2, 1.4, 2.4]));

  add(c.h2("4.7", "Security Analysis and Experiment Design"));
  add(c.p("The attacker's main tool against legacy links is the public frame grammar: any candidate key that decrypts a captured frame into a syntactically valid frame with a correct checksum is almost certainly the right key. {tab:cryptodesign} lists the attack designed for each cipher."));
  add(c.table("cryptodesign", "Cryptanalysis design per legacy cipher",
    ["Cipher", "Attack", "Why it works"],
    [
      ["Caesar / Additive", "Exhaustive search over 36 keys, frame-grammar test", "Tiny key space; fixed tags give a perfect plaintext test"],
      ["Affine", "Exhaustive search over 432 keys; known-plaintext solution of two congruences", "Small key space; linear structure"],
      ["Vigenere", "Per-residue constraint propagation: for each key position keep only shifts that map every symbol in that residue class onto the frame template; confirm by checksum", "Tags and digit-only fields constrain each key symbol independently"],
      ["Playfair", "Keyword dictionary search; known-plaintext digram codebook", "Keys are memorable words; digram substitution is deterministic"],
      ["Columnar", "Exhaustive search over column orders for up to 7 columns, plus protocol coherence (device id, consecutive sequence numbers)", "Small permutation space; a sum checksum cannot detect transpositions"],
      ["English text (textbook)", "Chi-squared shift search; Friedman period test; Kasiski examination", "Classical statistical attacks for comparison"],
    ], [1.5, 3.6, 3.6]));
  add(c.p("Transition vulnerabilities are studied in eight controlled experiments ({tab:tvdesign}). Each compares a vulnerable configuration with a mitigated one under an identical adversary and seed."));
  add(c.table("tvdesign", "Design of the transition-vulnerability experiments",
    ["ID", "Transition hazard", "Adversary and action", "Metric", "Mitigation tested"],
    [
      ["TV1", "Legacy last mile behind the gateway", "A1 breaks the legacy key, then rewrites frames (gross and stealthy false data)", "% forged readings accepted by SCADA", "Plausibility filter; native AES at the RTU"],
      ["TV2", "Downgrade while both protocols are accepted", "A2 strips envelopes of a migrated RTU and injects legacy frames", "% forged legacy frames accepted", "Policy pinning (HYBRID_PINNED), STRICT_AES"],
      ["TV3", "Replay, including replay laundered by the gateway", "A2 replays frames; A1 replays old legacy frames into the gateway", "% replays accepted", "Sequence window + timestamps; legacy sequence tracking"],
      ["TV4", "Malleability of legacy and confidentiality-only AES", "Blind modification of the breaker field without any key", "% successful tampering", "AES-GCM authentication"],
      ["TV5", "Deterministic encryption (ECB) of low-entropy status", "Passive inference of breaker state from ciphertext equality", "Attacker balanced accuracy", "Nonce-based AEAD (GCM)"],
      ["TV6", "Nonce reuse after reboot", "Passive collection of envelopes across reboots", "Nonce collisions; % plaintext recovered", "Persistent, reserved counters"],
      ["TV7", "AES keys derived from legacy secrets", "Pivot from broken legacy key; dictionary search on one envelope", "Key recovered? guesses", "HKDF from a random master key"],
      ["TV8", "Overhead on low-bandwidth links", "-", "Bytes, link time, gateway latency", "Compact payload; baud-rate planning"],
    ], [0.6, 1.9, 2.4, 1.7, 2.1], { size: 18 }));

  add(c.h2("4.8", "Module and Class Design"));
  add(c.p("{fig:classes} shows the package structure and the principal classes. The packages map one-to-one onto the work division between team members, and the only cross-package dependencies are the interfaces ~ClassicalCipher~, ~AEADEngine~, ~TelemetryReading~ and the envelope functions."));
  add(c.figure("classes", "fig_class_diagram.png", "Package and class design of LCMF (owner of each package in brackets)", 6.0));

  add(c.h2("4.9", "Justification of Algorithms and Techniques"));
  add(c.table("justify", "Justification of the main algorithms and techniques",
    ["Technique", "Why it was chosen", "Alternatives considered"],
    [
      ["Z36 alphabet for legacy ciphers", "Telemetry is numeric; Z36 keeps every cipher lossless while preserving its classical structure", "Spelling digits as words (inflates frames); Z26 with digit mapping (ambiguous)"],
      ["6x6 Playfair", "Enciphers digits; filler X never occurs in frames", "5x5 Playfair (cannot represent digits, merges I/J)"],
      ["AES-256", "NIST standard, long security margin, hardware acceleration [@fips197]", "AES-128 (sufficient today but smaller margin); ChaCha20-Poly1305 (not a project requirement)"],
      ["GCM mode", "Single-pass AEAD; authenticates the header as AAD; widely deployed [@sp80038d]", "CBC + HMAC (two passes, more overhead); CTR or CBC alone (malleable - TV4); ECB (leaks patterns - TV5)"],
      ["Deterministic 96-bit nonces with persistent counters", "Uniqueness guaranteed without a random-number generator on the device", "Random 96-bit nonces (birthday bound, needs good RNG)"],
      ["HKDF-SHA256 key hierarchy", "Key separation per device, direction and generation [@rfc5869]", "One shared key (single point of failure); keys hashed from legacy keywords (TV7)"],
      ["Sliding replay window + timestamps", "Tolerates reordering, rejects duplicates and stale frames [@rfc4303]", "Strictly increasing counter only (drops reordered frames)"],
      ["Frame-grammar-based cryptanalysis", "Matches the real attacker's knowledge (public protocol formats)", "English frequency analysis only (does not apply to numeric telemetry)"],
      ["Physics-based plausibility filter", "Cheap defence-in-depth against gross false data on the last mile", "Machine-learning anomaly detection (future scope)"],
    ], [2.0, 3.6, 3.0], { size: 18 }));

  // =================================================================== CHAPTER 5
  add(c.chapterHeading(5, "Implementation"));
  add(c.h2("5.1", "Development Environment and Project Structure"));
  add(c.p(`LCMF is implemented in Python ${R.bench.environment.python}. The only runtime dependency is the pyca/cryptography library (${R.bench.environment.cryptography}), used for the production AES-GCM path and HKDF [@pyca]; pytest, matplotlib and numpy are used for testing and figures, and Node.js scripts generate the report and slides. The source tree is shown in {lst:tree}.`));
  add(c.listing("tree", "Project directory structure", [
    "modern project submission/",
    "|-- lcmf/                      Python package (the framework)",
    "|   |-- classical/             legacy cipher suite                    (Member 1)",
    "|   |-- modern/                AES core, modes, AEAD, keys, nonces    (Member 2)",
    "|   |-- grid/                  telemetry, codec, simulator, SCADA     (Member 3)",
    "|   |-- gateway/               envelope (M2), gateway, policy, filter (M3)",
    "|   |-- analysis/              cryptanalysis (M1), TV experiments (M2, M3), runner (M2)",
    "|   `-- cli.py                 command-line interface / demonstration",
    "|-- tests/                     unit and integration tests (pytest)",
    "|-- scripts/generate_figures.py  figure pipeline                     (Member 1)",
    "|-- results/                   generated JSON results (single source of truth)",
    "|-- docs/figures/              generated figures",
    "|-- docs/build/                report and slide generators, team_config.json",
    "|-- requirements.txt, run_demo.bat, build_all.bat, README.md",
  ]));
  add(c.table("loc", "Size of the implementation (non-blank lines)",
    ["Package", "Purpose", "Lines"],
    extra.locRows, [2.2, 5, 1.2], { align: [undefined, undefined, 2] }));

  add(c.h2("5.2", "Legacy Cipher Suite and Cryptanalysis (Member 1)"));
  add(c.p("Each cipher is a small class built on the common interface. The Playfair digram rule ({lst:playfair}) is the core of the polygraphic cipher; the same method performs decryption when called with direction -1."));
  add(c.listing("playfair", "Playfair digram substitution - lcmf/classical/polyalphabetic.py", extract("lcmf/classical/polyalphabetic.py", "    def _sub(", 12)));
  add(c.p("The Vigenere attack ({lst:vigattack}) never guesses the whole key. For each candidate period it computes, independently for every residue class, the set of shifts that map all captured symbols in that class onto symbols allowed by the public frame template. The intersection is usually a single shift, so the key falls out after checking a handful of periods; candidates are confirmed by checksum."));
  add(c.listing("vigattack", "Template-constrained key search for Vigenere - lcmf/analysis/cryptanalysis.py", extract("lcmf/analysis/cryptanalysis.py", "def _residue_candidates(", 16)));
  add(c.p("While implementing the columnar attack the team found that the legacy checksum is *transposition-blind*: because it is a plain sum, a wrong column order that swaps two digits still produces a checksum-valid frame (for example ~RTU60...SEQ6010~ instead of ~RTU06...SEQ6001~). The attack therefore adds a protocol-coherence test - one device identifier per link and consecutive sequence numbers - which removes the ambiguity with a second frame."));

  add(c.h2("5.3", "Modern Cryptography Engine and Secure Envelope (Member 2)"));
  add(c.p("{lst:aes} shows block encryption in the from-scratch AES. The state is a list of sixteen integers in column-major order, matching FIPS 197."));
  add(c.listing("aes", "AES block encryption - lcmf/modern/aes_core.py", extract("lcmf/modern/aes_core.py", "    def encrypt_block(", 16)));
  add(c.p("GHASH multiplication in GF(2^128) is a direct transcription of Algorithm 1 of SP 800-38D ({lst:gf128}); the bit order follows GCM's convention that the most significant bit is the coefficient of x^0."));
  add(c.listing("gf128", "Multiplication in GF(2^128) for GHASH - lcmf/modern/aes_modes.py", extract("lcmf/modern/aes_modes.py", "def gf128_mul(", 12)));
  add(c.p("The nonce manager ({lst:nonce}) implements the crash-safe counter: the high-water mark is persisted before a new block of counters is used."));
  add(c.listing("nonce", "Crash-safe nonce allocation - lcmf/modern/nonce.py", extract("lcmf/modern/nonce.py", "    def next(", 12)));

  add(c.h2("5.4", "Grid Simulator, Gateway and SCADA (Member 3)"));
  add(c.p("The feeder model drives current from a 24-hour load curve and lets the bus voltage sag under load; frequency is a shared mean-reverting random walk around 50 Hz. Every sample satisfies the three-phase power relation, which the plausibility filter later relies on:"));
  add(c.equation("power", "P = √3 × V × I × pf,     pf = 0.95"));
  add(c.p("{lst:uplink} shows the gateway uplink, which mirrors the pipeline of {fig:flow} step by step and records per-stage timings."));
  add(c.listing("uplink", "Gateway uplink translation - lcmf/gateway/gateway.py", extract("lcmf/gateway/gateway.py", "    def translate_uplink(", 40)));
  add(c.p("The migration policy is deliberately small ({lst:policy}); its effect on downgrade attacks is measured in experiment TV2."));
  add(c.listing("policy", "Migration policy decision for legacy frames - lcmf/gateway/policy.py", extract("lcmf/gateway/policy.py", "    def accepts_legacy(", 12)));

  add(c.h2("5.5", "Design-to-Implementation Traceability"));
  add(c.p("{tab:trace} maps every design element of Chapter 4 to the code that implements it, the test that verifies it and the result that evidences it. Every row is complete, so the implementation is fully aligned with the design."));
  add(c.table("trace", "Traceability matrix: requirement - design - implementation - verification - evidence",
    ["Req.", "Design (section)", "Implementation", "Verified by", "Evidence"],
    [
      ["FR1", "Cipher suite (4.4)", "classical/monoalphabetic.py, polyalphabetic.py, transposition.py", "test_classical.py (vectors, round trips)", "{tab:vectors}"],
      ["FR2", "Legacy frame (4.3.1)", "grid/legacy_codec.py", "test_gateway.py::test_legacy_frame_format", "{fig:frame}"],
      ["FR3", "Simulator (4.2)", "grid/simulator.py, grid/network.py", "test_end_to_end_integrity", "{tab:integrity}"],
      ["FR4", "Uplink pipeline, STE (4.3.3, 4.6)", "gateway/gateway.py, gateway/envelope.py", "test_gateway_uplink_and_downlink", "{tab:integrity}, {fig:latency}"],
      ["FR5", "Downlink (4.6)", "ProtocolTranslationGateway.translate_downlink", "test_breaker_commands_reach_every_kind_of_rtu", "Appendix C"],
      ["FR6", "Migration policy (4.6)", "gateway/policy.py", "test_policy_rules, test_tv2_downgrade_blocked_by_pinning", "{tab:tv2}"],
      ["FR7", "Anti-replay (4.5)", "modern/replay.py, legacy_seq_is_newer", "test_replay_window, test_tv3_replay", "{tab:tv3}"],
      ["FR8", "Plausibility (4.9)", "gateway/plausibility.py", "test_plausibility_filter, test_tv1_trust_laundering", "{tab:tv1}"],
      ["FR9", "Cryptanalysis (4.7)", "analysis/cryptanalysis.py", "six test_break tests", "{tab:attacks}, {fig:keyspace}"],
      ["FR10", "TV experiments (4.7)", "analysis/transition_system.py, transition_crypto.py", "test_tv1 ... test_tv4_to_tv7", "Section 6.5"],
      ["FR11", "Tooling (4.8)", "cli.py, analysis/experiments.py, scripts/", "run_demo.bat (end-to-end)", "Appendix A, C"],
      ["NFR1", "Library AEAD engine (4.5)", "modern/aead.py (LibraryAESGCM)", "benchmark.py, TV8", "{fig:latency}"],
      ["NFR2", "Compact payload (4.3.2)", "TelemetryReading.PAYLOAD (15 B)", "test_envelope_layout_and_header_authentication", "{tab:tv8}"],
      ["NFR4", "AES / GCM / HKDF (4.5)", "modern/aes_core.py, aes_modes.py, keystore.py", "test_fips197 and test_gcm tests", "{tab:vectors}"],
    ], [0.6, 1.7, 2.6, 2.4, 1.3], { size: 17 }));

  add(c.h2("5.6", "Testing"));
  add(c.p(`Testing combines four techniques: *published test vectors* (textbook cipher examples, FIPS-197 Appendices A-C, GCM specification test cases), *property-based round trips* on randomly generated telemetry frames, *cross-implementation checks* between the educational and library AES-GCM, and *integration tests* that run the whole network in every migration mode and assert that each attack/mitigation pair behaves as designed. The suite contains ${extra.tests.total} automated tests, all of which pass (${extra.tests.summary}).`));
  add(c.table("tests", "Automated test suites",
    ["Test file", "Owner", "Focus", "Tests"],
    extra.tests.rows, [2.2, 1.0, 4.4, 0.8], { align: [undefined, undefined, undefined, 2] }));

  add(c.h2("5.7", "Demonstration of the Modules"));
  add(c.p("Every module can be demonstrated live from the command line ({tab:demo}). The guided demo walks through all modules in about two minutes and is the basis of the viva demonstration; Appendix C reproduces its output."));
  add(c.table("demo", "Command-line demonstration of each module",
    ["Command", "Module demonstrated", "What the audience sees"],
    [
      ["python -m lcmf demo --interactive", "All modules, in order", "Legacy ciphertexts, AES vector check, gateway translation with envelope hex, breaker commands, key recovery table, TV1-TV8 summary"],
      ["python -m lcmf cipher affine encrypt TEXT --a 5 --b 8", "Legacy cipher suite (M1)", "Encryption/decryption with any cipher and key; key space"],
      ["python -m lcmf attack", "Cryptanalysis (M1)", "Every legacy key recovered with effort metrics"],
      ["python -m lcmf simulate --mode STRICT_AES", "Simulator, gateway, SCADA (M3) + envelope (M2)", "Per-poll readings, path, verdict, wire bytes"],
      ["python -m lcmf transition", "Transition experiments (M2, M3)", "Raw TV1-TV8 results"],
      ["python -m lcmf experiments", "Experiment runner", "Objectives table; results/*.json regenerated"],
      ["python -m pytest", "All modules", `${extra.tests.total} passing tests`],
    ], [3.0, 2.2, 3.6], { size: 18 }));
  return out;
};
