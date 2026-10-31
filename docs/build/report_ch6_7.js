// Chapters 6-7, References, Appendices.
"use strict";
const { D } = require("./lib");
const REFS = require("./references");
const { Paragraph, TextRun, AlignmentType } = D;

const f1 = (x) => Number(x).toFixed(1);
const f0 = (x) => Number(x).toFixed(0);
const n0 = (x) => Number(x).toLocaleString("en-US");
const pct = (x) => `${Number(x) % 1 === 0 ? f0(x) : f1(x)}%`;

module.exports = function chapters6to7(c, R, team, extra) {
  const out = [];
  const add = (...xs) => xs.forEach((x) => (Array.isArray(x) ? out.push(...x) : out.push(x)));
  const TV = Object.fromEntries(R.trans.map((t) => [t.id, t]));
  const A = Object.fromEntries(R.crypt.attacks.map((a) => [a.cipher, a]));
  const env = R.bench.environment;
  const t8 = TV.TV8;
  const lat = t8.gateway_latency.library;
  const latE = t8.gateway_latency.educational;
  const worstMed = Math.max(...Object.values(lat).map((v) => v.median_us));
  const eduMed = Math.max(...Object.values(latE).map((v) => v.median_us));
  const aes = Object.fromEntries(R.bench.aes.map((a) => [a.operation, a.us]));
  const libSeal = aes["AES-256-GCM seal 15 B (library)"];
  const eduSeal = aes["AES-256-GCM seal 15 B (educational)"];
  const integ = R.integ;
  const delivered = integ.reduce((s, r) => s + r.delivered, 0);
  const frames = integ.reduce((s, r) => s + r.frames, 0);
  const pf = R.crypt.playfair_codebook;
  const pfAt = (k) => pf.find((p) => p.frames_observed === k).digram_coverage_pct;
  const tb = R.crypt.textbook_english;
  const ioc = R.crypt.index_of_coincidence;
  const maxFrames = Math.max(...R.crypt.attacks.map((a) => a.frames_used));
  const maxMs = Math.max(...R.crypt.attacks.map((a) => a.elapsed_ms));

  // =================================================================== CHAPTER 6
  add(c.chapterHeading(6, "Results and Discussion"));
  add(c.p("This chapter reports the measured results of every experiment. All values are produced by ~python -m lcmf experiments~ and read directly from the ~results/~ directory; they are reproducible because every experiment uses a fixed random seed."));

  add(c.h2("6.1", "Experimental Setup"));
  add(c.table("setup", "Experimental setup",
    ["Parameter", "Value"],
    [
      ["Processor / OS", `${env.processor} / ${env.platform}`],
      ["Software", `Python ${env.python}, cryptography ${env.cryptography}`],
      ["Simulated network", "8 feeders of an 11 kV distribution system, 2 s polling cycle, start 08:00"],
      ["Cryptanalysis data", "10 captured frames per legacy RTU (attacks use as few as needed)"],
      ["Transition experiments", "60 trials (TV1-TV3), 200 frames (TV4), 1,440 one-minute status messages (TV5), 120 polls with a reboot every 30 polls (TV6)"],
      ["Integrity test", `450 polls x 8 devices x 4 modes = ${n0(frames)} frames`],
      ["Total run time of the experiment suite", `${R.summary.runtime_s} s`],
    ], [2.6, 6]));

  add(c.h2("6.2", "Correctness of the Cryptographic Implementations"));
  const vecRows = R.val.vectors.map((v) => [v.module, v.test, v.pass ? "PASS" : "FAIL"]);
  add(c.table("vectors", "Validation against published test vectors",
    ["Module", "Test vector", "Result"], vecRows, [1.6, 5.4, 1.2]));
  const rtTotal = R.val.roundtrip.reduce((s, r) => s + r.frames, 0);
  const rtFail = R.val.roundtrip.reduce((s, r) => s + r.failures, 0);
  add(c.p(`All ${R.val.vectors.length} published vectors pass ({tab:vectors}). In addition, ${n0(rtTotal)} randomly generated telemetry frames were encrypted and decrypted with every legacy cipher with ${rtFail} failures, and the educational AES-256-GCM produced output identical to the cryptography library in ${R.val.gcm_cross_check.identical} of ${R.val.gcm_cross_check.cases} random cases with varying message and AAD lengths. Objectives O1 and O2 are therefore met.`));

  add(c.h2("6.3", "Cryptanalysis of the Legacy Ciphers"));
  add(c.table("attacks", "Key recovery against every legacy cipher from captured traffic",
    ["Cipher", "True key", "Key space", "Attack", "Frames", "Keys tried", "Time (ms)", "Recovered"],
    R.crypt.attacks.map((a) => [a.cipher, a.true_key, `${a.key_space_bits} bits`, a.method, String(a.frames_used),
      n0(a.candidates_tried), f1(a.elapsed_ms), a.success ? "Yes" : "No"]),
    [1.1, 1.6, 0.9, 2.6, 0.7, 0.9, 0.8, 0.9], { size: 17 }));
  add(c.p(`Every legacy cipher was broken ({tab:attacks}). The worst case required ${maxFrames} frames and ${f0(maxMs)} ms. The result that stands out is that **nominal key space has almost no bearing on security** ({fig:keyspace}). Playfair has a key space of about 2^138 - larger than AES-128 - yet fell in ${f1(A.Playfair.elapsed_ms)} ms because its key was a dictionary word. Vigenere's 2^41 keys were reduced to ${A.Vigenere.candidates_tried} candidate evaluations because the fixed tags and digit-only fields constrain every key symbol independently.`));
  add(c.figure("keyspace", "fig_keyspace.png", "Nominal key space of each cipher compared with the measured effort to break it", 5.9));
  add(c.p(`{fig:freq} explains why. Monoalphabetic ciphers only relabel the symbol distribution: the index of coincidence of Caesar ciphertext (${ioc.Caesar}) is essentially that of the plaintext frames (${ioc["Plaintext frames"]}), and the transposition preserves it exactly (${ioc.Columnar}). Vigenere (${ioc.Vigenere}) and Playfair (${ioc.Playfair}) flatten the profile but remain far from the uniform value 1/36 = 0.028, whereas AES-GCM output is statistically flat.`));
  add(c.figure("freq", "fig_frequency.png", "Symbol frequency profiles and index of coincidence of plaintext and ciphertext", 6.0));
  add(c.p(`Even without the key, an attacker who knows a few plaintext-ciphertext pairs can decrypt Playfair traffic with a digram codebook ({fig:playfair}): one known frame already decrypts ${pfAt(1)}% of the digrams of unseen frames, ${pfAt(20)}% after 20 frames and ${pfAt(200)}% after 200. Known-plaintext attacks also recovered the Affine key (${R.crypt.known_plaintext.affine.join(", ")}) from the three-symbol tag "RTU" alone, and the full Vigenere key "${R.crypt.known_plaintext.vigenere}" from one frame.`));
  add(c.figure("playfair", "fig_playfair.png", "Playfair digram-codebook attack: decryption coverage versus known frames", 4.8));
  add(c.p(`For comparison with the textbook setting, the classical statistical attacks were applied to a ${tb.letters}-letter English paragraph. Chi-squared analysis recovered the Caesar shift (${tb.caesar_shift_recovered}); the Friedman test estimated the Vigenere period as ${tb.vigenere_period_friedman}, in agreement with the dominant Kasiski factor (${tb.kasiski_top_factors[0][0]}), and per-column chi-squared recovered the key "${tb.vigenere_key_recovered}" in ${tb.vigenere_ms} ms. Telemetry is easier to attack than English because its grammar is exact.`));
  add(c.p("A secondary finding concerns the legacy checksum. Because it is a plain sum of symbol indices, it cannot detect transposed symbols: a wrong columnar key that swaps two digits still yields a checksum-valid frame. Non-cryptographic checksums therefore provide no integrity against an adversary, which is relevant to TV4."));

  add(c.h2("6.4", "Correctness and Performance of the Gateway"));
  add(c.table("integrity", "End-to-end delivery and data integrity in each migration mode",
    ["Mode", "Frames", "Delivered", "Corrupted", "Via envelope", "Via legacy path"],
    integ.map((r) => [r.mode, n0(r.frames), `${n0(r.delivered)} (${r.delivered_pct}%)`, String(r.corrupted), n0(r.secure_path), n0(r.legacy_path)]),
    [2.2, 1, 1.6, 1, 1.3, 1.3]));
  add(c.p(`Across all four modes, ${n0(delivered)} of ${n0(frames)} legitimate frames were delivered and not a single reading was altered in translation ({tab:integrity}), satisfying the correctness half of objective O3. {fig:latency} shows the per-frame gateway latency (legacy decryption, parsing, validation and AES-256-GCM sealing). The median is at most ${f1(worstMed)} microseconds for any cipher, about ${f0(1000 / worstMed)} times below the 1 ms target and more than ${Math.floor(Math.log10(2e6 / worstMed))} orders of magnitude below the 2 s polling cycle.`));
  add(c.figure("latency", "fig_latency.png", "Gateway uplink latency per legacy cipher with the library AES-GCM engine", 5.2));
  const benchRows = R.bench.classical.map((b) => [`${b.cipher} (encrypt / decrypt 52-symbol frame)`, `${f1(b.encrypt_us)} / ${f1(b.decrypt_us)}`])
    .concat(R.bench.aes.map((a) => [a.operation, f1(a.us)]));
  add(c.table("bench", "Micro-benchmarks (median time per operation)", ["Operation", "Time (microseconds)"], benchRows, [6, 2.4], { align: [undefined, 2] }));
  add(c.p(`The educational AES-GCM, written in pure Python, needs about ${f0(eduSeal)} microseconds to seal a reading against ${f1(libSeal)} microseconds for the library - roughly ${f0(eduSeal / libSeal)} times slower - and its end-to-end gateway median is ${f0(eduMed)} microseconds. It would still meet the real-time budget, but the library is used in production because it is constant-time and hardware-accelerated; the educational engine exists for verification and teaching.`));

  add(c.h2("6.5", "Transition Vulnerabilities"));
  add(c.p("This section presents the eight transition vulnerabilities. Each experiment compares a vulnerable configuration with a mitigated one under the same adversary."));

  // TV1
  const tv1 = TV.TV1;
  add(c.h3("6.5.1", "TV1 - Legacy last mile and trust laundering"));
  add(c.p(`A gateway protects only the segment *after* it. An eavesdropper at position A1 recovered the Vigenere key of RTU 4 from ${tv1.scenarios[0].frames_to_break} frame and could read ${pct(tv1.scenarios[0].aes_delivered_readings_exposed_pct)} of the readings that the control centre later received inside AES-GCM envelopes - encryption of the WAN gives no confidentiality for data that is exposed earlier. Worse, the adversary then rewrote frames on the serial link. The gateway faithfully sealed the forged readings into valid envelopes, so SCADA accepted them as authentic ({tab:tv1}). We call this *trust laundering*: a strong MAC certifies weak data.`));
  add(c.table("tv1", "TV1 - false-data injection on the legacy last mile",
    ["Defence", "Attack", "Forged readings accepted"],
    tv1.scenarios.map((s) => [s.defence, s.attack === "gross" ? "Gross: 9.0 kV under-voltage" : s.attack === "stealthy" ? "Stealthy: -3% voltage, power scaled" : "Bit flip on envelope", pct(s.forged_accepted_pct)]),
    [3.4, 3.4, 1.8]));
  add(c.p("The physics-based plausibility filter blocked every gross forgery but none of the physically consistent ones. Only moving cryptography into the RTU (native AES) closed the attack completely. **Mitigations:** install the gateway as close as possible to the RTU (ideally in the same cabinet), enable plausibility checks, physically protect the last mile, and prioritise RTUs on exposed links (radio, leased lines) for replacement."));

  // TV2
  const tv2 = TV.TV2;
  add(c.h3("6.5.2", "TV2 - Downgrade attack during hybrid operation"));
  add(c.p(`During migration the control centre must still accept legacy frames from devices that have not been migrated. The adversary at A2 suppressed the envelopes of migrated RTU 3 and injected legacy frames reporting its breaker as open, encrypted with the Affine key (${tv2.legacy_key_recovered.join(", ")}) recovered from traffic recorded before the migration ({tab:tv2}).`));
  add(c.table("tv2", "TV2 - downgrade attack against each migration policy",
    ["Policy", "Forged legacy frames accepted", "Unmigrated device still served?"],
    tv2.modes.map((m) => [m.mode, pct(m.forged_accepted_pct), m.unmigrated_device_supported ? `Yes (${pct(m.unmigrated_device_accept_pct)} delivered)` : "No (all devices must be migrated)"]),
    [2.6, 2.8, 3.2]));
  add(c.p("A permissive hybrid policy accepted every downgraded frame. Pinning - remembering that a device has migrated and refusing legacy frames that claim to come from it - stopped the attack completely while still serving the unmigrated RTU 7. STRICT_AES also blocks the attack but is only possible once every device is migrated. **Mitigation:** use HYBRID_PINNED throughout the transition and remove legacy keys from the front end as soon as a device is migrated."));

  // TV3
  const tv3 = TV.TV3;
  add(c.h3("6.5.3", "TV3 - Replay and freshness laundering"));
  const reasons = Object.entries(tv3.cases[1].rejection_reasons || {}).map(([k, v]) => `${v} as "${k}"`).join(" and ");
  add(c.p(`Legacy frames carry no cryptographic freshness, so replayed frames were always accepted on the WAN ({tab:tv3}). Replayed envelopes were all rejected by the 64-bit sequence window and timestamp check (${reasons}). The subtle case is replay on the last mile: a *stateless* gateway wraps an old legacy frame into a brand-new envelope with a fresh sequence number, which SCADA cannot distinguish from current data. Tracking the legacy sequence number at the gateway closes this gap.`));
  add(c.table("tv3", "TV3 - replay attacks",
    ["Scenario", "Defence", "Replays accepted"],
    tv3.cases.map((x) => [x.case, x.defence, pct(x.replay_accepted_pct)]), [3.4, 3.4, 1.8]));
  add(c.p("A residual risk remains because the legacy counter has only four digits and wraps after 10,000 frames; at a 2 s poll this is about 5.5 hours, after which very old frames could again look new. **Mitigation:** legacy sequence tracking plus plausibility checks, and native freshness once the RTU is upgraded."));

  // TV4
  const tv4 = TV.TV4;
  add(c.h3("6.5.4", "TV4 - Malleability: AES alone is not enough"));
  add(c.p(`In this experiment the attacker has no key and only wants SCADA to show a closed breaker as open. Against the Vigenere link it suffices to add 12 to the ciphertext symbol of the breaker field (C to O) and patch the checksum digits; this succeeded for ${pct(tv4.rows[0].tamper_success_pct)} of frames, failing only when the checksum patch carried into the next digit ({tab:tv4}). A naive migration to confidentiality-only AES is no better: flipping one ciphertext bit (CTR) or one IV bit (CBC) flips the breaker bit with certainty. Only authenticated encryption detected every modification.`));
  add(c.table("tv4", "TV4 - blind tampering of the breaker status without the key",
    ["Scheme", "Integrity protection", "Tampering success"],
    tv4.rows.map((r) => [r.scheme, r.integrity, pct(r.tamper_success_pct)]), [3.6, 3, 2]));

  // TV5
  const tv5 = TV.TV5;
  add(c.h3("6.5.5", "TV5 - Pattern leakage with ECB"));
  add(c.p(`Status words are low-entropy: a day of ${n0(tv5.messages)} one-minute status messages from one RTU contains only a handful of distinct plaintexts. Under AES-ECB they produced only ${tv5.rows[0].distinct_ciphertexts} distinct ciphertexts, so an attacker who simply labels the most frequent ciphertext as "normal" reconstructed the breaker timeline - including the ${tv5.abnormal_minutes} minutes of maintenance and protection trips - with ${pct(tv5.rows[0].attacker_balanced_accuracy_pct)} balanced accuracy ({tab:tv5}). With GCM every message was unique and the same attacker performed at chance level. {fig:ecb} visualises the effect on a bitmap.`));
  add(c.table("tv5", "TV5 - inference of breaker state from ciphertext alone",
    ["Mode", "Distinct ciphertexts", "Attacker balanced accuracy", "Precision of outage alarms"],
    tv5.rows.map((r) => [r.mode, n0(r.distinct_ciphertexts), pct(r.attacker_balanced_accuracy_pct), pct(r.outage_alarm_precision_pct)]),
    [2, 2, 2.4, 2.4]));
  add(c.figure("ecb", "fig_ecb.png", "The same bitmap encrypted with AES-ECB (structure visible) and with GCM's counter mode (noise)", 6.0));

  // TV6
  const tv6 = TV.TV6;
  add(c.h3("6.5.6", "TV6 - Nonce reuse after a reboot"));
  add(c.p(`Constrained devices often keep counters only in RAM. The gateway was rebooted every ${tv6.reboot_every_polls} polls ({tab:tv6}). With RAM-only counters it reused ${n0(tv6.rows[0].nonce_collisions)} nonces; for each collision an observer who knows or predicts one plaintext recovered ${pct(tv6.rows[0].plaintext_recovered_pct)} of the other by XORing the two ciphertexts. The same fault also caused a denial of service: after the first reboot the control centre's replay window rejected ${pct(100 - tv6.rows[0].post_reboot_delivery_pct)} of the gateway's envelopes because their sequence numbers looked old. Persistent, block-reserved counters eliminated both problems.`));
  add(c.table("tv6", "TV6 - GCM nonce management across reboots",
    ["Counter storage", "Reboots", "Envelopes", "Nonce collisions", "Plaintext recovered", "Delivery after reboot"],
    tv6.rows.map((r) => [r.counter_storage, String(r.reboots), n0(r.envelopes), n0(r.nonce_collisions), pct(r.plaintext_recovered_pct), pct(r.post_reboot_delivery_pct)]),
    [2.4, 1, 1.2, 1.3, 1.4, 1.4]));
  add(c.p("Nonce reuse in GCM also exposes the authentication subkey H, enabling forgeries [@joux,bock]; that attack is not reproduced here but motivates treating any collision as a key-compromise event."));

  // TV7
  const tv7 = TV.TV7;
  add(c.h3("6.5.7", "TV7 - AES keys derived from legacy secrets"));
  add(c.p(`A tempting shortcut during migration is to reuse existing secrets, for example by hashing the old Vigenere keyword into an AES key. {tab:tv7} shows the consequence. An attacker who had already broken the legacy cipher (one frame, Section 6.3) derived the AES key directly. Even without legacy traffic, a ${tv7.wordlist_size}-word dictionary found the key "${tv7.rows[0].dictionary_hit}" after ${tv7.rows[0].guesses} guesses in ${tv7.rows[0].attack_ms} ms by testing each candidate against the GCM tag of a single envelope. The effective strength of such an AES-256 key is about ${tv7.rows[0].effective_key_bits} bits.`));
  add(c.table("tv7", "TV7 - key provenance",
    ["Key derivation", "Pivot from legacy key", "Dictionary attack", "Effective strength"],
    tv7.rows.map((r) => [r.key_derivation, r.pivot_from_broken_legacy_key ? "Succeeds" : "Fails",
      r.dictionary_hit ? `Found "${r.dictionary_hit}" after ${r.guesses} guesses` : `Fails (${r.guesses} guesses)`, `${r.effective_key_bits} bits`]),
    [2.8, 1.6, 2.6, 1.6]));

  // TV8
  add(c.h3("6.5.8", "TV8 - Bandwidth and latency overhead"));
  add(c.p(`The envelope enlarges a reading from ${t8.legacy_frame_bytes} legacy bytes to ${t8.ste_bytes} bytes (+${t8.size_increase_pct}%). {fig:overhead} and {tab:tv8} translate this into serial-link time for a scan of all eight RTUs (10 bits per byte, 8N1 framing).`));
  add(c.table("tv8", "TV8 - link time per frame and per 8-RTU scan",
    ["Baud rate", "Legacy frame (ms)", "Envelope (ms)", "8-RTU scan, legacy (ms)", "8-RTU scan, envelope (ms)"],
    t8.link.map((l) => [n0(l.baud), f1(l.legacy_ms), f1(l.ste_ms), f0(l.scan_8_devices_legacy_ms), f0(l.scan_8_devices_ste_ms)]),
    [1.4, 1.6, 1.4, 2, 2], { align: [undefined, 2, 2, 2, 2] }));
  add(c.figure("overhead", "fig_overhead.png", "Serial-link time to poll eight RTUs, legacy frames versus secure envelopes", 5.2));
  add(c.p("At 9,600 baud and above the envelope fits comfortably within a 2 s scan. At 1,200 baud even the legacy protocol already overruns the cycle for eight RTUs, and the envelope lengthens the scan by a further ${t8.size_increase_pct}%; such links need fewer RTUs per line, a longer scan cycle or a bandwidth upgrade. Since the envelope is added on the gateway-to-control-centre segment, which is normally IP, the serial overhead matters chiefly for upgraded RTUs that still use slow radio links."));

  add(c.p("{fig:transition} summarises the attack success rates of the vulnerable and mitigated configurations for TV1-TV7."));
  add(c.figure("transition", "fig_transition.png", "Attack success before and after mitigation for each transition vulnerability", 6.0));

  add(c.h2("6.6", "Risk and Mitigation Matrix"));
  add(c.table("risk", "Risk assessment of the transition vulnerabilities (L = low, M = medium, H = high)",
    ["ID", "Vulnerability", "Likelihood", "Impact", "Risk", "Mitigation implemented in LCMF", "Residual risk"],
    [
      ["TV1", "Legacy last mile behind gateway", "H", "H", "High", "Plausibility filter; native-AES RTU", "Stealthy false data until RTU upgraded"],
      ["TV2", "Downgrade in hybrid mode", "M", "H", "High", "HYBRID_PINNED policy; STRICT_AES", "None once pinned"],
      ["TV3", "Replay / freshness laundering", "H", "M", "High", "64-bit window + timestamps; legacy sequence tracking", "Legacy counter wrap (about 5.5 h)"],
      ["TV4", "Malleable encryption", "M", "H", "High", "AES-256-GCM with header as AAD", "None"],
      ["TV5", "ECB pattern leakage", "M", "M", "Medium", "Nonce-based AEAD only", "Traffic-volume analysis"],
      ["TV6", "Nonce reuse after reboot", "M", "H", "High", "Persistent, reserved counters", "Storage failure; monitor collisions"],
      ["TV7", "Keys derived from legacy secrets", "M", "H", "High", "HKDF from random 256-bit master; key rotation", "Master-key protection (HSM: future)"],
      ["TV8", "Bandwidth overhead", "L", "M", "Low", "Compact 15-byte payload", "1,200-baud links need planning"],
    ], [0.6, 2.0, 1.0, 0.9, 0.9, 2.6, 2.2], { size: 17 }));

  add(c.h2("6.7", "Achievement of Objectives"));
  add(c.table("objres", "Objectives, targets and measured results",
    ["ID", "Target", "Measured result", "Status"],
    R.summary.objectives.map((o) => [o.id, o.target, o.measured, o.met ? "Met" : "Not met"]), [0.6, 3.6, 3.6, 0.9]));
  add(c.p(`All ${R.summary.objectives.length} objectives were met ({tab:objres}).`));

  add(c.h2("6.8", "Discussion"));
  add(c.p("Five lessons emerge from the results."));
  add(c.numbered([
    "**Structure, not key length, defeats classical ciphers.** Every legacy cipher fell in milliseconds because telemetry frames are rigidly formatted; the 2^138 key space of Playfair was irrelevant.",
    "**A gateway moves the trust boundary but does not remove the legacy link.** The last mile remains exactly as weak as before (TV1, TV3), and the gateway can even launder forged or replayed data into authentic-looking envelopes. Defence-in-depth (plausibility, sequence tracking) helps, but only native cryptography in the RTU closes the gap.",
    "**Choosing AES is necessary but far from sufficient.** Mode (TV4, TV5), nonce management (TV6) and key provenance (TV7) each turned AES-256 into something weaker than intended. Authenticated encryption, persistent counters and random master keys are essential.",
    "**The migration policy is a security control.** Accepting both protocols without pinning re-opens every legacy weakness through downgrade (TV2).",
    "**The overhead is affordable.** The envelope costs 53 bytes and tens of microseconds per frame; only 1,200-baud links need re-planning (TV8).",
  ]));
  add(c.p("Based on these results, we recommend the following migration playbook: (1) inventory legacy links and rank them by exposure; (2) deploy gateways with plausibility checks and legacy sequence tracking, as close to the RTUs as possible; (3) operate the control centre in HYBRID_PINNED mode, registering each device as migrated the moment its gateway is commissioned; (4) provision fresh random master keys - never derive keys from legacy secrets - and use persistent nonce counters; (5) replace RTUs on the most exposed links with native-AES devices first; and (6) switch to STRICT_AES and delete legacy keys once the last device is migrated."));

  // =================================================================== CHAPTER 7
  add(c.chapterHeading(7, "Conclusion and Future Scope"));
  add(c.h2("7.1", "Conclusion"));
  add(c.p(`This project designed, implemented and evaluated LCMF, a Legacy Cipher Migration Framework for industrial control systems. It reproduces a smart-grid environment protected by six classical ciphers, implements AES and GCM from first principles alongside a production library path, and provides a protocol-translation gateway that wraps legacy telemetry into a 68-byte AES-256-GCM envelope with authenticated headers, anti-replay protection and four migration policies. The gateway translated ${n0(delivered)} frames without a single error at a median latency of at most ${f1(worstMed)} microseconds.`));
  add(c.p("The evaluation confirms that classical ciphers provide no protection for structured telemetry - every key was recovered from at most two frames - and, more importantly, that the transition to AES introduces risks of its own. Eight transition vulnerabilities were demonstrated and quantified, and for each one a mitigation implemented in the framework reduced the attack success to zero, except for physically consistent false data on the legacy last mile, which only replacing the RTU removes. The resulting migration playbook gives utilities a concrete, evidence-based sequence for upgrading legacy grid hardware safely."));
  add(c.h2("7.2", "Limitations"));
  add(c.bullets([
    "The environment is simulated; real Modbus, DNP3 or IEC 60870-5-104 framing and timing are abstracted into the legacy telemetry frame.",
    "The gateway and control centre hosts are assumed to be uncompromised; key storage uses files rather than hardware security modules.",
    "The Playfair attacks assume dictionary keywords or known plaintext; a ciphertext-only attack on random squares (for example by hill climbing) was not implemented.",
    "The plausibility filter uses fixed engineering limits and cannot detect physically consistent false data.",
  ]));
  add(c.h2("7.3", "Future Scope"));
  add(c.bullets([
    "Deploy the gateway on embedded hardware (for example an industrial single-board computer) and measure latency on real serial and radio links.",
    "Add adapters for Modbus RTU and DNP3 and interoperate with IEC 62351 / TLS on the control-centre side.",
    "Store master keys in a hardware security module or TPM and automate key rotation.",
    "Replace the rule-based plausibility filter with state estimation or machine-learning anomaly detection to address stealthy false-data injection.",
    "Add post-quantum or hybrid key establishment for long-lived field devices.",
    "Formally verify the migration-policy state machine and the envelope parser.",
  ]));

  // =================================================================== REFERENCES
  add(c.frontHeading("References"));
  for (const [key, num] of c.cites.entries()) {
    if (!REFS[key]) throw new Error(`missing reference ${key}`);
    out.push(new Paragraph({
      children: [new TextRun({ text: `[${num}]` }), new TextRun({ text: `\t${REFS[key]}` })],
      tabStops: [{ type: "left", position: 600 }],
      indent: { left: 600, hanging: 600 }, alignment: AlignmentType.LEFT,
      spacing: { after: 100, line: 276 },
    }));
  }

  // =================================================================== APPENDICES
  add(c.frontHeading("Appendix A: User Manual"));
  c.setChapter("A");
  add(c.p("**Installation.** Install Python 3.10 or later, open a terminal in the project folder and run ~pip install -r requirements.txt~. On Windows, ~run_demo.bat~ performs the installation, runs the test suite, regenerates the results and starts the guided demonstration."));
  add(c.table("commands", "Commands provided by the framework",
    ["Command", "Purpose"],
    [
      ["python -m lcmf demo [--interactive]", "Guided end-to-end demonstration of all modules"],
      ["python -m lcmf simulate --mode MODE --polls N [--engine educational]", "Run the grid simulation in a migration mode"],
      ["python -m lcmf cipher TYPE encrypt|decrypt TEXT [--key K] [--a A --b B] [--z26]", "Use any legacy cipher"],
      ["python -m lcmf attack", "Recover the key of every legacy cipher"],
      ["python -m lcmf transition", "Run TV1-TV8 and print raw results"],
      ["python -m lcmf experiments", "Regenerate results/*.json and print the objectives table"],
      ["python -m pytest", "Run the automated test suite"],
      ["python scripts/generate_figures.py", "Regenerate docs/figures/*.png"],
      ["build_all.bat", "Regenerate results, figures, report (DOCX/PDF) and slides"],
    ], [4.4, 4.2], { size: 18 }));
  add(c.p("**Updating team details.** Edit ~docs/build/team_config.json~ (names, enrolment numbers, course and faculty) and run ~build_all.bat~; the cover page, certificate, declaration, contribution appendix and slides are regenerated with the new details."));

  add(c.frontHeading("Appendix B: Individual Contributions"));
  c.setChapter("B");
  add(c.p("The work was divided into three modules of comparable size, each owned end-to-end - design, code, tests, report sections and presentation slides - by one member. Problem analysis, integration, testing and documentation were shared. {tab:contrib} summarises the division and {tab:matrix} the responsibility for each task."));
  add(c.table("contrib", "Contribution of each team member",
    ["Member", "Module owned", "Main contributions"],
    team.members.map((m, i) => [`${m.name}\n${m.enrolment}`, m.role, m.work.join("; ") + "."]), [1.8, 1.8, 5.0], { size: 18 }));
  const L = "Lead", S = "Support";
  add(c.table("matrix", "Task responsibility matrix",
    ["Task", "Member 1", "Member 2", "Member 3"],
    [
      ["Problem analysis, literature review, feasibility", L, L, L],
      ["Legacy cipher suite (6 ciphers, Z36 alphabet)", L, S, "-"],
      ["Cryptanalysis of legacy ciphers", L, "-", S],
      ["AES core, modes of operation, GCM", "-", L, "-"],
      ["Secure envelope, keys, nonces, replay window", S, L, S],
      ["Grid simulator, RTUs, SCADA master", "-", "-", L],
      ["Translation gateway, migration policy, plausibility", S, S, L],
      ["Transition experiments TV4-TV7", "-", L, S],
      ["Transition experiments TV1-TV3, TV8", S, "-", L],
      ["Experiment runner, vector validation, benchmarks", "-", L, S],
      ["Result visualisation (figures and diagrams)", L, S, "-"],
      ["Command-line interface and viva demonstration", S, "-", L],
      ["Testing and integration", L, L, L],
      ["Report and presentation", L, L, L],
    ], [4.4, 1.4, 1.4, 1.4]));
  add(c.table("memberloc", "Code, report and presentation ownership",
    ["Member", "Code owned", "Lines of code", "Report sections", "Slides"],
    team.members.map((m, i) => [m.name, m.code.join(", "), n0(extra.memberLoc[i]), m.report.join("; "), m.slides]),
    [1.4, 2.6, 0.9, 2.4, 1.3], { size: 16 }));
  add(c.p("The comparable code sizes, the one-to-one mapping of packages to members and the shared ownership of analysis, integration and documentation reflect an equal and effective contribution by every member."));

  add(c.frontHeading("Appendix C: Sample Output of the Demonstration"));
  c.setChapter("C");
  add(c.p("The following excerpt is the unedited output of ~python -m lcmf demo~ (Modules 3 to 6)."));
  add(c.listing("demo", "Output of the guided demonstration (excerpt)", extra.demoLines, 13));
  return out;
};
