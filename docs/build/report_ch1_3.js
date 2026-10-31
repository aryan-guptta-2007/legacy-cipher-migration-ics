// Chapters 1-3: Introduction, Literature Review, Problem Analysis & Feasibility.
"use strict";

module.exports = function chapters1to3(c, R) {
  const out = [];
  const add = (...xs) => xs.forEach((x) => (Array.isArray(x) ? out.push(...x) : out.push(x)));
  const TV = Object.fromEntries(R.trans.map((t) => [t.id, t]));
  const obj = R.summary.objectives;
  const t8 = TV.TV8;
  const link9600 = t8.link.find((l) => l.baud === 9600);
  const worstMed = Math.max(...Object.values(t8.gateway_latency.library).map((v) => v.median_us));

  // =================================================================== CHAPTER 1
  add(c.chapterHeading(1, "Introduction"));
  add(c.h2("1.1", "Background"));
  add(c.p("Electric power grids are supervised and controlled by Industrial Control Systems (ICS). In a typical utility, a Supervisory Control and Data Acquisition (SCADA) master station in the control centre periodically polls Remote Terminal Units (RTUs) installed in substations. Each RTU reports telemetry - bus voltage, feeder current, system frequency, active power and the status of circuit breakers - and executes control commands such as opening or closing a breaker [@nist82,gungor]. The integrity and timeliness of this exchange is what allows operators to balance generation with demand, isolate faults and restore supply."));
  add(c.p("Much of this communication infrastructure was designed decades ago, when the control network was assumed to be physically isolated. Links were built from serial lines, leased telephone circuits and licensed radio running at 1,200 to 19,200 baud. Where any protection existed it was usually a lightweight substitution or transposition scheme - effectively a classical cipher - chosen because it was cheap to implement in early microcontrollers, and much of the security rested on the obscurity of proprietary formats [@igure,knapp]. The smart-grid programme has since connected these islands to IP networks, enterprise systems and the Internet, removing the isolation that the original designs relied on [@nistir7628,wang]."));
  add(c.p("Field equipment in a grid has a service life of fifteen to thirty years, and replacing every RTU in a utility is expensive and operationally disruptive [@nist82]. Utilities therefore modernise gradually, often by inserting *bump-in-the-wire* devices or protocol gateways in front of legacy equipment [@aga12,ieee1711]. For years, sometimes decades, legacy and modern cryptography coexist in the same network. This project studies exactly that coexistence."));

  add(c.h2("1.2", "Motivation"));
  add(c.p("Attacks on power systems are no longer hypothetical. In December 2015, attackers who had gained access to the SCADA environments of three Ukrainian distribution companies remotely opened breakers and left approximately 225,000 customers without power [@lee2016]. Stuxnet demonstrated that manipulated process data and commands can cause physical damage while operators see normal values [@langner], and false-data-injection attacks can mislead the state estimators that grid operators depend on [@liu,mo]."));
  add(c.p("Classical ciphers offer no meaningful defence against such adversaries: their key spaces are tiny or their structure leaks the statistics of the plaintext [@stallings,forouzan,kahn]. Replacing them with the Advanced Encryption Standard (AES) is clearly necessary. However, for a utility the practical question is not whether AES is stronger than a Caesar cipher - it obviously is - but **what can go wrong while old and new systems coexist, and how a migration can be carried out safely**. That question motivates this project."));

  add(c.h2("1.3", "Problem Statement"));
  add(c.p("*Design and implement a protocol-translation gateway that wraps legacy, unencrypted or classically encrypted smart-grid telemetry into AES-encrypted payloads, and systematically identify, demonstrate and quantify the security vulnerabilities that arise during the transition from legacy to modern cryptography, together with measured mitigations.*"));
  add(c.p("The problem has three coupled parts: (i) faithfully reproducing the legacy environment - its ciphers, frame formats and grid behaviour - so that conclusions are meaningful; (ii) building a gateway that is correct, fast enough for real-time operation and cryptographically sound; and (iii) evaluating the *transition* itself, not just the end state, by attacking every intermediate configuration that a real migration passes through."));

  add(c.h2("1.4", "Objectives"));
  add(c.p("Each objective is stated with a measurable acceptance target. {tab:objectives} lists them; Chapter 6 reports the measured value for each one."));
  add(c.table("objectives", "Measurable objectives of the project",
    ["ID", "Objective", "Acceptance target"],
    obj.map((o) => [o.id, o.objective, o.target]), [0.6, 4, 4.6]));

  add(c.h2("1.5", "Scope and Limitations"));
  add(c.p("**In scope.** A software framework, named LCMF (Legacy Cipher Migration Framework), comprising: six legacy ciphers (Caesar, Additive, Affine, Vigenere, Playfair and keyed Columnar transposition) plus unencrypted links; AES-128/192/256 and the ECB, CBC, CTR and GCM modes implemented from first principles; a production AES-256-GCM path using an audited library; a simulated 11 kV distribution network with eight feeders, legacy RTUs, an upgraded RTU and a SCADA master; a bidirectional protocol-translation gateway; four migration policies; and a reproducible experiment suite covering cryptanalysis of the legacy ciphers and eight transition vulnerabilities."));
  add(c.p("**Out of scope.** Physical hardware; byte-exact implementations of Modbus, DNP3 or IEC 60870-5-104 (their telemetry is abstracted into a representative fixed-width legacy frame); compromise of the gateway or SCADA host; side-channel attacks; and public-key infrastructure. All attacks are executed only against the project's own simulator."));

  add(c.h2("1.6", "Contributions"));
  add(c.bullets([
    "A modular, tested implementation of the classical cipher suite over a 36-symbol telemetry alphabet, including a 6x6 Playfair variant that enciphers digits losslessly.",
    "A from-scratch AES and GCM implementation that is bit-identical to the cryptography library on all published test vectors and on 500 random cases.",
    "A protocol-translation gateway and a 68-byte Secure Telemetry Envelope (STE) whose 37-byte header is authenticated as associated data.",
    "Practical key-recovery attacks that break every legacy cipher from at most two captured frames by exploiting the public frame grammar.",
    "A catalogue of eight transition vulnerabilities (TV1-TV8), each demonstrated in the simulator, quantified, and paired with a mitigation whose effect is measured.",
    "A fully reproducible pipeline: one command regenerates all results, figures, this report and the presentation.",
  ]));

  add(c.h2("1.7", "Organisation of the Report"));
  add(c.p("Chapter 2 reviews classical and modern cryptography, ICS protocols and existing approaches to securing legacy SCADA links. Chapter 3 analyses the problem domain, defines the threat model and requirements, and establishes feasibility. Chapter 4 presents the design and methodology, and Chapter 5 the implementation together with a design-to-implementation traceability matrix. Chapter 6 reports and discusses the results, and Chapter 7 concludes with limitations and future scope. Appendix A is a user manual, Appendix B documents the contribution of each team member, and Appendix C reproduces sample output of the demonstration."));

  // =================================================================== CHAPTER 2
  add(c.chapterHeading(2, "Literature Review"));
  add(c.p("This chapter reviews the cryptographic primitives that the project migrates from and to, the security extensions available for ICS protocols, and existing systems for retrofitting legacy SCADA links. It closes by identifying the research gap addressed in this work."));

  add(c.h2("2.1", "Foundations of Classical Cryptography"));
  add(c.p("A cipher is a pair of functions E and D such that D_K(E_K(P)) = P for every key K. Kerckhoffs's principle states that a system must remain secure even if everything about it except the key is public [@kerckhoffs]. Classical ciphers fall into two families: *substitution* ciphers replace symbols, and *transposition* ciphers permute their positions. Substitution ciphers are *monoalphabetic* when one fixed mapping is used for the whole message and *polyalphabetic* when the mapping changes with position [@stallings,forouzan]. Throughout this report a symbol is identified with its index in an alphabet of m symbols (m = 26 for A-Z, m = 36 for the telemetry alphabet A-Z0-9), and arithmetic is modulo m."));

  add(c.h2("2.2", "Monoalphabetic Ciphers"));
  add(c.h3("2.2.1", "Additive (shift) and Caesar ciphers"));
  add(c.p("The additive cipher adds a secret key k to each symbol:"));
  add(c.equation("additive", "C = (P + k) mod m,     P = (C − k) mod m"));
  add(c.p("The Caesar cipher is the historical special case k = 3 [@kahn]. Because the key is fixed into the algorithm, Caesar has no secret once the method is known (key space 1); the general additive cipher has only m keys and is broken by trying all of them."));
  add(c.h3("2.2.2", "Affine cipher"));
  add(c.p("The affine cipher combines multiplication and addition:"));
  add(c.equation("affine", "C = (a·P + b) mod m,     P = a⁻¹(C − b) mod m,     gcd(a, m) = 1"));
  add(c.p("The multiplier must be invertible modulo m, so a ranges over the φ(m) units of Z_m. For m = 26 and m = 36 alike, φ(m) = 12, giving 12 × 26 = 312 and 12 × 36 = 432 keys respectively [@forouzan]. Two known plaintext-ciphertext pairs with an invertible difference determine the key by solving a pair of linear congruences."));
  add(c.h3("2.2.3", "Cryptanalysis of monoalphabetic ciphers"));
  add(c.p("Since each plaintext symbol always maps to the same ciphertext symbol, the frequency profile of the plaintext is merely relabelled. Frequency analysis compares observed counts O_i with expected counts E_i using the chi-squared statistic, and the shift or key that minimises it is selected [@sinkov]:"));
  add(c.equation("chi", "χ² = Σ (Oᵢ − Eᵢ)² / Eᵢ"));

  add(c.h2("2.3", "Polyalphabetic Ciphers"));
  add(c.h3("2.3.1", "Vigenere cipher"));
  add(c.p("The Vigenere cipher applies a different shift to each position, cycling through a keyword of length L:"));
  add(c.equation("vig", "C_i = (P_i + K_(i mod L)) mod m"));
  add(c.p("Its key space m^L grows quickly with L, but the cipher is periodic. Kasiski observed that repeated plaintext fragments encrypted under the same key position produce repeated ciphertext fragments whose distances are multiples of L [@kasiski]. Friedman's index of coincidence (IoC) measures how far a text is from uniform; for English it is about 0.066, for uniformly random A-Z text 1/26 = 0.038 [@friedman]. Splitting the ciphertext into L columns with the correct period restores English-like IoC in every column, after which each column is a shift cipher solved by chi-squared."));
  add(c.equation("ioc", "IoC = Σ nᵢ(nᵢ − 1) / [N(N − 1)]"));
  add(c.h3("2.3.2", "Playfair cipher"));
  add(c.p("Playfair, a digraphic cipher, enciphers pairs of letters using a 5x5 square built from a keyword (I and J share a cell). For a pair in the same row each letter is replaced by its right neighbour; in the same column by the letter below; otherwise by the letters at the other corners of their rectangle. Doubled letters within a pair are separated by a filler, normally X [@stallings]. The nominal key space is 25! (about 2^84), but Playfair leaks digram statistics, maps reversed digrams to reversed ciphertext digrams, and yields readily to known-plaintext attacks [@kahn]."));

  add(c.h2("2.4", "Transposition Ciphers"));
  add(c.p("A keyed columnar transposition writes the plaintext row-wise into L columns and reads the columns out in the order defined by the alphabetical rank of the key letters. The key space is L!, and because only positions change, the symbol frequencies of the ciphertext are identical to those of the plaintext - a property that immediately reveals that a transposition has been used. Historically, such ciphers were attacked by anagramming and by exhaustive search over column orders [@sinkov]."));

  add(c.h2("2.5", "The Advanced Encryption Standard"));
  add(c.p("AES is the Rijndael block cipher standardised by NIST in FIPS 197 [@fips197,daemen]. It encrypts 128-bit blocks under 128-, 192- or 256-bit keys using 10, 12 or 14 rounds. The 16-byte state is arranged as a 4x4 matrix of bytes, and each round applies four transformations:"));
  add(c.bullets([
    "**SubBytes** - a non-linear byte substitution: the multiplicative inverse in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, followed by an affine transformation over GF(2).",
    "**ShiftRows** - row r of the state is rotated left by r bytes, mixing bytes across columns.",
    "**MixColumns** - each column is multiplied by a fixed polynomial matrix over GF(2^8), giving diffusion within a column.",
    "**AddRoundKey** - the state is XORed with a round key derived by the key-expansion routine (RotWord, SubWord and round constants).",
  ]));
  add(c.p("The final round omits MixColumns. After more than two decades of public analysis no practical attack on full AES is known, which is why it is the default choice for protecting critical-infrastructure data [@nist82,katz]."));

  add(c.h2("2.6", "Modes of Operation and Authenticated Encryption"));
  add(c.p("A block cipher on its own encrypts only one 16-byte block; a *mode of operation* defines how longer messages are processed [@sp80038a]:"));
  add(c.bullets([
    "**ECB** encrypts every block independently, so identical plaintext blocks give identical ciphertext blocks and patterns remain visible.",
    "**CBC** chains each block with the previous ciphertext block under a random IV. It provides confidentiality only; flipping IV bits flips the corresponding first-block plaintext bits, and padding errors can create decryption oracles [@vaudenay].",
    "**CTR** turns the cipher into a stream cipher. It is fast and parallel but perfectly malleable: flipping a ciphertext bit flips the same plaintext bit.",
    "**GCM** combines CTR encryption with GHASH, a polynomial hash over GF(2^128), to produce a 128-bit authentication tag over the ciphertext and any associated data (AAD) [@sp80038d,mcgrew].",
  ]));
  add(c.p("Modern guidance is to use authenticated encryption with associated data (AEAD) such as GCM rather than confidentiality-only modes [@katz,ferguson]. GCM has one critical requirement: a (key, nonce) pair must never repeat. A repeated nonce reveals the XOR of the two plaintexts and allows recovery of the authentication subkey H, which enables forgeries [@joux,bock]. Supporting mechanisms used in this project are the HMAC-based key derivation function HKDF [@rfc5869] and the sliding anti-replay window of IPsec ESP [@rfc4303]."));

  add(c.h2("2.7", "ICS Protocols and their Security Extensions"));
  add(c.p("Most field protocols in use today were designed without security. Modbus has no authentication at all; DNP3 (IEEE 1815) added Secure Authentication, a challenge-response HMAC mechanism that authenticates critical messages but does not encrypt them [@ieee1815,gilchrist]. IEC 62351 specifies TLS profiles for TCP-based protocols such as IEC 60870-5-104 and DNP3 over IP, and message authentication for IEC 61850 [@iec62351]. The Modbus/TCP Security specification wraps Modbus in mutually authenticated TLS [@modbussec]. IEC 62443 provides the overarching zone-and-conduit security architecture for industrial automation [@iec62443]. All of these, however, require the end devices to support the new protocol - which a legacy serial RTU cannot do."));

  add(c.h2("2.8", "Existing Approaches to Securing Legacy SCADA Links"));
  add(c.p("Because legacy devices cannot be upgraded in place, several retrofit approaches have been proposed. The American Gas Association's AGA-12 effort defined cryptographic protection for serial SCADA links using inline modules [@aga12] and evolved into IEEE 1711.2, the Secure SCADA Communications Protocol [@ieee1711]. Wright et al. studied how to provide such protection with low latency on slow links [@wright], and Tsang and Smith's YASIR proposed a low-latency, high-integrity retrofit specifically for legacy serial SCADA [@yasir]. Fovino et al. designed a secure variant of Modbus [@fovino]. In practice, utilities also tunnel traffic through IPsec VPNs between sites. {tab:existing} compares these approaches."));
  add(c.table("existing", "Comparison of existing approaches with the proposed framework",
    ["Approach", "Retrofits legacy RTU?", "Integrity / authenticity", "Main limitation"],
    [
      ["Classical cipher on the link (status quo)", "n/a", "None (checksum only)", "Broken from one or two frames (Section 6.3)"],
      ["DNP3 Secure Authentication [@ieee1815]", "No - needs firmware support", "HMAC challenge-response", "No confidentiality; device upgrade required"],
      ["IEC 62351 / Modbus-TCP Security (TLS) [@iec62351,modbussec]", "No - needs TCP/IP stack with TLS", "Yes (TLS)", "Not applicable to serial legacy devices"],
      ["AGA-12 / IEEE 1711.2 bump-in-the-wire [@aga12,ieee1711]", "Yes - inline modules", "Yes", "Module needed at both ends; transition risks not quantified"],
      ["YASIR [@yasir]", "Yes", "Yes, low latency", "Research prototype; focuses on the link, not the migration"],
      ["IPsec / VPN tunnel", "Partly - protects WAN only", "Yes", "Serial last mile and LAN stay in clear"],
      ["**LCMF (this work)**", "**Yes - translation gateway**", "**AES-256-GCM, header as AAD, anti-replay, policy pinning**", "**Last mile stays legacy until the RTU is replaced - quantified as TV1**"],
    ], [2.6, 1.8, 2.0, 2.8]));

  add(c.h2("2.9", "Research Gap"));
  add(c.p("The literature treats the problem in two separate ways: cryptographers analyse ciphers and modes in isolation, and ICS researchers design secure end-state protocols or individual retrofit devices. Comparatively little work quantifies the risks *during* the migration, when legacy and modern links coexist: the unprotected last mile behind a gateway, downgrade to legacy protocols, replays that are laundered into fresh secure messages, misuse of AES modes by integrators, nonce management on devices that reboot, and keys that are derived from old legacy secrets. This project closes that gap by building a migration framework and measuring each of these hazards experimentally."));

  // =================================================================== CHAPTER 3
  add(c.chapterHeading(3, "Problem Analysis, Requirements and Feasibility"));
  add(c.h2("3.1", "Problem Domain Analysis"));
  add(c.p("Grid telemetry differs from typical IT traffic in ways that drive every design decision of this project. {tab:domain} relates each property of the domain to its security consequence and to the resulting design implication."));
  add(c.table("domain", "Analysis of the problem domain",
    ["Domain property", "Security consequence", "Design implication"],
    [
      ["Small, fixed-format frames (tens of bytes)", "Fixed tags are *known plaintext*: 24 of 52 legacy symbols never change", "Assume Kerckhoffs-style attacker; legacy ciphers must be evaluated against known-plaintext attacks"],
      ["Periodic polling every few seconds", "Old frames are valid-looking and can be replayed", "Sequence numbers, replay window and timestamp freshness"],
      ["Slowly varying values, frequent repeats", "Low entropy - deterministic encryption leaks patterns", "Never use ECB; one nonce per message"],
      ["Low-bandwidth serial / radio links (1.2-19.2 kbaud)", "Cryptographic overhead costs scan time", "Compact binary payload; measure overhead per baud rate"],
      ["Physical consequences of commands", "Integrity matters more than confidentiality", "Authenticated encryption; plausibility checks"],
      ["15-30 year device lifetime", "Legacy and modern links coexist for years", "Explicit migration phases and policies; study the transition"],
      ["Availability is the top OT priority [@nist82]", "Security must not drop legitimate data", "Measure delivery rate and latency in every mode"],
    ], [2.6, 3.0, 3.2]));
  add(c.p("The analysis shows that the weakness of a classical cipher on a telemetry link is foremost an *integrity* problem: an attacker who recovers the key can inject commands or falsify measurements. Confidentiality matters as well - telemetry reveals load, outages and switching operations - but the most severe consequences are physical."));

  add(c.h2("3.2", "Threat Model"));
  add(c.p("Two adversary positions are considered, labelled A1 and A2 in the architecture of Chapter 4:"));
  add(c.bullets([
    "**A1 - legacy last mile.** The adversary taps the serial or radio link between an RTU and the gateway (for example at an unmanned substation or a radio repeater).",
    "**A2 - wide-area network.** The adversary is on the path between the gateway (or an upgraded RTU) and the control centre.",
  ]));
  add(c.p("At either position the adversary can eavesdrop, record, replay, inject, modify and drop frames. Following Kerckhoffs's principle, the adversary knows the cipher families, the frame format and the protocol behaviour, but not the keys, and is computationally bounded. Compromise of the gateway or SCADA hosts, physical tampering with RTUs, side channels and malicious insiders holding keys are outside the scope of this study. The assets to protect are, in order of priority, the integrity of commands, the integrity and freshness of telemetry, the availability of legitimate data, and the confidentiality of operational information."));

  add(c.h2("3.3", "Stakeholders and Use Cases"));
  add(c.table("usecases", "Principal use cases",
    ["ID", "Actor", "Use case", "Outcome"],
    [
      ["UC1", "Legacy / upgraded RTU", "Report telemetry each poll", "Reading stored in the SCADA historian"],
      ["UC2", "SCADA operator", "Open or close a breaker", "Command executed by the addressed RTU only"],
      ["UC3", "Utility engineer", "Move the network to the next migration phase", "Policy mode and device states updated"],
      ["UC4", "Security analyst", "Assess the strength of a legacy cipher", "Key-recovery result with effort metrics"],
      ["UC5", "Security analyst", "Run transition-vulnerability experiments", "results/*.json, figures and report regenerated"],
      ["UC6", "Key administrator", "Rotate keys", "New key generation used; old envelopes still verifiable"],
    ], [0.6, 1.8, 3.0, 3.2]));

  add(c.h2("3.4", "Functional Requirements"));
  add(c.table("fr", "Functional requirements",
    ["ID", "Requirement"],
    [
      ["FR1", "Encrypt and decrypt telemetry with Caesar, Additive, Affine, Vigenere, Playfair and Columnar ciphers, and support unencrypted legacy links."],
      ["FR2", "Encode and decode legacy telemetry and command frames, including checksum validation."],
      ["FR3", "Simulate eight 11 kV feeders producing physically consistent telemetry, with breaker control."],
      ["FR4", "Translate legacy uplink frames into AES-256-GCM Secure Telemetry Envelopes (gateway uplink)."],
      ["FR5", "Translate authenticated envelope commands into legacy command frames (gateway downlink)."],
      ["FR6", "Enforce one of four migration policies at the control centre."],
      ["FR7", "Reject replayed envelopes (sequence window and timestamp) and replayed legacy frames at the gateway."],
      ["FR8", "Check every decoded reading for physical plausibility before it is sealed."],
      ["FR9", "Recover the keys of the legacy ciphers from captured traffic for security assessment."],
      ["FR10", "Run the transition-vulnerability experiments TV1-TV8 reproducibly and store the results."],
      ["FR11", "Provide a command-line demonstration and regenerate results, figures, report and slides."],
    ], [0.7, 8]));

  add(c.h2("3.5", "Non-Functional Requirements"));
  add(c.table("nfr", "Non-functional requirements and their metrics",
    ["ID", "Quality", "Metric / target"],
    [
      ["NFR1", "Performance", "Median gateway latency per frame < 1 ms"],
      ["NFR2", "Bandwidth efficiency", "Envelope overhead <= 64 bytes; 8-RTU scan at 9,600 baud within a 2 s cycle"],
      ["NFR3", "Correctness", "0 corrupted readings end to end in every migration mode"],
      ["NFR4", "Security", "AES-256, 96-bit unique nonces, 128-bit tags, per-device per-direction keys"],
      ["NFR5", "Reproducibility", "All experiments seeded; one command regenerates every number"],
      ["NFR6", "Maintainability", "Modular packages with a common cipher interface; automated tests"],
      ["NFR7", "Portability", "Pure Python 3.10+ with one runtime dependency; Windows and Linux"],
    ], [0.8, 1.8, 6]));

  add(c.h2("3.6", "Feasibility Study"));
  add(c.h3("3.6.1", "Technical feasibility"));
  const sealUs = R.bench.aes.find((a) => a.operation.includes("seal 15 B (library)")).us;
  const sealOrders = Math.floor(Math.log10(2e6 / sealUs));
  add(c.p(`Every algorithm used is a published standard or textbook construction, and mature open-source implementations exist for the production path [@pyca]. A preliminary benchmark on the development laptop (${R.bench.environment.processor}) showed AES-256-GCM sealing a reading in about ${Number(sealUs).toFixed(1)} microseconds, more than ${sealOrders} orders of magnitude below the 2 s polling interval. The project is therefore technically feasible on commodity hardware; the final measured median gateway latency is ${worstMed.toFixed(1)} microseconds (Section 6.4).`));
  add(c.h3("3.6.2", "Economic feasibility"));
  add(c.p("The software stack is entirely open source (Python, the cryptography library, pytest and matplotlib), so there is no licensing cost. More importantly, the gateway approach keeps the existing RTUs in service: the capital cost of migration is limited to one gateway per substation instead of replacing every field device, and the same software runs on any industrial PC. Upgraded RTUs can be introduced later, as budgets allow, without changing the control centre."));
  add(c.h3("3.6.3", "Operational feasibility"));
  add(c.p(`The gateway is transparent to both sides: RTUs keep speaking their legacy protocol and the SCADA master receives the same readings. Migration proceeds in phases that can be rolled back, and the envelope overhead keeps an eight-RTU scan at 9,600 baud at ${link9600.scan_8_devices_ste_ms.toFixed(0)} ms, well inside a 2 s scan cycle (Section 6.5.8). Operators therefore need no retraining.`));
  add(c.h3("3.6.4", "Schedule feasibility"));
  add(c.p("The work was planned over twelve weeks with three parallel streams, one per team member, followed by joint integration, testing and documentation ({fig:gantt}). The plan was met; the streams were decoupled through the common interfaces defined in the design phase."));
  add(c.figure("gantt", "fig_gantt.png", "Project schedule (12 weeks) and allocation of work streams to team members", 5.9));
  add(c.h3("3.6.5", "Legal and ethical feasibility"));
  add(c.p("All experiments run against a self-contained simulator; no real utility system, network or data is accessed. The attack code is limited to breaking classical ciphers - long-documented textbook material - and to demonstrating misconfigurations of the project's own gateway, with every attack paired with a mitigation. The work therefore raises no legal or ethical concerns and its results serve defenders."));

  add(c.h2("3.7", "Hardware and Software Requirements"));
  add(c.table("hwsw", "Hardware and software requirements",
    ["Item", "Requirement", "Used in this project"],
    [
      ["Processor", "Any x86-64 / ARM64 CPU", R.bench.environment.processor],
      ["Memory", ">= 4 GB RAM", "8 GB+ laptop"],
      ["Operating system", "Windows 10/11 or Linux", R.bench.environment.platform],
      ["Language", "Python >= 3.10", `Python ${R.bench.environment.python}`],
      ["Cryptography library", "pyca/cryptography >= 41", `cryptography ${R.bench.environment.cryptography}`],
      ["Testing / figures", "pytest, matplotlib, numpy", "pytest, matplotlib, numpy"],
      ["Documentation build", "Node.js 18+, MS Word (PDF export)", "docx, pptxgenjs, Word"],
    ], [2, 3, 3.6]));
  return out;
};
