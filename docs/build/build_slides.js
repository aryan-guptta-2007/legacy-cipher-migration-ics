// Builds docs/Presentation.pptx from results/*.json, docs/figures and team_config.json.
//   node build_slides.js
"use strict";
const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");
const { applyTheme } = require("./apply_theme.js");

const ROOT = path.resolve(__dirname, "..", "..");
const FIG = (f) => path.join(ROOT, "docs", "figures", f);
const J = (f) => JSON.parse(fs.readFileSync(path.join(ROOT, "results", f), "utf8"));
const team = JSON.parse(fs.readFileSync(path.join(__dirname, "team_config.json"), "utf8"));
const R = { val: J("validation.json"), crypt: J("cryptanalysis.json"), trans: J("transition.json"),
  bench: J("benchmark.json"), integ: J("integrity.json"), summary: J("summary.json") };
const TV = Object.fromEntries(R.trans.map((t) => [t.id, t]));
const short = (i) => (team.members[i].name.startsWith("[") ? `Member ${i + 1}` : team.members[i].name);

const THEME = {
  name: "LCMF Grid", headFontFace: "Cambria", bodyFontFace: "Calibri",
  colors: { dk1: "14213D", lt1: "FFFFFF", dk2: "3B4A63", lt2: "EEF2F7", accent1: "2A78D6", accent2: "EB6834",
    accent3: "1BAF7A", accent4: "EDA100", accent5: "6250D6", accent6: "E34948", hlink: "2A78D6", folHlink: "6250D6" },
};
const HEX = { navy: "14213D", ink2: "3B4A63", muted: "6B7280", grid: "E5E7EB", blue: "2A78D6", orange: "EB6834", aqua: "1BAF7A",
  tintBlue: "E4EFFB", tintOrange: "FDE9E0", tintAqua: "DCF3EA", tintGray: "F3F4F6" };

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";            // 13.33 x 7.5 in
pres.title = team.project_title;
pres.author = team.members.map((m) => m.name).join(", ");
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;
const W = 13.333;

// ------------------------------------------------------------------ layouts
pres.defineSlideMaster({
  title: "LCMF_TITLE", background: { color: HEX.navy },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 1.5, w: 11.7, h: 1.9, fontSize: 40, bold: true,
      color: C.background1, valign: "bottom", align: "left" }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", x: 0.8, y: 3.55, w: 11.7, h: 1.1, fontSize: 18,
      color: "C9D6EA", valign: "top", align: "left" }, text: "" } },
  ],
});
pres.defineSlideMaster({
  title: "LCMF_SECTION", background: { color: HEX.navy },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 2.6, w: 11.7, h: 1.3, fontSize: 40, bold: true,
      color: C.background1, valign: "bottom", align: "left" }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", x: 0.8, y: 4.05, w: 11.7, h: 0.8, fontSize: 20,
      color: "C9D6EA", valign: "top", align: "left" }, text: "" } },
  ],
});
pres.defineSlideMaster({
  title: "LCMF_CONTENT", background: { color: "FFFFFF" }, margin: [0.5, 0.6, 0.6, 0.6],
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.3, w: 12.1, h: 0.85, fontSize: 30, bold: true,
      color: C.text1, valign: "middle", align: "left" }, text: "" } },
    { text: { text: "LCMF  |  Legacy Cipher Migration Framework for ICS", options: { x: 0.6, y: 7.02, w: 8, h: 0.3,
      fontSize: 10, color: C.text2, margin: 0 } } },
  ],
  slideNumber: { x: 12.2, y: 7.02, w: 0.5, h: 0.3, fontSize: 10, color: C.text2, align: "right" },
});

// ------------------------------------------------------------------ helpers
let section = "Introduction";
function slide(title, notes, master = "LCMF_CONTENT") {
  const s = pres.addSlide({ masterName: master, sectionTitle: section });
  s.addText(title, { placeholder: "title" });
  if (notes) s.addNotes(notes);
  return s;
}
function newSection(title) { section = title; pres.addSection({ title }); }
function text(s, t, o) { s.addText(t, { isTextBox: true, fontSize: 16, color: C.text1, valign: "top", margin: 0.05, ...o }); }
function card(s, x, y, w, h, fill, name) {
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.08, fill: { color: fill }, line: { color: fill }, objectName: name });
}
function badge(s, x, y, label, color, d = 0.62, size = 14) {
  s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color }, line: { color } });
  s.addText(label, { isTextBox: true, x, y, w: d, h: d, align: "center", valign: "middle", fontSize: size, bold: true, color: "FFFFFF", margin: 0 });
}
function stat(s, x, y, w, big, small, color) {
  text(s, big, { x, y, w, h: 0.8, fontSize: 40, bold: true, color, fontFace: THEME.headFontFace, margin: 0 });
  text(s, small, { x, y: y + 0.82, w, h: 0.7, fontSize: 14, color: C.text2, margin: 0 });
}
function png(file) { const b = fs.readFileSync(file); return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) }; }
function image(s, file, x, y, maxW, maxH) {
  const { w, h } = png(FIG(file));
  let iw = maxW, ih = (maxW * h) / w;
  if (ih > maxH) { ih = maxH; iw = (maxH * w) / h; }
  s.addImage({ path: FIG(file), x: x + (maxW - iw) / 2, y, w: iw, h: ih });
  return ih;
}
const chartBase = () => ({
  catAxisLabelColor: HEX.ink2, valAxisLabelColor: HEX.muted, catAxisLabelFontSize: 12, valAxisLabelFontSize: 10,
  catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt", dataLabelFontFace: "+mn-lt", titleFontFace: "+mn-lt",
  legendFontFace: "+mn-lt", dataLabelFontSize: 11, dataLabelColor: HEX.ink2, titleColor: HEX.navy, titleFontSize: 14,
  valGridLine: { color: HEX.grid, size: 0.75 }, catGridLine: { style: "none" }, showTitle: true,
});
const pct = (x) => `${Number(x) % 1 === 0 ? Number(x).toFixed(0) : Number(x).toFixed(1)}%`;
const n0 = (x) => Number(x).toLocaleString("en-US");

// ================================================================== 1. Title
newSection("Introduction");
{
  const s = slide(team.project_title, "Presenter: all members introduce themselves. One sentence: we built a gateway that moves legacy grid telemetry from classical ciphers to AES-256-GCM, and we measured what can go wrong during that migration.", "LCMF_TITLE");
  s.addText("A protocol-translation gateway from classical ciphers to AES-256-GCM for smart-grid telemetry, and a study of the vulnerabilities of the transition", { placeholder: "body" });
  const names = team.members.map((m) => `${m.name} (${m.enrolment})`).join("     ");
  text(s, names, { x: 0.8, y: 5.35, w: 11.7, h: 0.4, fontSize: 16, color: "FFFFFF" });
  text(s, `Guide: ${team.faculty}   |   ${team.course_code} - ${team.course_name}   |   ${team.school}, ${team.university}`,
    { x: 0.8, y: 5.85, w: 11.7, h: 0.4, fontSize: 13, color: "C9D6EA" });
}

// ================================================================== 2. Agenda
{
  const s = slide("Agenda and presenters", "Presenter: Member 1. Walk through the five parts and who presents each. Emphasise that every member owns one technical module end to end.");
  const items = [
    ["01", "Problem and background", "All members", HEX.navy],
    ["02", "Legacy ciphers and how they fall", short(0), HEX.blue],
    ["03", "AES engine and secure envelope", short(1), HEX.orange],
    ["04", "Gateway, migration and evaluation", short(2), HEX.aqua],
    ["05", "Results, demo and conclusion", "All members", HEX.navy],
  ];
  items.forEach(([num, title, who, col], i) => {
    const x = 0.6 + i * 2.48;
    card(s, x, 1.9, 2.28, 3.6, HEX.tintGray, `agenda-${num}`);
    badge(s, x + 0.25, 2.15, num, col, 0.75, 16);
    text(s, title, { x: x + 0.25, y: 3.1, w: 1.85, h: 1.3, fontSize: 18, bold: true, fontFace: THEME.headFontFace });
    text(s, who, { x: x + 0.25, y: 4.6, w: 1.85, h: 0.6, fontSize: 14, color: C.text2 });
  });
}

// ================================================================== 3. Problem domain
{
  const s = slide("Grid telemetry still runs on legacy links", "Presenter: Member 1. Explain SCADA, RTUs and telemetry. Legacy links used substitution/transposition scrambling or nothing. Devices live for decades so the migration is gradual: legacy and modern crypto coexist. Ukraine 2015 shows the consequences of attackers controlling breakers.");
  text(s, [
    { text: "SCADA master polls RTUs in substations every few seconds", options: { bullet: true, breakLine: true } },
    { text: "RTUs report voltage, current, frequency, power and breaker status, and execute breaker commands", options: { bullet: true, breakLine: true } },
    { text: "Many links still use classical ciphers - or no encryption", options: { bullet: true, breakLine: true } },
    { text: "Devices cannot all be replaced at once: legacy and modern cryptography coexist for years", options: { bullet: true } },
  ], { x: 0.6, y: 1.6, w: 6.6, h: 4.5, fontSize: 18, paraSpaceAfter: 14 });
  card(s, 7.7, 1.6, 5.0, 4.9, HEX.tintGray, "stats");
  stat(s, 8.0, 1.85, 4.5, "15-30 years", "service life of field equipment", HEX.blue);
  stat(s, 8.0, 3.4, 4.5, "1.2-19.2 kbaud", "typical legacy serial and radio links", HEX.orange);
  stat(s, 8.0, 4.95, 4.5, "~225,000", "customers lost power in the 2015 Ukraine grid attack", HEX.aqua);
}

// ================================================================== 4. Problem statement & objectives
{
  const s = slide("Problem statement and measurable objectives", "Presenter: Member 2. Read the problem statement. Then point out that every objective has a numeric target; slide 21 shows each one was met.");
  card(s, 0.6, 1.5, 12.1, 1.25, HEX.tintBlue, "statement");
  text(s, "Build a protocol-translation gateway that wraps legacy, unencrypted or classically encrypted grid telemetry into AES-encrypted payloads - and identify, demonstrate and quantify the vulnerabilities of the transition, with measured mitigations.",
    { x: 0.85, y: 1.62, w: 11.6, h: 1.0, fontSize: 17, italic: true, valign: "middle" });
  R.summary.objectives.forEach((o, i) => {
    const col = i % 4, row = Math.floor(i / 4);
    const x = 0.6 + col * 3.05, y = 2.95 + row * 1.95;
    card(s, x, y, 2.9, 1.85, HEX.tintGray, `obj-${o.id}`);
    badge(s, x + 0.15, y + 0.15, o.id, HEX.navy, 0.55, 12);
    text(s, o.objective, { x: x + 0.8, y: y + 0.1, w: 2.0, h: 0.95, fontSize: 12, bold: true, valign: "middle" });
    text(s, o.target, { x: x + 0.15, y: y + 1.08, w: 2.65, h: 0.72, fontSize: 11, color: C.text2 });
  });
}

// ================================================================== 5. Existing systems & gap
{
  const s = slide("Existing approaches and the research gap", "Presenter: Member 3. Secure protocols (DNP3-SA, IEC 62351, Modbus/TCP Security) need new device firmware. Bump-in-the-wire retrofits (AGA-12 / IEEE 1711.2, YASIR) protect the link but nobody quantifies the risks while old and new coexist. That is our gap.");
  const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: HEX.navy } } });
  const rows = [
    [hdr("Approach"), hdr("Works with legacy RTU?"), hdr("Integrity"), hdr("Limitation")],
    ["Classical cipher (status quo)", "n/a", "none", "broken from 1-2 frames"],
    ["DNP3 Secure Authentication", "no - firmware upgrade", "HMAC", "no confidentiality"],
    ["IEC 62351 / Modbus-TCP Security", "no - needs TLS stack", "TLS", "not for serial devices"],
    ["AGA-12 / IEEE 1711.2, YASIR", "yes - inline modules", "yes", "transition risks not quantified"],
    ["LCMF (this project)", "yes - translation gateway", "AES-256-GCM + policy", "last mile until RTU upgrade (TV1)"],
  ];
  s.addTable(rows, { x: 0.6, y: 1.55, w: 12.1, colW: [3.4, 3.0, 2.4, 3.3], fontSize: 14, color: HEX.navy, fontFace: THEME.bodyFontFace,
    border: { type: "solid", pt: 0.75, color: "D1D5DB" }, rowH: 0.5, valign: "middle" });
  card(s, 0.6, 5.35, 12.1, 1.3, HEX.tintOrange, "gap");
  text(s, "Gap: the risks of the migration itself - last mile, downgrade, replay laundering, AES misuse, nonce reuse, key provenance - are rarely measured.",
    { x: 0.85, y: 5.5, w: 11.6, h: 1.0, fontSize: 17, bold: true, valign: "middle" });
}

// ================================================================== Member 1
newSection("Legacy ciphers and cryptanalysis");
slide("Legacy ciphers and how they fall", `Presenter: ${short(0)} (Member 1). Module: lcmf.classical and lcmf.analysis.cryptanalysis.`, "LCMF_SECTION")
  .addText(`${short(0)}  -  Legacy Cipher Suite, Cryptanalysis & Result Visualisation`, { placeholder: "body" });
{
  const s = slide("Six legacy ciphers on one telemetry frame", `Presenter: ${short(0)}. All ciphers share one interface and a 36-symbol alphabet A-Z0-9 so digits are enciphered losslessly; Playfair uses a 6x6 square. Each RTU uses a different cipher.`);
  const net = R.crypt;  // ciphertexts come from the demo output for realism
  const demo = fs.existsSync(path.join(ROOT, "results", "demo_output.txt")) ? fs.readFileSync(path.join(ROOT, "results", "demo_output.txt"), "utf8").split(/\r?\n/) : [];
  const pick = (k) => (demo.find((l) => l.trim().startsWith(k)) || "").replace(/\s+/g, " ").trim();
  const plain = (pick("plaintext frame") || "plaintext frame : -").split(": ")[1];
  const rows = [[{ text: "Plaintext", options: { bold: true } }, { text: plain, options: { fontFace: "Courier New", bold: true } }]];
  ["Caesar", "Additive", "Affine", "Vigenere", "Playfair", "Columnar"].forEach((c) => {
    const line = pick(c);
    const ct = line.split("-> ")[1] || "";
    const key = line.replace(c, "").split("->")[0].trim();
    rows.push([{ text: `${c}  (${key})`, options: {} }, { text: ct, options: { fontFace: "Courier New" } }]);
  });
  s.addTable(rows, { x: 0.6, y: 1.55, w: 12.1, colW: [3.7, 8.4], fontSize: 14, color: HEX.navy, rowH: 0.52,
    border: { type: "solid", pt: 0.75, color: "D1D5DB" }, fill: { color: "FFFFFF" }, valign: "middle" });
  card(s, 0.6, 5.5, 12.1, 1.15, HEX.tintGray, "note");
  text(s, "Key spaces over Z36: Caesar 1 - Additive 36 - Affine 432 - Columnar 7! = 5,040 - Vigenere 36^8 - Playfair 36! (about 2^138)",
    { x: 0.85, y: 5.65, w: 11.6, h: 0.85, fontSize: 16, valign: "middle" });
}
{
  const s = slide("Fixed frame grammar = free known plaintext", `Presenter: ${short(0)}. 24 of 52 symbols are fixed tags. Any key that decrypts a capture into a valid frame with a valid checksum is the key. The chart shows nominal key space - which turns out to be irrelevant.`);
  image(s, "fig_frame_format.png", 0.6, 1.45, 12.1, 2.4);
  const a = R.crypt.attacks;
  s.addChart(pres.charts.BAR, [{ name: "Key space (bits)", labels: a.map((x) => x.cipher).concat(["AES-256"]), values: a.map((x) => x.key_space_bits).concat([256]) }], {
    x: 0.6, y: 4.1, w: 7.6, h: 2.8, barDir: "bar", catAxisOrientation: "maxMin", chartColors: [HEX.blue], showValue: true,
    dataLabelPosition: "outEnd", showLegend: false, title: "Nominal key space (bits)", valAxisMaxVal: 300, ...chartBase() });
  card(s, 8.5, 4.2, 4.2, 2.6, HEX.tintOrange, "callout");
  stat(s, 8.75, 4.4, 3.8, `<= ${Math.max(...a.map((x) => x.frames_used))} frames`, `and <= ${Math.max(...a.map((x) => x.elapsed_ms)).toFixed(0)} ms to recover every legacy key - even Playfair's 2^138`, HEX.orange);
}
{
  const s = slide("Cryptanalysis results: every key recovered", `Presenter: ${short(0)}. Walk the table. Highlight Vigenere: constraint propagation needs only 8 candidate checks. Playfair codebook: one known frame already decrypts over half of a new frame. Mention the finding that the legacy checksum is blind to transpositions.`);
  const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: HEX.navy } } });
  const rows = [[hdr("Cipher"), hdr("Attack"), hdr("Frames"), hdr("Keys tried"), hdr("Time (ms)"), hdr("Recovered key")]].concat(
    R.crypt.attacks.map((x) => [x.cipher, x.method, String(x.frames_used), n0(x.candidates_tried), Number(x.elapsed_ms).toFixed(1), String(x.key)]));
  s.addTable(rows, { x: 0.6, y: 1.5, w: 8.2, colW: [1.25, 3.05, 0.8, 1.0, 0.9, 1.2], fontSize: 12, color: HEX.navy, rowH: 0.48,
    border: { type: "solid", pt: 0.75, color: "D1D5DB" }, valign: "middle" });
  const pf = R.crypt.playfair_codebook;
  const at = (k) => pf.find((p) => p.frames_observed === k).digram_coverage_pct;
  card(s, 9.1, 1.5, 3.6, 2.45, HEX.tintBlue, "pf");
  stat(s, 9.35, 1.65, 3.2, `${at(1)}%`, `of a new Playfair frame decrypted from ONE known frame (${at(20)}% after 20) - no key needed`, HEX.blue);
  card(s, 9.1, 4.15, 3.6, 2.45, HEX.tintOrange, "chk");
  text(s, "Finding", { x: 9.35, y: 4.3, w: 3.2, h: 0.4, fontSize: 16, bold: true, color: HEX.orange });
  text(s, "The legacy checksum is a plain sum: it cannot detect transposed digits, so a wrong Columnar key still gave checksum-valid frames.", { x: 9.35, y: 4.75, w: 3.2, h: 1.8, fontSize: 14 });
}

// ================================================================== Member 2
newSection("AES engine and secure envelope");
slide("AES engine and secure envelope", `Presenter: ${short(1)} (Member 2). Module: lcmf.modern and gateway.envelope.`, "LCMF_SECTION")
  .addText(`${short(1)}  -  Modern Cryptography Engine, Secure Envelope & Experiment Validation`, { placeholder: "body" });
{
  const s = slide("AES-256 and GCM from first principles", `Presenter: ${short(1)}. S-box derived from GF(2^8) inverses, not copied. Key schedule for 128/192/256. GCM with GHASH in GF(2^128). Validated against FIPS-197 and the GCM spec, and bit-identical to the cryptography library. Production uses the library for constant-time AES-NI.`);
  image(s, "fig_aes_round.png", 0.6, 1.45, 12.1, 3.4);
  const vec = R.val.vectors;
  const rt = R.val.roundtrip.reduce((s2, r) => s2 + r.frames, 0);
  [[`${vec.filter((v) => v.pass).length}/${vec.length}`, "published test vectors pass (FIPS-197, GCM, textbook)", HEX.blue],
    [`${R.val.gcm_cross_check.identical}/${R.val.gcm_cross_check.cases}`, "random cases bit-identical to the library", HEX.orange],
    [n0(rt), "telemetry round trips, 0 failures", HEX.aqua]].forEach(([b, sm, col], i) => {
    card(s, 0.6 + i * 4.1, 5.05, 3.9, 1.7, HEX.tintGray, `v${i}`);
    stat(s, 0.85 + i * 4.1, 5.15, 3.5, b, sm, col);
  });
}
{
  const s = slide("Secure Telemetry Envelope: 68 bytes per reading", `Presenter: ${short(1)}. Header is authenticated as AAD so device id, sequence and timestamp cannot be changed. Nonce = sender id || 64-bit counter, persisted before use. HKDF gives each device and direction its own key. 64-entry replay window plus timestamps.`);
  image(s, "fig_envelope.png", 0.6, 1.4, 12.1, 2.6);
  const cards = [
    ["AAD", "37-byte header authenticated by the GCM tag", HEX.blue],
    ["Nonce", "sender id || 64-bit counter, reserved and persisted before use", HEX.orange],
    ["HKDF", "one key per device, direction and generation from a random master", HEX.aqua],
    ["Replay", "64-entry sliding window plus 30 s timestamp freshness", HEX.navy],
  ];
  cards.forEach(([t, d, col], i) => {
    const x = 0.6 + i * 3.05;
    card(s, x, 4.35, 2.9, 2.3, HEX.tintGray, `c${i}`);
    badge(s, x + 0.2, 4.55, String(i + 1), col, 0.55, 14);
    text(s, t, { x: x + 0.9, y: 4.6, w: 1.9, h: 0.45, fontSize: 18, bold: true });
    text(s, d, { x: x + 0.2, y: 5.25, w: 2.55, h: 1.3, fontSize: 14, color: C.text2 });
  });
}
{
  const s = slide("Choosing AES is not enough (TV4-TV7)", `Presenter: ${short(1)}. Four ways a migration to AES fails: malleable modes, ECB, nonce reuse after reboot, and keys derived from old legacy passwords. Each has a measured mitigation in the framework.`);
  const t4 = Object.fromEntries(TV.TV4.rows.map((r) => [r.scheme, r.tamper_success_pct]));
  const t5 = TV.TV5.rows, t6 = TV.TV6.rows, t7 = TV.TV7.rows;
  const cards = [
    ["TV4", "Malleable modes", `${pct(t4["AES-256-CTR, no MAC (bit flip)"])} vs ${pct(t4["AES-256-GCM (STE)"])}`, "blind breaker flip: AES-CTR without MAC vs AES-GCM", HEX.orange],
    ["TV5", "ECB patterns", `${t5[0].distinct_ciphertexts} ciphertexts`, `for ${n0(TV.TV5.messages)} status messages: breaker state inferred with ${pct(t5[0].attacker_balanced_accuracy_pct)} balanced accuracy (GCM: ${pct(t5[1].attacker_balanced_accuracy_pct)})`, HEX.blue],
    ["TV6", "Nonce reuse", `${n0(t6[0].nonce_collisions)} reuses`, `after reboots with RAM counters: ${pct(t6[0].plaintext_recovered_pct)} plaintext recovered; persistent counters: 0`, HEX.aqua],
    ["TV7", "Legacy-derived keys", `${t7[0].guesses} guesses`, `to find SHA-256("${t7[0].dictionary_hit}") from one envelope; HKDF random master: not found`, HEX.navy],
  ];
  cards.forEach(([id, t, big, d, col], i) => {
    const x = 0.6 + (i % 2) * 6.1, y = 1.5 + Math.floor(i / 2) * 2.65;
    card(s, x, y, 5.95, 2.45, HEX.tintGray, id);
    badge(s, x + 0.2, y + 0.2, id, col, 0.75, 13);
    text(s, t, { x: x + 1.1, y: y + 0.28, w: 4.6, h: 0.5, fontSize: 18, bold: true });
    text(s, big, { x: x + 1.1, y: y + 0.8, w: 4.6, h: 0.65, fontSize: 30, bold: true, color: col, fontFace: THEME.headFontFace });
    text(s, d, { x: x + 1.1, y: y + 1.45, w: 4.65, h: 0.9, fontSize: 13, color: C.text2 });
  });
}

// ================================================================== Member 3
newSection("Gateway, migration and evaluation");
slide("Gateway, migration and evaluation", `Presenter: ${short(2)} (Member 3). Module: lcmf.grid, lcmf.gateway, transition_system, cli.`, "LCMF_SECTION")
  .addText(`${short(2)}  -  Smart-Grid Simulation, Gateway & System Evaluation`, { placeholder: "body" });
{
  const s = slide("Architecture of the migration gateway", `Presenter: ${short(2)}. Field: legacy RTUs 1-6 with different ciphers, RTU 7 unencrypted, RTU 8 upgraded. Gateway pipeline: legacy decrypt, parse and checksum, identity / sequence / plausibility checks, AES-GCM seal. Control centre: policy, replay window, GCM verify. A1 and A2 are the attacker positions.`);
  image(s, "fig_architecture.png", 0.6, 1.3, 12.1, 5.6);
}
{
  const s = slide("Four migration phases - and a downgrade trap", `Presenter: ${short(2)}. Real migrations are gradual. If the control centre accepts both protocols from everyone, an attacker can strip the envelope and send a legacy frame (downgrade). Pinning migrated devices blocks it while still serving the unmigrated RTU.`);
  image(s, "fig_migration.png", 0.6, 1.35, 8.1, 3.9);
  const m = Object.fromEntries(TV.TV2.modes.map((x) => [x.mode, x.forged_accepted_pct]));
  card(s, 9.0, 1.45, 3.7, 2.4, HEX.tintOrange, "perm");
  stat(s, 9.25, 1.6, 3.3, pct(m.HYBRID_PERMISSIVE), "forged legacy frames accepted in HYBRID_PERMISSIVE", HEX.orange);
  card(s, 9.0, 4.05, 3.7, 2.4, HEX.tintBlue, "pin");
  stat(s, 9.25, 4.2, 3.3, pct(m.HYBRID_PINNED), "accepted once migrated devices are pinned (HYBRID_PINNED)", HEX.blue);
  text(s, "Legacy direct = talks legacy to SCADA   |   Bridged = legacy RTU behind the gateway   |   Native AES = upgraded RTU",
    { x: 0.6, y: 5.6, w: 8.1, h: 0.6, fontSize: 13, color: C.text2 });
}
{
  const s = slide("The legacy last mile: trust and freshness laundering", `Presenter: ${short(2)}. TV1: the attacker breaks the legacy key behind the gateway and rewrites frames; the gateway seals the lie into a valid envelope. Plausibility stops gross forgeries, not stealthy ones; only native AES at the RTU closes it. TV3: a stateless gateway turns old legacy frames into fresh envelopes; tracking the legacy sequence number fixes it.`);
  const t1 = TV.TV1.scenarios;
  const get = (d, a) => t1.find((x) => x.defence.startsWith(d) && x.attack === a).forged_accepted_pct;
  const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: HEX.navy } } });
  text(s, "TV1 - false data injected on the serial link", { x: 0.6, y: 1.45, w: 6, h: 0.45, fontSize: 18, bold: true });
  s.addTable([[hdr("Defence"), hdr("Gross"), hdr("Stealthy")],
    ["Gateway only", pct(get("gateway only", "gross")), pct(get("gateway only", "stealthy"))],
    ["Gateway + plausibility", pct(get("gateway + plausibility", "gross")), pct(get("gateway + plausibility", "stealthy"))],
    ["Native AES at RTU", "0%", "0%"]],
  { x: 0.6, y: 2.0, w: 5.9, colW: [3.1, 1.4, 1.4], fontSize: 15, color: HEX.navy, rowH: 0.55, border: { type: "solid", pt: 0.75, color: "D1D5DB" }, valign: "middle" });
  text(s, `Eavesdropper on the last mile already read ${pct(t1[0].aes_delivered_readings_exposed_pct)} of the readings later sent inside AES envelopes.`,
    { x: 0.6, y: 4.4, w: 5.9, h: 1.0, fontSize: 15, color: C.text2 });
  const c3 = TV.TV3.cases;
  text(s, "TV3 - replay", { x: 7.0, y: 1.45, w: 5.7, h: 0.45, fontSize: 18, bold: true });
  s.addTable([[hdr("Scenario"), hdr("Accepted")]].concat(c3.map((x) => [`${x.case} - ${x.defence}`, pct(x.replay_accepted_pct)])),
    { x: 7.0, y: 2.0, w: 5.7, colW: [4.4, 1.3], fontSize: 13, color: HEX.navy, rowH: 0.55, border: { type: "solid", pt: 0.75, color: "D1D5DB" }, valign: "middle" });
  card(s, 0.6, 5.6, 12.1, 1.05, HEX.tintOrange, "lesson");
  text(s, "A strong MAC can certify weak data: the gateway moves the trust boundary but does not remove the legacy link.",
    { x: 0.85, y: 5.7, w: 11.6, h: 0.85, fontSize: 17, bold: true, valign: "middle" });
}
{
  const s = slide("Correct and fast enough for real time", `Presenter: ${short(2)}. Integrity: 14,400 frames across all four modes with zero corrupted readings. Latency: median tens of microseconds per frame. Overhead: 53 bytes; an 8-RTU scan at 9,600 baud still fits a 2 s cycle; 1,200 baud already overruns even with legacy frames.`);
  const lat = TV.TV8.gateway_latency.library;
  const names = Object.keys(lat);
  s.addChart(pres.charts.BAR, [{ name: "Median latency (us)", labels: names.map((n) => n[0].toUpperCase() + n.slice(1)), values: names.map((n) => lat[n].median_us) }], {
    x: 0.6, y: 1.45, w: 6.0, h: 3.6, barDir: "col", chartColors: [HEX.blue], showValue: true, dataLabelPosition: "outEnd",
    showLegend: false, title: "Gateway latency per frame, median (µs)", dataLabelFormatCode: "0", ...chartBase() });
  const link = TV.TV8.link;
  s.addChart(pres.charts.BAR, [
    { name: `Legacy (${TV.TV8.legacy_frame_bytes} B)`, labels: link.map((l) => `${n0(l.baud)} baud`), values: link.map((l) => l.scan_8_devices_legacy_ms) },
    { name: `Envelope (${TV.TV8.ste_bytes} B)`, labels: link.map((l) => `${n0(l.baud)} baud`), values: link.map((l) => l.scan_8_devices_ste_ms) }], {
    x: 6.8, y: 1.45, w: 5.9, h: 3.6, barDir: "col", barGrouping: "clustered", chartColors: [HEX.orange, HEX.blue], showValue: true,
    dataLabelPosition: "outEnd", dataLabelFormatCode: "0", showLegend: true, legendPos: "t", legendFontSize: 11,
    title: "Time to poll 8 RTUs (ms); scan cycle 2,000 ms", ...chartBase() });
  const integ = R.integ.reduce((a, r) => a + r.delivered, 0);
  const corrupt = R.integ.reduce((a, r) => a + r.corrupted, 0);
  [[n0(integ), `frames delivered in 4 modes, ${corrupt} corrupted`, HEX.aqua],
    [`${Math.max(...names.map((n) => lat[n].median_us)).toFixed(0)} µs`, "worst median latency (target < 1 ms)", HEX.blue],
    [`+${TV.TV8.ste_overhead_bytes} B`, `envelope overhead per reading (+${TV.TV8.size_increase_pct}%)`, HEX.orange]].forEach(([b, sm, col], i) => {
    card(s, 0.6 + i * 4.1, 5.25, 3.9, 1.5, HEX.tintGray, `p${i}`);
    stat(s, 0.85 + i * 4.1, 5.3, 3.5, b, sm, col);
  });
}

// ================================================================== Results
newSection("Results and conclusion");
{
  const s = slide("Every transition vulnerability, before and after mitigation", "Presenter: all - each member comments on their experiments. Orange = vulnerable configuration, blue = mitigated. Every mitigation drops attack success to zero, except stealthy false data on the legacy last mile (TV1), which needs the RTU itself to be upgraded.");
  const s1 = TV.TV1.scenarios, m2 = Object.fromEntries(TV.TV2.modes.map((x) => [x.mode, x.forged_accepted_pct]));
  const c3 = TV.TV3.cases, r4 = Object.fromEntries(TV.TV4.rows.map((x) => [x.scheme, x.tamper_success_pct]));
  const rows = [
    ["TV1 last-mile false data", s1[0].forged_accepted_pct, s1[4].forged_accepted_pct],
    ["TV2 downgrade", m2.HYBRID_PERMISSIVE, m2.HYBRID_PINNED],
    ["TV3 WAN replay", c3[0].replay_accepted_pct, c3[1].replay_accepted_pct],
    ["TV3 last-mile replay", c3[2].replay_accepted_pct, c3[3].replay_accepted_pct],
    ["TV4 blind tampering", r4["AES-256-CTR, no MAC (bit flip)"], r4["AES-256-GCM (STE)"]],
    ["TV6 plaintext after reboot", TV.TV6.rows[0].plaintext_recovered_pct, TV.TV6.rows[1].plaintext_recovered_pct],
    ["TV7 key by dictionary", TV.TV7.rows[0].dictionary_hit ? 100 : 0, TV.TV7.rows[1].dictionary_hit ? 100 : 0],
  ];
  s.addChart(pres.charts.BAR, [
    { name: "Vulnerable configuration", labels: rows.map((r) => r[0]), values: rows.map((r) => r[1]) },
    { name: "Mitigated configuration", labels: rows.map((r) => r[0]), values: rows.map((r) => r[2]) }], {
    x: 0.6, y: 1.4, w: 12.1, h: 5.4, barDir: "bar", barGrouping: "clustered", catAxisOrientation: "maxMin",
    chartColors: [HEX.orange, HEX.blue], showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0\"%\"",
    valAxisMaxVal: 110, valAxisMinVal: 0, showLegend: true, legendPos: "t", legendFontSize: 12,
    title: "Attack success (%)", ...chartBase() });
}
{
  const s = slide("Live demonstration", "Presenter: Member 3 drives the keyboard, the others narrate their module as it appears. Run the guided demo; if time permits show python -m pytest (all tests pass) and python -m lcmf simulate --mode STRICT_AES.");
  const cmds = [
    ["python -m lcmf demo --interactive", "guided walk-through of all modules"],
    ["python -m lcmf cipher affine encrypt RTU01SEQ0001 --a 5 --b 8", "any legacy cipher, any key"],
    ["python -m lcmf attack", "every legacy key recovered"],
    ["python -m lcmf simulate --mode STRICT_AES --polls 3", "gateway + SCADA in a migration phase"],
    ["python -m lcmf experiments", "regenerates every number in the report"],
    ["python -m pytest", "automated test suite"],
  ];
  card(s, 0.6, 1.5, 12.1, 5.2, HEX.navy, "terminal");
  cmds.forEach(([c, d], i) => {
    text(s, `> ${c}`, { x: 0.95, y: 1.75 + i * 0.8, w: 8.1, h: 0.5, fontSize: 15, fontFace: "Courier New", color: "FFFFFF" });
    text(s, d, { x: 9.15, y: 1.75 + i * 0.8, w: 3.4, h: 0.5, fontSize: 15, color: "C9D6EA" });
  });
}
{
  const s = slide("All seven objectives met", "Presenter: Member 2. Read the measured column - every number is generated by the experiment runner, none is typed by hand.");
  const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: HEX.navy } } });
  s.addTable([[hdr("ID"), hdr("Objective"), hdr("Measured result"), hdr("Status")]].concat(
    R.summary.objectives.map((o) => [o.id, o.objective, o.measured, { text: o.met ? "Met" : "Not met", options: { bold: true, color: o.met ? "0B7A50" : "B42318" } }])),
  { x: 0.6, y: 1.5, w: 12.1, colW: [0.7, 4.6, 5.7, 1.1], fontSize: 13, color: HEX.navy, rowH: 0.62, border: { type: "solid", pt: 0.75, color: "D1D5DB" }, valign: "middle" });
}
{
  const s = slide("Conclusion: a migration playbook for utilities", "Presenter: Member 1. Summarise: classical ciphers give no protection for structured telemetry; the transition has its own risks; each has a tested mitigation. Then the six-step playbook. Future scope: embedded hardware, real Modbus/DNP3, HSM keys, ML anomaly detection, post-quantum key exchange.");
  const steps = ["Inventory legacy links, rank by exposure", "Gateways next to RTUs, with plausibility and sequence tracking",
    "Run HYBRID_PINNED; pin each device when migrated", "Fresh random master keys + persistent nonce counters",
    "Replace RTUs on the most exposed links first", "Switch to STRICT_AES; delete legacy keys"];
  steps.forEach((t, i) => {
    const x = 0.6 + i * 2.05;
    card(s, x, 1.6, 1.9, 3.0, HEX.tintGray, `step${i}`);
    badge(s, x + 0.2, 1.8, String(i + 1), [HEX.blue, HEX.orange, HEX.aqua, HEX.navy, HEX.blue, HEX.orange][i], 0.6, 14);
    text(s, t, { x: x + 0.2, y: 2.6, w: 1.55, h: 1.9, fontSize: 14 });
  });
  card(s, 0.6, 4.9, 12.1, 1.75, HEX.tintBlue, "future");
  text(s, "Future scope", { x: 0.85, y: 5.0, w: 3, h: 0.4, fontSize: 16, bold: true, color: HEX.blue });
  text(s, "Embedded gateway on real serial/radio links  -  Modbus RTU and DNP3 adapters with IEC 62351 on the control side  -  keys in an HSM/TPM  -  state-estimation or ML detection of stealthy false data  -  post-quantum key establishment",
    { x: 0.85, y: 5.42, w: 11.6, h: 1.1, fontSize: 14 });
}
{
  const s = slide("Contribution of each team member", "Presenter: all. Each member owned one module end to end - design, code, tests, report chapters and slides - and the analysis, integration and documentation were shared.");
  const cols = [HEX.blue, HEX.orange, HEX.aqua];
  const loc = (m) => m.code.reduce((acc, g) => {
    const files = g.endsWith("/*") ? fs.readdirSync(path.join(ROOT, g.slice(0, -2))).filter((f) => f.endsWith(".py")).map((f) => path.join(ROOT, g.slice(0, -2), f)) : [path.join(ROOT, g.split(" ")[0])];
    return acc + files.reduce((n, f) => n + fs.readFileSync(f, "utf8").split("\n").filter((l) => l.trim()).length, 0);
  }, 0);
  team.members.forEach((m, i) => {
    const x = 0.6 + i * 4.1;
    card(s, x, 1.5, 3.9, 5.2, HEX.tintGray, `m${i}`);
    badge(s, x + 0.25, 1.7, `M${i + 1}`, cols[i], 0.75, 14);
    text(s, m.name, { x: x + 1.15, y: 1.72, w: 2.6, h: 0.4, fontSize: 16, bold: true });
    text(s, m.enrolment, { x: x + 1.15, y: 2.12, w: 2.6, h: 0.35, fontSize: 12, color: C.text2 });
    text(s, m.role, { x: x + 0.25, y: 2.65, w: 3.4, h: 0.75, fontSize: 15, bold: true, color: cols[i] });
    text(s, m.work.slice(0, 4).map((w, k) => ({ text: w, options: { bullet: true, breakLine: k < 3 } })),
      { x: x + 0.25, y: 3.45, w: 3.45, h: 2.6, fontSize: 12, paraSpaceAfter: 4, color: C.text1 });
    text(s, `${n0(loc(m))} lines of code  |  ${m.slides}`, { x: x + 0.25, y: 6.1, w: 3.45, h: 0.5, fontSize: 11, color: C.text2 });
  });
}
{
  const s = slide("Thank you - questions?", "All members take questions. Key references: NIST SP 800-82r3, NISTIR 7628, FIPS 197, SP 800-38D, IEEE 1711.2, IEC 62351.", "LCMF_TITLE");
  s.addText("Code, results, report and slides are generated from one repository:  python -m lcmf demo", { placeholder: "body" });
  text(s, "Key references: NIST SP 800-82 Rev. 3  -  NISTIR 7628  -  FIPS 197  -  NIST SP 800-38D  -  IEEE 1711.2  -  IEC 62351  -  Lee et al., Ukraine grid attack analysis (2016)",
    { x: 0.8, y: 5.6, w: 11.7, h: 0.6, fontSize: 13, color: "C9D6EA" });
}

const out = path.join(ROOT, "docs", "Presentation.pptx");
pres.writeFile({ fileName: out }).then(async () => {
  await applyTheme(out, THEME);
  console.log(`wrote ${out} (${pres.slides.length} slides)`);
});
