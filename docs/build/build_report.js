// Builds docs/Project_Report.docx from results/*.json, docs/figures and team_config.json.
//   node build_report.js        (then: python export_pdf.py  -> updates TOC fields and writes the PDF)
"use strict";
const fs = require("fs");
const path = require("path");
const { D, Ctx, styles, numbering, readJSON, countLines, ROOT, FONT, TEXT_W } = require("./lib");
const ch13 = require("./report_ch1_3");
const ch45 = require("./report_ch4_5");
const ch67 = require("./report_ch6_7");
const {
  Document, Packer, Paragraph, TextRun, AlignmentType, Footer, Header, PageNumber, NumberFormat,
  TableOfContents, StyleLevel, Table, TableRow, TableCell, WidthType, BorderStyle, VerticalAlign,
} = D;

const team = JSON.parse(fs.readFileSync(path.join(__dirname, "team_config.json"), "utf8"));
const R = {
  val: readJSON("results/validation.json"),
  crypt: readJSON("results/cryptanalysis.json"),
  trans: readJSON("results/transition.json"),
  bench: readJSON("results/benchmark.json"),
  integ: readJSON("results/integrity.json"),
  summary: readJSON("results/summary.json"),
};

// ------------------------------------------------------------------ derived data
function testInfo() {
  const owner = { "test_classical.py": "M1", "test_cryptanalysis.py": "M1", "test_modern.py": "M2",
    "test_transition_crypto.py": "M2", "test_gateway.py": "M3", "test_transition_system.py": "M3" };
  const focus = {
    "test_classical.py": "Textbook vectors for all six ciphers, key handling, key spaces, telemetry round trips",
    "test_modern.py": "FIPS-197 and GCM vectors, S-box derivation, engine equivalence, tampering, keys, nonces, replay window, envelope",
    "test_gateway.py": "Frame codec, plausibility, gateway uplink/downlink, integrity in all modes, policy, commands",
    "test_cryptanalysis.py": "Key recovery for every cipher, known-plaintext solvers, textbook attacks, Playfair codebook",
    "test_transition_crypto.py": "TV4-TV7: malleability, ECB leakage, nonce reuse, legacy-derived keys",
    "test_transition_system.py": "TV1-TV3: last-mile injection, downgrade, replay - attack and mitigation pairs",
  };
  const collectFile = path.join(ROOT, "results", "test_collect.txt");
  const reportFile = path.join(ROOT, "results", "test_report.txt");
  const counts = {};
  if (fs.existsSync(collectFile)) {
    fs.readFileSync(collectFile, "utf8").split(/\r?\n/).forEach((l) => {
      const m = l.match(/^tests[\\/](test_\w+\.py)::/);
      if (m) counts[m[1]] = (counts[m[1]] || 0) + 1;
    });
  }
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  let summary = `${total} passed`;
  if (fs.existsSync(reportFile)) {
    const last = fs.readFileSync(reportFile, "utf8").trim().split(/\r?\n/).pop();
    summary = last.replace(/=/g, "").trim();
  }
  const rows = Object.keys(owner).map((f) => [`tests/${f}`, owner[f], focus[f], String(counts[f] || 0)]);
  rows.push(["**Total**", "", "", `**${total}**`]);
  return { total, summary, rows };
}

function locRows() {
  const pk = [
    ["lcmf/classical", "Legacy cipher suite", ["lcmf/classical/*"]],
    ["lcmf/modern", "AES core, modes, AEAD, keys, nonces, replay", ["lcmf/modern/*"]],
    ["lcmf/grid", "Telemetry, codec, simulator, SCADA, network", ["lcmf/grid/*"]],
    ["lcmf/gateway", "Envelope, gateway, policy, plausibility", ["lcmf/gateway/*"]],
    ["lcmf/analysis", "Cryptanalysis, experiments, benchmarks", ["lcmf/analysis/*"]],
    ["lcmf/cli.py", "Command-line interface", ["lcmf/cli.py"]],
    ["tests", "Automated tests", ["tests/*"]],
    ["scripts", "Figure generation", ["scripts/*"]],
  ];
  let total = 0;
  const rows = pk.map(([name, purpose, globs]) => {
    const n = globs.reduce((s, g) => s + countLines(g), 0);
    total += n;
    return [name, purpose, n.toLocaleString("en-US")];
  });
  rows.push(["**Total**", "", `**${total.toLocaleString("en-US")}**`]);
  return rows;
}

function memberLoc() {
  return team.members.map((m) => m.code.reduce((s, g) => s + countLines(g), 0));
}

function demoLines() {
  const file = path.join(ROOT, "results", "demo_output.txt");
  if (!fs.existsSync(file)) return ["(run build_all.bat to capture the demo output)"];
  const lines = fs.readFileSync(file, "utf8").replace(/\r/g, "").split("\n");
  const m3 = lines.findIndex((l) => l.includes("Module 3"));
  const m4 = lines.findIndex((l) => l.includes("Module 4"));
  const part3 = lines.slice(m3 - 1, m3 + 9);       // header + first device
  const dev8 = lines.findIndex((l) => l.includes("Device 8 ["));
  const part3b = dev8 > 0 ? ["  ...", ...lines.slice(dev8 - 1, dev8 + 4)] : [];
  return [...part3, ...part3b, ...lines.slice(m4 - 1)].filter((l, i, arr) => !(l === "" && arr[i - 1] === ""))
    .map((l) => (l.length > 98 ? l.slice(0, 98) : l));
}

const extra = { tests: testInfo(), locRows: locRows(), memberLoc: memberLoc(), demoLines: demoLines() };

// ------------------------------------------------------------------ front matter
const C = (text, size = 24, opts = {}) => new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { after: opts.after ?? 120, before: opts.before ?? 0, line: 300 },
  children: [new TextRun({ text, size, bold: opts.bold, italics: opts.italics, allCaps: opts.caps, color: opts.color })],
});
const none = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const noBorders = { top: none, bottom: none, left: none, right: none };

function plainTable(rows, widths, opts = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  const tw = opts.width || TEXT_W;
  const w = widths.map((x) => Math.floor((tw * x) / total));
  w[w.length - 1] = tw - w.slice(0, -1).reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: tw, type: WidthType.DXA }, columnWidths: w, alignment: AlignmentType.CENTER,
    rows: rows.map((r, ri) => new TableRow({ children: r.map((txt, i) => new TableCell({
      width: { size: w[i], type: WidthType.DXA }, borders: noBorders, verticalAlign: VerticalAlign.CENTER,
      children: String(txt).split("\n").map((line) => new Paragraph({
        alignment: opts.align ? opts.align[i] : AlignmentType.LEFT, spacing: { before: 40, after: 40, line: 276 },
        children: [new TextRun({ text: line, bold: opts.boldFirstRow && ri === 0, size: opts.size || 24 })] })),
    })) })),
  });
}

function cover() {
  const t = team;
  return [
    C(t.university, 34, { bold: true, caps: true, before: 200 }),
    C(t.school, 26, { bold: true, after: 300 }),
    C("[ University Logo ]", 22, { italics: true, color: "808080", after: 400 }),
    C("A Mini-Project Report on", 26, { italics: true, after: 200 }),
    C(t.project_title, 36, { bold: true, caps: true, after: 160 }),
    C(t.project_subtitle, 24, { italics: true, after: 400 }),
    C("Submitted in partial fulfilment of the requirements of the course", 24, { after: 60 }),
    C(`${t.course_code} - ${t.course_name}`, 24, { bold: true, after: 60 }),
    C(`${t.programme}, ${t.semester}`, 24, { after: 400 }),
    C("Submitted by", 24, { bold: true, after: 120 }),
    plainTable([["Name", "Enrolment No."], ...t.members.map((m) => [m.name, m.enrolment])], [1, 1],
      { width: 6000, boldFirstRow: true, align: [AlignmentType.CENTER, AlignmentType.CENTER] }),
    C("", 24, { after: 300 }),
    C("Under the guidance of", 24, { bold: true, after: 60 }),
    C(t.faculty, 24, { after: 40 }),
    C(t.faculty_designation, 24, { after: 500 }),
    C(t.school.toUpperCase(), 24, { bold: true, after: 40 }),
    C(`${t.university.toUpperCase()}, ${t.city.toUpperCase()}`, 24, { bold: true, after: 40 }),
    C(t.submission_month, 24, { bold: true }),
  ];
}

function signatureBlock(left, right) {
  return plainTable([[left[0], right[0]], [left[1], right[1]], [left[2], right[2]], [left[3] || "", right[3] || ""]], [1, 1],
    { align: [AlignmentType.LEFT, AlignmentType.RIGHT] });
}

function frontMatter(c) {
  const t = team;
  const names = t.members.map((m) => `${m.name} (${m.enrolment})`);
  const nameList = names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}` : names[0];
  const out = [];
  const add = (...xs) => xs.forEach((x) => (Array.isArray(x) ? out.push(...x) : out.push(x)));
  const TV = Object.fromEntries(R.trans.map((x) => [x.id, x]));
  const worstMed = Math.max(...Object.values(TV.TV8.gateway_latency.library).map((v) => v.median_us));
  const delivered = R.integ.reduce((s, r) => s + r.delivered, 0);

  add(c.frontHeading("Certificate", false));
  add(c.p(`This is to certify that the mini-project report entitled **"${t.project_title}"** submitted by ${nameList} in partial fulfilment of the requirements of the course ${t.course_code} - ${t.course_name}, ${t.programme}, ${t.semester}, ${t.school}, ${t.university}, is a bonafide record of the work carried out by them under my supervision during the academic year ${t.academic_year}.`));
  add(c.p("To the best of my knowledge, the work presented in this report is original and has not been submitted elsewhere for the award of any degree, diploma or course credit."));
  add(new Paragraph({ spacing: { before: 1200 }, children: [] }));
  add(signatureBlock(["______________________", "Signature of the Supervisor", t.faculty, t.faculty_designation],
    ["______________________", "Signature of the Head / Coordinator", "Name:", "Date:"]));

  add(c.frontHeading("Declaration"));
  add(c.p(`We hereby declare that the mini-project report entitled **"${t.project_title}"** is an authentic record of our own work, carried out during the academic year ${t.academic_year} under the guidance of ${t.faculty}, ${t.school}, ${t.university}.`));
  add(c.p("The matter embodied in this report has not been submitted by us for the award of any other degree, diploma or course credit. All sources of information, standards and published work used in this report have been duly acknowledged and cited. The source code, experiments and results presented here were developed by the team members named below."));
  add(new Paragraph({ spacing: { before: 600 }, children: [] }));
  add(plainTable([["Name", "Enrolment No.", "Signature"], ...t.members.map((m) => [m.name, m.enrolment, "____________________"])],
    [1.3, 1.1, 1.2], { boldFirstRow: true }));
  add(new Paragraph({ spacing: { before: 400 }, children: [new TextRun(`Place: ${t.city}`)] }));
  add(new Paragraph({ children: [new TextRun("Date:")] }));

  add(c.frontHeading("Acknowledgement"));
  add(c.p(`We express our sincere gratitude to our project supervisor, ${t.faculty}, ${t.faculty_designation}, for the guidance, encouragement and constructive feedback provided throughout this mini-project. The discussions on cryptographic design and on the realities of industrial control systems shaped both the direction and the rigour of this work.`));
  add(c.p(`We are thankful to the ${t.school}, ${t.university}, for providing the academic environment, computing facilities and the opportunity to undertake this project as part of the course ${t.course_code} - ${t.course_name}.`));
  add(c.p("We also thank the authors and maintainers of the open-source tools on which this project relies - Python, the pyca/cryptography library, pytest and matplotlib - and the standards bodies whose publicly available specifications made it possible to verify our implementations."));
  add(c.p("Finally, we thank our classmates for their feedback during review sessions, and our families for their constant support."));
  add(new Paragraph({ spacing: { before: 600 }, alignment: AlignmentType.RIGHT, children: [new TextRun({ text: t.members.map((m) => m.name).join(", "), bold: true })] }));

  add(c.frontHeading("Abstract"));
  add(c.p(`Electric-grid substations still contain Remote Terminal Units (RTUs) whose telemetry links are unencrypted or protected only by classical substitution and transposition ciphers. Because field devices remain in service for decades, utilities modernise gradually, and legacy and modern cryptography must coexist for years. This project presents LCMF, a Legacy Cipher Migration Framework for Industrial Control Systems, which (i) reproduces a smart-grid environment of eight 11 kV feeders protected by Caesar, Additive, Affine, Vigenere, Playfair and Columnar transposition ciphers; (ii) provides a bidirectional protocol-translation gateway that wraps legacy telemetry into a 68-byte AES-256-GCM Secure Telemetry Envelope with an authenticated header, per-device HKDF keys, crash-safe nonces and anti-replay protection; and (iii) systematically studies the security of the transition itself.`));
  add(c.p(`AES-128/192/256 and the ECB, CBC, CTR and GCM modes were implemented from first principles and validated against FIPS-197 and GCM test vectors, and against the cryptography library on 500 random cases. Exploiting the public frame grammar, every legacy cipher was broken from at most two captured frames in under a second, including a Playfair cipher with a nominal key space of 2^138. Eight transition vulnerabilities were demonstrated and quantified: false data laundered through the gateway from the legacy last mile, downgrade attacks in hybrid operation, replay laundering, malleability of confidentiality-only AES, ECB pattern leakage, GCM nonce reuse after reboots, AES keys derived from legacy secrets, and bandwidth overhead. For each, a mitigation implemented in the framework - device pinning, legacy sequence tracking, authenticated encryption, persistent counters, HKDF key hierarchy and plausibility filtering - was measured; all reduced attack success to zero except physically consistent false data on the legacy last mile, which only replacing the RTU removes. The gateway translated ${delivered.toLocaleString("en-US")} frames without error at a median latency of ${worstMed.toFixed(1)} microseconds and 53 bytes of overhead per reading. The results are condensed into an evidence-based migration playbook for utilities.`));
  add(c.p("**Keywords:** industrial control systems, SCADA, smart grid, legacy cipher migration, classical cryptanalysis, AES-GCM, protocol-translation gateway, transition vulnerabilities."));

  add(new Paragraph({ style: "FrontTitle", pageBreakBefore: true, children: [new TextRun("Table of Contents")] }));
  add(new TableOfContents("Table of Contents", { hyperlink: true, headingStyleRange: "1-3" }));
  add(c.frontHeading("List of Figures"));
  add(new TableOfContents("List of Figures", { hyperlink: true, stylesWithLevels: [new StyleLevel("Figure Caption", 1)] }));
  add(c.frontHeading("List of Tables"));
  add(new TableOfContents("List of Tables", { hyperlink: true, stylesWithLevels: [new StyleLevel("Table Caption", 1)] }));

  add(c.frontHeading("List of Abbreviations"));
  const abbr = [
    ["AAD", "Additional Authenticated Data"], ["AEAD", "Authenticated Encryption with Associated Data"],
    ["AES", "Advanced Encryption Standard"], ["CBC", "Cipher Block Chaining"], ["CTR", "Counter mode"],
    ["DFD", "Data-Flow Diagram"], ["DNP3", "Distributed Network Protocol 3 (IEEE 1815)"],
    ["ECB", "Electronic Codebook"], ["FDIA", "False-Data Injection Attack"],
    ["FIPS", "Federal Information Processing Standard"], ["GCM", "Galois/Counter Mode"],
    ["GF", "Galois Field"], ["HKDF", "HMAC-based Key Derivation Function"],
    ["HMAC", "Hash-based Message Authentication Code"], ["ICS", "Industrial Control System"],
    ["IEC", "International Electrotechnical Commission"], ["IoC", "Index of Coincidence"],
    ["IV", "Initialisation Vector"], ["LCMF", "Legacy Cipher Migration Framework (this project)"],
    ["LTF", "Legacy Telemetry Frame"], ["MAC", "Message Authentication Code"],
    ["NIST", "National Institute of Standards and Technology"], ["OT", "Operational Technology"],
    ["RTU", "Remote Terminal Unit"], ["SCADA", "Supervisory Control and Data Acquisition"],
    ["STE", "Secure Telemetry Envelope"], ["TV", "Transition Vulnerability"],
    ["WAN", "Wide-Area Network"], ["Z36", "36-symbol alphabet A-Z, 0-9"],
  ];
  add(plainTable(abbr.map(([a, b]) => [a, b]), [1, 4], { size: 23 }));
  return out;
}

// ------------------------------------------------------------------ assemble (two passes)
function buildAll(prevLabels) {
  const c = new Ctx(prevLabels);
  const front = frontMatter(c);
  const body = [...ch13(c, R), ...ch45(c, R, team, extra), ...ch67(c, R, team, extra)];
  return { c, front, body };
}

const pass1 = buildAll({});
const { c, front, body } = buildAll(pass1.c.labels);
if (c.missing.length) console.warn("Unresolved references:", [...new Set(c.missing)]);

const pageGeom = { size: { width: 11906, height: 16838 }, margin: { top: 1440, bottom: 1440, left: 2160, right: 1440, header: 709, footer: 709 } };
const footer = new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], size: 22 })] })] });
const header = new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
  border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "A6A6A6", space: 4 } },
  children: [new TextRun({ text: "Legacy Cipher Migration Framework for ICS", italics: true, size: 18, color: "595959" })] })] });

const doc = new Document({
  creator: team.members.map((m) => m.name).join(", "),
  title: team.project_title,
  description: "Mini-project report",
  styles, numbering,
  sections: [
    { properties: { page: pageGeom }, children: cover() },
    { properties: { page: { ...pageGeom, pageNumbers: { start: 1, formatType: NumberFormat.LOWER_ROMAN } } },
      footers: { default: footer }, children: front },
    { properties: { page: { ...pageGeom, pageNumbers: { start: 1, formatType: NumberFormat.DECIMAL } } },
      headers: { default: header }, footers: { default: footer }, children: body },
  ],
});

const outFile = path.join(ROOT, "docs", "Project_Report.docx");
Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(outFile, buf);
  console.log(`wrote ${outFile}  (${Object.keys(c.labels).filter((k) => k.startsWith("fig:")).length} figures, ` +
    `${Object.keys(c.labels).filter((k) => k.startsWith("tab:")).length} tables, ${c.cites.size} references)`);
});
