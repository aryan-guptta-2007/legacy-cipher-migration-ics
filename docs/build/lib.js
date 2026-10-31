// Shared helpers for build_report.js: page geometry, styles, inline markup,
// IEEE citations, figure/table numbering (two-pass), code listings from source.
"use strict";
const fs = require("fs");
const path = require("path");
const D = require("docx");
const {
  Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell, WidthType, BorderStyle,
  ShadingType, ImageRun, TabStopType, LevelFormat, VerticalAlign, PageBreak,
} = D;

const ROOT = path.resolve(__dirname, "..", "..");
const FONT = "Times New Roman";
const MONO = "Courier New";
const TEXT_W = 8306;                  // A4 (11906) - 1.5" left (2160) - 1" right (1440), in DXA
const LINE_15 = 360;                  // 1.5 line spacing
const GRID = "A6A6A6";
const HEAD_FILL = "E7E6E6";

function readJSON(rel) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, rel), "utf8"));
}

function pngSize(file) {
  const b = fs.readFileSync(file);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

// ---------------------------------------------------------------- styles
const styles = {
  default: { document: { run: { font: FONT, size: 24 }, paragraph: { spacing: { line: LINE_15 } } } },
  paragraphStyles: [
    { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { font: FONT, size: 32, bold: true, allCaps: true },
      paragraph: { alignment: AlignmentType.CENTER, spacing: { before: 0, after: 360, line: 276 }, outlineLevel: 0 } },
    { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { font: FONT, size: 28, bold: true },
      paragraph: { spacing: { before: 300, after: 120, line: 276 }, outlineLevel: 1, keepNext: true } },
    { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { font: FONT, size: 24, bold: true },
      paragraph: { spacing: { before: 200, after: 80, line: 276 }, outlineLevel: 2, keepNext: true } },
    { id: "FrontTitle", name: "Front Title", basedOn: "Normal", next: "Normal",
      run: { font: FONT, size: 32, bold: true, allCaps: true },
      paragraph: { alignment: AlignmentType.CENTER, spacing: { after: 360, line: 276 } } },
    { id: "FigureCaption", name: "Figure Caption", basedOn: "Normal", next: "Normal",
      run: { font: FONT, size: 22, bold: false },
      paragraph: { alignment: AlignmentType.CENTER, spacing: { before: 60, after: 240, line: 276 } } },
    { id: "TableCaption", name: "Table Caption", basedOn: "Normal", next: "Normal",
      run: { font: FONT, size: 22 },
      paragraph: { alignment: AlignmentType.CENTER, spacing: { before: 200, after: 80, line: 276 }, keepNext: true } },
    { id: "ListingCaption", name: "Listing Caption", basedOn: "Normal", next: "Normal",
      run: { font: FONT, size: 22 },
      paragraph: { alignment: AlignmentType.LEFT, spacing: { before: 160, after: 60, line: 276 }, keepNext: true } },
    { id: "Code", name: "Code", basedOn: "Normal", next: "Normal",
      run: { font: MONO, size: 16 },
      paragraph: { spacing: { before: 0, after: 0, line: 240 } } },
    { id: "TableText", name: "Table Text", basedOn: "Normal", next: "Normal",
      run: { font: FONT, size: 20 },
      paragraph: { spacing: { before: 30, after: 30, line: 252 } } },
  ],
};

const numbering = {
  config: [
    { reference: "bullets", levels: [
      { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } } },
      { level: 1, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 1440, hanging: 360 } } } },
    ] },
    { reference: "numbers", levels: [
      { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } } },
    ] },
  ],
};

// ---------------------------------------------------------------- builder context
class Ctx {
  constructor(prevLabels) {
    this.prev = prevLabels || {};     // labels from pass 1 (for forward references)
    this.labels = {};
    this.cites = new Map();           // key -> number, in order of first citation
    this.chapter = 0;
    this.fig = 0;
    this.tab = 0;
    this.lst = 0;
    this.numInstance = 0;
    this.missing = [];
  }

  setChapter(n) { this.chapter = n; this.fig = 0; this.tab = 0; this.lst = 0; }

  ref(id) {
    const v = this.labels[id] || this.prev[id];
    if (!v) { this.missing.push(id); return "??"; }
    return v;
  }

  cite(keys) {
    return keys.split(",").map((k) => k.trim()).map((k) => {
      if (!this.cites.has(k)) this.cites.set(k, this.cites.size + 1);
      return `[${this.cites.get(k)}]`;
    }).join(", ");
  }

  // Inline markup: **bold**, *italic*, ~code~, [@key1,key2] citations, {fig:id} references.
  runs(text, base = {}) {
    const out = [];
    const re = /(\*\*[^*]+\*\*|\*[^*]+\*|~[^~]+~|\[@[^\]]+\]|\{(?:fig|tab|lst|eq):[^}]+\})/g;
    let last = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) out.push(new TextRun({ text: text.slice(last, m.index), ...base }));
      const tok = m[0];
      if (tok.startsWith("**")) out.push(new TextRun({ text: tok.slice(2, -2), bold: true, ...base }));
      else if (tok.startsWith("~")) out.push(new TextRun({ text: tok.slice(1, -1), font: MONO, size: (base.size || 24) - 3 }));
      else if (tok.startsWith("[@")) out.push(new TextRun({ text: this.cite(tok.slice(2, -1)), ...base }));
      else if (tok.startsWith("{")) out.push(new TextRun({ text: this.ref(tok.slice(1, -1)), ...base }));
      else out.push(new TextRun({ text: tok.slice(1, -1), italics: true, ...base }));
      last = m.index + tok.length;
    }
    if (last < text.length) out.push(new TextRun({ text: text.slice(last), ...base }));
    return out;
  }

  p(text, opts = {}) {
    return new Paragraph({
      children: this.runs(text, opts.run || {}),
      alignment: opts.align || AlignmentType.JUSTIFIED,
      spacing: { after: 120, line: LINE_15, ...(opts.spacing || {}) },
      indent: opts.indent,
      keepNext: opts.keepNext,
      style: opts.style,
    });
  }

  bullets(items, level = 0) {
    return items.map((t) => new Paragraph({
      children: this.runs(t), numbering: { reference: "bullets", level },
      alignment: AlignmentType.JUSTIFIED, spacing: { after: 60, line: LINE_15 },
    }));
  }

  numbered(items) {
    this.numInstance += 1;
    const inst = this.numInstance;
    return items.map((t) => new Paragraph({
      children: this.runs(t), numbering: { reference: "numbers", level: 0, instance: inst },
      alignment: AlignmentType.JUSTIFIED, spacing: { after: 60, line: LINE_15 },
    }));
  }

  chapterHeading(n, title) {
    this.setChapter(n);
    return new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true,
      children: [new TextRun(`Chapter ${n}: ${title}`)] });
  }

  frontHeading(title, pageBreak = true) {
    return new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: pageBreak, children: [new TextRun(title)] });
  }

  h2(num, title) { return new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(`${num}  ${title}`)] }); }
  h3(num, title) { return new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(`${num}  ${title}`)] }); }

  figure(id, file, caption, widthIn = 5.75) {
    this.fig += 1;
    const label = `Figure ${this.chapter}.${this.fig}`;
    this.labels[`fig:${id}`] = label;
    const full = path.join(ROOT, "docs", "figures", file);
    const { w, h } = pngSize(full);
    const pxW = Math.round(widthIn * 96);
    const pxH = Math.round(pxW * h / w);
    return [
      new Paragraph({ alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 120, after: 0, line: 240 },
        children: [new ImageRun({ type: "png", data: fs.readFileSync(full), transformation: { width: pxW, height: pxH },
          altText: { title: label, description: caption, name: id } })] }),
      new Paragraph({ style: "FigureCaption", children: [new TextRun({ text: `${label}: `, bold: true }), ...this.runs(caption, { size: 22 })] }),
    ];
  }

  // cols: array of relative widths; rows: array of arrays of strings (inline markup allowed)
  table(id, caption, headers, rows, cols, opts = {}) {
    this.tab += 1;
    const label = `Table ${this.chapter}.${this.tab}`;
    this.labels[`tab:${id}`] = label;
    const total = cols.reduce((a, b) => a + b, 0);
    const widths = cols.map((c) => Math.floor((TEXT_W * c) / total));
    widths[widths.length - 1] = TEXT_W - widths.slice(0, -1).reduce((a, b) => a + b, 0);
    const border = { style: BorderStyle.SINGLE, size: 4, color: GRID };
    const borders = { top: border, bottom: border, left: border, right: border };
    const size = opts.size || 20;
    const cell = (text, w, header, align) => new TableCell({
      width: { size: w, type: WidthType.DXA }, borders, verticalAlign: VerticalAlign.CENTER,
      margins: { top: 50, bottom: 50, left: 90, right: 90 },
      shading: header ? { fill: HEAD_FILL, type: ShadingType.CLEAR, color: "auto" } : undefined,
      children: String(text).split("\n").map((line) => new Paragraph({ style: "TableText",
        alignment: align || (header ? AlignmentType.CENTER : AlignmentType.LEFT),
        children: this.runs(line, header ? { bold: true, size } : { size }) })),
    });
    // align shorthand: 1 = centre, 2 = right (numeric codes are not valid OOXML values)
    const amap = { 1: AlignmentType.CENTER, 2: AlignmentType.RIGHT };
    const aligns = (opts.align || []).map((a) => (typeof a === "number" ? amap[a] : a));
    const trs = [new TableRow({ tableHeader: true, cantSplit: true,
      children: headers.map((h, i) => cell(h, widths[i], true)) })];
    rows.forEach((r) => trs.push(new TableRow({ cantSplit: true,
      children: r.map((c, i) => cell(c, widths[i], false, aligns[i])) })));
    return [
      new Paragraph({ style: "TableCaption", children: [new TextRun({ text: `${label}: `, bold: true }), ...this.runs(caption, { size: 22 })] }),
      new Table({ width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: widths, rows: trs }),
      new Paragraph({ spacing: { after: 120, line: 240 }, children: [] }),
    ];
  }

  listing(id, caption, lines, size = 16) {
    this.lst += 1;
    const label = `Listing ${this.chapter}.${this.lst}`;
    this.labels[`lst:${id}`] = label;
    const shade = { fill: "F2F2F2", type: ShadingType.CLEAR, color: "auto" };
    const out = [new Paragraph({ style: "ListingCaption", children: [new TextRun({ text: `${label}: `, bold: true }), ...this.runs(caption, { size: 22 })] })];
    lines.forEach((ln, i) => out.push(new Paragraph({ style: "Code", shading: shade, keepNext: i < lines.length - 1,
      children: [new TextRun({ text: ln.length ? ln : " ", font: MONO, size })] })));
    out.push(new Paragraph({ spacing: { after: 120, line: 240 }, children: [] }));
    return out;
  }

  equation(id, text) {
    const n = (this.labels[`eqc:${this.chapter}`] || 0) + 1;
    this.labels[`eqc:${this.chapter}`] = n;
    const label = `(${this.chapter}.${n})`;
    this.labels[`eq:${id}`] = `Eq. ${label}`;
    return new Paragraph({
      tabStops: [{ type: TabStopType.CENTER, position: Math.round(TEXT_W / 2) }, { type: TabStopType.RIGHT, position: TEXT_W }],
      spacing: { before: 60, after: 120, line: 276 },
      children: [new TextRun("\t"), new TextRun({ text, italics: true }), new TextRun(`\t${label}`)],
    });
  }
}

// Extract a function/method body from a Python source file (keeps the report in sync with the code).
function extract(relFile, marker, maxLines = 40) {
  const lines = fs.readFileSync(path.join(ROOT, relFile), "utf8").replace(/\r/g, "").split("\n");
  const start = lines.findIndex((l) => l.includes(marker));
  if (start < 0) throw new Error(`marker ${marker} not found in ${relFile}`);
  const indent = lines[start].match(/^\s*/)[0].length;
  const out = [lines[start]];
  for (let i = start + 1; i < lines.length && out.length < maxLines; i++) {
    const l = lines[i];
    const ind = l.match(/^\s*/)[0].length;
    if (l.trim() && ind <= indent && !l.trim().startsWith(")") && !l.trim().startsWith("]")) break;
    out.push(l);
  }
  while (out.length && !out[out.length - 1].trim()) out.pop();
  return out.map((l) => l.slice(indent));
}

function countLines(relGlob) {
  // supports "dir/*" and plain files; counts non-blank lines
  const files = [];
  if (relGlob.endsWith("/*")) {
    const dir = path.join(ROOT, relGlob.slice(0, -2));
    fs.readdirSync(dir).filter((f) => f.endsWith(".py")).forEach((f) => files.push(path.join(dir, f)));
  } else {
    const clean = relGlob.split(" ")[0];
    files.push(path.join(ROOT, clean));
  }
  return files.reduce((n, f) => n + fs.readFileSync(f, "utf8").split("\n").filter((l) => l.trim()).length, 0);
}

module.exports = { D, Ctx, styles, numbering, readJSON, extract, countLines, ROOT, FONT, MONO, TEXT_W, LINE_15, PageBreak };
