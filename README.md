# LCMF - Legacy Cipher Migration Framework for Industrial Control Systems

A protocol-translation gateway that wraps legacy, unencrypted or classically encrypted
smart-grid telemetry (Caesar, Additive, Affine, Vigenere, Playfair, Columnar) into
**AES-256-GCM** envelopes, plus a reproducible study of the security vulnerabilities that
appear **during the transition** from legacy to modern cryptography.

## Deliverables

| What | Where |
|---|---|
| Source code (Python package) | `lcmf/` |
| Automated tests (63) | `tests/` |
| Experiment results (single source of truth) | `results/*.json` |
| Figures (17) | `docs/figures/` |
| **Project report** (67 pages, Word + PDF) | `docs/Project_Report.docx`, `docs/Project_Report.pdf` |
| **Presentation** (24 slides with speaker notes) | `docs/Presentation.pptx`, `docs/Presentation.pdf` |
| Viva / presentation guide | `docs/Viva_Guide.md` |
| Team details (edit this) | `docs/build/team_config.json` |

## Quick start

```bat
pip install -r requirements.txt
python -m pytest                      :: 63 tests
python -m lcmf demo --interactive     :: guided demonstration of every module
```

Or double-click **`run_demo.bat`** (installs, tests, regenerates results, runs the demo).

| Command | Shows |
|---|---|
| `python -m lcmf demo [--interactive]` | All modules end to end (used in the viva) |
| `python -m lcmf cipher affine encrypt RTU01SEQ0001 --a 5 --b 8` | Any legacy cipher (`--z26` for textbook A-Z) |
| `python -m lcmf attack` | Key recovery for every legacy cipher |
| `python -m lcmf simulate --mode STRICT_AES --polls 3` | Grid + gateway + SCADA in a migration phase |
| `python -m lcmf transition` | Raw TV1-TV8 results |
| `python -m lcmf experiments` | Regenerates `results/*.json` and the objectives table |

## Working on it as a team

```bat
git clone https://github.com/aryan-guptta-2007/legacy-cipher-migration-ics.git
cd legacy-cipher-migration-ics
pip install -r requirements.txt
python -m pytest                      :: must stay green before you push
```

* Work on your own module (see *Project structure* below) on a branch, then open a pull request:
  `git checkout -b member2-gcm-notes`, commit, `git push -u origin member2-gcm-notes`.
* Run `python -m pytest` before every push; keep module sizes balanced so the contribution split stays even.
* To rebuild the report and slides you also need Node.js 18+ (`npm install` inside `docs/build`, which
  `build_all.bat` does for you) and MS Word / PowerPoint for the PDF export.
* `results/*.json` is the single source of truth for every number in the report and slides - regenerate it
  with `python -m lcmf experiments` instead of editing numbers by hand.

## Putting in your names (do this before submitting)

1. Open `docs/build/team_config.json` and replace every `[bracketed]` value: university, programme,
   semester, course code/name, faculty, city, and each member's name and enrolment number.
2. Run **`build_all.bat`** (needs Python, Node.js 18+, MS Word and PowerPoint). It re-runs the tests and
   experiments, redraws the figures and regenerates the report and slides (DOCX/PPTX and PDF), so your
   names appear on the cover page, certificate, declaration, contribution appendix and slides.
3. Add your university logo on the cover page in Word (the `[ University Logo ]` placeholder).

## Project structure

```
lcmf/classical/   legacy cipher suite (Z36 alphabet, 6x6 Playfair)            Member 1
lcmf/analysis/cryptanalysis.py  key-recovery attacks, IoC, Kasiski, chi^2     Member 1
scripts/generate_figures.py     figure pipeline                                 Member 1
lcmf/modern/      AES from scratch, ECB/CBC/CTR/GCM, AEAD, HKDF, nonces, replay Member 2
lcmf/gateway/envelope.py        68-byte Secure Telemetry Envelope               Member 2
lcmf/analysis/transition_crypto.py, experiments.py, benchmark.py                Member 2
lcmf/grid/        telemetry model, legacy frame codec, feeder/RTU sim, SCADA    Member 3
lcmf/gateway/     translation gateway, migration policy, plausibility filter    Member 3
lcmf/analysis/transition_system.py, lcmf/cli.py                                 Member 3
docs/build/       report + slide generators (Node.js), PDF export (Word COM)
```

## Key results (from `results/summary.json`)

* All 15 published test vectors pass; educational AES-GCM is bit-identical to the `cryptography`
  library on 500/500 random cases; 70,000 legacy round trips with 0 failures.
* Every legacy cipher is broken from at most 2 captured frames in well under a second.
* 14,400 frames translated across 4 migration modes with 0 corrupted readings; median gateway
  latency of a few tens of microseconds; 53 bytes of overhead per reading.
* Eight transition vulnerabilities (TV1-TV8) demonstrated and each paired with a measured mitigation.

## How the project addresses the evaluation rubric

| Criterion | Sub-criterion | Where it is satisfied |
|---|---|---|
| Problem Analysis | Problem domain identification and analysis | Report Ch. 1 (background, motivation, problem statement), Sec. 3.1 domain-analysis table, 3.2 threat model |
| | Review of existing systems and feasibility | Ch. 2 literature review with comparison table (Table 2.1) and research gap; Sec. 3.6 technical / economic / operational / schedule (Gantt) / legal feasibility |
| Project Design | Objectives and methodology | Sec. 1.4 seven **measurable** objectives (O1-O7); Sec. 4.1 build-attack-mitigate-measure methodology; requirements FR1-FR11, NFR1-NFR7 |
| | Relevance of algorithms / techniques | Ch. 4 design of every algorithm; Table 4.6 justification of each technique against alternatives |
| Implementation | Synchronisation of design and implementation | Sec. 5.5 traceability matrix (requirement -> design -> code -> test -> evidence); diagrams annotated with module names; code listings extracted live from the source |
| | Implementation and demonstration of modules | 63 passing tests; `python -m lcmf demo`; Sec. 5.7 per-module demo table; Appendix C demo transcript |
| Project Report | Organisation and structure | Front matter, 7 chapters, references, 3 appendices; auto-generated TOC, list of figures, list of tables |
| | Compliance with prescribed format | A4; Times New Roman 12 pt; 1.5 line spacing; margins 1.5" left / 1" others; roman page numbers for front matter, arabic from Ch. 1; chapter-wise figure/table numbering; IEEE references |
| Communication | Clarity and organisation of presentation | 24-slide deck with sections per presenter, speaker notes, native charts; `docs/Viva_Guide.md` |
| | Contribution by each member | Balanced module ownership (about 1,200-1,300 lines each); Appendix B tables; slide 23; every member presents their own module |

> The report follows the common university mini-project format because no departmental template was
> provided. If your department prescribes a different template (margins, fonts, chapter names), change
> the values in `docs/build/lib.js` (styles, page geometry) and rerun `build_all.bat`.
