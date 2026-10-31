@echo off
REM Regenerates EVERYTHING from source: tests, results, figures, report (DOCX + PDF) and slides (PPTX + PDF).
REM Requirements: Python 3.10+, Node.js 18+, Microsoft Word and PowerPoint (for the PDF export step).
REM Edit docs\build\team_config.json first to put in your names, enrolment numbers and course details.
cd /d "%~dp0"
if not exist results mkdir results

echo === [1/7] Python dependencies ===
python -m pip install -q -r requirements.txt

echo === [2/7] Test suite ===
python -m pytest --collect-only > results\test_collect.txt
python -m pytest > results\test_report.txt
type results\test_report.txt

echo === [3/7] Experiments (results\*.json) ===
python -m lcmf experiments

echo === [4/7] Demo transcript ===
python -m lcmf demo > results\demo_output.txt

echo === [5/7] Figures ===
python scripts\generate_figures.py

echo === [6/7] Report and slides ===
pushd docs\build
if not exist node_modules call npm install --no-audit --no-fund
node build_report.js
node build_slides.js
popd

echo === [7/7] PDF export via Word / PowerPoint ===
python docs\build\export_pdf.py

echo.
echo Done. See docs\Project_Report.docx/.pdf and docs\Presentation.pptx/.pdf
