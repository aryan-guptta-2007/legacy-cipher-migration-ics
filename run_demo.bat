@echo off
REM One-click demonstration for the project viva (Windows).
REM   1. installs dependencies   2. runs the 63 unit/integration tests
REM   3. regenerates all results 4. runs the guided demo
cd /d "%~dp0"
echo === Installing dependencies ===
python -m pip install -q -r requirements.txt
echo.
echo === Running test suite ===
python -m pytest
echo.
echo === Regenerating experiment results (results\*.json) ===
python -m lcmf experiments
echo.
echo === Guided demonstration ===
python -m lcmf demo --interactive
pause
