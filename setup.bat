@echo off
REM NetSentry TraceIQ - one-command setup for Windows.
REM Creates .venv, installs requirements, checks for Nmap, runs the tests, then starts the app on port 5000.
REM Set NO_RUN=1 to stop after the tests instead of starting the server.
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo [error] Python 3.11 or newer is required. Install it from https://www.python.org/downloads/ and run this script again.
  exit /b 1
)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
  echo [error] Python 3.11 or newer is required.
  exit /b 1
)

echo [1/5] Creating virtual environment in .venv
if not exist ".venv\Scripts\python.exe" (
  %PY% -m venv .venv
  if errorlevel 1 exit /b 1
)
call ".venv\Scripts\activate.bat"

echo [2/5] Installing requirements
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if errorlevel 1 (
  echo [error] pip install failed. Check your internet connection and try again.
  exit /b 1
)

echo [3/5] Checking for Nmap
where nmap >nul 2>&1
if errorlevel 1 (
  echo [note] Nmap was not found. TraceIQ will use its built-in TCP scanner.
  echo        For deeper scans install Nmap from https://nmap.org/download and add it to PATH, then restart this terminal.
) else (
  echo        Nmap found.
)

echo [4/5] Running tests
python -m pytest -q
if errorlevel 1 (
  echo [error] Tests failed. Fix them before running the app.
  exit /b 1
)

if "%NO_RUN%"=="1" (
  echo [5/5] Skipped starting the app because NO_RUN=1.
  exit /b 0
)
echo [5/5] Starting NetSentry TraceIQ on http://127.0.0.1:5000  (Ctrl+C to stop)
echo        Try the sample assessment at http://127.0.0.1:5000/?demo=1
python app.py
endlocal
