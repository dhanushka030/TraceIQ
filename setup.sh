#!/usr/bin/env bash
# NetSentry TraceIQ - one-command setup for Linux and macOS.
# Creates .venv, installs requirements, checks for Nmap, runs the tests, then starts the app on port 5000.
# Set NO_RUN=1 to stop after the tests instead of starting the server.
set -euo pipefail
cd "$(dirname "$0")"

PY=""
for candidate in python3.13 python3.12 python3.11 python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then PY="$candidate"; break; fi
done
if [ -z "$PY" ]; then echo "[error] Python 3.11 or newer is required." >&2; exit 1; fi

echo "[1/5] Creating virtual environment in .venv"
[ -x .venv/bin/python ] || "$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[2/5] Installing requirements"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

echo "[3/5] Checking for Nmap"
if command -v nmap >/dev/null 2>&1; then
  echo "       Nmap found at $(command -v nmap)"
else
  echo "[note] Nmap was not found. TraceIQ will use its built-in TCP scanner."
  echo "       For deeper scans install it: Debian/Ubuntu 'sudo apt install nmap', macOS 'brew install nmap'."
fi

echo "[4/5] Running tests"
python -m pytest -q

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[note] Created .env from .env.example. Paste your Firebase keys into .env, then run ./setup.sh again."
  [ "${NO_RUN:-0}" = "1" ] && exit 0 || exit 2
fi

if [ "${NO_RUN:-0}" = "1" ]; then echo "[5/5] Skipped starting the app because NO_RUN=1."; exit 0; fi
echo "[5/5] Starting NetSentry TraceIQ on http://127.0.0.1:5000  (Ctrl+C to stop)"
echo "       Try the sample assessment at http://127.0.0.1:5000/?demo=1"
exec python app.py
