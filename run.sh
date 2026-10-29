#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cd backend
exec python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
