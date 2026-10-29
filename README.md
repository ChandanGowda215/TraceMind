# Trace Mind — merged application

This package keeps the original Trace Mind welcome page, sign-in/sign-up flow, and visual design while replacing the dashboard with the dashboard from TraceMind-updated and serving its incident-analysis backend. The existing user/session tables and `incidentiq_session` cookie are retained. The app binds to `127.0.0.1`; uploaded telemetry and investigations remain in server memory and reset on restart.

## Run on Windows

1. Install Python 3.10+.
2. Extract the ZIP and open the extracted `trace-mind` folder.
3. Double-click `run.bat`.
4. Create an account or sign in at the original welcome/login pages. The dashboard opens after login.

The launcher creates `.venv`, installs `requirements.txt`, and starts the merged app at `http://127.0.0.1:8000`. Keep the terminal open while using it; press Ctrl+C to stop the server. You can also use the project terminal:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

When merged into the supplied app folder, the existing local `incidentiq.db` continues to store account and session data; a fresh ZIP extraction creates the same database on first run. `INCIDENTIQ_DB` can point to another SQLite file. The analysis engine, upload previews, and investigation history use the analyzed backend's in-memory process model.

## Preserved and integrated features

- Original Trace Mind welcome screen, animated illustration, login and signup pages.
- The original dashboard is replaced at `/app` with the analyzed TraceMind-updated dashboard and its existing navigation: Overview, Investigate Incident, Timeline & Evidence, Root-Cause Analysis, Service Map, Reports & Evaluation, and Settings.
- Deterministic offline evidence parsing, timeline construction, signal correlation, and heuristic root-cause ranking.
- Evidence IDs attached to supporting and contradictory observations; clickable evidence details; missing-evidence reporting; no causal claims marked verified.
- Sample scenarios for connection-pool exhaustion, deployment regression, resource/memory pressure, and sparse evidence.
- `.log`, `.txt`, and `.csv` upload preview, malformed-record reporting, UTF-8 BOM handling, source line references, and a 2 MB upload limit.
- Three-dimensional dependency map, with a 2D fallback; suspected paths remain explicitly unverified.
- Investigation report exports in JSON, Markdown, CSV, and print/PDF; simulated-scenario evaluation.
- Optional OpenRouter AI explanation from the server. The API key remains server-side and is sent using a Bearer authorization header; deterministic analysis works without the key.

## Optional AI setup

Copy `.env.example` to `.env` in the project root and set your own `OPENROUTER_API_KEY`. Optionally set `OPENROUTER_MODEL`. Never share or commit `.env`. Without a key, all deterministic analysis and reports remain available.

## Supported input

Uploads accept `.log`, `.txt`, and `.csv` files up to 2 MB. Text log lines use:

```text
2026-10-28T10:32:01Z ERROR payment-service log: Database connection timeout
```

CSV headers should include timestamp, severity/level, service, type, and message. JSON-lines records can include equivalent fields. Source records are normalized to UTC; malformed records and warnings are returned in the upload preview. Built-in service topology and scenario labels are synthetic. Replace or supplement these with the architecture and fault-injection data for your environment before drawing operational conclusions.

## Tests

```powershell
cd backend
python -m pytest app/tests -q
cd ..
python -m unittest discover -s tests -v
```

Investigation scores are heuristic rankings, not probabilities. Timing and shared dependencies do not prove causation. The AI output is an unverified interpretation; it does not replace the deterministic evidence references.
