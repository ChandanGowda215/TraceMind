"""Trace Mind API. Investigation data is in memory; login sessions persist in SQLite."""
import hashlib, hmac, json, os, re, secrets, sqlite3, time, uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from . import ai, engine

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
SAMPLES = json.loads((ROOT / "sample_data" / "labels.json").read_text())
DB_PATH = Path(os.environ.get("INCIDENTIQ_DB", ROOT / "incidentiq.db"))
app = FastAPI(title="Trace Mind", version="1.0")
UPLOADS, INVS = OrderedDict(), OrderedDict()

def fail(status, code, msg): raise HTTPException(status, detail={"error": code, "message": msg})

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def init_auth_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH, timeout=20) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL
        )""")

def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"{salt.hex()}:{digest.hex()}"

def password_matches(password, stored):
    try:
        salt, expected = stored.split(":", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310_000)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False

def session_user(token):
    if not token:
        return None
    with sqlite3.connect(DB_PATH, timeout=20) as con:
        con.row_factory = sqlite3.Row
        return con.execute(
            """SELECT users.id, users.email FROM sessions JOIN users ON users.id=sessions.user_id
               WHERE sessions.token=? AND sessions.expires_at>?""", (token, now_iso())
        ).fetchone()

@app.on_event("startup")
def startup():
    init_auth_db()

@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    public = {"/health", "/api/auth/login", "/api/auth/signup", "/api/auth/logout", "/", "/welcome", "/login", "/signup"}
    if (path.startswith("/api/") and path not in public) or path == "/app":
        if not session_user(request.cookies.get("incidentiq_session")):
            if path == "/app":
                from fastapi.responses import RedirectResponse
                return RedirectResponse("/login", status_code=303)
            return JSONResponse({"error": "unauthorized", "message": "Sign in to continue."}, status_code=401)
    return await call_next(request)

@app.get("/")
@app.get("/welcome")
def welcome_page():
    return FileResponse(ROOT / "static" / "welcome.html")

@app.get("/login")
def login_page():
    return FileResponse(ROOT / "static" / "login.html")

@app.get("/signup")
def signup_page():
    return FileResponse(ROOT / "static" / "signup.html")

@app.get("/app")
def dashboard_page():
    return FileResponse(ROOT / "dashboard_ui.html")

@app.post("/api/auth/signup")
def signup(payload: dict):
    email = str(payload.get("email", "")).strip().lower()
    password = payload.get("password", "")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        fail(422, "invalid_email", "Enter a valid email address.")
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        fail(422, "invalid_password", "Password must be between 8 and 128 characters.")
    user_id, token = "USR-" + uuid.uuid4().hex[:12], secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        with sqlite3.connect(DB_PATH, timeout=20) as con:
            con.execute("INSERT INTO users VALUES(?,?,?,?)", (user_id, email, password_hash(password), now_iso()))
            con.execute("INSERT INTO sessions VALUES(?,?,?)", (token, user_id, expires))
    except sqlite3.IntegrityError:
        fail(409, "account_exists", "An account with this email already exists.")
    response = JSONResponse({"ok": True, "email": email})
    response.set_cookie("incidentiq_session", token, httponly=True, samesite="lax", max_age=14 * 86400)
    return response

@app.post("/api/auth/login")
def login(payload: dict):
    email = str(payload.get("email", "")).strip().lower()
    password = payload.get("password", "")
    with sqlite3.connect(DB_PATH, timeout=20) as con:
        con.row_factory = sqlite3.Row
        user = con.execute("SELECT id,password_hash FROM users WHERE email=?", (email,)).fetchone()
        if not user or not isinstance(password, str) or not password_matches(password, user["password_hash"]):
            fail(401, "invalid_credentials", "Email or password is incorrect.")
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat(timespec="seconds").replace("+00:00", "Z")
        con.execute("INSERT INTO sessions VALUES(?,?,?)", (token, user["id"], expires))
    response = JSONResponse({"ok": True, "email": email})
    response.set_cookie("incidentiq_session", token, httponly=True, samesite="lax", max_age=14 * 86400)
    return response

@app.post("/api/auth/logout")
def logout(request: Request):
    token = request.cookies.get("incidentiq_session")
    if token:
        with sqlite3.connect(DB_PATH, timeout=20) as con:
            con.execute("DELETE FROM sessions WHERE token=?", (token,))
    response = JSONResponse({"ok": True})
    response.delete_cookie("incidentiq_session")
    return response

@app.get("/api/me")
def me(request: Request):
    user = session_user(request.cookies.get("incidentiq_session"))
    if not user:
        fail(401, "unauthorized", "Sign in to continue.")
    return {"id": user["id"], "email": user["email"]}

app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

@app.exception_handler(HTTPException)
async def _h(_, e):
    d = e.detail if isinstance(e.detail, dict) else {"error": "http_error", "message": str(e.detail)}
    return JSONResponse(d, status_code=e.status_code)

def load_sample(sid):
    if sid not in SAMPLES: fail(404, "unknown_sample", f"No sample incident '{sid}'.")
    p = ROOT / "sample_data" / SAMPLES[sid]["file"]
    return engine.parse(p.read_text(), p.name)

def preview(name, evs, stats, **extra):
    return {"name": name, **extra, "stats": stats, "total": len(evs), "events": [{k: e[k] for k in ("id", "ts", "severity", "sev", "service", "type", "message")} for e in evs[:80]]}

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/api/incidents")
def incidents(): return [{"id": k, "name": v["name"], "description": v["description"], "simulated": True} for k, v in SAMPLES.items()]

@app.get("/api/incidents/{sid}/preview")
def sample_preview(sid):
    evs, st = load_sample(sid); return preview(SAMPLES[sid]["name"], evs, st)

@app.post("/api/incidents/upload")
async def upload(file: UploadFile = File(...)):
    name = file.filename or "upload"
    if not name.lower().endswith((".log", ".txt", ".csv")): fail(400, "unsupported_type", "Only .log, .txt and .csv files are supported.")
    data = await file.read(engine.MAX_BYTES + 1)
    if len(data) > engine.MAX_BYTES: fail(413, "too_large", "File is larger than 2 MB.")
    try: evs, st = engine.parse(data.decode("utf-8-sig"), name)
    except UnicodeDecodeError: fail(400, "bad_encoding", "File must be UTF-8 text.")
    except engine.IngestError as e: fail(413, "too_large", str(e))
    if not evs: fail(422, "no_valid_records", f"No valid records found ({st['rejected']} rejected). Expected '<timestamp> <LEVEL> <service> <type>: <message>', JSON lines, or CSV.")
    uid = uuid.uuid4().hex[:10]; UPLOADS[uid] = (name, evs, st)
    while len(UPLOADS) > 20: UPLOADS.popitem(last=False)
    return preview(name, evs, st, upload_id=uid)

class InvReq(BaseModel):
    sample_id: str | None = None
    upload_id: str | None = None
    start: str | None = None
    end: str | None = None
    min_score: float = 0.35
    window_min: int = 30

@app.post("/api/investigations")
def investigate(req: InvReq):
    if bool(req.sample_id) == bool(req.upload_id): fail(400, "bad_request", "Provide exactly one of sample_id or upload_id.")
    t0 = time.perf_counter()
    if req.sample_id: evs, st = load_sample(req.sample_id); name, kind = SAMPLES[req.sample_id]["name"], "sample (simulated)"
    else:
        if req.upload_id not in UPLOADS: fail(404, "unknown_upload", "Upload not found; upload the file again.")
        name, evs, st = UPLOADS[req.upload_id]; kind = "upload"
    try: evs = engine.filter_range(evs, req.start, req.end)
    except Exception: fail(400, "bad_range", "Invalid start/end time.")
    if not evs: fail(422, "empty_range", "No records fall inside the selected time range.")
    res = engine.analyze(evs, {"min_score": req.min_score, "window_min": max(1, req.window_min)})
    iid = uuid.uuid4().hex[:8]
    inv = {"id": iid, "source": {"name": name, "kind": kind}, "stats": st, "events": evs, **res, "ai": None, "duration_ms": round((time.perf_counter() - t0) * 1000, 1)}
    INVS[iid] = inv
    while len(INVS) > 50: INVS.popitem(last=False)
    return inv

def get_inv(i):
    if i not in INVS: fail(404, "unknown_investigation", "Investigation not found (sessions reset on restart).")
    return INVS[i]

@app.get("/api/investigations/{i}")
def inv_get(i): return get_inv(i)
@app.get("/api/investigations/{i}/timeline")
def inv_tl(i): return get_inv(i)["events"]
@app.get("/api/investigations/{i}/evidence")
def inv_ev(i): v = get_inv(i); return {"correlations": v["correlations"], "missing_evidence": v["missing_evidence"]}
@app.get("/api/investigations/{i}/hypotheses")
def inv_h(i): v = get_inv(i); return {"verdict": v["verdict"], "hypotheses": v["hypotheses"]}

@app.post("/api/investigations/{i}/ai-analysis")
async def inv_ai(i):
    v = get_inv(i)
    try: v["ai"] = await ai.analyze_ai(v)
    except ai.AIError as e:
        code = {"no_key": 503, "invalid_key": 502, "credits": 502, "rate_limit": 429, "timeout": 504}.get(e.code, 502)
        fail(code, e.code, e.message)
    return v["ai"]

@app.get("/api/investigations/{i}/report")
def report(i):
    v = get_inv(i)
    return {"tool": "TraceMind", "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "verification_status": "No root cause has been independently verified.",
            "investigation": {k: v[k] for k in v if k != "events"}, "timeline": v["events"],
            "limitations": ["Heuristic scores are rankings, not probabilities.", "Correlation and timing do not prove causation.", "Sample topology used unless dependency data is supplied.", "AI output (if any) is an unverified interpretation."]}

@app.get("/api/investigations")
def history(): return [{"id": v["id"], "source": v["source"], "verdict": v["verdict"], "top": v["hypotheses"][0]["title"] if v["hypotheses"] else None, "duration_ms": v["duration_ms"]} for v in reversed(INVS.values())]

@app.get("/api/services/dependencies")
def deps(): return {"topology": "sample topology (no dependency data supplied)", "nodes": [{"id": k, "role": engine.ROLES[k], "depends_on": v} for k, v in engine.DEPS.items()]}

@app.get("/api/ai/status")
def ai_status():
    k, m = ai.settings(); return {"configured": bool(k), "model": m}

@app.post("/api/ai/test")
async def ai_test():
    try: await ai.chat([{"role": "user", "content": "Reply with the word ok."}], max_tokens=5)
    except ai.AIError as e: return {"ok": False, "error": e.code, "message": e.message}
    return {"ok": True, "message": "Connection works."}

@app.get("/api/evaluation")
def evaluation():
    rows = []
    for sid, meta in SAMPLES.items():
        t0 = time.perf_counter(); evs, _ = load_sample(sid); r = engine.analyze(evs); ms = (time.perf_counter() - t0) * 1000
        keys = [h["key"] for h in r["hypotheses"]]; truth = meta["truth"]
        rank = keys.index(truth) + 1 if truth in keys else None
        ids = {e["id"] for e in evs}; valid = all(set(h["support"] + h["contradict"]) <= ids for h in r["hypotheses"])
        top1 = (r["verdict"] == "insufficient_evidence") if truth == "unknown" else (rank == 1 and r["verdict"] == "ok")
        rows.append({"id": sid, "name": meta["name"], "truth": truth, "predicted": keys[0] if keys and r["verdict"] == "ok" else "insufficient_evidence", "rank_of_truth": rank,
                     "top1": top1, "top3": top1 or (rank is not None and rank <= 3), "evidence_valid": valid, "latency_ms": round(ms, 1)})
    n = len(rows)
    return {"scenarios": rows, "summary": {"n": n, "top1": sum(r["top1"] for r in rows) / n, "top3": sum(r["top3"] for r in rows) / n,
            "evidence_validity": sum(r["evidence_valid"] for r in rows) / n, "mean_latency_ms": round(sum(r["latency_ms"] for r in rows) / n, 1)},
            "limitations": ["Scenarios are small, hand-written and simulated; rules were designed with them in view, so results are optimistic.", "Not an independent benchmark. Re-run against organizer fault-injection data when available."]}
