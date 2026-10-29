from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("INCIDENTIQ_DB", ROOT / "incidentiq.db"))
app = FastAPI(title="Trace Mind", version="1.0.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)
    except ValueError:
        for pattern in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(text, pattern).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    return None


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS datasets (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, source_type TEXT NOT NULL,
                created_at TEXT NOT NULL, synthetic INTEGER NOT NULL DEFAULT 0,
                stats_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(id),
                title TEXT NOT NULL, service TEXT NOT NULL, severity TEXT NOT NULL,
                started_at TEXT, ended_at TEXT, status TEXT NOT NULL, summary TEXT NOT NULL,
                symptoms_json TEXT NOT NULL DEFAULT '[]', recovered INTEGER NOT NULL DEFAULT 0,
                expected_category TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(id),
                incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL, timestamp TEXT,
                source_type TEXT NOT NULL, service TEXT NOT NULL, event_type TEXT NOT NULL,
                severity TEXT NOT NULL, message TEXT NOT NULL, trace_id TEXT, deployment_id TEXT,
                configuration_key TEXT, metadata_json TEXT NOT NULL DEFAULT '{}',
                source_reference TEXT NOT NULL, raw_json TEXT NOT NULL DEFAULT '{}',
                fingerprint TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS evidence_incident_time ON evidence(incident_id, timestamp);
            CREATE INDEX IF NOT EXISTS evidence_dataset_time ON evidence(dataset_id, timestamp);
            CREATE TABLE IF NOT EXISTS dependencies (
                dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
                service TEXT NOT NULL, depends_on TEXT NOT NULL,
                PRIMARY KEY(dataset_id, service, depends_on)
            );
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
                report_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS import_jobs (
                id TEXT PRIMARY KEY, file_name TEXT NOT NULL, payload_json TEXT NOT NULL,
                stats_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )
    seed_demo_data()


def seed_demo_data() -> None:
    with db() as connection:
        if connection.execute("SELECT 1 FROM datasets WHERE id='incidentiq-demo'").fetchone():
            return
        now = utc_now()
        connection.execute(
            "INSERT INTO datasets(id,name,source_type,created_at,synthetic,stats_json) VALUES(?,?,?,?,1,?)",
            ("incidentiq-demo", "Trace Mind reproducible scenarios", "synthetic", iso(now), json.dumps({"label": "Synthetic demonstration data"})),
        )
        base = now.replace(second=0, microsecond=0) - timedelta(days=1)
        scenarios = [
            {
                "key": "pool", "title": "Checkout latency after connection-pool change", "service": "payment-service",
                "severity": "critical", "expected": "Connection pool exhaustion",
                "summary": "Checkout latency and payment errors rose shortly after a connection-pool configuration change.",
                "symptoms": ["Payment latency increased", "Database timeouts", "Checkout failures"],
                "events": [
                    (-12, "deployment", "payment-service", "info", "Version pay-2.8.1 deployed", "deployment", "deploy-281", None, {}),
                    (-9, "change", "payment-service", "warning", "database.max_connections changed from 20 to 5", "configuration", None, "database.max_connections", {"before": 20, "after": 5}),
                    (-6, "metric", "payment-service", "warning", "payment latency p95 reached 1800 ms", "latency_anomaly", None, None, {"metric": "latency_p95_ms", "value": 1800, "baseline": 240}),
                    (-4, "log", "payment-service", "error", "Database connection timeout while acquiring connection", "database_timeout", None, None, {"request_id": "req-pool-1"}),
                    (-3, "trace", "payment-service", "error", "checkout -> database.query failed after 2400 ms", "slow_span", None, None, {"duration_ms": 2400}),
                    (-2, "metric", "checkout-service", "error", "checkout error rate reached 18 percent", "error_rate_anomaly", None, None, {"metric": "error_rate", "value": 18, "baseline": 0.4}),
                ],
            },
            {
                "key": "deploy", "title": "Product API failures after release", "service": "product-service",
                "severity": "high", "expected": "Deployment regression",
                "summary": "Product API exceptions began after a new release and propagated to order requests.",
                "symptoms": ["Product API failures", "Order request errors"],
                "events": [
                    (-8, "deployment", "product-service", "warning", "Version catalog-4.2.0 deployed", "deployment", "catalog-420", None, {}),
                    (-5, "log", "product-service", "error", "Unhandled TypeError in ProductController.getProduct", "application_exception", None, None, {"exception": "TypeError"}),
                    (-4, "metric", "product-service", "error", "product error rate reached 22 percent", "error_rate_anomaly", None, None, {"metric": "error_rate", "value": 22, "baseline": 0.2}),
                    (-3, "trace", "order-service", "error", "order.create -> product.get failed", "dependency_failure", None, None, {"upstream_service": "product-service", "duration_ms": 1300}),
                    (-2, "log", "order-service", "error", "Product lookup failed for order request", "upstream_error", None, None, {}),
                ],
            },
            {
                "key": "resource", "title": "Search latency during CPU saturation", "service": "search-service",
                "severity": "high", "expected": "Resource exhaustion",
                "summary": "Search latency and request failures coincided with unusually high CPU usage.",
                "symptoms": ["Elevated search latency", "Intermittent search errors"],
                "events": [
                    (-7, "metric", "search-service", "critical", "CPU utilization reached 98 percent", "cpu_saturation", None, None, {"metric": "cpu_percent", "value": 98, "baseline": 42}),
                    (-5, "metric", "search-service", "warning", "search latency p95 reached 2400 ms", "latency_anomaly", None, None, {"metric": "latency_p95_ms", "value": 2400, "baseline": 180}),
                    (-3, "trace", "search-service", "error", "search.index.scan span delayed for 2200 ms", "slow_span", None, None, {"duration_ms": 2200}),
                    (-2, "log", "search-service", "error", "Request deadline exceeded during search", "request_timeout", None, None, {}),
                ],
            },
            {
                "key": "dependency", "title": "Order errors during inventory dependency outage", "service": "order-service",
                "severity": "high", "expected": "Dependency failure",
                "summary": "Several downstream request paths failed while the shared inventory dependency timed out.",
                "symptoms": ["Order creation failures", "Checkout retries"],
                "events": [
                    (-8, "log", "inventory-service", "critical", "Upstream database request timed out", "dependency_timeout", None, None, {}),
                    (-6, "metric", "inventory-service", "error", "inventory error rate reached 31 percent", "error_rate_anomaly", None, None, {"metric": "error_rate", "value": 31, "baseline": 0.1}),
                    (-4, "trace", "order-service", "error", "order.create -> inventory.reserve timed out", "dependency_failure", None, None, {"upstream_service": "inventory-service", "duration_ms": 3000}),
                    (-3, "trace", "checkout-service", "error", "checkout -> inventory.check timed out", "dependency_failure", None, None, {"upstream_service": "inventory-service", "duration_ms": 3000}),
                    (-1, "log", "order-service", "error", "Inventory reservation unavailable", "upstream_error", None, None, {}),
                ],
            },
            {
                "key": "unknown", "title": "Intermittent API errors with sparse telemetry", "service": "profile-service",
                "severity": "medium", "expected": "Unknown",
                "summary": "A small number of API errors were reported, but the available records do not establish a cause.",
                "symptoms": ["Intermittent API failures"],
                "events": [
                    (-3, "log", "profile-service", "error", "Request failed with an unspecified upstream error", "unknown_error", None, None, {}),
                ],
            },
        ]
        edges = [
            ("checkout-service", "order-service"), ("order-service", "product-service"),
            ("order-service", "inventory-service"), ("checkout-service", "payment-service"),
            ("payment-service", "database"), ("inventory-service", "database"),
            ("profile-service", "user-database"),
        ]
        for service, upstream in edges:
            connection.execute("INSERT OR IGNORE INTO dependencies VALUES(?,?,?)", ("incidentiq-demo", service, upstream))
        for scenario in scenarios:
            incident_id = f"demo-{scenario['key']}"
            start = base + timedelta(minutes=-1)
            end = base + timedelta(minutes=10)
            connection.execute(
                """INSERT INTO incidents(id,dataset_id,title,service,severity,started_at,ended_at,status,summary,
                   symptoms_json,expected_category,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (incident_id, "incidentiq-demo", scenario["title"], scenario["service"], scenario["severity"],
                 iso(start), iso(end), "New", scenario["summary"], json.dumps(scenario["symptoms"]),
                 scenario["expected"], iso(now), iso(now)),
            )
            for offset, source, service, severity, message, event_type, deploy, config, metadata in scenario["events"]:
                timestamp = base + timedelta(minutes=offset)
                _insert_evidence(
                    connection, dataset_id="incidentiq-demo", incident_id=incident_id,
                    record={"timestamp": iso(timestamp), "source_type": source, "service": service,
                            "severity": severity, "message": message, "event_type": event_type,
                            "deployment_id": deploy, "configuration_key": config, "metadata": metadata,
                            "source_reference": f"synthetic:{scenario['key']}:{abs(offset):02d}"},
                )


def _insert_evidence(connection: sqlite3.Connection, dataset_id: str, incident_id: str | None, record: dict[str, Any]) -> bool:
    canonical = json.dumps(record, sort_keys=True, default=str)
    fingerprint = hashlib.sha256(f"{dataset_id}:{canonical}".encode()).hexdigest()
    if connection.execute("SELECT 1 FROM evidence WHERE fingerprint=?", (fingerprint,)).fetchone():
        return False
    evidence_id = "EVD-" + uuid.uuid4().hex[:12].upper()
    connection.execute(
        """INSERT INTO evidence(id,dataset_id,incident_id,timestamp,source_type,service,event_type,severity,
           message,trace_id,deployment_id,configuration_key,metadata_json,source_reference,raw_json,fingerprint)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (evidence_id, dataset_id, incident_id, record.get("timestamp"), record.get("source_type", "log"),
         record.get("service", "unknown-service"), record.get("event_type", "observation"),
         record.get("severity", "info"), record.get("message", ""), record.get("trace_id"),
         record.get("deployment_id"), record.get("configuration_key"),
         json.dumps(record.get("metadata", {}), default=str), record.get("source_reference", "imported record"),
         json.dumps(record.get("raw", record), default=str), fingerprint),
    )
    return True


def _public_evidence(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["metadata"] = json.loads(result.pop("metadata_json", "{}"))
    result.pop("raw_json", None)
    result.pop("fingerprint", None)
    return result


def _public_incident(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["symptoms"] = json.loads(result.pop("symptoms_json", "[]"))
    result.pop("expected_category", None)
    return result


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"{salt.hex()}:{digest.hex()}"


def _check_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000)
        return hmac.compare_digest(expected, actual)
    except (ValueError, TypeError):
        return False


def current_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get("incidentiq_session")
    if not token:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    with db() as connection:
        row = connection.execute(
            """SELECT users.id,users.email FROM sessions JOIN users ON users.id=sessions.user_id
               WHERE sessions.token=? AND sessions.expires_at>?""", (token, iso(utc_now()))
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Your session expired. Please sign in again.")
    return dict(row)


class Credentials(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=128)


class IncidentCreate(BaseModel):
    dataset_id: str
    title: str = Field(min_length=3, max_length=160)
    service: str = Field(min_length=1, max_length=100)
    severity: str = "medium"
    started_at: str | None = None
    ended_at: str | None = None
    summary: str = ""


class InvestigateRequest(BaseModel):
    before_minutes: int = Field(default=10, ge=0, le=1440)
    after_minutes: int = Field(default=10, ge=0, le=1440)
    mode: str = "evidence-based"


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
@app.get("/welcome", response_class=HTMLResponse)
def welcome_page():
    return FileResponse(ROOT / "static" / "welcome.html")


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return FileResponse(ROOT / "static" / "login.html")


@app.get("/signup", response_class=HTMLResponse)
def signup_page():
    return FileResponse(ROOT / "static" / "signup.html")


@app.get("/app", response_class=HTMLResponse)
def app_page():
    return FileResponse(ROOT / "static" / "app.html")


@app.get("/health")
def health():
    return {"status": "ok", "application": "Trace Mind"}


@app.post("/api/auth/signup")
def signup(credentials: Credentials):
    email = credentials.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    user_id, token = "USR-" + uuid.uuid4().hex[:12], secrets.token_urlsafe(32)
    expires = iso(utc_now() + timedelta(days=14))
    with db() as connection:
        try:
            connection.execute("INSERT INTO users VALUES(?,?,?,?)", (user_id, email, _hash_password(credentials.password), iso(utc_now())))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="An account with this email already exists.") from None
        connection.execute("INSERT INTO sessions VALUES(?,?,?)", (token, user_id, expires))
    response = JSONResponse({"ok": True, "email": email})
    response.set_cookie("incidentiq_session", token, httponly=True, samesite="lax", max_age=14 * 86400)
    return response


@app.post("/api/auth/login")
def login(credentials: Credentials):
    email = credentials.email.strip().lower()
    with db() as connection:
        user = connection.execute("SELECT id,password_hash FROM users WHERE email=?", (email,)).fetchone()
        if not user or not _check_password(credentials.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Email or password is incorrect.")
        token = secrets.token_urlsafe(32)
        connection.execute("INSERT INTO sessions VALUES(?,?,?)", (token, user["id"], iso(utc_now() + timedelta(days=14))))
    response = JSONResponse({"ok": True, "email": email})
    response.set_cookie("incidentiq_session", token, httponly=True, samesite="lax", max_age=14 * 86400)
    return response


@app.post("/api/auth/logout")
def logout(request: Request):
    token = request.cookies.get("incidentiq_session")
    if token:
        with db() as connection:
            connection.execute("DELETE FROM sessions WHERE token=?", (token,))
    response = JSONResponse({"ok": True})
    response.delete_cookie("incidentiq_session")
    return response


@app.get("/api/me")
def me(user: dict[str, Any] = Depends(current_user)):
    return user


@app.get("/api/dashboard")
def dashboard(user: dict[str, Any] = Depends(current_user)):
    del user
    with db() as connection:
        incidents = connection.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        investigations = connection.execute("SELECT status,created_at FROM investigations ORDER BY created_at DESC LIMIT 8").fetchall()
        counts = {
            "total": len(incidents),
            "active": sum(1 for row in incidents if row["status"] in ("Investigating", "Hypothesis Identified")),
            "awaiting": sum(1 for row in incidents if row["status"] in ("Awaiting Evidence", "Inconclusive")),
            "resolved": sum(1 for row in incidents if row["status"] == "Resolved"),
        }
        duration_rows = connection.execute(
            "SELECT started_at,ended_at FROM incidents WHERE started_at IS NOT NULL AND ended_at IS NOT NULL"
        ).fetchall()
        durations = [(parse_time(r["ended_at"]) - parse_time(r["started_at"])).total_seconds() / 60 for r in duration_rows if parse_time(r["ended_at"]) and parse_time(r["started_at"])]
        counts["average_duration_minutes"] = round(sum(durations) / len(durations), 1) if durations else None
        counts["ranking_performance"] = _ranking_performance(connection)
        recent = [_public_incident(row) for row in incidents[:8]]
        for item in recent:
            leading = connection.execute("SELECT report_json FROM investigations WHERE incident_id=? ORDER BY created_at DESC LIMIT 1", (item["id"],)).fetchone()
            report = json.loads(leading["report_json"]) if leading else None
            item["leading_cause"] = report["candidates"][0]["title"] if report and report.get("candidates") else "Not investigated"
        service_rows = connection.execute("SELECT service,source_type,severity,metadata_json FROM evidence ORDER BY timestamp DESC").fetchall()
        by_service: dict[str, dict[str, Any]] = {}
        for row in service_rows:
            stats = by_service.setdefault(row["service"], {"service": row["service"], "errors": 0, "latencies": [], "related_incidents": 0})
            stats["errors"] += row["severity"].lower() in ("error", "critical")
            metadata = json.loads(row["metadata_json"])
            for key, value in metadata.items():
                if key.lower() in ("latency_p95_ms", "latency_ms", "duration_ms") and isinstance(value, (int, float)):
                    stats["latencies"].append(value)
        for stat in by_service.values():
            stat["latency_ms"] = round(sum(stat["latencies"]) / len(stat["latencies"])) if stat["latencies"] else None
            stat.pop("latencies")
            stat["status"] = "degraded" if stat["errors"] else "no error signal observed"
            stat["related_incidents"] = sum(1 for row in incidents if row["service"] == stat["service"])
        activities = [{"kind": "investigation", "message": f"Investigation {row['status'].lower()}", "at": row["created_at"]} for row in investigations]
        datasets = connection.execute("SELECT id,name,synthetic FROM datasets ORDER BY created_at DESC").fetchall()
        categories = connection.execute("SELECT report_json FROM investigations").fetchall()
        root_causes: dict[str, int] = {}
        for row in categories:
            report = json.loads(row["report_json"])
            if report.get("candidates"):
                category = report["candidates"][0]["category"]
                root_causes[category] = root_causes.get(category, 0) + 1
    return {"metrics": counts, "incidents": recent, "services": list(by_service.values())[:8],
            "activity": activities, "datasets": [dict(row) for row in datasets], "root_causes": root_causes}


def _ranking_performance(connection: sqlite3.Connection) -> dict[str, Any]:
    rows = connection.execute(
        """SELECT i.expected_category, x.report_json FROM incidents i JOIN
           (SELECT incident_id, MAX(created_at) AS latest FROM investigations GROUP BY incident_id) latest
           ON latest.incident_id=i.id JOIN investigations x
           ON x.incident_id=latest.incident_id AND x.created_at=latest.latest
           WHERE i.expected_category IS NOT NULL"""
    ).fetchall()
    if not rows:
        return {"top1": None, "evaluated": 0}
    correct = 0
    for row in rows:
        report = json.loads(row["report_json"])
        winner = report["candidates"][0]["category"] if report.get("candidates") else "Unknown"
        correct += winner == row["expected_category"]
    return {"top1": round(100 * correct / len(rows)), "evaluated": len(rows)}


@app.get("/api/datasets")
def get_datasets(user: dict[str, Any] = Depends(current_user)):
    del user
    with db() as connection:
        return [dict(row) for row in connection.execute("SELECT * FROM datasets ORDER BY created_at DESC")]


@app.get("/api/incidents")
def list_incidents(search: str = "", service: str = "", severity: str = "", status: str = "", user: dict[str, Any] = Depends(current_user)):
    del user
    query = "SELECT * FROM incidents WHERE 1=1"
    params: list[Any] = []
    if search:
        query += " AND (title LIKE ? OR summary LIKE ? OR id LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if service:
        query += " AND service=?"
        params.append(service)
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY started_at DESC, created_at DESC"
    with db() as connection:
        return [_public_incident(row) for row in connection.execute(query, params)]


@app.post("/api/incidents")
def create_incident(payload: IncidentCreate, user: dict[str, Any] = Depends(current_user)):
    del user
    start = parse_time(payload.started_at)
    end = parse_time(payload.ended_at)
    if payload.started_at and not start:
        raise HTTPException(status_code=422, detail="Incident start time is invalid.")
    if payload.ended_at and not end:
        raise HTTPException(status_code=422, detail="Incident end time is invalid.")
    if bool(start) != bool(end):
        raise HTTPException(status_code=422, detail="Provide both incident window endpoints, or leave both empty.")
    if start and end and end < start:
        raise HTTPException(status_code=422, detail="Incident end time must be after its start time.")
    with db() as connection:
        if not connection.execute("SELECT 1 FROM datasets WHERE id=?", (payload.dataset_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Dataset not found.")
        incident_id, now = "INC-" + uuid.uuid4().hex[:10].upper(), iso(utc_now())
        connection.execute(
            """INSERT INTO incidents(id,dataset_id,title,service,severity,started_at,ended_at,status,summary,
               created_at,updated_at) VALUES(?,?,?,?,?,?,?,'New',?,?,?)""",
            (incident_id, payload.dataset_id, payload.title, payload.service, payload.severity.lower(),
             iso(start) if start else None, iso(end) if end else None, payload.summary, now, now),
        )
        if start and end:
            connection.execute("UPDATE evidence SET incident_id=? WHERE dataset_id=? AND timestamp BETWEEN ? AND ? AND incident_id IS NULL",
                               (incident_id, payload.dataset_id, iso(start), iso(end)))
        row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return _public_incident(row)


def fetch_incident(connection: sqlite3.Connection, incident_id: str) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return row


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str, user: dict[str, Any] = Depends(current_user)):
    del user
    with db() as connection:
        incident = fetch_incident(connection, incident_id)
        evidence = list(connection.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY timestamp", (incident_id,)).fetchall())
        start, end = parse_time(incident["started_at"]), parse_time(incident["ended_at"])
        if start and end:
            window_rows = connection.execute(
                """SELECT * FROM evidence WHERE dataset_id=? AND timestamp BETWEEN ? AND ?
                   AND (incident_id IS NULL OR incident_id=?) ORDER BY timestamp""",
                (incident["dataset_id"], iso(start - timedelta(minutes=10)), iso(end + timedelta(minutes=10)), incident_id),
            ).fetchall()
            known_ids = {row["id"] for row in evidence}
            evidence.extend(row for row in window_rows if row["id"] not in known_ids)
            evidence.sort(key=lambda row: row["timestamp"] or "")
        investigation = connection.execute("SELECT * FROM investigations WHERE incident_id=? ORDER BY created_at DESC LIMIT 1", (incident_id,)).fetchone()
        history = connection.execute("SELECT id,created_at,mode,status FROM investigations WHERE incident_id=? ORDER BY created_at DESC", (incident_id,)).fetchall()
        dataset = connection.execute("SELECT name,synthetic FROM datasets WHERE id=?", (incident["dataset_id"],)).fetchone()
    return {"incident": _public_incident(incident), "evidence": [_public_evidence(row) for row in evidence],
            "report": json.loads(investigation["report_json"]) if investigation else None,
            "history": [dict(row) for row in history], "dataset": dict(dataset)}


@app.post("/api/incidents/{incident_id}/investigate")
def investigate(incident_id: str, options: InvestigateRequest, user: dict[str, Any] = Depends(current_user)):
    del user
    if options.mode not in ("evidence-based", "ai-assisted"):
        raise HTTPException(status_code=422, detail="Mode must be evidence-based or ai-assisted.")
    with db() as connection:
        incident = fetch_incident(connection, incident_id)
        report = analyze_incident(connection, incident, options.before_minutes, options.after_minutes)
        if options.mode == "ai-assisted":
            report["mode_note"] = "No LLM credentials are configured; this report uses the deterministic evidence-based engine."
        status = report["status"]
        connection.execute("INSERT INTO investigations VALUES(?,?,?,?,?,?)",
                           ("RUN-" + uuid.uuid4().hex[:10].upper(), incident_id, iso(utc_now()), options.mode, status, json.dumps(report)))
        connection.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?", (status, iso(utc_now()), incident_id))
    return report


def detect_metric_anomalies(evidence: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    limitations: list[str] = []
    for item in evidence:
        if item.get("source_type") != "metric":
            continue
        metadata = item.get("metadata") or {}
        if isinstance(metadata.get("metadata"), dict):
            metadata = {**metadata, **metadata["metadata"]}
        value = metadata.get("value", metadata.get("metric_value"))
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(numeric_value):
            continue
        metric = str(metadata.get("metric_name") or metadata.get("metric") or metadata.get("measurement") or item.get("event_type") or "unknown-metric").lower()
        groups.setdefault((item["service"], metric), []).append({**item, "_value": numeric_value, "_metadata": metadata})

    anomalies: list[dict[str, Any]] = []
    for (service, metric), points in groups.items():
        baselined = [point for point in points if point["_metadata"].get("baseline") is not None]
        if baselined:
            for point in baselined:
                try:
                    baseline = float(point["_metadata"]["baseline"])
                except (TypeError, ValueError):
                    continue
                if not math.isfinite(baseline):
                    continue
                threshold = max(abs(baseline) * 0.5, 1e-9)
                if abs(point["_value"] - baseline) > threshold:
                    anomalies.append({"evidence_id": point["id"], "service": service, "metric": metric,
                                      "value": point["_value"], "baseline": baseline, "method": "provided baseline; deviation > 50%"})
            continue
        if len(points) < 5:
            limitations.append(f"{service}/{metric}: {len(points)} numeric sample(s), no supplied baseline; at least 5 are needed for a robust local comparison.")
            continue
        values = sorted(point["_value"] for point in points)
        median = values[len(values) // 2]
        deviations = sorted(abs(value - median) for value in values)
        mad = deviations[len(deviations) // 2]
        threshold = max(3.5 * 1.4826 * mad, abs(median) * 0.2, 1e-9)
        for point in points:
            if abs(point["_value"] - median) > threshold:
                anomalies.append({"evidence_id": point["id"], "service": service, "metric": metric,
                                  "value": point["_value"], "baseline": median, "method": "median/MAD; 3.5 robust deviations"})
    return anomalies, limitations


def analyze_incident(connection: sqlite3.Connection, incident: sqlite3.Row, before_minutes: int, after_minutes: int) -> dict[str, Any]:
    start = parse_time(incident["started_at"])
    end = parse_time(incident["ended_at"])
    rows = list(connection.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY timestamp", (incident["id"],)).fetchall())
    query_start = iso(start - timedelta(minutes=before_minutes)) if start else None
    query_end = iso(end + timedelta(minutes=after_minutes)) if end else None
    if query_start and query_end:
        window_rows = connection.execute(
            """SELECT * FROM evidence WHERE dataset_id=? AND timestamp BETWEEN ?
               AND ? AND (incident_id IS NULL OR incident_id=?) ORDER BY timestamp""",
            (incident["dataset_id"], query_start, query_end, incident["id"]),
        ).fetchall()
        known_ids = {row["id"] for row in rows}
        rows.extend(row for row in window_rows if row["id"] not in known_ids)
        rows.sort(key=lambda row: row["timestamp"] or "")
    evidence = [_public_evidence(row) for row in rows]
    for item in evidence:
        item["phase"] = "unknown"
        event_time = parse_time(item.get("timestamp"))
        if start and event_time:
            item["phase"] = "before symptoms" if event_time < start else ("during incident" if not end or event_time <= end else "after incident")
    metric_anomalies, metric_limitations = detect_metric_anomalies(evidence)
    metric_anomaly_ids = {item["evidence_id"] for item in metric_anomalies}

    text = " ".join((item.get("message", "") + " " + item.get("event_type", "")).lower() for item in evidence)
    service_set = {item["service"] for item in evidence}
    signals: list[dict[str, Any]] = []
    patterns = [
        ("Connection pool exhaustion", "Connection pool exhaustion", r"(pool|connection).*(timeout|exhaust|changed|reduce)|(database\.max_connections|connection pool)", {"change", "log", "trace"}),
        ("Deployment regression", "Deployment regression", r"(deployment|deployed|release|version|exception|typeerror|regression)", {"deployment", "log", "metric"}),
        ("Resource exhaustion", "Resource exhaustion", r"(cpu|memory|resource|saturation|out of memory)", {"metric", "trace", "log"}),
        ("Dependency failure", "Dependency failure", r"(upstream|dependency|downstream|inventory|product).*(timeout|fail|error)|(dependency_failure|dependency_timeout)", {"trace", "log", "metric"}),
        ("Database or network connectivity failure", "Connectivity failure", r"(database|network|connection).*(fail|timeout|refused|unavailable)", {"log", "trace", "metric"}),
        ("Application exception", "Application exception", r"(exception|traceback|unhandled|panic|crash)", {"log", "deployment", "trace"}),
    ]
    for title, category, pattern, expected_sources in patterns:
        matching = [item for item in evidence if re.search(pattern, (item.get("message", "") + " " + item.get("event_type", "")).lower())]
        if matching:
            direct_matching = list(matching)
            if category in ("Connection pool exhaustion", "Deployment regression", "Resource exhaustion"):
                related = [item for item in evidence
                           if item["service"] == incident["service"]
                           and item["source_type"] in ("log", "metric", "trace", "deployment", "change")]
                seen = {item["id"] for item in matching}
                matching.extend(item for item in related if item["id"] not in seen)
            elif category == "Dependency failure":
                related = [item for item in evidence if item["service"] in service_set]
                seen = {item["id"] for item in matching}
                matching.extend(item for item in related if item["id"] not in seen)
            signals.append({"title": title, "category": category, "matching": matching,
                            "direct_matching": direct_matching, "expected_sources": expected_sources})

    edges = [dict(row) for row in connection.execute("SELECT service,depends_on FROM dependencies WHERE dataset_id=?", (incident["dataset_id"],))]
    service_set = {item["service"] for item in evidence}
    related_edges = [edge for edge in edges if edge["service"] in service_set or edge["depends_on"] in service_set]
    candidates: list[dict[str, Any]] = []
    available_sources = {item["source_type"] for item in evidence}
    for signal in signals:
        matches = signal["matching"]
        sources = {item["source_type"] for item in matches}
        logs = [item for item in matches if item["source_type"] == "log"]
        metrics = [item for item in matches if item["source_type"] == "metric" and item["id"] in metric_anomaly_ids]
        traces = [item for item in matches if item["source_type"] == "trace"]
        change_type = "change" if signal["category"] == "Connection pool exhaustion" else "deployment"
        changes = [item for item in matches if item["source_type"] == change_type] if signal["category"] in ("Connection pool exhaustion", "Deployment regression") else []
        matching_services = {item["service"] for item in matches}
        dependency_support = any(edge["depends_on"] in matching_services and edge["service"] in service_set for edge in related_edges)
        corroboration = min(1.0, max(0, len(sources) - 1) / 3)
        contradiction_count = sum(1 for item in matches if item["phase"] == "after incident")
        direct_times = [parse_time(item.get("timestamp")) for item in signal["direct_matching"]]
        direct_times = [value for value in direct_times if value]
        temporal = 0.5
        if direct_times and start:
            temporal_scores = []
            for value in direct_times:
                delta = (value - start).total_seconds()
                if delta < 0:
                    temporal_scores.append(max(0.0, 1.0 - abs(delta) / (20 * 60)))
                elif end and value > end:
                    temporal_scores.append(0.1)
                else:
                    temporal_scores.append(max(0.3, 0.65 - delta / (20 * 60)))
            temporal = max(temporal_scores)
        factors = {
            "temporal": round(temporal, 2),
            "logs": round(min(1, len(logs) / 2), 2),
            "metrics": round(min(1, len(metrics) / 2), 2),
            "traces": round(min(1, len(traces) / 2), 2),
            "changes": round(min(1, len(changes) / 1), 2),
            "dependencies": 1.0 if dependency_support else 0.0,
            "corroboration": round(corroboration, 2),
            "contradictions": round(min(1, contradiction_count / max(1, len(matches))), 2),
        }
        weighted = (factors["temporal"] * 15 + factors["logs"] * 18 + factors["metrics"] * 16 +
                    factors["traces"] * 15 + factors["changes"] * 25 + factors["dependencies"] * 5 +
                    factors["corroboration"] * 6 - factors["contradictions"] * 20)
        score = max(0, min(100, round(weighted)))
        strong_sources = len(sources)
        assessment = "Strongly supported hypothesis" if score >= 65 and strong_sources >= 2 else ("Plausible hypothesis" if score >= 40 else "Weakly supported hypothesis")
        missing = [source for source in sorted(signal["expected_sources"]) if source not in available_sources]
        next_steps = []
        if "metric" in missing:
            next_steps.append(f"Import metrics for {incident['service']} during the incident window.")
        if "trace" in missing:
            next_steps.append("Import representative distributed traces to verify the failing operation.")
        if "deployment" in missing:
            next_steps.append("Check deployment history around the first observed symptom.")
        if "change" in missing and signal["category"] == "configuration regression":
            next_steps.append("Compare configuration values and audit changes near the incident.")
        candidates.append({
            "title": signal["title"], "category": signal["category"], "service": incident["service"],
            "score": score, "assessment": assessment, "confidence": "high" if score >= 65 and strong_sources >= 2 else ("medium" if score >= 40 else "low"),
            "verification": "corroborated" if strong_sources >= 2 and score >= 55 else "unverified",
            "supporting_evidence": matches, "contradictory_evidence": [item for item in matches if item["phase"] == "after incident"],
            "evidence_count": len(matches), "source_count": len(sources), "factors": factors,
            "missing_evidence": missing, "next_steps": next_steps,
            "services_observed": sorted(matching_services),
        })
    candidates.sort(key=lambda item: (-item["score"], item["title"]))
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = rank
    reliable = bool(candidates and candidates[0]["score"] >= 40 and candidates[0]["evidence_count"] >= 2)
    status = "Hypothesis Identified" if reliable else "Inconclusive"
    timeline = sorted(evidence, key=lambda item: item.get("timestamp") or "")
    missing_general = []
    for source in ("log", "metric", "trace", "deployment", "change"):
        if source not in available_sources:
            missing_general.append(f"No {source} evidence was provided.")
    if "metric" in available_sources and not metric_anomalies:
        missing_general.append("Metric records did not support a reliable numerical anomaly test.")
    summary = f"Root cause unknown from the available evidence. {len(evidence)} evidence record(s) were inspected." if not reliable else f"{candidates[0]['title']} is the leading evidence-backed hypothesis (ranking score {candidates[0]['score']}/100); it is not verified."
    return {
        "incident_id": incident["id"], "summary": summary, "status": status, "mode": "evidence-based",
        "candidate_ranking_note": "Scores rank candidates from this dataset; they are not probabilities.",
        "candidates": candidates, "timeline": timeline, "evidence_count": len(evidence),
        "metric_anomalies": metric_anomalies, "analysis_limitations": metric_limitations,
        "available_sources": sorted(available_sources), "missing_information": missing_general,
        "uncertainties": ["Timestamps are compared as supplied; clock skew between data sources is not estimated.",
                          "A temporal association does not establish causality."],
        "dependencies": related_edges,
    }


@app.get("/api/evidence")
def evidence_search(search: str = "", service: str = "", source_type: str = "", severity: str = "",
                    trace_id: str = "", dataset_id: str = "", incident_id: str = "",
                    user: dict[str, Any] = Depends(current_user)):
    del user
    query = "SELECT * FROM evidence WHERE 1=1"
    params: list[Any] = []
    for column, value in (("service", service), ("source_type", source_type), ("severity", severity),
                          ("trace_id", trace_id), ("dataset_id", dataset_id), ("incident_id", incident_id)):
        if value:
            query += f" AND {column}=?"
            params.append(value)
    if search:
        query += " AND (message LIKE ? OR event_type LIKE ? OR source_reference LIKE ?)"
        params.extend([f"%{search}%"] * 3)
    query += " ORDER BY timestamp DESC LIMIT 500"
    with db() as connection:
        return [_public_evidence(row) for row in connection.execute(query, params)]


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if re.search(r"password|secret|token|authorization|api[_-]?key", str(key), re.I) else redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED_EMAIL]", value, flags=re.I)
        return re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+", r"\1[REDACTED]", value)
    return value


def normalize_record(record: Any, source_ref: str) -> tuple[dict[str, Any] | None, str | None, bool]:
    if not isinstance(record, dict):
        return None, "Record must be a JSON object.", False
    raw = redact(record)
    lowered = {str(key).strip().lower(): value for key, value in raw.items()}
    timestamp = parse_time(next((lowered[key] for key in ("timestamp", "time", "datetime", "ts", "start_time") if lowered.get(key) is not None), None))
    if not timestamp:
        return None, "Missing or invalid timestamp.", False
    service = next((str(lowered[key]).strip().lower() for key in ("service", "service_name", "app", "application", "resource.service.name") if lowered.get(key)), "unknown-service")
    source = str(next((lowered[key] for key in ("source_type", "type", "kind") if lowered.get(key)), "log")).lower()
    if source in ("metrics", "metricpoint"):
        source = "metric"
    if source in ("span", "distributed_trace", "traces"):
        source = "trace"
    if source in ("deployment_record",):
        source = "deployment"
    if source not in ("log", "metric", "trace", "deployment", "change", "dependency"):
        source = "log"
    metric_name = next((lowered[key] for key in ("metric_name", "metric", "measurement") if lowered.get(key)), None)
    if source == "metric":
        metric_name = metric_name or lowered.get("name")
    message = str(next((lowered[key] for key in ("message", "msg", "log", "span_name", "event") if lowered.get(key) is not None), "")).strip()
    if not message and source == "metric" and metric_name:
        message = f"{metric_name}={lowered.get('value', 'value unavailable')} {lowered.get('unit', '')}".strip()
    if not message:
        message = str(lowered.get("name") or "").strip()
    severity = str(next((lowered[key] for key in ("severity", "level", "status") if lowered.get(key)), "info")).lower()
    if severity not in ("debug", "info", "warning", "warn", "error", "critical"):
        severity = "info"
    if severity == "warn":
        severity = "warning"
    known = {"timestamp", "time", "datetime", "ts", "start_time", "service", "service_name", "app", "application", "message", "msg", "log", "name", "span_name", "event", "source_type", "type", "kind", "severity", "level", "status", "trace_id", "deployment_id", "configuration_key", "config_key", "event_type", "source_reference"}
    metadata = {key: value for key, value in raw.items() if str(key).lower() not in known}
    normalized = {
        "timestamp": iso(timestamp), "source_type": source, "service": service,
        "event_type": str(lowered.get("event_type") or metric_name or re.sub(r"\W+", "_", message.lower()).strip("_")[:80] or "observation"),
        "severity": severity, "message": message or "(no message field)", "trace_id": lowered.get("trace_id"),
        "deployment_id": lowered.get("deployment_id"), "configuration_key": lowered.get("configuration_key") or lowered.get("config_key"),
        "metadata": metadata, "source_reference": str(lowered.get("source_reference") or source_ref), "raw": raw,
    }
    return normalized, None, source != str(next((lowered[key] for key in ("source_type", "type", "kind") if lowered.get(key)), "log")).lower()


def parse_import(filename: str, content: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Files must be 10 MB or smaller.")
    text = content.decode("utf-8-sig", errors="replace")
    suffix = Path(filename).suffix.lower()
    input_records: list[Any] = []
    skipped = 0
    if suffix == ".csv":
        input_records = list(csv.DictReader(io.StringIO(text)))
    elif suffix in (".jsonl", ".ndjson"):
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                skipped += 1
                continue
            try:
                input_records.append(json.loads(line))
            except json.JSONDecodeError as error:
                input_records.append({"__invalid__": f"Line {line_number}: {error.msg}"})
    elif suffix == ".json" or text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as error:
            raise HTTPException(status_code=422, detail=f"Invalid JSON: {error.msg}") from error
        if isinstance(parsed, list):
            input_records = parsed
        elif isinstance(parsed, dict):
            records = next((parsed[key] for key in ("records", "events", "data", "spans", "metrics") if isinstance(parsed.get(key), list)), None)
            input_records = records if records is not None else [parsed]
    else:
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                skipped += 1
                continue
            match = re.match(r"^(\d{4}-\d\d-\d\d[T ][^ ]+)\s+(?:([A-Za-z0-9_.-]+)\s+)?(?:\[([^\]]+)\]\s*)?(.*)$", line)
            if match:
                timestamp, service, level, message = match.groups()
                input_records.append({"timestamp": timestamp, "service": service or "unknown-service",
                                     "severity": (level or "info").lower(), "message": message,
                                     "source_type": "log", "source_reference": f"{filename}:{line_number}"})
            else:
                input_records.append({"__invalid__": f"Line {line_number}: unrecognized plain-text log format."})
    normalized, errors = [], []
    transformed = 0
    for index, record in enumerate(input_records, 1):
        if isinstance(record, dict) and record.get("__invalid__"):
            errors.append({"record": index, "error": record["__invalid__"]})
            continue
        item, error, changed = normalize_record(record, f"{filename}:record-{index}")
        if error:
            errors.append({"record": index, "error": error})
        else:
            normalized.append(item)
            transformed += changed
    return normalized, errors, skipped


@app.post("/api/import/preview")
async def import_preview(file: UploadFile = File(...), user: dict[str, Any] = Depends(current_user)):
    del user
    filename = Path(file.filename or "upload.data").name
    records, errors, skipped = parse_import(filename, await file.read())
    stats = {"total": len(records) + len(errors) + skipped, "valid": len(records), "rejected": len(errors),
             "skipped": skipped, "normalized": len(records),
             "privacy_redacted": True, "errors": errors[:100]}
    job_id = "IMP-" + uuid.uuid4().hex[:12].upper()
    with db() as connection:
        connection.execute("INSERT INTO import_jobs VALUES(?,?,?,?,?)",
                           (job_id, filename, json.dumps(records), json.dumps(stats), iso(utc_now())))
    return {"job_id": job_id, "file_name": filename, "stats": stats, "preview": records[:8]}


class ImportCommit(BaseModel):
    job_id: str
    name: str = Field(min_length=1, max_length=120)


@app.post("/api/import/commit")
def import_commit(payload: ImportCommit, user: dict[str, Any] = Depends(current_user)):
    del user
    with db() as connection:
        job = connection.execute("SELECT * FROM import_jobs WHERE id=?", (payload.job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Import preview expired or not found.")
        dataset_id = "DS-" + uuid.uuid4().hex[:10].upper()
        records = json.loads(job["payload_json"])
        stats = json.loads(job["stats_json"])
        connection.execute("INSERT INTO datasets VALUES(?,?,?,?,0,?)", (dataset_id, payload.name.strip(), Path(job["file_name"]).suffix.lower().lstrip(".") or "import", iso(utc_now()), json.dumps(stats)))
        inserted = 0
        dependency_count = 0
        for item in records:
            inserted += _insert_evidence(connection, dataset_id, None, item)
            if item["source_type"] == "dependency":
                depends_on = item.get("metadata", {}).get("depends_on")
                if depends_on and item["service"] and item["service"] != "unknown-service":
                    connection.execute("INSERT OR IGNORE INTO dependencies VALUES(?,?,?)",
                                       (dataset_id, item["service"], str(depends_on).strip().lower()))
                    dependency_count += 1
        connection.execute("DELETE FROM import_jobs WHERE id=?", (payload.job_id,))
        return {"dataset_id": dataset_id, "name": payload.name, "stats": {**stats, "imported": inserted, "dependencies": dependency_count, "duplicates_skipped": len(records) - inserted}}


@app.get("/api/services")
def services(user: dict[str, Any] = Depends(current_user)):
    del user
    with db() as connection:
        nodes = connection.execute("SELECT DISTINCT service FROM evidence UNION SELECT DISTINCT depends_on FROM dependencies UNION SELECT DISTINCT service FROM dependencies ORDER BY service").fetchall()
        links = connection.execute("SELECT DISTINCT service,depends_on FROM dependencies").fetchall()
        observed = {row["service"] for row in connection.execute("SELECT DISTINCT service FROM evidence")}
    return {"services": [{"name": row["service"], "observed": row["service"] in observed} for row in nodes],
            "dependencies": [dict(row) for row in links]}


@app.get("/api/timeline")
def timeline(incident_id: str = "", user: dict[str, Any] = Depends(current_user)):
    del user
    if not incident_id:
        raise HTTPException(status_code=422, detail="Choose an incident to view its timeline.")
    with db() as connection:
        incident = fetch_incident(connection, incident_id)
        start, end = parse_time(incident["started_at"]), parse_time(incident["ended_at"])
        if start and end:
            rows = connection.execute(
                """SELECT * FROM evidence WHERE dataset_id=? AND timestamp BETWEEN ? AND ?
                   AND (incident_id IS NULL OR incident_id=?) ORDER BY timestamp""",
                (incident["dataset_id"], iso(start - timedelta(minutes=10)), iso(end + timedelta(minutes=10)), incident_id),
            ).fetchall()
        else:
            rows = connection.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY timestamp", (incident_id,)).fetchall()
    return [_public_evidence(row) for row in rows]


@app.get("/api/incidents/{incident_id}/report")
def export_report(incident_id: str, user: dict[str, Any] = Depends(current_user)):
    del user
    with db() as connection:
        incident = fetch_incident(connection, incident_id)
        run = connection.execute("SELECT report_json,created_at FROM investigations WHERE incident_id=? ORDER BY created_at DESC LIMIT 1", (incident_id,)).fetchone()
    if not run:
        raise HTTPException(status_code=404, detail="Run an investigation before exporting its report.")
    report = json.loads(run["report_json"])
    lines = [f"# Trace Mind Investigation: {incident['title']}", "", f"- Incident: `{incident_id}`",
             f"- Service: `{incident['service']}`", f"- Severity: {incident['severity']}",
             f"- Status: {report['status']}", f"- Generated: {run['created_at']}", "", report["summary"], "",
             "## Ranked candidates"]
    for candidate in report["candidates"]:
        lines += ["", f"### {candidate['rank']}. {candidate['title']} — {candidate['score']}/100",
                  f"Category: {candidate['category']} · {candidate['assessment']} · {candidate['verification']}", "",
                  "Score breakdown: " + ", ".join(f"{key} {value}" for key, value in candidate["factors"].items()),
                  "", "Supporting evidence:"]
        lines.extend(f"- `{item['id']}` {item['timestamp']} {item['service']}: {item['message']}" for item in candidate["supporting_evidence"])
        lines.extend(f"- Missing source: {source}" for source in candidate["missing_evidence"])
    lines += ["", "## Timeline"]
    lines.extend(f"- {item.get('timestamp') or 'Timestamp unavailable'} — `{item['service']}` [{item['source_type']}] {item['message']} ({item['source_reference']})" for item in report["timeline"])
    lines += ["", "## Uncertainties"]
    lines.extend(f"- {item}" for item in report["uncertainties"])
    return PlainTextResponse("\n".join(lines), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{incident_id}-report.md"'})


@app.post("/api/evaluation/run")
def run_evaluation(user: dict[str, Any] = Depends(current_user)):
    del user
    results = []
    with db() as connection:
        incidents = connection.execute("SELECT * FROM incidents WHERE expected_category IS NOT NULL ORDER BY id").fetchall()
        for incident in incidents:
            report = analyze_incident(connection, incident, 10, 10)
            expected = incident["expected_category"]
            predicted = report["candidates"][0]["category"] if report["status"] != "Inconclusive" and report["candidates"] else "Unknown"
            results.append({"incident_id": incident["id"], "scenario": incident["title"], "expected": expected,
                            "predicted": predicted, "correct": expected.lower() in predicted.lower() or predicted.lower() in expected.lower(),
                            "status": report["status"], "score": report["candidates"][0]["score"] if report["candidates"] else 0})
        accuracy = round(100 * sum(item["correct"] for item in results) / len(results)) if results else None
        return {"scenarios": results, "top1_accuracy": accuracy, "evaluated": len(results),
                "note": "Evaluation labels are used only here; the investigation engine ranks from evidence signals."}


# Preserve the original module's helper functions for its regression tests, but
# make every documented server entry point serve the merged dashboard/backend.
from backend.app.main import app as app

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), reload=False)
