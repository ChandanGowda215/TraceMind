import atexit, asyncio, json, os, tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

_test_database = tempfile.TemporaryDirectory()
os.environ["INCIDENTIQ_DB"] = str(Path(_test_database.name) / "test.db")

from app import ai, engine
from app.main import app, ROOT

client = TestClient(app)
client.__enter__()
atexit.register(client.__exit__, None, None, None)
atexit.register(_test_database.cleanup)
_account = {"email": "backend-tests@example.test", "password": "TraceMind-test-password"}
assert client.post("/api/auth/signup", json=_account).status_code == 200

def load(n): return engine.parse((ROOT / "sample_data" / f"{n}.log").read_text(), f"{n}.log")[0]

def test_parse_formats_and_malformed():
    txt = "2026-01-01T00:00:00Z ERROR db log: x\nnot a log line\n" + json.dumps({"timestamp": "2026-01-01T00:00:01Z", "level": "warn", "service": "Database", "message": "y"}) + "\n{bad json"
    ev, st = engine.parse(txt)
    assert st["accepted"] == 2 and st["rejected"] == 2 and ev[1]["service"] == "db"
    ev, st = engine.parse("timestamp,level,service,type,message\n2026-01-01T00:00:00Z,error,app,log,boom\n,error,app,log,no time\n", "a.csv")
    assert st["accepted"] == 1 and st["rejected"] == 1

def test_timezone_normalization():
    assert engine.parse_ts("2026-01-01T02:00:00+02:00") == engine.parse_ts("2026-01-01T00:00:00Z")
    assert engine.parse_ts("2026-01-01 00:00:00").tzinfo is not None

def test_timeline_deterministic_regardless_of_input_order():
    lines = (ROOT / "sample_data" / "bad_deploy.log").read_text().splitlines()
    a = engine.parse("\n".join(lines), "x.log")[0]
    b = engine.parse("\n".join(reversed(lines)), "x.log")[0]
    assert [e["ts"] for e in a] == sorted(e["ts"] for e in a) and [(e["ts"], e["message"]) for e in a] == [(e["ts"], e["message"]) for e in b]

@pytest.mark.parametrize("name,truth", [("db_pool", "db_connection_exhaustion"), ("bad_deploy", "faulty_deployment"), ("memory_leak", "memory_pressure")])
def test_top1_ranking(name, truth):
    r = engine.analyze(load(name))
    assert r["verdict"] == "ok" and r["hypotheses"][0]["key"] == truth

def test_insufficient_evidence():
    r = engine.analyze(load("vague"))
    assert r["verdict"] == "insufficient_evidence" and r["hypotheses"] == []

def test_red_herring_deploy_ranked_lower_with_contradiction_preserved():
    r = engine.analyze(load("db_pool")); h = {x["key"]: x for x in r["hypotheses"]}
    assert h["faulty_deployment"]["rank"] > 1 and h["faulty_deployment"]["contradict"]

def test_evidence_references_exist_and_old_deploy_ignored():
    ev = load("memory_leak"); r = engine.analyze(ev); ids = {e["id"] for e in ev}
    assert all(set(h["support"] + h["contradict"]) <= ids for h in r["hypotheses"])
    assert "faulty_deployment" not in {h["key"] for h in r["hypotheses"]}

def test_scores_are_labeled_heuristic_and_weights_configurable():
    r = engine.analyze(load("db_pool"), {"weights": {"con": 0.0}})
    assert "not a probability" in r["hypotheses"][0]["score_label"] and r["settings"]["weights"]["con"] == 0.0

def test_redaction():
    out = engine.redact("Bearer abc.def password=hunter2 mail a@b.com sk-abcdefghijkl")
    assert "hunter2" not in out and "a@b.com" not in out and "abc.def" not in out and "sk-abcdefghijkl" not in out

def test_upload_validation():
    assert client.post("/api/incidents/upload", files={"file": ("x.exe", b"x")}).json()["error"] == "unsupported_type"
    assert client.post("/api/incidents/upload", files={"file": ("x.log", b"a" * 2_100_000)}).status_code == 413
    assert client.post("/api/incidents/upload", files={"file": ("x.log", b"garbage only")}).json()["error"] == "no_valid_records"

def test_full_workflow_report_and_deps(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    up = client.post("/api/incidents/upload", files={"file": ("a.log", (ROOT / "sample_data/bad_deploy.log").read_bytes())}).json()
    inv = client.post("/api/investigations", json={"upload_id": up["upload_id"]}).json()
    assert inv["hypotheses"][0]["key"] == "faulty_deployment"
    assert client.get(f"/api/investigations/{inv['id']}/report").json()["verification_status"].startswith("No root cause")
    r = client.post(f"/api/investigations/{inv['id']}/ai-analysis")
    assert r.status_code == 503 and r.json()["error"] == "no_key"       # deterministic result still intact
    assert client.get(f"/api/investigations/{inv['id']}/hypotheses").json()["verdict"] == "ok"
    assert {n["id"] for n in client.get("/api/services/dependencies").json()["nodes"]} >= {"app", "db"}
    assert client.post("/api/investigations", json={}).status_code == 400

class Resp:
    def __init__(self, code, body=None): self.status_code, self._b = code, body
    def json(self): return self._b

def run_chat(monkeypatch, resp=None, exc=None):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    async def fake(payload, key):
        if exc: raise exc
        return resp
    monkeypatch.setattr(ai, "_post", fake)
    return asyncio.run(ai.chat([{"role": "user", "content": "hi"}]))

@pytest.mark.parametrize("code,err", [(401, "invalid_key"), (402, "credits"), (404, "invalid_model"), (429, "rate_limit"), (500, "upstream")])
def test_openrouter_http_errors(monkeypatch, code, err):
    with pytest.raises(ai.AIError) as e: run_chat(monkeypatch, Resp(code))
    assert e.value.code == err and "test-key" not in e.value.message

def test_openrouter_timeout_and_network(monkeypatch):
    import httpx
    with pytest.raises(ai.AIError) as e: run_chat(monkeypatch, exc=httpx.ReadTimeout("t"))
    assert e.value.code == "timeout"
    with pytest.raises(ai.AIError) as e: run_chat(monkeypatch, exc=httpx.ConnectError("c"))
    assert e.value.code == "network"

def make_inv():
    ev = load("bad_deploy"); return {"events": ev, **engine.analyze(ev)}

def test_ai_malformed_and_unknown_references(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    async def bad(m, max_tokens=0): return "not json"
    monkeypatch.setattr(ai, "chat", bad)
    with pytest.raises(ai.AIError) as e: asyncio.run(ai.analyze_ai(make_inv()))
    assert e.value.code == "malformed"
    async def fab(m, max_tokens=0): return json.dumps({"summary": "s", "hypotheses": [{"title": "Fake", "supporting_evidence_ids": ["E999"]}]})
    monkeypatch.setattr(ai, "chat", fab)
    out = asyncio.run(ai.analyze_ai(make_inv()))
    assert out["unknown_references"] == ["E999"] and out["ungrounded_hypotheses"] == ["Fake"]

# ---- regression tests for bugs found during the hardening pass ----
def test_csv_with_utf8_bom_is_accepted():
    body = b"\xef\xbb\xbftimestamp,level,service,type,message\n2026-01-01T00:00:00Z,error,app,log,boom\n"
    r = client.post("/api/incidents/upload", files={"file": ("excel.csv", body)})
    assert r.status_code == 200 and r.json()["stats"]["accepted"] == 1

def test_service_names_are_sanitized_before_reaching_the_ui():
    ev, _ = engine.parse("2026-01-01T00:00:00Z ERROR <img/src=x/onerror=alert(1)> log: boom\n")
    assert ev[0]["service"] and not set("<>/=()'\" ") & set(ev[0]["service"])
    assert engine.norm_service("Auth_Service") == "auth" and engine.norm_service("") == "unknown"

def test_epoch_milliseconds_and_seconds():
    assert engine.parse_ts("1767225600000") == engine.parse_ts("1767225600")

def test_stats_do_not_claim_deduplication():
    assert "deduplicated" not in engine.parse("2026-01-01T00:00:00Z INFO app log: x")[1]

@pytest.mark.parametrize("body", [{"choices": [{"message": {"content": None}}]}, {"choices": [{"message": {"content": "  "}}]}, {"choices": []}])
def test_openrouter_null_or_empty_content_is_a_clean_error(monkeypatch, body):
    with pytest.raises(ai.AIError) as e: run_chat(monkeypatch, Resp(200, body))
    assert e.value.code == "bad_response"

def test_openrouter_200_with_error_body(monkeypatch):
    with pytest.raises(ai.AIError) as e: run_chat(monkeypatch, Resp(200, {"error": {"message": "provider down"}}))
    assert e.value.code == "upstream" and "provider down" in e.value.message

def test_api_key_never_returned_by_api(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-SECRETSECRET123")
    for path in ("/api/ai/status", "/health", "/api/evaluation"):
        assert "SECRETSECRET123" not in client.get(path).text
    assert "SECRETSECRET123" not in client.post("/api/ai/test").text

def test_ai_prompt_marks_evidence_as_untrusted(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k"); seen = {}
    async def cap(m, max_tokens=0): seen["m"] = m; return json.dumps({"summary": "s"})
    monkeypatch.setattr(ai, "chat", cap); asyncio.run(ai.analyze_ai(make_inv()))
    assert "untrusted" in seen["m"][0]["content"] and "untrusted" in seen["m"][1]["content"]

def test_static_files_do_not_expose_env_or_source():
    for p in ("/.env", "/../.env", "/backend/app/ai.py"): assert client.get(p).status_code == 404

def test_original_login_flow_protects_merged_dashboard_and_api():
    assert client.get("/").status_code == 200
    assert "Trace" in client.get("/login").text
    client.post("/api/auth/logout")
    assert client.get("/app", follow_redirects=False).status_code == 303
    assert client.get("/api/incidents").status_code == 401
    assert client.post("/api/auth/login", json=_account).status_code == 200
    dashboard = client.get("/app")
    assert dashboard.status_code == 200
    assert "Root-Cause Analysis" in dashboard.text and 'id="logout"' in dashboard.text
    assert client.get("/api/incidents").status_code == 200
