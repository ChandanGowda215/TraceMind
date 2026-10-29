"""TraceMind core engine. Deterministic and offline: parse -> normalize -> timeline -> correlate -> rank.
Scores are HEURISTIC RANKING SCORES, not probabilities of causation."""
import csv, io, json, re
from datetime import datetime, timezone

# Sample topology (clearly labeled in the UI). Each key calls the services in its list.
DEPS = {"frontend": ["api-gateway"], "api-gateway": ["auth", "app"], "auth": ["db"],
        "app": ["db", "cache", "queue"], "db": [], "cache": [], "queue": []}
ROLES = {"frontend": "Web UI", "api-gateway": "Edge routing", "auth": "Authentication service",
         "app": "Core application service", "db": "Primary database", "cache": "In-memory cache", "queue": "Message queue"}
ALIASES = {"gateway": "api-gateway", "apigateway": "api-gateway", "auth-service": "auth", "authentication": "auth",
           "app-service": "app", "application": "app", "database": "db", "postgres": "db", "redis": "cache",
           "kafka": "queue", "mq": "queue", "web": "frontend"}
SEV = {"debug": 0, "info": 1, "warn": 2, "warning": 2, "error": 3, "err": 3, "critical": 4, "fatal": 4}
TYPES = {"deploy", "config", "metric", "trace", "restart", "resolved", "log"}
SRC = {"deploy": "change", "config": "change", "metric": "metric", "trace": "trace", "restart": "ops", "resolved": "ops", "log": "log"}
METRICS = {"cpu", "mem", "disk", "net", "db_connections", "latency_ms", "queue_depth"}
LINE = re.compile(r"^(\S+)\s+(\w+)\s+(\S+)\s+(\w+):\s*(.*)$")
MAX_BYTES, MAX_LINES = 2_000_000, 20000

# pat=error signature, metric=(key, threshold) hit, normal=(key, level) contradicts,
# spec=specificity multiplier (symptom-like categories count less), explains=resource-level cause.
CATS = {
 "db_connection_exhaustion": dict(title="Database connection exhaustion", explains=True,
    pat=r"connection pool|pool exhausted|too many connections|acquir\w* (a )?connection", metric=("db_connections", 90), normal=("db_connections", 70)),
 "slow_database_query": dict(title="Slow or failed database queries", explains=True, pat=r"slow quer|query timeout|lock wait|deadlock"),
 "memory_pressure": dict(title="Memory pressure", explains=True,
    pat=r"\boom\b|out of memory|memory pressure|java heap space|outofmemory", metric=("mem", 85), normal=("mem", 65)),
 "cpu_saturation": dict(title="CPU saturation", explains=True, pat=r"cpu (throttl|saturat)|high cpu", metric=("cpu", 90), normal=("cpu", 60)),
 "invalid_configuration": dict(title="Invalid configuration", explains=True,
    pat=r"invalid config|config\w* (error|invalid)|failed to (load|parse) config|missing required (env|setting)"),
 "faulty_deployment": dict(title="Faulty deployment", explains=False),
 "dependency_failure": dict(title="Dependency failure", spec=0.5, pat=r"connection refused|upstream|bad gateway|service unavailable|\b50[234]\b"),
 "network_timeout": dict(title="Network or timeout problems", spec=0.6, pat=r"timed? ?out|timeout|dns|unreachable|connection reset"),
}
CHANGE = {"faulty_deployment": "deploy", "invalid_configuration": "config"}
DEFAULTS = {"min_score": 0.35, "window_min": 30}
W = {"sig": 0.35, "src": 0.20, "temp": 0.20, "dep": 0.25, "con": 0.30}
REC = {
 "db_connection_exhaustion": (["Compare active connections to max_connections over the incident window", "Identify which services/queries hold connections longest"], ["Raise pool limit or add a pooler (human-reviewed change)", "Terminate leaked idle connections"], ["Alert at 80% pool use", "Set per-service connection budgets"], ["Confirm db_connections stays below 70% under load test"]),
 "slow_database_query": (["Inspect slow-query log and lock waits"], ["Add missing index or kill blocking query (reviewed)"], ["Query timeouts and slow-query alerts"], ["Re-run the query plan and confirm latency"]),
 "memory_pressure": (["Plot memory trend per service before the OOM", "Take heap profile from a healthy replica"], ["Restart affected instances; raise limits temporarily"], ["Memory growth alerts; soak tests"], ["Confirm memory plateaus after the fix"]),
 "cpu_saturation": (["Profile hot paths during the spike"], ["Scale out or throttle noisy callers"], ["Autoscaling rules, CPU alerts"], ["Confirm CPU stays under 70% at peak"]),
 "invalid_configuration": (["Diff the config before/after the change"], ["Revert the config change (reviewed)"], ["Config validation in CI"], ["Reload service and confirm errors stop"]),
 "faulty_deployment": (["Diff the release against the previous version", "Check error signatures that start right after the deploy"], ["Roll back or hotfix after review"], ["Canary releases and automatic rollback gates"], ["Replay the failing request on the fixed build"]),
 "dependency_failure": (["Check health of the called service first; this is often a symptom"], ["Fail over or enable circuit breaker"], ["Timeouts, retries with backoff"], ["Confirm upstream error rate returns to baseline"]),
 "network_timeout": (["Check network/DNS metrics between the affected services"], ["Tune timeouts only after finding the slow hop"], ["Synthetic probes between services"], ["Confirm timeouts disappear in traces"]),
}

class IngestError(ValueError):
    pass

def norm_service(s):
    s = re.sub(r"[_\s]+", "-", str(s or "").strip().lower())
    s = re.sub(r"[^a-z0-9.\-]+", "-", s).strip("-")[:64]  # safe charset: service names are rendered in the UI
    return ALIASES.get(s, s) or "unknown"

def parse_ts(v):
    s = str(v if v is not None else "").strip()
    if not s: raise ValueError("missing timestamp")
    if re.fullmatch(r"\d{10}(\.\d+)?", s):
        d = datetime.fromtimestamp(float(s), timezone.utc)
    elif re.fullmatch(r"\d{13}", s):  # epoch milliseconds
        d = datetime.fromtimestamp(int(s) / 1000, timezone.utc)
    else:
        d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1))
        if d.tzinfo is None: d = d.replace(tzinfo=timezone.utc)  # assume UTC when no zone given
    return d.astimezone(timezone.utc)

def closure(s, seen=None):
    seen = set() if seen is None else seen
    for d in DEPS.get(s, []):
        if d not in seen:
            seen.add(d); closure(d, seen)
    return seen

def dependents(s):
    return {x for x in DEPS if s in closure(x)}

def parse(text, filename="upload.log"):
    """Returns (events, stats). Never silently drops records: rejects are listed with reasons."""
    text = text.lstrip("\ufeff")  # tolerate a UTF-8 BOM (Excel CSV exports)
    if len(text.encode("utf-8", "ignore")) > MAX_BYTES: raise IngestError(f"File exceeds {MAX_BYTES // 1_000_000} MB limit.")
    rows, rejected, warnings = [], [], []
    if filename.lower().endswith(".csv"):
        for i, r in enumerate(csv.DictReader(io.StringIO(text)), start=2):
            rows.append((i, {str(k).strip().lower(): v for k, v in r.items() if k}))
    else:
        lines = text.splitlines()
        if len(lines) > MAX_LINES: raise IngestError(f"File has more than {MAX_LINES} lines.")
        for i, l in enumerate(lines, 1):
            l = l.strip()
            if not l or l.startswith("#"): continue
            if l.startswith("{"):
                try: rows.append((i, {str(k).lower(): v for k, v in json.loads(l).items()}))
                except Exception: rejected.append({"line": i, "reason": "invalid JSON", "text": l[:120]})
            else:
                m = LINE.match(l)
                if m: rows.append((i, dict(zip(("timestamp", "level", "service", "type", "message"), m.groups()))))
                else: rejected.append({"line": i, "reason": "expected '<timestamp> <LEVEL> <service> <type>: <message>'", "text": l[:120]})
    evs = []
    for i, r in rows:
        try: d = parse_ts(r.get("timestamp") or r.get("time") or r.get("ts"))
        except Exception as ex:
            rejected.append({"line": i, "reason": f"bad timestamp ({ex})", "text": str(r)[:120]}); continue
        msg = str(r.get("message") or r.get("msg") or "")
        typ = str(r.get("type") or r.get("event_type") or "log").lower()
        typ = typ if typ in TYPES else "log"
        sv = str(r.get("level") or r.get("severity") or "").lower()
        if sv not in SEV:
            warnings.append({"line": i, "reason": f"unknown/missing severity '{sv}', treated as info"}); sv = "info"
        metrics = {k.lower(): float(v) for k, v in re.findall(r"\b([A-Za-z_]+)=(\d+(?:\.\d+)?)", msg) if k.lower() in METRICS}
        t = re.search(r"trace_id=(\w+)", msg)
        evs.append({"epoch": d.timestamp(), "ts": d.isoformat().replace("+00:00", "Z"), "type": typ, "source": SRC[typ],
                    "service": norm_service(r.get("service")), "severity": sv, "sev": SEV[sv], "message": msg,
                    "metrics": metrics, "trace_id": t.group(1) if t else None, "ref": f"{filename}:{i}", "line": i,
                    "raw": json.dumps(r, default=str)[:500]})
    evs.sort(key=lambda e: (e["epoch"], e["line"]))  # deterministic order
    for n, e in enumerate(evs, 1): e["id"] = f"E{n:03d}"
    return evs, {"accepted": len(evs), "rejected": len(rejected), "warnings": len(warnings),
                 "rejected_records": rejected[:20], "warning_records": warnings[:20]}

def filter_range(evs, start=None, end=None):
    s = parse_ts(start).timestamp() if start else None
    e = parse_ts(end).timestamp() if end else None
    return [x for x in evs if (s is None or x["epoch"] >= s) and (e is None or x["epoch"] <= e)]

RED = [(re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"), "Bearer [REDACTED]"),
       (re.compile(r"(?i)\b(api[_-]?key|token|password|passwd|secret)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
       (re.compile(r"sk-[A-Za-z0-9_\-]{10,}"), "[REDACTED_KEY]"),
       (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[REDACTED_EMAIL]")]

def redact(s):
    for p, r in RED: s = p.sub(r, s)
    return s

def hit(c, e):
    if c.get("pat") and re.search(c["pat"], e["message"], re.I) and (e["sev"] >= 2 or e["type"] in ("trace", "restart")): return True
    m = c.get("metric")
    return bool(m and e["metrics"].get(m[0], -1) >= m[1])

def normal(c, e):
    n = c.get("normal")
    return bool(n and e["metrics"].get(n[0], 1e9) < n[1])

def analyze(events, cfg=None):
    cfg = {**DEFAULTS, **(cfg or {})}; w = {**W, **cfg.get("weights", {})}
    sym = [e for e in events if e["sev"] >= 2]
    notes, cands, corr = [], [], []
    E = {e["service"] for e in sym}
    if sym:
        first, last = sym[0], sym[-1]
        raw = {}
        for k, c in CATS.items():
            sup = [e for e in events if hit(c, e)]
            con = [e for e in events if first["epoch"] <= e["epoch"] <= last["epoch"] and normal(c, e)]
            raw[k] = (sup, con, len(sup))
        win = cfg["window_min"] * 60
        for k, typ in CHANGE.items():  # changes shortly BEFORE the first symptom
            ch = [e for e in events if e["type"] == typ and 0 <= first["epoch"] - e["epoch"] <= win]
            if not ch: continue
            aff = set()
            for d in ch: aff |= {d["service"]} | dependents(d["service"])
            t0 = min(d["epoch"] for d in ch); chs = {d["service"] for d in ch}
            after = [e for e in sym if e["epoch"] >= t0 and e["service"] in aff and e["type"] != typ]
            expl = [e for e in after if any(hit(c2, e) for k2, c2 in CATS.items() if c2.get("explains") and k2 != k)]
            eids = {e["id"] for e in expl}
            direct = [e for e in after if e["id"] not in eids and e["service"] in chs]  # downstream errors are symptoms, not proof
            sup0 = raw[k][0]
            merged = list({e["id"]: e for e in ch + direct + sup0}.values())
            raw[k] = (merged, expl, len(direct) + len(sup0))
        for k, (sup, con, n) in raw.items():
            if not sup: continue
            sup = sorted(sup, key=lambda e: (e["epoch"], e["id"]))  # each record counted once per candidate
            sig = min(n / 3, 1) * CATS[k].get("spec", 1.0)
            srcs = {e["source"] for e in sup}
            src = min(len(srcs) / 3, 1)
            d = sup[0]["epoch"] - first["epoch"]
            temp = 1.0 if d <= 0 else 0.6 if d <= 60 else 0.2
            S = {e["service"] for e in sup}
            cov = [x for x in E if x in S or closure(x) & S]
            dep = len(cov) / len(E)
            cs = min(len(con) / 3, 1)
            sc = max(0.0, min(1.0, w["sig"] * sig + w["src"] * src + w["temp"] * temp + w["dep"] * dep - w["con"] * cs))
            cands.append({"key": k, "title": CATS[k]["title"], "score": round(sc, 3), "score_label": "heuristic ranking score (not a probability)",
                "status": "candidate - not verified", "signals": {"signature": round(sig, 2), "cross_source": round(src, 2), "temporal": temp, "dependency": round(dep, 2), "contradiction": round(cs, 2)},
                "support": [e["id"] for e in sup], "contradict": [e["id"] for e in con], "services": sorted(S),
                "rationale": f"{len(sup)} supporting record(s) from {', '.join(sorted(srcs))} on {', '.join(sorted(S))}. Earliest supporting record {'precedes or coincides with' if d <= 0 else 'follows'} the first symptom ({first['id']}). Dependency graph links it to {len(cov)}/{len(E)} symptomatic service(s). {len(con)} contradicting record(s).",
                "steps": dict(zip(("investigate", "remediate", "prevent", "verify"), REC[k]))})
        cands.sort(key=lambda h: (-h["score"], -len(h["support"]), h["key"]))
        for i, h in enumerate(cands, 1): h["rank"] = i
    verdict = "ok"
    if len(sym) < 2: verdict = "insufficient_evidence"; notes.append("Fewer than two warning/error records: not enough evidence to name a cause.")
    elif not cands: verdict = "insufficient_evidence"; notes.append("Errors exist but match no known failure signature.")
    elif cands[0]["score"] < cfg["min_score"]: verdict = "insufficient_evidence"; notes.append(f"Best heuristic score {cands[0]['score']} is below the minimum {cfg['min_score']}.")
    if verdict == "ok" and len(cands) > 1 and cands[0]["score"] - cands[1]["score"] < 0.05: notes.append("Top candidates are nearly tied; treat the ranking with extra caution.")
    present = {e["source"] for e in events}
    missing = [m for s, m in (("metric", "No metric records"), ("trace", "No trace records"), ("change", "No deployment/configuration change records")) if s not in present]
    missing.append("No service dependency data supplied: sample topology used.")
    groups = {}
    for e in events:
        if e["trace_id"]: groups.setdefault(e["trace_id"], []).append(e)
    for t, g in sorted(groups.items()):
        if len(g) > 1: corr.append({"type": "shared_trace_id", "key": t, "evidence": [e["id"] for e in g], "reason": f"Records share trace_id {t} across {', '.join(sorted({e['service'] for e in g}))}.", "causation": "not established"})
    for h in cands[:3]: corr.append({"type": "signature_and_timing", "key": h["key"], "evidence": h["support"], "reason": h["rationale"], "causation": "not established; timing and signatures only"})
    edges = []
    if verdict == "ok":
        S = set(cands[0]["services"])
        edges += [[a, b] for a in sorted(S) for b in DEPS.get(a, []) if b in S]  # links between services holding supporting evidence
        for x in sorted(E - S):  # shortest dependency path from a symptomatic service to a suspected one
            prev, q, found = {x: None}, [x], None
            while q and not found:
                cur = q.pop(0)
                for nx in DEPS.get(cur, []):
                    if nx not in prev:
                        prev[nx] = cur; q.append(nx)
                        if nx in S: found = nx; break
            while found and prev[found]: edges.append([prev[found], found]); found = prev[found]
    svc = {}
    for e in events:
        s = svc.setdefault(e["service"], {"events": 0, "warnings": 0, "errors": 0})
        s["events"] += 1; s["warnings"] += e["sev"] == 2; s["errors"] += e["sev"] >= 3
    top = cands[0] if cands else None
    summary = (f"Top-ranked candidate: {top['title']} (heuristic score {top['score']}). This is an unverified hypothesis built from timing, signatures and the dependency graph." if verdict == "ok"
               else "Insufficient evidence to name a likely cause. " + " ".join(notes))
    return {"verdict": verdict, "notes": notes, "summary": summary, "hypotheses": cands, "correlations": corr, "missing_evidence": missing,
            "services": svc, "affected_services": sorted(E), "suspected_edges": sorted({tuple(x) for x in edges}),
            "severity": "critical" if any(e["sev"] >= 3 for e in events) else "warning" if sym else "info",
            "counts": {"events": len(events), "warnings": sum(e["sev"] == 2 for e in events), "errors": sum(e["sev"] >= 3 for e in events)},
            "window": {"start": events[0]["ts"], "end": events[-1]["ts"]} if events else None, "settings": {**cfg, "weights": w}}
