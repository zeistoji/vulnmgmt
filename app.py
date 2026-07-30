"""Risk-based Vulnerability Management server (NIST SP 800-40 / ISO 27001 A.8.8 / CIS 7).

Run:  uvicorn app:app --port 8321
Auth: set VULNMGMT_TOKEN to require `Authorization: Bearer <token>` on /api/*.

Pipeline: import scans (Nessus/Trivy/Grype/CSV) -> enrich (CISA KEV, EPSS,
NVD backfill) -> composite risk score & SLA tiers -> lifecycle with rescan
verification & risk acceptance -> metrics + dashboard at /.
"""
import csv, datetime, io, json, os, threading

from fastapi import Depends, FastAPI, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

import connectors, db, enrich, importers

HERE = os.path.dirname(os.path.abspath(__file__))
CRIT_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
REFRESH_SECONDS = 3600  # hourly housekeeping; KEV feed itself has a 24h TTL


# ------------------------------------------------------------------ scoring
def priority_of(cvss, epss, kev, crit, inet):
    """CISA KEV auto-escalates to P1; otherwise CVSS bands with risk context."""
    cvss = cvss or 0
    if kev or (cvss >= 9 and (epss or 0) >= 0.5 and (inet or crit == "critical")):
        return "P1"
    if cvss >= 7:
        return "P2"
    if cvss >= 4:
        return "P3"
    return "P4"


def risk_score(cvss, epss, crit, inet, comp):
    """Weighted composite: CVSS 20%, EPSS 30%, criticality 25%, exposure 15%,
    compensating control -10. Range 0-90."""
    s = ((cvss or 0) / 10) * 20 + (epss or 0) * 30 + CRIT_WEIGHT.get(crit, 0.4) * 25
    s += 15 if inet else 0
    s -= 10 if comp else 0
    return round(max(s, 0), 1)


def rescore(con, kev, epss_map, ids=None):
    """Recompute score/priority/due date for open+remediated findings."""
    cfg = db.get_config(con)
    where = "f.status IN ('open','remediated')"
    args = []
    if ids:
        where += f" AND f.id IN ({','.join('?' * len(ids))})"
        args = list(ids)
    rows = con.execute(
        f"SELECT f.*, a.criticality, a.internet_facing, a.compensating_control"
        f" FROM findings f LEFT JOIN assets a ON a.hostname=f.asset WHERE {where}",
        args).fetchall()
    for r in rows:
        crit = r["criticality"] or "medium"
        inet, comp = bool(r["internet_facing"]), bool(r["compensating_control"])
        e = epss_map.get(r["cve"], r["epss"])
        k = r["cve"] in kev
        pri = priority_of(r["cvss"], e, k, crit, inet)
        due = db.iso(db.parse(r["detected_at"]) +
                     datetime.timedelta(days=cfg["sla_days"][pri]))
        con.execute(
            "UPDATE findings SET epss=?, kev=?, risk_score=?, priority=?, due_at=?,"
            " enriched_at=? WHERE id=?",
            (e, int(k), risk_score(r["cvss"], e, crit, inet, comp), pri, due,
             db.iso(db.now()), r["id"]))
    con.commit()
    return len(rows)


def enrich_all(con, force_kev=False):
    kev = enrich.get_kev(con, force=force_kev)
    cves = [r["cve"] for r in con.execute(
        "SELECT DISTINCT cve FROM findings WHERE status IN ('open','remediated')")]
    epss_map = enrich.get_epss(cves)
    n = rescore(con, kev, epss_map)
    db.log(con, "system", "enrich", f"rescored {n} findings, {len(kev)} KEV entries")
    con.commit()
    return n


def sla_state_of(f, now_dt):
    """SLA clock state for an open/remediated finding: on_track|notify|escalate|breached."""
    if not f["due_at"]:
        return None, None
    det, due = db.parse(f["detected_at"]), db.parse(f["due_at"])
    frac = (now_dt - det) / (due - det) if due > det else 2
    state = ("breached" if now_dt > due else "escalate" if frac >= 0.9
             else "notify" if frac >= 0.5 else "on_track")
    return state, round(min(frac, 2) * 100)


# ------------------------------------------------------------------ connectors
PRI_ORDER = ["P1", "P2", "P3", "P4"]
STATE_TEXT = {"notify": "● 50% of SLA window elapsed",
              "escalate": "▲ 90% of SLA window — escalate",
              "breached": "⛔ SLA BREACHED"}


def sync_connectors(con):
    """Create Jira tickets for prioritized findings and send webhook/Jira
    notifications when a finding's SLA state advances. Idempotent: jira_key
    and notified_state on the finding prevent duplicates."""
    cfg = db.get_config(con)
    wh, jr = connectors.webhook_enabled(cfg), connectors.jira_enabled(cfg)
    if not (wh or jr):
        return {"tickets": 0, "notices": 0}
    ticketable = set(PRI_ORDER[:PRI_ORDER.index(cfg.get("ticket_min", "P2")) + 1])
    now_dt, tickets, notices = db.now(), 0, 0
    rows = con.execute(
        "SELECT f.*, a.owner FROM findings f LEFT JOIN assets a ON a.hostname=f.asset"
        " WHERE f.status IN ('open','remediated') AND f.priority IS NOT NULL").fetchall()
    for f in rows:
        key = f["jira_key"]
        if jr and not key and f["priority"] in ticketable:
            try:
                key = connectors.jira_create(cfg, dict(f))
                con.execute("UPDATE findings SET jira_key=? WHERE id=?", (key, f["id"]))
                db.log(con, "system", "jira_created",
                       f"{key} for #{f['id']} {f['cve']} on {f['asset']}")
                tickets += 1
            except Exception as exc:
                db.log(con, "system", "jira_failed", f"#{f['id']}: {exc}")
        state, _ = sla_state_of(f, now_dt)
        if state in STATE_TEXT and state != f["notified_state"]:
            text = (f"{STATE_TEXT[state]}: {f['cve']} on {f['asset']}"
                    f" ({f['priority']}, owner {f['owner'] or 'unassigned'},"
                    f" due {f['due_at'][:10]})")
            sent = True
            if wh:
                try:
                    connectors.notify(cfg, text)
                except Exception as exc:
                    sent = False
                    db.log(con, "system", "webhook_failed", str(exc))
            if jr and key:
                try:
                    connectors.jira_comment(cfg, key, text)
                except Exception as exc:
                    db.log(con, "system", "jira_failed", f"comment {key}: {exc}")
            if sent:
                con.execute("UPDATE findings SET notified_state=? WHERE id=?",
                            (state, f["id"]))
                notices += 1
    con.commit()
    return {"tickets": tickets, "notices": notices}


def sync_connectors_bg():
    con = db.connect()
    try:
        sync_connectors(con)
    finally:
        con.close()


# ------------------------------------------------------------------ background
def housekeeping():
    """Hourly: refresh stale KEV/EPSS, expire risk acceptances, NVD backfill."""
    con = db.connect()
    try:
        expired = con.execute(
            "UPDATE findings SET status='open', accepted_until=NULL"
            " WHERE status='accepted' AND accepted_until < ? RETURNING id",
            (db.iso(db.now()),)).fetchall()
        if expired:
            db.log(con, "system", "acceptance_expired",
                   f"reopened {len(expired)} findings: {[r['id'] for r in expired]}")
            con.commit()
        try:
            enrich_all(con)
        except Exception as exc:
            db.log(con, "system", "enrich_failed", str(exc)); con.commit()
        try:
            sync_connectors(con)
        except Exception as exc:
            db.log(con, "system", "connector_sync_failed", str(exc)); con.commit()
    finally:
        con.close()
    try:
        enrich.nvd_backfill()
    except Exception:
        pass


def _loop(stop: threading.Event):
    while not stop.wait(REFRESH_SECONDS):
        housekeeping()


# ------------------------------------------------------------------ app & auth
app = FastAPI(title="vulnmgmt", version="1.0")
_stop = threading.Event()


@app.on_event("startup")
def startup():
    threading.Thread(target=housekeeping, daemon=True).start()
    threading.Thread(target=_loop, args=(_stop,), daemon=True).start()


@app.on_event("shutdown")
def shutdown():
    _stop.set()


def auth(authorization: str = Header(default="")):
    token = os.environ.get("VULNMGMT_TOKEN")
    if token and authorization != f"Bearer {token}":
        raise HTTPException(401, "missing or invalid bearer token")


def actor_of(request: Request):
    return request.headers.get("X-Actor", "local")


api = Depends(auth)


# ------------------------------------------------------------------ endpoints
@app.get("/api/health")
def health():
    return {"status": "ok", "time": db.iso(db.now())}


@app.get("/api/config", dependencies=[api])
def get_config():
    con = db.connect()
    try:
        return db.get_config(con)
    finally:
        con.close()


@app.put("/api/config", dependencies=[api])
async def put_config(request: Request):
    body = await request.json()
    con = db.connect()
    try:
        cfg = db.get_config(con)
        if "sla_days" in body:
            cfg["sla_days"] = {p: int(body["sla_days"][p]) for p in ("P1", "P2", "P3", "P4")}
        for k in ("kev_target_hours", "sla_target_pct"):
            if k in body:
                cfg[k] = int(body[k])
        for k in ("webhook_url", "jira_url", "jira_email", "jira_token", "jira_project"):
            if k in body:
                cfg[k] = str(body[k]).strip()
        if "ticket_min" in body:
            if body["ticket_min"] not in PRI_ORDER:
                raise HTTPException(422, "ticket_min must be P1..P4")
            cfg["ticket_min"] = body["ticket_min"]
        db.set_config(con, cfg)
        db.log(con, actor_of(request), "config_update", json.dumps(cfg))
        con.commit()
        kev = enrich.get_kev(con)
        rescore(con, kev, {})
        return cfg
    finally:
        con.close()


@app.get("/api/assets", dependencies=[api])
def list_assets():
    con = db.connect()
    try:
        return [dict(r) for r in con.execute(
            "SELECT a.*, COUNT(f.id) FILTER (WHERE f.status IN ('open','remediated'))"
            " AS open_findings FROM assets a LEFT JOIN findings f ON f.asset=a.hostname"
            " GROUP BY a.hostname ORDER BY a.hostname")]
    finally:
        con.close()


@app.post("/api/assets", dependencies=[api])
async def upsert_asset(request: Request):
    b = await request.json()
    if not b.get("hostname"):
        raise HTTPException(422, "hostname required")
    if b.get("criticality", "medium") not in CRIT_WEIGHT:
        raise HTTPException(422, "criticality must be critical|high|medium|low")
    con = db.connect()
    try:
        con.execute(
            "INSERT INTO assets VALUES(?,?,?,?,?,?) ON CONFLICT(hostname) DO UPDATE SET"
            " criticality=excluded.criticality, internet_facing=excluded.internet_facing,"
            " owner=excluded.owner, compensating_control=excluded.compensating_control",
            (b["hostname"].strip(), b.get("criticality", "medium"),
             int(bool(b.get("internet_facing"))), b.get("owner") or "unassigned",
             int(bool(b.get("compensating_control"))), db.iso(db.now())))
        db.log(con, actor_of(request), "asset_upsert", b["hostname"])
        con.commit()
        kev = enrich.get_kev(con)
        rescore(con, kev, {})
        return {"ok": True}
    finally:
        con.close()


@app.delete("/api/assets/{hostname}", dependencies=[api])
def delete_asset(hostname: str, request: Request):
    con = db.connect()
    try:
        con.execute("DELETE FROM assets WHERE hostname=?", (hostname,))
        db.log(con, actor_of(request), "asset_delete", hostname)
        con.commit()
        return {"ok": True}
    finally:
        con.close()


@app.post("/api/import", dependencies=[api])
async def import_scan(request: Request, file: UploadFile):
    raw = await file.read()
    try:
        rows = importers.parse(file.filename or "scan", raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if not rows:
        raise HTTPException(422, "no CVE findings recognized in file")
    con = db.connect()
    try:
        ts, new, reopened, updated, ids = db.iso(db.now()), 0, 0, 0, []
        for r in rows:
            con.execute("INSERT OR IGNORE INTO assets(hostname, created_at) VALUES(?,?)",
                        (r["asset"], ts))
            old = con.execute("SELECT * FROM findings WHERE asset=? AND cve=?",
                              (r["asset"], r["cve"])).fetchone()
            if old is None:
                cur = con.execute(
                    "INSERT INTO findings(asset,cve,title,solution,source,cvss,detected_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (r["asset"], r["cve"], r["title"], r["solution"], r["source"],
                     r["cvss"], ts))
                ids.append(cur.lastrowid); new += 1
            elif old["status"] == "verified":
                # verified-fixed but seen again in a new scan: false remediation
                con.execute(
                    "UPDATE findings SET status='open', detected_at=?, remediated_at=NULL,"
                    " verified_at=NULL, reopened=reopened+1, cvss=COALESCE(?, cvss)"
                    " WHERE id=?", (ts, r["cvss"], old["id"]))
                ids.append(old["id"]); reopened += 1
            else:
                con.execute("UPDATE findings SET cvss=COALESCE(?, cvss),"
                            " title=COALESCE(title, ?), solution=COALESCE(solution, ?)"
                            " WHERE id=?", (r["cvss"], r["title"], r["solution"], old["id"]))
                updated += 1
        db.log(con, actor_of(request), "import",
               f"{file.filename}: {new} new, {reopened} reopened, {updated} still present")
        con.commit()
        enrich_error = None
        try:
            kev = enrich.get_kev(con)
            epss_map = enrich.get_epss([r["cve"] for r in rows])
            rescore(con, kev, epss_map)
        except Exception as exc:
            enrich_error = f"enrichment deferred ({exc}); background refresh will retry"
        cfg = db.get_config(con)
        if connectors.webhook_enabled(cfg) and (new or reopened) and ids:
            p1 = con.execute(
                f"SELECT COUNT(*) c FROM findings WHERE priority='P1'"
                f" AND id IN ({','.join('?' * len(ids))})", ids).fetchone()["c"]
            try:
                connectors.notify(cfg, f"Scan import ({file.filename}): {new} new,"
                                  f" {reopened} reopened, {updated} still present"
                                  + (f" — ⚠ {p1} new P1" if p1 else ""))
            except Exception as exc:
                db.log(con, "system", "webhook_failed", str(exc)); con.commit()
        threading.Thread(target=enrich.nvd_backfill, daemon=True).start()
        threading.Thread(target=sync_connectors_bg, daemon=True).start()
        return {"new": new, "reopened": reopened, "still_present": updated,
                "source": rows[0]["source"], "enrich_error": enrich_error}
    finally:
        con.close()


@app.get("/api/findings", dependencies=[api])
def list_findings(status: str = "", priority: str = "", q: str = "",
                  kev_only: bool = False, limit: int = 1000):
    con = db.connect()
    try:
        cfg = db.get_config(con)
        where, args = ["1=1"], []
        if status:
            where.append("f.status=?"); args.append(status)
        if priority:
            where.append("f.priority=?"); args.append(priority)
        if kev_only:
            where.append("f.kev=1")
        if q:
            where.append("(f.cve LIKE ? OR f.asset LIKE ? OR f.title LIKE ?)")
            args += [f"%{q}%"] * 3
        rows = con.execute(
            f"SELECT f.*, a.owner, a.criticality, a.internet_facing FROM findings f"
            f" LEFT JOIN assets a ON a.hostname=f.asset WHERE {' AND '.join(where)}"
            f" ORDER BY f.risk_score DESC NULLS LAST, f.detected_at LIMIT ?",
            args + [min(limit, 5000)]).fetchall()
        out, now_dt = [], db.now()
        for r in rows:
            d = dict(r)
            if r["status"] in ("open", "remediated") and r["due_at"]:
                d["sla_state"], d["sla_pct_elapsed"] = sla_state_of(r, now_dt)
            out.append(d)
        return {"findings": out, "config": cfg}
    finally:
        con.close()


ACTIONS = {"remediate", "verify", "verify_failed", "accept", "reopen"}


@app.post("/api/findings/{fid}/action", dependencies=[api])
async def finding_action(fid: int, request: Request):
    b = await request.json()
    action = b.get("action")
    if action not in ACTIONS:
        raise HTTPException(422, f"action must be one of {sorted(ACTIONS)}")
    con = db.connect()
    try:
        f = con.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if not f:
            raise HTTPException(404, "finding not found")
        ts = db.iso(db.now())
        if action == "remediate":
            if f["status"] != "open":
                raise HTTPException(409, f"cannot remediate a {f['status']} finding")
            con.execute("UPDATE findings SET status='remediated', remediated_at=?"
                        " WHERE id=?", (ts, fid))
        elif action == "verify":
            if f["status"] != "remediated":
                raise HTTPException(409, "verify requires status=remediated (rescan gate)")
            con.execute("UPDATE findings SET status='verified', verified_at=? WHERE id=?",
                        (ts, fid))
        elif action == "verify_failed":
            if f["status"] != "remediated":
                raise HTTPException(409, "verify_failed requires status=remediated")
            con.execute("UPDATE findings SET status='open', remediated_at=NULL,"
                        " reopened=reopened+1 WHERE id=?", (fid,))
        elif action == "accept":
            reason, until = (b.get("reason") or "").strip(), b.get("until")
            if not reason or not until:
                raise HTTPException(422, "risk acceptance requires reason and until (expiry)")
            try:
                until_dt = db.parse(until)
            except ValueError:
                raise HTTPException(422, "until must be ISO date, e.g. 2026-12-31")
            if until_dt <= db.now():
                raise HTTPException(422, "acceptance expiry must be in the future")
            con.execute("UPDATE findings SET status='accepted', accepted_until=?,"
                        " accepted_reason=? WHERE id=?", (db.iso(until_dt), reason, fid))
        elif action == "reopen":
            con.execute("UPDATE findings SET status='open', remediated_at=NULL,"
                        " verified_at=NULL, accepted_until=NULL WHERE id=?", (fid,))
        db.log(con, actor_of(request), f"finding_{action}",
               f"#{fid} {f['asset']} {f['cve']}" +
               (f" until {b.get('until')}: {b.get('reason')}" if action == "accept" else ""))
        con.commit()
        if action in ("verify", "verify_failed") and f["jira_key"]:
            cfg = db.get_config(con)
            if connectors.jira_enabled(cfg):
                try:
                    connectors.jira_comment(cfg, f["jira_key"],
                        "vulnmgmt: rescan verified clean — remediation confirmed, safe to close."
                        if action == "verify" else
                        "vulnmgmt: rescan FAILED — vulnerability still present, finding reopened.")
                except Exception as exc:
                    db.log(con, "system", "jira_failed", f"comment {f['jira_key']}: {exc}")
                    con.commit()
        return dict(con.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
    finally:
        con.close()


@app.post("/api/enrich", dependencies=[api])
def trigger_enrich(request: Request):
    con = db.connect()
    try:
        n = enrich_all(con, force_kev=True)
        sync = sync_connectors(con)
        return {"rescored": n, **sync}
    except Exception as exc:
        raise HTTPException(502, f"enrichment failed: {exc}")
    finally:
        con.close()


@app.post("/api/connectors/test", dependencies=[api])
def test_connectors():
    """Send a test webhook message and probe Jira auth; report per-connector."""
    con = db.connect()
    try:
        cfg = db.get_config(con)
        out = {}
        if connectors.webhook_enabled(cfg):
            try:
                connectors.notify(cfg, "vulnmgmt: test notification — connector is working ✓")
                out["webhook"] = "ok"
            except Exception as exc:
                out["webhook"] = f"failed: {exc}"
        else:
            out["webhook"] = "not configured"
        if connectors.jira_enabled(cfg):
            try:
                out["jira"] = f"ok — authenticated as {connectors.jira_check(cfg)}"
            except Exception as exc:
                out["jira"] = f"failed: {exc}"
        else:
            out["jira"] = "not configured"
        db.log(con, "local", "connector_test", json.dumps(out))
        con.commit()
        return out
    finally:
        con.close()


@app.get("/api/metrics", dependencies=[api])
def metrics():
    con = db.connect()
    try:
        cfg = db.get_config(con)
        rows = [dict(r) for r in con.execute(
            "SELECT f.*, a.owner FROM findings f LEFT JOIN assets a ON a.hostname=f.asset"
            " WHERE f.priority IS NOT NULL")]
        now_dt = db.now()
        m = {"generated_at": db.iso(now_dt), "config": cfg,
             "totals": {"open": 0, "remediated": 0, "verified": 0, "accepted": 0},
             "mttr_days": {}, "sla_pct": {}, "priority_open": {},
             "backlog_age": {"0-7": 0, "8-30": 0, "31-90": 0, "90+": 0},
             "kev_open": [], "kev_exposure_hours": None, "recurrence_pct": None,
             "escalations": [], "slow_owners": [], "dwell_trend": []}
        dwell, compliant, breached, kev_hours = {}, {}, {}, []
        owners, monthly, reopens = {}, {}, 0
        for f in rows:
            det = db.parse(f["detected_at"])
            pri, st = f["priority"], f["status"]
            m["totals"][st] += 1
            reopens += f["reopened"]
            if st == "verified":
                ver = db.parse(f["verified_at"])
                d = (ver - det).total_seconds() / 86400
                dwell.setdefault(pri, []).append(d)
                bucket = compliant if f["verified_at"] <= f["due_at"] else breached
                bucket[pri] = bucket.get(pri, 0) + 1
                if f["kev"]:
                    kev_hours.append(d * 24)
                owners.setdefault(f["owner"] or "unassigned", []).append(d)
                monthly.setdefault(ver.strftime("%Y-%m"), []).append(d)
            elif st in ("open", "remediated"):
                m["priority_open"][pri] = m["priority_open"].get(pri, 0) + 1
                age = (now_dt - det).days
                key = "0-7" if age <= 7 else "8-30" if age <= 30 else "31-90" if age <= 90 else "90+"
                m["backlog_age"][key] += 1
                if f["kev"]:
                    m["kev_open"].append({"id": f["id"], "asset": f["asset"], "cve": f["cve"],
                                          "hours_open": round((now_dt - det).total_seconds() / 3600)})
                due = db.parse(f["due_at"])
                frac = (now_dt - det) / (due - det) if due > det else 2
                if now_dt > due:
                    breached[pri] = breached.get(pri, 0) + 1
                    m["escalations"].append({"id": f["id"], "asset": f["asset"], "cve": f["cve"],
                                             "priority": pri, "state": "breached"})
                elif frac >= 0.9:
                    m["escalations"].append({"id": f["id"], "asset": f["asset"], "cve": f["cve"],
                                             "priority": pri, "state": "escalate"})
                elif frac >= 0.5:
                    m["escalations"].append({"id": f["id"], "asset": f["asset"], "cve": f["cve"],
                                             "priority": pri, "state": "notify"})
        for pri in cfg["sla_days"]:
            if pri in dwell:
                m["mttr_days"][pri] = round(sum(dwell[pri]) / len(dwell[pri]), 1)
            tot = compliant.get(pri, 0) + breached.get(pri, 0)
            if tot:
                m["sla_pct"][pri] = round(100 * compliant.get(pri, 0) / tot, 1)
        if kev_hours:
            m["kev_exposure_hours"] = round(sum(kev_hours) / len(kev_hours))
        closed = m["totals"]["verified"]
        if closed or reopens:
            m["recurrence_pct"] = round(100 * reopens / (closed + reopens), 1)
        m["slow_owners"] = sorted(
            ({"owner": o, "avg_dwell_days": round(sum(d) / len(d), 1), "closed": len(d)}
             for o, d in owners.items()), key=lambda x: -x["avg_dwell_days"])[:10]
        m["dwell_trend"] = [{"month": k, "avg_dwell_days": round(sum(v) / len(v), 1),
                             "closed": len(v)} for k, v in sorted(monthly.items())][-12:]
        kev_meta = con.execute("SELECT value FROM meta WHERE key='kev'").fetchone()
        if kev_meta:
            km = json.loads(kev_meta["value"])
            m["kev_feed"] = {"fetched_at": km["fetched_at"], "entries": len(km["cves"]),
                             "catalog_version": km.get("catalog_version")}
        return m
    finally:
        con.close()


@app.get("/api/export.csv", dependencies=[api])
def export_csv():
    con = db.connect()
    try:
        rows = con.execute(
            "SELECT f.*, a.owner, a.criticality, a.internet_facing FROM findings f"
            " LEFT JOIN assets a ON a.hostname=f.asset ORDER BY f.risk_score DESC").fetchall()
        buf = io.StringIO()
        if rows:
            w = csv.DictWriter(buf, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(dict(r) for r in rows)
        return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={
            "Content-Disposition": "attachment; filename=findings.csv"})
    finally:
        con.close()


@app.get("/api/activity", dependencies=[api])
def activity(limit: int = 200):
    con = db.connect()
    try:
        return [dict(r) for r in con.execute(
            "SELECT * FROM activity ORDER BY id DESC LIMIT ?", (min(limit, 2000),))]
    finally:
        con.close()


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"))


app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")
