"""Risk-based Vulnerability Management server (NIST SP 800-40 / ISO 27001 A.8.8 / CIS 7).

Run:  uvicorn app:app --port 8321
Auth: set VULNMGMT_TOKEN to require `Authorization: Bearer <token>` on /api/*.

Pipeline: import scans (Nessus/Trivy/Grype/CSV) -> enrich (CISA KEV, EPSS,
NVD backfill) -> composite risk score & SLA tiers -> lifecycle with rescan
verification & risk acceptance -> metrics + dashboard at /.
"""
import csv, datetime, io, json, os, re, shutil, threading, uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

import connectors, db, enrich, importers

HERE = os.path.dirname(os.path.abspath(__file__))
CRIT_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
REFRESH_SECONDS = 3600  # hourly housekeeping; KEV feed itself has a 24h TTL
MAX_UPLOAD = 5_000_000  # bytes

# Public mode: every anonymous visitor gets an isolated database seeded with a
# realistic programme, so a hosted instance is safe to hand to strangers.
PUBLIC_DEMO = os.environ.get("VULNMGMT_PUBLIC", "") == "1"
DATA_DIR = os.environ.get("VULNMGMT_DATA", os.path.join(HERE, "data"))
SEED_DB = os.path.join(DATA_DIR, "seed.db")
SESS_DIR = os.path.join(DATA_DIR, "sessions")
SESSION_TTL_HOURS = 24
if PUBLIC_DEMO:
    os.makedirs(SESS_DIR, exist_ok=True)
    db.DB_PATH = SEED_DB  # background threads and the seed builder use the seed


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


def rescore(con, kev, epss_map, ids=None, all_statuses=False):
    """Recompute score/priority/due date for open+remediated findings."""
    cfg = db.get_config(con)
    where = "1=1" if all_statuses else "f.status IN ('open','remediated')"
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
    if not PUBLIC_DEMO:
        try:
            enrich.nvd_backfill()
        except Exception:
            pass


def _loop(stop: threading.Event):
    while not stop.wait(REFRESH_SECONDS):
        housekeeping()
        if PUBLIC_DEMO:  # drop visitor sandboxes older than the session TTL
            cutoff = datetime.datetime.now().timestamp() - SESSION_TTL_HOURS * 3600
            for name in os.listdir(SESS_DIR):
                p = os.path.join(SESS_DIR, name)
                try:
                    if os.path.getmtime(p) < cutoff:
                        os.remove(p)
                except OSError:
                    pass


# ------------------------------------------------------------------ public-mode seed
# (asset, cve, cvss, title, detected_days_ago, verified_days_ago|None)
SEED_ASSETS = [
    ("pan-fw-edge-01", "critical", 1, "network-team", 0),
    ("web-lb-01", "high", 1, "web-team", 1),
    ("db-prod-01", "critical", 0, "dba-team", 0),
    ("jump-host-01", "high", 1, "infra-team", 0),
    ("legacy-app-03", "medium", 0, "app-team", 0),
    ("dev-tomcat-07", "low", 0, "dev-team", 0),
    ("payments-api:2.4.1 (debian 12.5)", "critical", 1, "payments-team", 0),
    ("build-agent-02", "medium", 0, "ci-team", 0),
    ("mail-relay-01", "medium", 0, "infra-team", 0),
    ("citrix-adc-01", "critical", 1, "network-team", 0),
    ("wiki-01", "medium", 0, "app-team", 0),
]
SEED_FINDINGS = [
    # ~5 months of verified history (dwell time trending down)
    ("web-lb-01", "CVE-2023-38545", 9.8, "curl SOCKS5 Heap Buffer Overflow", 140, 118),
    ("mail-relay-01", "CVE-2023-5678", 5.3, "OpenSSL DH Key Generation DoS", 132, 112),
    ("jump-host-01", "CVE-2023-48795", 5.9, "SSH Terrapin Prefix Truncation", 105, 89),
    ("db-prod-01", "CVE-2024-0727", 5.5, "OpenSSL PKCS12 NULL Dereference", 98, 84),
    ("build-agent-02", "CVE-2024-2511", 5.9, "OpenSSL Session Cache DoS", 70, 61),
    ("pan-fw-edge-01", "CVE-2024-3596", 9.0, "RADIUS Blast-RADIUS Forgery", 68, 59),
    ("web-lb-01", "CVE-2022-48174", 9.8, "BusyBox Stack Overflow", 66, 58),
    ("citrix-adc-01", "CVE-2023-4966", 9.4, "Citrix NetScaler Session Hijack (Citrix Bleed)", 40, 38),
    ("mail-relay-01", "CVE-2024-28182", 7.5, "nghttp2 CONTINUATION Flood", 38, 33.5),
    ("dev-tomcat-07", "CVE-2024-23897", 9.8, "Jenkins CLI Arbitrary File Read", 15, 13),
    ("wiki-01", "CVE-2023-22515", 10.0, "Atlassian Confluence Privilege Escalation", 12, 9.5),
    # open backlog with varied ages and SLA states
    ("pan-fw-edge-01", "CVE-2024-3400", 10.0, "PAN-OS GlobalProtect Command Injection", 2, None),
    ("web-lb-01", "CVE-2023-44487", 7.5, "HTTP/2 Rapid Reset DDoS", 20, None),
    ("jump-host-01", "CVE-2024-6387", 8.1, "OpenSSH regreSSHion RCE", 26, None),
    ("db-prod-01", "CVE-2024-1086", 7.8, "Linux Kernel netfilter Use-After-Free", 4, None),
    ("dev-tomcat-07", "CVE-2022-22965", 9.8, "Spring4Shell RCE", 6.5, None),
    ("payments-api:2.4.1 (debian 12.5)", "CVE-2023-45853", 9.8, "zlib integer overflow", 10, None),
    ("payments-api:2.4.1 (debian 12.5)", "CVE-2024-6345", 8.8, "setuptools RCE via download functions", 33, None),
    ("payments-api:2.4.1 (debian 12.5)", "CVE-2024-28085", 6.7, "util-linux wall escape injection", 45, None),
    ("payments-api:2.4.1 (debian 12.5)", "CVE-2024-35195", 5.6, "requests cert verification bypass", 95, None),
    ("mail-relay-01", "CVE-2021-3449", 5.9, "OpenSSL NULL Pointer Dereference", 15, None),
    ("build-agent-02", "CVE-2023-38408", 9.8, "OpenSSH ssh-agent Forwarding RCE", 8, None),
]
# offline fallback so a hosted instance still seeds if feeds are unreachable at boot
FALLBACK_KEV = {"CVE-2024-3400", "CVE-2023-44487", "CVE-2019-0708", "CVE-2022-22965",
                "CVE-2024-1086", "CVE-2023-4966", "CVE-2023-22515"}
FALLBACK_EPSS = {"CVE-2024-3400": .97, "CVE-2023-44487": .97, "CVE-2024-6387": .92,
                 "CVE-2024-1086": .28, "CVE-2022-22965": .96, "CVE-2023-4966": .96,
                 "CVE-2023-22515": .94, "CVE-2023-38408": .80, "CVE-2021-3449": .63}


def build_seed():
    """Build the seed database every visitor's sandbox is copied from."""
    con = db.connect()
    try:
        if con.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]:
            return
        t0 = db.now()
        d = lambda days: db.iso(t0 - datetime.timedelta(days=days))
        con.executemany("INSERT OR IGNORE INTO assets VALUES(?,?,?,?,?,?)",
                        [(h, c, i, o, cc, d(150)) for h, c, i, o, cc in SEED_ASSETS])
        for asset, cve, cvss, title, det, ver in SEED_FINDINGS:
            if ver is None:
                con.execute("INSERT INTO findings(asset,cve,cvss,title,detected_at)"
                            " VALUES(?,?,?,?,?)", (asset, cve, cvss, title, d(det)))
            else:
                con.execute(
                    "INSERT INTO findings(asset,cve,cvss,title,detected_at,remediated_at,"
                    "verified_at,status) VALUES(?,?,?,?,?,?,?,'verified')",
                    (asset, cve, cvss, title, d(det), d(ver + 0.5), d(ver)))
        con.execute("INSERT INTO findings(asset,cve,cvss,title,detected_at,status,"
                    "accepted_until,accepted_reason) VALUES(?,?,?,?,?,'accepted',?,?)",
                    ("legacy-app-03", "CVE-2019-0708", 9.8, "Microsoft RDP BlueKeep RCE",
                     d(30), db.iso(t0 + datetime.timedelta(days=60)),
                     "Isolated to management VLAN; decommission scheduled next quarter."))
        con.execute("UPDATE findings SET reopened=1 WHERE cve='CVE-2024-28182'")
        try:
            kev = enrich.get_kev(con)
            epss = enrich.get_epss([r[1] for r in SEED_FINDINGS])
        except Exception:
            kev, epss = FALLBACK_KEV, dict(FALLBACK_EPSS)
        rescore(con, kev, epss, all_statuses=True)
        db.log(con, "system", "seed_built", f"{len(SEED_FINDINGS) + 1} findings")
        con.commit()
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        con.close()


# ------------------------------------------------------------------ app & auth
app = FastAPI(title="vulnmgmt", version="1.0")
_stop = threading.Event()


if PUBLIC_DEMO:
    @app.middleware("http")
    async def session_sandbox(request: Request, call_next):
        """Each visitor works on their own copy of the seed database."""
        sid = request.cookies.get("vm_sid", "")
        if not re.fullmatch(r"[0-9a-f]{32}", sid):
            sid = uuid.uuid4().hex
        path = os.path.join(SESS_DIR, sid + ".db")
        if not os.path.exists(path):
            shutil.copy(SEED_DB, path)
        token = db.db_path.set(path)
        try:
            response = await call_next(request)
        finally:
            db.db_path.reset(token)
        response.set_cookie("vm_sid", sid, max_age=SESSION_TTL_HOURS * 3600,
                            httponly=True, samesite="lax")
        return response


@app.on_event("startup")
def startup():
    if PUBLIC_DEMO:
        build_seed()
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
            if k in body and not PUBLIC_DEMO:  # public instance: no outbound targets for visitors
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
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, f"file exceeds {MAX_UPLOAD // 1_000_000} MB limit")
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
        if not PUBLIC_DEMO:  # worker threads don't carry the visitor's sandbox context
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
    if PUBLIC_DEMO:
        return {"webhook": "disabled on the public instance — run your own copy to connect",
                "jira": "disabled on the public instance — run your own copy to connect"}
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
