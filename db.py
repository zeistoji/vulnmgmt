"""SQLite persistence layer. WAL mode, one connection per request/thread.

In public mode the app serves many anonymous visitors, each with an isolated
database: request middleware points `db_path` (a contextvar) at that
visitor's session copy; background threads fall back to DB_PATH."""
import contextvars, datetime, json, os, sqlite3

DB_PATH = os.environ.get("VULNMGMT_DB",
                         os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnmgmt.db"))
db_path = contextvars.ContextVar("db_path", default=None)

DEFAULT_CONFIG = {
    "sla_days": {"P1": 7, "P2": 30, "P3": 90, "P4": 180},
    "kev_target_hours": 72,
    "sla_target_pct": 92,
    # connectors (Settings tab): chat webhook + Jira ticketing
    "webhook_url": "",
    "jira_url": "", "jira_email": "", "jira_token": "", "jira_project": "",
    "ticket_min": "P2",  # auto-create tickets for findings at this priority or above
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets(
  hostname TEXT PRIMARY KEY,
  criticality TEXT NOT NULL DEFAULT 'medium',      -- critical|high|medium|low
  internet_facing INTEGER NOT NULL DEFAULT 0,
  owner TEXT NOT NULL DEFAULT 'unassigned',
  compensating_control INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY,
  asset TEXT NOT NULL,
  cve TEXT NOT NULL,
  title TEXT,
  solution TEXT,
  source TEXT,                                     -- nessus|trivy|grype|csv
  cvss REAL,
  detected_at TEXT NOT NULL,
  remediated_at TEXT,
  verified_at TEXT,
  status TEXT NOT NULL DEFAULT 'open',             -- open|remediated|verified|accepted
  epss REAL,
  kev INTEGER NOT NULL DEFAULT 0,
  risk_score REAL,
  priority TEXT,
  due_at TEXT,
  reopened INTEGER NOT NULL DEFAULT 0,
  accepted_until TEXT,
  accepted_reason TEXT,
  enriched_at TEXT,
  UNIQUE(asset, cve));
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE TABLE IF NOT EXISTS activity(
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
"""

now = lambda: datetime.datetime.utcnow().replace(microsecond=0)
iso = lambda dt: dt.isoformat()
parse = datetime.datetime.fromisoformat


def connect():
    con = sqlite3.connect(db_path.get() or DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(SCHEMA)
    for col in ("jira_key TEXT", "notified_state TEXT"):  # additive migrations
        try:
            con.execute(f"ALTER TABLE findings ADD COLUMN {col}")
        except sqlite3.OperationalError:
            pass
    return con


def get_config(con):
    row = con.execute("SELECT value FROM meta WHERE key='config'").fetchone()
    cfg = dict(DEFAULT_CONFIG)
    if row:
        cfg.update(json.loads(row["value"]))
    return cfg


def set_config(con, cfg):
    con.execute("INSERT OR REPLACE INTO meta VALUES('config', ?)", (json.dumps(cfg),))
    con.commit()


def log(con, actor, action, detail=""):
    con.execute("INSERT INTO activity(ts, actor, action, detail) VALUES(?,?,?,?)",
                (iso(now()), actor, action, detail))
