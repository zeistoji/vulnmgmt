# vulnmgmt — Risk-Based Vulnerability Management

A self-hosted vulnerability management server implementing a risk-based
remediation programme aligned to **NIST SP 800-40**, **ISO 27001 A.8.8**, and
**CIS Control 7**: scanner import → live threat-intel enrichment → composite
risk scoring → SLA tracking with escalation → rescan-gated closure → metrics
dashboard.

FastAPI + SQLite. No other infrastructure required.

## Hosting it publicly (portfolio link)

The repo ships a [render.yaml](render.yaml) Blueprint that deploys the real
server to Render's free tier with `VULNMGMT_PUBLIC=1`. In public mode every
visitor is silently given **their own sandboxed copy of the database**
(cookie-keyed, seeded with a realistic five-month programme history, cleaned
up after 24 h), so strangers can freely import scans, remediate, verify, and
accept risk without stepping on each other — while enrichment still runs
against the live CISA KEV feed and EPSS API. Outbound connectors and NVD
backfill are disabled for visitors, and uploads are capped at 5 MB.
Note: free-tier instances sleep when idle — the first visit after a quiet
period takes ~30–60 s to wake.

## Run

```bash
pip install -r requirements.txt
uvicorn app:app --port 8321
```

Open http://localhost:8321. To require authentication, set `VULNMGMT_TOKEN`
before starting — all `/api/*` calls then need `Authorization: Bearer <token>`
(the UI prompts for it). Optional `NVD_API_KEY` raises the NVD backfill rate
limit. `VULNMGMT_DB` overrides the database path.

## What it does

**Import** (`POST /api/import` or the Import tab) — auto-detects and parses:

| Format | Detection |
|---|---|
| Nessus CSV export | `Plugin ID` header |
| Trivy JSON | `Results` key |
| Grype JSON | `matches` key |
| Generic CSV | `asset,cve,cvss[,title,solution]` headers |

New asset+CVE pairs open a finding — **the SLA clock starts at detection**,
not triage. A finding previously verified-fixed that reappears in a scan is
auto-reopened and counted as a recurrence (false-remediation detection).

**Enrichment** — live, on import and hourly in the background:

- **CISA KEV** catalog (24h-cached in DB; KEV listing auto-escalates to P1)
- **FIRST.org EPSS** exploit-prediction scores (batched 100/request)
- **NVD** CVSS backfill for findings that arrive without a score
  (rate-limit-aware background thread)

**Scoring** — `CVSS·20% + EPSS·30% + asset criticality·25% + internet
exposure·15% − compensating control·10`, with priority tiers:

| Priority | Criteria | Default SLA |
|---|---|---|
| P1 | KEV-listed, or CVSS≥9 + EPSS≥0.5 on exposed/critical asset | 7 days |
| P2 | CVSS 7–8.9 | 30 days |
| P3 | CVSS 4–6.9 | 90 days |
| P4 | CVSS <4 | 180 days |

SLA days and targets are editable in Settings; changes rescore all open
findings. Asset context (criticality, internet-facing, owner, compensating
control) is set in the Assets tab — this is what makes prioritisation
risk-based instead of CVSS-based.

**Lifecycle** — `open → remediated → verified`, enforced server-side:

- `verify` requires `remediated` — **tickets close only on rescan
  confirmation**, never on "patch deployed"
- `verify_failed` reopens and increments the recurrence counter
- `accept` (risk acceptance) requires a written justification **and an expiry
  date** — never indefinite; the background job reopens expired acceptances
- Every transition is written to the audit log (Activity tab)

**Escalation** — computed from the SLA clock: notify owner at 50% of the
window, escalate at 90%, breach past due. Surfaced on the dashboard and per
finding.

**Dashboard** — MTTR (dwell time) by priority, SLA compliance % (verified +
past-due), open backlog by priority, backlog aging histogram, monthly dwell
trend, open KEV exposures against a 72-hour target, recurrence rate, slowest
owners by average dwell, KEV catalog version/freshness.

**Connectors** (Settings tab, no restart needed):

- **Chat webhook** — one URL works for Slack *or* Discord incoming webhooks.
  Gets import summaries (with new-P1 warnings) and SLA clock alerts at 50%
  (notify), 90% (escalate), and breach — each state fires once per finding.
- **Jira** — base URL + email + API token + project key. Auto-creates a
  ticket (with SLA due date) for every finding at or above the chosen
  priority; SLA alerts and rescan results (`verified clean` / `rescan
  FAILED — reopened`) land as comments on the ticket. Closing the Jira
  ticket is left to the engineer — the system's own closure still requires
  a rescan. Use **Test connectors** to check both before relying on them.

## Getting scan files

Any of these produce files the Import tab accepts directly:

- **Trivy** (bundled at `tools/trivy.exe`, free OSS) —
  `tools\trivy.exe fs --scanners vuln --format json --output scan.json <path>`
  for filesystems/repos, or `trivy image --format json -o scan.json <image>`
  for containers
- **Grype** (free OSS) — `grype <target> -o json > scan.json`
- **Nessus Essentials** (free for 16 IPs) — export scan results as CSV
- **Anything else** — a CSV with `asset,cve,cvss[,title,solution]` columns

## API

`GET /api/health` · `GET/PUT /api/config` · `GET/POST /api/assets` ·
`DELETE /api/assets/{hostname}` · `POST /api/import` · `GET /api/findings`
(filters: `status`, `priority`, `q`, `kev_only`) ·
`POST /api/findings/{id}/action` (`remediate|verify|verify_failed|accept|reopen`) ·
`POST /api/enrich` · `GET /api/metrics` · `GET /api/export.csv` ·
`GET /api/activity`. Interactive docs at `/docs`.

## Files

- [app.py](app.py) — API, auth, scoring, SLA engine, background housekeeping
- [db.py](db.py) — SQLite schema (WAL), config, audit log
- [enrich.py](enrich.py) — KEV / EPSS / NVD clients
- [importers.py](importers.py) — format auto-detection and parsers
- [static/index.html](static/index.html) — dashboard UI (no build step)
- [samples/](samples/) — example Nessus CSV and Trivy JSON for a first import

## Evidence discipline

To claim a dwell-time improvement, baseline MTTR over a pre-programme period
from the same `detected_at → verified_at` timestamps this system records —
metrics are only defensible when detection-to-verified-closure is measured,
not estimated.
