"""Threat-intel clients: CISA KEV feed, FIRST.org EPSS API, NVD CVE API.

KEV is cached in the meta table with a 24h TTL. EPSS is fetched in batches of
100 CVEs per request. NVD is a best-effort backfill for findings that arrive
without a CVSS score (rate-limited: 5 req/30s anonymous, 50 with NVD_API_KEY).
"""
import datetime, json, os, time, urllib.parse, urllib.request

import db

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
KEV_TTL_HOURS = 24
UA = {"User-Agent": "vulnmgmt/1.0"}


def _get(url, timeout=60, headers=None):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def get_kev(con, force=False):
    """Return set of KEV CVE ids, refreshing the cached feed if stale."""
    row = con.execute("SELECT value FROM meta WHERE key='kev'").fetchone()
    if row and not force:
        cached = json.loads(row["value"])
        age = db.now() - db.parse(cached["fetched_at"])
        if age < datetime.timedelta(hours=KEV_TTL_HOURS):
            return set(cached["cves"])
    data = _get(KEV_URL)
    cves = sorted({v["cveID"] for v in data["vulnerabilities"]})
    con.execute("INSERT OR REPLACE INTO meta VALUES('kev', ?)",
                (json.dumps({"fetched_at": db.iso(db.now()), "cves": cves,
                             "catalog_version": data.get("catalogVersion")}),))
    con.commit()
    return set(cves)


def get_epss(cves):
    """Batch EPSS lookup. Returns {cve: probability}."""
    out, cves = {}, sorted({c for c in cves if c.startswith("CVE-")})
    for i in range(0, len(cves), 100):
        url = EPSS_URL + ",".join(cves[i:i + 100])
        try:
            for row in _get(url)["data"]:
                out[row["cve"]] = float(row["epss"])
        except Exception:
            pass  # partial enrichment beats none; refreshed on next cycle
    return out


def nvd_cvss(cve):
    """Best-effort CVSS base score from NVD for a single CVE, or None."""
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    try:
        data = _get(NVD_URL + urllib.parse.quote(cve), timeout=30, headers=headers)
        metrics = data["vulnerabilities"][0]["cve"]["metrics"]
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                return float(metrics[key][0]["cvssData"]["baseScore"])
    except Exception:
        return None
    return None


def nvd_backfill(limit=25):
    """Fill missing CVSS scores from NVD, honouring the anonymous rate limit.
    Runs in the background thread; re-enriches what it fills."""
    con = db.connect()
    try:
        rows = con.execute("SELECT DISTINCT cve FROM findings WHERE cvss IS NULL"
                           " AND status IN ('open','remediated') LIMIT ?", (limit,)).fetchall()
        delay = 1.5 if os.environ.get("NVD_API_KEY") else 6.5
        filled = 0
        for r in rows:
            score = nvd_cvss(r["cve"])
            if score is not None:
                con.execute("UPDATE findings SET cvss=? WHERE cve=? AND cvss IS NULL",
                            (score, r["cve"]))
                con.commit()
                filled += 1
            time.sleep(delay)
        return filled
    finally:
        con.close()
