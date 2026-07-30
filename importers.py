"""Scan-result importers with format auto-detection.

Supported: Nessus CSV export, Trivy JSON, Grype JSON, generic CSV
(asset,cve,cvss[,title]). Each parser yields normalized dicts:
{asset, cve, cvss, title, solution, source}. Findings without a CVE id
(informational plugins) are skipped. Duplicate asset+CVE rows are collapsed
keeping the highest CVSS.
"""
import csv, io, json, re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def parse(filename, raw: bytes):
    text = raw.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        data = json.loads(text)
        if isinstance(data, dict) and "Results" in data:
            rows = _trivy(data)
        elif isinstance(data, dict) and "matches" in data:
            rows = _grype(data)
        else:
            raise ValueError("unrecognized JSON: expected Trivy (Results) or Grype (matches)")
    else:
        reader = csv.DictReader(io.StringIO(text))
        headers = [h.strip() for h in (reader.fieldnames or [])]
        if "Plugin ID" in headers:
            rows = _nessus(reader)
        elif {"asset", "cve", "cvss"} <= {h.lower() for h in headers}:
            rows = _generic(reader)
        else:
            raise ValueError(f"unrecognized CSV headers: {headers}."
                             " Expected Nessus export or asset,cve,cvss[,title]")
    return _dedupe(rows)


def _dedupe(rows):
    best = {}
    for r in rows:
        key = (r["asset"], r["cve"])
        if key not in best or (r["cvss"] or 0) > (best[key]["cvss"] or 0):
            best[key] = r
    return list(best.values())


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _nessus(reader):
    for row in reader:
        cve = (row.get("CVE") or "").strip().upper()
        if not CVE_RE.fullmatch(cve):
            continue
        cvss = (_num(row.get("CVSS v3.0 Base Score")) or _num(row.get("CVSS v3.1 Base Score"))
                or _num(row.get("CVSS")) or _num(row.get("CVSS v2.0 Base Score")))
        yield {"asset": (row.get("Host") or "").strip(), "cve": cve, "cvss": cvss,
               "title": (row.get("Name") or "").strip() or None,
               "solution": (row.get("Solution") or "").strip() or None, "source": "nessus"}


def _trivy(data):
    default_asset = data.get("ArtifactName") or "unknown"
    for result in data.get("Results") or []:
        asset = result.get("Target") or default_asset
        for v in result.get("Vulnerabilities") or []:
            cve = (v.get("VulnerabilityID") or "").upper()
            if not CVE_RE.fullmatch(cve):
                continue
            cvss = None
            for src in (v.get("CVSS") or {}).values():
                cvss = src.get("V3Score") or src.get("V2Score") or cvss
            yield {"asset": asset, "cve": cve, "cvss": _num(cvss),
                   "title": v.get("Title") or f'{v.get("PkgName", "")} {v.get("InstalledVersion", "")}'.strip() or None,
                   "solution": (f'upgrade {v["PkgName"]} to {v["FixedVersion"]}'
                                if v.get("FixedVersion") else None),
                   "source": "trivy"}


def _grype(data):
    asset = ((data.get("source") or {}).get("target") or {})
    asset = asset.get("userInput") if isinstance(asset, dict) else asset
    asset = asset or "unknown"
    for m in data.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        cve = (vuln.get("id") or "").upper()
        if not CVE_RE.fullmatch(cve):
            related = (m.get("relatedVulnerabilities") or [{}])[0]
            cve = (related.get("id") or "").upper()
            if not CVE_RE.fullmatch(cve):
                continue
        cvss = None
        for c in vuln.get("cvss") or []:
            cvss = (c.get("metrics") or {}).get("baseScore") or cvss
        art = m.get("artifact") or {}
        yield {"asset": str(asset), "cve": cve, "cvss": _num(cvss),
               "title": f'{art.get("name", "")} {art.get("version", "")}'.strip() or None,
               "solution": None, "source": "grype"}


def _generic(reader):
    for row in reader:
        row = {k.lower().strip(): (v or "").strip() for k, v in row.items() if k}
        cve = row.get("cve", "").upper()
        if not CVE_RE.fullmatch(cve):
            continue
        yield {"asset": row.get("asset", ""), "cve": cve, "cvss": _num(row.get("cvss")),
               "title": row.get("title") or None, "solution": row.get("solution") or None,
               "source": "csv"}
