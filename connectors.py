"""Outbound connectors: chat webhook (Slack/Discord-compatible) and Jira Cloud.

Configured in the Settings tab (persisted in the config table) — no restart
needed. The webhook payload carries both "text" (Slack) and "content"
(Discord), so one URL setting serves either.
"""
import base64, json, urllib.error, urllib.request


def _req(url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json", "User-Agent": "vulnmgmt/1.0",
        **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
    try:
        return json.loads(raw)
    except ValueError:
        return {}  # Slack webhooks answer plain "ok"


def webhook_enabled(cfg):
    return bool(cfg.get("webhook_url"))


def jira_enabled(cfg):
    return all(cfg.get(k) for k in ("jira_url", "jira_email", "jira_token", "jira_project"))


def notify(cfg, text):
    _req(cfg["webhook_url"], {"text": text, "content": text})


def _jira(cfg, path, payload=None):
    tok = base64.b64encode(f"{cfg['jira_email']}:{cfg['jira_token']}".encode()).decode()
    return _req(cfg["jira_url"].rstrip("/") + path, payload,
                {"Authorization": "Basic " + tok})


def jira_check(cfg):
    """Auth probe — GET /myself succeeds iff url+email+token are valid."""
    return _jira(cfg, "/rest/api/2/myself").get("displayName", "ok")


def jira_create(cfg, f):
    fields = {
        "project": {"key": cfg["jira_project"]},
        "issuetype": {"name": "Task"},
        "summary": f"[{f['priority']}] {f['cve']} on {f['asset']}",
        "description": (
            f"CVE: {f['cve']}\nAsset: {f['asset']}\nTitle: {f['title'] or '-'}\n"
            f"Risk score: {f['risk_score']}  CVSS: {f['cvss']}  EPSS: {f['epss']}  "
            f"KEV: {'YES' if f['kev'] else 'no'}\n"
            f"Detected: {f['detected_at']}Z\nSLA due: {f['due_at']}Z\n"
            + (f"Remediation: {f['solution']}\n" if f['solution'] else "")
            + f"\nOpened by vulnmgmt (finding #{f['id']}). Close only after rescan verification."),
    }
    if f.get("due_at"):
        fields["duedate"] = f["due_at"][:10]
    try:
        return _jira(cfg, "/rest/api/2/issue", {"fields": fields})["key"]
    except urllib.error.HTTPError:
        # projects without the Due Date field reject the create; retry without it
        fields.pop("duedate", None)
        return _jira(cfg, "/rest/api/2/issue", {"fields": fields})["key"]


def jira_comment(cfg, key, text):
    _jira(cfg, f"/rest/api/2/issue/{key}/comment", {"body": text})
