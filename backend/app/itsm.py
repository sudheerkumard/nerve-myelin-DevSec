# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Ticketing (ITSM) integrations: turn findings into assigned work items and keep them in step with re-scans.

  kind           system                         credential (pasted once, kept in the vault)
  jira           Jira Cloud / Data Center       Cloud: API token (+ account e-mail in config); Data Center: personal access token
  servicenow     ServiceNow (any table)         "username:password" (basic) or "Bearer <OAuth token>"
  azure_boards   Azure DevOps Boards            personal access token with Work Items (Read & write)
  webhook        Microsoft Teams, Slack, any    optional "Header-Name: value" (e.g. an authorisation header)

Behaviour
  * one ticket per finding (fingerprint) — never duplicated; the ticket reference is stored on the finding
  * routing rules pick the assignee / group / area per repository, engine or severity; first match wins
  * automatic mode raises tickets for new findings at or above a priority after every scan (capped per scan)
  * when a re-scan no longer sees the finding, the ticket gets a comment and is resolved (if configured);
    when it comes back, the ticket gets a comment
"""
import base64
import copy
import fnmatch
import html as _html
import ipaddress
import json
import os
import re
import socket
import urllib.parse
import uuid
from datetime import datetime, timezone

import httpx

KINDS = {
    "jira": {"title": "Jira (Cloud or Data Center)",
             "fields": ["base_url", "deployment", "email", "project_key", "issue_type", "labels", "resolve_transition"],
             "credential": "Jira Cloud: API token (id.atlassian.com → Security → API tokens). Data Center: personal access token."},
    "servicenow": {"title": "ServiceNow",
                   "fields": ["base_url", "table", "assignment_group", "category", "resolve_fields"],
                   "credential": "username:password of an integration user with the itil role, or 'Bearer <OAuth token>'."},
    "azure_boards": {"title": "Azure DevOps Boards",
                     "fields": ["organization", "project", "work_item_type", "area_path", "resolved_state"],
                     "credential": "Personal access token with Work Items: Read & write."},
    "webhook": {"title": "Webhook (Microsoft Teams, Slack, any HTTPS endpoint)", "fields": ["url"],
                "credential": "Optional header, e.g. 'Authorization: Bearer <token>'."},
}
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
JIRA_PRIORITY = {"P0": "Highest", "P1": "High", "P2": "Medium", "P3": "Low", "P4": "Lowest"}
SN_URGENCY = {"P0": "1", "P1": "1", "P2": "2", "P3": "3", "P4": "3"}
SN_IMPACT = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "3"}
ADO_SEVERITY = {"critical": "1 - Critical", "high": "2 - High", "medium": "3 - Medium", "low": "4 - Low", "info": "4 - Low"}
ADO_PRIORITY = {"P0": 1, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
MAX_AUTO_PER_SCAN = 25


class ItsmError(ValueError):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def now():
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ validation
def _https(url, field):
    u = urllib.parse.urlsplit((url or "").strip())
    if u.scheme != "https" or not u.hostname:
        raise ItsmError(f"{field} must be an https address")
    return f"https://{u.netloc}{u.path.rstrip('/')}"


def _guard(url):
    if os.environ.get("MYELIN_ITSM_ALLOW_PRIVATE") == "1":
        return
    host = urllib.parse.urlsplit(url).hostname
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(host, 443)}
    except socket.gaierror:
        raise ItsmError(f"cannot resolve {host}") from None
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_unspecified:
            raise ItsmError(f"{host} resolves to an internal address; on-premises ticketing systems need "
                            "MYELIN_ITSM_ALLOW_PRIVATE=1 on the platform")


def new_integration(body: dict, actor: str) -> dict:
    kind = body.get("kind")
    if kind not in KINDS:
        raise ItsmError(f"kind must be one of {', '.join(KINDS)}")
    cfg = {k: v for k, v in (body.get("config") or {}).items() if v not in (None, "")}
    if kind == "jira":
        cfg["base_url"] = _https(cfg.get("base_url"), "Jira address")
        cfg.setdefault("deployment", "cloud" if cfg["base_url"].endswith(".atlassian.net") else "datacenter")
        if not re.match(r"^[A-Z][A-Z0-9_]{0,19}$", str(cfg.get("project_key", ""))):
            raise ItsmError("project_key is the Jira project key, e.g. SEC")
        if cfg["deployment"] == "cloud" and "@" not in str(cfg.get("email", "")):
            raise ItsmError("Jira Cloud needs the e-mail address of the account that owns the API token")
        cfg.setdefault("issue_type", "Bug")
    elif kind == "servicenow":
        cfg["base_url"] = _https(cfg.get("base_url"), "ServiceNow address")
        cfg.setdefault("table", "incident")
        if not re.match(r"^[a-z][a-z0-9_]{1,79}$", cfg["table"]):
            raise ItsmError("table must be a ServiceNow table name, e.g. incident")
        cfg.setdefault("category", "security")
    elif kind == "azure_boards":
        for f in ("organization", "project"):
            if not cfg.get(f):
                raise ItsmError(f"{f} is required")
        cfg.setdefault("work_item_type", "Bug")
        cfg.setdefault("resolved_state", "Done")
    elif kind == "webhook":
        cfg["url"] = _https(cfg.get("url"), "Webhook address")
    cfg["routing"] = _routing(body.get("routing") or cfg.get("routing") or [])
    auto = body.get("auto") or cfg.get("auto") or {}
    cfg["auto"] = {"enabled": bool(auto.get("enabled")), "min_priority": auto.get("min_priority", "P1"),
                   "engines": [e for e in (auto.get("engines") or []) if isinstance(e, str)]}
    if cfg["auto"]["min_priority"] not in PRIORITY_RANK:
        raise ItsmError("auto.min_priority must be P0-P4")
    name = (body.get("name") or KINDS[kind]["title"]).strip()[:200]
    return {"id": uuid.uuid4(), "name": name, "kind": kind, "config": cfg, "credential_ref": None, "enabled": True,
            "last_error": None, "created_by": actor, "created_at": now()}


def _routing(rules):
    out = []
    for r in rules[:100]:
        if not isinstance(r, dict):
            continue
        m, a = r.get("match") or {}, r.get("assign") or {}
        out.append({"match": {k: m[k] for k in ("repo", "engine", "min_priority") if m.get(k)},
                    "assign": {k: str(a[k])[:300] for k in ("assignee", "assignment_group", "area_path", "component", "labels") if a.get(k)}})
    return out


def route(cfg: dict, f: dict) -> dict:
    """Assignment for a finding: the first routing rule that matches, else the integration defaults."""
    for r in cfg.get("routing") or []:
        m = r["match"]
        if m.get("repo") and not fnmatch.fnmatch(str(f.get("repo", "")), m["repo"]):
            continue
        if m.get("engine") and f.get("engine") not in [e.strip() for e in str(m["engine"]).split(",")]:
            continue
        if m.get("min_priority") and PRIORITY_RANK.get(f.get("priority"), 9) > PRIORITY_RANK.get(m["min_priority"], 9):
            continue
        return r["assign"]
    return {k: cfg[k] for k in ("assignee", "assignment_group", "area_path", "component") if cfg.get(k)}


# ------------------------------------------------------------------ content
def summary(f: dict) -> str:
    ident = f.get("cve") or f.get("rule_id") or ""
    title = f.get("title") or ""
    s = f"[{f.get('priority', '')}][{str(f.get('severity', '')).upper()}] {ident + ': ' if ident and ident not in title else ''}{title} — {f.get('repo', '')}"
    return s[:250]


def description(f: dict, console_url: str = "") -> str:
    loc = f.get("file") or ""
    if f.get("line"):
        loc += f":{f['line']}"
    rows = [("Repository", f.get("repo")), ("Finding", f"{f.get('id')} ({f.get('engine')})"),
            ("Severity / priority", f"{f.get('severity')} · {f.get('priority')} · NERvvE Risk Score {f.get('mrs')} · fix within {f.get('sla_days')} days"),
            ("CVE", f.get("cve")), ("Advisory", f.get("advisory")), ("Weakness", f.get("cwe")),
            ("Package", f"{f.get('package')} {f.get('version')}" + (f" → fixed in {f['fixed_version']}" if f.get("fixed_version") else "")
             if f.get("package") else None),
            ("Introduced by", f.get("introduced_by")), ("Location", loc or None), ("Evidence", f.get("evidence")),
            ("Remediation", f.get("remediation"))]
    text = "\n".join(f"{k}: {v}" for k, v in rows if v)
    if console_url:
        text += f"\n\nOpen in NERvvE DevSecOps: {console_url.rstrip('/')}/#findings"
    return text + "\n\nRaised by NERvvE DevSecOps. The ticket is updated automatically when a re-scan confirms the fix."


# ------------------------------------------------------------------ clients
class Client:
    def __init__(self, integ: dict, credential: str | None, transport=None):
        self.i, self.cfg, self.cred = integ, integ["config"], (credential or "").strip()
        self.http = httpx.Client(timeout=20, transport=transport, follow_redirects=False)

    # ---- auth
    def _headers(self):
        k, c = self.i["kind"], self.cred
        if not c:
            return {}
        if k == "jira":
            if self.cfg.get("deployment") == "cloud":
                return {"Authorization": "Basic " + base64.b64encode(f"{self.cfg['email']}:{c}".encode()).decode()}
            return {"Authorization": f"Bearer {c}"}
        if k == "servicenow":
            if c.lower().startswith("bearer "):
                return {"Authorization": c}
            user, _, pw = c.partition(":")
            return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
        if k == "azure_boards":
            return {"Authorization": "Basic " + base64.b64encode(f":{c}".encode()).decode()}
        if k == "webhook" and ":" in c:
            name, _, val = c.partition(":")
            return {name.strip(): val.strip()}
        return {}

    def _req(self, method, url, **kw):
        _guard(url)
        headers = {"Accept": "application/json", "User-Agent": "NERvvE-DevSecOps", **self._headers(), **kw.pop("headers", {})}
        try:
            r = self.http.request(method, url, headers=headers, **kw)
        except httpx.HTTPError as e:
            raise ItsmError(f"cannot reach {urllib.parse.urlsplit(url).hostname}: {type(e).__name__}") from None
        if r.status_code in (401, 403):
            raise ItsmError(f"{KINDS[self.i['kind']]['title']} refused the credential (HTTP {r.status_code})")
        if r.status_code >= 400:
            detail = ""
            try:
                j = r.json()
                detail = "; ".join(filter(None, [*(j.get("errorMessages") or []), *[f"{k}: {v}" for k, v in (j.get("errors") or {}).items()],
                                                 (j.get("error") or {}).get("message") if isinstance(j.get("error"), dict) else None,
                                                 j.get("message")]))
            except ValueError:
                detail = r.text[:200]
            raise ItsmError(f"HTTP {r.status_code}: {detail[:400]}", 502)
        return r

    # ---- operations
    def check(self) -> str:
        k, c = self.i["kind"], self.cfg
        if k == "jira":
            me = self._req("GET", f"{c['base_url']}/rest/api/2/myself").json()
            self._req("GET", f"{c['base_url']}/rest/api/2/project/{c['project_key']}")
            return f"connected as {me.get('displayName') or me.get('name')}; project {c['project_key']} found"
        if k == "servicenow":
            self._req("GET", f"{c['base_url']}/api/now/table/{c['table']}", params={"sysparm_limit": "1", "sysparm_fields": "sys_id"})
            return f"connected; table {c['table']} is readable"
        if k == "azure_boards":
            p = self._req("GET", f"https://dev.azure.com/{c['organization']}/_apis/projects/{urllib.parse.quote(c['project'])}",
                          params={"api-version": "7.1"}).json()
            return f"connected; project {p.get('name')} found"
        self._req("POST", c["url"], json={"text": "NERvvE DevSecOps: test message — ticketing integration connected."})
        return "test message delivered"

    def create(self, f: dict, assign: dict, console_url: str = "") -> dict:
        k, c = self.i["kind"], self.cfg
        title, body = summary(f), description(f, console_url)
        if k == "jira":
            fields = {"project": {"key": c["project_key"]}, "issuetype": {"name": c.get("issue_type", "Bug")}, "summary": title,
                      "description": body,
                      "labels": [x.strip().replace(" ", "-") for x in (str(c.get("labels") or "security,nerve-myelin") + "," + str(assign.get("labels") or "")).split(",") if x.strip()],
                      "priority": {"name": JIRA_PRIORITY.get(f.get("priority"), "Medium")}}
            if assign.get("assignee"):
                fields["assignee"] = {"accountId": assign["assignee"]} if c.get("deployment") == "cloud" else {"name": assign["assignee"]}
            if assign.get("component"):
                fields["components"] = [{"name": assign["component"]}]
            url = f"{c['base_url']}/rest/api/2/issue"
            try:
                r = self._req("POST", url, json={"fields": fields})
            except ItsmError as e:                      # project screens often hide priority/components: retry without them
                if e.status != 502 or not re.search(r"priority|components|assignee", str(e), re.I):
                    raise
                for opt in ("priority", "components") if "assignee" not in str(e).lower() else ("priority", "components", "assignee"):
                    fields.pop(opt, None)
                r = self._req("POST", url, json={"fields": fields})
            key = r.json()["key"]
            return {"system": "jira", "key": key, "url": f"{c['base_url']}/browse/{key}"}
        if k == "servicenow":
            rec = {"short_description": title[:160], "description": body, "category": c.get("category", "security"),
                   "urgency": SN_URGENCY.get(f.get("priority"), "2"), "impact": SN_IMPACT.get(f.get("severity"), "2"),
                   "correlation_id": f"nerve-myelin:{f.get('fingerprint')}", "correlation_display": "NERvvE DevSecOps"}
            if assign.get("assignment_group") or c.get("assignment_group"):
                rec["assignment_group"] = assign.get("assignment_group") or c["assignment_group"]
            if assign.get("assignee"):
                rec["assigned_to"] = assign["assignee"]
            res = self._req("POST", f"{c['base_url']}/api/now/table/{c['table']}", json=rec,
                            params={"sysparm_display_value": "false", "sysparm_fields": "sys_id,number"}).json()["result"]
            return {"system": "servicenow", "key": res.get("number") or res["sys_id"], "sys_id": res["sys_id"],
                    "url": f"{c['base_url']}/nav_to.do?uri={c['table']}.do%3Fsys_id%3D{res['sys_id']}"}
        if k == "azure_boards":
            html = "<br>".join(_html.escape(x) for x in body.split("\n"))
            ops = [{"op": "add", "path": "/fields/System.Title", "value": title},
                   {"op": "add", "path": "/fields/System.Description" if c.get("work_item_type") != "Bug" else "/fields/Microsoft.VSTS.TCM.ReproSteps", "value": html},
                   {"op": "add", "path": "/fields/System.Tags", "value": "security; nerve-myelin"},
                   {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Priority", "value": ADO_PRIORITY.get(f.get("priority"), 2)}]
            if c.get("work_item_type", "Bug") == "Bug":
                ops.append({"op": "add", "path": "/fields/Microsoft.VSTS.Common.Severity", "value": ADO_SEVERITY.get(f.get("severity"), "3 - Medium")})
            if assign.get("area_path") or c.get("area_path"):
                ops.append({"op": "add", "path": "/fields/System.AreaPath", "value": assign.get("area_path") or c["area_path"]})
            if assign.get("assignee"):
                ops.append({"op": "add", "path": "/fields/System.AssignedTo", "value": assign["assignee"]})
            wit = urllib.parse.quote(c.get("work_item_type", "Bug"))
            r = self._req("POST", f"https://dev.azure.com/{c['organization']}/{urllib.parse.quote(c['project'])}/_apis/wit/workitems/${wit}",
                          params={"api-version": "7.1"}, content=json.dumps(ops), headers={"Content-Type": "application/json-patch+json"}).json()
            return {"system": "azure_boards", "key": str(r["id"]),
                    "url": ((r.get("_links") or {}).get("html") or {}).get("href") or
                    f"https://dev.azure.com/{c['organization']}/{urllib.parse.quote(c['project'])}/_workitems/edit/{r['id']}"}
        self._req("POST", c["url"], json={"text": f"**{title}**\n\n{body}", "finding": {k2: f.get(k2) for k2 in (
            "id", "repo", "engine", "severity", "priority", "mrs", "cve", "cwe", "file", "line", "package", "version", "fixed_version")}})
        return {"system": "webhook", "key": f"notified-{f.get('id')}", "url": None}

    def update(self, ticket: dict, text: str, resolve: bool) -> bool:
        """Comment on (and optionally resolve) an existing ticket. Returns True if it was resolved."""
        k, c = self.i["kind"], self.cfg
        if k == "jira":
            self._req("POST", f"{c['base_url']}/rest/api/2/issue/{ticket['key']}/comment", json={"body": text})
            name = c.get("resolve_transition")
            if resolve and name:
                ts = self._req("GET", f"{c['base_url']}/rest/api/2/issue/{ticket['key']}/transitions").json().get("transitions") or []
                t = next((t for t in ts if t.get("name", "").lower() == name.lower() or (t.get("to") or {}).get("name", "").lower() == name.lower()), None)
                if t:
                    self._req("POST", f"{c['base_url']}/rest/api/2/issue/{ticket['key']}/transitions", json={"transition": {"id": t["id"]}})
                    return True
            return False
        if k == "servicenow":
            patch = {"work_notes": text}
            if resolve:
                rf = c.get("resolve_fields")
                if isinstance(rf, str):
                    try:
                        rf = json.loads(rf)
                    except ValueError:
                        rf = None
                patch.update(rf or ({"state": "6", "close_code": "Solved (Permanently)", "close_notes": text} if c["table"] == "incident" else {}))
            self._req("PATCH", f"{c['base_url']}/api/now/table/{c['table']}/{ticket['sys_id']}", json=patch)
            return resolve and (bool(c.get("resolve_fields")) or c["table"] == "incident")
        if k == "azure_boards":
            base = f"https://dev.azure.com/{c['organization']}/{urllib.parse.quote(c['project'])}/_apis/wit/workItems/{ticket['key']}"
            self._req("POST", f"{base}/comments", params={"api-version": "7.1-preview.4"}, json={"text": text})
            if resolve and c.get("resolved_state"):
                self._req("PATCH", base.replace("/workItems/", "/workitems/"), params={"api-version": "7.1"},
                          content=json.dumps([{"op": "add", "path": "/fields/System.State", "value": c["resolved_state"]}]),
                          headers={"Content-Type": "application/json-patch+json"})
                return True
            return False
        self._req("POST", c["url"], json={"text": text})
        return False


# ------------------------------------------------------------------ orchestration
def eligible(cfg: dict, f: dict) -> bool:
    a = cfg.get("auto") or {}
    if not a.get("enabled") or f.get("status", "open") != "open":
        return False
    if PRIORITY_RANK.get(f.get("priority"), 9) > PRIORITY_RANK.get(a.get("min_priority", "P1"), 1):
        return False
    return not a.get("engines") or f.get("engine") in a["engines"]


def raise_ticket(store, client: Client, integ: dict, f: dict, actor: str, console_url: str = "") -> dict:
    if f.get("ticket"):
        return f["ticket"]
    t = client.create(f, route(integ["config"], f), console_url)
    t.update(integration_id=str(integ["id"]), created_at=now().isoformat(), status="open")
    store.set_ticket(f["id"], t, actor)
    return t


def process_delta(store, integrations, delta, client_for, actor="nerve-myelin", console_url=""):
    """After a scan: tickets for new eligible findings; comments/resolution for fixed and reopened ones.
    Errors are recorded per integration and never interrupt the scan."""
    if not delta:
        return {"created": 0, "updated": 0, "errors": []}
    out = {"created": 0, "updated": 0, "errors": []}
    active = [i for i in integrations if i.get("enabled", True)]
    by_id = {str(i["id"]): i for i in active}
    for integ in active:
        new = [f for f in delta.get("new") or [] if eligible(integ["config"], f) and not f.get("ticket")]
        new.sort(key=lambda f: (PRIORITY_RANK.get(f.get("priority"), 9), -float(f.get("mrs") or 0)))
        try:
            cl = client_for(integ)
            for f in new[:MAX_AUTO_PER_SCAN]:
                stored = store.get_finding(f["id"]) or f
                if not stored.get("ticket"):
                    raise_ticket(store, cl, integ, stored, actor, console_url)
                    out["created"] += 1
            if len(new) > MAX_AUTO_PER_SCAN:
                out["errors"].append(f"{integ['name']}: {len(new) - MAX_AUTO_PER_SCAN} more eligible findings not ticketed (limit "
                                     f"{MAX_AUTO_PER_SCAN} per scan); raise them from the Findings page")
        except ItsmError as e:
            out["errors"].append(f"{integ['name']}: {e}")
    commit = (delta.get("commit") or "")[:12]
    for kind, resolve in (("fixed", True), ("reopened", False)):
        for f in delta.get(kind) or []:
            t = f.get("ticket")
            integ = by_id.get(str((t or {}).get("integration_id")))
            if not t or not integ:
                continue
            text = (f"NERvvE DevSecOps re-scan{' of commit ' + commit if commit else ''} no longer finds this issue: marked fixed."
                    if resolve else f"NERvvE DevSecOps re-scan{' of commit ' + commit if commit else ''} found this issue again (regression): reopened.")
            try:
                resolved = client_for(integ).update(t, text, resolve)
                store.set_ticket(f["id"], {**t, "status": "resolved" if resolved else ("open" if not resolve else t.get("status", "open")),
                                           "updated_at": now().isoformat()}, actor)
                out["updated"] += 1
            except ItsmError as e:
                out["errors"].append(f"{integ['name']}: {e}")
    return out


# ------------------------------------------------------------------ storage
class MemoryIntegrations:
    """Demo mode: in-process (lost on restart); credentials kept in memory only."""

    def __init__(self):
        self._i, self._cred = {}, {}

    def list(self, tenant_id):
        return [copy.deepcopy(i) for i in self._i.values() if i["tenant_id"] == str(tenant_id)]

    def get(self, tenant_id, iid):
        i = self._i.get(str(iid))
        if not i or i["tenant_id"] != str(tenant_id):
            raise ItsmError("integration not found", 404)
        return copy.deepcopy(i)

    def add(self, tenant_id, integ):
        self._i[str(integ["id"])] = {**integ, "tenant_id": str(tenant_id)}
        return integ

    def update(self, tenant_id, iid, **fields):
        self.get(tenant_id, iid)
        self._i[str(iid)].update(fields)

    def delete(self, tenant_id, iid):
        self.get(tenant_id, iid)
        self._i.pop(str(iid))
        self._cred.pop(str(iid), None)


class PgIntegrations:
    COLS = ("id", "name", "kind", "config", "credential_ref", "enabled", "last_error", "created_by", "created_at")

    def __init__(self, db_url):
        self.db_url = db_url

    def _tx(self, tenant_id):
        from .db.session import tenant_tx
        return tenant_tx(self.db_url, tenant_id)

    def _get(self, s, iid):
        from .db.models import TicketIntegration
        try:
            r = s.get(TicketIntegration, uuid.UUID(str(iid)))
        except ValueError:
            r = None
        if not r:
            raise ItsmError("integration not found", 404)
        return r

    def list(self, tenant_id):
        from sqlalchemy import select
        from .db.models import TicketIntegration
        with self._tx(tenant_id) as s:
            return [{c: getattr(r, c) for c in self.COLS} for r in s.scalars(select(TicketIntegration).order_by(TicketIntegration.created_at))]

    def get(self, tenant_id, iid):
        with self._tx(tenant_id) as s:
            r = self._get(s, iid)
            return {c: getattr(r, c) for c in self.COLS}

    def add(self, tenant_id, integ):
        from .db.models import TicketIntegration
        with self._tx(tenant_id) as s:
            s.add(TicketIntegration(tenant_id=uuid.UUID(str(tenant_id)), **integ))
        return integ

    def update(self, tenant_id, iid, **fields):
        with self._tx(tenant_id) as s:
            r = self._get(s, iid)
            for k, v in fields.items():
                setattr(r, k, v)

    def delete(self, tenant_id, iid):
        with self._tx(tenant_id) as s:
            s.delete(self._get(s, iid))


def public(i: dict) -> dict:
    out = {k: (v.isoformat() if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v)
           for k, v in i.items() if k not in ("credential_ref", "tenant_id")}
    out["has_credential"] = bool(i.get("credential_ref"))
    return out


def credential_ref(tenant_id, iid) -> str:
    return f"vault://secret/myelin/tenants/{tenant_id}/itsm/{iid}#token"
