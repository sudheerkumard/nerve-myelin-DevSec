# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Ticketing integrations against faithful fakes of the Jira, ServiceNow, Azure Boards and webhook APIs."""
import base64
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient  # noqa: E402

from app import itsm, main, scm  # noqa: E402
from tests.test_repo_sources import _archive  # noqa: E402

H = {"X-API-Key": "nm_demo_9f2c41e7b8"}


class Fake:
    """Records requests and answers like the real services."""

    def __init__(self):
        self.calls, self.n, self.fail_priority = [], 100, False

    def __call__(self, req: httpx.Request):
        body = json.loads(req.content) if req.content else None
        self.calls.append((req.method, str(req.url), dict(req.headers), body))
        u, host = req.url, req.url.host
        if host == "acme.atlassian.net":
            if u.path == "/rest/api/2/myself":
                return httpx.Response(200, json={"displayName": "NERvvE Bot"})
            if u.path.startswith("/rest/api/2/project/"):
                return httpx.Response(200, json={"key": "SEC"})
            if u.path == "/rest/api/2/issue" and req.method == "POST":
                if self.fail_priority and "priority" in body["fields"]:
                    return httpx.Response(400, json={"errorMessages": [], "errors": {"priority": "Field 'priority' cannot be set."}})
                self.n += 1
                return httpx.Response(201, json={"id": str(self.n), "key": f"SEC-{self.n}"})
            if u.path.endswith("/comment"):
                return httpx.Response(201, json={})
            if u.path.endswith("/transitions"):
                if req.method == "GET":
                    return httpx.Response(200, json={"transitions": [{"id": "21", "name": "In Progress"}, {"id": "31", "name": "Done"}]})
                return httpx.Response(204)
        if host == "acme.service-now.com":
            if req.method == "GET":
                return httpx.Response(200, json={"result": []})
            if req.method == "POST":
                self.n += 1
                return httpx.Response(201, json={"result": {"sys_id": f"sys{self.n}", "number": f"INC00{self.n}"}})
            return httpx.Response(200, json={"result": {}})
        if host == "dev.azure.com":
            if "/_apis/projects/" in u.path:
                return httpx.Response(200, json={"name": "Payments"})
            if "/_apis/wit/workitems/$" in u.path:
                self.n += 1
                return httpx.Response(200, json={"id": self.n, "_links": {"html": {"href": f"https://dev.azure.com/contoso/Payments/_workitems/edit/{self.n}"}}})
            return httpx.Response(200, json={})
        if host == "hooks.example.com":
            return httpx.Response(200, text="1")
        return httpx.Response(404)


@pytest.fixture()
def fake(monkeypatch):
    f = Fake()
    monkeypatch.setattr(main, "ITSM_TRANSPORT", httpx.MockTransport(f))
    monkeypatch.setenv("MYELIN_ITSM_ALLOW_PRIVATE", "1")
    yield f
    main.TICKETING._i.clear(); main.TICKETING._cred.clear()


@pytest.fixture()
def repo(monkeypatch):
    state = {"a": _archive(top="acme-ledger-1111111")}
    monkeypatch.setattr(scm, "_http", lambda url, headers, limit=0, want_json=False: state["a"])
    return state


def _clean_archive():
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "README.md"), "w").write("clean\n")
    return _archive(top="acme-ledger-2222222", src=d)


def test_jira_auto_tickets_routing_no_duplicates_and_resolution(fake, repo):
    c = TestClient(main.app)
    r = c.post("/api/v1/ticketing/integrations", headers=H, json={
        "kind": "jira", "name": "Jira SEC", "token": "atl-token",
        "config": {"base_url": "https://acme.atlassian.net", "email": "bot@acme.com", "project_key": "SEC", "resolve_transition": "Done"},
        "routing": [{"match": {"engine": "secrets"}, "assign": {"assignee": "acct-secops"}},
                    {"match": {"repo": "ledger*"}, "assign": {"assignee": "acct-payments-devops", "component": "ledger"}}],
        "auto": {"enabled": True, "min_priority": "P2"}})
    assert r.status_code == 201, r.text
    iid = r.json()["id"]
    assert "atl-token" not in r.text and r.json()["has_credential"]
    assert c.post(f"/api/v1/ticketing/integrations/{iid}/test", headers=H).json() == {"ok": True, "message": "connected as NERvvE Bot; project SEC found"}
    s = c.post("/api/v1/repos/sources?wait=true", headers=H, json={"url": "https://github.com/acme/ledger"}).json()
    creates = [x for x in fake.calls if x[0] == "POST" and x[1].endswith("/rest/api/2/issue")]
    assert creates, "auto mode should raise tickets"
    auth = creates[0][2]["authorization"]
    assert auth == "Basic " + base64.b64encode(b"bot@acme.com:atl-token").decode()
    fields = [x[3]["fields"] for x in creates]
    assert all(f["project"] == {"key": "SEC"} and "nerve-myelin" in f["labels"] for f in fields)
    assert all(f["priority"]["name"] in ("Highest", "High", "Medium") for f in fields)
    sec = [f for f in fields if f.get("assignee") == {"accountId": "acct-secops"}]      # first rule: secrets engine → SecOps
    assert sec and all(any(w in f["summary"].lower() for w in ("secret", "key", "token", "password", "credential")) for f in sec)
    other = [f for f in fields if f not in sec]
    assert other and all(f["assignee"] == {"accountId": "acct-payments-devops"} and f["components"] == [{"name": "ledger"}] for f in other)
    assert any("CVE-" in f["summary"] for f in fields) and all("[P" in f["summary"] for f in fields)
    ticketed = [f for f in main.DEMO.db["findings"] if f.get("repo") == "ledger" and f.get("ticket")]
    assert len(ticketed) == len(creates) and all(f["ticket"]["url"].startswith("https://acme.atlassian.net/browse/SEC-") for f in ticketed)
    # re-scan of the same code: no duplicate tickets
    n = len(creates)
    c.post(f"/api/v1/repos/sources/{s['id']}/scan?wait=true", headers=H)
    assert len([x for x in fake.calls if x[0] == "POST" and x[1].endswith("/rest/api/2/issue")]) == n
    # the fix lands: tickets get a comment and move to Done
    repo["a"] = _clean_archive()
    c.post(f"/api/v1/repos/sources/{s['id']}/scan?wait=true", headers=H)
    comments = [x for x in fake.calls if x[1].endswith("/comment")]
    transitions = [x for x in fake.calls if x[0] == "POST" and x[1].endswith("/transitions")]
    assert len(comments) == n and len(transitions) == n and all(t[3] == {"transition": {"id": "31"}} for t in transitions)
    assert "2222222" in comments[0][3]["body"]
    assert all(f["ticket"]["status"] == "resolved" for f in main.DEMO.db["findings"] if f.get("repo") == "ledger" and f.get("ticket"))
    c.delete(f"/api/v1/repos/sources/{s['id']}", headers=H)


def test_jira_retries_without_fields_the_project_screen_hides(fake):
    fake.fail_priority = True
    integ = itsm.new_integration({"kind": "jira", "config": {"base_url": "https://jira.acme.example", "deployment": "datacenter",
                                                             "project_key": "OPS"}}, "me")
    integ["config"]["base_url"] = "https://acme.atlassian.net"
    cl = itsm.Client(integ, "dc-pat", transport=httpx.MockTransport(fake))
    t = cl.create({"id": "NM-1", "repo": "r", "engine": "sast", "severity": "high", "priority": "P1", "title": "SQL injection"},
                  {"assignee": "jdoe"}, "")
    posts = [x for x in fake.calls if x[1].endswith("/rest/api/2/issue")]
    assert t["key"].startswith("SEC-") and len(posts) == 2 and "priority" not in posts[1][3]["fields"]
    assert posts[0][2]["authorization"] == "Bearer dc-pat" and posts[1][3]["fields"]["assignee"] == {"name": "jdoe"}


def test_servicenow_manual_ticket_and_resolution(fake, repo):
    c = TestClient(main.app)
    iid = c.post("/api/v1/ticketing/integrations", headers=H, json={
        "kind": "servicenow", "token": "svc_myelin:Pa55word", "config": {"base_url": "https://acme.service-now.com", "assignment_group": "DevOps - Payments"}}).json()["id"]
    s = c.post("/api/v1/repos/sources?wait=true", headers=H, json={"url": "https://github.com/acme/ledger-sn"}).json()
    f = next(x for x in main.DEMO.db["findings"] if x.get("repo") == "ledger-sn" and x["engine"] == "sca" and x["status"] == "open")
    r = c.post("/api/v1/ticketing/tickets", headers=H, json={"finding_ids": [f["id"], f["id"]]}).json()
    assert r["results"][0]["ticket"]["key"].startswith("INC00") and r["results"][1]["ticket"] == r["results"][0]["ticket"]   # no duplicate
    post = next(x for x in fake.calls if x[0] == "POST" and "/api/now/table/incident" in x[1])
    assert post[3]["assignment_group"] == "DevOps - Payments" and post[3]["urgency"] in ("1", "2") and f["cve"] in post[3]["short_description"]
    assert post[3]["correlation_id"] == f"nerve-myelin:{f['fingerprint']}"
    assert post[2]["authorization"] == "Basic " + base64.b64encode(b"svc_myelin:Pa55word").decode()
    repo["a"] = _clean_archive()
    c.post(f"/api/v1/repos/sources/{s['id']}/scan?wait=true", headers=H)
    patch = next(x for x in fake.calls if x[0] == "PATCH")
    assert patch[1].endswith("/api/now/table/incident/" + r["results"][0]["ticket"]["sys_id"])
    assert patch[3]["state"] == "6" and patch[3]["close_code"] == "Solved (Permanently)"
    c.delete(f"/api/v1/repos/sources/{s['id']}", headers=H)
    c.delete(f"/api/v1/ticketing/integrations/{iid}", headers=H)


def test_azure_boards_work_item(fake):
    integ = itsm.new_integration({"kind": "azure_boards", "config": {"organization": "contoso", "project": "Payments", "area_path": "Payments\\DevOps"}}, "me")
    cl = itsm.Client(integ, "ado-pat", transport=httpx.MockTransport(fake))
    t = cl.create({"id": "NM-2", "repo": "ledger", "engine": "iac", "severity": "critical", "priority": "P0",
                   "title": "Compose service 'api' runs privileged", "remediation": "Remove privileged <now>"}, {"assignee": "dev@contoso.com"}, "")
    req = next(x for x in fake.calls if "wit/workitems" in x[1])
    assert "/contoso/Payments/_apis/wit/workitems/$Bug" in req[1] or "/contoso/Payments/_apis/wit/workitems/%24Bug" in req[1]
    assert req[2]["content-type"] == "application/json-patch+json" and req[2]["authorization"] == "Basic " + base64.b64encode(b":ado-pat").decode()
    paths = {o["path"]: o["value"] for o in req[3]}
    assert paths["/fields/Microsoft.VSTS.Common.Severity"] == "1 - Critical" and paths["/fields/System.AreaPath"] == "Payments\\DevOps"
    assert paths["/fields/System.AssignedTo"] == "dev@contoso.com" and "&lt;now&gt;" in paths["/fields/Microsoft.VSTS.TCM.ReproSteps"]
    assert t["url"].endswith(f"/_workitems/edit/{t['key']}")
    assert cl.update(t, "fixed", resolve=True) is True
    assert fake.calls[-1][3] == [{"op": "add", "path": "/fields/System.State", "value": "Done"}]


def test_webhook_and_validation(fake):
    integ = itsm.new_integration({"kind": "webhook", "config": {"url": "https://hooks.example.com/teams/abc"}}, "me")
    itsm.Client(integ, None, transport=httpx.MockTransport(fake)).create({"id": "NM-3", "title": "x", "priority": "P1", "severity": "high"}, {}, "")
    assert fake.calls[-1][3]["finding"]["id"] == "NM-3" and "**[P1][HIGH]" in fake.calls[-1][3]["text"]
    for bad in ({"kind": "jira", "config": {"base_url": "http://acme.atlassian.net", "project_key": "SEC", "email": "a@b"}},
                {"kind": "jira", "config": {"base_url": "https://acme.atlassian.net", "project_key": "SEC"}},
                {"kind": "servicenow", "config": {"base_url": "https://x.service-now.com", "table": "incident; drop"}},
                {"kind": "ftp", "config": {}}):
        with pytest.raises(itsm.ItsmError):
            itsm.new_integration(bad, "me")


def test_internal_ticketing_hosts_refused_by_default(monkeypatch):
    monkeypatch.delenv("MYELIN_ITSM_ALLOW_PRIVATE", raising=False)
    integ = itsm.new_integration({"kind": "webhook", "config": {"url": "https://127.0.0.1/hook"}}, "me")
    with pytest.raises(itsm.ItsmError, match="internal address"):
        itsm.Client(integ, None).check()


def test_routing_rules_first_match_wins():
    cfg = {"routing": itsm._routing([{"match": {"repo": "pay*", "min_priority": "P1"}, "assign": {"assignee": "a"}},
                                     {"match": {"repo": "pay*"}, "assign": {"assignee": "b"}}]), "assignee": "default"}
    assert itsm.route(cfg, {"repo": "payments", "priority": "P0"}) == {"assignee": "a"}
    assert itsm.route(cfg, {"repo": "payments", "priority": "P3"}) == {"assignee": "b"}
    assert itsm.route(cfg, {"repo": "ledger", "priority": "P0"}) == {"assignee": "default"}
