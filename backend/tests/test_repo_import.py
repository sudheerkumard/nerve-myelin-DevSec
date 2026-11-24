# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""One-click import: repository addresses from shared files and organisation listings; bounded scan queue."""
import base64
import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient  # noqa: E402

from app import main, repo_import as RI, scm  # noqa: E402
from tests.test_repo_sources import _archive  # noqa: E402

H = {"X-API-Key": "nm_demo_9f2c41e7b8"}


def _xlsx():
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Application", "Repository URL", "Branch", "Tier"])
    ws.append(["Payments API", "https://github.com/acme/payments-api", "release/2.1", "critical"])
    ws.append(["Ledger", "https://dev.azure.com/contoso/Finance/_git/ledger", "", "high"])
    ws.append(["Billing", "git@gitlab.com:acme/platform/billing.git", "main", ""])
    ws.append(["Docs site", "https://www.acme.com/docs", "", ""])                         # not a repository
    ws["E2"] = "source"
    ws["E2"].hyperlink = "https://bitbucket.org/acme/mobile-app"                          # link behind a label
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _office(kind, text_xml, rels=""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if kind == "docx":
            z.writestr("word/document.xml", f'<w:document xmlns:w="w"><w:body>{text_xml}</w:body></w:document>')
            z.writestr("word/_rels/document.xml.rels", rels)
        else:
            z.writestr("ppt/slides/slide1.xml", f'<p:sld xmlns:p="p" xmlns:a="a">{text_xml}</p:sld>')
    return buf.getvalue()


def test_spreadsheet_with_header_hyperlinks_and_ssh():
    res = RI.extract_file("inventory.xlsx", _xlsx())
    got = {r["url"]: r for r in res["repositories"]}
    assert got["https://github.com/acme/payments-api"]["branch"] == "release/2.1"
    assert got["https://github.com/acme/payments-api"]["criticality"] == "critical"
    assert got["https://github.com/acme/payments-api"]["name"] == "Payments API"
    assert got["https://dev.azure.com/contoso/Finance/_git/ledger"]["provider"] == "azure"
    assert got["https://gitlab.com/acme/platform/billing"]["provider"] == "gitlab"            # SSH address converted
    assert "https://bitbucket.org/acme/mobile-app" in got                                     # hyperlink target
    assert not any("acme.com/docs" in u for u in got)


def test_word_powerpoint_text_csv_and_json():
    docx = _office("docx", "<w:p><w:r><w:t>Scope: https://github.com/acme/web/tree/main/src and</w:t></w:r></w:p>"
                           "<w:p><w:r><w:t>https://git-codecommit.ap-south-1.amazonaws.com/v1/repos/orders</w:t></w:r></w:p>",
                   '<Relationships><Relationship Id="r1" Target="https://gitlab.com/acme/infra/terraform" TargetMode="External"/></Relationships>')
    urls = {r["url"] for r in RI.extract_file("scope.docx", docx)["repositories"]}
    assert urls == {"https://github.com/acme/web", "https://git-codecommit.ap-south-1.amazonaws.com/v1/repos/orders",
                    "https://gitlab.com/acme/infra/terraform"}
    pptx = _office("pptx", "<a:t>Repos: git@ssh.dev.azure.com:v3/contoso/Payments/ledger-api</a:t>")
    assert RI.extract_file("deck.pptx", pptx)["repositories"][0]["url"] == "https://dev.azure.com/contoso/Payments/_git/ledger-api"
    csv_ = b"name,repo,branch\nCore,https://github.com/acme/core,develop\nCore again,https://github.com/acme/core,\n"
    r = RI.extract_file("list.csv", csv_)["repositories"]
    assert r == [{"url": "https://github.com/acme/core", "provider": "github", "name": "Core", "branch": "develop", "criticality": None}]
    txt = ("Hi team, please scan https://github.com/acme/api.git, https://source.developers.google.com/p/acme-prod/r/billing "
           "and https://git.acme.internal/scm/pay/gateway.git — see https://www.example.com/runbook for details.").encode()
    urls = [x["url"] for x in RI.extract_file("email.txt", txt)["repositories"]]
    assert urls == ["https://github.com/acme/api", "https://source.developers.google.com/p/acme-prod/r/billing",
                    "https://git.acme.internal/scm/pay/gateway.git"]
    j = b'{"apps":[{"repo":"https:\\/\\/bitbucket.org\\/acme\\/pos"}]}'
    assert RI.extract_file("apps.json", j)["repositories"][0]["url"] == "https://bitbucket.org/acme/pos"
    for bad in ("old.xls", "scope.pdf"):
        with pytest.raises(RI.ImportError_):
            RI.extract_file(bad, b"x")


def test_discover_all_providers_with_paging(monkeypatch):
    calls = []

    def fake(url, headers, limit=0, want_json=False):
        calls.append((url, headers))
        if "api.github.com/orgs/acme/repos" in url:
            import re as _re
            page = int(_re.search(r"[?&]page=(\d+)", url).group(1))
            n = 100 if page == 1 else 3
            return [{"html_url": f"https://github.com/acme/r{page}-{i}", "name": f"r{page}-{i}", "archived": i == 0,
                     "default_branch": "main", "private": True} for i in range(n)]
        if "gitlab.com/api/v4/groups/acme%2Fplatform/projects" in url:
            return [{"web_url": "https://gitlab.com/acme/platform/api", "path": "api", "visibility": "private", "default_branch": "main"}]
        if "dev.azure.com/contoso/_apis/git/repositories" in url:
            return {"value": [{"name": "ledger", "webUrl": "https://dev.azure.com/contoso/Finance/_git/ledger", "defaultBranch": "refs/heads/main",
                               "project": {"name": "Finance"}}, {"name": "old", "webUrl": "https://dev.azure.com/contoso/X/_git/old", "isDisabled": True}]}
        if "api.bitbucket.org/2.0/repositories/acme" in url:
            if "page=2" in url:
                return {"values": [{"slug": "pos", "links": {"html": {"href": "https://bitbucket.org/acme/pos"}}}]}
            return {"values": [{"slug": "web", "links": {"html": {"href": "https://bitbucket.org/acme/web"}}}],
                    "next": "https://api.bitbucket.org/2.0/repositories/acme?pagelen=100&page=2"}
        raise scm.ScmError("the provider answered HTTP 404", 404)
    monkeypatch.setattr(scm, "_http", fake)
    gh = RI.discover("github", "https://github.com/acme", "ghp_x")
    assert gh["count"] == 101 and calls[0][1]["Authorization"] == "Bearer ghp_x"             # 2 archived skipped
    assert RI.discover("gitlab", "https://gitlab.com/acme/platform", "glpat")["repositories"][0]["url"] == "https://gitlab.com/acme/platform/api"
    az = RI.discover("azure", "https://dev.azure.com/contoso", "pat")["repositories"]
    assert [r["name"] for r in az] == ["ledger"] and az[0]["default_branch"] == "main"
    assert [r["name"] for r in RI.discover("bitbucket", "acme", "tok")["repositories"]] == ["web", "pos"]
    with pytest.raises(RI.ImportError_):
        RI.discover("codecommit", "x", None)


def test_import_flow_preview_select_scan_and_skip_duplicates(monkeypatch):
    monkeypatch.setattr(scm, "_http", lambda url, headers, limit=0, want_json=False:
                        {"mainbranch": {"name": "main"}} if want_json else _archive(top="acme-x-3333333"))
    c = TestClient(main.app)
    prev = c.post("/api/v1/repos/import/file", headers=H, json={"filename": "inventory.xlsx", "content_base64": base64.b64encode(_xlsx()).decode()}).json()
    items = [{"url": r["url"], "provider": r["provider"], "name": r["name"], "branch": r["branch"], "criticality": r["criticality"]}
             for r in prev["repositories"] if r["provider"] in ("github", "bitbucket")]
    r = c.post("/api/v1/repos/import", headers=H, json={"items": items, "tokens": {"github": "ghp_import", "bitbucket": "bb"}}).json()
    assert len(r["added"]) == 2 and r["queued"] == 2 and not r["skipped"]
    again = c.post("/api/v1/repos/import/file", headers=H, json={"filename": "inventory.xlsx", "content_base64": base64.b64encode(_xlsx()).decode()}).json()
    assert {x["url"]: x["already_added"] for x in again["repositories"]}["https://github.com/acme/payments-api"] is True
    r2 = c.post("/api/v1/repos/import", headers=H, json={"items": items[:1]}).json()
    assert r2["added"] == [] and r2["skipped"][0]["reason"] == "already added"
    import time
    for _ in range(100):
        st = {s["url"]: s["status"] for s in c.get("/api/v1/repos/sources", headers=H).json()}
        if all(st.get(i["url"]) == "done" for i in items):
            break
        time.sleep(0.2)
    assert all(st.get(i["url"]) == "done" for i in items), st
    src = next(s for s in c.get("/api/v1/repos/sources", headers=H).json() if s["url"] == "https://github.com/acme/payments-api")
    assert src["branch"] == "release/2.1" and src["config"]["criticality"] == "critical" and src["private"]
    for s in c.get("/api/v1/repos/sources", headers=H).json():
        c.delete(f"/api/v1/repos/sources/{s['id']}", headers=H)


def test_deployment_gate(monkeypatch):
    c = TestClient(main.app)
    up = {"repo": "gate-demo", "branch": "main", "commit": "abcdef1234567890", "engines": ["secrets"],
          "findings": [{"engine": "secrets", "rule_id": "NM-SEC-001", "title": "AWS key", "severity": "critical", "file": "a.py", "line": 1}]}
    assert c.post("/api/scans", headers=H, json=up).status_code == 200
    g = c.get("/api/v1/gate", headers=H, params={"repo": "gate-demo", "commit": "abcdef1234567890", "environment": "production"}).json()
    assert g["decision"] == "block" and g["commit"] == "abcdef1"
    assert c.get("/api/v1/gate", headers=H, params={"repo": "gate-demo", "commit": "0000000"}).status_code == 404
    assert c.get("/api/v1/gate", headers=H, params={"repo": "never-scanned"}).status_code == 404
