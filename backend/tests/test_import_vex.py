# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Bring-your-own-scanner import, VEX export/import, new-findings-only and coverage gates, accepted-risk expiry."""
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from myelin_engine import importers, vex  # noqa: E402

H = {"X-API-Key": "nm_demo_9f2c41e7b8"}


def setup_module(_):
    # other test modules bind project-level policies; project layers require every repository to be mapped
    for repo in ("byo-svc", "vex-svc", "gate-new", "accept-svc", "csv-svc"):
        main.DEMO.set_repo_project(repo, "import-vex-tests", "test-setup")
B64 = lambda d: base64.b64encode((json.dumps(d) if not isinstance(d, (bytes, str)) else d).encode() if not isinstance(d, bytes) else d).decode()  # noqa: E731

SARIF = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [
    {"id": "py/sql-injection", "shortDescription": {"text": "SQL injection"}, "properties": {"security-severity": "9.1", "tags": ["security", "external/cwe/cwe-089"]}}]}},
    "results": [{"ruleId": "py/sql-injection", "level": "error", "message": {"text": "Query built from user input"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 42}}}]}]}]}
CDX = {"bomFormat": "CycloneDX", "specVersion": "1.5",
       "components": [{"bom-ref": "pkg:pypi/pyyaml@5.3", "name": "pyyaml", "version": "5.3", "purl": "pkg:pypi/pyyaml@5.3"},
                      {"bom-ref": "pkg:npm/lodash@4.17.15", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}],
       "vulnerabilities": [
           {"id": "CVE-2020-14343", "ratings": [{"score": 9.8, "severity": "critical"}], "description": "full_load RCE",
            "recommendation": "Upgrade to 5.4", "cwes": [20], "affects": [{"ref": "pkg:pypi/pyyaml@5.3"}]},
           {"id": "CVE-2021-23337", "ratings": [{"score": 7.2, "severity": "high"}], "description": "template injection",
            "affects": [{"ref": "pkg:npm/lodash@4.17.15"}]}]}
TRIVY = {"SchemaVersion": 2, "ArtifactName": ".", "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2023-0286", "PkgName": "cryptography", "InstalledVersion": "38.0.0", "FixedVersion": "39.0.1", "Severity": "HIGH"}]}]}
GITLEAKS = [{"RuleID": "aws-access-token", "Description": "AWS key", "File": "deploy.sh", "StartLine": 3, "Secret": "AKIAEXAMPLE", "Commit": "abc"}]
ZAP = {"@programName": "ZAP", "@version": "2.15.0", "site": [{"@name": "https://api.example.com", "alerts": [
    {"pluginid": "10038", "name": "CSP header not set", "riskcode": "2", "cweid": "693", "solution": "<p>Set it</p>",
     "instances": [{"uri": "https://api.example.com/", "method": "GET"}]}]}]}


def test_format_detection_and_parsing():
    cases = [(SARIF, "sarif"), (CDX, "cyclonedx"), (TRIVY, "trivy"), (GITLEAKS, "gitleaks"), (ZAP, "zap")]
    for doc, fmt in cases:
        got, fs = importers.parse(json.dumps(doc), "svc")
        assert got == fmt and fs, fmt
    _, fs = importers.parse(json.dumps(SARIF), "svc")
    assert fs[0]["severity"] == "critical" and fs[0]["cwe"] == "CWE-89" and fs[0]["file"] == "app/db.py" and fs[0]["line"] == 42
    _, fs = importers.parse(json.dumps(CDX), "svc")
    assert {f["cve"] for f in fs} == {"CVE-2020-14343", "CVE-2021-23337"} and fs[0]["fixed_version"] == "5.4"
    for bad in ("not json", "{}", "[1,2]"):
        try:
            importers.parse(bad, "svc")
            raise AssertionError("should fail")
        except importers.ImportError_:
            pass


def test_import_endpoint_scores_gates_and_never_autocloses():
    c = TestClient(main.app)
    own = {"repo": "byo-svc", "branch": "main", "commit": "1111111aaaa", "engines": ["secrets"],
           "findings": [{"engine": "secrets", "rule_id": "NM-SEC-001", "title": "key", "severity": "high", "file": "x.py", "line": 1}]}
    assert c.post("/api/scans", headers=H, json=own).status_code == 200
    r = c.post("/api/v1/scans/import", headers=H, json={"repo": "byo-svc", "commit": "2222222bbbb", "filename": "codeql.sarif",
                                                         "content_base64": B64(SARIF)})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["format"] == "sarif" and d["received"] == 1 and d["new"] == 1 and d["decision"]["decision"] in ("block", "warn", "pass")
    items = c.get("/api/findings", headers=H, params={"repo": "byo-svc"}).json()["items"]
    assert {f["engine"] for f in items} == {"secrets", "sast"}                  # the import did not close the secrets finding
    imported = next(f for f in items if f["engine"] == "sast")
    assert imported["source_tool"] == "CodeQL" and imported["mrs"] > 0 and imported["priority"] in ("P0", "P1", "P2", "P3")
    bad = c.post("/api/v1/scans/import", headers=H, json={"repo": "byo-svc", "content_base64": B64("hello")})
    assert bad.status_code == 400 and "not valid JSON" in bad.json()["detail"]


def test_vex_export_and_import_round_trip():
    c = TestClient(main.app)
    assert c.post("/api/v1/scans/import", headers=H, json={"repo": "vex-svc", "commit": "3333333", "content_base64": B64(CDX)}).status_code == 200
    items = c.get("/api/findings", headers=H, params={"repo": "vex-svc"}).json()["items"]
    yaml_f = next(f for f in items if f.get("cve") == "CVE-2020-14343")
    assert c.post(f"/api/findings/{yaml_f['id']}/status", headers=H,
                  json={"status": "suppressed", "reason": "vulnerable_code_not_in_execute_path: full_load is never called"}).status_code == 200
    ov = c.get("/api/v1/vex", headers=H, params={"repo": "vex-svc"}).json()
    assert ov["@context"].startswith("https://openvex.dev/ns/v0.2")
    st = {s["vulnerability"]["name"]: s for s in ov["statements"]}
    assert st["CVE-2020-14343"]["status"] == "not_affected" and st["CVE-2020-14343"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert st["CVE-2021-23337"]["status"] in ("under_investigation", "affected")
    assert st["CVE-2020-14343"]["products"][0]["@id"] == "pkg:pypi/pyyaml@5.3"
    # our own export round-trips through the conservative importer
    assert {(x["vulnerability"], x["purl"], x["state"]) for x in vex.normalize_document(ov)} >= {("CVE-2020-14343", "pkg:pypi/pyyaml@5.3", "not_affected")}
    cdx = c.get("/api/v1/vex", headers=H, params={"repo": "vex-svc", "format": "cyclonedx"}).json()
    assert cdx["bomFormat"] == "CycloneDX" and any(v["analysis"]["state"] == "not_affected" for v in cdx["vulnerabilities"])
    # a supplier's OpenVEX says lodash is not affected in this product
    supplier = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": [
        {"vulnerability": {"name": "CVE-2021-23337"}, "products": [{"@id": "pkg:npm/lodash@4.17.15"}], "status": "not_affected",
         "justification": "vulnerable_code_not_present"}]}
    dry = c.post("/api/v1/vex/import", headers=H, json={"content_base64": B64(supplier), "repo": "vex-svc", "dry_run": True}).json()
    assert dry["matched"] == 1 and dry["applied"] == []
    real = c.post("/api/v1/vex/import", headers=H, json={"content_base64": B64(supplier), "repo": "vex-svc", "dry_run": False}).json()
    assert real["matched"] == 1
    lod = next(f for f in c.get("/api/findings", headers=H, params={"repo": "vex-svc", "status": "suppressed"}).json()["items"]
               if f.get("cve") == "CVE-2021-23337")
    assert "VEX not_affected" in lod["triage"]["reason"]
    # a statement for a different version does not apply
    other = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": [
        {"vulnerability": {"name": "CVE-2020-14343"}, "products": [{"@id": "pkg:pypi/pyyaml@6.0"}], "status": "fixed"}]}
    assert c.post("/api/v1/vex/import", headers=H, json={"content_base64": B64(other), "repo": "vex-svc", "dry_run": False}).json()["matched"] == 0
    assert c.get("/api/v1/vex", headers=H, params={"repo": "nothing-here"}).status_code == 404


def test_gate_new_findings_only_and_required_engines():
    c = TestClient(main.app)
    old = {"engine": "secrets", "rule_id": "NM-SEC-001", "title": "old key", "severity": "critical", "file": "old.py", "line": 1}
    c.post("/api/scans", headers=H, json={"repo": "gate-new", "commit": "aaaaaaa111", "engines": ["secrets", "sast"], "findings": [old]})
    clean = c.post("/api/scans", headers=H, json={"repo": "gate-new", "commit": "bbbbbbb222", "engines": ["secrets", "sast"], "findings": [old]})
    assert clean.status_code == 200
    full = c.get("/api/v1/gate", headers=H, params={"repo": "gate-new", "commit": "bbbbbbb222"}).json()
    new = c.get("/api/v1/gate", headers=H, params={"repo": "gate-new", "commit": "bbbbbbb222", "scope": "new"}).json()
    # the full gate repeats the scan's own decision (whatever policy is bound); only new findings can block with scope=new
    assert full["decision"] == clean.json()["decision"]["decision"] and new["decision"] == "pass" and new["new_findings"] == 0
    cov = c.get("/api/v1/gate", headers=H, params={"repo": "gate-new", "commit": "bbbbbbb222", "scope": "new", "require": "sast,sca"}).json()
    assert cov["decision"] == "block" and cov["missing_engines"] == ["sca"]


def test_risk_acceptance_needs_and_honours_expiry():
    c = TestClient(main.app)
    c.post("/api/scans", headers=H, json={"repo": "accept-svc", "commit": "ccc", "engines": ["sast"],
                                          "findings": [{"engine": "sast", "rule_id": "X1", "title": "t", "severity": "high", "file": "a", "line": 2}]})
    fid = c.get("/api/findings", headers=H, params={"repo": "accept-svc"}).json()["items"][0]["id"]
    assert c.post(f"/api/findings/{fid}/status", headers=H, json={"status": "risk_accepted", "reason": "compensating"}).status_code == 400
    far = (datetime.now(timezone.utc) + timedelta(days=500)).date().isoformat()
    assert c.post(f"/api/findings/{fid}/status", headers=H, json={"status": "risk_accepted", "reason": "compensating", "expires": far}).status_code == 400
    ok = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
    r = c.post(f"/api/findings/{fid}/status", headers=H, json={"status": "risk_accepted", "reason": "compensating", "expires": ok})
    assert r.status_code == 200 and r.json()["triage"]["expires"] == ok
    store_f = next(x for x in main.DEMO.db["findings"] if x["id"] == fid)
    store_f["triage"]["expires"] = "2020-01-01"                                  # the date passes
    items = c.get("/api/findings", headers=H, params={"repo": "accept-svc"}).json()["items"]
    assert items and items[0]["status"] == "open" and "expired" in items[0]["reopened_reason"]


def test_vex_justification_mapping():
    f = {"engine": "sca", "cve": "CVE-1", "package": "p", "version": "1", "ecosystem": "pypi", "status": "suppressed",
         "triage": {"reason": "WAF mitigates it", "at": "2026-11-20T00:00:00+00:00"}}
    doc = vex.openvex([f], "pkg:generic/x")
    assert doc["statements"][0]["justification"] == "inline_mitigations_already_exist"


def test_findings_csv_export_is_excel_safe():
    c = TestClient(main.app)
    c.post("/api/scans", headers=H, json={"repo": "csv-svc", "commit": "ddd", "engines": ["sast"],
                                          "findings": [{"engine": "sast", "rule_id": "X9", "title": "=HYPERLINK(\"http://evil\")",
                                                        "severity": "high", "file": "a.py", "line": 1}]})
    r = c.get("/api/v1/findings/export", headers=H, params={"repo": "csv-svc"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    body = r.content.decode("utf-8-sig")
    assert body.splitlines()[0].startswith("id,priority,severity") and "'=HYPERLINK" in body
