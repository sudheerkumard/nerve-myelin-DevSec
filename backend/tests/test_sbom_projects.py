# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""SBOM projects, repository export and purge, remediation plan, licence reasons, inline advisory jobs."""
import base64
import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

c = TestClient(main.app)
H = {"X-API-Key": "nm_demo_9f2c41e7b8"}

CDX = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
    {"type": "library", "bom-ref": "a", "name": "lodash", "version": "4.17.11", "purl": "pkg:npm/lodash@4.17.11",
     "licenses": [{"license": {"id": "MIT"}}]},
    {"type": "library", "bom-ref": "b", "name": "gplthing", "version": "1.0", "purl": "pkg:npm/gplthing@1.0",
     "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
    {"type": "library", "bom-ref": "c", "name": "mystery", "version": "2.0", "purl": "pkg:npm/mystery@2.0"}]}
SPDX = {"spdxVersion": "SPDX-2.3", "packages": [
    {"SPDXID": "SPDXRef-1", "name": "lodash", "versionInfo": "4.17.11", "licenseConcluded": "NOASSERTION",
     "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.11"}]},
    {"SPDXID": "SPDXRef-2", "name": "requests", "versionInfo": "2.31.0", "licenseConcluded": "Apache-2.0",
     "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}]}]}


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("web/bom.json", json.dumps(CDX))
        z.writestr("api/sbom.spdx.json", json.dumps(SPDX))
        z.writestr("notes.txt", "ignored")
    return base64.b64encode(buf.getvalue()).decode()


def test_sbom_zip_becomes_one_project_without_touching_findings():
    before = c.get("/api/findings", params={"limit": 1}).json()["total"]
    r = c.post("/api/v1/sbom-projects", headers=H, json={"name": "Checkout suite", "files": [
        {"filename": "suite.zip", "content_b64": _zip()}]})
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["components"] == 4 and len(d["files"]) == 2 and all("error" not in f for f in d["files"])
    lic = {x["package"]: x for x in d["licences"]}
    assert lic["lodash"]["decision"] == "allow" and set(lic["lodash"]["sources"]) == {"suite.zip/web/bom.json", "suite.zip/api/sbom.spdx.json"}
    assert lic["gplthing"]["decision"] == "review" and "strong copyleft" in lic["gplthing"]["reason"]
    assert "declares no licence" in lic["mystery"]["reason"] and lic["mystery"]["action"]
    assert len({x["reason"] for x in d["licences"]}) == len(d["licences"])          # every reason is specific
    assert c.get("/api/findings", params={"limit": 1}).json()["total"] == before     # the dashboard is not affected
    assert "Checkout suite" in [p["name"] for p in c.get("/api/v1/sbom-projects", headers=H).json()["items"]]
    html = c.get("/api/v1/sbom-projects/Checkout suite/report", headers=H)
    assert html.status_code == 200 and "Licence findings" in html.text and "gplthing" in html.text
    csv = c.get("/api/v1/sbom-projects/Checkout suite/report", params={"format": "csv"}, headers=H).text
    assert csv.splitlines()[0].startswith("type,package") and "gplthing" in csv
    cdx = c.get("/api/v1/sbom-projects/Checkout suite/report", params={"format": "cyclonedx"}, headers=H).json()
    assert cdx["bomFormat"] == "CycloneDX" and len(cdx["components"]) == 4
    rep = c.get("/api/v1/licenses/report", params={"repo": "SBOM: Checkout suite"}, headers=H).json()
    assert rep["components_evaluated"] == 4 and "SBOM: Checkout suite" in rep["all_repositories"]
    assert c.delete("/api/v1/sbom-projects/Checkout suite", headers=H).status_code == 204
    assert c.get("/api/v1/sbom-projects/Checkout suite", headers=H).status_code == 404


def test_sbom_upload_rejects_non_sbom_files():
    bad = base64.b64encode(b'{"hello": "world"}').decode()
    r = c.post("/api/v1/sbom-projects", headers=H, json={"name": "Bad", "files": [{"filename": "x.json", "content_b64": bad}]})
    assert r.status_code == 422
    doc = base64.b64encode(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><bom>&e;</bom>').decode()
    r = c.post("/api/v1/sbom-projects", headers=H, json={"name": "Xxe", "files": [{"filename": "b.xml", "content_b64": doc}]})
    assert r.status_code == 422


def test_remediation_plan_groups_findings_with_steps():
    r = c.get("/api/v1/findings/remediation-plan", headers=H)
    assert r.status_code == 200 and "Remediation plan" in r.text and "<ol>" in r.text and "Verify:" in r.text


def test_repository_export_and_purge():
    r = c.get("/api/v1/repos/sources/export", headers=H)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert "repositories.csv" in z.namelist() and z.read("repositories.csv").decode().startswith("repository,url")
    # purge removes the repository's findings and SBOM
    store = main.DEMO
    store.db.setdefault("findings", []).append({"id": "f-purge-1", "fingerprint": "fp-purge-1", "repo": "purge-me",
                                                 "engine": "sast", "status": "open", "priority": "P2", "mrs": 10,
                                                 "severity": "low", "title": "x"})
    store.db.setdefault("sboms", {})["purge-me"] = {"components": []}
    assert store.purge_repo("purge-me")["findings"] == 1
    assert not any(f.get("repo") == "purge-me" for f in store.db["findings"]) and "purge-me" not in store.db["sboms"]


def test_advisory_jobs_drain_inline(monkeypatch):
    ran = []
    monkeypatch.setattr(main, "_run_advisory_feed_sync", lambda jid, source, tenant, purls, cves, actor, scope=None: ran.append(source))

    class S:
        jobs = [{"id": "j1", "kind": "advisory_sync", "source": "EPSS", "counters": {"targets": ["CVE-2021-44228"]}},
                {"id": "j2", "kind": "other", "source": "EPSS"}]
        failed = []

        def claim_import_job(self, *a):
            return self.jobs.pop(0) if self.jobs else None

        def update_import_job(self, jid, status, **kw):
            self.failed.append((jid, status))
    s = S()
    assert main.drain_advisory_jobs(s, None, "w1") == 1 and ran == ["EPSS"] and s.failed == [("j2", "failed")]
