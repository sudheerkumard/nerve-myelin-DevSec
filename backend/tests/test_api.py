# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
import os, sys
import uuid
import pytest
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fastapi.testclient import TestClient
from app.main import app

c = TestClient(app)
H = {"X-API-Key": "nm_demo_9f2c41e7b8"}

def test_health():
    assert c.get("/api/health").json()["status"] == "ok"

def test_summary_kpis():
    k = c.get("/api/summary").json()["kpis"]
    assert k["open_findings"] > 100 and k["p0"] > 0 and 0 < k["noise_reduction_pct"] < 100

def test_findings_filter_and_detail():
    r = c.get("/api/findings", params={"engine": "secrets"}).json()
    assert r["total"] > 0 and all(f["engine"] == "secrets" for f in r["items"])
    d = c.get(f"/api/findings/{r['items'][0]['id']}").json()
    assert "blast_radius" in d and d["compliance"]

def test_live_scan_blocks():
    r = c.post("/api/scans/live", json={}, headers=H).json()
    assert r["decision"]["decision"] == "block"
    assert {"sca", "secrets", "cicd", "sast", "iac", "aibom"} <= {f["engine"] for f in r["findings"]}

def test_upload_and_gate():
    r = c.post("/api/scans", json={"repo": "x", "findings": [{"engine": "secrets", "rule_id": "NM-SEC-001", "severity": "critical", "title": "AWS key", "file": "a.py", "line": 1}]}, headers=H).json()
    assert r["decision"]["decision"] == "block" and r["new"] == 1

def test_autofix_and_plans():
    f = next(x for x in c.get("/api/findings", params={"engine": "sca", "repo": "payments-web", "limit": 500}).json()["items"]
             if x.get("file") == "requirements.txt" and x.get("fixed_version"))
    r = c.post(f"/api/findings/{f['id']}/autofix", headers=H).json()
    assert r["proposed"] and f"+{f['package']}=={f['fixed_version']}" in r["diff"].lower().replace(" ", "")
    gen = next(x for x in c.get("/api/findings", params={"engine": "sca", "limit": 500}).json()["items"] if x["repo"] != "payments-web")
    g = c.post(f"/api/findings/{gen['id']}/autofix", headers=H).json()
    assert g["proposed"] is False and g["guidance"]          # no source files: guidance, never an invented patch
    q = c.get("/api/plans/quote", params={"plan": "business", "devs": 300}).json()
    from app import plans
    unit = plans.plan("business")["price_annual_per_dev"]
    if unit is None:                                         # editions without a price list quote on request
        assert q["total"] is None and "total_annual" not in q
    else:
        assert q["total_annual"] == round(300 * unit * (1 - plans.volume_discount(300)))

def test_compliance_and_posture():
    assert len(c.get("/api/compliance").json()) >= 10
    assert len(c.get("/api/posture/cicd").json()) == 10


def test_supply_chain_graph_has_grounded_edges_and_no_orphan_nodes():
    graph = c.get("/api/supply-chain/graph").json()
    ids = {node["id"] for node in graph["nodes"]}
    assert graph["data_source"] == "demo_seed"
    assert graph["summary"]["repositories"] > 0
    assert graph["summary"]["components"] > 0
    assert all(edge["source"] in ids and edge["target"] in ids for edge in graph["edges"])
    assert all(edge["evidence"] for edge in graph["edges"])
    assert any(node["type"] == "sbom" for node in graph["nodes"])
    assert not any(node["type"] in {"workload", "cluster", "cloud_resource"} for node in graph["nodes"])
    assert any(edge["relationship"] == "reports_finding" for edge in graph["edges"])


def test_supply_chain_endpoint_does_not_invent_admission_events():
    result = c.get("/api/supply-chain").json()
    assert result["admission_events_24h"]["available"] is False
    assert result["admission_events_24h"]["allowed"] == 0
    assert all(a["admission"] == "not_observed" for a in result["artifacts"])


def test_console_is_served_without_stale_browser_cache():
    response = c.get("/")
    assert response.status_code == 200
    assert "no-store" in response.headers.get("cache-control", "")


def test_supply_graph_component_matches_require_exact_package_and_version():
    graph = c.get("/api/supply-chain/graph").json()
    nodes = {node["id"]: node for node in graph["nodes"]}
    for edge in graph["edges"]:
        if edge["linkage"] != "component_match":
            continue
        component = nodes[edge["source"]]
        finding = nodes[edge["target"]]
        assert component["label"].casefold() == finding["package"].casefold()
        assert component["version"].casefold() == finding["version"].casefold()


def test_vulnerability_intelligence_aggregates_existing_evidence_without_claiming_feed_freshness():
    r = c.get("/api/v1/intelligence/vulnerabilities")
    assert r.status_code == 200
    d = r.json()
    assert d["source"] == "tenant_findings"
    assert d["summary"]["unique_cves"] > 0
    feeds = {x["name"]: x["state"] for x in d["advisory_feeds"]}
    assert all(feeds[name] == "not_configured" for name in ("OSV", "CISA KEV", "EPSS", "NVD", "GitHub Advisory Database"))
    assert feeds["CSAF/VEX"] == "source_documents"
    assert any(x["kev"] for x in d["items"])
    assert all(isinstance(x["repositories"], list) for x in d["items"])


def test_remediation_campaigns_are_proposal_only_and_group_open_findings():
    r = c.get("/api/v1/remediation/campaigns")
    assert r.status_code == 200
    d = r.json()
    assert d["summary"]["campaigns"] > 0
    assert d["summary"]["findings"] == sum(x["open_count"] for x in d["items"])
    fresh = [x for x in d["items"] if x["state"] == "proposed"]
    assert fresh and all(x["execution_state"] == "proposal_only" and x["approval_state"] == "not_requested"
                         and x["verification_state"] == "not_started" for x in fresh)      # nothing runs until planned and approved


def test_new_intelligence_endpoints_require_authentication(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "demo_open", False)
    assert c.get("/api/v1/intelligence/vulnerabilities", headers={"X-API-Key": "invalid"}).status_code == 401
    assert c.get("/api/v1/remediation/campaigns", headers={"X-API-Key": "invalid"}).status_code == 401


def test_openvex_preview_normalizes_status_without_applying_suppression():
    doc = {"@id": "https://example.test/vex/1", "statements": [
        {"vulnerability": {"name": "CVE-2025-12345"}, "products": ["pkg:pypi/demo@1.0"],
         "status": "not_affected", "justification": "component_not_present"}]}
    r = c.post("/api/v1/intelligence/vex/parse", json={"format": "openvex", "document": doc})
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "openvex" and d["statement_count"] == 1
    assert d["statements"][0]["status"] == "not_affected"
    assert d["applied"] is False


def test_csaf_preview_expands_product_status_without_suppressing_findings():
    doc = {"document": {"tracking": {"id": "CSAF-2026-01"}}, "vulnerabilities": [
        {"cve": "CVE-2026-0001", "product_status": {
            "known_affected": ["product-a"], "fixed": ["product-b"]}}]}
    r = c.post("/api/v1/intelligence/vex/parse", json={"format": "csaf", "document": doc})
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "csaf" and d["statement_count"] == 2
    assert {x["status"] for x in d["statements"]} == {"affected", "fixed"}
    assert d["applied"] is False


def test_vex_parser_rejects_unknown_status_and_oversized_documents():
    bad = {"statements": [{"status": "ignored", "products": ["pkg:pypi/x@1"]}]}
    assert c.post("/api/v1/intelligence/vex/parse", json={"document": bad}).status_code == 422
    huge = {"statements": [{"status": "affected", "products": ["x" * 1_600_000]}]}
    assert c.post("/api/v1/intelligence/vex/parse", json={"document": huge}).status_code == 413


def test_vex_parser_requires_authenticated_access(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "demo_open", False)
    r = c.post("/api/v1/intelligence/vex/parse", headers={"X-API-Key": "invalid"},
               json={"document": {"statements": [{"status": "affected", "products": ["pkg:x"]}]}})
    assert r.status_code == 401


def test_sarif_scanner_import_normalizes_and_persists_findings():
    report = {"runs": [{"tool": {"driver": {"name": "Semgrep", "rules": [{"id": "python.lang.security.audit"}]}},
        "results": [{"ruleId": "python.lang.security.audit", "level": "error",
            "message": {"text": "Unsafe code path"}, "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 12}}}]}]}]}
    r = c.post("/api/v1/scanners/import", headers=H, json={"repo": "parser-test", "format": "sarif", "document": report})
    assert r.status_code == 200
    d = r.json()
    assert d["received"] == 1 and d["format"] == "sarif"
    assert d["scan_id"]
    found = c.get("/api/findings", params={"repo": "parser-test", "status": "all"}).json()["items"]
    assert any(x["file"] == "src/app.py" and x["line"] == 12 for x in found)


def test_trivy_and_grype_scanner_imports_extract_cve_package_and_fix():
    trivy = {"Results": [{"Target": "image.tar", "Type": "os-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2025-1111", "PkgName": "openssl", "InstalledVersion": "1.0",
         "FixedVersion": "1.1", "Severity": "CRITICAL"}]}]}
    a = c.post("/api/v1/scanners/import", headers=H, json={"repo": "trivy-test", "format": "trivy", "document": trivy})
    assert a.status_code == 200 and a.json()["received"] == 1
    grype = {"matches": [{"vulnerability": {"id": "CVE-2025-2222", "severity": "High", "fix": {"versions": ["2.0"]}},
        "artifact": {"name": "libdemo", "version": "1.0", "type": "deb", "locations": [{"path": "rootfs"}]}}]}
    b = c.post("/api/v1/scanners/import", headers=H, json={"repo": "grype-test", "format": "grype", "document": grype})
    assert b.status_code == 200 and b.json()["received"] == 1


def test_dependency_check_import_and_invalid_scanner_report():
    report = {"dependencies": [{"fileName": "pom.xml", "packages": [{"id": "pkg:maven/demo",
        "vulnerabilities": [{"name": "CVE-2025-3333", "severity": "HIGH", "cvssv3": {"baseScore": 8.1}}]}]}]}
    r = c.post("/api/v1/scanners/import", headers=H, json={"repo": "odc-test", "format": "dependency-check", "document": report})
    assert r.status_code == 200 and r.json()["received"] == 1
    bad = c.post("/api/v1/scanners/import", headers=H, json={"repo": "bad", "format": "trivy", "document": {"Results": "not-an-array"}})
    assert bad.status_code == 422


def test_scanner_import_requires_scan_permission(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "demo_open", False)
    r = c.post("/api/v1/scanners/import", headers={"X-API-Key": "invalid"},
        json={"repo": "x", "format": "trivy", "document": {"Results": [{"Target": "image", "Vulnerabilities": []}]}})
    assert r.status_code == 401


def test_finding_assessment_is_persisted_without_closing_finding():
    finding = c.get("/api/findings", params={"status": "open", "limit": 1}).json()["items"][0]
    r = c.patch(f"/api/findings/{finding['id']}/assessment", headers=H, json={
        "assessment": "needs_review", "business_impact": "Production payment workflow",
        "rationale": "Needs application owner validation before risk disposition.",
        "owner": "appsec-team", "due_date": "2026-12-15"})
    assert r.status_code == 200
    updated = r.json()["finding"]
    assert updated["status"] == "open"
    assert updated["assessment"]["assessment"] == "needs_review"
    assert updated["assessment"]["owner"] == "appsec-team"
    again = c.get(f"/api/findings/{finding['id']}").json()
    assert again["assessment"]["rationale"].startswith("Needs application owner")


def test_finding_assessment_rejects_invalid_values_and_bad_dates():
    finding = c.get("/api/findings", params={"status": "open", "limit": 1}).json()["items"][0]
    bad_status = c.patch(f"/api/findings/{finding['id']}/assessment", headers=H, json={
        "assessment": "ignore", "rationale": "This is a sufficiently long reason."})
    assert bad_status.status_code == 422
    bad_date = c.patch(f"/api/findings/{finding['id']}/assessment", headers=H, json={
        "assessment": "exploitable", "rationale": "Validated with the application owner.", "due_date": "2026-99-99"})
    assert bad_date.status_code == 422


def test_finding_assessment_requires_triage_permission(monkeypatch):
    from app.config import settings
    finding = c.get("/api/findings", params={"status": "open", "limit": 1}).json()["items"][0]
    monkeypatch.setattr(settings, "demo_open", False)
    r = c.patch(f"/api/findings/{finding['id']}/assessment", headers={"X-API-Key": "invalid"},
        json={"assessment": "needs_review", "rationale": "Needs validation by the owner."})
    assert r.status_code == 401


def test_baseline_delta_identifies_only_new_findings_and_evaluates_policy():
    first = c.post("/api/scans", headers=H, json={"repo": "baseline-delta-test", "branch": "main",
        "commit": "1111111", "engines": ["sast", "sca"], "findings": [
            {"engine": "sast", "rule_id": "BASELINE-001", "title": "Existing baseline issue",
             "severity": "medium", "file": "src/old.py", "line": 10}]}).json()
    second = c.post("/api/scans", headers=H, json={"repo": "baseline-delta-test", "branch": "main",
        "commit": "2222222", "engines": ["sast", "sca"], "findings": [
            {"engine": "sca", "rule_id": "CVE-2025-9999", "cve": "CVE-2025-9999",
             "title": "New critical dependency", "severity": "critical", "reachable": True,
             "package": "demo-lib", "version": "1.0", "file": "requirements.txt"}]}).json()
    r = c.get("/api/v1/policies/baseline-delta", params={"repo": "baseline-delta-test",
        "base_scan_id": first["scan_id"], "head_scan_id": second["scan_id"]})
    assert r.status_code == 200
    d = r.json()
    assert d["delta"] == {"introduced": 1, "resolved": 1, "unchanged": 0}
    assert d["decision"]["observed_decision"] == "block"
    assert d["introduced_findings"][0]["cve"] == "CVE-2025-9999"


def test_baseline_delta_rejects_same_or_missing_scan_ids():
    same = c.get("/api/v1/policies/baseline-delta", params={"repo": "x",
        "base_scan_id": "same", "head_scan_id": "same"})
    assert same.status_code == 422
    missing = c.get("/api/v1/policies/baseline-delta", params={"repo": "x",
        "base_scan_id": "missing-a", "head_scan_id": "missing-b"})
    assert missing.status_code == 404


def test_baseline_delta_rejects_newer_baseline():
    first = c.post("/api/scans", headers=H, json={"repo": "baseline-order-test", "commit": "aaa",
        "engines": ["sast"], "findings": [{"engine": "sast", "rule_id": "ORDER-1",
        "title": "One", "severity": "low", "file": "a.py"}]}).json()
    second = c.post("/api/scans", headers=H, json={"repo": "baseline-order-test", "commit": "bbb",
        "engines": ["sast"], "findings": [{"engine": "sast", "rule_id": "ORDER-2",
        "title": "Two", "severity": "low", "file": "b.py"}]}).json()
    r = c.get("/api/v1/policies/baseline-delta", params={"repo": "baseline-order-test",
        "base_scan_id": second["scan_id"], "head_scan_id": first["scan_id"]})
    assert r.status_code == 422


def test_policy_version_requires_independent_approval_before_binding():
    from app.main import DEMO
    policy = {"mode": "enforce", "gates": [
        {"id": "test-independent-approval", "description": "Block critical test", "when": {"severity": ["critical"]}, "action": "block"}],
        "exceptions": []}
    created = c.post("/api/policies/versions", headers=H, json={"name": "test-governance", "content": policy})
    assert created.status_code == 201
    version = created.json()["version"]
    assert version["status"] == "draft"
    denied = c.put("/api/policies/bindings", headers=H, json={"policy_version_id": version["id"],
        "scope_type": "organisation", "scope_key": "*"})
    assert denied.status_code == 409
    request = c.post(f"/api/policies/versions/{version['id']}/request-approval", headers=H)
    assert request.status_code == 201
    approval = request.json()["approval"]
    demo_review = c.post(f"/api/policies/approvals/{approval['id']}/review", headers=H,
        json={"decision": "approved", "note": "Demo mode must not approve production policy."})
    assert demo_review.status_code == 403
    assert DEMO.get_policy_version(version["id"])["status"] == "pending"
    with pytest.raises(PermissionError):
        DEMO.review_policy_approval(approval["id"], approval["requested_by"], "approved",
            "Attempted self approval must be rejected.", datetime.now(timezone.utc).isoformat())
    reviewed = DEMO.review_policy_approval(approval["id"], "independent.approver@example.test", "approved",
        "Reviewed policy semantics and accepted the enforcement change.", datetime.now(timezone.utc).isoformat())
    assert reviewed["status"] == "approved"
    assert DEMO.get_policy_version(version["id"])["status"] == "published"
    bound = c.put("/api/policies/bindings", headers=H, json={"policy_version_id": version["id"],
        "scope_type": "organisation", "scope_key": "*"})
    assert bound.status_code == 200
    effective = c.get("/api/policies/effective").json()
    assert effective["_governance"]["layers"][0]["policy_version_id"] == version["id"]
    assert any(g["id"] == "test-independent-approval" for g in effective["gates"])


def test_policy_scope_precedence_and_rollback_create_new_immutable_version():
    from app.main import DEMO
    def publish_and_bind(name, scope_type, scope_key, gate_id, action, mode):
        created = c.post("/api/policies/versions", headers=H, json={"name": name, "content": {
            "mode": mode, "gates": [{"id": gate_id, "description": gate_id,
            "when": {"engine": ["sast"]}, "action": action}], "exceptions": []}})
        assert created.status_code == 201
        version = created.json()["version"]
        req = c.post(f"/api/policies/versions/{version['id']}/request-approval", headers=H)
        assert req.status_code == 201
        DEMO.review_policy_approval(req.json()["approval"]["id"], "independent.approver@example.test",
            "approved", "Independent policy review completed.", datetime.now(timezone.utc).isoformat())
        bound = c.put("/api/policies/bindings", headers=H, json={"policy_version_id": version["id"],
            "scope_type": scope_type, "scope_key": scope_key})
        assert bound.status_code == 200
        return version
    org = publish_and_bind("org-policy-test", "organisation", "*", "org-gate-test", "warn", "audit")
    publish_and_bind("project-policy-test", "project", "payments", "project-gate-test", "block", "warn")
    publish_and_bind("repo-policy-test", "repository", "payments-api", "repo-gate-test", "block", "enforce")
    mapping = c.put("/api/policies/repository-projects", headers=H,
        json={"repo": "payments-api", "project": "payments"})
    assert mapping.status_code == 200
    effective = c.get("/api/policies/effective", params={"project": "payments", "repo": "payments-api"}).json()
    layers = effective["_governance"]["layers"]
    assert [x["scope_type"] for x in layers] == ["organisation", "project", "repository"]
    assert effective["mode"] == "enforce"
    assert {g["id"] for g in effective["gates"]} >= {"org-gate-test", "project-gate-test", "repo-gate-test"}
    unmapped = c.post("/api/scans", headers=H, json={"repo": "unmapped-project-repo",
        "commit": "must-fail-closed", "engines": ["sast"], "findings": []})
    assert unmapped.status_code == 409
    scan = c.post("/api/scans", headers=H, json={"repo": "payments-api", "project": "attacker-selected-project",
        "commit": "policy-scope-test", "engines": ["sast"], "findings": [
            {"engine": "sast", "rule_id": "SCOPE-TEST-1", "title": "Scoped policy test",
             "severity": "low", "file": "src/example.py"}]})
    assert scan.status_code == 200
    assert scan.json()["decision"]["mode"] == "enforce"
    assert scan.json()["decision"]["observed_decision"] == "block"
    rolled = c.post(f"/api/policies/versions/{org['id']}/rollback", headers=H)
    assert rolled.status_code == 201
    draft = rolled.json()["version"]
    assert draft["id"] != org["id"] and draft["version"] > org["version"]
    assert draft["status"] == "draft"
    assert draft["content_sha256"] == org["content_sha256"]
    assert draft["content"] == org["content"]


def test_policy_version_validation_and_scope_binding_validation():
    bad_mode = c.post("/api/policies/versions", headers=H, json={"name": "bad-mode", "content": {
        "mode": "disable", "gates": [], "exceptions": []}})
    assert bad_mode.status_code == 422
    bad_action = c.post("/api/policies/versions", headers=H, json={"name": "bad-action", "content": {
        "mode": "enforce", "gates": [{"id": "bad-action", "when": {}, "action": "disable"}], "exceptions": []}})
    assert bad_action.status_code == 422
    duplicate = c.post("/api/policies/versions", headers=H, json={"name": "duplicate-gates", "content": {
        "mode": "enforce", "gates": [{"id": "same", "when": {}, "action": "warn"},
        {"id": "same", "when": {}, "action": "block"}], "exceptions": []}})
    assert duplicate.status_code == 422
    bad_scope = c.put("/api/policies/bindings", headers=H, json={"policy_version_id": "not-a-uuid",
        "scope_type": "organisation", "scope_key": "not-star"})
    assert bad_scope.status_code == 422


def test_scanner_import_supports_semgrep_and_cyclonedx():
    from app.main import DEMO
    DEMO.set_repo_project("parser-semgrep", "payments", "test-setup")
    DEMO.set_repo_project("parser-cyclonedx", "payments", "test-setup")
    semgrep = c.post("/api/v1/scanners/import", headers=H, json={
        "repo": "parser-semgrep", "commit": "abcdef1234567", "format": "semgrep",
        "document": {"results": [{"check_id": "python.lang.security.audit.subprocess-shell-true",
            "path": "app.py", "start": {"line": 12}, "extra": {"severity": "ERROR",
            "message": "Subprocess shell execution", "metadata": {"cwe": ["CWE-78"]}}}]}})
    assert semgrep.status_code == 200
    assert semgrep.json()["received"] == 1
    bom = c.post("/api/v1/scanners/import", headers=H, json={
        "repo": "parser-cyclonedx", "commit": "abcdef1234568", "format": "cyclonedx",
        "document": {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"type": "library", "bom-ref": "pkg-1", "name": "log4j-core",
                "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
            "vulnerabilities": [{"id": "CVE-2021-44228", "detail": "Log4Shell",
                "ratings": [{"severity": "critical", "score": 10.0}],
                "affects": [{"ref": "pkg-1"}]}]}})
    assert bom.status_code == 200
    assert bom.json()["received"] == 1


def test_spdx_sbom_import_retains_packages_licenses_and_dependency_edges():
    from app.main import DEMO
    repo = "spdx-import-validation"
    DEMO.set_repo_project(repo, "payments", "test-setup")
    doc = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "payments-service", "documentNamespace": "https://example.test/spdx/payments-service",
        "packages": [
            {"SPDXID": "SPDXRef-App", "name": "payments-service", "versionInfo": "1.0.0",
             "licenseDeclared": "Apache-2.0", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
             "referenceType": "purl", "referenceLocator": "pkg:pypi/payments-service@1.0.0"}]},
            {"SPDXID": "SPDXRef-Lib", "name": "requests", "versionInfo": "2.31.0",
             "licenseConcluded": "Apache-2.0", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
             "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}]}],
        "relationships": [{"spdxElementId": "SPDXRef-App", "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Lib"}]}
    response = c.post("/api/v1/scanners/import", headers=H, json={
        "repo": repo, "commit": "spdx-commit-1", "format": "spdx", "document": doc})
    assert response.status_code == 200
    assert response.json()["received"] == 0
    assert response.json()["components"] == 2
    graph = c.get("/api/supply-chain/graph", headers=H).json()
    components = [x for x in graph["nodes"] if x["type"] == "component" and x.get("repository") == repo]
    assert len(components) == 2
    assert any("Apache-2.0" in str(x.get("licenses")) for x in components)
    assert any(x["relationship"] == "depends_on" for x in graph["edges"])


def test_spdx_import_rejects_invalid_version_and_missing_packages():
    assert c.post("/api/v1/scanners/import", headers=H, json={
        "repo": "spdx-bad", "format": "spdx", "document": {"spdxVersion": "SPDX-3.0", "packages": []}}).status_code == 422
    assert c.post("/api/v1/scanners/import", headers=H, json={
        "repo": "spdx-bad", "format": "spdx", "document": {"spdxVersion": "SPDX-2.3"}}).status_code == 422


def test_advisory_sync_persists_queued_job_for_independent_worker():
    response = c.post("/api/v1/intelligence/feeds/KEV/sync", headers=H, json={"limit": 10})
    assert response.status_code == 202
    assert response.json()["job"]["status"] == "queued"
    jobs = c.get("/api/v1/intelligence/feeds/jobs", headers=H).json()["items"]
    assert jobs[0]["id"] == response.json()["job"]["id"]
    assert jobs[0]["status"] == "queued"
    assert "separately deployed" in response.json()["note"]


def test_failed_advisory_sync_job_is_requeued_for_worker_not_run_in_api():
    from app.main import DEMO
    job = {"id": str(uuid.uuid4()), "kind": "advisory_sync", "source": "EPSS", "status": "failed",
        "requested_by": "security@example.test", "counters": {"targets": ["CVE-2025-1111"], "requested": 1},
        "error": "temporary upstream failure", "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None, "finished_at": datetime.now(timezone.utc).isoformat()}
    DEMO.create_import_job(job)
    response = c.post(f"/api/v1/intelligence/feeds/jobs/{job['id']}/retry", headers=H)
    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    current = next(x for x in DEMO.import_jobs() if x["id"] == job["id"])
    assert current["status"] == "queued"
    assert current["counters"]["targets"] == ["CVE-2025-1111"]


def test_demo_worker_claims_queued_job_and_enforces_attempt_limit():
    from app.store import DemoStore
    store = DemoStore({"import_jobs": []})
    now = datetime.now(timezone.utc).isoformat()
    job = {"id": str(uuid.uuid4()), "kind": "advisory_sync", "source": "OSV", "status": "queued",
        "requested_by": "worker-test", "counters": {"targets": ["pkg:pypi/demo@1"]},
        "error": "", "created_at": now, "started_at": None, "finished_at": None}
    store.create_import_job(job)
    claimed = store.claim_import_job("worker-a", lease_seconds=60, max_attempts=2)
    assert claimed["status"] == "running"
    assert claimed["counters"]["attempts"] == 1
    assert claimed["counters"]["worker_id"] == "worker-a"
    assert store.claim_import_job("worker-b", lease_seconds=60, max_attempts=2) is None
    # A failed job can be explicitly requeued, retaining its idempotent target set.
    store.update_import_job(job["id"], "failed", error="simulated crash")
    store.requeue_import_job(job["id"], "operator")
    second = store.claim_import_job("worker-b", lease_seconds=60, max_attempts=2)
    assert second["counters"]["attempts"] == 2
    store.update_import_job(job["id"], "failed", error="second failure")
    store.requeue_import_job(job["id"], "operator")
    assert store.claim_import_job("worker-c", lease_seconds=60, max_attempts=2) is None
    final = next(x for x in store.import_jobs() if x["id"] == job["id"])
    assert final["status"] == "failed"
    assert "maximum worker attempts" in final["error"]


def test_osv_sync_persists_normalized_advisories_without_network(monkeypatch):
    import httpx
    import app.main as main
    from app.main import DEMO, DEMO_TENANT
    job = {"id": str(uuid.uuid4()), "kind": "advisory_sync", "source": "OSV", "status": "queued",
        "requested_by": "security@example.test", "counters": {"targets": ["pkg:pypi/requests@2.31.0"]},
        "error": "", "created_at": datetime.now(timezone.utc).isoformat(), "started_at": None, "finished_at": None}
    DEMO.create_import_job(job)
    class FakeResponse:
        status_code = 200
        headers = {}
        content = b'{}'
        def raise_for_status(self): return None
        def json(self):
            return {"results": [{"vulns": [{"id": "GHSA-test-1234", "aliases": ["CVE-2025-1234"],
                "summary": "Test advisory", "modified": "2026-11-20T00:00:00Z", "affected": []}]}]}
    class FakeClient:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def request(self, method, url, **kwargs):
            assert url == "https://api.osv.dev/v1/querybatch"
            assert kwargs["json"]["queries"][0]["package"]["purl"] == "pkg:pypi/requests@2.31.0"
            return FakeResponse()
    monkeypatch.setattr(httpx, "Client", FakeClient)
    main._run_advisory_feed_sync(job["id"], "OSV", DEMO_TENANT, ["pkg:pypi/requests@2.31.0"], [], "security@example.test")
    stored = DEMO.advisory_records("OSV")
    assert any(x["advisory_id"] == "GHSA-test-1234" and x["payload"]["aliases"] == ["CVE-2025-1234"] for x in stored)
    current = next(x for x in DEMO.import_jobs() if x["id"] == job["id"])
    assert current["status"] == "succeeded" and current["counters"]["stored"] == 1


def test_advisory_feeds_enrich_finding_kev_epss_and_osv_fix_versions():
    from app.main import DEMO
    repo = "advisory-enrichment-test"
    DEMO.set_repo_project(repo, "payments", "test-setup")
    imported = c.post("/api/v1/scanners/import", headers=H, json={"repo": repo, "format": "trivy",
        "document": {"Results": [{"Target": "image", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2025-9876", "PkgName": "demo-lib", "InstalledVersion": "1.0",
            "Severity": "HIGH"}]}]}})
    assert imported.status_code == 200
    DEMO.upsert_advisories("KEV", [{"advisory_id": "CVE-2025-9876", "modified_at": None,
        "payload": {"cve": "CVE-2025-9876", "required_action": "Apply vendor update"}}])
    DEMO.upsert_advisories("EPSS", [{"advisory_id": "CVE-2025-9876", "modified_at": None,
        "payload": {"cve": "CVE-2025-9876", "epss": "0.98", "percentile": "0.999"}}])
    DEMO.upsert_advisories("OSV", [{"advisory_id": "GHSA-demo-1234", "modified_at": None,
        "payload": {"id": "GHSA-demo-1234", "aliases": ["CVE-2025-9876"],
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}]}]}}])
    DEMO.upsert_advisories("NVD", [{"advisory_id": "CVE-2025-9876", "modified_at": None,
        "payload": {"cve": "CVE-2025-9876", "cvss": 9.8, "severity": "CRITICAL"}}])
    DEMO.upsert_advisories("GITHUB", [{"advisory_id": "GHSA-github-1234", "modified_at": None,
        "payload": {"id": "GHSA-github-1234", "cve": "CVE-2025-9876"}}])
    data = c.get("/api/v1/intelligence/vulnerabilities", headers=H).json()
    item = next(x for x in data["items"] if x["cve"] == "CVE-2025-9876")
    assert item["kev"] is True
    assert item["epss"] == 0.98
    assert "GHSA-demo-1234" in item["advisories"]
    assert item["cvss"] == 9.8 and item["nvd_severity"] == "CRITICAL"
    assert "GHSA-github-1234" in item["github_advisories"]
    assert "1.2.0" in item["fixed_versions"]


def test_nvd_and_github_advisory_sync_use_fixed_vendor_apis(monkeypatch):
    import httpx
    import app.main as main
    from app.main import DEMO, DEMO_TENANT
    monkeypatch.setenv("NVD_API_KEY", "test-nvd-key")
    monkeypatch.setenv("GITHUB_ADVISORY_TOKEN", "test-github-token")
    class FakeResponse:
        status_code = 200
        headers = {}
        content = b'{}'
        def __init__(self, payload): self.payload = payload
        def raise_for_status(self): return None
        def json(self): return self.payload
    class FakeClient:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def request(self, method, url, **kwargs):
            if "nvd.nist.gov" in url:
                assert kwargs["params"]["cveId"] == "CVE-2025-9876"
                assert kwargs["headers"]["apiKey"] == "test-nvd-key"
                return FakeResponse({"vulnerabilities": [{"cve": {"id": "CVE-2025-9876",
                    "lastModified": "2026-11-20T00:00:00Z",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                    "descriptions": [{"lang": "en", "value": "Test NVD advisory"}]}}]})
            assert "api.github.com/advisories" in url
            assert kwargs["params"]["cve_id"] == "CVE-2025-9876"
            assert kwargs["headers"]["Authorization"] == "Bearer test-github-token"
            return FakeResponse([{"ghsa_id": "GHSA-test-9876", "cve_id": "CVE-2025-9876",
                "summary": "Test GitHub advisory", "severity": "high", "updated_at": "2026-11-20T00:00:00Z"}])
    monkeypatch.setattr(httpx, "Client", FakeClient)
    for source in ("NVD", "GITHUB"):
        job = {"id": str(uuid.uuid4()), "kind": "advisory_sync", "source": source, "status": "queued",
            "requested_by": "security@example.test", "counters": {}, "error": "",
            "created_at": datetime.now(timezone.utc).isoformat(), "started_at": None, "finished_at": None}
        DEMO.create_import_job(job)
        main._run_advisory_feed_sync(job["id"], source, DEMO_TENANT, [], ["CVE-2025-9876"], "security@example.test")
    assert any(x["advisory_id"] == "CVE-2025-9876" for x in DEMO.advisory_records("NVD"))
    assert any(x["advisory_id"] == "GHSA-test-9876" for x in DEMO.advisory_records("GITHUB"))


def test_remediation_verification_requires_originating_engine_coverage():
    from app.main import DEMO
    DEMO.set_repo_project("verify-repo", "payments", "test-setup")
    first = c.post("/api/scans", headers=H, json={"repo": "verify-repo", "commit": "1111111",
        "engines": ["sast"], "findings": [{"engine": "sast", "rule_id": "VERIFY-001",
            "severity": "high", "title": "Verification test"}]})
    assert first.status_code == 200
    finding = c.get("/api/findings", headers=H, params={"repo": "verify-repo", "status": "open", "limit": 10}).json()["items"][0]
    wrong = c.post("/api/scans", headers=H, json={"repo": "verify-repo", "commit": "2222222",
        "engines": ["sca"], "findings": []}).json()
    rejected = c.post(f"/api/v1/findings/{finding['id']}/verify-remediation", headers=H, json={
        "verification_scan_id": wrong["scan_id"], "remediation_commit": "2222222",
        "notes": "Attempted verification without SAST coverage"})
    assert rejected.status_code == 409
    clean = c.post("/api/scans", headers=H, json={"repo": "verify-repo", "commit": "3333333",
        "engines": ["sast"], "findings": []}).json()
    verified = c.post(f"/api/v1/findings/{finding['id']}/verify-remediation", headers=H, json={
        "verification_scan_id": clean["scan_id"], "remediation_commit": "3333333",
        "notes": "SAST rerun completed and finding fingerprint is absent"})
    assert verified.status_code == 200
    assert verified.json()["finding_status"] == "fixed"
    events = c.get(f"/api/findings/{finding['id']}/events", headers=H).json()
    assert any(x["event"] == "remediation_verification" for x in events["events"])
    assert events["remediation_verifications"][-1]["result"] == "passed"


def test_openvex_document_is_persisted_as_provenance_without_suppressing_finding():
    from app.main import DEMO
    finding = next((x for x in DEMO.findings() if x.get("cve") == "CVE-2021-44228" and x.get("purl")), None)
    if finding is None:
        finding = {"id": "vex-fixture-finding", "fingerprint": "a" * 64, "repo": "vex-fixture",
            "engine": "sca", "severity": "critical", "priority": "P0", "mrs": 95, "status": "open",
            "cve": "CVE-2021-44228", "rule_id": "CVE-2021-44228",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "title": "Log4Shell"}
        DEMO.findings().append(finding)
    original_status = finding["status"]
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://vendor.example/vex/2026-01",
        "author": "Vendor PSIRT", "timestamp": "2026-01-01T00:00:00Z", "version": 1,
        "statements": [{"vulnerability": {"name": "CVE-2021-44228"}, "products": [
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"], "status": "not_affected",
            "justification": "component_not_present"}]}
    response = c.post("/api/v1/intelligence/vex/documents", headers=H, json={"document": doc})
    assert response.status_code == 200
    assert response.json()["created"] is True
    assert response.json()["matched_findings"] >= 1
    assert finding["status"] == original_status
    docs = c.get("/api/v1/intelligence/vex/documents", headers=H).json()["items"]
    assert any(x["sha256"] == response.json()["document"]["sha256"] for x in docs)


def test_finding_assessment_and_status_changes_record_event_history():
    finding = c.get("/api/findings", params={"status": "open", "limit": 1}).json()["items"][0]
    updated = c.patch(f"/api/findings/{finding['id']}/assessment", headers=H, json={
        "assessment": "needs_review", "rationale": "Review evidence and exploitability before accepting risk.",
        "owner": "AppSec", "due_date": "2026-12-01"})
    assert updated.status_code == 200
    events = c.get(f"/api/findings/{finding['id']}/events", headers=H).json()["events"]
    assert any(x["event"] == "assessed" for x in events)


def test_policy_exception_requires_independent_approval_and_expires():
    from app.main import DEMO
    from datetime import timedelta
    expires = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
    created = c.post("/api/policies/exceptions", headers=H, json={
        "scope_type": "repository", "scope_key": "exception-test-repo",
        "match": {"cve": "CVE-2099-0001", "repo": "exception-test-repo"},
        "reason": "Temporary exception while a vendor patch is validated in the controlled release window.",
        "expires_at": expires})
    assert created.status_code == 201
    item = created.json()["exception"]
    assert item["status"] == "pending"
    assert not any(x["id"] == item["id"] for x in DEMO.policy_exceptions() if x["status"] == "approved")
    with pytest.raises(PermissionError):
        DEMO.review_policy_exception(item["id"], item["requested_by"], "approved", "self approval", datetime.now(timezone.utc).isoformat())
    reviewed = DEMO.review_policy_exception(item["id"], "independent.approver@example.test", "approved",
        "Independent review completed; exception is narrowly scoped and time limited.", datetime.now(timezone.utc).isoformat())
    assert reviewed["status"] == "approved"
    assert reviewed["reviewed_by"] != reviewed["requested_by"]
    DEMO.set_repo_project("exception-test-repo", "payments", "policy-admin@example.test")
    effective = c.get("/api/policies/effective", params={"repo": "exception-test-repo"}).json()
    assert any(x["id"] == item["id"] for x in effective["exceptions"])



def test_policy_approver_role_is_separate_from_policy_author_role():
    from app.auth.rbac import Principal, map_roles
    mapping = {"appsec": "security_lead", "policy-review": "policy_approver"}
    author_roles = map_roles(["appsec"], mapping)
    reviewer_roles = map_roles(["policy-review"], mapping)
    author = Principal(uuid.uuid4(), "author", "issuer", roles=author_roles)
    reviewer = Principal(uuid.uuid4(), "reviewer", "issuer", roles=reviewer_roles)
    assert author.can("policies:write") and not author.can("policies:approve")
    assert reviewer.can("policies:approve") and not reviewer.can("policies:write")


def test_licence_policy_report_is_tenant_scoped_and_explicit_about_unknowns():
    from app.main import DEMO

    DEMO.sbom("payments-web")
    DEMO.db.setdefault("sboms", {})["licence-policy-test"] = {
        "components": [
            {"name": "permissive-lib", "version": "1.0", "license": "MIT"},
            {"name": "copyleft-lib", "version": "2.0", "license": "GPL-3.0-only"},
            {"name": "custom-lib", "version": "3.0", "license": "LicenseRef-Internal"},
            {"name": "bad-expression", "version": "4.0", "license": "MIT AND"},
        ]
    }
    DEMO.repos().append({"name": "licence-policy-test"})
    DEMO.set_repo_project("licence-policy-test", "payments", "test-setup")    # project policy layers require a mapping
    try:
        response = c.get("/api/v1/licenses/report", params={"repo": "licence-policy-test"})
        assert response.status_code == 200
        report = response.json()
        assert report["components_evaluated"] == 4
        assert report["counts"] == {"allow": 1, "review": 3, "deny": 0}
        decisions = {x["package"]: x["decision"] for x in report["items"]}
        assert decisions["permissive-lib"] == "allow"
        assert decisions["copyleft-lib"] == "review"
        assert decisions["custom-lib"] == "review"
        assert decisions["bad-expression"] == "review"
        assert report["legal_advice"] is False
    finally:
        DEMO.db["sboms"].pop("licence-policy-test", None)
        DEMO.db["repos"][:] = [x for x in DEMO.db["repos"] if x.get("name") != "licence-policy-test"]


def test_licence_report_uses_published_repository_policy_binding():
    from app.main import DEMO

    repository = "licence-policy-binding-test"
    version_id = str(uuid.uuid4())
    DEMO.db.setdefault("sboms", {})[repository] = {"components": [
        {"name": "test-mit", "version": "1.0", "license": "MIT"},
        {"name": "test-gpl", "version": "2.0", "license": "GPL-3.0-only"},
    ]}
    DEMO.repos().append({"name": repository})
    DEMO.set_repo_project(repository, "payments", "test-setup")
    version = {"id": version_id, "name": "customer-licence-policy", "version": 1,
        "status": "published", "content": {"mode": "enforce", "licence_policy": {
            "version": "customer-licence-v1", "deny": ["MIT"],
            "require_approval": [], "allow": ["GPL-3.0-only"], "unknown_action": "review"}},
        "content_sha256": "a" * 64, "created_by": "policy-admin@example.test",
        "created_at": datetime.now(timezone.utc).isoformat()}
    DEMO.create_policy_version(version)
    DEMO.bind_policy({"scope_type": "repository", "scope_key": repository,
        "policy_version_id": version_id, "updated_by": "policy-admin@example.test"})
    try:
        response = c.get("/api/v1/licenses/report", params={"repo": repository})
        assert response.status_code == 200
        result = response.json()
        assert result["policy_version"] == "customer-licence-v1"
        decisions = {x["package"]: x["decision"] for x in result["items"]}
        assert decisions == {"test-mit": "deny", "test-gpl": "allow"}
    finally:
        DEMO.db["sboms"].pop(repository, None)
        DEMO.db["repos"][:] = [x for x in DEMO.db["repos"] if x.get("name") != repository]
        DEMO.db["policy_versions"][:] = [x for x in DEMO.policy_versions() if x["id"] != version_id]
        DEMO.db["policy_bindings"][:] = [x for x in DEMO.policy_bindings()
            if not (x["scope_type"] == "repository" and x["scope_key"] == repository)]
