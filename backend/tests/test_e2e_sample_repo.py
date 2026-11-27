# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""End-to-end: one sample repository (demo/vulnerable-app) through every feature of the platform.

scan from the console → every engine reports → dashboards → report (internal + external) → SBOM → licence policy →
VEX export → AI explain / triage / ask / briefing → triage decisions → campaign workflow → gates (full, new-only,
coverage) → re-scan closes fixed findings → baseline delta → scanner import → CSV / audit exports → supply-chain defence →
SSVC → repository posture (OSPS Baseline) → cryptography inventory (CBOM) / post-quantum readiness → EU CRA tracker."""
import base64
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient  # noqa: E402

from app import main, scm  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLE = os.path.join(ROOT, "demo", "vulnerable-app")
H = {"X-API-Key": "nm_demo_9f2c41e7b8"}
REPO = "acme-sample-app"


def _tar(src, top):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(src, arcname=top)
    return buf.getvalue()


@pytest.fixture(scope="module")
def world():
    """Serve the sample repo as a GitHub archive; a second commit removes the hard-coded OpenAI key and the MCP config."""
    work = tempfile.mkdtemp()
    v1 = os.path.join(work, "v1")
    shutil.copytree(SAMPLE, v1)
    v2 = os.path.join(work, "v2")
    shutil.copytree(SAMPLE, v2)
    p = os.path.join(v2, "ai", "support_agent.py")
    open(p, "w").write("\n".join(ln for ln in open(p).read().splitlines() if "OPENAI_API_KEY" not in ln) + "\n")
    os.remove(os.path.join(v2, ".vscode", "mcp.json"))
    os.remove(os.path.join(v2, "AGENTS.md"))                       # the backdoored agent instructions are removed too
    state = {"version": "v1"}
    orig = scm._http

    def _http(url, headers, limit=0, want_json=False):
        if want_json:
            return {"default_branch": "main"}
        return _tar(v1 if state["version"] == "v1" else v2, "acme-sample-app-" + ("1111111aaa" if state["version"] == "v1" else "2222222bbb"))
    scm._http = _http
    os.environ["MYELIN_OFFLINE"] = "1"
    main.DEMO.set_repo_project(REPO, "e2e-sample", "test-setup")
    yield {"c": TestClient(main.app), "state": state}
    scm._http = orig
    shutil.rmtree(work, ignore_errors=True)


def test_01_scan_reports_every_engine(world):
    c = world["c"]
    r = c.post("/api/v1/repos/sources?wait=true", headers=H, json={"url": f"https://github.com/acme/{REPO}", "criticality": "high"})
    assert r.status_code == 201, r.text
    src = r.json()
    world["src"] = src
    assert src["status"] == "done", src
    by = src["summary"]["by_engine"]
    for eng in ("sast", "sca", "secrets", "iac", "cicd", "license", "aibom", "supply"):
        assert by.get(eng, 0) > 0, (eng, by)
    rules = {f["rule_id"] for f in c.get("/api/findings", headers=H, params={"repo": REPO, "limit": 1000}).json()["items"]}
    for rid in ("NM-CD-001", "NM-CD-002", "NM-CD-006", "NM-CD-009", "NM-CD-010",   # CD / GitOps
                "NM-AI-008", "NM-AI-011", "NM-AI-013", "NM-AI-016", "NM-AI-023", "NM-AI-026", "NM-AI-027",   # AI app + MCP
                "NM-SEC-012", "NM-SEC-002", "NM-LIC-001", "CVE-2020-14343", "CVE-2021-44228",
                "NM-SUP-002", "NM-SUP-004", "NM-SUP-005", "NM-SUP-006", "NM-SUP-008", "NM-SUP-009",   # supply-chain defence
                "NM-CICD-014", "NM-CICD-015", "NM-CICD-021",                                         # CI token-theft hardening
                "NM-AI-028", "NM-AI-029", "NM-AI-030", "NM-AI-031"):                                 # AI coding agents
        assert rid in rules, rid


def test_02_findings_are_linked_and_scored(world):
    c = world["c"]
    items = c.get("/api/findings", headers=H, params={"repo": REPO, "limit": 1000}).json()["items"]
    sast = next(f for f in items if f["engine"] == "sast" and f.get("line"))
    assert sast["code_url"].startswith(f"https://github.com/acme/{REPO}/blob/1111111aaa/") and f"#L{sast['line']}" in sast["code_url"]
    assert all(f["priority"] in ("P0", "P1", "P2", "P3") and 0 <= f["mrs"] <= 100 for f in items)
    ai = [f for f in items if f["engine"] == "aibom"]
    assert ai and all(f.get("owasp_llm") for f in ai)


def test_03_dashboards(world):
    s = world["c"].get("/api/summary", headers=H).json()
    row = next(r for r in s["by_repo"] if r["repo"] == REPO)
    assert row["open"] > 0 and row["gate"] in ("block", "warn", "pass")
    assert any(f["id"] == "llm" for f in s["frameworks"])
    assert s["trend"][-1]["open"] >= row["open"] and len(s["aging"]) == 4


def test_04_report_editions_with_cves_and_frameworks(world):
    c, sid = world["c"], world["src"]["id"]
    internal = c.get(f"/api/v1/repos/sources/{sid}/report", headers=H).text
    external = c.get(f"/api/v1/repos/sources/{sid}/report", headers=H, params={"audience": "external", "prepared_for": "Initech"}).text
    for t in ("Vulnerability register (CVE)", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "OWASP Top 10 for LLM Applications",
              "Software bill of materials (SBOM)", "RAT Flea DevSec", "github.com/sudheerkumard/nervve-devsecops"):
        assert t in internal, t
    assert "<b>Evidence</b>" in internal and "<b>Evidence</b>" not in external and "Initech" in external
    assert "sk-proj-AbCdEf" not in internal and "ghp_Zx9Yw8" not in internal       # secret values never appear


def test_05_sbom_licence_and_vex(world):
    c, sid = world["c"], world["src"]["id"]
    sbom = c.get(f"/api/v1/repos/sources/{sid}/sbom", headers=H).json()
    assert sbom["bomFormat"] == "CycloneDX" and len(sbom["components"]) > 5
    ov = c.get("/api/v1/vex", headers=H, params={"repo": REPO}).json()
    assert ov["statements"] and all(s["status"] in ("affected", "under_investigation", "fixed", "not_affected") for s in ov["statements"])


def test_06_ai_assistant(world):
    c = world["c"]
    items = c.get("/api/findings", headers=H, params={"repo": REPO, "limit": 1000}).json()["items"]
    sqli = next(f for f in items if f.get("cwe") == "CWE-89")
    e = c.post(f"/api/findings/{sqli['id']}/explain", headers=H).json()
    assert e["source"] == "built-in" and "parameterised" in " ".join(e["steps"]).lower() and e["references"]
    cve = next(f for f in items if f.get("cve") == "CVE-2020-14343")
    e2 = c.post(f"/api/findings/{cve['id']}/explain", headers=H).json()
    assert e2["steps"][0].startswith("Upgrade pyyaml") and any(r["url"].endswith("CVE-2020-14343") for r in e2["references"])
    t = c.post(f"/api/v1/ai/triage/{cve['id']}", headers=H).json()
    assert t["verdict"] in ("likely_true_positive", "needs_review", "likely_false_positive") and t["note"]
    a = c.post("/api/v1/ai/ask", headers=H, json={"question": f"critical secrets in {REPO}"}).json()
    assert a["count"] >= 1 and all(f["engine"] == "secrets" and f["severity"] == "critical" and f["repo"] == REPO for f in a["findings"])
    a2 = c.post("/api/v1/ai/ask", headers=H, json={"question": f"AI findings in {REPO}"}).json()
    assert a2["count"] >= 5 and {f["engine"] for f in a2["findings"]} == {"aibom"}
    b = c.get("/api/v1/ai/briefing", headers=H).json()
    assert len(b["paragraphs"]) >= 3 and "posture" in b["paragraphs"][0].lower()
    assert c.get("/api/v1/ai/status", headers=H).json()["built_in"] is True


def test_07_triage_decisions_feed_vex(world):
    c = world["c"]
    items = c.get("/api/findings", headers=H, params={"repo": REPO, "engine": "sca", "limit": 1000}).json()["items"]
    jinja = next(f for f in items if f.get("package") == "jinja2")
    assert c.post(f"/api/findings/{jinja['id']}/status", headers=H,
                  json={"status": "suppressed", "reason": "vulnerable_code_not_in_execute_path: xmlattr is never used"}).status_code == 200
    req = next(f for f in items if f.get("package") == "requests")
    exp = (datetime.now(timezone.utc) + timedelta(days=45)).date().isoformat()
    assert c.post(f"/api/findings/{req['id']}/status", headers=H,
                  json={"status": "risk_accepted", "reason": "egress proxy enforces TLS", "expires": exp}).status_code == 200
    st = {s["vulnerability"]["name"]: s for s in c.get("/api/v1/vex", headers=H, params={"repo": REPO}).json()["statements"]}
    assert st[jinja["cve"]]["status"] == "not_affected" and st[req["cve"]]["status"] == "affected"
    assert exp in st[req["cve"]]["action_statement"]


def test_08_campaign_workflow_enforces_four_eyes(world):
    c = world["c"]
    camps = c.get("/api/v1/remediation/campaigns", headers=H).json()["items"]
    mine = next(x for x in camps if x["repository"] == REPO and x["target"] == "pyyaml")
    assert mine["state"] == "proposed" and mine["action"].startswith("Upgrade pyyaml")
    p = c.post(f"/api/v1/remediation/campaigns/{mine['id']}", headers=H, json={"action": "plan", "owner": "payments-devops", "due_date": "2026-12-31"})
    assert p.status_code == 200 and p.json()["state"] == "planned" and "payments-devops" in p.json()["owners"]
    # the same person cannot approve their own plan
    assert c.post(f"/api/v1/remediation/campaigns/{mine['id']}", headers=H, json={"action": "approve"}).status_code == 403
    assert c.post(f"/api/v1/remediation/campaigns/{mine['id']}", headers=H, json={"action": "start"}).status_code == 409
    assert c.post(f"/api/v1/remediation/campaigns/{mine['id']}", headers=H, json={"action": "plan"}).status_code == 400   # owner required


def test_09_gates(world):
    c = world["c"]
    full = c.get("/api/v1/gate", headers=H, params={"repo": REPO, "commit": "1111111aaa"}).json()
    scan = next(p for p in c.get("/api/pipelines", headers=H, params={"repo": REPO}).json() if p["id"] == full["scan_id"])
    assert full["decision"] == scan["decision"] and full["engines"]      # the gate repeats the policy decision of that scan
    new = c.get("/api/v1/gate", headers=H, params={"repo": REPO, "commit": "1111111aaa", "scope": "new"}).json()
    assert new["new_findings"] > 0                       # the first scan introduces everything
    cov = c.get("/api/v1/gate", headers=H, params={"repo": REPO, "commit": "1111111aaa", "require": "sast,sca,dast"}).json()
    # A bundled advisory pack is assessed but partial; the coverage gate must not count it as complete.
    assert cov["decision"] == "block" and {"sca", "dast"} <= set(cov["missing_engines"])
    assert c.get("/api/v1/gate", headers=H, params={"repo": REPO, "commit": "9999999"}).status_code == 404   # unscanned fails closed


def test_10_rescan_closes_fixed_findings_and_baseline_delta(world):
    c = world["c"]
    world["state"]["version"] = "v2"
    r = c.post(f"/api/v1/repos/sources/{world['src']['id']}/scan?wait=true", headers=H)
    assert r.status_code in (200, 202), r.text
    items = c.get("/api/findings", headers=H, params={"repo": REPO, "status": "fixed", "limit": 1000}).json()["items"]
    fixed_rules = {f["rule_id"] for f in items}
    assert {"NM-SEC-012", "NM-AI-023", "NM-AI-026", "NM-AI-028", "NM-AI-029"} <= fixed_rules, fixed_rules
    new = c.get("/api/v1/gate", headers=H, params={"repo": REPO, "commit": "2222222bbb", "scope": "new"}).json()
    assert new["new_findings"] == 0 and new["decision"] == "pass"   # the fix commit introduced nothing
    scans = sorted([p for p in c.get("/api/pipelines", headers=H, params={"repo": REPO}).json() if p.get("finding_fingerprints")],
                   key=lambda p: p["started"])
    d = c.get("/api/v1/policies/baseline-delta", headers=H, params={"repo": REPO, "base_scan_id": scans[0]["id"], "head_scan_id": scans[-1]["id"]})
    assert d.status_code == 200, d.text
    assert d.json()["delta"]["resolved"] >= 3 and d.json()["delta"]["introduced"] == 0


def test_11_import_other_scanner_and_exports(world):
    c = world["c"]
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "js/xss", "properties": {"security-severity": "7.5"}}]}},
             "results": [{"ruleId": "js/xss", "message": {"text": "DOM XSS from location.hash"},
                          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/server.js"}, "region": {"startLine": 7}}}]}]}]}
    r = c.post("/api/v1/scans/import", headers=H, json={"repo": REPO, "commit": "2222222bbb", "filename": "codeql.sarif",
                                                         "content_base64": base64.b64encode(json.dumps(sarif).encode()).decode()})
    assert r.status_code == 200 and r.json()["format"] == "sarif" and r.json()["new"] == 1
    csv = c.get("/api/v1/findings/export", headers=H, params={"repo": REPO}).content.decode("utf-8-sig")
    assert "js/xss" in csv and "https://nvd.nist.gov/vuln/detail/" in csv
    audit = c.get("/api/v1/audit/export", headers=H, params={"format": "jsonl"}).text
    assert '"campaign.plan"' in audit or "campaign.plan" in audit
    assert "ai.explain" in audit and "scan.imported" in audit


def test_12_licence_policy_and_assessment(world):
    c = world["c"]
    lic = c.get("/api/v1/licenses/report", headers=H, params={"repo": REPO})
    assert lic.status_code == 200, lic.text
    decisions = {x["package"]: x["decision"] for x in lic.json()["items"]}
    assert decisions.get("mysql-connector-python") in ("review", "deny")
    fid = c.get("/api/findings", headers=H, params={"repo": REPO, "engine": "aibom"}).json()["items"][0]["id"]
    a = c.patch(f"/api/findings/{fid}/assessment", headers=H,
               json={"assessment": "exploitable", "owner": "ml-platform", "business_impact": "customer chat", "rationale": "reachable from public chat"})
    assert a.status_code == 200, a.text
    assert c.get(f"/api/findings/{fid}", headers=H).json()["assessment"]["owner"] == "ml-platform"


def test_13_supply_chain_defence_and_ssvc(world):
    c = world["c"]
    d = c.get("/api/v1/supply-chain/defence", headers=H).json()
    mine = [f for f in d["typosquats"] if f["repo"] == REPO]
    assert any(f["package"] == "expresss" and f["lookalike_of"] == "express" for f in mine)
    assert d["counts"]["secret_exposure_in_ci"] >= 2 and any(r["repo"] == REPO for r in d["repos"])
    items = c.get("/api/findings", headers=H, params={"repo": REPO, "limit": 1000}).json()["items"]
    assert all(f["ssvc"]["decision"] in ("Act", "Attend", "Track*", "Track") for f in items)
    log4j = next(f for f in items if f.get("cve") == "CVE-2021-44228")
    assert log4j["ssvc"]["exploitation"] == "active" and log4j["ssvc"]["decision"] in ("Act", "Attend")
    acts = c.get("/api/findings", headers=H, params={"repo": REPO, "ssvc": "Act", "limit": 1000}).json()["items"]
    assert acts and all(f["ssvc"]["decision"] == "Act" for f in acts)
    one = c.get(f"/api/findings/{log4j['id']}", headers=H).json()
    assert "OWASP A05:2025" in one["frameworks"] and one["ssvc"]["decision"] == log4j["ssvc"]["decision"]
    a = c.post("/api/v1/ai/ask", headers=H, json={"question": f"supply chain findings in {REPO}"}).json()
    assert a["count"] >= 5 and all(f["engine"] == "supply" for f in a["findings"])


def test_14_repository_posture_and_osps(world):
    c = world["c"]
    p = c.get(f"/api/v1/posture/{REPO}", headers=H).json()
    checks = {x["id"]: x for x in p["checks"]}
    assert len(checks) == 19 and 0 <= p["score"] <= 10 and p["grade"] in "ABCDE"
    assert checks["ai-agent-guardrails"]["status"] == "fail" and checks["dangerous-workflow"]["status"] == "fail"
    assert checks["binary-artifacts"]["status"] == "pass"
    st = {x["id"]: x["status"] for x in p["osps"]["controls"]}
    assert st["OSPS-AC-01.01"] == "attestation" and st["OSPS-BR-07.01"] in ("met", "not_met")
    ov = c.get("/api/v1/posture", headers=H).json()
    assert any(r["repo"] == REPO for r in ov["repos"]) and ov["average"] is not None
    sb = c.get(f"/api/sbom/{REPO}", headers=H).json()             # internal extension data never leaks into the SBOM export
    assert not [x for x in sb["metadata"]["properties"] if x["name"] in ("myelin:posture-detail", "myelin:crypto")]


def test_15_cryptography_inventory_and_pqc(world):
    c = world["c"]
    cb = c.get(f"/api/v1/cbom/{REPO}", headers=H)
    assert cb.status_code == 200 and cb.json()["specVersion"] == "1.6"
    names = {x["name"]: x for x in cb.json()["components"]}
    assert {"RSA", "ECDSA/ECDH", "AES-ECB", "SHA-2"} <= set(names), set(names)
    assert names["RSA"]["type"] == "cryptographic-asset" and names["RSA"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    q = c.get("/api/v1/pqc", headers=H).json()
    mine = next(r for r in q["repos"] if r["repo"] == REPO)
    assert mine["by_class"]["broken"] >= 2 and mine["by_class"]["quantum-vulnerable"] >= 2 and mine["status"] == "action"


def test_16_eu_cra_tracker(world):
    c = world["c"]
    d = c.get("/api/v1/cra", headers=H).json()
    mine = [x for x in d["reportable"] if x["repo"] == REPO]
    assert mine and all(x["kev"] or x["malicious"] for x in mine)
    st = {s["stage"]: s for s in mine[0]["stages"]}
    assert set(st) == {"early_warning", "notification", "final_report"}
    r = c.post(f"/api/v1/cra/{mine[0]['id']}", headers=H, json={"stage": "early_warning", "reference": "ENISA-SRP-TEST-1"})
    assert r.status_code == 200, r.text
    again = next(x for x in c.get("/api/v1/cra", headers=H).json()["reportable"] if x["id"] == mine[0]["id"])
    ew = next(s for s in again["stages"] if s["stage"] == "early_warning")
    assert ew["status"] == "submitted" and ew["submitted"]["reference"] == "ENISA-SRP-TEST-1"
    assert c.post(f"/api/v1/cra/{mine[0]['id']}", headers=H, json={"stage": "bogus"}).status_code == 422
    prod = next(p for p in d["products"] if p["repo"] == REPO)
    assert prod["checks"]["sbom"] is True and prod["checks"]["no_known_exploited"] is False
    k = c.get("/api/summary", headers=H).json()["kpis"]
    assert k["cra_reportable"] >= 1 and k["supply_chain_open"] >= 5 and set(k["ssvc"]) == {"Act", "Attend", "Track*", "Track"}
