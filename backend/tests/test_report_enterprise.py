# Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only.
"""Corporate report and framework mapping."""
import json
from pathlib import Path

from myelin_engine import frameworks as FW
from myelin_engine import orchestrator, report_enterprise as R

CORPUS = Path(__file__).resolve().parents[2] / "engine" / "tests" / "benchmark" / "corpus"


def test_framework_tags_are_specific():
    sqli = {"engine": "sast", "cwe": "CWE-89", "severity": "critical"}
    t = FW.tags(sqli)
    assert t["owasp"] == ["A05:2025"] and t["cwe25"] == ["CWE-89"] and "6.2.4" in t["pci"] and "8.28" in t["iso"]
    sec = FW.tags({"engine": "secrets", "cwe": "CWE-798"})
    assert sec["owasp"] == ["A07:2025"] and "8.6.2" in sec["pci"] and "IA-5" in sec["nist"]
    sca = FW.tags({"engine": "sca", "cve": "CVE-2020-14343", "cwe": "CWE-20"})
    assert "6.3.3" in sca["pci"] and "RA-5" in sca["nist"]
    cd = FW.tags({"engine": "cicd", "rule_id": "NM-CD-008", "owasp_cicd": "CICD-SEC-1: Insufficient Flow Control"})
    assert cd["cicd"] == ["CICD-SEC-1"] and "6.5.1" in cd["pci"] and "8.32" in cd["iso"]
    api = FW.tags({"engine": "dast", "owasp_api": "API1:2023 Broken Object Level Authorization", "cwe": "CWE-639"})
    assert api["api"] == ["API1:2023"] and api["owasp"] == ["A01:2025"]


def test_matrix_statuses():
    fs = [{"engine": "sast", "cwe": "CWE-89", "severity": "critical"}, {"engine": "iac", "severity": "low", "file": "Dockerfile"}]
    m = {x["id"]: x for x in FW.matrix(fs, ["sast", "iac", "sca"])}
    owasp = {c["id"]: c["status"] for c in m["owasp"]["controls"]}
    assert owasp["A05:2025"] == "gap" and owasp["A02:2025"] == "observation" and owasp["A03:2025"] == "clear"
    pci = {c["id"]: c["status"] for c in m["pci"]["controls"]}
    assert pci["6.2.4"] == "gap" and pci["8.6.2"] == "not_tested" and pci["6.3.2"] == "clear"
    assert "api" not in m  # a framework nobody tested is left out entirely
    cra = {c["id"]: c["status"] for c in m["cra"]["controls"]}
    assert cra["I.2(a)"] == "gap" and cra["II.1"] == "clear" and cra["II.3"] == "clear"


def test_agentic_and_supply_chain_tags():
    t = FW.tags({"engine": "aibom", "rule_id": "NM-AI-031", "owasp_llm": "LLM01", "owasp_agentic": "ASI01", "cwe": "CWE-1427"})
    assert t["agentic"] == ["ASI01:2026"] and t["llm"] == ["LLM01:2025"] and t["owasp"] == ["A05:2025"]
    s = FW.tags({"engine": "supply", "rule_id": "NM-SUP-001", "cwe": "CWE-506"})
    assert s["owasp"] == ["A03:2025"] and "I.2(a)" in s["cra"] and "SR-3" in s["nist"]
    assert "OWASP Agentic ASI01:2026" in FW.short({"engine": "aibom", "owasp_agentic": "ASI01"})


def test_code_report_editions(monkeypatch):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    res = orchestrator.scan(str(CORPUS), repo="payments-api")
    res.update(commit="4c1e9a7b2d3f", branch="main", engines=["sca", "license", "sast", "secrets", "iac", "cicd", "aibom"])
    internal = R.render(res, issuer="Globex", prepared_for="Initech Bank", source_url="https://github.com/globex/payments-api")
    external = R.render(res, issuer="Globex", prepared_for="Initech Bank", source_url="https://github.com/globex/payments-api",
                        audience="external")
    for h in (internal, external):
        for s in ("Overall risk rating", "Document control", "Framework &amp; compliance alignment", "OWASP Top 10", "CWE Top 25",
                  "PCI DSS", "ISO/IEC 27001:2022", "NIST SSDF", "NIST SP 800-53", "SOC 2", "Remediation roadmap",
                  "Software bill of materials", "Attestation", "Initech Bank", "CVE-2020-14343"):
            assert s in h, s
    assert "<b>Evidence</b>" in internal and "<b>Evidence</b>" not in external
    assert "withheld in the external edition" in external
    secrets = [f for f in res["findings"] if f["engine"] == "secrets"]
    assert external.count("withheld in the external edition") >= len(secrets)       # every secret location is withheld
    assert not any(f'{f["file"]}:{f["line"]}' in external for f in secrets)


def test_dast_report():
    res = {"target": "https://api.example.com", "duration_s": 4.2, "requests": 61, "spec_operations": 12, "identities": ["alice", "bob"],
           "mode": "safe", "findings": [
               {"engine": "dast", "rule_id": "NM-DAST-020", "title": "bob can read alice's object via /orders/{id}", "severity": "critical",
                "file": "GET /orders/{id}", "owasp_api": "API1:2023 Broken Object Level Authorization", "cwe": "CWE-639",
                "evidence": "GET /orders/17 as bob → 200", "remediation": "Check object ownership.", "mrs": 90, "priority": "P0"}]}
    h = R.render(json.loads(json.dumps(res)), issuer="Globex", kind="dast")
    assert "OWASP API Security Top 10" in h and "API1:2023" in h and 'id="sbom"' not in h
    assert "Live application" in h and "61 requests" in h


def test_dast_report_only_claims_recorded_checks_and_marks_partial_zap():
    res = {"target": "https://api.example.com", "requests": 5, "tools": ["myelin-dast", "zap"],
           "stats": {"zap": {"complete": False, "urls": 3, "mode": "passive"}}, "findings": []}
    html = R.render(res, kind="dast")
    assert "ZAP did not complete" in html and "Undetermined" in html
    assert "Multi-user checks with the configured test identities" not in html
    assert "API specification</th>" not in html and "Testing ran only after" not in html
    assert "✓ No open findings" not in html
