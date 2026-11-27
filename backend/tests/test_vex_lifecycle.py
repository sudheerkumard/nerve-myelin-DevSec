# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Exact-component VEX/CSAF ingestion and fail-closed lifecycle regression tests."""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import policy, vex


PURL = "pkg:pypi/urllib3@1.26.4"


def test_cyclonedx_vex_not_affected_requires_exact_purl_and_keeps_audit_detail():
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:test",
        "metadata": {"timestamp": "2026-11-19T10:00:00Z", "supplier": {"name": "RAT Flea"}},
        "components": [{"bom-ref": "component-1", "purl": PURL}],
        "vulnerabilities": [{"id": "CVE-2021-33503",
            "analysis": {"state": "not_affected", "justification": "code_not_reachable", "detail": "Validated by call-path review"},
            "affects": [{"ref": "component-1"}]}],
    }
    findings = [
        {"id": "F1", "engine": "sca", "cve": "CVE-2021-33503", "purl": PURL, "severity": "high"},
        {"id": "F2", "engine": "sca", "cve": "CVE-2021-33503", "purl": "pkg:pypi/urllib3@1.25.0", "severity": "high"},
    ]
    summary = vex.apply(findings, [doc])
    assert findings[0]["status"] == "not_affected"
    assert findings[0]["vex"]["justification"] == "code_not_reachable"
    assert findings[0]["vex"]["source_digest"].startswith("sha256:")
    assert findings[1].get("status", "open") == "open"
    assert summary["applied"] == 1 and summary["not_affected"] == 1


def test_under_investigation_does_not_suppress_policy_gate():
    doc = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "c", "purl": PURL}],
           "vulnerabilities": [{"id": "CVE-2021-33503", "analysis": {"state": "under_investigation"},
                                "affects": [{"ref": "c"}]}]}
    findings = [{"id": "F", "cve": "CVE-2021-33503", "purl": PURL, "severity": "critical", "reachable": True}]
    vex.apply(findings, [doc])
    result = policy.evaluate(findings, {"name": "p", "gates": [
        {"id": "critical-reachable", "when": {"severity": ["critical"], "reachable": True}, "action": "block"}]})
    assert findings[0].get("status", "open") == "open"
    assert result["decision"] == "block"


def test_conflicting_vex_statements_are_ambiguous_and_not_suppressed():
    def doc(state):
        return {"bomFormat": "CycloneDX", "components": [{"bom-ref": "c", "purl": PURL}],
                "vulnerabilities": [{"id": "CVE-2021-33503", "analysis": {"state": state}, "affects": [{"ref": "c"}]}]}
    findings = [{"id": "F", "cve": "CVE-2021-33503", "purl": PURL, "severity": "critical"}]
    summary = vex.apply(findings, [doc("not_affected"), doc("affected")])
    assert findings[0]["vex"]["state"] == "ambiguous"
    assert findings[0].get("status", "open") == "open"
    assert summary["ambiguous"] == 1


def test_csaf_product_mapping_uses_explicit_purl():
    doc = {"csaf_version": "2.0", "document": {"category": "csaf_vex",
        "tracking": {"id": "ADV-1", "current_release_date": "2026-11-19T10:00:00Z"},
        "publisher": {"name": "Vendor"}},
        "product_tree": {"branches": [{"name": "Library", "category": "product_name", "branches": [
            {"name": "urllib3", "category": "product_version", "product": {"product_id": "P1",
             "product_identification_helper": {"purl": PURL}}}]}]},
        "vulnerabilities": [{"cve": "CVE-2021-33503", "product_status": {"known_not_affected": ["P1"]}}]}
    findings = [{"id": "F", "cve": "CVE-2021-33503", "purl": PURL, "severity": "high"}]
    summary = vex.apply(findings, [doc])
    assert findings[0]["status"] == "not_affected"
    assert findings[0]["vex"]["source"] == "csaf-2.0"
    assert findings[0]["vex"]["source_digest"].startswith("sha256:")
    assert summary["applied"] == 1


def test_unknown_or_unmapped_vex_is_not_applied():
    findings = [{"id": "F", "cve": "CVE-2021-33503", "package": "urllib3", "severity": "high"}]
    doc = {"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "CVE-2021-33503",
        "analysis": {"state": "not_affected"}, "affects": [{"ref": "missing"}]}]}
    summary = vex.apply(findings, [doc])
    assert findings[0].get("status", "open") == "open"
    assert summary["applied"] == 0


def test_unsupported_document_format_fails_closed():
    try:
        vex.normalize_document({"format": "unknown"})
    except ValueError as exc:
        assert "Unsupported VEX format" in str(exc)
    else:
        raise AssertionError("unsupported VEX format was accepted")
