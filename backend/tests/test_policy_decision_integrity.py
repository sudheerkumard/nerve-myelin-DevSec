# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Regression tests for deterministic, non-order-dependent policy decisions."""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import cli, policy


def test_later_blocking_gate_cannot_be_masked_by_earlier_warning():
    finding = {"id": "F-1", "severity": "critical", "reachable": True, "status": "open"}
    p = {"name": "customer-policy", "gates": [
        {"id": "warn-everything", "when": {"severity": ["critical"]}, "action": "warn"},
        {"id": "block-reachable-critical", "when": {"severity": ["critical"], "reachable": True}, "action": "block"},
    ]}
    result = policy.evaluate([finding], p)
    assert result["decision"] == "block"
    assert result["blocking"] == 1
    assert result["warnings"] == 1
    assert {v["gate"] for v in result["violations"]} == {"warn-everything", "block-reachable-critical"}


def test_gate_order_does_not_change_policy_decision():
    finding = {"id": "F-2", "severity": "high", "status": "open"}
    gates = [
        {"id": "warn-high", "when": {"severity": ["high"]}, "action": "warn"},
        {"id": "block-high", "when": {"severity": ["high"]}, "action": "block"},
    ]
    forward = policy.evaluate([finding], {"name": "p", "gates": gates})
    reverse = policy.evaluate([finding], {"name": "p", "gates": list(reversed(gates))})
    assert forward["decision"] == reverse["decision"] == "block"
    assert forward["blocking"] == reverse["blocking"] == 1
    assert forward["warnings"] == reverse["warnings"] == 1


def test_exception_applies_to_all_matching_gates_and_is_auditable():
    finding = {"id": "F-3", "severity": "critical", "reachable": True, "status": "open", "repo": "payments"}
    p = {"name": "p", "gates": [
        {"id": "warn-critical", "when": {"severity": ["critical"]}, "action": "warn"},
        {"id": "block-reachable", "when": {"reachable": True}, "action": "block"},
    ], "exceptions": [{"id": "EX-9", "match": {"repo": "payments"}, "reason": "approved"}]}
    result = policy.evaluate([finding], p)
    assert result["decision"] == "pass"
    assert result["excepted"] == 2
    assert {v["gate"] for v in result["exceptions_applied"]} == {"warn-critical", "block-reachable"}
    assert all(v["exception"] == "EX-9" for v in result["exceptions_applied"])


def test_expired_exception_does_not_suppress_blocking_gate():
    finding = {"id": "F-4", "severity": "critical", "status": "open", "repo": "payments"}
    p = {"name": "p", "gates": [
        {"id": "block-critical", "when": {"severity": ["critical"]}, "action": "block"},
    ], "exceptions": [{"id": "EX-OLD", "match": {"repo": "payments"}, "expires": "2000-01-01"}]}
    result = policy.evaluate([finding], p)
    assert result["decision"] == "block"
    assert result["excepted"] == 0


def test_closed_findings_are_not_evaluated():
    findings = [{"id": "F-5", "severity": "critical", "status": "fixed"}]
    result = policy.evaluate(findings, {"name": "p", "gates": [
        {"id": "block-critical", "when": {"severity": ["critical"]}, "action": "block"}]})
    assert result["decision"] == "pass"
    assert result["violations"] == []

def test_generic_exception_cannot_suppress_required_scanner_failure():
    finding = {"id": "tool-error:trivy", "repo": "payments", "scanner_status": "required_error",
               "severity": "high", "status": "open"}
    result = policy.evaluate([finding], {"name": "p",
        "gates": [{"id": "scanner-failed", "when": {"scanner_status": ["required_error"]}, "action": "block"}],
        "exceptions": [{"id": "EX-ALL", "match": {"repo": "payments"}, "reason": "temporary waiver"}]})
    assert result["decision"] == "block"
    assert result["excepted"] == 0


def test_scanner_failure_exception_requires_explicit_opt_in():
    finding = {"id": "tool-error:trivy", "repo": "payments", "scanner_status": "required_error",
               "severity": "high", "status": "open"}
    result = policy.evaluate([finding], {"name": "p",
        "gates": [{"id": "scanner-failed", "when": {"scanner_status": ["required_error"]}, "action": "block"}],
        "exceptions": [{"id": "EX-SCAN", "match": {"scanner_status": "required_error", "repo": "payments"},
                        "allow_scanner_failure": True, "reason": "approved alternate control"}]})
    assert result["decision"] == "pass"
    assert result["excepted"] == 1


def test_weak_copyleft_license_is_visible_but_does_not_block():
    finding = {"id": "F-LGPL", "engine": "license", "rule_id": "NM-LIC-002",
               "license": "LGPL-3.0-only", "severity": "info", "status": "open"}
    result = policy.evaluate([finding], policy.DEFAULT_POLICY)
    assert result["decision"] == "pass"
    assert result["blocking"] == 0


def test_strong_copyleft_license_remains_blocking():
    finding = {"id": "F-GPL", "engine": "license", "rule_id": "NM-LIC-001",
               "license": "GPL-3.0-only", "severity": "high", "status": "open"}
    result = policy.evaluate([finding], policy.DEFAULT_POLICY)
    assert result["decision"] == "block"
    assert result["blocking"] == 1


def test_suppressed_findings_export_as_accepted_sarif_suppressions():
    sarif = cli.to_sarif([{
        "id": "F-SUPPRESSED", "engine": "sast", "rule_id": "NM-SAST-009",
        "title": "JWT verification routing heuristic", "severity": "critical",
        "priority": "P1", "mrs": 70.5, "fingerprint": "abc123",
        "status": "suppressed",
        "suppression": {"type": "inline", "reason": "issuer routing only"},
    }])
    finding = sarif["runs"][0]["results"][0]
    assert finding["suppressions"] == [{
        "kind": "inSource", "status": "accepted", "justification": "issuer routing only"
    }]


def test_open_sarif_findings_do_not_receive_suppression_metadata():
    sarif = cli.to_sarif([{
        "id": "F-OPEN", "engine": "sast", "rule_id": "NM-SAST-009",
        "title": "JWT verification disabled", "severity": "critical",
        "priority": "P1", "mrs": 90.0, "fingerprint": "def456",
        "status": "open",
    }])
    finding = sarif["runs"][0]["results"][0]
    assert "suppressions" not in finding


def test_audit_mode_records_violations_without_blocking_gate():
    finding = {"id": "F-AUDIT", "severity": "critical", "reachable": True, "status": "open"}
    result = policy.evaluate([finding], {"name": "audit-policy", "mode": "audit", "gates": [
        {"id": "block-critical", "when": {"severity": ["critical"]}, "action": "block"}]})
    assert result["mode"] == "audit"
    assert result["decision"] == "pass"
    assert result["observed_decision"] == "block"
    assert result["would_block"] is True
    assert result["blocking"] == 1
    assert len(result["violations"]) == 1


def test_warn_mode_downgrades_block_but_preserves_decision_evidence():
    finding = {"id": "F-WARN", "severity": "critical", "status": "open"}
    result = policy.evaluate([finding], {"name": "warn-policy", "mode": "warn", "gates": [
        {"id": "block-critical", "when": {"severity": ["critical"]}, "action": "block"}]})
    assert result["mode"] == "warn"
    assert result["decision"] == "warn"
    assert result["observed_decision"] == "block"
    assert result["would_block"] is True


def test_enforce_mode_preserves_blocking_decision():
    finding = {"id": "F-ENFORCE", "severity": "critical", "status": "open"}
    result = policy.evaluate([finding], {"name": "enforce-policy", "mode": "enforce", "gates": [
        {"id": "block-critical", "when": {"severity": ["critical"]}, "action": "block"}]})
    assert result["decision"] == "block"
    assert result["observed_decision"] == "block"


def test_invalid_policy_mode_is_rejected():
    try:
        policy.evaluate([], {"name": "invalid", "mode": "silent", "gates": []})
    except ValueError as exc:
        assert "policy mode" in str(exc)
    else:
        raise AssertionError("invalid mode should be rejected")
