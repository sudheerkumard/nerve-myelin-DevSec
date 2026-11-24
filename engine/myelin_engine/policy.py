# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Policy-as-code gate evaluation.

The same policy file drives PR checks, pipeline gates, deploy-time admission and reporting.
Native evaluator below; the identical logic ships as OPA/Rego in /policies/rego for customers
who standardise on OPA/Conftest.
"""
from datetime import date

import yaml

from .scoring import SEV_ORDER

ACTION_RANK = {"pass": 0, "warn": 1, "block": 2}

DEFAULT_POLICY = {
    "name": "myelin-default", "version": 1, "mode": "enforce",
    "gates": [
        {"id": "block-required-scanner-failure", "description": "A required security scanner did not produce a valid result",
         "when": {"scanner_status": ["required_error"]}, "action": "block"},
        {"id": "block-known-exploited", "description": "CISA KEV vulnerability present", "when": {"kev": True}, "action": "block"},
        {"id": "block-critical-reachable", "description": "Critical, reachable vulnerability",
         "when": {"severity": ["critical"], "reachable": True}, "action": "block"},
        {"id": "block-secrets", "description": "Live credential committed", "when": {"engine": ["secrets"], "severity": ["critical", "high"]}, "action": "block"},
        {"id": "block-ppe", "description": "Poisoned pipeline execution path", "when": {"rule_id": ["NM-CICD-002", "NM-CICD-003"]}, "action": "block"},
        {"id": "block-unsigned", "description": "Artifacts not signed / no provenance", "when": {"rule_id": ["NM-CICD-009"]}, "action": "warn"},
        {"id": "block-mrs-80", "description": "NERvvE Risk Score >= 80 (P0)", "when": {"mrs_gte": 80}, "action": "block"},
        {"id": "warn-high", "description": "High severity findings", "when": {"severity": ["high"]}, "action": "warn"},
        {"id": "block-copyleft", "description": "Strong copyleft licence requires legal approval", "when": {"rule_id": ["NM-LIC-001"]}, "action": "block"},
    ],
    "exceptions": [],
}


def load(path: str | None) -> dict:
    if not path:
        return DEFAULT_POLICY
    with open(path) as fh:
        return yaml.safe_load(fh)


def _matches(f: dict, when: dict) -> bool:
    for k, v in when.items():
        if k == "mrs_gte":
            if (f.get("mrs") or 0) < v:
                return False
        elif k == "min_severity":
            if SEV_ORDER.get(f.get("severity"), 0) < SEV_ORDER[v]:
                return False
        elif isinstance(v, list):
            if f.get(k) not in v:
                return False
        elif f.get(k) != v:
            return False
    return True


def _excepted(f: dict, exceptions: list) -> dict | None:
    today = date.today().isoformat()
    for ex in exceptions or []:
        if ex.get("expires") and str(ex["expires"]) < today:
            continue
        # A broad finding exception must never turn a failed required scanner into a pass.
        # Explicit scanner-failure acceptance needs a separately declared opt-in.
        if f.get("scanner_status") == "required_error" and ex.get("allow_scanner_failure") is not True:
            continue
        if all(f.get(k) == v for k, v in (ex.get("match") or {}).items()):
            return ex
    return None


def evaluate(findings: list[dict], policy: dict | None = None) -> dict:
    """Evaluate every matching gate; the strongest applicable action determines the decision.

    A finding can match more than one gate. A warning earlier in a customer policy must
    never mask a later blocking rule. Valid exceptions suppress matching gate outcomes,
    but remain visible in the returned exception audit list.
    """
    policy = policy or DEFAULT_POLICY
    violations, excepted = [], []
    for f in findings:
        if f.get("status") in ("fixed", "suppressed", "risk_accepted", "false_positive"):
            continue
        ex = _excepted(f, policy.get("exceptions"))
        matched = False
        for g in policy.get("gates", []):
            if not _matches(f, g.get("when", {})):
                continue
            matched = True  # noqa: F841
            rec = {"gate": g["id"], "action": g["action"], "finding": f.get("id"), "title": f.get("title"),
                   "severity": f.get("severity"), "mrs": f.get("mrs"), "file": f.get("file")}
            if ex:
                excepted.append({**rec, "exception": ex.get("id")})
            else:
                violations.append(rec)
        # Findings with no matching policy gate are intentionally not violations.
    blocks = [v for v in violations if v["action"] == "block"]
    warns = [v for v in violations if v["action"] == "warn"]
    observed_decision = "block" if blocks else "warn" if warns else "pass"
    mode = policy.get("mode", "enforce")
    if mode not in {"audit", "warn", "enforce"}:
        raise ValueError("policy mode must be audit, warn or enforce")
    # Audit mode records the full decision without affecting the gate. Warn mode
    # surfaces every violation but downgrades a would-block result to a warning.
    decision = observed_decision if mode == "enforce" else ("warn" if observed_decision != "pass" else "pass") if mode == "warn" else "pass"
    return {"policy": policy.get("name"), "mode": mode, "decision": decision,
            "observed_decision": observed_decision, "would_block": bool(blocks),
            "blocking": len(blocks), "warnings": len(warns),
            "excepted": len(excepted), "violations": violations[:500], "exceptions_applied": excepted[:500]}
