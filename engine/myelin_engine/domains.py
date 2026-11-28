# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Security domain of every finding, and the testing-type x domain coverage matrix shown in reports.

Domains: application, network, data, compute, identity, logging, supply chain. A rule that states its domain keeps
it; other findings are placed by engine, rule family, CWE and (for external tools) the words of the check title.
"""
from __future__ import annotations

import re

DOMAINS = [
    ("application", "Application security"), ("network", "Network security"), ("data", "Data security"),
    ("compute", "Compute and workload security"), ("identity", "Identity and access"),
    ("logging", "Logging and monitoring"), ("supply_chain", "Software supply chain"),
]
LABEL = dict(DOMAINS)
TESTS = [("sast", "SAST"), ("sca", "SCA"), ("secrets", "Secrets"), ("iac", "IaC and configuration"), ("container", "Container image"),
         ("dast", "DAST"), ("supply", "Supply chain and CI/CD"), ("cloud", "Cloud and Kubernetes posture")]
TEST_OF_ENGINE = {"sast": "sast", "aibom": "sast", "sca": "sca", "license": "supply", "secrets": "secrets", "iac": "iac",
                  "container": "container", "dast": "dast", "supply": "supply", "cicd": "supply", "cspm": "cloud", "kspm": "cloud",
                  "ciem": "cloud", "runtime": "cloud"}

IDENTITY_CWE = {"CWE-287", "CWE-306", "CWE-347", "CWE-798", "CWE-521", "CWE-522", "CWE-259", "CWE-258", "CWE-613", "CWE-384",
                "CWE-639", "CWE-285", "CWE-862", "CWE-863", "CWE-269", "CWE-250", "CWE-266", "CWE-915"}
DATA_CWE = {"CWE-311", "CWE-312", "CWE-313", "CWE-319", "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-295",
            "CWE-916", "CWE-200", "CWE-209", "CWE-532", "CWE-538", "CWE-530", "CWE-359", "CWE-614", "CWE-1004", "CWE-732"}
NETWORK_CWE = {"CWE-918", "CWE-942", "CWE-601", "CWE-644", "CWE-346", "CWE-345", "CWE-1021"}
LOGGING_CWE = {"CWE-778", "CWE-117", "CWE-223"}
CLOUD_CATEGORY = {"exposure": "network", "data": "data", "encryption": "data", "identity": "identity", "rbac": "identity",
                  "logging": "logging", "runtime": "logging", "workload": "compute", "kubernetes": "compute", "path": "network"}
WORDS = [("identity", r"\b(iam|role|polic|permission|privilege|admin|rbac|abac|mfa|password|credential|authenticat|authoriz|service account|access key)"),
         ("network", r"\b(ingress|egress|port|security group|nsg|firewall|public ip|internet|0\.0\.0\.0|vpc|subnet|endpoint|cors|waf|load balancer|listener|http\b)"),
         ("logging", r"\b(log|logging|trail|audit|monitor|alert|flow log|guardduty|defender|threat detection)"),
         ("data", r"\b(encrypt|kms|cmk|tls|ssl|https|backup|versioning|public access|bucket|retention|secret|key rotation|snapshot|replication)"),
         ("compute", r"\b(container|privileged|root|capabilit|seccomp|apparmor|imds|metadata|host|image|kernel|vm\b|instance|pod|node)")]


def domain_of(f: dict) -> str:
    if f.get("domain") in LABEL:
        return f["domain"]
    eng, rid, cwe = f.get("engine"), str(f.get("rule_id") or ""), str(f.get("cwe") or "")
    cat = str(f.get("category") or "")
    if eng in ("cspm", "kspm", "ciem", "runtime"):
        return CLOUD_CATEGORY.get(cat, "compute")
    if eng in ("supply", "cicd", "license") or rid.startswith(("NM-LIC", "NM-SUP", "NM-CICD", "NM-CD-")):
        return "supply_chain"
    if eng == "secrets":
        return "identity"
    if eng in ("sca", "container"):
        if rid.startswith(("NM-OS", "NM-BIN", "NM-DRV", "NM-FW", "NM-CTR", "NM-K8S")) or cat in ("os-package", "binary", "firmware", "driver"):
            return "compute"
        if f.get("malicious"):
            return "supply_chain"
        if cat == "eol":
            return "compute" if f.get("dependency_type") not in ("library",) and "library" not in str(f.get("evidence", "")) else "application"
        return "application"
    if eng == "dast":
        if rid in ("NM-DAST-001", "NM-DAST-002", "NM-DAST-003", "NM-DAST-013", "NM-DAST-014", "NM-DAST-005", "NM-DAST-043"):
            return "network"
        if rid in ("NM-DAST-010", "NM-DAST-013", "NM-DAST-020", "NM-DAST-021", "NM-DAST-023"):
            return "identity"
        if rid in ("NM-DAST-022", "NM-DAST-040", "NM-DAST-011"):
            return "data"
        return "application"
    if eng in ("sast", "aibom"):
        if cwe in IDENTITY_CWE:
            return "identity"
        if cwe in DATA_CWE:
            return "data"
        if cwe in LOGGING_CWE:
            return "logging"
        return "application"
    if eng == "iac":
        text = (f.get("title") or "").lower()
        for d, rx in WORDS:
            if re.search(rx, text):
                return d
        return "compute"
    return "application"


def assign(findings: list[dict]) -> None:
    for f in findings:
        f["domain"] = domain_of(f)


def matrix(findings: list[dict], engines_run: list[str]) -> dict:
    """{'rows': [(domain, label, {test: count})], 'tests': [(test, label, assessed)]} for open findings."""
    run_tests = {TEST_OF_ENGINE.get(e, e) for e in engines_run}
    counts = {d: {t: 0 for t, _ in TESTS} for d, _ in DOMAINS}
    for f in findings:
        if f.get("status", "open") in ("suppressed", "fixed", "risk_accepted", "accepted", "false_positive"):
            continue
        t = TEST_OF_ENGINE.get(f.get("engine"), None)
        d = f.get("domain") or domain_of(f)
        if t and d in counts:
            counts[d][t] += 1
            run_tests.add(t)
    return {"rows": [(d, LABEL[d], counts[d]) for d, _ in DOMAINS], "tests": [(t, lab, t in run_tests) for t, lab in TESTS]}
