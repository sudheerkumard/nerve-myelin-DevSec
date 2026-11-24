# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Subscription plans + entitlement gating (single source of truth for API, console and billing)."""

FEATURES = {
    "sca": "Open-source dependency scanning (SCA) + reachability",
    "secrets": "Secrets detection (code, configuration, pipelines) + opt-in live provider validation",
    "sbom": "SBOM generation & import (CycloneDX / SPDX) + VEX",
    "license": "Licence compliance & policy",
    "sast": "Static code analysis (SAST): Python, JavaScript/TypeScript, Java/Kotlin, Go, C#, PHP, Ruby; more through SARIF import",
    "iac": "Infrastructure-as-Code scanning (Terraform, Bicep, ARM, K8s, Helm, Dockerfile)",
    "container": "Container image scanning (Trivy / Grype)",
    "cicd": "Pipeline Posture Management — OWASP Top-10 CI/CD",
    "autofix": "AutoFix: fixes computed from your files, pull requests on GitHub, GitLab and Azure DevOps",
    "ai_remediation": "AI assistant: explain & fix, triage suggestions, plain-language questions, executive briefing",
    "provenance": "SLSA provenance and Sigstore signing",
    "admission": "Kubernetes admission policy (Kyverno) and admission-decision reporting",
    "dast": "DAST & API security testing",
    "aibom": "AI application & coding-agent security: models, prompts, agents, MCP and agent rule files",
    "supply_chain": "Supply-chain defence: malicious & look-alike packages, worms, dependency confusion, CI token theft",
    "posture": "Repository posture scoring mapped to the OpenSSF OSPS Baseline",
    "pqc": "Cryptography inventory (CycloneDX CBOM) & post-quantum readiness",
    "cra": "EU Cyber Resilience Act readiness: Article 14 reporting clocks & Annex I evidence",
    "developer_tools": "Developer tools: git pre-commit hook and MCP server for AI coding assistants",
    "cspm": "Cloud security posture (Azure, AWS, Google Cloud): live read-only collection or inventory import, code-to-cloud links",
    "kspm": "Kubernetes security posture: Pod Security Standards, RBAC, exposure and network isolation",
    "ciem": "Cloud identity & entitlement analysis: admin and escalation rights, MFA, key age, dormant, external and public access",
    "cwpp": "Runtime workload protection: Falco and Tetragon detections with MITRE ATT&CK mapping and code-to-runtime links",
    "attack_paths": "Attack paths across code, cloud, identity and runtime (internet exposure → weakness → privilege or data)",
    "policy_as_code": "Custom policy-as-code (YAML / OPA Rego) & exceptions workflow",
    "compliance": "Compliance packs (SOC 2, ISO 27001, PCI DSS 4.0, NIST SSDF, EU CRA, DORA, RBI/SEBI)",
    "sso": "Single sign-on (OIDC; SAML identity providers through Keycloak) with MFA",
    "rbac_custom": "Role-based access (seven roles, separation of duties) & business-unit views",
    "audit_export": "Hash-chained audit log & SIEM export API (Sentinel, Splunk, Wazuh, Elastic)",
    "self_hosted": "Self-hosted / air-gapped deployment",
    "sovereign": "Sovereign / in-country deployment with keys held in your own vault",
    "dedicated_csm": "Named customer success contact and priority support",
}

PLANS = [
    {"id": "community", "name": "Community", "tagline": "For open-source and individual developers",
     "price_monthly_per_dev": None, "price_annual_per_dev": None, "min_devs": 1, "max_devs": 5, "min_annual": None,
     "limits": {"repos": 10, "scans_per_month": 500, "retention_days": 30, "api_rpm": 60},
     "features": ["sca", "secrets", "sbom", "cicd", "developer_tools"], "support": "Documentation and email"},
    {"id": "team", "name": "Team", "tagline": "Secure the pipeline from day one",
     "price_monthly_per_dev": None, "price_annual_per_dev": None, "min_devs": 5, "max_devs": 100, "min_annual": None,
     "limits": {"repos": 200, "scans_per_month": 20000, "retention_days": 180, "api_rpm": 600},
     "features": ["sca", "secrets", "sbom", "license", "cicd", "iac", "container", "autofix", "supply_chain", "developer_tools"], "support": "Email, 1 business day"},
    {"id": "business", "name": "Business", "tagline": "Full AppSec + supply-chain integrity", "popular": True,
     "price_monthly_per_dev": None, "price_annual_per_dev": None, "min_devs": 20, "max_devs": None, "min_annual": None,
     "limits": {"repos": None, "scans_per_month": None, "retention_days": 365, "api_rpm": 3000},
     "features": ["sca", "secrets", "sbom", "license", "cicd", "iac", "container", "autofix", "sast", "ai_remediation",
                  "provenance", "admission", "policy_as_code", "compliance", "sso", "supply_chain", "posture", "pqc", "cra",
                  "developer_tools", "cspm", "kspm", "ciem", "attack_paths", "cwpp"], "support": "24×5, 4-hour P1"},
    {"id": "enterprise", "name": "Enterprise", "tagline": "Every engine, every pipeline, every BU",
     "price_monthly_per_dev": None, "price_annual_per_dev": None, "min_devs": 100, "max_devs": None, "min_annual": None,
     "limits": {"repos": None, "scans_per_month": None, "retention_days": 1095, "api_rpm": 10000},
     "features": [f for f in FEATURES if f not in {"self_hosted", "sovereign"}], "support": "24×7, 1-hour P1, named CSM"},
    {"id": "sovereign", "name": "Sovereign / Air-Gapped", "tagline": "Regulated, defence, critical infrastructure",
     "price_monthly_per_dev": None, "price_annual_per_dev": None, "min_devs": 250, "max_devs": None, "min_annual": None,
     "limits": {"repos": None, "scans_per_month": None, "retention_days": 2555, "api_rpm": None},
     "features": list(FEATURES.keys()), "support": "24×7, 1-hour P1, named CSM + TAM, on-site"},
]

ADDONS = [
    {"id": "dast", "name": "DAST & API Security", "price": "On request", "for": ["team", "business"]},
    {"id": "aibom", "name": "AI application & coding-agent security", "price": "On request", "for": ["team", "business"]},
    {"id": "pro_services", "name": "Onboarding & policy design (2 weeks)", "price": "On request", "for": ["team", "business", "enterprise"]},
]


def plan(pid: str) -> dict:
    return next(p for p in PLANS if p["id"] == pid)


def entitled(pid: str, feature: str) -> bool:
    return feature in plan(pid)["features"]


VOLUME_DISCOUNTS = []   # (minimum developers, discount)


def volume_discount(devs: int) -> float:
    return next((d for n, d in VOLUME_DISCOUNTS if devs >= n), 0)


def quote(pid: str, devs: int, annual: bool = True) -> dict:
    p = plan(pid)
    if p["price_annual_per_dev"] is None:
        return {"plan": pid, "devs": devs, "total": None, "note": "Quote on request"}
    devs = max(devs, p["min_devs"])
    unit = p["price_annual_per_dev"] if annual else p["price_monthly_per_dev"] * 12
    disc = volume_discount(devs)
    total = max(round(devs * unit * (1 - disc)), p["min_annual"])
    return {"plan": pid, "devs": devs, "unit_annual": unit, "volume_discount": disc, "total_annual": total,
            "effective_per_dev_month": round(total / devs / 12, 2)}
