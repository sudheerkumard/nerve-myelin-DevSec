# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Normalisers: third-party scanner JSON -> NERvvE DevSecOps unified Finding schema."""
import re

SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info",
       "ERROR": "high", "WARNING": "medium", "INFO": "low", "Negligible": "info"}


def trivy(doc: dict, repo: str) -> list[dict]:
    out = []
    for r in doc.get("Results") or []:
        target = r.get("Target")
        for v in r.get("Vulnerabilities") or []:
            cvss = None
            for src in (v.get("CVSS") or {}).values():
                cvss = src.get("V3Score") or cvss
            out.append({"engine": "container" if r.get("Class") == "os-pkgs" else "sca", "rule_id": v.get("VulnerabilityID"),
                        "cve": v.get("VulnerabilityID"), "title": f"{v.get('PkgName')}@{v.get('InstalledVersion')}: {v.get('Title', '')}",
                        "severity": SEV.get(v.get("Severity"), "medium"), "cvss": cvss, "package": v.get("PkgName"),
                        "version": v.get("InstalledVersion"), "fixed_version": v.get("FixedVersion"), "file": target,
                        "repo": repo, "source_tool": "trivy", "autofix": bool(v.get("FixedVersion"))})
        for m in r.get("Misconfigurations") or []:
            out.append({"engine": "iac", "rule_id": m.get("ID"), "title": m.get("Title"), "severity": SEV.get(m.get("Severity"), "medium"),
                        "file": target, "line": (m.get("CauseMetadata") or {}).get("StartLine"), "repo": repo,
                        "remediation": m.get("Resolution"), "source_tool": "trivy"})
        for s in r.get("Secrets") or []:
            out.append({"engine": "secrets", "rule_id": s.get("RuleID"), "title": s.get("Title"), "severity": SEV.get(s.get("Severity"), "high"),
                        "file": target, "line": s.get("StartLine"), "repo": repo, "source_tool": "trivy"})
    return out


def semgrep(doc: dict, repo: str) -> list[dict]:
    out = []
    for r in doc.get("results") or []:
        meta = (r.get("extra") or {}).get("metadata") or {}
        cwe = meta.get("cwe")
        out.append({"engine": "sast", "rule_id": r.get("check_id"), "title": (r.get("extra") or {}).get("message", "")[:200],
                    "severity": SEV.get((r.get("extra") or {}).get("severity"), "medium"), "file": r.get("path"),
                    "line": (r.get("start") or {}).get("line"), "repo": repo, "cwe": cwe[0] if isinstance(cwe, list) and cwe else cwe,
                    "source_tool": "semgrep"})
    return out


def gitleaks(doc: list, repo: str) -> list[dict]:
    return [{"engine": "secrets", "rule_id": d.get("RuleID"), "title": d.get("Description"), "severity": "critical",
             "file": d.get("File"), "line": d.get("StartLine"), "repo": repo, "commit": d.get("Commit"),
             "evidence": (d.get("Secret") or "")[:4] + "…", "source_tool": "gitleaks"} for d in (doc or [])]


_CHECKOV_HIGH = re.compile(r"(?i)public|0\.0\.0\.0|privileged|root|admin|encrypt|https|tls|ssl|secret|password|"
                           r"credential|anonymous|wildcard|\*|unrestricted|exposed|host(network|pid|ipc|path)|capabilit")
_CHECKOV_HYGIENE = re.compile(r"(?i)probe|namespace|label|description|tag|log(ging)? retention|healthcheck|image pull policy|"
                              r"seccomp|apparmor|cpu|memory|limit|request")


def _checkov_severity(check_id: str, name: str) -> str:
    """Checkov's open-source output has no severity: rate exposure/crypto/privilege checks medium, hygiene low."""
    if _CHECKOV_HYGIENE.search(name):
        return "low"
    return "medium" if _CHECKOV_HIGH.search(name) else "low"


def checkov(doc, repo: str) -> list[dict]:
    docs = doc if isinstance(doc, list) else [doc]
    out = []
    for d in docs:
        for c in ((d.get("results") or {}).get("failed_checks") or []):
            out.append({"engine": "iac", "rule_id": c.get("check_id"), "title": c.get("check_name"),
                        "severity": (c.get("severity") or _checkov_severity(c.get("check_id", ""), c.get("check_name", ""))).lower(),
                        "file": c.get("file_path"),
                        "line": (c.get("file_line_range") or [None])[0], "repo": repo, "remediation": c.get("guideline"),
                        "source_tool": "checkov"})
    return out


def grype(doc: dict, repo: str) -> list[dict]:
    out = []
    for m in doc.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        fixes = (v.get("fix") or {}).get("versions") or []
        out.append({"engine": "sca", "rule_id": v.get("id"), "cve": v.get("id"), "title": f"{a.get('name')}@{a.get('version')}",
                    "severity": SEV.get(v.get("severity", "").upper(), "medium"), "package": a.get("name"), "version": a.get("version"),
                    "fixed_version": fixes[0] if fixes else None, "purl": a.get("purl"), "repo": repo, "source_tool": "grype",
                    "autofix": bool(fixes)})
    return out


BANDIT_SKIP = {"B101", "B110", "B112", "B603", "B607", "B311",            # asserts, try/except/pass, subprocess without shell, non-crypto random
               "B105", "B106", "B107"}                                    # password heuristics: the secrets engine covers these precisely
# B401-B415 only report that a module was *imported* (pickle, subprocess, xml...). The dangerous *calls* are reported by
# their own tests and by NERvvE DevSecOps rules, so import notices are noise in a security report.
BANDIT_SEVERITY_OVERRIDE = {"B104": "low"}
BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def bandit(doc: dict, repo: str) -> list[dict]:
    """Bandit (Python SAST). Low-confidence results and noisy informational tests are dropped."""
    out = []
    for r in (doc or {}).get("results") or []:
        tid = r.get("test_id", "")
        if tid in BANDIT_SKIP or r.get("issue_confidence") == "LOW" or re.match(r"^B4(0[1-9]|1[0-5])$", tid):
            continue
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append({"engine": "sast", "rule_id": f"BANDIT-{r['test_id']}", "title": r.get("issue_text", r["test_id"]).rstrip("."),
                    "severity": BANDIT_SEVERITY_OVERRIDE.get(r["test_id"]) or BANDIT_SEV.get(r.get("issue_severity"), "low"),
                    "cwe": f"CWE-{cwe}" if cwe else None,
                    "file": r.get("filename", ""), "line": r.get("line_number"), "repo": repo,
                    "evidence": (r.get("code") or "").strip().splitlines()[0][:160] if r.get("code") else "",
                    "remediation": f"See {r.get('more_info', 'the Bandit documentation')}.", "source_tool": "bandit",
                    "reachable": True, "exposure": "internet"})
    return out
