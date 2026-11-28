# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Normalisers: third-party scanner JSON -> RAT Flea DevSec unified Finding schema."""
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
                        "remediation": m.get("Resolution"), "resource": (m.get("CauseMetadata") or {}).get("Resource"),
                        "source_tool": "trivy"})
        for s in r.get("Secrets") or []:
            out.append({"engine": "secrets", "rule_id": s.get("RuleID"), "title": s.get("Title"), "severity": SEV.get(s.get("Severity"), "high"),
                        "file": target, "line": s.get("StartLine"), "repo": repo, "source_tool": "trivy"})
    return out


# RAT Flea taint rules that cover the same weakness as a built-in pattern rule: an inline suppression of either id
# applies to both, and the deeper result replaces the pattern match on the same line
SAST_EQUIVALENT = {
    "nervve.python.sql-injection": "NM-SAST-001", "nervve.python.code-injection": "NM-SAST-002",
    "nervve.python.command-injection": "NM-SAST-003", "nervve.python.tls-verification-disabled": "NM-SAST-004",
    "nervve.python.insecure-deserialisation": "NM-SAST-006", "nervve.python.jwt-unverified": "NM-SAST-009",
    "nervve.python.ssrf": "NM-SAST-010", "nervve.python.xxe": "NM-SAST-015",
    "nervve.js.code-injection": "NM-SAST-017", "nervve.js.command-injection": "NM-SAST-018", "nervve.js.dom-xss": "NM-SAST-019",
    "nervve.js.tls-verification-disabled": "NM-SAST-004", "nervve.js.jwt-unverified": "NM-SAST-009",
    "nervve.java.sql-injection": "NM-SAST-021", "nervve.java.command-injection": "NM-SAST-022",
    "nervve.java.unsafe-deserialisation": "NM-SAST-023", "nervve.java.weak-crypto": "NM-SAST-024",
    "nervve.java.weak-hash": "NM-SAST-024", "nervve.js.hardcoded-session-secret": "NM-SAST-045",
    "nervve.java.tls-verification-disabled": "NM-SAST-025", "nervve.java.xxe": "NM-SAST-026",
    "nervve.go.sql-injection": "NM-SAST-027", "nervve.go.command-injection": "NM-SAST-028",
    "nervve.go.tls-verification-disabled": "NM-SAST-029", "nervve.go.weak-crypto": "NM-SAST-030",
    "nervve.csharp.sql-injection": "NM-SAST-031", "nervve.csharp.unsafe-deserialisation": "NM-SAST-032",
    "nervve.csharp.tls-verification-disabled": "NM-SAST-033", "nervve.csharp.command-injection": "NM-SAST-034",
    "nervve.php.sql-injection": "NM-SAST-035", "nervve.php.command-injection": "NM-SAST-036",
    "nervve.php.code-injection": "NM-SAST-037", "nervve.php.file-inclusion": "NM-SAST-038",
    "nervve.ruby.sql-injection": "NM-SAST-039", "nervve.ruby.command-injection": "NM-SAST-040",
    "nervve.python.debug-enabled": "NM-SAST-008", "nervve.python.weak-random-token": "NM-SAST-014",
    "nervve.python.csrf-exempt": "NM-SAST-042", "nervve.java.spring-csrf-disabled": "NM-SAST-042",
    "nervve.php.unsafe-deserialisation": "NM-SAST-037",
    "nervve.c.unbounded-copy": "NM-SAST-048", "nervve.c.gets": "NM-SAST-048", "nervve.c.command-injection": "NM-SAST-049",
    "nervve.c.tls-verification-disabled": "NM-SAST-050", "nervve.kotlin.webview-javascript-bridge": "NM-SAST-051",
    "nervve.kotlin.webview-file-access": "NM-SAST-051", "nervve.kotlin.world-readable-storage": "NM-SAST-051",
    "nervve.kotlin.weak-crypto": "NM-SAST-052", "nervve.scala.weak-crypto": "NM-SAST-052",
    "nervve.swift.tls-trust-all": "NM-SAST-053", "nervve.swift.keychain-always-accessible": "NM-SAST-053",
    "nervve.swift.weak-crypto": "NM-SAST-053", "nervve.rust.tls-verification-disabled": "NM-SAST-054",
    "nervve.bash.pipe-to-shell": "NM-SAST-055", "nervve.bash.tls-verification-disabled": "NM-SAST-055",
}


CRITICAL_TAINT_CWE = {"CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-98", "CWE-502", "CWE-1336"}


def _split_message(msg: str) -> tuple[str, str]:
    """'Title sentence. Impact. Remediation.' -> (title, remediation)"""
    msg = " ".join((msg or "").split())
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z])", msg)
    title = parts[0].rstrip(".") if parts else msg
    rest = [p for p in parts[1:] if not p.startswith(("An attacker", "Anyone", "Attackers", "That ", "This "))]
    return title[:200], " ".join(rest)[:600]


def semgrep(doc: dict, repo: str) -> list[dict]:
    """Opengrep / Semgrep CE JSON. RAT Flea rule ids are reported without the config-path prefix the engine adds."""
    out = []
    for r in doc.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe = meta.get("cwe")
        cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
        if isinstance(cwe, str):
            m = re.match(r"(CWE-\d+)", cwe)
            cwe = m.group(1) if m else cwe
        rid = r.get("check_id") or ""
        if "nervve." in rid:
            rid = rid[rid.index("nervve."):]
        title, fix = _split_message(extra.get("message", ""))
        sev = SEV.get(extra.get("severity"), "medium")
        traced = bool(extra.get("dataflow_trace"))
        if sev == "high" and traced and cwe in CRITICAL_TAINT_CWE:
            sev = "critical"                      # proven flow from a request into code/command/SQL execution
        f = {"engine": "sast", "rule_id": rid, "title": title, "severity": sev,
             "file": r.get("path"), "line": (r.get("start") or {}).get("line"), "repo": repo, "cwe": cwe,
             "owasp": meta.get("owasp"), "confidence": meta.get("confidence"), "source_tool": "opengrep",
             "evidence": (extra.get("lines") or "").strip()[:300]}
        if fix:
            f["remediation"] = fix
        if rid in SAST_EQUIVALENT:
            f["rule_aliases"] = [SAST_EQUIVALENT[rid]]
        if traced:
            # the data flow starts at an HTTP request (or CLI input) and reaches the sink: exposed and reachable
            f["dataflow"], f["reachable"], f["exposure"] = True, True, "internet"
        trace = extra.get("dataflow_trace") or {}
        src = trace.get("taint_source")
        if isinstance(src, list) and len(src) > 1 and isinstance(src[1], list) and src[1] and isinstance(src[1][0], dict):
            loc, code = src[1][0], (src[1][1] if len(src[1]) > 1 else "")
            path = [str(v.get("content")) for v in trace.get("intermediate_vars") or [] if isinstance(v, dict)][:6]
            f["taint_source"] = {"line": (loc.get("start") or {}).get("line"), "code": str(code)[:200], "via": path}
            f["evidence"] = (f"untrusted input `{str(code)[:80]}` (line {(loc.get('start') or {}).get('line')})"
                             + (f" → {' → '.join(path)}" if path else "") + f" → sink at line {f['line']}: " + f["evidence"])[:500]
        if mode := meta.get("category"):
            f["category"] = mode
        out.append(f)
    return out


def gitleaks(doc: list, repo: str) -> list[dict]:
    """Gitleaks JSON (grouped per secret by secrets.consolidate_gitleaks when available). A secret removed from the
    current files is still exposed to anyone with the history and must be rotated; one finding lists every place
    and commit the same secret appears in."""
    out = []
    for d in doc or []:
        occ = d.get("_occurrences") or []
        head = d.get("_in_head")
        hist = bool(d.get("Commit")) if head is None else not head
        ctx = d.get("_context") or "code"
        rule = str(d.get("RuleID") or "")
        provider = bool(re.search(r"(?i)aws|github|gitlab|private-key|stripe|slack|gcp|google|azure|openai|anthropic|"
                                  r"twilio|sendgrid|npm|pypi|shopify|heroku|databricks|hashicorp", rule))
        if ctx == "test":
            sev = "low"
        elif ctx == "documentation":
            sev = "medium"
        elif hist:
            sev = "high"
        else:
            sev = "critical" if provider else "high"
        title = d.get("Description") or "Secret detected"
        if hist:
            title += " (in git history, removed from current files)"
        commits = sorted({o["commit"] for o in occ if o.get("commit")})
        f = {"engine": "secrets", "rule_id": rule, "title": title, "severity": sev,
             "file": d.get("File"), "line": d.get("StartLine"), "repo": repo,
             "commit": d.get("Commit") or None, "cwe": "CWE-798",
             "confidence": "low" if ctx == "test" else "high" if provider else "medium",
             "evidence": (d.get("Secret") or d.get("Match") or "")[:4] + "…", "source_tool": "gitleaks",
             "remediation": "Revoke and rotate this credential now, then remove it from the code"
                            + (" and the git history (git filter-repo), as every clone still holds it." if hist or commits else ".")
                            + (" It is in a test or fixture file: if it is a real credential, replace it with a generated test value."
                               if ctx == "test" else "")}
        if ctx != "code":
            f["context"] = ctx
        if d.get("_hash"):
            f["secret_id"] = d["_hash"]
        if occ:
            f["occurrences"] = len(occ)
            f["locations"] = [{k: v for k, v in o.items() if v} for o in occ[:20]]
            if commits:
                f["commits"] = len(commits)
        out.append(f)
    return out


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
                        "resource": c.get("resource"), "source_tool": "checkov"})
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
# their own tests and by RAT Flea DevSec rules, so import notices are noise in a security report.
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
