# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Bring-your-own-scanner import.

Results from other tools are converted to RAT Flea DevSec findings, then go through the same de-duplication, risk scoring,
policy gate, ticketing, reporting and VEX as RAT Flea DevSec's own engines. Supported, detected automatically:

  SARIF 2.1.0 (any SARIF producer, e.g. CodeQL or Semgrep)
  CycloneDX 1.4+ JSON (vulnerabilities section; a plain SBOM is matched against RAT Flea DevSec's vulnerability intelligence)
  Trivy JSON · Grype JSON · Semgrep JSON · Gitleaks JSON · Checkov JSON · Bandit JSON · OWASP ZAP JSON
"""
import json
import re

from . import normalize

SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
CVE_RX = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
CWE_RX = re.compile(r"CWE[-_ ]?(\d+)", re.I)


class ImportError_(ValueError):
    pass


def detect(doc, filename: str = "") -> str:
    name = filename.lower()
    if isinstance(doc, list):
        if doc and isinstance(doc[0], dict) and "RuleID" in doc[0]:
            return "gitleaks"
        if doc and isinstance(doc[0], dict) and "check_type" in doc[0]:
            return "checkov"
        if not doc and "gitleaks" in name:
            return "gitleaks"
        raise ImportError_("unrecognised JSON list")
    if not isinstance(doc, dict):
        raise ImportError_("not a JSON object")
    if str(doc.get("version", "")).startswith("2.1") and "runs" in doc:
        return "sarif"
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "Results" in doc and ("ArtifactName" in doc or "SchemaVersion" in doc):
        return "trivy"
    if "matches" in doc and ("descriptor" in doc or "source" in doc):
        return "grype"
    if "results" in doc and "errors" in doc and ("paths" in doc or "version" in doc) and \
            all("check_id" in r for r in (doc.get("results") or [])[:5]):
        return "semgrep"
    if "results" in doc and isinstance(doc.get("results"), dict) and "failed_checks" in doc["results"]:
        return "checkov"
    if "results" in doc and "metrics" in doc and "generated_at" in doc:
        return "bandit"
    if "site" in doc and ("@version" in doc or "@programName" in doc or "@generated" in doc):
        return "zap"
    raise ImportError_("unrecognised format: supported are SARIF, CycloneDX, Trivy, Grype, Semgrep, Gitleaks, Checkov, Bandit, ZAP")


def sarif(doc: dict, repo: str) -> list[dict]:
    out = []
    for run in doc.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool = driver.get("name") or "sarif"
        rules = {r.get("id"): r for r in driver.get("rules") or []}
        for res in run.get("results") or []:
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "sarif"
            rule = rules.get(rid) or {}
            props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            sev = SARIF_LEVEL.get(level, "medium")
            sec = props.get("security-severity")             # GitHub convention, CVSS-like 0-10
            try:
                s = float(sec)
                sev = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
            except (TypeError, ValueError):
                pass
            loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
            msg = (res.get("message") or {}).get("text") or (rule.get("shortDescription") or {}).get("text") or rid
            text = " ".join(map(str, [rid, msg, props.get("tags", ""), rule.get("name", "")]))
            cve = (CVE_RX.search(text) or [None])[0]
            cwe = CWE_RX.search(text)
            tags = " ".join(map(str, props.get("tags") or [])).lower()
            eng = "secrets" if "secret" in tags or "secret" in tool.lower() else "sca" if cve and "dependenc" in text.lower() else \
                "iac" if any(k in tags for k in ("iac", "terraform", "kubernetes", "docker")) else "sast"
            out.append({"engine": eng, "rule_id": str(rid)[:120], "title": str(msg)[:200], "severity": sev, "cve": cve,
                        "cwe": f"CWE-{int(cwe.group(1))}" if cwe else None,
                        "file": ((loc.get("artifactLocation") or {}).get("uri") or "").replace("file://", ""),
                        "line": (loc.get("region") or {}).get("startLine"), "repo": repo, "source_tool": tool,
                        "remediation": (rule.get("help") or {}).get("text")})
    return out


def _cdx_sev(v):
    for r in v.get("ratings") or []:
        s = str(r.get("severity") or "").lower()
        if s in ("critical", "high", "medium", "low", "info"):
            return s, r.get("score")
    return "medium", None


def cyclonedx(doc: dict, repo: str) -> list[dict]:
    comps = {c.get("bom-ref"): c for c in doc.get("components") or []}
    vulns = doc.get("vulnerabilities") or []
    out = []
    for v in vulns:
        sev, score = _cdx_sev(v)
        vid = v.get("id") or ""
        fixed = None
        for rec in (v.get("recommendation") or "",):
            m = re.search(r"(\d+(?:\.\d+)+)", rec)
            fixed = m.group(1) if m else None
        for a in v.get("affects") or [{"ref": None}]:
            c = comps.get(a.get("ref")) or {}
            out.append({"engine": "sca", "rule_id": vid, "cve": vid if vid.startswith("CVE-") else None, "advisory": vid,
                        "title": f"{c.get('name', '?')}@{c.get('version', '?')}: {(v.get('description') or vid)[:160]}",
                        "severity": sev, "cvss": score, "package": c.get("name"), "version": c.get("version"), "purl": c.get("purl"),
                        "fixed_version": fixed, "cwe": f"CWE-{(v.get('cwes') or [None])[0]}" if v.get("cwes") else None,
                        "repo": repo, "source_tool": "cyclonedx"})
    if not vulns and comps:                       # a plain SBOM: match it against RAT Flea DevSec's vulnerability intelligence
        from . import sbom as _sbom
        inv = []
        for c in comps.values():
            p = c.get("purl") or ""
            m = re.match(r"pkg:([a-z]+)/(.+)@([^?#]+)", p)
            if m:
                eco, name = m.group(1), m.group(2)
                eco = {"pypi": "pypi", "npm": "npm", "maven": "maven", "golang": "go", "nuget": "nuget", "cargo": "cargo",
                       "gem": "rubygems"}.get(eco, eco)
                inv.append({"ecosystem": eco, "name": name.replace("/", ":") if eco == "maven" else name, "version": m.group(3),
                            "file": "sbom", "scope": "required", "purl": p})
        out = _sbom.match_advisories(inv, repo)
        for f in out:
            f["source_tool"] = "cyclonedx-sbom"
    return out


def zap(doc: dict, repo: str) -> list[dict]:
    out = []
    for site in doc.get("site") or []:
        for a in site.get("alerts") or []:
            inst = (a.get("instances") or [{}])[0]
            cwe = a.get("cweid")
            out.append({"engine": "dast", "rule_id": f"ZAP-{a.get('pluginid')}", "title": a.get("name") or a.get("alert"),
                        "severity": ZAP_RISK.get(str(a.get("riskcode")), "medium"),
                        "file": f"{inst.get('method', 'GET')} {inst.get('uri', site.get('@name', ''))}", "url": inst.get("uri"),
                        "cwe": f"CWE-{cwe}" if cwe and str(cwe) not in ("0", "-1") else None,
                        "remediation": re.sub(r"<[^>]+>", "", a.get("solution") or "")[:500], "repo": repo, "source_tool": "zap"})
    return out


PARSERS = {"sarif": sarif, "cyclonedx": cyclonedx, "zap": zap, "trivy": normalize.trivy, "grype": normalize.grype,
           "semgrep": normalize.semgrep, "gitleaks": normalize.gitleaks, "checkov": normalize.checkov, "bandit": normalize.bandit}


def parse(content: bytes | str, repo: str, filename: str = "", fmt: str = "auto") -> tuple[str, list[dict]]:
    """Returns (format, findings). Raises ImportError_ with a readable message for anything it cannot read."""
    if isinstance(content, bytes):
        content = content.decode("utf-8-sig", errors="replace")
    try:
        doc = json.loads(content)
    except json.JSONDecodeError as e:
        raise ImportError_(f"not valid JSON ({e.msg} at line {e.lineno})") from None
    fmt = detect(doc, filename) if fmt in ("", "auto", None) else fmt
    if fmt not in PARSERS:
        raise ImportError_(f"unsupported format '{fmt}'")
    found = PARSERS[fmt](doc, repo)
    for f in found:
        f.setdefault("repo", repo)
        f.setdefault("source_tool", fmt)
        f["imported"] = True
    return fmt, [f for f in found if f.get("rule_id") or f.get("title")]
