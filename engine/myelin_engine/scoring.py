# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""NERvvE Risk Score (MRS): 0-100 exploitability-weighted priority.

Severity alone over-alerts. MRS blends:
  * CVSS base (impact)                     up to 40
  * EPSS probability of exploitation       up to 25 (severity prior for code/config)
  * CISA KEV (known exploited)             +15
  * Exposure (internet / internal)         +10 / +4
  * Reachability: reachable +10, proven unreachable x0.45
  * Secret: provider-format key +10, confirmed live by the provider +25
  * Known malicious package release        +30
  * Runtime detection (critical/high)       +15   (attack behaviour observed on the workload)
  * Attack path (exposure + weakness + privilege or data) +20
  * Asset criticality multiplier           0.6 - 1.4

Every finding also carries a CISA SSVC decision (Track / Track* / Attend / Act), so teams that run their vulnerability
programme on SSVC get the same answer from the platform as from their own decision tree.
"""
import hashlib

SEV_DEFAULT_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def mrs(f: dict, asset_criticality: float = 1.0) -> float:
    cvss = f.get("cvss") or SEV_DEFAULT_CVSS.get(f.get("severity", "medium"), 5.0)
    s = cvss * 4.0
    epss = f.get("epss")
    if epss is None and f.get("engine") in ("sast", "secrets", "cicd", "iac", "aibom", "dast", "supply", "cspm", "kspm", "ciem", "runtime", "paths"):
        # first-party / config weaknesses have no EPSS: use a severity-based exploit likelihood prior
        epss = {"critical": 0.5, "high": 0.25, "medium": 0.1}.get(f.get("severity"), 0.0)
    s += float(epss or 0) * 25.0
    if f.get("kev"):
        s += 15
    exp = f.get("exposure")
    if exp == "internet":
        s += 10
    elif exp == "internal":
        s += 4
    if f.get("engine") == "secrets" and f.get("validated"):
        s += 25
    elif f.get("engine") == "secrets" and f.get("high_confidence"):
        s += 10
    if f.get("malicious"):
        s += 30
    if f.get("engine") == "runtime" and f.get("severity") in ("critical", "high"):
        s += 15
    if f.get("engine") == "paths":
        s += 20
    reach = f.get("reachable")
    if reach is True:
        s += 10
    elif reach is False:
        s *= 0.45
    s *= 0.8 + 0.2 * asset_criticality  # dampened so business context re-orders without saturating at 100
    return round(max(0.0, min(100.0, s)), 1)


def priority(score: float) -> str:
    if score >= 80:
        return "P0"
    if score >= 60:
        return "P1"
    if score >= 35:
        return "P2"
    return "P3"


SLA_DAYS = {"P0": 2, "P1": 7, "P2": 30, "P3": 90}


def fingerprint(f: dict) -> str:
    key = "|".join(str(f.get(k, "")) for k in
                   ("engine", "rule_id", "cve", "package", "file", "line", "repo"))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------- CISA SSVC (deployer tree used by CISA)
# Weakness classes whose successful exploitation gives the attacker full control of the component ("total" impact).
TOTAL_IMPACT_CWES = {"CWE-78", "CWE-77", "CWE-94", "CWE-95", "CWE-502", "CWE-917", "CWE-89", "CWE-798", "CWE-287",
                     "CWE-306", "CWE-434", "CWE-611", "CWE-918", "CWE-269", "CWE-506", "CWE-494", "CWE-1427", "CWE-639"}
# (exploitation, automatable, technical impact, mission & well-being) -> decision; every other combination is Track.
_SSVC = {
    ("none", True, "total", "high"): "Attend", ("none", False, "total", "high"): "Track*",
    ("poc", True, "partial", "high"): "Attend", ("poc", True, "total", "medium"): "Track*",
    ("poc", True, "total", "high"): "Attend", ("poc", False, "partial", "high"): "Track*",
    ("poc", False, "total", "medium"): "Track*", ("poc", False, "total", "high"): "Attend",
    ("active", True, "partial", "low"): "Attend", ("active", True, "partial", "medium"): "Attend",
    ("active", True, "partial", "high"): "Act", ("active", True, "total", "low"): "Attend",
    ("active", True, "total", "medium"): "Act", ("active", True, "total", "high"): "Act",
    ("active", False, "partial", "high"): "Attend", ("active", False, "total", "medium"): "Attend",
    ("active", False, "total", "high"): "Act",
}


def ssvc(f: dict, asset_criticality: float = 1.0) -> dict:
    """SSVC decision with the decision-point values it was derived from (so an analyst can see and challenge them).

    Exploitation: active = CISA KEV, a validated live secret, a known malicious release, a critical/high runtime
    detection or an attack path through a known-exploited weakness or a runtime detection; poc = EPSS >= 0.1, a finding
    confirmed against the running application (DAST), any runtime detection or attack path; otherwise none.
    Automatable: the weakness is internet-exposed and reachable (or a live secret / malicious package, which needs no
    further attacker steps). Technical impact: total for code-execution, injection, authentication-bypass and
    credential classes or critical severity; partial otherwise. Mission & well-being: from asset criticality."""
    if f.get("kev") or f.get("malicious") or (f.get("engine") == "secrets" and f.get("validated")) or f.get("exploited_weakness") \
            or (f.get("engine") == "runtime" and f.get("severity") in ("critical", "high")):
        expl = "active"
    elif float(f.get("epss") or 0) >= 0.1 or f.get("engine") in ("dast", "runtime", "paths"):
        expl = "poc"
    else:
        expl = "none"
    auto = bool(f.get("malicious") or (f.get("engine") == "secrets" and f.get("validated")) or
                (f.get("exposure") == "internet" and f.get("reachable") is not False and f.get("engine") in ("sca", "dast", "supply", "paths", "cspm")))
    impact = "total" if (f.get("severity") == "critical" or str(f.get("cwe") or "").upper() in TOTAL_IMPACT_CWES) else "partial"
    mission = "high" if asset_criticality >= 1.25 else "low" if asset_criticality < 0.8 else "medium"
    decision = _SSVC.get((expl, auto, impact, mission), "Track")
    return {"decision": decision, "exploitation": expl, "automatable": "yes" if auto else "no",
            "technical_impact": impact, "mission_wellbeing": mission}


def enrich(f: dict, asset_criticality: float = 1.0) -> dict:
    f.setdefault("status", "open")
    f["ssvc"] = ssvc(f, asset_criticality)
    f["mrs"] = mrs(f, asset_criticality)
    f["priority"] = priority(f["mrs"])
    f["sla_days"] = SLA_DAYS[f["priority"]]
    f["fingerprint"] = fingerprint(f)
    f.setdefault("id", "NM-" + f["fingerprint"][:10].upper())
    return f
