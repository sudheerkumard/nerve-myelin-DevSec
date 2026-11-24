# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Maps NERvvE DevSecOps findings to the security and compliance frameworks customers report against.

Control titles are short summaries written for this product (not the standards' own text); identifiers refer to the
published standards, which remain the property of their owners. Every mapping is deliberate and conservative: a finding is tagged with a control only when the control's own text
covers that kind of weakness. Mappings show where automated testing produced evidence for (or against) a control;
they are not a certification and do not replace an assessor.
"""
from collections import defaultdict

# ---------------------------------------------------------------- OWASP Top 10:2025, by CWE
# Built from the 2021 CWE lists as OWASP re-grouped them for 2025: SSRF joined Broken Access Control, Vulnerable and
# Outdated Components grew into Software Supply Chain Failures, and Mishandling of Exceptional Conditions is new.
_A01 = (22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566,
        601, 639, 651, 668, 706, 862, 863, 913, 918, 922, 1275)
_A02 = (2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 776, 942, 1004, 1032, 1174)
_A03 = (937, 1035, 1104, 1357, 506, 1395)
_A04 = (261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720,
        757, 759, 760, 780, 818, 916)
_A05 = (20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564,
        610, 643, 644, 652, 917, 1427)
_A06 = (73, 183, 213, 235, 256, 257, 266, 269, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579,
        598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173, 250, 770)
_A07 = (255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216)
_A08 = (345, 353, 426, 427, 494, 502, 565, 784, 829, 830, 915)
_A09 = (117, 223, 532, 778)
_A10 = (209, 234, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703, 754, 755, 756)
_OWASP_CWES = {"A01": _A01, "A02": _A02, "A03": _A03, "A04": _A04, "A05": _A05, "A06": _A06, "A07": _A07, "A08": _A08,
               "A09": _A09, "A10": _A10}
OWASP_YEAR = "2025"
OWASP_BY_CWE = {c: k for k, cs in _OWASP_CWES.items() for c in cs}
OWASP_NAMES = {
    "A01": "Broken Access Control", "A02": "Security Misconfiguration", "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures", "A05": "Injection", "A06": "Insecure Design", "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures", "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}
OWASP_BY_ENGINE = {"sca": "A03", "supply": "A03", "cicd": "A03", "iac": "A02", "secrets": "A07", "aibom": "A08"}

OWASP_AGENTIC_NAMES = {
    "ASI01:2026": "Agent Goal Hijack", "ASI02:2026": "Tool Misuse & Exploitation", "ASI03:2026": "Identity & Privilege Abuse",
    "ASI04:2026": "Agentic Supply Chain Vulnerabilities", "ASI05:2026": "Unexpected Code Execution (RCE)",
    "ASI06:2026": "Memory & Context Poisoning", "ASI07:2026": "Insecure Inter-Agent Communication",
    "ASI08:2026": "Cascading Failures", "ASI09:2026": "Human-Agent Trust Exploitation", "ASI10:2026": "Rogue Agents",
}
AGENTIC_TESTED = ("ASI01:2026", "ASI02:2026", "ASI03:2026", "ASI04:2026", "ASI05:2026", "ASI06:2026", "ASI07:2026")

# EU Cyber Resilience Act, Regulation (EU) 2024/2847, Annex I essential cybersecurity requirements (paraphrased).
CRA_NAMES = {
    "I.2(a)": "Placed on the market without known exploitable vulnerabilities",
    "I.2(b)": "Secure-by-default configuration",
    "I.2(d)": "Protection from unauthorised access (authentication, identity and access management)",
    "I.2(e)": "Confidentiality of stored, transmitted and processed data (state-of-the-art encryption)",
    "I.2(f)": "Integrity of data, programs and configuration against unauthorised manipulation",
    "I.2(j)": "Limit attack surfaces, including external interfaces",
    "I.2(l)": "Security-relevant logging and monitoring",
    "II.1": "Identify and document components and vulnerabilities, including an SBOM",
    "II.2": "Address and remediate vulnerabilities without delay",
    "II.3": "Apply effective and regular security tests and reviews",
    "II.5": "Coordinated vulnerability disclosure policy",
    "II.7": "Mechanisms to securely distribute updates",
}

# ---------------------------------------------------------------- CWE Top 25 (2024 edition), rank order
CWE_TOP25 = (79, 787, 89, 352, 22, 125, 78, 416, 862, 434, 94, 20, 77, 287, 269, 502, 200, 863, 918, 119, 476, 798,
             190, 400, 306)

OWASP_CICD_NAMES = {
    "CICD-SEC-1": "Insufficient Flow Control Mechanisms", "CICD-SEC-2": "Inadequate Identity and Access Management",
    "CICD-SEC-3": "Dependency Chain Abuse", "CICD-SEC-4": "Poisoned Pipeline Execution",
    "CICD-SEC-5": "Insufficient PBAC (Pipeline-Based Access Controls)", "CICD-SEC-6": "Insufficient Credential Hygiene",
    "CICD-SEC-7": "Insecure System Configuration", "CICD-SEC-8": "Ungoverned Usage of 3rd Party Services",
    "CICD-SEC-9": "Improper Artifact Integrity Validation", "CICD-SEC-10": "Insufficient Logging and Visibility",
}

OWASP_API_NAMES = {
    "API1:2023": "Broken Object Level Authorization", "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization", "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization", "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery", "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management", "API10:2023": "Unsafe Consumption of APIs",
}
OWASP_LLM_NAMES = {
    "LLM01:2025": "Prompt Injection", "LLM02:2025": "Sensitive Information Disclosure", "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning", "LLM05:2025": "Improper Output Handling", "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage", "LLM08:2025": "Vector and Embedding Weaknesses", "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}
LLM_TESTED = ("LLM01:2025", "LLM02:2025", "LLM03:2025", "LLM05:2025", "LLM06:2025", "LLM07:2025", "LLM08:2025", "LLM10:2025")
API_TESTED = ("API1:2023", "API2:2023", "API3:2023", "API5:2023", "API8:2023", "API9:2023")

# ---------------------------------------------------------------- control catalogue
# framework id -> (display name, version label, {control id: title})
FRAMEWORKS = {
    "owasp": ("OWASP Top 10", "2025", {f"{k}:2025": v for k, v in OWASP_NAMES.items()}),
    "cwe25": ("CWE Top 25 Most Dangerous Software Weaknesses", "2024", {}),  # filled per finding
    "api": ("OWASP API Security Top 10", "2023", OWASP_API_NAMES),
    "llm": ("OWASP Top 10 for LLM Applications", "2025", OWASP_LLM_NAMES),
    "agentic": ("OWASP Top 10 for Agentic Applications", "2026", OWASP_AGENTIC_NAMES),
    "cra": ("EU Cyber Resilience Act", "Annex I", CRA_NAMES),
    "cicd": ("OWASP Top 10 CI/CD Security Risks", "2022", OWASP_CICD_NAMES),
    "pci": ("PCI DSS", "v4.0", {
        "2.2": "Secure configuration of system components",
        "6.2.4": "Coding practices that prevent common software attacks",
        "6.3.2": "Inventory of bespoke and third-party software",
        "6.3.3": "Known vulnerabilities fixed by patching",
        "6.5.1": "Controlled changes to production systems",
        "8.6.2": "No hard-coded application or system passwords",
        "1.3.1": "Inbound traffic to the cardholder environment is restricted",
        "3.5.1": "Stored account data is unreadable",
        "4.2.1": "Strong cryptography protects data in transit",
        "7.2.1": "Access is assigned by job need (least privilege)",
        "8.4.2": "Multi-factor authentication for access to the cardholder environment",
        "10.2.1": "Audit logs capture user and administrator activity",
        "11.5.1": "Intrusion detection or prevention monitors traffic and activity",
        "6.3.1": "Security vulnerabilities are identified and ranked by risk",
    }),
    "iso": ("ISO/IEC 27001:2022", "Annex A", {
        "5.17": "Authentication information",
        "5.32": "Intellectual property rights",
        "8.8": "Management of technical vulnerabilities",
        "8.9": "Configuration management",
        "8.25": "Secure development life cycle",
        "8.28": "Secure coding",
        "8.32": "Change management",
        "5.15": "Access control", "5.18": "Access rights", "8.2": "Privileged access rights", "8.3": "Information access restriction",
        "8.12": "Data leakage prevention", "8.15": "Logging", "8.16": "Monitoring activities", "8.20": "Network security",
        "8.24": "Use of cryptography",
    }),
    "ssdf": ("NIST SSDF", "SP 800-218 v1.1", {
        "PO.3": "Implement supporting toolchains",
        "PS.1": "Protect all forms of code from unauthorized access and tampering",
        "PS.3": "Archive and protect each software release (incl. provenance / SBOM)",
        "PW.4": "Reuse existing, well-secured software",
        "PW.7": "Review and/or analyze human-readable code to identify vulnerabilities",
        "PW.9": "Configure software to have secure settings by default",
        "RV.1": "Identify and confirm vulnerabilities on an ongoing basis",
    }),
    "nist": ("NIST SP 800-53", "Rev. 5", {
        "CM-6": "Configuration Settings", "CM-7": "Least Functionality", "IA-5": "Authenticator Management",
        "RA-5": "Vulnerability Monitoring and Scanning", "SA-11": "Developer Testing and Evaluation",
        "SI-2": "Flaw Remediation", "SR-3": "Supply Chain Controls and Processes",
        "AC-2": "Account Management", "AC-3": "Access Enforcement", "AC-6": "Least Privilege", "AU-2": "Event Logging",
        "IA-2": "Identification and Authentication (Organizational Users)", "IR-4": "Incident Handling", "RA-3": "Risk Assessment",
        "SC-7": "Boundary Protection", "SC-8": "Transmission Confidentiality and Integrity", "SC-13": "Cryptographic Protection",
        "SC-28": "Protection of Information at Rest", "SI-4": "System Monitoring",
    }),
    "soc2": ("SOC 2 Trust Services Criteria", "2017 (rev. 2022)", {
        "CC6.1": "Logical access controls",
        "CC7.1": "Detecting configuration changes and new vulnerabilities",
        "CC8.1": "Authorised, tested and approved changes",
        "CC9.2": "Vendor and business-partner risk",
        "CC3.2": "Risks are identified and analysed", "CC6.3": "Access is authorised, modified and removed by role",
        "CC6.6": "Protection against threats from outside system boundaries", "CC6.7": "Restriction and protection of data in transmission",
        "CC7.2": "Monitoring of system components for anomalies", "CC7.3": "Evaluation of security events",
    }),
    "cis": ("CIS Benchmarks", "Docker, Kubernetes, Azure, AWS, Google Cloud", {
        "Docker §4": "Container images and build file configuration",
        "Docker §5": "Container runtime configuration",
        "Kubernetes §5.2": "Pod security standards",
        **{f"{b} §{sec}": f"{ {'Microsoft Azure Foundations': 'Azure', 'AWS Foundations': 'AWS', 'Google Cloud Platform Foundation': 'Google Cloud', 'Kubernetes Benchmark': 'Kubernetes'}[b]} — {sec}"
           for b, secs in {"Microsoft Azure Foundations": ["Identity", "Storage", "Key Vault", "Database Services", "Networking", "Virtual Machines",
                                                           "AKS", "App Service", "Container Registry", "Microsoft Defender"],
                           "AWS Foundations": ["Identity and Access Management", "Storage", "Logging", "Monitoring", "Networking", "Compute",
                                               "Database", "EKS"],
                           "Google Cloud Platform Foundation": ["Identity and Access Management", "Storage", "Networking", "Virtual Machines",
                                                                "Cloud SQL", "GKE", "Cryptographic Keys"],
                           "Kubernetes Benchmark": ["RBAC", "Policies"]}.items() for sec in secs},
    }),
}

# Which controls an engine's findings bear on (engine -> framework -> controls).
BY_ENGINE = {
    "sast": {"pci": ["6.2.4"], "iso": ["8.28"], "ssdf": ["PW.7"], "nist": ["SA-11"], "soc2": ["CC8.1"]},
    "sca": {"pci": ["6.3.3"], "iso": ["8.8"], "ssdf": ["PW.4", "RV.1"], "nist": ["RA-5", "SI-2"], "soc2": ["CC7.1", "CC9.2"]},
    "secrets": {"pci": ["8.6.2"], "iso": ["5.17"], "ssdf": ["PS.1"], "nist": ["IA-5"], "soc2": ["CC6.1"]},
    "iac": {"pci": ["2.2"], "iso": ["8.9"], "ssdf": ["PW.9"], "nist": ["CM-6", "CM-7"], "soc2": ["CC7.1"]},
    "cicd": {"iso": ["8.25"], "ssdf": ["PO.3", "PS.1"], "nist": ["SR-3"], "soc2": ["CC8.1"]},
    "license": {"iso": ["5.32"], "ssdf": ["PW.4"], "soc2": ["CC9.2"]},
    "aibom": {"ssdf": ["PW.4"], "nist": ["SR-3"], "soc2": ["CC9.2"]},
    "supply": {"pci": ["6.3.2"], "iso": ["8.8"], "ssdf": ["PW.4", "PS.1"], "nist": ["SR-3"], "soc2": ["CC9.2"], "cra": ["I.2(a)", "I.2(f)"]},
    "dast": {"pci": ["6.2.4"], "ssdf": ["PW.7", "RV.1"], "nist": ["SA-11", "RA-5"], "soc2": ["CC7.1"]},
}
# Controls for which the scan itself is evidence (an engine that ran is testing for the control).
COVERAGE_ONLY = {"sca": {"pci": ["6.3.2"], "ssdf": ["PS.3"], "cra": ["II.1"]}, "license": {"pci": ["6.3.2"]}}
for _eng, _ctrls in {"sca": ["I.2(a)", "II.2"], "dast": ["I.2(a)", "I.2(j)"], "secrets": ["I.2(d)"], "iac": ["I.2(b)", "I.2(j)"],
                     "cicd": ["I.2(f)"], "sast": ["I.2(a)"]}.items():
    BY_ENGINE[_eng]["cra"] = _ctrls
_CRA_BY_OWASP = {"A04": "I.2(e)", "A07": "I.2(d)", "A01": "I.2(d)", "A08": "I.2(f)", "A09": "I.2(l)", "A02": "I.2(b)"}
_CRA_UPDATES = {"NM-CICD-009", "NM-CICD-021", "NM-CD-004", "NM-CD-011"}
# Deployment (CD) rules additionally touch change management.
_CD_EXTRA = {"pci": ["6.5.1"], "iso": ["8.32"]}


def _cwe_num(f):
    c = str(f.get("cwe") or "").upper().replace("CWE-", "").strip()
    return int(c) if c.isdigit() else None


def _cis(f):
    name = (f.get("file") or "").lower()
    if f.get("engine") != "iac":
        return []
    if "dockerfile" in name or name.endswith(".dockerfile"):
        return ["Docker §4"]
    if "compose" in name:
        return ["Docker §5"]
    if name.endswith((".yaml", ".yml")) and any(k in (f.get("title") or "").lower() for k in
                                                  ("privilege", "root", "capabilit", "host", "read-only", "seccomp", "security context")):
        return ["Kubernetes §5.2"]
    return []


CLOUD_ENGINES = ("cspm", "kspm", "ciem", "runtime", "paths")


def _cloud_cis(f):
    ref = str(f.get("cis") or "")
    if ref.startswith("CIS "):
        return [ref[4:]] if ref[4:] in FRAMEWORKS["cis"][2] else []
    if ref.startswith("Pod Security Standards"):
        return ["Kubernetes §5.2"]
    return []


def tags(f) -> dict:
    """Framework references for one finding: {framework id: [control ids]}."""
    out = defaultdict(list)
    eng = f.get("engine")
    if eng in CLOUD_ENGINES:
        from .cloud.rules import CONTROLS
        for fw, ctrls in CONTROLS.get(f.get("category") or ("runtime" if eng == "runtime" else "path" if eng == "paths" else "workload"), {}).items():
            out[fw].extend(ctrls)
        out["cis"].extend(_cloud_cis(f))
        out["owasp"].append(f"A02:{OWASP_YEAR}")             # Security Misconfiguration (2025 numbering)
        if f.get("category") == "identity" or eng == "ciem":
            out["owasp"] = [f"A01:{OWASP_YEAR}"]            # Broken Access Control
        return {k: sorted(set(v), key=v.index) for k, v in out.items() if v}
    cwe = _cwe_num(f)
    a = OWASP_BY_CWE.get(cwe) if cwe else None
    a = a or OWASP_BY_ENGINE.get(eng)
    if a:
        out["owasp"].append(f"{a}:{OWASP_YEAR}")
        if a in _CRA_BY_OWASP:
            out["cra"].append(_CRA_BY_OWASP[a])
    if f.get("owasp_agentic"):
        for part in str(f["owasp_agentic"]).replace(",", "/").split("/"):
            part = part.strip().split(":")[0]
            if part.startswith("ASI"):
                out["agentic"].append(f"{part}:2026")
    if f.get("rule_id") in _CRA_UPDATES:
        out["cra"].append("II.7")
    if cwe in CWE_TOP25:
        out["cwe25"].append(f"CWE-{cwe}")
    if f.get("owasp_llm"):
        for part in str(f["owasp_llm"]).replace(",", "/").split("/"):
            part = part.strip().split(":")[0]
            if part.startswith("LLM"):
                out["llm"].append(f"{part}:2025")
    if f.get("owasp_api"):
        k = str(f["owasp_api"]).split(" ")[0].strip()
        out["api"].append(k if ":" in k else f"{k}:2023")
    if f.get("owasp_cicd"):
        out["cicd"].append(str(f["owasp_cicd"]).split(":")[0].strip())
    for fw, ctrls in BY_ENGINE.get(eng, {}).items():
        out[fw].extend(ctrls)
    if str(f.get("rule_id", "")).startswith("NM-CD-"):
        for fw, ctrls in _CD_EXTRA.items():
            out[fw].extend(ctrls)
    for c in _cis(f):
        out["cis"].append(c)
    return {k: sorted(set(v), key=v.index) for k, v in out.items()}


def short(f) -> list[str]:
    """Compact labels for a finding row, e.g. ['OWASP A05:2025', 'CWE Top 25 #3', 'PCI DSS 6.2.4']."""
    t = tags(f)
    lab = [f"OWASP {c}" for c in t.get("owasp", [])]
    lab += [f"CWE Top 25 #{CWE_TOP25.index(int(c[4:])) + 1}" for c in t.get("cwe25", [])]
    lab += [f"OWASP {c}" for c in t.get("api", [])]
    lab += [f"OWASP {c}" for c in t.get("llm", [])]
    lab += [f"OWASP Agentic {c}" for c in t.get("agentic", [])]
    lab += [f"OWASP {c}" for c in t.get("cicd", [])]
    lab += [f"PCI DSS {c}" for c in t.get("pci", [])]
    lab += [f"ISO 27001 A.{c}" for c in t.get("iso", [])]
    lab += [f"NIST SSDF {c}" for c in t.get("ssdf", [])]
    lab += [f"CIS {c}" for c in t.get("cis", [])]
    lab += [f"EU CRA {c}" for c in t.get("cra", [])]
    return lab


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def matrix(findings, engines_run) -> list[dict]:
    """Per framework, per control: open findings by severity and an evidence status.

    status: 'gap' (critical/high open), 'observation' (only medium/low open), 'clear' (tested, nothing open),
            'not_tested' (no engine that tests the control ran)."""
    engines_run = set(engines_run)
    tested = defaultdict(set)
    for eng in engines_run:
        for src in (BY_ENGINE.get(eng, {}), COVERAGE_ONLY.get(eng, {})):
            for fw, ctrls in src.items():
                tested[fw].update(ctrls)
        if eng == "sast" or eng == "dast":
            tested["owasp"].update(f"{k}:{OWASP_YEAR}" for k in ("A01", "A04", "A05", "A06", "A07", "A08", "A09", "A10"))
        if eng in OWASP_BY_ENGINE:
            tested["owasp"].add(f"{OWASP_BY_ENGINE[eng]}:{OWASP_YEAR}")
        if eng in ("sast", "sca", "dast", "secrets", "iac", "cicd", "supply"):
            tested["cra"].add("II.3")
        if eng == "dast":
            tested["api"].update(API_TESTED)
        if eng == "aibom":
            tested["llm"].update(LLM_TESTED)
            tested["agentic"].update(AGENTIC_TESTED)
        if eng == "cicd":
            tested["cicd"].update(OWASP_CICD_NAMES)
            tested["pci"].add("6.5.1"); tested["iso"].add("8.32")
        if eng == "iac":
            tested["cis"].update(["Docker §4", "Docker §5", "Kubernetes §5.2"])
        if eng in CLOUD_ENGINES:
            from .cloud.rules import CONTROLS
            cats = {"cspm": ["exposure", "data", "encryption", "identity", "logging", "workload"], "kspm": ["kubernetes", "rbac", "workload", "exposure"],
                    "ciem": ["identity"], "runtime": ["runtime"], "paths": ["path"]}[eng]
            for cat in cats:
                for fw, ctrls in CONTROLS[cat].items():
                    tested[fw].update(ctrls)
            if eng == "kspm":
                tested["cis"].update(["Kubernetes §5.2", "Kubernetes Benchmark §RBAC", "Kubernetes Benchmark §Policies"])
    hits = defaultdict(lambda: defaultdict(list))
    for f in findings:
        for fw, ctrls in tags(f).items():
            for c in ctrls:
                hits[fw][c].append(f)
    out = []
    for fw, (name, ver, catalogue) in FRAMEWORKS.items():
        ids = list(catalogue) if fw != "cwe25" else [f"CWE-{c}" for c in CWE_TOP25]
        rows = []
        for cid in ids:
            fs = hits[fw].get(cid, [])
            sev = defaultdict(int)
            for f in fs:
                sev[f.get("severity", "info")] += 1
            if fs:
                status = "gap" if sev["critical"] or sev["high"] else "observation"
            elif fw == "cwe25":
                status = "clear" if engines_run & {"sast", "dast"} else "not_tested"
            else:
                status = "clear" if cid in tested[fw] else "not_tested"
            title = catalogue.get(cid) if fw != "cwe25" else f"Rank {CWE_TOP25.index(int(cid[4:])) + 1}"
            rows.append({"id": cid, "title": title, "status": status, "count": len(fs), "severity": dict(sev)})
        if fw != "cwe25" and all(r["status"] == "not_tested" for r in rows):
            continue
        if fw == "cwe25":  # only list the Top-25 weaknesses actually found, plus a summary line
            found = [r for r in rows if r["count"]]
            rows = found
        out.append({"id": fw, "name": name, "version": ver, "controls": rows,
                    "gaps": sum(r["status"] == "gap" for r in rows),
                    "observations": sum(r["status"] == "observation" for r in rows),
                    "clear": sum(r["status"] == "clear" for r in rows),
                    "not_tested": sum(r["status"] == "not_tested" for r in rows)})
    return out
