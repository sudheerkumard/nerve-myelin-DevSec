# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Deterministic demo tenant: 'Orion Financial Group' (fictional).

One repo (payments-web) is a REAL scan of demo/vulnerable-app; the rest are generated
from realistic templates so the console tells a coherent enterprise story.
"""
import os
import random
from datetime import datetime, timedelta, timezone

from myelin_engine import orchestrator
from myelin_engine.scoring import enrich

R = random.Random(20261109)
R2 = random.Random(20261121)        # supply-chain, posture and cryptography demo data (keeps the original sequence stable)
NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

BUS = ["Retail Banking", "Payments", "Wealth & Markets", "Platform Engineering", "Data & AI"]
REPOS = [
    # name, BU, lang, scm, ci, criticality, internet-facing
    ("payments-web", "Payments", "Python/Node/Java", "GitHub", "GitHub Actions", 1.4, True),
    ("payments-gateway", "Payments", "Java", "GitHub", "GitHub Actions", 1.4, True),
    ("card-tokenizer", "Payments", "Go", "GitHub", "GitHub Actions", 1.4, False),
    ("upi-switch-adapter", "Payments", "Java", "Azure Repos", "Azure Pipelines", 1.3, True),
    ("netbanking-portal", "Retail Banking", "TypeScript", "GitLab", "GitLab CI", 1.3, True),
    ("mobile-bff", "Retail Banking", "Node", "GitLab", "GitLab CI", 1.2, True),
    ("kyc-onboarding", "Retail Banking", "Python", "GitLab", "GitLab CI", 1.3, True),
    ("loan-origination", "Retail Banking", "Java", "Azure Repos", "Azure Pipelines", 1.1, False),
    ("customer-notify", "Retail Banking", "Go", "GitLab", "GitLab CI", 0.9, False),
    ("trade-capture", "Wealth & Markets", "Java", "Bitbucket", "Jenkins", 1.3, False),
    ("risk-engine", "Wealth & Markets", "Python", "Bitbucket", "Jenkins", 1.2, False),
    ("advisor-portal", "Wealth & Markets", "TypeScript", "GitHub", "GitHub Actions", 1.0, True),
    ("market-data-feed", "Wealth & Markets", "Go", "Bitbucket", "Jenkins", 1.0, False),
    ("platform-terraform", "Platform Engineering", "HCL", "GitHub", "GitHub Actions", 1.3, False),
    ("aks-baseline", "Platform Engineering", "YAML/Helm", "GitHub", "GitHub Actions", 1.2, False),
    ("golden-images", "Platform Engineering", "Dockerfile", "GitHub", "GitHub Actions", 1.2, False),
    ("shared-ci-templates", "Platform Engineering", "YAML", "GitHub", "GitHub Actions", 1.3, False),
    ("identity-gateway", "Platform Engineering", "Go", "Azure Repos", "Azure Pipelines", 1.4, True),
    ("fraud-ml", "Data & AI", "Python", "GitHub", "GitHub Actions", 1.2, False),
    ("genai-support-assistant", "Data & AI", "Python", "GitHub", "GitHub Actions", 1.2, True),
    ("feature-store", "Data & AI", "Python", "Azure Repos", "Azure Pipelines", 1.0, False),
    ("data-lake-ingest", "Data & AI", "Scala", "Azure Repos", "Azure Pipelines", 0.9, False),
    ("reporting-dwh", "Data & AI", "SQL/Python", "GitLab", "GitLab CI", 0.8, False),
    ("internal-wiki", "Platform Engineering", "Node", "GitLab", "GitLab CI", 0.6, False),
]
SCA_POOL = [
    ("org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", 10.0, .975, True, "maven"),
    ("org.springframework:spring-beans", "5.3.15", "5.3.18", "CVE-2022-22965", 9.8, .974, True, "maven"),
    ("org.apache.commons:commons-text", "1.9", "1.10.0", "CVE-2022-42889", 9.8, .969, False, "maven"),
    ("com.fasterxml.jackson.core:jackson-databind", "2.13.2", "2.13.4.2", "CVE-2022-42003", 7.5, .004, False, "maven"),
    ("org.yaml:snakeyaml", "1.30", "2.0", "CVE-2022-1471", 8.3, .44, False, "maven"),
    ("golang.org/x/net", "0.13.0", "0.17.0", "CVE-2023-44487", 7.5, .94, True, "go"),
    ("google.golang.org/grpc", "1.56.2", "1.56.3", "CVE-2023-44487", 7.5, .94, True, "go"),
    ("lodash", "4.17.15", "4.17.21", "CVE-2021-23337", 7.2, .012, False, "npm"),
    ("semver", "7.3.8", "7.5.2", "CVE-2022-25883", 7.5, .006, False, "npm"),
    ("@babel/traverse", "7.22.5", "7.23.2", "CVE-2023-45133", 9.3, .015, False, "npm"),
    ("jsonwebtoken", "8.5.1", "9.0.0", "CVE-2022-23529", 7.6, .004, False, "npm"),
    ("axios", "1.4.0", "1.6.0", "CVE-2023-45857", 6.5, .002, False, "npm"),
    ("express", "4.18.2", "4.19.2", "CVE-2024-29041", 6.1, .002, False, "npm"),
    ("django", "4.2.7", "4.2.15", "CVE-2024-42005", 9.8, .011, False, "pypi"),
    ("requests", "2.31.0", "2.32.0", "CVE-2024-35195", 5.6, .001, False, "pypi"),
    ("pyyaml", "5.3.1", "5.4", "CVE-2020-14343", 9.8, .021, False, "pypi"),
    ("jinja2", "3.1.2", "3.1.4", "CVE-2024-34064", 5.4, .001, False, "pypi"),
    ("cryptography", "41.0.3", "41.0.4", "CVE-2023-5363", 7.5, .003, False, "pypi"),
]
CONTAINER_POOL = [
    ("openssh-server", "1:9.2p1-2", "1:9.2p1-2+deb12u3", "CVE-2024-6387", 8.1, .52, False),
    ("libwebp7", "1.2.4-0.2", "1.2.4-0.2+deb12u1", "CVE-2023-4863", 8.8, .74, True),
    ("curl", "7.88.1-10", "7.88.1-10+deb12u4", "CVE-2023-38545", 9.8, .29, False),
    ("runc", "1.1.10", "1.1.12", "CVE-2024-21626", 8.6, .05, False),
    ("xz-utils", "5.6.0-0.2", "5.6.1+really5.4.5-1", "CVE-2024-3094", 10.0, .85, False),
    ("glibc", "2.36-9", "2.36-9+deb12u3", "CVE-2023-4911", 7.8, .19, True),
]
SAST_POOL = [("NM-SAST-001", "SQL injection: query built from untrusted input", "critical", "CWE-89"),
             ("NM-SAST-002", "Code injection via eval/exec on user input", "critical", "CWE-95"),
             ("NM-SAST-003", "OS command injection", "high", "CWE-78"),
             ("NM-SAST-004", "TLS certificate validation disabled", "high", "CWE-295"),
             ("NM-SAST-006", "Insecure deserialisation", "high", "CWE-502"),
             ("NM-SAST-007", "DOM XSS sink", "medium", "CWE-79"),
             ("NM-SAST-010", "Server-side request forgery (SSRF)", "high", "CWE-918"),
             ("NM-SAST-011", "Path traversal in file download", "high", "CWE-22"),
             ("NM-SAST-012", "Missing authorisation check on admin route", "high", "CWE-862"),
             ("NM-SAST-005", "Weak hash algorithm", "medium", "CWE-327")]
CICD_POOL = ["NM-CICD-001", "NM-CICD-001", "NM-CICD-004", "NM-CICD-009", "NM-CICD-011", "NM-CICD-005", "NM-CICD-008",
             "NM-CICD-010", "NM-CICD-003", "NM-CICD-007", "NM-CICD-002", "NM-CICD-006"]
IAC_POOL = [("NM-IAC-003", "Network rule open to the internet (0.0.0.0/0)", "high"),
            ("NM-IAC-005", "PaaS resource reachable from public network", "high"),
            ("NM-IAC-002", "Kubernetes container runs privileged", "critical"),
            ("NM-IAC-008", "Key Vault without purge protection", "medium"),
            ("NM-IAC-009", "AKS cluster without Azure Policy / Defender", "medium"),
            ("NM-IAC-001", "Dockerfile runs as root or uses :latest base", "medium")]
SECRET_POOL = [("NM-SEC-001", "AWS Access Key ID", "critical"), ("NM-SEC-002", "GitHub Personal Access Token", "critical"),
               ("NM-SEC-006", "Azure Storage account key", "critical"), ("NM-SEC-010", "Generic credential assignment", "high"),
               ("NM-SEC-004", "Slack token", "high")]
AI_POOL = [("NM-AI-002", "Model loading executes remote code (trust_remote_code=True)", "high"),  # myelin:ignore[NM-AI-002] -- demo seed title text, not model loading
           ("NM-AI-004", "Prompt built by concatenating user input (prompt injection)", "medium"),
           ("NM-AI-005", "LLM agent exposed to unrestricted shell tool (excessive agency)", "high"),
           ("NM-AI-006", "MCP server tool without allow-list / auth", "high"),
           ("NM-AI-001", "AI model pulled without pinned revision", "medium")]
DEVS = ["a.mehta", "r.iyer", "s.kapoor", "j.fernandes", "l.chen", "m.okafor", "p.nair", "d.walsh", "k.sato", "n.rao", "t.mueller", "v.reddy"]


def _ts(days_ago):
    return (NOW - timedelta(days=days_ago, hours=R.randint(0, 23), minutes=R.randint(0, 59))).isoformat()


def _gen_findings(repo):
    name, bu, lang, scm, ci, crit, internet = repo
    exposure = "internet" if internet else "internal"
    out = []
    n_sca = R.randint(4, 16)
    for _ in range(n_sca):
        pkg, ver, fix, cve, cvss, epss, kev, eco = R.choice(SCA_POOL)
        out.append({"engine": "sca", "rule_id": cve, "cve": cve, "title": f"{pkg}@{ver}", "package": pkg, "version": ver,
                    "fixed_version": fix, "cvss": cvss, "epss": epss, "kev": kev, "ecosystem": eco,
                    "severity": "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium",
                    "reachable": R.random() < 0.35, "exposure": exposure, "file": {"maven": "pom.xml", "go": "go.mod", "npm": "package-lock.json", "pypi": "requirements.txt"}[eco],
                    "dependency_type": R.choice(["direct", "transitive", "transitive"]), "autofix": True})
    if "Dockerfile" in lang or R.random() < 0.6:
        for _ in range(R.randint(1, 6)):
            pkg, ver, fix, cve, cvss, epss, kev = R.choice(CONTAINER_POOL)
            out.append({"engine": "container", "rule_id": cve, "cve": cve, "title": f"{pkg} {ver} in image {name}:{R.randint(100, 999)}",
                        "package": pkg, "version": ver, "fixed_version": fix, "cvss": cvss, "epss": epss, "kev": kev,
                        "severity": "critical" if cvss >= 9 else "high", "reachable": R.random() < 0.5, "exposure": exposure,
                        "file": "Dockerfile", "autofix": True, "image": f"acr.orion.example/{name}"})
    for _ in range(R.randint(0, 7)):
        rid, t, sev, cwe = R.choice(SAST_POOL)
        out.append({"engine": "sast", "rule_id": rid, "title": t, "severity": sev, "cwe": cwe, "reachable": True, "exposure": exposure,
                    "file": f"src/{R.choice(['api', 'service', 'handlers', 'controllers'])}/{R.choice(['orders', 'auth', 'users', 'reports', 'export'])}.{R.choice(['py', 'java', 'ts', 'go'])}",
                    "line": R.randint(12, 480), "autofix": R.random() < 0.6})
    for _ in range(R.randint(1, 6)):
        from myelin_engine.cicd_posture import RULES
        rid = R.choice(CICD_POOL)
        t, sev, owasp, fix = RULES[rid]
        out.append({"engine": "cicd", "rule_id": rid, "title": t, "severity": sev, "owasp_cicd": owasp, "remediation": fix,
                    "file": {"GitHub Actions": ".github/workflows/build.yml", "GitLab CI": ".gitlab-ci.yml", "Azure Pipelines": "azure-pipelines.yml", "Jenkins": "Jenkinsfile"}[ci],
                    "line": R.randint(5, 90), "exposure": "internet" if rid in ("NM-CICD-002", "NM-CICD-003") else "internal"})
    if lang in ("HCL", "YAML/Helm", "Dockerfile") or R.random() < 0.4:
        for _ in range(R.randint(1, 8)):
            rid, t, sev = R.choice(IAC_POOL)
            iac_file = {"NM-IAC-002": "charts/app/templates/deployment.yaml", "NM-IAC-001": "Dockerfile",
                        "NM-IAC-009": "infra/aks.tf"}.get(rid, R.choice(["infra/main.tf", "infra/network.bicep", "infra/storage.tf"]))
            out.append({"engine": "iac", "rule_id": rid, "title": t, "severity": sev, "file": iac_file,
                        "line": R.randint(3, 200), "exposure": "internet"})
    if R.random() < 0.3:
        rid, t, sev = R.choice(SECRET_POOL)
        out.append({"engine": "secrets", "rule_id": rid, "title": f"{t} committed to source", "severity": sev, "file": R.choice(["config/settings.py", ".env.example", "scripts/deploy.sh", "src/main/resources/application.yml"]),
                    "line": R.randint(1, 60), "validated": (live := R.random() < 0.5), "validation": "live" if live else "not_checked", "high_confidence": True, "exposure": "internet", "cwe": "CWE-798",
                    "commit": "%07x" % R.getrandbits(28)})
    if bu == "Data & AI":
        for _ in range(R.randint(2, 5)):
            rid, t, sev = R.choice(AI_POOL)
            out.append({"engine": "aibom", "rule_id": rid, "title": t, "severity": sev, "file": R.choice(["agents/support.py", "ml/train.py", "mcp/server.py"]),
                        "line": R.randint(5, 120), "owasp_llm": R.choice(["LLM01", "LLM03", "LLM06", "LLM08"])})
    if R.random() < 0.15:
        out.append({"engine": "license", "rule_id": "NM-LIC-001", "title": "Copyleft licence AGPL-3.0 in itext7", "severity": "high",
                    "package": "itext7", "license": "AGPL-3.0", "file": "pom.xml"})
    if internet and R.random() < 0.6:
        for t, sev, cwe in R.sample([("Missing Content-Security-Policy header", "low", "CWE-693"), ("BOLA: object ID enumeration on /api/accounts/{id}", "high", "CWE-639"),
                                     ("Reflected XSS in search parameter", "medium", "CWE-79"), ("JWT accepted after logout (no revocation)", "medium", "CWE-613"),
                                     ("Rate limiting absent on /auth/otp", "high", "CWE-307")], 2):
            out.append({"engine": "dast", "rule_id": "NM-DAST-" + cwe.split("-")[1], "title": t, "severity": sev, "cwe": cwe,
                        "file": f"https://{name}.orion.example", "exposure": "internet", "reachable": True})
    for f in out:
        f["repo"], f["business_unit"] = name, bu
        age = R.choice([1, 2, 3, 5, 8, 13, 21, 34, 55, 80])
        f["first_seen"] = _ts(age)
        f["age_days"] = age
        f["assignee"] = R.choice(DEVS)
        r = R.random()
        f["status"] = "fixed" if r < 0.38 else "risk_accepted" if r < 0.42 else "suppressed" if r < 0.45 else "open"
        enrich(f, crit)
    return out + _advanced_demo(repo)


SUPPLY_DEMO = [  # (rule, title, severity, file, extra)
    ("NM-SUP-005", "Dependencies are not locked (no lockfile)", "medium", "package.json", {}),
    ("NM-SUP-008", "No dependency cooldown (minimum release age) configured", "low", "package.json", {}),
    ("NM-SUP-007", "4 dependencies run install-time scripts", "low", "package-lock.json",
     {"packages": ["node-pre-gyp-helper", "native-hash", "postinstall-banner", "fast-crc32c"]}),
    ("NM-SUP-002", "Possible typosquat: 'requets' looks like 'requests'", "high", "requirements.txt",
     {"package": "requets", "lookalike_of": "requests", "ecosystem": "pypi", "exposure": "internet", "reachable": True}),
    ("NM-SUP-002", "Possible typosquat: 'axois' looks like 'axios'", "high", "package.json",
     {"package": "axois", "lookalike_of": "axios", "ecosystem": "npm", "exposure": "internet", "reachable": True}),
    ("NM-SUP-004", "Dependency confusion: extra package index is consulted alongside the private one", "high", "requirements.txt", {"line": 1}),
    ("NM-SUP-006", "Dependency installed from a URL, git branch or tarball", "medium", "package.json", {"line": 14}),
]
HARDENING_DEMO = ["NM-CICD-015", "NM-CICD-014", "NM-CICD-019", "NM-CICD-016", "NM-CICD-021", "NM-CICD-017"]


def _advanced_demo(repo):
    """Supply-chain defence and CI hardening findings for a generated repository (own random stream)."""
    from myelin_engine import supply_chain as SC
    from myelin_engine.cicd_posture import RULES
    name, bu, lang, scm, ci, crit, internet = repo
    out = []
    node = any(k in lang for k in ("Node", "TypeScript"))
    py = "Python" in lang
    for rid, title, sev, file, extra in SUPPLY_DEMO:
        if (file.startswith("package") and not node) or (file == "requirements.txt" and not py) or R2.random() > 0.45:
            continue
        out.append({"engine": "supply", "rule_id": rid, "title": title, "severity": sev, "file": file, "cwe": SC.RULES[rid][2],
                    "owasp_cicd": "CICD-SEC-3", "remediation": SC.REMEDIATION[rid], **{"exposure": "internal", **extra}})
    if node and name in ("mobile-bff", "netbanking-portal"):
        pkg, ver = ("debug", "4.4.2") if name == "mobile-bff" else ("chalk", "5.6.1")
        out.append({"engine": "supply", "rule_id": "NM-SUP-001", "title": f"Known malicious release: {pkg}@{ver}", "severity": "critical",
                    "package": pkg, "version": ver, "ecosystem": "npm", "file": "package-lock.json", "malicious": True,
                    "reachable": True, "exposure": "internet", "cwe": "CWE-506", "remediation": SC.REMEDIATION["NM-SUP-001"],
                    "evidence": f"{pkg}@{ver}: " + SC.MALICIOUS_VERSIONS[("npm", pkg, ver)], "purl": f"pkg:npm/{pkg}@{ver}"})
    if ci == "GitHub Actions":
        for rid in R2.sample(HARDENING_DEMO, R2.randint(0, 3)):
            t, sev, owasp, fix = RULES[rid]
            out.append({"engine": "cicd", "rule_id": rid, "title": t, "severity": sev, "owasp_cicd": owasp, "remediation": fix,
                        "file": ".github/workflows/release.yml", "line": R2.randint(8, 70), "exposure": "internal"})
    for f in out:
        f["repo"], f["business_unit"] = name, bu
        age = R2.choice([1, 2, 4, 9, 16, 30])
        f["first_seen"], f["age_days"], f["assignee"] = _ts2(age), age, R2.choice(DEVS)
        f["status"] = "open" if R2.random() > 0.2 else "fixed"
        enrich(f, crit)
    return out


def _demo_cra_records(findings):
    """Most actively exploited findings already have their CRA early warning and notification recorded (demo)."""
    start = datetime(2026, 9, 11, tzinfo=timezone.utc)
    for f in findings:
        if not (f.get("kev") or f.get("malicious")) or f.get("status") != "open" or f.get("repo") == "payments-web":
            continue
        aware = max(datetime.fromisoformat(f["first_seen"]), start)
        roll = R2.random()
        if roll < 0.75:
            rec = {"early_warning": {"at": (aware + timedelta(hours=R2.randint(3, 20))).isoformat(), "by": "r.iyer",
                                     "reference": f"ENISA-SRP-2026-{R2.randint(10000, 99999)}", "note": ""}}
            if roll < 0.6:
                rec["notification"] = {"at": (aware + timedelta(hours=R2.randint(30, 70))).isoformat(), "by": "r.iyer",
                                       "reference": rec["early_warning"]["reference"], "note": ""}
            f["regulatory"] = {"cra": rec}


def _ts2(days_ago):
    return (NOW - timedelta(days=days_ago, hours=R2.randint(0, 23))).isoformat()


CRYPTO_DEMO = {   # language family -> [(algorithm, file, line)]
    "Java": [("RSA", "src/main/java/com/orion/security/JwtSigner.java", 41), ("AES-GCM", "src/main/java/com/orion/crypto/Vault.java", 77),
             ("SHA-2", "src/main/java/com/orion/crypto/Hashes.java", 18), ("ECDSA/ECDH", "src/main/java/com/orion/tls/Handshake.java", 102),
             ("SHA-1", "src/main/java/com/orion/legacy/Checksum.java", 22)],
    "Go": [("ECDSA/ECDH", "internal/token/sign.go", 33), ("AES-GCM", "internal/vault/seal.go", 58), ("SHA-2", "internal/hash/hash.go", 12),
           ("ML-KEM", "internal/tls/hybrid.go", 27)],
    "Python": [("RSA", "app/auth/jwt.py", 19), ("AES", "app/crypto/fields.py", 44), ("Password hashing", "app/auth/passwords.py", 8),
               ("MD5", "app/reports/etag.py", 15)],
    "Node": [("RSA", "src/auth/jwt.ts", 22), ("SHA-2", "src/util/hash.ts", 5), ("HMAC-SHA256", "src/webhooks/verify.ts", 31),
             ("AES-GCM", "src/crypto/encrypt.ts", 14)],
}


def demo_extensions(repos, live):
    """Posture and cryptography inventory for generated repositories (demo only; payments-web uses its real scan)."""
    from myelin_engine import crypto_inventory as CI
    from myelin_engine import repo_posture as RP
    meta = {a[0]: a for a in CI.ALGORITHMS}
    out = {}
    base = live["posture"]["checks"]
    for r in repos:
        if r["name"] == "payments-web":
            continue
        maturity = 0.85 if r["slsa_level"] >= 3 else 0.6 if r["slsa_level"] >= 1 else 0.42
        checks = []
        for ch in base:
            roll = R2.random()
            status = "pass" if roll < maturity else "partial" if roll < maturity + 0.12 else "fail"
            if ch["id"] == "signed-releases":
                status = "pass" if r["signed"] else "fail"
            if ch["id"] == "code-review":
                status = "pass" if r["branch_protection"] else "fail"
            score = 10 if status == "pass" else 5 if status == "partial" else 0
            checks.append({**ch, "score": score, "status": status,
                           "evidence": "demo repository record", "osps": RP.FULL_OSPS.get(ch["id"], []) if status == "pass" else []})
        fam = next((k for k in CRYPTO_DEMO if k in r["language"] or (k == "Node" and "TypeScript" in r["language"])), "Java")
        assets = {}
        for alg, file, line in CRYPTO_DEMO[fam]:
            if R2.random() < 0.2 and alg not in ("RSA", "SHA-2"):
                continue
            a, family, prim, cls, lvl, _ = meta[alg]
            n = R2.randint(1, 9)
            assets[alg] = {"algorithm": alg, "family": family, "primitive": prim, "classification": cls, "nist_quantum_level": lvl,
                           "advice": CI.ADVICE[cls], "count": n, "occurrences": [{"file": file, "line": line + i * 7, "snippet": ""} for i in range(min(n, 3))]}
        out[r["name"]] = {"posture": RP.summarise(checks), "crypto": list(assets.values())}
    return out


def build():
    repos, findings, pipelines = [], [], []
    live = orchestrator.scan(os.path.join(ROOT, "demo", "vulnerable-app"), repo="payments-web", use_external=False, criticality=1.4)
    for i, r in enumerate(REPOS):
        name, bu, lang, scm, ci, crit, internet = r
        if name == "payments-web":
            fs = live["findings"]
            for f in fs:
                f.update({"business_unit": bu, "first_seen": _ts(R.randint(0, 6)), "age_days": R.randint(0, 6), "assignee": R.choice(DEVS)})
        else:
            fs = _gen_findings(r)
        findings += fs
        opn = [f for f in fs if f["status"] == "open"]
        slsa = 3 if name in ("payments-gateway", "identity-gateway", "golden-images", "card-tokenizer") else R.choice([0, 1, 1, 2, 2]) if name != "payments-web" else 0
        repos.append({"name": name, "business_unit": bu, "language": lang, "scm": scm, "ci": ci, "criticality": crit,
                      "internet_facing": internet, "open": len(opn), "p0": sum(f["priority"] == "P0" for f in opn),
                      "p1": sum(f["priority"] == "P1" for f in opn), "risk": round(max([f["mrs"] for f in opn] or [0]), 1),
                      "slsa_level": slsa, "signed": slsa >= 2, "sbom": True, "branch_protection": R.random() < 0.8 or slsa == 3,
                      "last_scan": _ts(R.choice([0, 0, 0, 1])), "owner": R.choice(DEVS), "components": R.randint(80, 1400) if name != "payments-web" else live["components"]})
        for k in range(R.randint(3, 6)):
            stages = ["checkout", "build", "sca", "sast", "secrets", "iac", "container", "sign", "deploy"]
            decision = R.choices(["pass", "warn", "block"], [6, 3, 2])[0] if name != "payments-web" or k else "block"
            pipelines.append({"id": f"run-{i:02d}{k:02d}{R.randint(100, 999)}", "repo": name, "ci": ci, "business_unit": bu,
                              "branch": R.choice(["main", "main", "release/2026.11", f"feature/{R.choice(['upi-v3', 'otp-flow', 'kyc-ocr', 'risk-calc'])}"]),
                              "commit": "%07x" % R.getrandbits(28), "author": R.choice(DEVS), "started": _ts(k * R.randint(0, 2)),
                              "duration_s": R.randint(90, 780), "decision": decision,
                              "stages": [{"name": s, "status": "skipped" if s == "sign" and slsa < 2 else ("failed" if decision == "block" and s == R.choice(["sca", "secrets", "sast"]) else "passed"),
                                          "duration_s": R.randint(4, 120)} for s in stages],
                              "gate": {"blocking": R.randint(1, 6) if decision == "block" else 0, "warnings": R.randint(0, 9)},
                              "stats": {"raw": (n_repo := sum(1 for f in findings if f["repo"] == name)) * R.randint(4, 8),
                                        "after_dedup": n_repo, "reported": n_repo}})
    findings.sort(key=lambda f: -f["mrs"])
    _demo_cra_records(findings)
    pipelines.sort(key=lambda p: p["started"], reverse=True)
    return {"tenant": {"id": "orion-fg", "name": "Orion Financial Group", "plan": "enterprise", "devs": 640, "region": "Azure Central India",
                       "sso": "Entra ID (SAML)", "created": "2026-03-02"},
            "repos": repos, "findings": findings, "pipelines": pipelines, "live_scan": {k: live[k] for k in ("repo", "duration_s", "tools", "components")},
            "sbom_payments_web": live["sbom"], "trend": _trend(), "audit": _audit(),
            "repo_ext": demo_extensions(repos, live)}


def _trend():
    out, open_, mttr = [], 1480, 21.0
    for d in range(90, -1, -1):
        open_ = max(380, open_ + R.randint(-22, 12) - (6 if d < 60 else 0))
        mttr = max(4.2, mttr - R.uniform(0.0, 0.32))
        out.append({"date": (NOW - timedelta(days=d)).date().isoformat(), "open": open_, "p0": max(3, int(open_ / 95) + R.randint(-2, 2)),
                    "fixed": R.randint(18, 64), "introduced": R.randint(10, 40), "mttr_days": round(mttr, 1),
                    "autofix_merged": R.randint(4, 22) if d < 75 else R.randint(0, 3)})
    return out


def _audit():
    ev = [("policy.updated", "s.kapoor", "Gate 'block-known-exploited' enforced for Payments BU"),
          ("exception.approved", "CISO (r.iyer)", "Risk accepted: CVE-2022-42003 in trade-capture, expires 2026-12-31"),
          ("autofix.merged", "myelin-bot", "PR #4812 payments-gateway: log4j-core 2.14.1 → 2.17.1"),
          ("deploy.blocked", "myelin-admission", "aks-prod-cin: image payments-web:latest rejected — no valid signature"),
          ("scan.completed", "myelin-ci", "netbanking-portal@main — 0 blocking, 4 warnings"),
          ("secret.validated", "myelin-ci", "GitHub PAT in svc-release confirmed live by the provider; rotation ticket SEC-2291 raised"),
          ("sso.login", "a.mehta", "Console login via Entra ID"),
          ("integration.added", "d.walsh", "Microsoft Sentinel export enabled"),
          ("report.exported", "p.nair", "PCI DSS 4.0 §6 evidence pack (PDF) generated")]
    return [{"ts": _ts(i * 0.4), "event": e, "actor": a, "detail": d} for i, (e, a, d) in enumerate(ev)]


def empty():
    """Production start: no demo data. Findings arrive from `myelin scan --server`."""
    day = NOW.date().isoformat()
    return {"tenant": {"id": "tenant", "name": "", "plan": "business", "devs": 0, "region": "", "sso": "", "created": day},
            "repos": [], "findings": [], "pipelines": [], "live_scan": {}, "sbom_payments_web": {"components": [], "metadata": {"tools": [{"name": "nerve-myelin"}]}},
            "trend": [{"date": day, "open": 0, "p0": 0, "fixed": 0, "introduced": 0, "mttr_days": 0, "autofix_merged": 0}], "audit": []}
