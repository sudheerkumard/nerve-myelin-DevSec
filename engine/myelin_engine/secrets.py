# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Built-in secrets scanner (regex + entropy). Gitleaks/Trivy results are merged when available."""
import math
import os
import re

from . import secret_validation

PATTERNS = [
    ("NM-SEC-001", "AWS Access Key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "critical"),
    ("NM-SEC-002", "GitHub Personal Access Token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "critical"),
    ("NM-SEC-003", "GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", "critical"),
    ("NM-SEC-004", "Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "high"),
    ("NM-SEC-005", "Private key", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critical"),
    ("NM-SEC-006", "Azure Storage account key", r"AccountKey=[A-Za-z0-9+/=]{80,}", "critical"),
    ("NM-SEC-007", "Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "high"),
    ("NM-SEC-008", "Stripe live secret key", r"\bsk_live_[0-9a-zA-Z]{24,}\b", "critical"),
    ("NM-SEC-012", "OpenAI API key", r"\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b", "critical"),
    ("NM-SEC-013", "Anthropic API key", r"\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b", "critical"),
    ("NM-SEC-014", "Hugging Face access token", r"\bhf_[A-Za-z0-9]{34,}\b", "high"),
    ("NM-SEC-015", "Azure OpenAI / Cognitive Services key", r"(?i)(azure_openai_(api_)?key|openai_api_key|cognitive_?services_key|ocp-apim-subscription-key)[\"']?\s*[:=]\s*[\"'][0-9a-f]{32}[\"']", "critical"),
    # source control, CI/CD and package registries
    ("NM-SEC-016", "GitLab access token", r"\bglpat-[A-Za-z0-9_-]{20,}\b|\bgl(?:dt|rt|ptt|cbt|oas|imt|agent)-[A-Za-z0-9_-]{20,}\b", "critical"),
    ("NM-SEC-017", "Bitbucket app password / access token", r"\bATBB[A-Za-z0-9_=.-]{28,}\b|\bATCTT3x[A-Za-z0-9_=.-]{100,}\b", "critical"),
    ("NM-SEC-018", "Atlassian API token", r"\bATATT3x[A-Za-z0-9_\-=]{150,}\b", "high"),
    ("NM-SEC-019", "npm access token", r"\bnpm_[A-Za-z0-9]{36}\b", "critical"),
    ("NM-SEC-020", "PyPI upload token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b", "critical"),
    ("NM-SEC-021", "Docker Hub personal access token", r"\bdckr_pat_[A-Za-z0-9_-]{27,}\b", "high"),
    ("NM-SEC-022", "NuGet API key", r"\boy2[a-z0-9]{43}\b", "high"),
    ("NM-SEC-023", "RubyGems API key", r"\brubygems_[0-9a-f]{48}\b", "high"),
    ("NM-SEC-024", "Artifactory API or reference token", r"\bAKCp[A-Za-z0-9]{69}\b|\bcmVmd[A-Za-z0-9]{59}\b", "high"),
    ("NM-SEC-025", "CircleCI / Travis / Buildkite token", r"\bCCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}\b|\bbkua_[a-f0-9]{40}\b", "high"),
    # cloud providers and infrastructure
    ("NM-SEC-026", "Google Cloud service account key", r"\\?\"type\\?\"\s*:\s*\\?\"service_account\\?\"[\s\S]{0,400}?\\?\"private_key\\?\"\s*:", "critical"),
    ("NM-SEC-027", "Google OAuth client secret", r"\bGOCSPX-[A-Za-z0-9_-]{28}\b", "high"),
    ("NM-SEC-028", "Azure Entra ID client secret", r"(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.-])", "critical"),
    ("NM-SEC-029", "Azure SAS token", r"[?&]sv=20\d\d-\d\d-\d\d&[^\s\"']*?sig=[A-Za-z0-9%/+=]{40,}", "high"),
    ("NM-SEC-030", "Azure connection string key", r"(?i)(?:SharedAccessKey|AccountKey|PrimaryKey)=[A-Za-z0-9+/]{40,}={0,2}", "critical"),
    ("NM-SEC-031", "Alibaba Cloud AccessKey ID", r"\bLTAI[A-Za-z0-9]{12,20}\b", "high"),
    ("NM-SEC-032", "Tencent Cloud SecretId", r"\bAKID[A-Za-z0-9]{32}\b", "high"),
    ("NM-SEC-033", "DigitalOcean token", r"\bdo[opr]_v1_[a-f0-9]{64}\b", "critical"),
    ("NM-SEC-034", "HashiCorp Vault token", r"\bhv[sbr]\.[A-Za-z0-9_-]{24,}\b", "critical"),
    ("NM-SEC-035", "Terraform Cloud API token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,}\b", "critical"),
    ("NM-SEC-036", "Doppler / Pulumi token", r"\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b|\bpul-[a-f0-9]{40}\b", "high"),
    ("NM-SEC-037", "Heroku / Fly.io / Vercel token", r"\bHRKU-AA[0-9a-zA-Z_-]{58}\b|\bFlyV1 fm\d_[A-Za-z0-9+/=,_-]{100,}", "high"),
    ("NM-SEC-038", "Cloudflare API token", r"(?i)cloudflare[\w-]{0,20}[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_-]{40})\b", "high"),
    ("NM-SEC-039", "Kubernetes client key in kubeconfig", r"client-key-data:\s*[A-Za-z0-9+/=]{100,}", "critical"),
    ("NM-SEC-040", "Database connection string with password",
     r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|jdbc:[a-z]+)://[^\s:/@\"']{1,64}:([^\s@/\"'$]{6,128})@[\w.-]+", "high"),
    # payments, communication and SaaS
    ("NM-SEC-041", "Stripe restricted key / webhook secret", r"\brk_live_[0-9a-zA-Z]{24,}\b|\bwhsec_[0-9a-zA-Z]{32,}\b", "critical"),
    ("NM-SEC-042", "PayPal Braintree access token", r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b", "critical"),
    ("NM-SEC-043", "Square access token", r"\bEAAA[A-Za-z0-9_-]{60}\b|\bsq0csp-[A-Za-z0-9_-]{43}\b", "critical"),
    ("NM-SEC-044", "Shopify access token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", "critical"),
    ("NM-SEC-045", "Twilio API key", r"\bSK[0-9a-f]{32}\b", "high"),
    ("NM-SEC-046", "SendGrid API key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "critical"),
    ("NM-SEC-047", "Mailgun / Mailchimp API key", r"\bkey-[0-9a-f]{32}\b|\b[0-9a-f]{32}-us\d{1,2}\b", "high"),
    ("NM-SEC-048", "Slack webhook", r"https://hooks\.slack\.com/(?:services|workflows)/T[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]{20,}", "high"),
    ("NM-SEC-049", "Microsoft Teams / Discord webhook", r"https://[\w-]+\.webhook\.office\.com/webhookb2/[\w@/-]{60,}|https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]{60,}", "high"),
    ("NM-SEC-050", "Telegram bot token", r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b", "high"),
    ("NM-SEC-051", "Discord bot token", r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b", "high"),
    ("NM-SEC-052", "Linear / Notion / Airtable / Asana token", r"\blin_api_[A-Za-z0-9]{40}\b|\bsecret_[A-Za-z0-9]{43}\b|\bntn_[A-Za-z0-9]{46}\b|\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", "high"),
    ("NM-SEC-053", "Postman API key", r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b", "high"),
    ("NM-SEC-054", "Datadog / New Relic / Sentry / Grafana token",
     r"\bNRAK-[A-Z0-9]{27}\b|\bsntry[su]_[A-Za-z0-9+/=_]{60,}|\bglc_[A-Za-z0-9+/]{32,}={0,2}|\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b|\bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b", "high"),
    ("NM-SEC-055", "Okta / Auth0 / Twitch / Facebook token", r"\b00[A-Za-z0-9_-]{40}\b(?=.*okta)|\bEAA[A-Za-z0-9]{100,}\b", "high"),
    ("NM-SEC-056", "Age / PGP / PuTTY private key", r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b|-----BEGIN PGP PRIVATE KEY BLOCK-----|PuTTY-User-Key-File-\d: ", "critical"),  # myelin:ignore[NM-SEC-056] -- the pattern itself
    ("NM-SEC-057", "Encrypted private key or keystore password",
     r"-----BEGIN ENCRYPTED PRIVATE KEY-----|(?i:\b(?:keystore|truststore|key_store)[._-]?pass(?:word)?\b)\s*[:=]\s*['\"]?[^\s'\"$]{6,}", "high"),  # myelin:ignore[NM-SEC-057] -- the pattern itself
    ("NM-SEC-058", "Package registry credentials file",
     r"(?m)^\s*//[^\s]+/:_authToken=[^\s$]{10,}|^\s*_auth\s*=\s*[A-Za-z0-9+/=]{16,}", "high"),
    ("NM-SEC-059", "Generic bearer / basic credential in a URL or header",
     r"(?i:authorization)['\"]?\s*[:=]\s*['\"](?i:bearer|basic)\s+[A-Za-z0-9._~+/=-]{24,}['\"]|https?://[^\s:/@\"']{2,64}:[^\s@/\"'$]{6,64}@(?!example\.|localhost)[\w.-]+\.[a-z]{2,}", "high"),
    ("NM-SEC-060", "AI provider key (Groq, Mistral, Cohere, Replicate, Perplexity, xAI)",
     r"\bgsk_[A-Za-z0-9]{52}\b|\br8_[A-Za-z0-9]{37}\b|\bpplx-[A-Za-z0-9]{48}\b|\bxai-[A-Za-z0-9]{80}\b", "critical"),
    ("NM-SEC-009", "JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "medium"),
    ("NM-SEC-010", "Generic credential assignment",
     r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", "high"),
]
COMPILED = [(rid, title, re.compile(rx), sev) for rid, title, rx, sev in PATTERNS]
# A literal that looks like a real password (upper, lower, digit and symbol) on a line or block about credentials:
# catches documented default/demo logins in comments, README tables and login pages, which assignment rules miss.
PW = r"(?<![\w@#$%!&./+=-])(?=[^\s<>\"'|/]*[A-Z])(?=[^\s<>\"'|/]*[a-z])(?=[^\s<>\"'|/]*\d)(?=[^\s<>\"'|/]*[@#$%!&])[A-Za-z\d@#$%!&._-]{8,40}"
USERNAME = r"(?:admin(?:istrator)?|root|sa|user|analyst|viewer|operator|responder|guest|test|demo|manager|auditor|support)\w*"
# "admin / Pa$$w0rd", "admin: Pa$$w0rd", "| admin | Pa$$w0rd |", "<td>admin</td><td>Pa$$w0rd</td>", "password: Pa$$w0rd"  # myelin:ignore[NM-SEC-011] -- examples of the pattern, not credentials
STRONG_PW = re.compile(
    r"(?i:\b" + USERNAME + r"\b)`?(?:\s*[/:|,]\s*`?|\s*(?:</?b>)*\s*</td>\s*<td>\s*(?:<[^>]+>)*\s*|\s+)(" + PW + r")(?![\w@#$%!&])"
    r"|(?i:passw(?:or)?d|pwd|credentials?)\b[^\n]{0,20}?[:=]?\s*['\"]?(" + PW + r")(?![\w@#$%!&])")
EMAILISH = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.]+$")
HASHLIKE = re.compile(r"(?i)^(pbkdf2|argon2|bcrypt|scrypt|sha\d+|md5)[$_:]|^\$\d[aby]?\$")
_TEST_LOWER = re.compile(r"(?i)(^|/)([\w.-]*[._-])?(tests?|testing|testdata|testassets|test[_-]?data|fixtures?|mocks?|"
                         r"__tests__|specs?|samples?|examples?)([._-][\w.-]*)?/|(^|/)test_[^/]+$|_test\.\w+$|\.(spec|test)\.\w+$")
_TEST_CAMEL = re.compile(r"(^|[/.])(\w*[a-z])?Tests?([A-Z]\w*)?/|(^|/)\w+Tests?\.\w+$")


class _TestPath:
    """Test, fixture, sample and example locations: snake/kebab names (tests/, test-data/, foo.tests/) and .NET/Java
    CamelCase project folders (UnitTests/, TestCertificates/, Foo.IntegrationTests/)."""
    def search(self, path):
        p = str(path or "").replace("\\", "/")
        return _TEST_LOWER.search(p) or _TEST_CAMEL.search(p)


TEST_PATH = _TestPath()
# Credentials published on purpose for local emulators and documentation: never real secrets.
KNOWN_PUBLIC = {
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",   # Azure Storage emulator (Azurite)
    "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD9b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==",   # Azure Cosmos DB emulator
    "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",                           # AWS documentation
}

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", ".pytest_cache", ".mypy_cache",
             ".ruff_cache", ".tox", ".nox", "htmlcov", ".coverage", ".next", ".cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".avif", ".bmp", ".tif", ".tiff", ".pdf", ".zip", ".gz", ".jar", ".so", ".dll", ".exe", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".docx", ".pptx", ".xlsx"}
PLACEHOLDERS = re.compile(r"(?i)(changeme|example|placeholder|dummy|xxxx|<.*>|\$\{|\{\{)")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def redact(s: str) -> str:
    return s[:4] + "…" + s[-2:] if len(s) > 8 else "****"


def scan_path(root: str, repo: str = "local") -> list[dict]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            try:
                if os.path.getsize(p) > 1_000_000:
                    continue
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            rel = os.path.relpath(p, root)
            is_test = bool(TEST_PATH.search(rel.replace("\\", "/")))
            for i, line in enumerate(lines, 1):
                if not is_test:
                    for m in STRONG_PW.finditer(line):
                        val = m.group(1) or m.group(2)
                        if not val or EMAILISH.match(val) or PLACEHOLDERS.search(val) or HASHLIKE.search(val):
                            continue
                        out.append({
                            "engine": "secrets", "rule_id": "NM-SEC-011", "title": "Default or demo password documented in source",
                            "severity": "medium" if DOC_PATH.search(rel.replace("\\", "/")) else "high", "file": rel, "line": i,
                            "repo": repo, "evidence": redact(val), "cwe": "CWE-1392", "_value": val,
                            **({"context": "documentation"} if DOC_PATH.search(rel.replace("\\", "/")) else {}),
                            "remediation": "Remove the password from code, comments and pages. Ship without default accounts (create "
                                           "the first administrator at install time with a one-time password) and change any "
                                           "deployed account that uses it.",
                            "validated": False, "exposure": "internet",
                        })
                        break
                for rid, title, rx, sev in COMPILED:
                    m = rx.search(line)
                    if not m:
                        continue
                    val = m.group(m.lastindex or 0)
                    if PLACEHOLDERS.search(val) or val in KNOWN_PUBLIC or any(k in line for k in KNOWN_PUBLIC):
                        continue
                    if rid == "NM-SEC-010" and entropy(val) < 3.0:
                        continue
                    state = secret_validation.validate(rid, val) if not is_test else "not_checked"
                    ctx = "test" if is_test else "documentation" if DOC_PATH.search(rel.replace("\\", "/")) else "code"
                    out.append({
                        "engine": "secrets", "rule_id": rid, "title": f"{title} committed to source",
                        "severity": ("low" if ctx == "test" and state != "live" else "medium" if ctx == "documentation"
                                     and state != "live" and sev == "high" else sev),
                        "file": rel, "line": i, "repo": repo, "_value": val, **({"context": ctx} if ctx != "code" else {}),
                        "evidence": redact(val) + {"live": " · provider accepted it (live)", "revoked": " · provider rejected it (revoked)"}.get(state, ""),
                        "cwe": "CWE-798",
                        "remediation": "Revoke and rotate the credential, purge it from git history "
                                       "(git filter-repo), and move it to a secrets manager (Key Vault / Vault / AWS SM).",
                        "validated": state == "live", "validation": state,
                        "high_confidence": rid in secret_validation.HIGH_CONFIDENCE,
                        "exposure": "internet",
                    })
    return _group(out)


def _group(found: list[dict]) -> list[dict]:
    """The same credential copied into several files is one secret to rotate: one finding, every location listed."""
    import hashlib
    by, out = {}, []
    for f in found:
        val = f.pop("_value", None)
        if val is None:
            out.append(f)
            continue
        key = hashlib.sha256(f"{f['rule_id']}\0{val}".encode()).hexdigest()[:16]
        if key in by:
            g = by[key]
            g["locations"].append({"file": f["file"], "line": f["line"]})
            g["occurrences"] = len(g["locations"])
            if f.get("context") is None and g.get("context"):          # a real-code copy outranks the test copy
                for k in ("severity", "file", "line"):
                    g[k] = f[k]
                g.pop("context", None)
            continue
        f["secret_id"], f["locations"], f["occurrences"] = key, [{"file": f["file"], "line": f["line"]}], 1
        by[key] = f
        out.append(f)
    return out


# ------------------------------------------------------------------ Gitleaks consolidation
# Gitleaks reports one result per commit that touched a secret, so one leaked key can become dozens of findings.
# Results are grouped per secret (rule + value hash; the value itself is never kept), classified as present now or
# history-only, and test fixtures and placeholders are separated from real credentials.
PROVIDER_RULES = re.compile(r"(?i)aws|github|gitlab|private-key|stripe|slack|gcp|google|azure|openai|anthropic|"
                            r"twilio|sendgrid|npm|pypi|shopify|square|heroku|digitalocean|databricks|hashicorp|jwt-base64")
DOC_PATH = re.compile(r"(?i)(^|/)(docs?|examples?|samples?|demo)/|\.(md|rst|adoc|txt)$|readme")
PLACEHOLDER_VALUE = re.compile(r"(?i)^(.)\1{5,}$|changeme|example|placeholder|dummy|sample|fake|your[_-]|redacted|"
                               r"xxxx|test(ing)?[_-]?(key|token|secret)|^<.*>$|^\$\{.*\}$|^\{\{.*\}\}$|^%.*%$|1234567")


def consolidate_gitleaks(doc, root: str):
    """Group raw Gitleaks results per distinct secret. Returns the same list shape with extra keys
    (_occurrences, _in_head, _context, _hash) that normalize.gitleaks understands."""
    import hashlib
    groups: dict[str, dict] = {}
    for d in doc or []:
        secret = str(d.get("Secret") or "")
        rule = str(d.get("RuleID") or "")
        if not secret or PLACEHOLDER_VALUE.search(secret) or secret in KNOWN_PUBLIC or any(k in secret for k in KNOWN_PUBLIC):
            continue
        if rule == "generic-api-key" and (float(d.get("Entropy") or entropy(secret)) < 3.3 or EMAILISH.match(secret)
                                          or HASHLIKE.search(secret)):
            continue
        h = hashlib.sha256(f"{rule}\0{secret}".encode()).hexdigest()[:16]
        g = groups.get(h)
        occ = {"file": d.get("File"), "line": d.get("StartLine"), "commit": (d.get("Commit") or "")[:12] or None,
               "date": d.get("Date")}
        if g is None:
            g = dict(d)
            g["_hash"], g["_occurrences"], g["_secret"] = h, [], secret
            groups[h] = g
        g["_occurrences"].append(occ)
    out = []
    for g in groups.values():
        secret = g.pop("_secret")
        files = {o["file"] for o in g["_occurrences"] if o.get("file")}
        in_head = []
        for f in sorted(files):
            p = os.path.join(root, f)
            try:
                if os.path.isfile(p) and os.path.getsize(p) < 5_000_000:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        for n, line in enumerate(fh, 1):
                            if secret in line:
                                in_head.append({"file": f, "line": n})
                                break
            except OSError:
                continue
        g["_in_head"] = in_head
        where = in_head[0]["file"] if in_head else (g.get("File") or "")
        g["_context"] = ("test" if TEST_PATH.search(where) else "documentation" if DOC_PATH.search(where) else "code")
        g["_occurrences"].sort(key=lambda o: str(o.get("date") or ""), reverse=True)
        if in_head:
            g["File"], g["StartLine"], g["Commit"] = in_head[0]["file"], in_head[0]["line"], None
        g["Secret"] = secret[:4]
        g["Match"] = ""
        out.append(g)
    return out
