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
TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|fixtures?|testdata)/|(^|/)test_[^/]+$|_test\.\w+$|\.spec\.\w+$")

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
                            "severity": "high", "file": rel, "line": i, "repo": repo, "evidence": redact(val), "cwe": "CWE-1392",
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
                    if PLACEHOLDERS.search(val):
                        continue
                    if rid == "NM-SEC-010" and entropy(val) < 3.0:
                        continue
                    state = secret_validation.validate(rid, val) if not is_test else "not_checked"
                    out.append({
                        "engine": "secrets", "rule_id": rid, "title": f"{title} committed to source",
                        "severity": sev, "file": rel, "line": i, "repo": repo,
                        "evidence": redact(val) + {"live": " · provider accepted it (live)", "revoked": " · provider rejected it (revoked)"}.get(state, ""),
                        "cwe": "CWE-798",
                        "remediation": "Revoke and rotate the credential, purge it from git history "
                                       "(git filter-repo), and move it to a secrets manager (Key Vault / Vault / AWS SM).",
                        "validated": state == "live", "validation": state,
                        "high_confidence": rid in secret_validation.HIGH_CONFIDENCE,
                        "exposure": "internet",
                    })
    return out
