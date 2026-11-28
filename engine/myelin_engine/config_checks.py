# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Security settings in application, mobile and server configuration files (built-in, offline).

  Mobile         AndroidManifest.xml, network_security_config.xml, iOS Info.plist (App Transport Security)
  Frameworks     Spring (application.properties / .yml), ASP.NET (web.config), Django settings, php.ini
  Web servers    nginx and Apache httpd: directory listing, old TLS, version disclosure
  Services       sshd_config, redis.conf, mongod.conf

Rules NM-CFG-0xx; each finding carries its security domain (application, network, data, identity, compute).
"""
from __future__ import annotations

import os
import re

SKIP = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build", "target", "__pycache__", "Pods", ".gradle"}
MAX = 1_000_000


def _f(rid, domain, sev, title, rel, line, repo, ev, fix, cwe):
    return {"engine": "iac", "rule_id": rid, "domain": domain, "category": "configuration", "title": title, "severity": sev,
            "cwe": cwe, "repo": repo, "file": rel, "line": line, "evidence": ev[:200], "remediation": fix}


def _line(text, pos):
    return text.count("\n", 0, pos) + 1


def _rx(text, rx, flags=re.M | re.I):
    return re.search(rx, text, flags)


def android_manifest(text, rel, repo):
    out = []
    for rx, rid, sev, title, fix, cwe, dom in (
        (r'android:debuggable\s*=\s*"true"', "NM-CFG-001", "high", "Android app is debuggable",
         "Remove android:debuggable (release builds set it to false); a debuggable app can be attached to and its data read.", "CWE-489", "application"),
        (r'android:usesCleartextTraffic\s*=\s*"true"', "NM-CFG-002", "medium", "Android app allows plain-HTTP traffic",
         "Set usesCleartextTraffic=\"false\" (or restrict it in network_security_config to specific debug hosts).", "CWE-319", "network"),
        (r'android:allowBackup\s*=\s*"true"', "NM-CFG-003", "low", "Android app data is included in device backups",
         "Set android:allowBackup=\"false\" or define fullBackupContent / dataExtractionRules that exclude secrets.", "CWE-530", "data"),
    ):
        m = _rx(text, rx)
        if m:
            out.append(_f(rid, dom, sev, title, rel, _line(text, m.start()), repo, m.group(0), fix, cwe))
    for m in re.finditer(r"<(activity|service|receiver|provider)\b([^>]*)>", text, re.S):
        attrs = m.group(2)
        if re.search(r'android:exported\s*=\s*"true"', attrs) and not re.search(r'android:permission\s*=', attrs):
            name = (re.search(r'android:name\s*=\s*"([^"]+)"', attrs) or [None, "?"])[1]
            if m.group(1) == "activity" and "MAIN" in text[m.end():m.end() + 600] and "LAUNCHER" in text[m.end():m.end() + 600]:
                continue                                            # the launcher activity is exported on purpose
            out.append(_f("NM-CFG-004", "application", "high" if m.group(1) == "provider" else "medium",
                          f"Exported Android {m.group(1)} without a permission ({name})", rel, _line(text, m.start()), repo,
                          f"{m.group(1)} {name} exported=true", "Set android:exported=\"false\" or protect it with android:permission "
                          "(signature-level for internal components) and validate incoming intents.", "CWE-926"))
    return out


def network_security_config(text, rel, repo):
    out = []
    m = _rx(text, r'cleartextTrafficPermitted\s*=\s*"true"')
    if m:
        out.append(_f("NM-CFG-005", "network", "medium", "Network security config permits plain HTTP", rel, _line(text, m.start()), repo,
                      m.group(0), "Set cleartextTrafficPermitted=\"false\" for every domain that is not a local debug host.", "CWE-319"))
    m = _rx(text, r'<certificates\s+src\s*=\s*"user"')
    if m and "<debug-overrides" not in text[:m.start()][-400:]:
        out.append(_f("NM-CFG-006", "network", "medium", "App trusts user-installed CA certificates", rel, _line(text, m.start()), repo,
                      m.group(0), "Trust only system CAs (or pin certificates) outside debug-overrides; user CAs let anyone with device access intercept TLS.", "CWE-295"))
    return out


def info_plist(text, rel, repo):
    out = []
    for key, rid, sev, title in (("NSAllowsArbitraryLoads", "NM-CFG-007", "medium", "iOS App Transport Security is disabled"),
                                 ("NSExceptionAllowsInsecureHTTPLoads", "NM-CFG-008", "low", "iOS app allows plain HTTP for some domains"),
                                 ("NSAllowsArbitraryLoadsInWebContent", "NM-CFG-008", "low", "iOS web content may load over plain HTTP")):
        m = re.search(rf"<key>{key}</key>\s*<true\s*/>", text)
        if m:
            out.append(_f(rid, "network", sev, title, rel, _line(text, m.start()), repo, f"{key} = true",
                          "Remove the exception and serve every endpoint over HTTPS with TLS 1.2 or later.", "CWE-319"))
    return out


SPRING = [
    (r"^\s*management\.endpoints\.web\.exposure\.include\s*[=:]\s*['\"]?\*", "NM-CFG-010", "high", "application",
     "All Spring Boot Actuator endpoints are exposed", "Expose only health and info; secure the rest behind authentication.", "CWE-200"),
    (r"^\s*spring\.h2\.console\.enabled\s*[=:]\s*true", "NM-CFG-011", "high", "application", "H2 web console is enabled",
     "Disable the H2 console outside local development; it allows code execution.", "CWE-489"),
    (r"^\s*management\.endpoint\.env\.show-values\s*[=:]\s*ALWAYS", "NM-CFG-012", "high", "data", "Actuator shows environment values",
     "Use show-values: NEVER (or WHEN_AUTHORIZED).", "CWE-200"),
    (r"^\s*server\.ssl\.enabled\s*[=:]\s*false", "NM-CFG-013", "medium", "network", "Server TLS is disabled",
     "Enable TLS on the server or terminate it at a trusted proxy and enforce HTTPS.", "CWE-319"),
    (r"^\s*server\.error\.include-stacktrace\s*[=:]\s*always", "NM-CFG-014", "low", "application", "Stack traces are returned to clients",
     "Set server.error.include-stacktrace=never.", "CWE-209"),
]
WEBCONFIG = [
    (r'<customErrors\s+[^>]*mode\s*=\s*"Off"', "NM-CFG-020", "medium", "application", "Detailed ASP.NET errors are shown to users",
     "Set customErrors mode=\"RemoteOnly\" or \"On\".", "CWE-209"),
    (r'<compilation\s+[^>]*debug\s*=\s*"true"', "NM-CFG-021", "low", "application", "ASP.NET debug compilation is on",
     "Set compilation debug=\"false\" for production.", "CWE-489"),
    (r'<httpCookies\s+[^>]*requireSSL\s*=\s*"false"', "NM-CFG-022", "medium", "data", "ASP.NET cookies are sent over plain HTTP",
     "Set httpCookies requireSSL=\"true\" httpOnlyCookies=\"true\".", "CWE-614"),
    (r'<trace\s+[^>]*enabled\s*=\s*"true"', "NM-CFG-023", "medium", "application", "ASP.NET tracing is enabled",
     "Disable trace.axd in production.", "CWE-200"),
    (r'<pages\s+[^>]*validateRequest\s*=\s*"false"', "NM-CFG-024", "medium", "application", "ASP.NET request validation is disabled",
     "Keep request validation on and encode output.", "CWE-79"),
]
DJANGO = [
    (r"^\s*ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]", "NM-CFG-030", "medium", "application", "Django accepts any Host header",
     "List the real host names in ALLOWED_HOSTS (prevents host-header poisoning of reset links and caches).", "CWE-644"),
    (r"^\s*SECURE_SSL_REDIRECT\s*=\s*False", "NM-CFG-031", "low", "network", "Django does not redirect HTTP to HTTPS",
     "Set SECURE_SSL_REDIRECT = True (and SECURE_HSTS_SECONDS).", "CWE-319"),
    (r"^\s*CORS_ALLOW_ALL_ORIGINS\s*=\s*True|^\s*CORS_ORIGIN_ALLOW_ALL\s*=\s*True", "NM-CFG-032", "medium", "application",
     "Django CORS allows every origin", "List trusted origins in CORS_ALLOWED_ORIGINS.", "CWE-942"),
]
PHPINI = [
    (r"^\s*allow_url_include\s*=\s*(On|1)", "NM-CFG-040", "high", "application", "PHP allows remote file inclusion",
     "Set allow_url_include = Off.", "CWE-98"),
    (r"^\s*display_errors\s*=\s*(On|1)", "NM-CFG-041", "low", "application", "PHP shows errors to users", "Set display_errors = Off and log errors.", "CWE-209"),
    (r"^\s*session\.cookie_secure\s*=\s*(Off|0)", "NM-CFG-042", "medium", "data", "PHP session cookie is sent over plain HTTP",
     "Set session.cookie_secure = On and session.cookie_httponly = On.", "CWE-614"),
]
NGINX = [
    (r"^\s*autoindex\s+on\s*;", "NM-CFG-050", "medium", "application", "nginx directory listing is on", "Set autoindex off.", "CWE-548"),
    (r"^\s*ssl_protocols\s+[^;]*\b(SSLv3|TLSv1|TLSv1\.1)\b(?!\.[23])", "NM-CFG-051", "medium", "network", "nginx allows TLS versions below 1.2",
     "Use ssl_protocols TLSv1.2 TLSv1.3.", "CWE-326"),
    (r"^\s*server_tokens\s+on\s*;", "NM-CFG-052", "low", "application", "nginx discloses its version", "Set server_tokens off.", "CWE-200"),
]
APACHE = [
    (r"^\s*Options\s+[^\n#]*(?<![-\w])\+?Indexes\b", "NM-CFG-053", "medium", "application", "Apache directory listing is on",
     "Remove Indexes from Options (Options -Indexes).", "CWE-548"),
    (r"^\s*SSLProtocol\s+[^\n#]*(\+?TLSv1(?!\.[23])\b|\+?TLSv1\.1\b|\+?SSLv3\b|\ball\b(?![^\n]*-TLSv1\.1))", "NM-CFG-054", "medium", "network",
     "Apache allows TLS versions below 1.2", "Use SSLProtocol -all +TLSv1.2 +TLSv1.3.", "CWE-326"),
    (r"^\s*ServerSignature\s+On|^\s*ServerTokens\s+(Full|OS)", "NM-CFG-055", "low", "application", "Apache discloses its version",
     "Set ServerTokens Prod and ServerSignature Off.", "CWE-200"),
]
SSHD = [
    (r"^\s*PermitRootLogin\s+yes", "NM-CFG-060", "high", "identity", "SSH allows root login", "Set PermitRootLogin no (or prohibit-password).", "CWE-250"),
    (r"^\s*PasswordAuthentication\s+yes", "NM-CFG-061", "medium", "identity", "SSH allows password sign-in", "Use keys: PasswordAuthentication no.", "CWE-521"),
    (r"^\s*PermitEmptyPasswords\s+yes", "NM-CFG-062", "critical", "identity", "SSH allows empty passwords", "Set PermitEmptyPasswords no.", "CWE-258"),
    (r"^\s*(Ciphers|MACs)\s+[^\n]*(3des|arcfour|blowfish|cbc|hmac-md5|hmac-sha1\b)", "NM-CFG-063", "medium", "network", "SSH allows weak ciphers or MACs",
     "Use the OpenSSH defaults (chacha20-poly1305, aes-gcm, hmac-sha2-etm).", "CWE-327"),
]


def _scan_rules(text, rel, repo, rules):
    out = []
    for rx, rid, sev, dom, title, fix, cwe in rules:
        m = re.search(rx, text, re.M | re.I)
        if m:
            out.append(_f(rid, dom, sev, title, rel, _line(text, m.start()), repo, m.group(0).strip(), fix, cwe))
    return out


def redis_conf(text, rel, repo):
    out = []
    if re.search(r"^\s*protected-mode\s+no", text, re.M) or (re.search(r"^\s*bind\s+0\.0\.0\.0", text, re.M) and not re.search(r"^\s*requirepass\s+\S", text, re.M)
                                                              and not re.search(r"^\s*aclfile\s", text, re.M)):
        out.append(_f("NM-CFG-070", "data", "high", "Redis accepts unauthenticated connections from the network", rel, 1, repo,
                      "protected-mode no or bind 0.0.0.0 without requirepass/ACLs",
                      "Bind to private interfaces, keep protected-mode yes and require authentication (ACL users).", "CWE-306"))
    return out


def mongod_conf(text, rel, repo):
    if re.search(r"bindIp\s*:\s*['\"]?0\.0\.0\.0|bindIpAll\s*:\s*true", text) and not re.search(r"authorization\s*:\s*['\"]?enabled", text):
        return [_f("NM-CFG-071", "data", "high", "MongoDB listens on all interfaces without authorisation", rel, 1, repo,
                   "bindIp 0.0.0.0 and security.authorization not enabled",
                   "Set security.authorization: enabled and bind to private addresses.", "CWE-306")]
    return []


def scan_path(root: str, repo: str) -> list[dict]:
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP]
        for fn in files:
            low = fn.lower()
            p = os.path.join(d, fn)
            rel = os.path.relpath(p, root).replace("\\", "/")
            kind = None
            if fn == "AndroidManifest.xml":
                kind = android_manifest
            elif low == "network_security_config.xml" or (low.endswith(".xml") and "/res/xml/" in rel and "network" in low):
                kind = network_security_config
            elif fn == "Info.plist":
                kind = info_plist
            elif re.fullmatch(r"application(-[\w]+)?\.(properties|ya?ml)|bootstrap(-[\w]+)?\.(properties|ya?ml)", low):
                kind = lambda t, r, repo_: _scan_rules(_yaml_to_props(t), r, repo_, SPRING)  # noqa: E731
            elif low in ("web.config",) or re.fullmatch(r"web\.\w+\.config", low):
                kind = lambda t, r, repo_: _scan_rules(t, r, repo_, WEBCONFIG)  # noqa: E731
            elif low in ("settings.py", "production.py", "prod.py") or (low.endswith(".py") and "/settings/" in rel):
                kind = lambda t, r, repo_: _scan_rules(t, r, repo_, DJANGO)  # noqa: E731
            elif low in ("php.ini", ".user.ini") or low.endswith("-php.ini"):
                kind = lambda t, r, repo_: _scan_rules(t, r, repo_, PHPINI)  # noqa: E731
            elif low == "nginx.conf" or (low.endswith(".conf") and ("nginx" in rel or "sites-" in rel)):
                kind = lambda t, r, repo_: _scan_rules(t, r, repo_, NGINX)  # noqa: E731
            elif low in ("httpd.conf", "apache2.conf", "ssl.conf", ".htaccess") or (low.endswith(".conf") and ("apache" in rel or "httpd" in rel)):
                kind = lambda t, r, repo_: _scan_rules(t, r, repo_, APACHE)  # noqa: E731
            elif low in ("sshd_config",) or rel.endswith("sshd_config.d/" + fn):
                kind = lambda t, r, repo_: _scan_rules(t, r, repo_, SSHD)  # noqa: E731
            elif low in ("redis.conf",) or (low.endswith(".conf") and "redis" in low):
                kind = redis_conf
            elif low in ("mongod.conf", "mongodb.conf"):
                kind = mongod_conf
            if not kind:
                continue
            try:
                if os.path.getsize(p) > MAX:
                    continue
                text = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            out += kind(text, rel, repo)
    return out


def _yaml_to_props(text: str) -> str:
    """Flatten simple YAML (application.yml) into dotted properties so one set of rules reads both formats."""
    if not re.search(r"^\s*[\w.-]+\s*:\s*$", text, re.M):
        return text
    out, stack = [], []
    for ln in text.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#") or ln.lstrip().startswith("-"):
            continue
        indent = len(ln) - len(ln.lstrip())
        m = re.match(r"\s*([\w.\-\"']+)\s*:\s*(.*)$", ln)
        if not m:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = m.group(1).strip("\"'")
        if m.group(2).strip() == "":
            stack.append((indent, key))
        else:
            out.append(".".join([k for _, k in stack] + [key]) + "=" + m.group(2).strip().strip("\"'"))
    return text + "\n" + "\n".join(out)
