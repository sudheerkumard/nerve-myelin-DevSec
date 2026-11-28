# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""DAST / API engine — tests a running web API.

Two depths:

  safe (default, built in)  Read-only checks: GET, HEAD and OPTIONS requests only, rate-limited and capped. No payloads,
                            no fuzzing, no state changes. Safe to run against production with the owner's permission.
                            Checks TLS, HTTPS enforcement, security headers, CORS, cookies, version disclosure, verbose
                            errors, exposed API documentation and — given an OpenAPI spec — operations that declare
                            authentication but answer without it (OWASP API Security Top 10 2023).

  zap (optional)            OWASP ZAP via Docker: --zap runs the passive baseline; --zap --active runs ZAP's API scan,
                            which SENDS ATTACK PAYLOADS. Active scans need --authorized and should target non-production.

Only scan systems you own or have written permission to test.
"""
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "RAT-Flea-DevSec-DAST/1.2 (+authorised security scan)"
DOC_PATHS = ["/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/v3/api-docs", "/v2/api-docs",
             "/swagger-ui.html", "/swagger-ui/", "/swagger/index.html", "/docs", "/redoc", "/api-docs", "/graphql"]
STACK = re.compile(r"(Traceback \(most recent call last\)|at [\w$.]+\([\w]+\.java:\d+\)|System\.\w+Exception|"
                   r"Microsoft\.AspNetCore|Stack trace:|Exception in thread|<b>Warning</b>:|PHP (Fatal|Parse) error|"
                   r"ORA-\d{5}|SQLSTATE\[|org\.springframework|django\.\w+\.exceptions|node_modules/express)", re.I)
VERSION_RX = re.compile(r"\d+\.\d+")
OWASP = {"API2": "API2:2023 Broken Authentication", "API8": "API8:2023 Security Misconfiguration",
         "API9": "API9:2023 Improper Inventory Management", "API1": "API1:2023 Broken Object Level Authorization",
         "API3": "API3:2023 Broken Object Property Level Authorization", "API5": "API5:2023 Broken Function Level Authorization"}


def host_guard(allow_private=False):
    """Return a checker that refuses hosts resolving to internal addresses (SSRF protection for hosted scanning).
    Cloud metadata, loopback, link-local, multicast and unspecified addresses are always refused; private ranges
    only when allow_private is False."""
    import ipaddress

    def check(host):
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            raise RuntimeError(f"cannot resolve {host}") from None
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved \
                    or str(ip) in ("169.254.169.254", "fd00:ec2::254"):
                raise RuntimeError(f"{host} resolves to {ip}, which is not allowed for online scanning")
            if ip.is_private and not allow_private:
                raise RuntimeError(f"{host} resolves to private address {ip}; online scanning of internal networks is disabled "
                                   "(self-hosted installations can enable MYELIN_DAST_ALLOW_PRIVATE)")
    return check


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    """Minimal rate-limited HTTP client that never follows redirects and never sends bodies."""

    AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "api-key", "x-auth-token")

    def __init__(self, headers=None, timeout=15, delay=0.2, max_requests=300, verify_tls=True, scope_host=None, guard=None):
        self.headers = {"User-Agent": UA, "Accept": "application/json, */*", **(headers or {})}
        self.timeout, self.delay, self.max, self.count = timeout, delay, max_requests, 0
        self.scope_host = scope_host                     # every request must stay on this host (scope lock)
        self.guard = guard                               # optional host_guard(); checked before every request
        ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self.opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        self.log = []

    def request(self, method, url, headers=None, auth=True, identity=None):
        """identity=None: default headers; identity=(name, headers): replace credentials with that user's;
        auth=False: send no credentials at all (anonymous)."""
        assert method in ("GET", "HEAD", "OPTIONS"), "safe mode only sends read-only methods"
        if self.scope_host and urllib.parse.urlsplit(url).hostname != self.scope_host:
            raise RuntimeError(f"out of scope: {url} (scan is locked to {self.scope_host})")
        if self.guard:
            self.guard(urllib.parse.urlsplit(url).hostname)
        if self.count >= self.max:
            raise RuntimeError(f"request budget of {self.max} reached")
        self.count += 1
        if self.count > 1:
            time.sleep(self.delay)
        anon = {k: v for k, v in self.headers.items() if k.lower() not in self.AUTH_HEADERS}
        h = dict(self.headers) if auth and identity is None else anon
        if identity is not None and auth:
            h.update(identity[1])
        h.update(headers or {})
        req = urllib.request.Request(url, method=method, headers=h)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                body = _read_capped(r, self.timeout) if method != "HEAD" else b""
                res = (r.status, {k.lower(): v for k, v in r.headers.items()}, r.headers.get_all("Set-Cookie") or [], body)
        except urllib.error.HTTPError as e:
            res = (e.code, {k.lower(): v for k, v in e.headers.items()}, e.headers.get_all("Set-Cookie") or [], _read_capped(e, self.timeout))
        self.log.append({"method": method, "url": url, "status": res[0], "authenticated": auth,
                         "identity": identity[0] if identity and auth else ("anonymous" if not auth else "default")})
        return res


# Endpoints that are normally public: liveness/readiness, sign-in flows, static assets and API documentation
PUBLIC_BY_DESIGN = re.compile(r"(^|/)(health|healthz|livez|readyz|ready|ping|status|login|logout|signin|auth(/|$)|oauth|oidc|"
                              r"\.well-known|favicon|robots\.txt|static|assets|docs|redoc|swagger|openapi)", re.I)

STREAMING_TYPES = ("text/event-stream", "application/x-ndjson", "multipart/x-mixed-replace", "application/stream+json")


def _read_capped(r, timeout, limit=200_000):
    """Read at most `limit` bytes and for at most `timeout` seconds in total. Streaming endpoints (server-sent
    events, NDJSON feeds) never end, so their body is not read at all: status and headers are enough."""
    ctype = (r.headers.get("Content-Type") or "").lower()
    if any(t in ctype for t in STREAMING_TYPES):
        return b""
    deadline, buf = time.monotonic() + timeout, bytearray()
    read = getattr(r, "read1", None) or r.read
    while len(buf) < limit and time.monotonic() < deadline:
        chunk = read(min(65536, limit - len(buf)))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _f(rule, title, severity, url, owasp, remediation, evidence="", cwe=None, method="GET"):
    path = urllib.parse.urlsplit(url).path or "/"
    return {"engine": "dast", "rule_id": rule, "title": title, "severity": severity, "file": f"{method} {path}",
            "url": url, "line": None, "owasp_api": OWASP.get(owasp, owasp), "cwe": cwe, "remediation": remediation,
            "evidence": evidence[:300], "exposure": "internet", "reachable": True, "source_tool": "myelin-dast"}


def _tls_checks(host, port):
    out = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            cert, ver = t.getpeercert(), t.version()
        exp = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((exp - time.time()) // 86400)
        if days < 30:
            out.append(("NM-DAST-014", f"TLS certificate expires in {days} days", "medium" if days >= 0 else "high",
                        "Renew the certificate and automate renewal (e.g. cert-manager, ACME).", f"notAfter={cert['notAfter']}"))
        if ver in ("TLSv1", "TLSv1.1"):
            out.append(("NM-DAST-013", f"Server negotiated legacy {ver}", "high", "Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only.", ver))
    except ssl.SSLCertVerificationError as e:
        out.append(("NM-DAST-002", "TLS certificate is not trusted", "high",
                    "Serve a certificate from a trusted CA that matches the host name and includes the full chain.", str(e)))
    except (OSError, ssl.SSLError):
        pass
    for proto, name in ((getattr(ssl.TLSVersion, "TLSv1_1", None), "TLSv1.1"),):
        if proto is None:
            continue
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
            c.minimum_version = c.maximum_version = proto
            with socket.create_connection((host, port), timeout=8) as s, c.wrap_socket(s, server_hostname=host):
                out.append(("NM-DAST-013", f"Server accepts legacy {name}", "high", "Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only.", name))
        except (OSError, ssl.SSLError, ValueError):
            pass                                  # refused, or this client's OpenSSL cannot offer it: no finding
    return out


def _load_spec(spec, client):
    if not spec:
        return None
    if isinstance(spec, dict):
        return spec
    if re.match(r"https?://", spec):
        if client.scope_host and urllib.parse.urlsplit(spec).hostname != client.scope_host:
            client = Client(delay=0, max_requests=2, guard=client.guard)   # spec hosted elsewhere: fetch without credentials
        st, _, _, body = client.request("GET", spec)
        if st != 200:
            raise SystemExit(f"could not fetch the OpenAPI spec (HTTP {st}): {spec} - correct the spec URL, or leave it empty to scan without a spec")
        text = body.decode("utf-8", "ignore")
    else:
        text = open(spec, encoding="utf-8").read()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        import yaml
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            doc = None
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc or "paths" in doc):
        raise SystemExit(f"{spec} is not an OpenAPI/Swagger document - correct the spec URL, or leave it empty to scan without a spec")
    return doc


def _spec_get_operations(spec, base):
    """Concrete, parameter-free GET operations and whether the spec says they need authentication."""
    if not spec:
        return []
    global_sec = spec.get("security")
    server = ""
    if spec.get("servers"):
        server = urllib.parse.urlsplit(spec["servers"][0].get("url", "")).path.rstrip("/")
    elif spec.get("basePath"):
        server = spec["basePath"].rstrip("/")
    ops = []
    for path, item in (spec.get("paths") or {}).items():
        get = (item or {}).get("get")
        if not get or "{" in path:
            continue
        sec = get.get("security", global_sec)
        ops.append({"path": server + path, "url": base.rstrip("/") + server + path,
                    "requires_auth": bool(sec) and any(bool(s) for s in sec), "id": get.get("operationId", path)})
    return ops


def safe_scan(target, spec=None, headers=None, max_requests=300, delay=0.2, verify_tls=True, guard=None):
    t0 = time.time()
    u = urllib.parse.urlsplit(target)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise SystemExit("--target must be an http(s) URL, e.g. https://api.example.com")
    base = f"{u.scheme}://{u.netloc}"
    if guard:
        guard(u.hostname)
    c = Client(headers, delay=delay, max_requests=max_requests, verify_tls=verify_tls, scope_host=u.hostname, guard=guard)
    findings = []

    try:
        status, h, cookies, body = c.request("GET", target)
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLCertVerificationError):
            findings.append(_f("NM-DAST-002", "TLS certificate is not trusted", "high", target, "API8",
                               "Serve a certificate from a trusted CA that matches the host name.", str(reason), "CWE-295"))
            c = Client(headers, delay=delay, max_requests=max_requests, verify_tls=False, scope_host=u.hostname, guard=guard)
            status, h, cookies, body = c.request("GET", target)
        else:
            raise SystemExit(f"cannot reach {target}: {reason}")

    # --- transport ---------------------------------------------------------------------------------
    if u.scheme == "http":
        findings.append(_f("NM-DAST-001", "API served over plain HTTP", "high", target, "API8",
                           "Serve the API over HTTPS only and redirect or refuse HTTP.", cwe="CWE-319"))
    else:
        for rule, title, sev, rem, ev in _tls_checks(u.hostname, u.port or 443):
            findings.append(_f(rule, title, sev, target, "API8", rem, ev, "CWE-326"))
        try:
            hs, hh, _, _ = c.request("GET", "http://" + u.hostname + (u.path or "/"))
            loc = hh.get("location", "")
            if hs < 300 or (hs < 400 and not loc.startswith("https://")):
                findings.append(_f("NM-DAST-001", "HTTP requests are served without redirect to HTTPS", "medium", "http://" + u.hostname,
                                   "API8", "Redirect all HTTP requests to HTTPS (301/308) or close port 80.", f"HTTP {hs}", "CWE-319"))
        except (urllib.error.URLError, OSError, RuntimeError):
            pass
        if "strict-transport-security" not in h:
            findings.append(_f("NM-DAST-003", "Strict-Transport-Security header missing", "medium", target, "API8",
                               "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", cwe="CWE-523"))

    # --- headers -----------------------------------------------------------------------------------
    if h.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_f("NM-DAST-004", "X-Content-Type-Options: nosniff missing", "low", target, "API8",
                           "Send X-Content-Type-Options: nosniff on every response.", cwe="CWE-693"))
    ctype = h.get("content-type", "")
    if "html" in ctype and "content-security-policy" not in h and "x-frame-options" not in h:
        findings.append(_f("NM-DAST-012", "HTML served without Content-Security-Policy or frame protection", "medium", target, "API8",
                           "Add a Content-Security-Policy with frame-ancestors, or X-Frame-Options: DENY.", cwe="CWE-1021"))
    leaks = [f"{n}: {h[n]}" for n in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
             if n in h and VERSION_RX.search(h[n])]
    if leaks:
        findings.append(_f("NM-DAST-006", "Technology versions disclosed in response headers", "low", target, "API8",
                           "Remove or genericise these headers so software versions are not disclosed.", "; ".join(leaks), "CWE-200"))

    # --- cookies -----------------------------------------------------------------------------------
    for ck in cookies:
        low = ck.lower()
        name = ck.split("=", 1)[0]
        missing = [a for a, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in low]
        if missing and (u.scheme == "https" or "HttpOnly" in missing):
            findings.append(_f("NM-DAST-011", f"Cookie '{name}' lacks {', '.join(missing)}", "medium", target, "API8",
                               "Set Secure, HttpOnly and SameSite on session and authentication cookies.", ck[:120], "CWE-614"))

    # --- CORS --------------------------------------------------------------------------------------
    evil = "https://myelin-cors-probe.invalid"
    try:
        cs, ch, _, _ = c.request("OPTIONS", target, headers={"Origin": evil, "Access-Control-Request-Method": "GET"})
        _, gh, _, _ = c.request("GET", target, headers={"Origin": evil})
        acao = gh.get("access-control-allow-origin") or ch.get("access-control-allow-origin", "")
        acac = (gh.get("access-control-allow-credentials") or ch.get("access-control-allow-credentials", "")).lower() == "true"
        if acao == evil:
            findings.append(_f("NM-DAST-005", "CORS reflects arbitrary origins" + (" with credentials" if acac else ""),
                               "high" if acac else "medium", target, "API8",
                               "Allow only an explicit list of trusted origins; never reflect the Origin header with credentials.",
                               f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}", "CWE-942"))
        elif acao == "*" and acac:
            findings.append(_f("NM-DAST-005", "CORS allows any origin with credentials", "high", target, "API8",
                               "Do not combine a wildcard origin with credentials.", "ACAO: * with credentials", "CWE-942"))
        allow = (ch.get("allow") or ch.get("access-control-allow-methods") or "").upper()
        if "TRACE" in allow:
            findings.append(_f("NM-DAST-007", "TRACE method advertised", "low", target, "API8",
                               "Disable the TRACE method on the server and proxies.", f"Allow: {allow}", "CWE-693", "OPTIONS"))
    except (urllib.error.URLError, OSError, RuntimeError):
        pass

    # --- verbose errors ----------------------------------------------------------------------------
    for probe in ("/myelin-nonexistent-%7B%7D", (u.path.rstrip("/") or "") + "/%00myelin"):
        try:
            es, eh, _, eb = c.request("GET", base + probe)
            m = STACK.search(eb.decode("utf-8", "ignore"))
            if m:
                findings.append(_f("NM-DAST-009", "Stack trace or framework internals in error response", "medium", base + probe, "API8",
                                   "Return generic error bodies in production; log details server-side only.", m.group(0), "CWE-209"))
                break
        except (urllib.error.URLError, OSError, RuntimeError):
            pass

    # --- inventory: exposed API documentation ------------------------------------------------------
    exposed = []
    for p in DOC_PATHS:
        try:
            ds, dh, _, db = c.request("GET", base + p, auth=False)
        except (urllib.error.URLError, OSError, RuntimeError):
            continue
        text = db[:4000].decode("utf-8", "ignore")
        if ds == 200 and ('"openapi"' in text or '"swagger"' in text or "swagger-ui" in text or "redoc" in text.lower()
                          or ("graphql" in p and "errors" in text)):
            exposed.append(p)
    if exposed:
        findings.append(_f("NM-DAST-008", "API documentation publicly accessible without authentication", "low",
                           base + exposed[0], "API9", "Restrict API documentation to internal networks or authenticated users in production.",
                           ", ".join(exposed), "CWE-200"))

    # --- authentication enforcement from the OpenAPI spec -------------------------------------------
    spec_doc = _load_spec(spec, c)
    ops = _spec_get_operations(spec_doc, base)
    checked = 0
    for op in [o for o in ops if o["requires_auth"]][:40]:
        try:
            st, _, _, _ = c.request("GET", op["url"], auth=False)
            checked += 1
        except (urllib.error.URLError, OSError, RuntimeError):
            continue
        if 200 <= st < 300:
            findings.append(_f("NM-DAST-010", f"Operation '{op['id']}' responds without authentication", "critical", op["url"], "API2",
                               "Enforce authentication on this operation in the API gateway and the service; add a regression test.",
                               f"unauthenticated GET → HTTP {st}", "CWE-306"))
    # --- authentication inferred from behaviour --------------------------------------------------
    # Many specs declare no security schemes (authentication enforced in middleware). Probe the operations
    # anonymously; when most of the API refuses anonymous calls, the ones that still answer are reported.
    if ops and not any(o["requires_auth"] for o in ops):
        anon = []
        for op in ops[:80]:
            try:
                st, oh, _, _ = c.request("GET", op["url"], auth=False)
            except (urllib.error.URLError, OSError, RuntimeError):
                continue
            anon.append((op, st, (oh.get("content-type") or "").lower()))
        checked += len(anon)
        denied = [a for a in anon if a[1] in (401, 403)]
        if len(denied) >= 5 and len(denied) >= 0.5 * len(anon):
            for op, st, ctype in anon:
                if 200 <= st < 300 and not PUBLIC_BY_DESIGN.search(op["path"]) and "text/html" not in ctype:
                    findings.append(_f("NM-DAST-013", f"'{op['path']}' answers without authentication while the rest of the API requires it",
                                       "medium", op["url"], "API2",
                                       "Require authentication on this endpoint, or confirm it is public by design and return only "
                                       "non-sensitive fields (no configuration, site names, counts or versions).",
                                       f"anonymous GET → HTTP {st}; {len(denied)} of {len(anon)} operations refuse anonymous access",
                                       "CWE-306"))
    findings += exposure_checks(c, base, target, h, body)
    return {"target": target, "duration_s": round(time.time() - t0, 2), "requests": c.count, "request_log": c.log,
            "spec_operations": len(ops), "auth_checks": checked, "findings": findings, "client": c, "spec": spec_doc}


# Files that must never be served. Each needs its own content signature, so a catch-all 200 page is not a finding.
SENSITIVE_PATHS = [
    ("/.git/HEAD", r"^ref: refs/heads/", "Git repository exposed (source code and history)", "high", "CWE-527"),
    ("/.git/config", r"\[core\]", "Git configuration exposed", "high", "CWE-527"),
    ("/.svn/entries", r"^\d+\s*$|svn:", "Subversion metadata exposed", "high", "CWE-527"),
    ("/.env", r"(?m)^(APP_KEY|DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET_ACCESS_KEY|[A-Z_]*(PASSWORD|SECRET|TOKEN))=.+", "Environment file with secrets exposed", "critical", "CWE-538"),
    ("/.aws/credentials", r"aws_secret_access_key", "Cloud credentials file exposed", "critical", "CWE-538"),
    ("/.npmrc", r"_authToken=", "Package registry token exposed", "high", "CWE-538"),
    ("/id_rsa", r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----", "Private key exposed", "critical", "CWE-538"),
    ("/backup.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "Database dump exposed", "critical", "CWE-530"),
    ("/dump.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "Database dump exposed", "critical", "CWE-530"),
    ("/wp-config.php.bak", r"DB_PASSWORD", "Backup of a configuration file exposed", "critical", "CWE-530"),
    ("/config.php.bak", r"(?i)password", "Backup of a configuration file exposed", "high", "CWE-530"),
    ("/web.config", r"<configuration", "web.config served to clients", "medium", "CWE-538"),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "phpinfo() page exposed", "medium", "CWE-200"),
    ("/server-status", r"Apache Server Status", "Apache server-status exposed", "medium", "CWE-200"),
    ("/actuator/env", r"propertySources|activeProfiles", "Spring Boot Actuator environment exposed", "high", "CWE-200"),
    ("/actuator/heapdump", None, "Spring Boot heap dump downloadable", "critical", "CWE-200"),
    ("/debug/pprof/", r"Types of profiles available", "Go pprof debug endpoint exposed", "medium", "CWE-200"),
    ("/elmah.axd", r"Error Log for", "ELMAH error log exposed", "high", "CWE-200"),
    ("/trace.axd", r"Application Trace", "ASP.NET trace exposed", "high", "CWE-200"),
    ("/.DS_Store", None, "macOS .DS_Store file lists directory contents", "low", "CWE-538"),
    ("/docker-compose.yml", r"(?m)^services:", "Docker Compose file exposed", "medium", "CWE-538"),
]


def exposure_checks(c, base, target, h, body):
    out = []
    for path, sig, title, sev, cwe in SENSITIVE_PATHS:
        try:
            st, hh, _, b = c.request("GET", base + path, auth=False)
        except (urllib.error.URLError, OSError, RuntimeError):
            continue
        if st != 200:
            continue
        text = b[:20000].decode("utf-8", "ignore")
        ctype = (hh.get("content-type") or "").lower()
        hit = False
        if path == "/actuator/heapdump":
            hit = "octet-stream" in ctype and (b[:4] == b"JAVA" or b[:10].startswith(b"\x1f\x8b"))
        elif path == "/.DS_Store":
            hit = b[4:8] == b"Bud1"
        elif sig and "text/html" not in ctype or (sig and path in ("/phpinfo.php", "/server-status", "/elmah.axd", "/trace.axd", "/debug/pprof/")):
            hit = bool(re.search(sig, text))
        if hit:
            out.append(_f("NM-DAST-040", title, sev, base + path, "API8",
                          "Remove the file from the web root (or block the path at the server/proxy) and rotate any secret it contained.",
                          f"GET {path} -> HTTP 200 with matching content", cwe))
    # directory listing
    if re.search(r"<title>\s*Index of /|Directory listing for /", body[:5000].decode("utf-8", "ignore")):
        out.append(_f("NM-DAST-041", "Directory listing is enabled", "medium", target, "API8",
                      "Disable directory indexes (autoindex off / Options -Indexes).", "Index of / page", "CWE-548"))
    # GraphQL introspection
    for gp in ("/graphql", "/api/graphql"):
        try:
            st, _, _, b = c.request("GET", base + gp + "?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D", auth=False)
        except (urllib.error.URLError, OSError, RuntimeError):
            continue
        if st == 200 and b'"__schema"' in b and b'"queryType"' in b:
            out.append(_f("NM-DAST-042", "GraphQL introspection is enabled", "medium", base + gp, "API9",
                          "Disable introspection in production and enforce query depth/complexity limits.", "__schema query answered", "CWE-200"))
            break
    # Host header injection (via X-Forwarded-Host, which does not change routing)
    evil = "myelin-host-probe.invalid"
    try:
        st, hh, _, b = c.request("GET", target, headers={"X-Forwarded-Host": evil})
        if evil in (hh.get("location") or "") or evil.encode() in b[:50000]:
            out.append(_f("NM-DAST-043", "Host header injection: forwarded host is reflected", "medium", target, "API8",
                          "Build absolute URLs from a configured host name, and trust X-Forwarded-Host only from your proxy.",
                          "X-Forwarded-Host value appears in the response", "CWE-644"))
    except (urllib.error.URLError, OSError, RuntimeError):
        pass
    # weak Content-Security-Policy and missing browser policies on HTML
    if "html" in (h.get("content-type") or ""):
        csp = h.get("content-security-policy", "")
        if csp and re.search(r"script-src[^;]*('unsafe-inline'|'unsafe-eval'|\*(?![.\w]))", csp) and "nonce-" not in csp and "strict-dynamic" not in csp:
            out.append(_f("NM-DAST-044", "Content-Security-Policy allows inline or any-origin scripts", "low", target, "API8",
                          "Use nonces or hashes instead of 'unsafe-inline'/'unsafe-eval', and list script origins explicitly.", csp[:200], "CWE-693"))
        missing = [n for n in ("referrer-policy", "permissions-policy") if n not in h]
        if missing:
            out.append(_f("NM-DAST-045", "Browser privacy headers missing: " + ", ".join(missing), "low", target, "API8",
                          "Send Referrer-Policy: strict-origin-when-cross-origin and a restrictive Permissions-Policy.", "", "CWE-693"))
    return out


# ---------------------------------------------------------------------------------------------------
def zap_scan(target, spec=None, headers=None, active=False, timeout=3600):
    """Run OWASP ZAP in Docker and normalise its JSON report."""
    if not shutil.which("docker"):
        raise SystemExit("--zap needs Docker (Docker Desktop on Windows). Without it, run the built-in safe scan only.")
    work = tempfile.mkdtemp(prefix="myelin-zap-")
    os.chmod(work, 0o777)
    argv = ["docker", "run", "--rm", "-v", f"{work}:/zap/wrk:rw"]
    for k, v in (headers or {}).items():
        if k.lower() == "authorization":
            argv += ["-e", "ZAP_AUTH_HEADER=Authorization", "-e", f"ZAP_AUTH_HEADER_VALUE={v}"]
        else:
            argv += ["-e", f"ZAP_AUTH_HEADER={k}", "-e", f"ZAP_AUTH_HEADER_VALUE={v}"]
    image = "ghcr.io/zaproxy/zaproxy:stable"
    if active:
        if not spec:
            raise SystemExit("--active needs --openapi so ZAP knows the API's operations")
        spec_arg = spec
        if not re.match(r"https?://", spec):
            shutil.copy(spec, os.path.join(work, "spec.json"))
            spec_arg = "/zap/wrk/spec.json"
        argv += [image, "zap-api-scan.py", "-t", spec_arg, "-f", "openapi", "-J", "zap.json", "-I"]
    else:
        argv += [image, "zap-baseline.py", "-t", target, "-J", "zap.json", "-I"]
    subprocess.run(argv, timeout=timeout, check=False)
    path = os.path.join(work, "zap.json")
    if not os.path.exists(path):
        raise SystemExit("ZAP produced no report — check Docker is running and the target is reachable from containers")
    return normalize_zap(json.load(open(path)))


def normalize_zap(doc):
    from .zap_api import affected_endpoints
    sev = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    out = []
    for site in doc.get("site", []):
        for a in site.get("alerts", []):
            inst = (a.get("instances") or [{}])[0]
            url = inst.get("uri") or site.get("@name", "")
            f = _f(f"ZAP-{a.get('pluginid')}", a.get("name") or a.get("alert", "ZAP alert"), sev.get(str(a.get("riskcode")), "info"),
                   url, "API8", re.sub("<[^>]+>", "", a.get("solution", ""))[:400], inst.get("evidence", ""),
                   f"CWE-{a['cweid']}" if a.get("cweid") not in (None, "", "-1", "0") else None, inst.get("method", "GET"))
            f["source_tool"], f["instances"] = "zap", len(a.get("instances") or [])
            f["affected_endpoints"] = affected_endpoints(a.get("instances") or [], url_key="uri")
            out.append(f)
    return out
