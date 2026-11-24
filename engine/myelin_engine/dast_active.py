# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Built-in crawler and active checks for live application testing.

crawl (safe)    Follows same-host links, reads GET forms, scripts and the OpenAPI spec to discover endpoints and their
                query parameters. GET requests only, inside the request budget.
active (opt-in) Sends test values in query parameters, one parameter at a time, and confirms each result against a
                baseline response. Only GET requests are sent, so no form is submitted and no record is created, but
                the values are attack payloads: active checks require written authorisation (--authorized on the CLI,
                verified ownership plus the active setting on the platform) and should target non-production.

    reflected XSS        unique marker with < " ' > returned unencoded in an HTML response        CWE-79
    SQL injection        a quote produces a database error that the baseline response does not     CWE-89
    open redirect        a redirect parameter sends the browser to an external host                CWE-601
    path traversal       ../ sequences return the contents of /etc/passwd or win.ini               CWE-22
    template injection   {{7*191}} / ${7*191} is evaluated to 1337                                 CWE-1336
"""
import html.parser
import re
import secrets
import urllib.error
import urllib.parse

from .dast import _f

MAX_PAGES = 60
MAX_PARAMS = 80
SQL_ERRORS = re.compile(r"(SQL syntax.*MySQL|Warning.*mysql_|MySqlException|valid MySQL result|PostgreSQL.*ERROR|pg_query\(\)|PSQLException|"
                        r"unterminated quoted string|syntax error at or near|ORA-0\d{4}|Oracle error|Microsoft OLE DB Provider for SQL Server|"
                        r"Unclosed quotation mark after the character string|SQLServerException|SQLite3::|sqlite3\.OperationalError|"
                        r"SQLSTATE\[|near \".*\": syntax error|DB2 SQL error|Sybase message)", re.I)
PASSWD = re.compile(r"root:[x*]?:0:0:")
WININI = re.compile(r"\[(fonts|extensions)\]\s*\r?\n", re.I)
REDIRECT_PARAMS = re.compile(r"^(url|uri|next|redirect|redirect_uri|redirect_url|return|returnto|return_to|returnurl|continue|dest|destination|goto|target|redir|r|u|forward|callback)$", re.I)
FILE_PARAMS = re.compile(r"^(file|filename|path|page|template|doc|document|download|include|name|folder|dir|img|image|view|lang|locale)$", re.I)
REDIRECT_HOST = "myelin-redirect-check.invalid"


class _Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.scripts, self._form = [], [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None and a.get("name"):
            if (a.get("type") or "").lower() not in ("submit", "button", "image", "file", "password", "hidden"):
                self._form["inputs"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _same_host(url, host):
    return urllib.parse.urlsplit(url).hostname == host


def crawl(client, base: str, start: str, spec=None, max_pages: int = MAX_PAGES) -> list[dict]:
    """Discover GET endpoints with query parameters. Returns [{"url", "params": [names], "source"}]."""
    host = urllib.parse.urlsplit(base).hostname
    queue, seen, endpoints, js_paths = [start], set(), {}, set()

    def add(url, params, source):
        u = urllib.parse.urlsplit(url)
        key = f"{u.scheme}://{u.netloc}{u.path}"
        e = endpoints.setdefault(key, {"url": key, "params": [], "source": source})
        for p in params:
            if p not in e["params"]:
                e["params"].append(p)

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        url = urllib.parse.urldefrag(url)[0]
        if url in seen or not _same_host(url, host):
            continue
        seen.add(url)
        try:
            status, h, _, body = client.request("GET", url)
        except (urllib.error.URLError, OSError, RuntimeError):
            if client.count >= client.max:
                break
            continue
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True)
        if q:
            add(url, list(q), "link")
        ctype = (h.get("content-type") or "").lower()
        text = body.decode("utf-8", "replace")
        if 300 <= status < 400 and h.get("location"):
            nxt = urllib.parse.urljoin(url, h["location"])
            if _same_host(nxt, host):
                queue.append(nxt)
            continue
        if "html" in ctype:
            p = _Links()
            try:
                p.feed(text[:400_000])
            except Exception:  # noqa: BLE001 - malformed HTML must not stop the crawl
                pass
            for link in p.links:
                nxt = urllib.parse.urljoin(url, link)
                if nxt.startswith(("http://", "https://")) and _same_host(nxt, host) and not re.search(r"\.(png|jpe?g|gif|svg|ico|css|woff2?|pdf|zip)$", urllib.parse.urlsplit(nxt).path, re.I):
                    queue.append(nxt)
            for f in p.forms:
                if f["method"] == "get" and f["inputs"]:
                    add(urllib.parse.urljoin(url, f["action"] or url), f["inputs"], "form")
            for s in p.scripts[:10]:
                js = urllib.parse.urljoin(url, s)
                if _same_host(js, host) and js not in seen and len(seen) < max_pages:
                    seen.add(js)
                    try:
                        _, _, _, jb = client.request("GET", js)
                        js_paths.update(re.findall(r"""["'`](/api/[A-Za-z0-9_\-/{}.]+(?:\?[A-Za-z0-9_=&\-]+)?)["'`]""", jb.decode("utf-8", "replace"))[:50])
                    except (urllib.error.URLError, OSError, RuntimeError):
                        pass
    for jp in sorted(js_paths)[:40]:
        if "{" in jp:
            continue
        u = urllib.parse.urljoin(base, jp)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query, keep_blank_values=True)
        add(u, list(q), "script")
    for op in _spec_query_ops(spec, base):
        add(op["url"], op["params"], "openapi")
    return [e for e in endpoints.values() if e["params"]][:MAX_PARAMS]


def _spec_query_ops(spec, base):
    if not isinstance(spec, dict):
        return []
    server = ((spec.get("servers") or [{}])[0].get("url") or "").rstrip("/")
    root = urllib.parse.urljoin(base + "/", server.lstrip("/")) if server and not server.startswith("http") else server or base
    out = []
    for path, item in (spec.get("paths") or {}).items():
        op = (item or {}).get("get")
        if not op or "{" in path:
            continue
        params = [p.get("name") for p in (op.get("parameters") or []) + (item.get("parameters") or [])
                  if isinstance(p, dict) and p.get("in") == "query" and p.get("name")]
        if params:
            out.append({"url": root.rstrip("/") + path, "params": params})
    return out


def _with(url, param, value, others):
    q = {k: (others.get(k) or "1") for k in others}
    q[param] = value
    return url.split("?")[0] + "?" + urllib.parse.urlencode(q)


def active_checks(client, endpoints: list[dict], max_params: int = MAX_PARAMS) -> tuple[list[dict], dict]:
    """Probe each discovered query parameter. Returns (findings, stats)."""
    findings, tested = [], 0
    done = set()
    for ep in endpoints:
        url, params = ep["url"], ep["params"]
        base_vals = {p: "1" for p in params}
        try:
            bs, bh, _, bb = client.request("GET", _with(url, params[0], "1", base_vals))
        except (urllib.error.URLError, OSError, RuntimeError):
            continue
        baseline = bb.decode("utf-8", "replace")
        for p in params:
            if tested >= max_params or client.count >= client.max - 6:
                return findings, {"parameters_tested": tested, "endpoints": len(endpoints)}
            tested += 1
            path = urllib.parse.urlsplit(url).path or "/"
            try:
                # reflected XSS
                mark = "myl" + secrets.token_hex(4)
                payload = f"{mark}<\"'>"
                st, h, _, body = client.request("GET", _with(url, p, payload, base_vals))
                text = body.decode("utf-8", "replace")
                if payload in text and "html" in (h.get("content-type") or "").lower() and ("xss", path, p) not in done:
                    done.add(("xss", path, p))
                    findings.append(_active("NM-DAST-030", f"Reflected cross-site scripting in parameter '{p}'", "high", url, p,
                                            "Encode output for the HTML context (templating auto-escaping) and add a strict Content-Security-Policy.",
                                            f"value {payload!r} returned unencoded in an HTML response (HTTP {st})", "CWE-79"))
                # SQL injection (error-based, confirmed against the baseline)
                st, h, _, body = client.request("GET", _with(url, p, "1'\"", base_vals))
                text = body.decode("utf-8", "replace")
                m = SQL_ERRORS.search(text)
                if m and not SQL_ERRORS.search(baseline) and ("sqli", path, p) not in done:
                    done.add(("sqli", path, p))
                    findings.append(_active("NM-DAST-031", f"SQL injection in parameter '{p}'", "critical", url, p,
                                            "Use parameterised queries or an ORM; never build SQL from request values.",
                                            f"a quote in '{p}' produced a database error: {m.group(0)[:80]}", "CWE-89"))
                # template injection
                st, h, _, body = client.request("GET", _with(url, p, "{{7*191}}${7*191}", base_vals))
                text = body.decode("utf-8", "replace")
                if "1337" in text and "1337" not in baseline and "7*191" not in text and ("ssti", path, p) not in done:
                    done.add(("ssti", path, p))
                    findings.append(_active("NM-DAST-034", f"Server-side template injection in parameter '{p}'", "high", url, p,
                                            "Never render request values as templates; pass them as template data.",
                                            f"'{{{{7*191}}}}' in '{p}' was evaluated to 1337", "CWE-1336"))
                if REDIRECT_PARAMS.match(p):
                    st, h, _, _ = client.request("GET", _with(url, p, f"https://{REDIRECT_HOST}/", base_vals))
                    if 300 <= st < 400 and urllib.parse.urlsplit(h.get("location", "")).hostname == REDIRECT_HOST:
                        findings.append(_active("NM-DAST-032", f"Open redirect through parameter '{p}'", "medium", url, p,
                                                "Allow only relative paths or a fixed list of destinations in redirect parameters.",
                                                f"HTTP {st} Location: {h.get('location')}", "CWE-601"))
                if FILE_PARAMS.match(p):
                    for val in ("../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "..\\..\\..\\..\\windows\\win.ini"):
                        st, h, _, body = client.request("GET", _with(url, p, val, base_vals))
                        text = body.decode("utf-8", "replace")
                        if (PASSWD.search(text) and not PASSWD.search(baseline)) or (WININI.search(text) and not WININI.search(baseline)):
                            findings.append(_active("NM-DAST-033", f"Path traversal in parameter '{p}'", "critical", url, p,
                                                    "Resolve the requested name against an allow-list or a fixed directory and reject '..' and absolute paths.",
                                                    f"'{val}' returned the contents of a system file", "CWE-22"))
                            break
            except (urllib.error.URLError, OSError, RuntimeError):
                continue
    return findings, {"parameters_tested": tested, "endpoints": len(endpoints)}


def _active(rule, title, sev, url, param, remediation, evidence, cwe):
    f = _f(rule, title, sev, url, "API8", remediation, evidence, cwe)
    f["file"] = f"GET {urllib.parse.urlsplit(url).path or '/'}?{param}"
    f["parameter"] = param
    f["owasp_api"] = None
    f["confirmed"] = True
    return f
