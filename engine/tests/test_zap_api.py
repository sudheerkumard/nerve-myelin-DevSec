# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""The OWASP ZAP driver against a fake ZAP daemon: scope, safe-mode options, headers, active scan gating, alerts."""
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from myelin_engine import dast, zap_api

CALLS = []


class FakeZap(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        _, _, comp, kind, name, _ = (u.path.split("/") + ["", "", "", "", "", ""])[:6]
        CALLS.append((comp, kind, name, q, self.headers.get("X-ZAP-API-Key")))
        body = {"Result": "OK"}
        if (comp, name) in (("spider", "scan"), ("ascan", "scan")):
            body = {"scan": "1"}
        elif name == "status":
            body = {"status": "100"}
        elif name == "recordsToScan":
            body = {"recordsToScan": "0"}
        elif name == "context" and kind == "view":
            body = {"context": {"id": "7"}}
        elif name == "urls":
            body = {"urls": ["https://app.example.com/", "https://app.example.com/login"]}
        elif name == "version":
            body = {"version": "2.16.1"}
        elif name == "alerts":
            body = {"alerts": [
                {"pluginId": "10038", "name": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "confidence": "High",
                 "url": "https://app.example.com/", "method": "GET", "cweid": "693", "solution": "<p>Set a CSP header.</p>"},
                {"pluginId": "10038", "name": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "confidence": "High",
                 "url": "https://app.example.com/login", "method": "GET", "cweid": "693", "solution": "Set a CSP header."},
                {"pluginId": "40012", "name": "Cross Site Scripting (Reflected)", "risk": "High", "confidence": "Medium",
                 "url": "https://app.example.com/search?q=x", "method": "GET", "cweid": "79", "evidence": "<script>alert(1)</script>"},
                {"pluginId": "90", "name": "Noise", "risk": "Low", "confidence": "False Positive", "url": "https://app.example.com/"},
            ]}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


def _server():
    srv = HTTPServer(("127.0.0.1", 0), FakeZap)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_passive_scan_is_scoped_writes_nothing_and_normalises_alerts():
    CALLS.clear()
    srv = _server()
    z = zap_api.Zap(f"http://127.0.0.1:{srv.server_port}", "k3y")
    res = z.scan("https://app.example.com/", headers={"Authorization": "Bearer t"})
    srv.shutdown()
    names = [(c, n) for c, _, n, _, _ in CALLS]
    assert names[0] == ("core", "newSession") and all(k == "k3y" for *_, k in CALLS)
    include = next(q for c, _, n, q, _ in CALLS if n == "includeInContext")
    assert include["regex"] == r"https://app\.example\.com(/.*)?"
    assert next(q for c, _, n, q, _ in CALLS if n == "setOptionPostForm")["Boolean"] == "false"
    assert next(q for c, _, n, q, _ in CALLS if n == "setOptionProcessForm")["Boolean"] == "false"
    assert ("ascan", "scan") not in names, "passive mode must never start the active scanner"
    rule = next(q for c, _, n, q, _ in CALLS if n == "addRule")
    assert rule["matchString"] == "Authorization" and rule["replacement"] == "Bearer t" and ("replacer", "removeRule") in names
    assert res["mode"] == "passive" and res["urls"] == 2 and res["version"] == "2.16.1"
    fs = zap_api.normalize(res["alerts"], dast._f)
    by = {f["rule_id"]: f for f in fs}
    assert set(by) == {"ZAP-10038", "ZAP-40012"}                        # false positives dropped
    assert by["ZAP-10038"]["instances"] == 2 and by["ZAP-10038"]["remediation"] == "Set a CSP header."
    assert by["ZAP-40012"]["severity"] == "high" and by["ZAP-40012"]["cwe"] == "CWE-79"


def test_active_scan_runs_only_when_requested():
    CALLS.clear()
    srv = _server()
    zap_api.Zap(f"http://127.0.0.1:{srv.server_port}", "k").scan("https://app.example.com/", active=True)
    srv.shutdown()
    names = [(c, n) for c, _, n, _, _ in CALLS]
    assert ("ascan", "scan") in names
    assert next(q for c, _, n, q, _ in CALLS if n == "scan" and c == "ascan")["contextId"] == "7"


def test_alerts_keep_report_locations_when_the_first_instance_is_a_false_positive():
    alerts = [
        {"pluginId": "10038", "name": "Missing CSP", "confidence": "False Positive", "url": "https://app.example/ignored"},
        {"pluginId": "10038", "name": "Missing CSP", "confidence": "High", "url": "https://app.example/one?param=redacted"},
        {"pluginId": "10038", "name": "Missing CSP", "confidence": "High", "url": "https://app.example/two"},
    ]
    finding, = zap_api.normalize(alerts, dast._f)
    assert finding["instances"] == 2
    assert finding["affected_endpoints"] == ["GET /one", "GET /two"]
