# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
import os
import subprocess
import sys
import threading
import time

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
from engine.myelin_engine import dast  # noqa: E402

PORT = 8097


@pytest.fixture(scope="module")
def api():
    from tests.vapi import start
    server, th = start(PORT)
    yield f"http://127.0.0.1:{PORT}"
    server.should_exit = True
    th.join(5)


def test_safe_scan_finds_misconfigurations(api):
    r = dast.safe_scan(api, spec=api + "/openapi.json", delay=0)
    rules = {f["rule_id"] for f in r["findings"]}
    assert {"NM-DAST-001", "NM-DAST-004", "NM-DAST-005", "NM-DAST-006", "NM-DAST-007", "NM-DAST-008",
            "NM-DAST-009", "NM-DAST-010", "NM-DAST-011"} <= rules
    unauth = [f for f in r["findings"] if f["rule_id"] == "NM-DAST-010"]
    assert [f["file"] for f in unauth] == ["GET /api/v1/accounts"]          # /transfers enforces auth: not flagged
    cors = next(f for f in r["findings"] if f["rule_id"] == "NM-DAST-005")
    assert cors["severity"] == "high" and "credentials" in cors["title"]


def test_safe_scan_is_read_only_and_bounded(api):
    r = dast.safe_scan(api, spec=api + "/openapi.json", delay=0)
    assert {e["method"] for e in r["request_log"]} <= {"GET", "HEAD", "OPTIONS"}
    assert r["requests"] < 80                     # includes ~25 GET probes for exposed files (bounded by max_requests)
    with pytest.raises(AssertionError):
        dast.Client().request("POST", api)
    c = dast.Client(max_requests=1, delay=0)
    c.request("GET", api)
    with pytest.raises(RuntimeError):
        c.request("GET", api)


def test_auth_header_sent_but_stripped_for_auth_checks(api):
    r = dast.safe_scan(api, spec=api + "/openapi.json", headers={"Authorization": "Bearer t"}, delay=0)
    unauth_calls = [e for e in r["request_log"] if "/api/v1/" in e["url"]]
    assert unauth_calls and all(e["authenticated"] is False for e in unauth_calls)


def test_cli_dast_end_to_end_and_active_guard(api, tmp_path):
    cli = [sys.executable, os.path.join(ROOT, "cli", "myelin.py"), "dast", "--target", api]
    out = tmp_path / "r.json"
    p = subprocess.run(cli + ["--openapi", api + "/openapi.json", "--delay", "0", "--json", str(out), "--sarif", str(tmp_path / "r.sarif")],
                       capture_output=True, text=True)
    assert p.returncode == 1 and "BLOCK" in p.stdout                     # unauthenticated operation blocks the gate
    import json
    d = json.load(open(out))
    assert d["findings"][0]["rule_id"] == "NM-DAST-010" and d["findings"][0]["priority"] in ("P0", "P1")
    p = subprocess.run(cli + ["--zap", "--active"], capture_output=True, text=True)
    assert p.returncode == 2 and "--authorized" in p.stderr


def test_unreachable_target_and_bad_url():
    with pytest.raises(SystemExit):
        dast.safe_scan("ftp://example.com")
    with pytest.raises(SystemExit):
        dast.safe_scan("http://127.0.0.1:9", delay=0)


def test_zap_report_normalisation():
    doc = {"site": [{"@name": "https://api.example.com", "alerts": [
        {"pluginid": "10038", "alert": "Content Security Policy (CSP) Header Not Set", "riskcode": "2", "cweid": "693",
         "solution": "<p>Set the header.</p>", "instances": [{"uri": "https://api.example.com/v1/x", "method": "GET", "evidence": ""}]},
        {"pluginid": "40018", "name": "SQL Injection", "riskcode": "3", "cweid": "89",
         "solution": "Use parameterised queries", "instances": [{"uri": "https://api.example.com/v1/q?id=1", "method": "GET"}]}]}]}
    fs = dast.normalize_zap(doc)
    assert [(f["rule_id"], f["severity"], f["cwe"]) for f in fs] == [("ZAP-10038", "medium", "CWE-693"), ("ZAP-40018", "high", "CWE-89")]
    assert fs[0]["remediation"] == "Set the header." and fs[1]["file"] == "GET /v1/q"


# ---------------- multi-user authorisation testing (offline engine + CLI report) ----------------
from engine.myelin_engine import dast_authz  # noqa: E402
from tests.vapi import IDENTITIES  # noqa: E402


def _authz(api, ids=IDENTITIES, **cfg):
    c = dast.Client(delay=0, scope_host="127.0.0.1")
    spec = dast._load_spec(api + "/openapi.json", c)
    conf = dast_authz.load_identities({"identities": ids, **cfg})
    return dast_authz.authz_scan(c, api, spec, conf), c


def test_authz_finds_bola_bfla_and_exposure_without_false_positives(api):
    (fs, stats), c = _authz(api)
    by = {(f["rule_id"], f["file"]) for f in fs}
    assert ("NM-DAST-020", "GET /api/v2/accounts/{accountId}") in by          # BOLA
    assert ("NM-DAST-023", "GET /api/v2/admin/users") in by                   # BFLA
    assert ("NM-DAST-022", "GET /api/v2/me/profile") in by                    # sensitive fields
    files = {f["file"] for f in fs}
    assert "GET /api/v2/cards/{cardId}" not in files                          # ownership enforced: no finding
    assert "GET /api/v2/admin/audit" not in files                             # role enforced: no finding
    assert len([f for f in fs if f["rule_id"] == "NM-DAST-020"]) == 1         # one finding per endpoint
    assert {e["method"] for e in c.log} == {"GET"} and stats["object_checks"] >= 2


def test_authz_respects_cross_user_roles_and_scope(api):
    only_admin_and_alice = [IDENTITIES[0], IDENTITIES[2]]
    (fs, _), _ = _authz(api, only_admin_and_alice)
    assert not [f for f in fs if f["rule_id"] == "NM-DAST-020"]               # admin may read all objects
    c = dast.Client(delay=0, scope_host="127.0.0.1")
    with pytest.raises(RuntimeError, match="out of scope"):
        c.request("GET", "http://localhost:%d/" % PORT)


def test_identities_validation(tmp_path):
    with pytest.raises(dast_authz.IdentityError):
        dast_authz.load_identities({"identities": IDENTITIES[:1]})
    with pytest.raises(dast_authz.IdentityError, match="NOT_SET_VAR"):
        dast_authz.load_identities({"identities": [{"name": "a", "headers": {"Authorization": "env:NOT_SET_VAR"}}, IDENTITIES[1]]})


def test_cli_offline_assessment_report(api, tmp_path):
    import yaml
    ids = tmp_path / "ids.yaml"
    ids.write_text(yaml.safe_dump({"identities": IDENTITIES}))
    rep = tmp_path / "report.html"
    p = subprocess.run([sys.executable, os.path.join(ROOT, "cli", "myelin.py"), "dast", "--target", api, "--openapi", api + "/openapi.json",
                        "--identities", str(ids), "--report", str(rep), "--delay", "0", "--customer", "Demo"], capture_output=True, text=True)
    assert p.returncode == 1 and "cross-user object checks" in p.stdout
    html = rep.read_text()
    assert "API1:2023" in html and "Not acceptable for release" in html and "alice-token" not in html


def test_host_guard():
    g = dast.host_guard(allow_private=False)
    for h in ("127.0.0.1", "169.254.169.254", "10.0.0.5"):
        with pytest.raises(RuntimeError):
            g(h)
    dast.host_guard(allow_private=True)("10.0.0.5")
    with pytest.raises(RuntimeError):
        dast.host_guard(allow_private=True)("169.254.169.254")


def test_cli_survives_windows_cp1252_console(api, tmp_path):
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    cli = [sys.executable, os.path.join(ROOT, "cli", "myelin.py")]
    h = subprocess.run(cli + ["dast", "--help"], capture_output=True, env=env)
    assert h.returncode == 0 and b"--identities" in h.stdout
    r = subprocess.run(cli + ["dast", "--target", api, "--openapi", api + "/openapi.json", "--delay", "0", "--fail-on", "never"],
                       capture_output=True, env=env)
    assert r.returncode == 0 and b"Traceback" not in r.stderr, r.stderr[-400:]


# ---- online runs: bad spec URL and interrupted runs must never leave a target stuck in "running" ----
def _http_404_server():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def _send(self, body=True):
            self.send_response(404); self.send_header("Content-Type", "text/html"); self.end_headers()
            if body:
                self.wfile.write(b"<html>Page not found</html>")
        do_GET = _send
        def do_HEAD(self): self._send(False)
        def do_OPTIONS(self): self._send(False)
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_online_run_with_missing_spec_fails_cleanly():
    from app import dast_targets as d
    srv = _http_404_server()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        repo, tenant = d.MemoryTargets(), "t1"
        t = repo.add(tenant, d.new_target({"name": "site", "base_url": base, "spec_url": base + "/swagger/v1/swagger.json"}, "me"))

        class _Store:
            def add_scan(self, *a): return ("scan", None)
        d.start_run(repo, _Store, tenant, repo.get(tenant, t["id"]), "me", resolver=None, guard=None, max_requests=50,
                    require_verification=False, synchronous=True)
        got = repo.get(tenant, t["id"])
        assert got["status"] == "failed"
        assert "OpenAPI spec" in got["last_error"] and "404" in got["last_error"]
    finally:
        srv.shutdown()


def test_interrupted_run_can_be_started_again():
    from datetime import timedelta
    from app import dast_targets as d
    repo, tenant = d.MemoryTargets(), "t1"
    t = repo.add(tenant, d.new_target({"name": "x", "base_url": "https://example.invalid"}, "me"))
    repo.update(tenant, t["id"], status="running", last_run_at=d.now())
    with pytest.raises(d.TargetError, match="already in progress"):
        d.start_run(repo, None, tenant, repo.get(tenant, t["id"]), "me", resolver=None, guard=None, max_requests=1,
                    require_verification=False, synchronous=False)
    repo.update(tenant, t["id"], last_run_at=d.now() - timedelta(seconds=d.RUN_STALE_AFTER + 5))
    stale = repo.get(tenant, t["id"])
    assert d.public(stale)["status"] == "failed" and "interrupted" in d.public(stale)["last_error"]
    repo.update(tenant, t["id"], last_run_at=None)          # stuck by an older version: no start time recorded
    assert d.is_stale(repo.get(tenant, t["id"]))


# ---- scanner robustness: streaming endpoints and specs without declared security ----
def _api_server(routes):
    import time as _t
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/api/stream":                       # server-sent events that never end
                self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
                try:
                    while True:
                        self.wfile.write(b"data: tick\n\n"); self.wfile.flush(); _t.sleep(0.5)
                except OSError:
                    return
            code, body = routes.get(path, (401, b'{"detail":"auth required"}'))
            self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(body)
        def do_HEAD(self): self.send_response(200); self.end_headers()
        def do_OPTIONS(self): self.send_response(200); self.end_headers()
        def log_message(self, *a): pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_streaming_endpoint_does_not_hang_and_open_endpoints_are_inferred():
    paths = ["/api/stream", "/api/health", "/api/config", "/api/a", "/api/b", "/api/c", "/api/d", "/api/e"]
    spec = {"openapi": "3.0.0", "paths": {p: {"get": {"operationId": p}} for p in paths}}   # no security declared
    srv = _api_server({"/api/health": (200, b'{"ok":true}'), "/api/config": (200, b'{"site":"x"}')})
    try:
        t0 = time.time()
        res = dast.safe_scan(f"http://127.0.0.1:{srv.server_port}", spec=spec, max_requests=200, delay=0)
        assert time.time() - t0 < 60
        open_paths = {f["file"] for f in res["findings"] if f["rule_id"] == "NM-DAST-013"}
        assert open_paths == {"GET /api/config", "GET /api/stream"}   # health is public by design; the open stream is reported, not read
    finally:
        srv.shutdown()
