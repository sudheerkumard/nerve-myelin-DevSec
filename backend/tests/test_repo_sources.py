# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Repositories scanned from the console: URL parsing, safe archive extraction, full scan, report, API flow."""
import io
import os
import sys
import tarfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient  # noqa: E402

from app import scm  # noqa: E402
from app.main import app  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
H = {"X-API-Key": "nm_demo_9f2c41e7b8"}


def _archive(top="acme-payments-0123abc", src=os.path.join(ROOT, "demo", "vulnerable-app"), extra=()):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(src, arcname=top)
        for info, data in extra:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


@pytest.fixture()
def fake_provider(monkeypatch):
    calls = []

    def _http(url, headers, limit=0, want_json=False):
        calls.append((url, headers))
        return {"mainbranch": {"name": "main"}} if want_json else _archive()
    monkeypatch.setattr(scm, "_http", _http)
    return calls


def test_url_parsing_rejects_unsafe_addresses():
    assert scm.detect("https://github.com/acme/payments.git")["provider"] == "github"
    for bad in ("http://github.com/a/b", "https://github.com/a", "file:///etc/passwd", "https://github.com/a/../../c",
                "ftp://example.com/x", "https://dev.azure.com/org/_apis/x"):
        with pytest.raises(scm.ScmError):
            scm.detect(bad)


def test_safe_extract_skips_traversal_links_and_devices(tmp_path):
    evil = tarfile.TarInfo("../escape.txt"); evil.size = 3
    link = tarfile.TarInfo("acme-payments-0123abc/link"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/passwd"
    root = scm._extract(_archive(extra=[(evil, b"bad"), (link, None)]), "tar", str(tmp_path))
    assert root.endswith("acme-payments-0123abc") and os.path.isdir(root)
    assert not (tmp_path.parent / "escape.txt").exists()
    assert not os.path.lexists(os.path.join(root, "link"))


def test_archive_providers_use_their_apis_and_credentials(fake_provider, tmp_path):
    scm.fetch("https://github.com/acme/payments", None, "release/1.2", "ghp_example", str(tmp_path / "a"))
    assert fake_provider[-1] == ("https://api.github.com/repos/acme/payments/tarball/release%2F1.2",
                                 {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Authorization": "Bearer ghp_example"})
    scm.fetch("https://gitlab.com/acme/platform/api", None, None, "glpat-x", str(tmp_path / "b"))
    assert fake_provider[-1][0].startswith("https://gitlab.com/api/v4/projects/acme%2Fplatform%2Fapi/repository/archive.tar.gz")
    assert fake_provider[-1][1]["PRIVATE-TOKEN"] == "glpat-x"
    scm.fetch("https://bitbucket.org/acme/web", None, None, "jane:app-pass", str(tmp_path / "c"))
    assert fake_provider[-1][0] == "https://bitbucket.org/acme/web/get/main.tar.gz"                 # default branch looked up
    assert fake_provider[-1][1]["Authorization"].startswith("Basic ")


def test_azure_devops_zip(monkeypatch, tmp_path):
    import base64, zipfile
    seen = []
    def _http(url, headers, limit=0, want_json=False):
        seen.append((url, headers))
        if want_json:
            return {"value": [{"commitId": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"}]}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("requirements.txt", "pyyaml==5.3\n"); z.writestr("../evil.txt", "x"); z.writestr("src/app.py", "import yaml\n")
        return buf.getvalue()
    monkeypatch.setattr(scm, "_http", _http)
    root, commit = scm.fetch("https://dev.azure.com/contoso/Payments%20Team/_git/ledger", None, "main", "azpat", str(tmp_path))
    assert commit.startswith("9f86d08") and os.path.isfile(os.path.join(root, "src", "app.py"))
    assert not (tmp_path.parent / "evil.txt").exists()
    url, h = seen[0]
    assert url.startswith("https://dev.azure.com/contoso/Payments%20Team/_apis/git/repositories/ledger/items?")
    assert "versionDescriptor.version=main" in url and "%24format=zip" in url
    assert h["Authorization"] == "Basic " + base64.b64encode(b":azpat").decode()


def test_console_flow_scan_report_sbom_delete(fake_provider):
    c = TestClient(app)
    r = c.post("/api/v1/repos/sources?wait=true", json={"url": "https://github.com/acme/payments-web", "token": "ghp_secret_value"}, headers=H)
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["status"] == "done" and s["private"] is True and s["last_commit"] == "0123abc", s
    assert "ghp_secret_value" not in r.text
    by = s["summary"]["by_engine"]
    for engine in ("sca", "sast", "secrets", "iac", "cicd"):
        assert by.get(engine, 0) > 0, (engine, by)
    assert s["summary"]["components"] > 0
    assert fake_provider[-1][1]["Authorization"] == "Bearer ghp_secret_value"
    # the repository and its findings appear in the console's existing views
    assert any(x["name"] == "payments-web" for x in c.get("/api/repos", headers=H).json())
    rep = c.get(f"/api/v1/repos/sources/{s['id']}/report", headers=H)
    assert rep.status_code == 200
    for section in ("Source code analysis (SAST)", "Software components (SCA)", "Secrets exposure", "Infrastructure as Code",
                    "CI/CD pipeline &amp; deployment", "Software bill of materials", "Executive summary", "Overall risk rating",
                    "OWASP Top 10", "PCI DSS", "ISO/IEC 27001:2022", "NIST SSDF", "Remediation roadmap", "Attestation"):
        assert section in rep.text, section
    assert "ghp_secret_value" not in rep.text
    # the external edition for the customer's customers withholds code evidence
    ext = c.get(f"/api/v1/repos/sources/{s['id']}/report?audience=external&prepared_for=Initech%20Bank", headers=H).text
    assert "External edition" in ext and "Initech Bank" in ext and "<b>Evidence</b>" not in ext
    assert "<b>Evidence</b>" in rep.text
    sbom = c.get(f"/api/v1/repos/sources/{s['id']}/sbom", headers=H).json()
    assert sbom["bomFormat"] == "CycloneDX" and sbom["components"]
    assert c.post("/api/v1/repos/sources", json={"url": "https://github.com/acme/payments-web"}, headers=H).status_code == 409
    assert c.delete(f"/api/v1/repos/sources/{s['id']}", headers=H).status_code == 204
    assert c.get(f"/api/v1/repos/sources/{s['id']}/report", headers=H).status_code == 404


def test_provider_errors_are_explained(monkeypatch):
    def _deny(url, headers, limit=0, want_json=False):
        raise scm.ScmError("the provider answered HTTP 404: the repository does not exist, or it is private and the access token is missing")
    monkeypatch.setattr(scm, "_http", _deny)
    c = TestClient(app)
    s = c.post("/api/v1/repos/sources?wait=true", json={"url": "https://github.com/acme/private-thing"}, headers=H).json()
    assert s["status"] == "failed" and "private" in s["last_error"]
    c.delete(f"/api/v1/repos/sources/{s['id']}", headers=H)


# ---------------------------------------------------------------- Git over HTTPS (CodeCommit, Google Cloud, any server)
def _git_server(tmp_path, user="jane", password="s3cret-pass"):
    """A dumb-HTTP Git server that requires Basic auth, like CodeCommit HTTPS Git credentials."""
    import base64, subprocess, threading
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
    work, bare = tmp_path / "work", tmp_path / "srv" / "orders.git"
    work.mkdir(); bare.parent.mkdir()
    (work / "requirements.txt").write_text("pyyaml==5.3\n")
    (work / "Dockerfile").write_text("FROM python:latest\nCMD python app.py\n")
    g = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "init.defaultBranch=main"]
    subprocess.run(g + ["init", "-q", str(work)], check=True)
    subprocess.run(g + ["-C", str(work), "add", "."], check=True)
    subprocess.run(g + ["-C", str(work), "commit", "-qm", "init"], check=True)
    subprocess.run(["git", "clone", "-q", "--bare", str(work), str(bare)], check=True)
    subprocess.run(["git", "-C", str(bare), "update-server-info"], check=True)
    want, seen = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode(), []

    class H(SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(tmp_path / "srv"), **k)
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            if self.headers.get("Authorization") != want:
                self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="git"'); self.end_headers(); return
            super().do_GET()
        def log_message(self, *a): pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def test_git_https_clone_with_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("MYELIN_SCM_ALLOW_HTTP", "1")
    monkeypatch.setenv("MYELIN_SCM_ALLOW_PRIVATE", "1")
    srv, seen = _git_server(tmp_path)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/orders.git"
        root, commit = scm.fetch(url, "git", None, "jane:s3cret-pass", str(tmp_path / "out"))
        assert len(commit) == 40 and os.path.isfile(os.path.join(root, "Dockerfile")) and not os.path.exists(os.path.join(root, ".git"))
        assert all("s3cret" not in p for p, _ in seen)                                           # never in the URL
        with pytest.raises(scm.ScmError, match="credential can read"):
            scm.fetch(url, "git", None, "jane:wrong", str(tmp_path / "out2"))
    finally:
        srv.shutdown()


def test_git_refuses_internal_hosts_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("MYELIN_SCM_ALLOW_HTTP", "1")
    monkeypatch.delenv("MYELIN_SCM_ALLOW_PRIVATE", raising=False)
    for host in ("127.0.0.1", "169.254.169.254", "10.0.0.5"):
        with pytest.raises(scm.ScmError, match="internal address"):
            scm.fetch(f"http://{host}/x/repo.git", "git", None, None, str(tmp_path))


def test_gcp_service_account_key_is_exchanged_for_a_token(tmp_path, monkeypatch):
    import json as _j, threading, urllib.parse
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    got = {}

    class T(BaseHTTPRequestHandler):
        def do_POST(self):
            body = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            got["claims"] = jwt.decode(body["assertion"][0], key.public_key(), algorithms=["RS256"], audience=got["aud"])
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(_j.dumps({"access_token": "ya29.test-token", "expires_in": 3600}).encode())
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), T)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    got["aud"] = f"http://127.0.0.1:{srv.server_port}/token"
    sa = _j.dumps({"type": "service_account", "client_email": "myelin-reader@acme.iam.gserviceaccount.com",
                   "private_key": pem, "private_key_id": "k1", "token_uri": got["aud"]})
    try:
        assert scm.gcp_access_token(sa) == "ya29.test-token"
        assert got["claims"]["iss"] == "myelin-reader@acme.iam.gserviceaccount.com"
        assert scm.gcp_access_token("Bearer ya29.raw") == "ya29.raw"
    finally:
        srv.shutdown()


def test_rescan_closes_fixed_findings_and_reopens_regressions(monkeypatch):
    """A finding that disappears is closed; one that comes back is reopened; a false-positive mark sticks."""
    from app.main import DEMO
    from myelin_engine import vulndb

    # Simulate a complete offline feed; the scan still combines it with the bundled advisories.
    monkeypatch.setattr(vulndb, "_offline_osv", lambda comps: {})
    archives = {"v1": _archive(top="acme-svc-1111111"), "v2": None}
    import tempfile
    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, "app")); open(os.path.join(tmp, "app", "requirements.txt"), "w").write("pyyaml==6.0.1\n")
    open(os.path.join(tmp, "app", "Dockerfile"), "w").write("FROM python:3.12-slim\nUSER 10001\nHEALTHCHECK CMD true\n")
    archives["v2"] = _archive(top="acme-svc-2222222", src=os.path.join(tmp, "app"))
    current = {"a": archives["v1"]}
    monkeypatch.setattr(scm, "_http", lambda url, headers, limit=0, want_json=False: current["a"])
    c = TestClient(app)
    s = c.post("/api/v1/repos/sources?wait=true", json={"url": "https://github.com/acme/svc"}, headers=H).json()
    mine = lambda: [f for f in DEMO.db["findings"] if f.get("repo") == "svc"]
    first = mine()
    assert first and all(f["status"] == "open" for f in first)
    fp = next(f for f in first if f["engine"] == "sast")
    assert c.post(f"/api/findings/{fp['id']}/status", json={"status": "suppressed", "reason": "false positive: test fixture"}, headers=H).status_code == 200
    current["a"] = archives["v2"]                                                                # vulnerable code removed
    with monkeypatch.context() as incomplete:
        incomplete.setattr(vulndb, "_offline_osv", lambda comps: None)
        rescan = c.post(f"/api/v1/repos/sources/{s['id']}/scan?wait=true", headers=H).json()
        assert "sca" in rescan["summary"]["partial"]
        assert any(f["status"] == "open" and f["engine"] == "sca" for f in mine())
    c.post(f"/api/v1/repos/sources/{s['id']}/scan?wait=true", headers=H)
    after = {f["fingerprint"]: f for f in mine()}
    assert all(f["status"] in ("fixed", "suppressed") for f in after.values())
    assert after[fp["fingerprint"]]["status"] == "suppressed"                                     # decision kept
    assert any(f["status"] == "fixed" and f.get("fixed_in") == "2222222" for f in after.values())
    current["a"] = archives["v1"]                                                                # regression
    c.post(f"/api/v1/repos/sources/{s['id']}/scan?wait=true", headers=H)
    again = {f["fingerprint"]: f for f in mine()}
    assert again[fp["fingerprint"]]["status"] == "suppressed"
    assert all(f["status"] == "open" for k, f in again.items() if k != fp["fingerprint"])
    c.delete(f"/api/v1/repos/sources/{s['id']}", headers=H)


def test_sign_in_page_instead_of_archive_is_explained(monkeypatch, tmp_path):
    """Azure DevOps answers an expired PAT with HTTP 203 and an HTML sign-in page."""
    monkeypatch.setattr(scm, "_http", lambda url, headers, limit=0, want_json=False: b"<!DOCTYPE html><html><body>Sign in</body></html>")
    with pytest.raises(scm.ScmError, match="sign-in page"):
        scm.fetch("https://dev.azure.com/contoso/Payments/_git/ledger", None, None, "expired", str(tmp_path))
    monkeypatch.setattr(scm, "_http", lambda url, headers, limit=0, want_json=False: b"not an archive at all")
    with pytest.raises(scm.ScmError, match="did not return a repository archive"):
        scm.fetch("https://github.com/acme/x", None, None, None, str(tmp_path))
