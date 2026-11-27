# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""End-to-end enterprise mode: real PostgreSQL (RLS), mocked OIDC provider, full API surface."""
from datetime import datetime, timedelta, timezone
import base64
import importlib
import importlib.util
import json
import os
import sys
import tempfile
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests.idp_fixture import FakeIdP  # noqa: E402
from tests.pg import drop, needs_pg, provision  # noqa: E402

HAS_EVIDENCE_STORE = importlib.util.find_spec("app.evidence.service") is not None

pytestmark = needs_pg
ROLE_MAP = {"myelin-tenant-admin": "tenant_admin", "myelin-security-lead": "security_lead", "myelin-auditor": "auditor", "myelin-viewer": "viewer"}


@pytest.fixture(scope="module")
def ent():
    from fastapi.testclient import TestClient
    urls = provision()
    fake = FakeIdP()
    from app.db import admin
    acme = admin.create_tenant(urls["owner"], "acme", "Acme Bank", plan="enterprise", bindings=[(fake.issuer, "acme")])
    globex = admin.create_tenant(urls["owner"], "globex", "Globex Insurance", plan="business", bindings=[(fake.issuer, "globex")])
    tmp = tempfile.mkdtemp()
    idp_cfg = os.path.join(tmp, "idps.yaml")
    json.dump({"providers": [{"name": "kc", "type": "keycloak", "issuer": fake.issuer, "client_id": "myelin-console",
                              "client_secret_ref": "env://TEST_OIDC_SECRET", "role_mapping": ROLE_MAP}]}, open(idp_cfg, "w"))
    sk = Ed25519PrivateKey.generate()
    from app import licensing
    vendor = Ed25519PrivateKey.generate()
    old_keys, licensing.TRUSTED_KEYS = licensing.TRUSTED_KEYS, {"test-vendor": vendor.public_key()}
    lic = licensing.sign({"lid": "t", "kid": "test-vendor", "licensee": "Test", "plan": "enterprise", "max_tenants": 2,
                          "issued_at": "2026-01-01T00:00:00+00:00", "expires_at": "2099-01-01T00:00:00+00:00"}, vendor)
    env = {"MYELIN_LICENSE": lic,"MYELIN_MODE": "enterprise", "MYELIN_DATABASE_URL": urls["app"], "MYELIN_IDP_CONFIG": idp_cfg,
           "MYELIN_SESSION_SECRET": "s" * 48, "MYELIN_API_KEY_PEPPER": "p" * 48, "TEST_OIDC_SECRET": "client-secret",
           "MYELIN_EVIDENCE_SIGNING_KEY": base64.b64encode(sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                                           serialization.NoEncryption())).decode(),
           "MYELIN_EVIDENCE_STORE": "file://" + os.path.join(tmp, "evidence"), "MYELIN_PUBLIC_URL": "https://testserver",
           "MYELIN_CORS": "https://testserver", "MYELIN_DEMO_OPEN": "false", "MYELIN_ENV_FILE": "/nonexistent"}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    import app.config, app.connectors.api, app.main
    importlib.reload(app.config)
    importlib.reload(app.connectors.api)
    main = importlib.reload(app.main)
    from app.auth.oidc import JWKSCache
    main.AUTH.verifier.jwks = JWKSCache(fetch=fake.fetch)
    codes = {}

    def token_endpoint(req: httpx.Request):
        form = parse_qs(req.content.decode())
        assert req.headers["authorization"] == "Basic " + base64.b64encode(b"myelin-console:client-secret").decode()
        code = form["code"][0]
        assert "code_verifier" in form
        return httpx.Response(200, json={"id_token": codes[code], "access_token": "at", "refresh_token": "rt-secret"})
    main.AUTH.http = httpx.Client(transport=httpx.MockTransport(token_endpoint))
    client = TestClient(main.app, base_url="https://testserver")
    yield {"c": client, "fake": fake, "acme": acme, "globex": globex, "main": main, "codes": codes, "tmp": tmp, "urls": urls,
           "vendor": vendor}
    licensing.TRUSTED_KEYS = old_keys
    for k, v in old.items():
        os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    importlib.reload(app.config)
    importlib.reload(app.connectors.api)
    importlib.reload(app.main)
    drop(urls["db"])


def H(e, tenant="acme", roles=("myelin-security-lead",), sub="alice", **kw):
    return {"Authorization": "Bearer " + e["fake"].token(tenant=tenant, sub=sub, email=f"{sub}@{tenant}.test",
                                                         realm_access={"roles": list(roles)}, **kw)}


SCAN = {"repo": "payments-api", "branch": "main", "commit": "abc1234", "findings": [
    {"engine": "secrets", "rule_id": "NM-SEC-001", "title": "AWS key", "severity": "critical", "file": "a.py", "line": 3},
    {"engine": "sca", "rule_id": "CVE-2021-44228", "cve": "CVE-2021-44228", "title": "log4j", "severity": "critical", "cvss": 10, "kev": True,
     "package": "log4j-core", "version": "2.14.1", "fixed_version": "2.17.1", "file": "pom.xml"}]}


def test_unauthenticated_is_rejected(ent):
    for path in ("/api/summary", "/api/findings", "/api/audit", "/api/v1/connectors") + (("/api/v1/evidence",) if HAS_EVIDENCE_STORE else ()):
        assert ent["c"].get(path).status_code == 401, path


def test_mfa_required_with_step_up_challenge(ent):
    r = ent["c"].get("/api/tenant", headers=H(ent, acr="1", amr=["pwd"]))
    assert r.status_code == 401 and "insufficient_user_authentication" in r.headers["www-authenticate"]


def test_bearer_token_tenant_and_roles(ent):
    r = ent["c"].get("/api/tenant", headers=H(ent))
    assert r.status_code == 200 and r.json()["name"] == "Acme Bank" and r.json()["you"]["roles"] == ["security_lead"]


def test_upload_and_cross_tenant_isolation_through_api(ent):
    c = ent["c"]
    r = c.post("/api/scans", json=SCAN, headers=H(ent))
    assert r.status_code == 200 and r.json()["decision"]["decision"] == "block" and r.json()["new"] == 2
    acme_items = c.get("/api/findings", headers=H(ent)).json()["items"]
    assert len(acme_items) == 2
    g = c.get("/api/findings", headers=H(ent, tenant="globex"))
    assert g.status_code == 200 and g.json()["total"] == 0
    fid = acme_items[0]["id"]
    assert c.get(f"/api/findings/{fid}", headers=H(ent, tenant="globex")).status_code == 404
    assert c.post(f"/api/findings/{fid}/status", json={"status": "fixed"}, headers=H(ent, tenant="globex")).status_code == 404
    assert c.get("/api/summary", headers=H(ent, tenant="globex")).json()["kpis"]["open_findings"] == 0


def test_dashboards_are_computed_from_real_data(ent):
    c = ent["c"]
    c.post("/api/scans", json={**SCAN, "stats": {"raw": 9, "after_dedup": 2, "reported": 2}}, headers=H(ent))
    s = c.get("/api/summary", headers=H(ent)).json()
    assert len(s["trend"]) == 90 and s["trend"][-1]["open"] == s["kpis"]["open_findings"] == 2
    assert s["trend"][-1]["introduced"] == 2 and s["funnel"]["raw_alerts"] == 9
    assert s["runs_30d"] >= 1 and s["gates_30d"][-1]["block"] >= 1 and s["gate_pass_rate"] is not None
    assert s["by_repo"][0]["repo"] == SCAN["repo"] and s["by_repo"][0]["gate"] == "block"
    assert {f["id"] for f in s["frameworks"]} >= {"owasp", "pci", "iso"}
    assert sum(a["critical"] + a["high"] + a["medium"] + a["low"] for a in s["aging"]) == 2
    # closing a finding feeds the history and the time-to-remediate
    fid = c.get("/api/findings", headers=H(ent)).json()["items"][0]["id"]
    c.post(f"/api/findings/{fid}/status", json={"status": "fixed", "reason": "patched"}, headers=H(ent))
    s = c.get("/api/summary", headers=H(ent)).json()
    assert s["trend"][-1]["open"] == 1 and s["kpis"]["open_findings"] == 1
    assert c.get("/api/summary", headers=H(ent, tenant="globex")).json()["by_repo"] == []
    c.post(f"/api/findings/{fid}/status", json={"status": "open"}, headers=H(ent))      # leave shared state as found


def test_tenant_header_spoofing_has_no_effect(ent):
    r = ent["c"].get("/api/findings", headers={**H(ent, tenant="globex"), "X-Tenant-Id": str(ent["acme"])}, params={"tenant": str(ent["acme"])})
    assert r.json()["total"] == 0


def test_rbac_enforced(ent):
    c = ent["c"]
    fid = c.get("/api/findings", headers=H(ent)).json()["items"][0]["id"]
    assert c.post(f"/api/findings/{fid}/status", json={"status": "fixed"}, headers=H(ent, roles=["myelin-viewer"])).status_code == 403
    assert c.post("/api/scans", json=SCAN, headers=H(ent, roles=["myelin-auditor"])).status_code == 403
    assert c.get("/api/audit", headers=H(ent, roles=["myelin-viewer"])).status_code == 403
    assert c.get("/api/findings", headers=H(ent, roles=[])).status_code == 403
    assert c.post(f"/api/findings/{fid}/status", json={"status": "risk_accepted", "reason": "compensating control"},
                  headers=H(ent)).status_code == 400                      # accepted risk must expire
    exp = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
    r = c.post(f"/api/findings/{fid}/status", json={"status": "risk_accepted", "reason": "compensating control", "expires": exp}, headers=H(ent))
    assert r.status_code == 200 and r.json()["status"] == "risk_accepted" and r.json()["triage"]["expires"] == exp


def test_api_keys_for_ci(ent):
    c = ent["c"]
    assert c.post("/api/v1/api-keys", json={"name": "ci", "roles": ["integration"]}, headers=H(ent)).status_code == 403   # security_lead lacks apikeys:manage
    assert c.post("/api/v1/api-keys", json={"name": "x", "roles": ["tenant_admin"]}, headers=H(ent, roles=["myelin-tenant-admin"])).status_code == 400
    key = c.post("/api/v1/api-keys", json={"name": "github-actions", "roles": ["integration"]},
                 headers=H(ent, roles=["myelin-tenant-admin"])).json()["api_key"]
    r = c.post("/api/scans", json={**SCAN, "repo": "web"}, headers={"X-API-Key": key})
    assert r.status_code == 200
    assert c.get("/api/audit", headers={"Authorization": f"Bearer {key}"}).status_code == 403          # integration role is narrow
    assert c.get("/api/findings", headers={"X-API-Key": key[:-4] + "AAAA"}).status_code == 401
    assert c.get("/api/findings", headers={"X-API-Key": "nm_aaaaaaaaaaaa_" + "x" * 40}).status_code == 401


def test_console_login_session_csrf_logout(ent):
    from app.auth.service import CSRF_COOKIE
    c = ent["c"]
    r = c.get("/auth/login", params={"idp": "kc", "return_to": "https://evil.example/"}, follow_redirects=False)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["client_id"] == ["myelin-console"] and "acr_values" in q
    ent["codes"]["code-1"] = ent["fake"].token(nonce=q["nonce"][0], sub="alice", realm_access={"roles": ["myelin-security-lead"]})
    r = c.get("/auth/callback", params={"code": "code-1", "state": q["state"][0]}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/"                      # open redirect neutralised
    set_cookie = r.headers.get_list("set-cookie")
    assert any(h.startswith("__Host-myelin_session=") and "HttpOnly" in h and "Secure" in h for h in set_cookie)
    me = c.get("/auth/me")
    assert me.status_code == 200 and me.json()["roles"] == ["security_lead"] and me.json()["method"] == "session"
    fid = c.get("/api/findings").json()["items"][0]["id"]
    assert c.post(f"/api/findings/{fid}/status", json={"status": "open"}).status_code == 403          # no CSRF header
    csrf = c.cookies.get(CSRF_COOKIE)
    assert c.post(f"/api/findings/{fid}/status", json={"status": "open"}, headers={"X-CSRF-Token": csrf}).status_code == 200
    assert c.post("/auth/logout", headers={"X-CSRF-Token": csrf}).json()["logged_out"]
    c.cookies.clear()
    assert c.get("/auth/me").status_code == 401


def test_replayed_login_state_is_rejected(ent):
    r = ent["c"].get("/auth/callback", params={"code": "code-1", "state": "forged"}, follow_redirects=False)
    assert r.status_code == 400


def test_audit_chain_verifies(ent):
    r = ent["c"].get("/api/v1/evidence/audit/verify", headers=H(ent, roles=["myelin-auditor"])).json()
    assert r["valid"] and r["checked"] >= 5


def test_connectors_least_privilege_and_isolation(ent):
    from app.connectors import api as capi
    from app.connectors.github import GitHubConnector
    from tests.test_connectors import gh_secret, github_mock
    c, tid = ent["c"], ent["acme"]
    base = {"kind": "github", "name": "acme-org", "config": {"organization": "acme"}}
    admin = H(ent, roles=["myelin-tenant-admin"])
    assert c.post("/api/v1/connectors", json={**base, "credential_ref": "env://MYELIN_SESSION_SECRET"}, headers=admin).status_code == 400
    assert c.post("/api/v1/connectors", json={**base, "credential_ref": "vault://secret/myelin/tenants/other/gh"}, headers=admin).status_code == 400
    assert c.post("/api/v1/connectors", json={**base, "credential_ref": f"vault://secret/myelin/tenants/{tid}/gh"}, headers=H(ent)).status_code == 403
    conn = c.post("/api/v1/connectors", json={**base, "credential_ref": f"vault://secret/myelin/tenants/{tid}/gh"}, headers=admin).json()
    secret = gh_secret()
    capi.OVERRIDES["github"] = lambda row: GitHubConnector(row.config, row.credential_ref, resolve=lambda _: secret,
                                                           http=httpx.Client(transport=httpx.MockTransport(github_mock([]))))
    try:
        r = c.post(f"/api/v1/connectors/{conn['id']}/sync", headers=admin).json()
    finally:
        capi.OVERRIDES.clear()
    assert r["findings"] >= 3 and r["evidence"] == 1   # evidence count is reported even when no store keeps it
    assert any(f["repo"] == "acme/payments" for f in c.get("/api/findings", headers=H(ent), params={"limit": 1000}).json()["items"])
    assert c.get("/api/v1/connectors", headers=H(ent, tenant="globex", roles=["myelin-tenant-admin"])).json() == []
    assert c.post(f"/api/v1/connectors/{conn['id']}/sync", headers=H(ent, tenant="globex", roles=["myelin-tenant-admin"])).status_code == 404


def test_readiness_and_metrics(ent):
    r = ent["c"].get("/readyz").json()
    assert r["status"] == "ready" and r["checks"]["database"] == "ok" and r["checks"]["schema"] == "0011"
    assert "myelin_http_requests_total" in ent["c"].get("/metrics").text
    h = ent["c"].get("/api/health").headers
    assert h["x-frame-options"] == "DENY" and "max-age" in h["strict-transport-security"] and h["cache-control"] == "no-store"


def _set_license(ent, **payload):
    from app import licensing, secrets
    base = {"lid": "t2", "kid": "test-vendor", "licensee": "Test", "plan": "enterprise",
            "issued_at": "2026-01-01T00:00:00+00:00", "expires_at": "2099-01-01T00:00:00+00:00"}
    os.environ["MYELIN_LICENSE"] = licensing.sign({**base, **payload}, ent["vendor"]) if payload.get("_raw") is None else payload["_raw"]
    secrets.clear_cache()
    ent["main"].LICENSE.refresh()


def test_license_status_endpoint(ent):
    r = ent["c"].get("/api/v1/license", headers=H(ent, roles=["myelin-tenant-admin"])).json()
    assert r["state"] == "valid" and r["licensee"] == "Test" and r["limits"]["max_tenants"] == 2 and "usage" in r
    v = ent["c"].get("/api/v1/license", headers=H(ent, roles=["myelin-viewer"])).json()
    assert set(v) == {"state", "reason", "days_remaining", "plan", "expires_at"}


def test_license_feature_cap(ent):
    _set_license(ent, plan="team")                       # tenant plan is enterprise, licence only team
    try:
        r = ent["c"].get("/api/compliance", headers=H(ent))
        assert r.status_code == 402 and "licence" in r.json()["detail"]
    finally:
        _set_license(ent)


def test_restricted_license_keeps_data_readable(ent):
    c = ent["c"]
    _set_license(ent, _raw="NMLIC1.garbage.sig")
    try:
        assert c.get("/api/findings", headers=H(ent)).status_code == 200              # reads continue
        if HAS_EVIDENCE_STORE:
            assert c.get("/api/v1/evidence", headers=H(ent)).status_code == 200
        r = c.post("/api/scans", json=SCAN, headers=H(ent))
        assert r.status_code == 402 and "Existing data remains available" in r.json()["detail"]
        assert "restricted" in c.get("/api/health").headers.get("x-myelin-license", "")
        assert "myelin_license_usable 0.0" in c.get("/metrics").text
    finally:
        _set_license(ent)
    assert c.post("/api/scans", json=SCAN, headers=H(ent)).status_code == 200


# ---------------- online live-application testing ----------------
def _target(ent, **kw):
    tid = ent["acme"]
    body = {"name": "payments-api", "base_url": "https://api.acme.example", "spec_url": "https://api.acme.example/openapi.json",
            "identities": [{"name": "u1", "role": "customer", "headers": {"Authorization": f"vault://secret/myelin/tenants/{tid}/dast/u1"}},
                           {"name": "u2", "role": "customer", "headers": {"Authorization": f"vault://secret/myelin/tenants/{tid}/dast/u2"}}]}
    body.update(kw)
    return body


def test_dast_targets_validation_rbac_and_isolation(ent, monkeypatch):
    from app import main
    from myelin_engine import dast as eng
    c, admin = ent["c"], H(ent, roles=["myelin-tenant-admin"])
    monkeypatch.setattr(main, "_dast_runtime", lambda: {"resolver": None, "guard": lambda h: None, "require_verification": True,
                                                        "max_requests": 1500})
    lit = _target(ent)
    lit["identities"][0]["headers"]["Authorization"] = "Bearer literal-token"
    assert c.post("/api/v1/dast/targets", json=lit, headers=admin).status_code == 400            # secrets must be references
    assert c.post("/api/v1/dast/targets", json=_target(ent, base_url="http://api.acme.example"), headers=admin).status_code == 400
    monkeypatch.setattr(main, "_dast_runtime", lambda: {"resolver": None, "guard": eng.host_guard(False),
                                                        "require_verification": True, "max_requests": 1500})
    r = c.post("/api/v1/dast/targets", json=_target(ent, name="internal", base_url="https://169.254.169.254"), headers=admin)
    assert r.status_code == 400 and "not allowed" in r.json()["detail"]                         # SSRF guard
    monkeypatch.setattr(main, "_dast_runtime", lambda: {"resolver": None, "guard": lambda h: None, "require_verification": True,
                                                        "max_requests": 1500})
    assert c.post("/api/v1/dast/targets", json=_target(ent), headers=H(ent, roles=["myelin-viewer"])).status_code == 403
    t = c.post("/api/v1/dast/targets", json=_target(ent), headers=admin)
    assert t.status_code == 201 and t.json()["identities"][0]["headers"] == ["Authorization"]
    tid = t.json()["id"]
    assert "vault://" not in json.dumps(t.json())                                               # references never echoed
    assert c.get(f"/api/v1/dast/targets/{tid}", headers=H(ent, roles=["myelin-auditor"])).status_code == 200
    assert c.get("/api/v1/dast/targets", headers=H(ent, tenant="globex", roles=["myelin-tenant-admin"])).status_code in (200, 402)
    g = c.get(f"/api/v1/dast/targets/{tid}", headers=H(ent, tenant="globex", roles=["myelin-tenant-admin"]))
    assert g.status_code in (404, 402)                                                          # other tenant cannot see it
    r = c.post(f"/api/v1/dast/targets/{tid}/run", headers=H(ent))
    assert r.status_code == 409 and "verify ownership" in r.json()["detail"]                    # verification required
    assert c.post(f"/api/v1/dast/targets/{tid}/run", headers=H(ent, roles=["myelin-auditor"])).status_code == 403
    # edit: clear the spec, change criticality; the address is fixed so ownership is kept; auditors cannot edit
    main.TARGETS.update(ent["acme"], tid, verified_at=main.DT.now())
    assert c.patch(f"/api/v1/dast/targets/{tid}", json={"spec_url": ""}, headers=H(ent, roles=["myelin-auditor"])).status_code == 403
    e = c.patch(f"/api/v1/dast/targets/{tid}", json={"spec_url": "", "criticality": "high"}, headers=admin)
    assert e.status_code == 200, e.json()
    assert e.json()["spec_url"] is None and e.json()["config"]["criticality"] == "high" and e.json()["verified_at"]
    bad = c.patch(f"/api/v1/dast/targets/{tid}", json={"identities": [{"name": "x", "headers": {"Authorization": "Bearer abc"}},
                                                                       {"name": "y", "headers": {"Authorization": "Bearer def"}}]}, headers=admin)
    assert bad.status_code == 400                                                               # still references only
    assert c.patch(f"/api/v1/dast/targets/{tid}", json={"spec_url": ""}, headers=H(ent, tenant="globex", roles=["myelin-tenant-admin"])).status_code in (404, 402)


def test_dast_online_run_stores_findings_and_report(ent, monkeypatch):
    from app import main
    from tests.vapi import IDENTITIES, start
    server, th = start(8098)
    try:
        tokens = {f"vault://secret/myelin/tenants/{ent['acme']}/dast/{i['name']}": i["headers"]["Authorization"] for i in IDENTITIES}
        monkeypatch.setattr(main, "_dast_runtime", lambda: {"resolver": tokens.__getitem__, "guard": None,
                                                            "require_verification": False, "max_requests": 1500})
        monkeypatch.setattr(main.DT, "validate", lambda *a, **k: None)                      # allow the local http test target
        body = _target(ent, name="orion-local", base_url="http://127.0.0.1:8098", spec_url="http://127.0.0.1:8098/openapi.json",
                       identities=[{**i, "headers": {"Authorization": ref}} for i, ref in zip(IDENTITIES, tokens)],
                       privileged=[{"path": "/api/v2/admin/*", "roles": ["admin"]}])
        tid = ent["c"].post("/api/v1/dast/targets", json=body, headers=H(ent, roles=["myelin-tenant-admin"])).json()["id"]
        r = ent["c"].post(f"/api/v1/dast/targets/{tid}/run?wait=true", headers=H(ent))
        assert r.status_code == 202 and r.json()["status"] == "done", r.json()
        assert r.json()["summary"]["by_severity"]["critical"] >= 2
        res = ent["c"].get(f"/api/v1/dast/targets/{tid}/result", headers=H(ent)).json()
        assert "NM-DAST-020" in {f["rule_id"] for f in res["findings"]} and "alice-token" not in json.dumps(res)
        rep = ent["c"].get(f"/api/v1/dast/targets/{tid}/report", headers=H(ent, roles=["myelin-auditor"]))
        assert rep.status_code == 200 and "API1:2023" in rep.text and "alice-token" not in rep.text
        items = ent["c"].get("/api/findings", headers=H(ent), params={"limit": 1000}).json()["items"]
        assert any(f["repo"] == "orion-local" and f["engine"] == "dast" for f in items)
        assert not any(f["repo"] == "orion-local" for f in ent["c"].get("/api/findings", headers=H(ent, tenant="globex")).json()["items"])
        # wrong spec URL -> clear failure; clearing it in Edit (as the console sends it) -> the next run succeeds without a spec
        admin = H(ent, roles=["myelin-tenant-admin"])
        assert ent["c"].patch(f"/api/v1/dast/targets/{tid}", json={"spec_url": "http://127.0.0.1:8098/missing.json"}, headers=admin).status_code == 200
        bad = ent["c"].post(f"/api/v1/dast/targets/{tid}/run?wait=true", headers=H(ent)).json()
        assert bad["status"] == "failed" and "OpenAPI spec" in bad["last_error"], bad
        e = ent["c"].patch(f"/api/v1/dast/targets/{tid}", json={"spec_url": "", "criticality": "medium", "identities": []}, headers=admin)
        assert e.status_code == 200 and e.json()["spec_url"] is None and e.json()["identities"] == [], e.json()
        ok = ent["c"].post(f"/api/v1/dast/targets/{tid}/run?wait=true", headers=H(ent)).json()
        assert ok["status"] == "done", ok
    finally:
        server.should_exit = True


def test_repo_sources_enterprise_token_in_vault_and_tenant_isolation(ent, monkeypatch):
    import json, threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from app import secrets as sm
    from tests.test_repo_sources import _archive
    kv = {}

    class V(BaseHTTPRequestHandler):
        def do_POST(self):
            kv[self.path.replace("/v1/secret/data/", "")] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["data"]
            self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
        def do_GET(self):
            d = kv.get(self.path.replace("/v1/secret/data/", ""))
            self.send_response(200 if d else 404); self.send_header("Content-Type", "application/json"); self.end_headers()
            if d:
                self.wfile.write(json.dumps({"data": {"data": d}}).encode())
        def do_DELETE(self):
            kv.pop(self.path.replace("/v1/secret/metadata/", ""), None); self.send_response(204); self.end_headers()
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), V)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("VAULT_TOKEN", "test")
    sm.clear_cache()
    seen = []
    from app import scm
    monkeypatch.setattr(scm, "_http", lambda url, headers, limit=0, want_json=False: seen.append(headers) or _archive())
    c, admin = ent["c"], H(ent, roles=["myelin-security-lead"])
    try:
        r = c.post("/api/v1/repos/sources?wait=true", json={"url": "https://github.com/acme/ledger", "token": "ghp_enterprise_secret"}, headers=admin)
        assert r.status_code == 201, r.text
        s = r.json()
        assert s["status"] == "done" and s["private"] and s["summary"]["by_engine"].get("sast"), s
        assert seen[-1]["Authorization"] == "Bearer ghp_enterprise_secret"                     # resolved from the vault at fetch time
        path = f"myelin/tenants/{ent['acme']}/repos/{s['id']}"
        assert kv[path] == {"token": "ghp_enterprise_secret"}
        from sqlalchemy import create_engine, text
        with create_engine(ent["urls"]["owner"]).connect() as db:                                  # never stored in the database
            row = db.execute(text("select credential_ref, last_result::text from repo_sources where id = :i"), {"i": s["id"]}).one()
        assert row[0] == f"vault://secret/{path}#token" and "ghp_enterprise_secret" not in (row[1] or "")
        # tenant isolation: globex cannot see, scan, report or delete acme's repository
        g = H(ent, tenant="globex", roles=["myelin-tenant-admin"])
        assert all(x["id"] != s["id"] for x in c.get("/api/v1/repos/sources", headers=g).json())
        for call in (lambda: c.post(f"/api/v1/repos/sources/{s['id']}/scan", headers=g),
                     lambda: c.get(f"/api/v1/repos/sources/{s['id']}/report", headers=g),
                     lambda: c.delete(f"/api/v1/repos/sources/{s['id']}", headers=g)):
            assert call().status_code == 404
        # viewers can read reports but cannot add or scan
        v = H(ent, roles=["myelin-viewer"])
        assert c.get(f"/api/v1/repos/sources/{s['id']}/report", headers=v).status_code == 200
        assert c.post(f"/api/v1/repos/sources/{s['id']}/scan", headers=v).status_code == 403
        assert c.delete(f"/api/v1/repos/sources/{s['id']}", headers=admin).status_code == 204
        assert path not in kv                                                                    # token removed with the repository
    finally:
        srv.shutdown()
        sm.clear_cache()


def test_ticketing_enterprise_vault_and_isolation(ent, monkeypatch):
    import json, threading
    import httpx
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from app import secrets as sm
    from tests.test_itsm import Fake
    kv = {}

    class V(BaseHTTPRequestHandler):
        def do_POST(self):
            kv[self.path.replace("/v1/secret/data/", "")] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["data"]
            self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
        def do_GET(self):
            d = kv.get(self.path.replace("/v1/secret/data/", ""))
            self.send_response(200 if d else 404); self.send_header("Content-Type", "application/json"); self.end_headers()
            if d:
                self.wfile.write(json.dumps({"data": {"data": d}}).encode())
        def do_DELETE(self):
            kv.pop(self.path.replace("/v1/secret/metadata/", ""), None); self.send_response(204); self.end_headers()
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), V)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{srv.server_port}"); monkeypatch.setenv("VAULT_TOKEN", "t")
    monkeypatch.setenv("MYELIN_ITSM_ALLOW_PRIVATE", "1")
    fake = Fake()
    monkeypatch.setattr(ent["main"], "ITSM_TRANSPORT", httpx.MockTransport(fake))
    sm.clear_cache()
    c, admin = ent["c"], H(ent, roles=["myelin-tenant-admin"])
    try:
        assert c.post("/api/v1/ticketing/integrations", headers=H(ent, roles=["myelin-security-lead"]), json={
            "kind": "jira", "token": "x", "config": {"base_url": "https://acme.atlassian.net", "email": "a@acme.com", "project_key": "SEC"}}).status_code == 403
        r = c.post("/api/v1/ticketing/integrations", headers=admin, json={
            "kind": "jira", "token": "atl-enterprise", "config": {"base_url": "https://acme.atlassian.net", "email": "bot@acme.com", "project_key": "SEC"}})
        assert r.status_code == 201, r.text
        iid = r.json()["id"]
        assert kv[f"myelin/tenants/{ent['acme']}/itsm/{iid}"] == {"token": "atl-enterprise"}
        assert c.post(f"/api/v1/ticketing/integrations/{iid}/test", headers=admin).json()["ok"] is True
        c.post("/api/scans", json=SCAN, headers=H(ent))
        fid = next(f["id"] for f in c.get("/api/findings", headers=H(ent)).json()["items"] if f["repo"] == "payments-api")
        t = c.post("/api/v1/ticketing/tickets", headers=H(ent), json={"finding_ids": [fid]}).json()
        assert t["results"][0]["ticket"]["key"].startswith("SEC-")
        assert c.get(f"/api/findings/{fid}", headers=H(ent)).json()["ticket"]["url"].startswith("https://acme.atlassian.net/browse/")
        g = H(ent, tenant="globex", roles=["myelin-tenant-admin"])
        assert c.get("/api/v1/ticketing/integrations", headers=g).json() == []
        assert c.post(f"/api/v1/ticketing/integrations/{iid}/test", headers=g).status_code == 404
        assert c.delete(f"/api/v1/ticketing/integrations/{iid}", headers=admin).status_code == 204
        assert f"myelin/tenants/{ent['acme']}/itsm/{iid}" not in kv
    finally:
        srv.shutdown()
        sm.clear_cache()


def test_risk_acceptance_expires_and_reopens(ent):
    c = ent["c"]
    c.post("/api/scans", json=SCAN, headers=H(ent))
    fid = c.get("/api/findings", headers=H(ent)).json()["items"][0]["id"]
    exp = (datetime.now(timezone.utc) + timedelta(days=10)).date().isoformat()
    assert c.post(f"/api/findings/{fid}/status", json={"status": "risk_accepted", "reason": "WAF rule in place", "expires": exp},
                  headers=H(ent)).status_code == 200
    # simulate the date passing
    from app.db.models import Finding
    from app.db.session import tenant_tx
    with tenant_tx(ent["urls"]["app"], ent["acme"]) as s:
        r = s.get(Finding, fid)
        r.data = {**r.data, "triage": {**r.data["triage"], "expires": "2020-01-01"}}
    items = c.get("/api/findings", headers=H(ent)).json()["items"]
    assert any(f["id"] == fid and f["status"] == "open" and "expired" in f.get("reopened_reason", "") for f in items)


def test_campaign_four_eyes_with_two_people(ent):
    c = ent["c"]
    c.post("/api/scans", json=SCAN, headers=H(ent))
    camp = c.get("/api/v1/remediation/campaigns", headers=H(ent)).json()["items"][0]
    cid = camp["id"]
    assert c.post(f"/api/v1/remediation/campaigns/{cid}", json={"action": "plan", "owner": "payments-devops", "due_date": "2026-12-31"},
                  headers=H(ent, sub="alice")).json()["state"] == "planned"
    assert c.post(f"/api/v1/remediation/campaigns/{cid}", json={"action": "approve"}, headers=H(ent, sub="alice")).status_code == 403
    r = c.post(f"/api/v1/remediation/campaigns/{cid}", json={"action": "approve"}, headers=H(ent, sub="bob"))
    assert r.status_code == 200 and r.json()["state"] == "approved" and r.json()["approved_by"] == "bob@acme.test"
    assert c.post(f"/api/v1/remediation/campaigns/{cid}", json={"action": "start"}, headers=H(ent, sub="bob")).json()["state"] == "in_progress"
    # state persists in PostgreSQL across requests and is isolated per tenant
    again = next(x for x in c.get("/api/v1/remediation/campaigns", headers=H(ent)).json()["items"] if x["id"] == cid)
    assert again["state"] == "in_progress"
    assert all(x["id"] != cid for x in c.get("/api/v1/remediation/campaigns", headers=H(ent, tenant="globex")).json()["items"])
    assert c.post(f"/api/v1/remediation/campaigns/{cid}", json={"action": "reopen"}, headers=H(ent, sub="bob")).status_code == 200


def test_ai_assistant_with_a_configured_model_redacts_and_falls_back(ent, monkeypatch):
    import httpx
    from app import ai
    c = ent["c"]
    c.post("/api/scans", json=SCAN, headers=H(ent))
    fid = c.get("/api/findings", headers=H(ent)).json()["items"][0]["id"]
    sent = []

    def handler(req: httpx.Request):
        sent.append(json.loads(req.content))
        assert req.headers["x-api-key"] == "anthropic-test-key"
        return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(
            {"what": "Model explanation", "impact": "Model impact", "steps": ["Rotate the key", "Move it to the vault"], "verify": "Re-scan"})}]})
    monkeypatch.setenv("MYELIN_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("MYELIN_AI_MODEL", "claude-test")
    monkeypatch.setenv("MYELIN_AI_KEY_REF", "env://TEST_AI_KEY")
    monkeypatch.setenv("TEST_AI_KEY", "anthropic-test-key")
    monkeypatch.setattr(ai, "TRANSPORT", httpx.MockTransport(handler))
    r = c.post(f"/api/findings/{fid}/explain", headers=H(ent)).json()
    assert r["source"] == "llm" and r["steps"] == ["Rotate the key", "Move it to the vault"] and "claude-test" in r["model"]
    body = json.dumps(sent[-1])
    assert "AKIA" not in body and "evidence" not in body            # secret values and code never leave by default
    assert c.get("/api/v1/ai/status", headers=H(ent)).json()["configured"] is True
    # provider failure: built-in answer, no error for the user
    monkeypatch.setattr(ai, "TRANSPORT", httpx.MockTransport(lambda req: httpx.Response(500)))
    assert c.post(f"/api/findings/{fid}/explain", headers=H(ent)).json()["source"] == "built-in"


def test_cloud_inventory_runtime_and_attack_paths_enterprise_isolation(ent):
    """Enterprise mode: cloud inventories, runtime events and attack paths live in PostgreSQL per tenant."""
    c, root = ent["c"], os.path.join(os.path.dirname(__file__), "..", "..", "demo", "cloud")
    with open(os.path.join(root, "aks-prod-cin.kubectl.json"), "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode()
    r = c.post("/api/v1/cloud/inventory", headers=H(ent), json={"content_base64": b64, "account": "acme-aks"})
    assert r.status_code == 200, r.text
    assert r.json()["key"] == "k8s:acme-aks" and r.json()["received"] >= 48
    with open(os.path.join(root, "runtime-events.json"), "rb") as fh:
        ev = c.post("/api/v1/runtime/events?cluster=acme-aks", headers=H(ent), content=fh.read())
    assert ev.status_code == 200 and ev.json()["received"] == 5
    ov = c.get("/api/v1/cnapp", headers=H(ent)).json()
    assert [i["key"] for i in ov["inventories"]] == ["k8s:acme-aks"] and ov["runtime"]["events_24h"] >= 0
    assert c.get("/api/findings?engine=kspm", headers=H(ent)).json()["total"] >= 48
    # the other tenant sees nothing; viewers cannot upload
    other = H(ent, tenant="globex", sub="gina")
    assert c.get("/api/v1/cloud/inventories", headers=other).json() == []
    assert c.get("/api/v1/runtime/events?hours=720", headers=other).json() == []
    assert c.get("/api/findings?engine=kspm", headers=other).json()["total"] == 0
    viewer = H(ent, roles=("myelin-viewer",), sub="victor")
    assert c.post("/api/v1/cloud/inventory", headers=viewer, json={"content_base64": b64}).status_code == 403
