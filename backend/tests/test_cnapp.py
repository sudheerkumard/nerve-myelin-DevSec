# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Cloud-native application protection: inventory import, live collectors (with recorded provider responses), CSPM /
KSPM / CIEM accuracy against a labelled set, runtime ingestion, attack paths, API and CLI."""
import base64
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
sys.path.insert(0, os.path.join(ROOT, "demo", "cloud"))
import aws_demo  # noqa: E402
from myelin_engine.cloud import ciem, collect_aws, collect_azure, collect_gcp, collect_k8s, evaluate, graph, http, inventory, runtime  # noqa: E402

from app import cnapp, main  # noqa: E402

H = {"X-API-Key": "nm_demo_9f2c41e7b8"}
CLOUD = os.path.join(ROOT, "demo", "cloud")
EXPECTED = json.load(open(os.path.join(ROOT, "engine", "tests", "benchmark", "cloud_expected.json")))


def _read(name):
    with open(os.path.join(CLOUD, name), "rb") as fh:
        return fh.read()


def _inventories():
    return {"aws": collect_aws.collect(["ap-south-1"], client=aws_demo.client),
            "azure": inventory.load(_read("azure-resource-graph.json")),
            "gcp": inventory.load(_read("gcp-cloud-asset-export.jsonl"), account="acme-risk-analytics"),
            "kubernetes": inventory.load(_read("aks-prod-cin.kubectl.json"), account="aks-prod-cin")}


# ------------------------------------------------------------------ accuracy (labelled set: every expected finding, nothing else)
@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "kubernetes"])
def test_posture_and_identity_rules_match_the_labelled_set(provider):
    got = sorted(f"{f['rule_id']}|{f['resource']['name']}" for f in evaluate(_inventories()[provider]))
    assert got == EXPECTED[provider]


def test_compliant_resources_stay_silent():
    inv = _inventories()
    names = lambda p: {f["resource"]["name"] for f in evaluate(inv[p])}  # noqa: E731
    assert "stauditlogsprod" not in names("azure")              # private, TLS 1.2, no shared key
    assert "nsg-aks-nodes" not in names("azure")                # only the Azure load balancer allowed in
    assert "acme-risk-models" not in names("gcp")                # uniform access, public access prevention, versioning
    assert "internal-only" not in names("aws")                   # 10.0.0.0/8 only
    assert "batch-runner" not in names("aws")                    # IMDSv2, private
    k8s = evaluate(inv["kubernetes"])
    assert not [f for f in k8s if f["resource"]["name"] == "payments-api"]   # hardened workload, internal load balancer
    assert not [f for f in k8s if f.get("namespace") == "kube-system"]        # system namespaces excluded by default
    assert not [f for f in k8s if f["rule_id"] == "NM-K8S-020" and "system:masters" in f["evidence"]]


def test_kubernetes_secrets_are_never_kept_and_literal_env_values_are_not_stored():
    inv = _inventories()["kubernetes"]
    blob = json.dumps(inv)
    assert "never-collected" not in blob and "c2VjcmV0" not in blob
    assert "tok_live_3f9a8c7b6d5e4f3a" not in blob and "Backup#2026!prod" not in blob   # only names + a literal flag
    wl = next(r for r in inv["resources"] if r["name"] == "payments-web" and r["type"] == "k8s.workload")
    assert {"container": "web", "name": "PAYMENT_API_TOKEN", "literal_secret": True} in wl["props"]["env"]


def test_code_to_cloud_links_come_from_iac_tags_annotations_and_images():
    inv = _inventories()
    f = next(f for f in evaluate(inv["azure"]) if f["rule_id"] == "NM-AZ-001")
    assert f["source"] == {"repo": "platform-terraform", "file": "modules/storage/main.tf", "commit": "4e1b9c7"}
    links = graph.code_to_cloud(list(inv.values()), ["payments-web", "payments-gateway", "kyc-onboarding", "platform-terraform"])
    via = {(x["repo"], x["via"].split(" ")[0]) for x in links}
    assert ("payments-gateway", "annotation") in via and ("payments-web", "image") in via and ("kyc-onboarding", "IaC") in via


def test_framework_references_for_cloud_findings():
    from myelin_engine import frameworks
    f = next(f for f in evaluate(_inventories()["aws"]) if f["rule_id"] == "NM-AWS-005")
    t = frameworks.tags(f)
    assert t["cis"] == ["AWS Foundations §Networking"] and "1.3.1" in t["pci"] and "SC-7" in t["nist"]
    assert "CIS AWS Foundations §Networking" in frameworks.short(f)


# ------------------------------------------------------------------ identities (CIEM)
def test_identity_privilege_and_flags():
    inv = _inventories()
    az = {i["name"]: i for i in ciem.identities(inv["azure"])}
    assert az["sp-legacy-deploy"]["privilege"] == "admin"
    assert az["vm-jumpbox-01 (managed identity)"]["privilege"] == "write"           # Contributor cannot change role assignments
    assert "external" in az["it-vendor_partner.example#EXT#@acmebank.onmicrosoft.com"]["flags"]
    aws = {i["name"]: i for i in ciem.identities(inv["aws"])}
    assert aws["rahul.admin"]["privilege"] == "admin" and "no MFA" in aws["rahul.admin"]["flags"]   # via group platform-admins
    assert aws["auditor"]["privilege"] == "read" and not aws["auditor"]["flags"]
    assert aws["kyc-ocr-role"]["privilege"] == "admin"                                  # iam:PassRole + lambda:CreateFunction
    assert "dormant" in aws["break-glass-admin"]["flags"]
    k8s = {i["id"]: i for i in ciem.identities(inv["kubernetes"])}
    assert k8s["system:serviceaccount:ci:deployer"]["privilege"] == "admin"


def test_aws_policy_privilege_classification():
    P = collect_aws.privilege
    assert P(["*@*"]) == "admin" and P(["iam:*@*"]) == "admin" and P(["iam:AttachRolePolicy@*"]) == "admin"
    assert P(["iam:PassRole@*", "ec2:RunInstances@*"]) == "admin"
    assert P(["s3:PutObject@scoped"]) == "write" and P(["s3:GetObject@*", "ec2:DescribeInstances@*"]) == "read"


# ------------------------------------------------------------------ live collectors (recorded provider responses)
def test_azure_collector_queries_resource_graph_and_firewall_rules(monkeypatch):
    rows = json.loads(_read("azure-resource-graph.json"))["data"]
    for r in rows:
        r.pop("firewallRules", None)
    calls = []

    def transport(method, url, headers, body):
        calls.append((method, url))
        if "login.microsoftonline.com" in url:
            scope = "graph" if b"graph.microsoft.com" in body else "arm"
            return 200, json.dumps({"access_token": f"tok-{scope}"}).encode()
        if "Microsoft.ResourceGraph" in url:
            assert headers["Authorization"] == "Bearer tok-arm"
            q = json.loads(body)["query"]
            table = q.split(" ")[0]
            pick = [r for r in rows if (table == "authorizationresources") == r["type"].startswith("microsoft.authorization") and
                    (table == "securityresources") == (r["type"] == "microsoft.security/pricings")]
            return 200, json.dumps({"data": pick}).encode()
        if url.endswith("firewallRules?api-version=2021-11-01"):
            return 200, json.dumps({"value": [{"name": "AllowAll", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}]}).encode()
        if "graph.microsoft.com/v1.0/directoryObjects/getByIds" in url:
            ids = json.loads(body)["ids"]
            return 200, json.dumps({"value": [{"id": i, "displayName": f"name-{i[:4]}"} for i in ids]}).encode()
        return 404, b"{}"

    monkeypatch.setattr(http, "TRANSPORT", transport)
    inv = collect_azure.collect({"tenant_id": "t", "client_id": "c", "client_secret": "s"}, ["8c1f4e2a-55d0-4b7e-9a31-6f20c7d1b9e4"])
    assert inv["collector"]["rows"] == len(rows)
    assert any(f["rule_id"] == "NM-AZ-009" for f in evaluate(inv))          # firewall rules fetched from ARM
    assert all(m in ("GET", "POST") for m, _ in calls)                       # read-only: Resource Graph queries are POST reads
    assert {i["name"][:5] for i in inv["identities"]} == {"name-"}           # names resolved through Microsoft Graph


def test_gcp_collector_pages_through_cloud_asset_api(monkeypatch):
    items = [json.loads(x) for x in _read("gcp-cloud-asset-export.jsonl").decode().splitlines()]
    res = [{k: v for k, v in i.items() if k != "iamPolicy"} for i in items]
    pol = [{"name": i["name"], "assetType": i["assetType"], "iamPolicy": i["iamPolicy"]} for i in items if i.get("iamPolicy")]
    pages = {"RESOURCE": [res[:5], res[5:]], "IAM_POLICY": [pol]}

    def transport(method, url, headers, body):
        assert method == "GET" and headers["Authorization"] == "Bearer at"
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(url).query)
        ct, page = q["contentType"][0], int(q.get("pageToken", ["0"])[0])
        nxt = page + 1 if page + 1 < len(pages[ct]) else None
        return 200, json.dumps({"assets": pages[ct][page], **({"nextPageToken": str(nxt)} if nxt else {})}).encode()

    monkeypatch.setattr(http, "TRANSPORT", transport)
    inv = collect_gcp.collect({"access_token": "at"}, "projects/acme-risk-analytics")
    assert sorted(f"{f['rule_id']}|{f['resource']['name']}" for f in evaluate(inv)) == EXPECTED["gcp"]


def test_gcp_service_account_key_signs_a_jwt(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    seen = {}

    def transport(method, url, headers, body):
        seen["assertion"] = body.decode()
        return 200, b'{"access_token": "ya29.test"}'

    monkeypatch.setattr(http, "TRANSPORT", transport)
    assert collect_gcp.token({"type": "service_account", "client_email": "x@p.iam.gserviceaccount.com", "private_key": pem}) == "ya29.test"
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer" in seen["assertion"]


def test_kubernetes_collector_never_requests_secrets(monkeypatch):
    doc = json.loads(_read("aks-prod-cin.kubectl.json"))
    by_kind = {}
    for it in doc["items"]:
        by_kind.setdefault(it["kind"], []).append(it)
    urls = []

    def transport(method, url, headers, body):
        urls.append(url)
        assert method == "GET" and headers["Authorization"] == "Bearer sa-token"
        plural = url.split("?")[0].rsplit("/", 1)[-1]
        kind = collect_k8s.KIND[plural]
        return 200, json.dumps({"items": [{k: v for k, v in i.items() if k != "kind"} for i in by_kind.get(kind, [])]}).encode()

    monkeypatch.setattr(http, "TRANSPORT", transport)
    inv = collect_k8s.collect({"server": "https://aks.example:443", "token": "sa-token", "ca_data": base64.b64encode(b"-----CA-----").decode()}, "aks-prod-cin")
    assert not [u for u in urls if "secret" in u.lower()]
    assert sorted(f"{f['rule_id']}|{f['resource']['name']}" for f in evaluate(inv)) == EXPECTED["kubernetes"]


def test_collectors_refuse_plain_http_and_missing_scope():
    with pytest.raises(http.CollectorError):
        http.request("GET", "http://management.azure.com/")
    with pytest.raises(http.CollectorError):
        collect_k8s.collect({"server": "http://cluster", "token": "x"})
    with pytest.raises(http.CollectorError):
        collect_gcp.collect({"access_token": "x"}, "acme")
    with pytest.raises(http.CollectorError):
        collect_aws.clients({"role_arn": "arn:aws:iam::1:role/r"})          # ExternalId is mandatory


# ------------------------------------------------------------------ runtime (CWPP)
def test_runtime_normalises_falco_and_tetragon_and_redacts_secrets():
    events = runtime.normalise(json.loads(_read("runtime-events.json")), "aks-prod-cin")
    assert [e["sensor"] for e in events] == ["falco", "falco", "falco", "tetragon", "tetragon"]
    api_call = events[2]
    assert "eyJ" not in api_call["command"] and "****" in api_call["command"]
    assert events[0]["workload"] == "payments-web" and events[0]["tactics"] == ["Execution"] and events[0]["techniques"] == ["T1059"]
    assert events[3]["tactics"] == ["Credential Access"] and events[4]["severity"] == "critical"
    assert runtime.redact("export AWS=AKIAABCDEFGHIJKLMNOP token=abc123") == "export AWS=**** token=****"
    # benign Tetragon exec events are not detections
    assert runtime.normalise([{"process_exec": {"process": {"binary": "/usr/bin/python3"}}}]) == []


def test_runtime_events_group_into_findings_with_counts():
    ev = runtime.normalise(json.loads(_read("runtime-events.json")) * 3, "aks-prod-cin")
    fs = runtime.findings(ev)
    assert len(fs) == 5 and {f["event_count"] for f in fs} == {3}
    assert runtime.workload_of("payments-web-7d9c6b5f8d-x2k4q") == "payments-web" and runtime.workload_of("db-0") == "db"


# ------------------------------------------------------------------ attack paths
REPOS = [r["name"] for r in main.DEMO.repos()]


def test_attack_paths_need_exposure_weakness_and_impact():
    inv = list(_inventories().values())
    fs = main.DEMO.findings()
    paths = graph.attack_paths(inv, fs, REPOS)
    names = {p["resource"]["name"] for p in paths}
    assert {"kyc-ocr-worker", "vm-jumpbox-01", "app-advisor-portal", "fraud-ml-trainer", "payments-web"} <= names
    assert "payments-api" not in names and "batch-runner" not in names        # internal load balancer / no public IP
    kyc = next(p for p in paths if p["resource"]["name"] == "kyc-ocr-worker")
    assert [s["kind"] for s in kyc["steps"]] == ["internet", "exposure", "workload", "weakness", "identity", "data"]
    assert kyc["severity"] == "critical" and "acme-kyc-documents" in kyc["steps"][-1]["items"]
    assert any(s["kind"] == "weakness" for s in kyc["steps"])
    # remove both weaknesses (vulnerable code in kyc-onboarding and IMDSv1 on the instance): the path disappears
    no_weak = [f for f in fs if f.get("repo") != "kyc-onboarding" and f.get("file") != kyc["resource"]["id"]]
    assert "kyc-ocr-worker" not in {p["resource"]["name"] for p in graph.attack_paths(inv, no_weak, REPOS)}


# ------------------------------------------------------------------ API (demo mode)
def test_cnapp_overview_and_views_from_the_seeded_demo():
    c = TestClient(main.app)
    d = c.get("/api/v1/cnapp", headers=H).json()
    assert d["attack_path_count"] >= 6 and len(d["inventories"]) == 4 and d["runtime"]["events_24h"] == 5
    assert {i["provider"] for i in d["inventories"]} == {"azure", "aws", "gcp", "kubernetes"}
    assert d["engines"]["paths"]["critical"] >= 5
    ids = c.get("/api/v1/cloud/identities?provider=aws", headers=H).json()
    assert {i["provider"] for i in ids} == {"aws"}
    ev = c.get("/api/v1/runtime/events?hours=24", headers=H).json()
    assert len(ev) == 5 and ev[0]["ts"] >= ev[-1]["ts"]
    assert len(c.get("/api/v1/cloud/rules", headers=H).json()) > 90
    paths = c.get("/api/findings?engine=paths", headers=H).json()["items"]
    assert all(p["priority"] == "P0" for p in paths if p["severity"] == "critical")
    assert any(p["ssvc"]["decision"] == "Act" for p in paths)


def test_inventory_upload_then_fix_closes_the_finding():
    c = TestClient(main.app)
    doc = json.loads(_read("aks-prod-cin.kubectl.json"))
    up = lambda d: c.post("/api/v1/cloud/inventory", headers=H, json={"content_base64": base64.b64encode(json.dumps(d).encode()).decode(),  # noqa: E731
                                                                     "account": "aks-test"}).json()
    r = up(doc)
    assert r["key"] == "k8s:aks-test" and r["received"] >= 48 and r["new"] >= 48
    open_ = {f["rule_id"] for f in c.get("/api/findings?repo=k8s:aks-test&limit=1000", headers=H).json()["items"]}
    assert "NM-K8S-021" in open_
    doc["items"] = [i for i in doc["items"] if i["metadata"]["name"] != "all-can-read-secrets"]   # the binding is removed
    up(doc)
    fixed = c.get("/api/findings?repo=k8s:aks-test&status=fixed&limit=1000", headers=H).json()["items"]
    assert any(f["rule_id"] == "NM-K8S-021" for f in fixed)
    assert c.delete("/api/v1/cloud/inventories?key=k8s:aks-test", headers=H).status_code == 204
    bad = c.post("/api/v1/cloud/inventory", headers=H, json={"content_base64": base64.b64encode(b'{"hello": 1}').decode()})
    assert bad.status_code == 400


def test_runtime_endpoint_accepts_a_falcosidekick_event_and_json_lines():
    c = TestClient(main.app)
    falco = json.loads(_read("runtime-events.json"))[1]
    r = c.post("/api/v1/runtime/events?cluster=test-cluster", headers=H, content=json.dumps(falco))
    assert r.status_code == 200 and r.json()["received"] == 1
    lines = "\n".join(json.dumps(e) for e in json.loads(_read("runtime-events.json"))[3:])
    r2 = c.post("/api/v1/runtime/events?cluster=test-cluster", headers=H, content=lines).json()
    assert r2["received"] == 2
    again = c.post("/api/v1/runtime/events?cluster=test-cluster", headers=H, content=json.dumps(falco)).json()
    assert again["new"] == 0                                     # same rule + workload + image: count updated, not duplicated
    f = next(x for x in c.get("/api/findings?engine=runtime&repo=k8s:test-cluster", headers=H).json()["items"] if "sensitive file" in x["title"])
    assert f["event_count"] == 2
    assert c.post("/api/v1/runtime/events", headers=H, content=b"not json at all {").status_code == 400


def test_cloud_account_live_collection_through_the_api(monkeypatch):
    monkeypatch.setattr(cnapp, "COLLECT_TRANSPORT", aws_demo.client)
    c = TestClient(main.app)
    a = c.post("/api/v1/cloud/accounts", headers=H, json={"provider": "aws", "name": "test", "config": {"regions": "ap-south-1", "account": "aws-api-test"}})
    assert a.status_code == 201 and a.json()["has_credential"] is False
    r = c.post(f"/api/v1/cloud/accounts/{a.json()['id']}/collect", headers=H).json()
    assert r["key"] == "cloud:aws:aws-api-test" and r["received"] >= 32
    assert c.post("/api/v1/cloud/accounts", headers=H, json={"provider": "azure", "config": {"subscriptions": "x"}}).status_code == 400   # needs a credential
    assert c.post("/api/v1/cloud/accounts", headers=H, json={"provider": "kubernetes", "config": {"server": "http://x"}, "credential": "{}"}).status_code == 400
    assert c.delete(f"/api/v1/cloud/accounts/{a.json()['id']}", headers=H).status_code == 204


def test_cloud_plan_entitlements():
    from app import plans
    for f in ("cspm", "kspm", "ciem", "cwpp", "attack_paths"):
        assert plans.entitled("business", f) and plans.entitled("enterprise", f) and not plans.entitled("team", f)


# ------------------------------------------------------------------ CLI
def test_cli_cloud_scan_and_runtime_forward():
    env = {**os.environ, "PYTHONPATH": os.path.join(ROOT, "engine"), "MYELIN_OFFLINE": "1"}
    env.pop("MYELIN_SERVER", None)
    r = subprocess.run([sys.executable, "-m", "myelin_engine.cli", "cloud", "scan", "--inventory", os.path.join(CLOUD, "gcp-cloud-asset-export.jsonl"),
                        "--account", "acme-risk-analytics", "--fail-on", "critical"], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 1 and "NM-GCP-001" in r.stdout and "total 22" in r.stdout
    r = subprocess.run([sys.executable, "-m", "myelin_engine.cli", "runtime", "forward", os.path.join(CLOUD, "runtime-events.json"), "--cluster", "c1"],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0 and "5 runtime detections" in r.stdout
