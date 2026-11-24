# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Connector and evidence-integrity unit tests (no network: provider APIs are mocked)."""
import base64
import json
import os
import sys
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.connectors.aws import AWSConnector  # noqa: E402
from app.connectors.azure import AzureConnector  # noqa: E402
from app.connectors.base import ConnectorError, validate_credential_ref  # noqa: E402
from app.connectors.github import READ_PERMISSIONS, GitHubConnector  # noqa: E402

TENANT = uuid.uuid4()
WORKFLOW = """name: ci
on: [pull_request_target]
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""


def github_mock(seen):
    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path))
        p = req.url.path
        if p.endswith("/access_tokens"):
            body = json.loads(req.content)
            assert body["permissions"] == READ_PERMISSIONS                       # least privilege requested per token
            assert req.headers["authorization"].startswith("Bearer ey")
            return httpx.Response(201, json={"token": "ghs_x"})
        if p == "/installation/repositories":
            return httpx.Response(200, json={"total_count": 1, "repositories": [
                {"full_name": "acme/payments", "owner": {"login": "acme"}, "default_branch": "main", "private": True}]})
        if p == "/repos/acme/payments/contents/.github/workflows":
            return httpx.Response(200, json=[{"name": "ci.yml", "path": ".github/workflows/ci.yml"}])
        if p == "/repos/acme/payments/contents/.github/workflows/ci.yml":
            return httpx.Response(200, json={"content": base64.b64encode(WORKFLOW.encode()).decode()})
        if p.endswith("/protection"):
            return httpx.Response(404, json={"message": "Branch not protected"})
        return httpx.Response(404)
    return handler


def gh_secret():
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
    return json.dumps({"app_id": "123", "installation_id": "456", "private_key": pem})


def test_github_connector_reads_workflows_and_branch_protection():
    seen, secret = [], gh_secret()
    c = GitHubConnector({"organization": "acme"}, f"vault://secret/myelin/tenants/{TENANT}/github",
                        http=httpx.Client(transport=httpx.MockTransport(github_mock(seen))), resolve=lambda _: secret)
    res = c.sync()
    rules = {f["rule_id"] for f in res.findings}
    assert {"NM-CICD-002", "NM-CICD-001", "NM-CICD-012"} <= rules
    assert res.evidence and res.evidence[0][1] == "pipeline-definition"
    assert all(m == "GET" for m, p in seen if not p.endswith("/access_tokens"))      # read-only API usage


def test_github_rejects_plain_http_enterprise_url():
    c = GitHubConnector({"organization": "acme", "api_url": "http://ghes.internal/api/v3"}, "vault://x", resolve=lambda _: gh_secret())
    with pytest.raises(ConnectorError, match="HTTPS"):
        c.sync()


def test_azure_connector_findings():
    def handler(req: httpx.Request):
        p = req.url.path
        if "oauth2/v2.0/token" in p:
            assert b"client_secret=s3cr3t" in req.content and b"management.azure.com" in req.content
            return httpx.Response(200, json={"access_token": "az"})
        if p.endswith("/assessments"):
            return httpx.Response(200, json={"value": [
                {"name": "a1", "properties": {"status": {"code": "Unhealthy"}, "displayName": "Storage accounts should restrict network access",
                                              "metadata": {"severity": "High"}, "resourceDetails": {"Id": "/sub/x/sa"}}},
                {"name": "a2", "properties": {"status": {"code": "Healthy"}, "displayName": "ok"}}]})
        if p.endswith("/registries"):
            return httpx.Response(200, json={"value": [{"id": "/acr1", "name": "acr1", "properties": {"adminUserEnabled": True, "publicNetworkAccess": "Enabled"}}]})
        if p.endswith("/managedClusters"):
            return httpx.Response(200, json={"value": [{"id": "/aks1", "name": "aks1", "properties": {"disableLocalAccounts": False, "addonProfiles": {}}}]})
        return httpx.Response(404)
    c = AzureConnector({"subscription_ids": "sub-1"}, f"azkv://kv/myelin-{TENANT}-azure",
                       http=httpx.Client(transport=httpx.MockTransport(handler)),
                       resolve=lambda _: json.dumps({"tenant_id": "t", "client_id": "c", "client_secret": "s3cr3t"}))
    rules = {f["rule_id"] for f in c.sync().findings}
    assert {"AZ-a1", "NM-AZ-ACR-001", "NM-AZ-ACR-002", "NM-AZ-AKS-001", "NM-AZ-AKS-002"} == rules


def test_aws_connector_requires_external_id_and_reads_only():
    calls = []

    class Fake:
        def __init__(self, svc):
            self.svc = svc

        def describe_repositories(self, **kw):
            calls.append("ecr:DescribeRepositories")
            return {"repositories": [{"repositoryArn": "arn:ecr:r1", "repositoryName": "r1", "imageTagMutability": "MUTABLE",
                                      "imageScanningConfiguration": {"scanOnPush": False}}]}

        def get_findings(self, **kw):
            calls.append("securityhub:GetFindings")
            return {"Findings": [{"GeneratorId": "aws-foundational/EC2.19", "Title": "Security groups allow unrestricted access",
                                  "Severity": {"Label": "CRITICAL"}, "Resources": [{"Id": "sg-1"}]}]}

    c = AWSConnector({"regions": "ap-south-1"}, f"awssm://ap-south-1/myelin/{TENANT}/aws",
                     resolve=lambda _: json.dumps({"role_arn": "arn:aws:iam::1:role/NerveMyelinReadOnly", "external_id": "ext-1"}),
                     client_factory=lambda svc, region, cred: Fake(svc))
    res = c.sync()
    assert {f["rule_id"] for f in res.findings} == {"NM-AWS-ECR-001", "NM-AWS-ECR-002", "AWS-aws-foundational/EC2.19"}
    policy = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "config", "connectors", "aws-iam-policy.json")))
    allowed = {a for st in policy["Statement"] for a in st["Action"]}
    assert set(calls) <= {a.replace("ecr:", "ecr:").replace("securityhub:", "securityhub:") for a in allowed}   # policy covers every call
    bad = AWSConnector({"regions": "ap-south-1"}, "awssm://x", resolve=lambda _: json.dumps({"role_arn": "arn"}), client_factory=lambda *a: Fake("x"))
    with pytest.raises(ConnectorError, match="external_id"):
        bad.sync()


@pytest.mark.parametrize("ref", ["env://MYELIN_SESSION_SECRET", "file:///etc/passwd", "plain-secret", "vault://secret/other-tenant/github",
                                 "azkv://kv/shared-secret"])
def test_credential_refs_must_be_tenant_namespaced(ref):
    with pytest.raises(ConnectorError):
        validate_credential_ref(ref, TENANT)


def test_valid_credential_ref():
    validate_credential_ref(f"vault://secret/myelin/tenants/{TENANT}/github#app", TENANT)
