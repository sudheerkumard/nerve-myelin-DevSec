# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Built-in cloud IaC checks (Terraform, CloudFormation, ARM, Bicep, Kubernetes), configuration files, provider secret
formats, DAST exposure checks, container image configuration and security-domain tagging."""
import http.server
import io
import json
import tarfile
import threading

import pytest

from myelin_engine import config_checks, dast, domains, iac_cloud, iac_parse, image_tar, secrets


def _rules(fs):
    return {f["rule_id"] for f in fs}


# ------------------------------------------------------------------------------------------ parsing
def test_hcl_parser_values_blocks_and_expressions():
    doc = iac_parse.parse_hcl('''
resource "aws_iam_policy" "p" {
  name   = "x-${var.env}"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
  count  = var.enabled ? 1 : 0
  tags   = { team = "a" }
  inner { flag = true  # comment
          n = 3 }
}
''')
    r = doc["resource"][0]
    assert r["__labels__"] == ["aws_iam_policy", "p"]
    assert isinstance(r["name"], iac_parse.Expr) and isinstance(r["count"], iac_parse.Expr)
    assert r["policy"]["Statement"][0]["Action"] == "*"
    assert r["inner"][0]["flag"] is True and r["inner"][0]["n"] == 3 and r["tags"] == {"team": "a"}


# ------------------------------------------------------------------------------------------ Terraform
TF = '''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  engine              = "postgres"
  publicly_accessible = true
  password            = "Sup3rSecret!"
}
resource "aws_instance" "vm" {
  ami = "ami-1"
}
resource "aws_instance" "hardened" {
  metadata_options { http_tokens = "required" }
}
resource "aws_iam_role_policy" "admin" {
  policy = <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF
}
resource "aws_s3_bucket" "logs" { bucket = "x" }
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_db_instance" "computed" {
  publicly_accessible = var.public
  storage_encrypted   = var.encrypted
}
resource "azurerm_network_security_rule" "rdp" {
  direction = "Inbound"
  access = "Allow"
  source_address_prefix = "*"
  destination_port_range = "3389"
}
resource "google_storage_bucket_iam_member" "pub" {
  role = "roles/storage.objectViewer"
  member = "allUsers"
}
'''


def test_terraform_checks_by_domain(tmp_path):
    (tmp_path / "main.tf").write_text(TF)
    fs = iac_cloud.scan(str(tmp_path), "r")
    by = {(f["rule_id"], f["resource"]) for f in fs}
    assert ("NM-IAC-101", "aws_security_group.web") in by
    sg = [f for f in fs if f["rule_id"] == "NM-IAC-101"]
    assert len(sg) == 1 and "22 (SSH)" in sg[0]["evidence"]           # port 443 open to the internet is not a finding
    assert ("NM-IAC-116", "aws_db_instance.db") in by and ("NM-IAC-206", "aws_db_instance.db") in by
    assert ("NM-IAC-218", "aws_db_instance.db") in by
    assert ("NM-IAC-301", "aws_instance.vm") in by and ("NM-IAC-301", "aws_instance.hardened") not in by
    assert next(f for f in fs if f["rule_id"] == "NM-IAC-401")["severity"] == "critical"
    assert ("NM-IAC-202", "aws_s3_bucket.logs") not in by            # its public access block is defined
    assert ("NM-IAC-116", "aws_db_instance.computed") not in by      # computed values are not guessed
    assert ("NM-IAC-121", "azurerm_network_security_rule.rdp") in by
    assert ("NM-IAC-241", "google_storage_bucket_iam_member.pub") in by
    assert {f["domain"] for f in fs} >= {"network", "data", "compute", "identity"}


def test_cloudformation_arm_and_bicep(tmp_path):
    (tmp_path / "cfn.yaml").write_text('''AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 3389, ToPort: 3389, CidrIp: 0.0.0.0/0}
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
      BucketName: !Sub "${AWS::StackName}-data"
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      StorageEncrypted: !Ref Enc
''')
    (tmp_path / "arm.json").write_text(json.dumps({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "resources": [{"type": "Microsoft.Storage/storageAccounts", "name": "sa", "properties": {"allowBlobPublicAccess": True,
                                                                                                   "minimumTlsVersion": "TLS1_0"}}]}))
    (tmp_path / "main.bicep").write_text('''resource kv 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: 'kv1'
  properties: {
    enablePurgeProtection: false
  }
}
''')
    fs = iac_cloud.scan(str(tmp_path), "r")
    rules = {(f["rule_id"], f["file"]) for f in fs}
    assert ("NM-IAC-101", "cfn.yaml") in rules and ("NM-IAC-201", "cfn.yaml") in rules and ("NM-IAC-116", "cfn.yaml") in rules
    assert not any(f["rule_id"] == "NM-IAC-206" and f["file"] == "cfn.yaml" for f in fs)      # !Ref is not guessed
    assert ("NM-IAC-222", "arm.json") in rules and ("NM-IAC-127", "arm.json") in rules
    assert ("NM-IAC-224", "main.bicep") in rules


def test_kubernetes_network_rbac_and_secrets(tmp_path):
    (tmp_path / "k8s.yaml").write_text('''apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {type: LoadBalancer}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: shop}
spec: {rules: []}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: open}
roleRef: {kind: ClusterRole, name: view}
subjects: [{kind: Group, name: system:unauthenticated}]
---
apiVersion: v1
kind: Secret
metadata: {name: db}
stringData: {password: s3cr3t-value}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny, namespace: payments}
spec: {podSelector: {}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: shop}
spec: {template: {spec: {containers: [{name: a, image: x}]}}}
''')
    rules = _rules(iac_cloud.scan(str(tmp_path), "r"))
    assert {"NM-IAC-151", "NM-IAC-152", "NM-IAC-454", "NM-IAC-251", "NM-IAC-153"} <= rules


def test_external_iac_duplicates_dropped():
    built = [{"rule_id": "NM-IAC-206", "file": "main.tf", "resource": "aws_db_instance.db", "title": "Database storage is not encrypted",
              "evidence": ""}]
    ext = [{"file": "/main.tf", "resource": "aws_db_instance.db", "title": "Ensure RDS is encrypted at rest", "source_tool": "checkov"},
           {"file": "/main.tf", "resource": "aws_db_instance.db", "title": "Ensure RDS has a description", "source_tool": "checkov"}]
    kept = iac_cloud.drop_duplicates(built, ext)
    assert [k["title"] for k in kept] == ["Ensure RDS has a description"]


# ------------------------------------------------------------------------------------------ configuration files
def test_mobile_framework_and_server_config(tmp_path):
    (tmp_path / "app/src/main").mkdir(parents=True)
    (tmp_path / "app/src/main/AndroidManifest.xml").write_text(
        '<manifest><application android:debuggable="true" android:usesCleartextTraffic="true">'
        '<provider android:name=".Files" android:exported="true"/></application></manifest>')
    (tmp_path / "Info.plist").write_text("<dict><key>NSAllowsArbitraryLoads</key><true/></dict>")
    (tmp_path / "application.yml").write_text("management:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\n")
    (tmp_path / "sshd_config").write_text("PermitRootLogin yes\nPasswordAuthentication no\n")
    (tmp_path / "nginx.conf").write_text("server {\n  autoindex on;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n")
    rules = _rules(config_checks.scan_path(str(tmp_path), "r"))
    assert {"NM-CFG-001", "NM-CFG-002", "NM-CFG-004", "NM-CFG-007", "NM-CFG-010", "NM-CFG-060", "NM-CFG-050", "NM-CFG-051"} <= rules
    assert "NM-CFG-061" not in rules


# ------------------------------------------------------------------------------------------ secrets
@pytest.mark.parametrize("rid,text", [
    ("NM-SEC-016", "token = glpat-" + "Ab1x" * 6), ("NM-SEC-019", "npm_" + "a1B2" * 9), ("NM-SEC-033", "dop_v1_" + "a" * 64),
    ("NM-SEC-034", "hvs.CAESIJq8v2Lk9TzR4wYp0mXnB7aHdF3uQ"), ("NM-SEC-040", "DATABASE_URL=postgres://app:S3cretPass@db.internal:5432/x"),
    ("NM-SEC-046", "SG." + "a" * 22 + "." + "b" * 43), ("NM-SEC-048", "https://hooks.slack." + "com/services/T04ABCD12/B05EFGH34/q8Wz3Lm9Rt2Yp6Kd1Xv7Nb4H"),
    ("NM-SEC-044", "shpat_" + "a1" * 16)])
def test_provider_secret_formats(tmp_path, rid, text):
    (tmp_path / "config.txt").write_text(text + "\n")
    assert rid in _rules(secrets.scan_path(str(tmp_path), "r"))


# ------------------------------------------------------------------------------------------ DAST
def test_dast_exposed_files_and_listing(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git/HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / ".env").write_text("DB_PASSWORD=hunter2\n")
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(tmp_path), **k)  # noqa: E731
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = dast.safe_scan(f"http://127.0.0.1:{srv.server_address[1]}/", max_requests=200, delay=0)
    finally:
        srv.shutdown()
    titles = {f["title"] for f in r["findings"] if f["rule_id"] == "NM-DAST-040"}
    assert "Git repository exposed (source code and history)" in titles and "Environment file with secrets exposed" in titles
    assert "NM-DAST-041" in _rules(r["findings"])


# ------------------------------------------------------------------------------------------ container image config
def test_image_configuration_checks(tmp_path):
    def layer(files):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w") as t:
            for name, data, mode in files:
                ti = tarfile.TarInfo(name)
                ti.size, ti.mode = len(data), mode
                t.addfile(ti, io.BytesIO(data))
        return b.getvalue()
    cfg = {"created": "2020-01-01T00:00:00Z", "config": {"Env": ["DB_PASSWORD=supersecret1"], "ExposedPorts": {"22/tcp": {}}}}
    arc = tmp_path / "i.tar"
    with tarfile.open(arc, "w") as t:
        for name, data in [("l/layer.tar", layer([("usr/sbin/sshd", b"x", 0o755), ("opt/tool", b"y", 0o4755)])),
                           ("c.json", json.dumps(cfg).encode()),
                           ("manifest.json", json.dumps([{"Config": "c.json", "RepoTags": ["x:1"], "Layers": ["l/layer.tar"]}]).encode())]:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    root = tmp_path / "root"
    root.mkdir()
    meta = image_tar.unpack(str(arc), str(root))
    rules = _rules(image_tar.config_findings(meta, str(root), "x:1"))
    assert {"NM-CTR-001", "NM-CTR-002", "NM-CTR-003", "NM-CTR-004", "NM-CTR-005", "NM-CTR-006", "NM-CTR-007"} <= rules


# ------------------------------------------------------------------------------------------ domains
def test_domain_assignment_and_matrix():
    fs = [{"engine": "sast", "cwe": "CWE-89", "rule_id": "x"}, {"engine": "sast", "cwe": "CWE-327", "rule_id": "y"},
          {"engine": "secrets", "rule_id": "NM-SEC-001"}, {"engine": "iac", "rule_id": "NM-IAC-101", "domain": "network"},
          {"engine": "sca", "rule_id": "NM-OS-001", "category": "os-package"}, {"engine": "dast", "rule_id": "NM-DAST-003"},
          {"engine": "cicd", "rule_id": "NM-CICD-001"}, {"engine": "iac", "rule_id": "CKV_AWS_67", "title": "Ensure CloudTrail logging is enabled"}]
    domains.assign(fs)
    assert [f["domain"] for f in fs] == ["application", "data", "identity", "network", "compute", "network", "supply_chain", "logging"]
    m = domains.matrix(fs, ["sast", "secrets", "iac", "sca", "dast", "cicd"])
    rows = {d: r for d, _, r in m["rows"]}
    assert rows["network"]["iac"] == 1 and rows["network"]["dast"] == 1 and rows["application"]["sast"] == 1
