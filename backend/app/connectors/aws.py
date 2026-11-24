# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Amazon Web Services connector (read-only, cross-account role).

Least privilege: the customer creates role `NerveMyelinReadOnly` with the policy in
config/connectors/aws-iam-policy.json and a trust policy that only allows the NERvvE DevSecOps platform
principal *with the tenant's ExternalId* (confused-deputy protection). The platform assumes the role for
15 minutes per sync. No long-lived AWS keys are stored.
Secret (JSON): {"role_arn": "arn:aws:iam::<acct>:role/NerveMyelinReadOnly", "external_id": "<per-tenant id>"}
Requires boto3 (bundled in the platform image).
"""
from .base import Connector, ConnectorError, SyncResult, register


@register
class AWSConnector(Connector):
    kind = "aws"
    title = "Amazon Web Services (assume-role, read-only)"
    config_fields = {"regions": "Comma-separated regions, e.g. ap-south-1,us-east-1"}
    least_privilege = {"summary": "Cross-account role with ExternalId; read-only ECR and Security Hub actions; 15-minute sessions",
                       "policy_file": "config/connectors/aws-iam-policy.json"}

    def __init__(self, *a, client_factory=None, **kw):
        super().__init__(*a, **kw)
        self._factory = client_factory

    def _session_clients(self):
        cred = self.secret_json()
        if not cred.get("external_id"):
            raise ConnectorError("external_id is required (confused-deputy protection)")
        if self._factory:
            return lambda svc, region: self._factory(svc, region, cred)
        import boto3
        sts = boto3.client("sts")
        c = sts.assume_role(RoleArn=cred["role_arn"], RoleSessionName="nerve-myelin", ExternalId=cred["external_id"],
                            DurationSeconds=900)["Credentials"]
        sess = boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])
        return lambda svc, region: sess.client(svc, region_name=region)

    def _regions(self):
        return [r.strip() for r in self.config["regions"].split(",") if r.strip()]

    def test(self) -> dict:
        client = self._session_clients()
        client("ecr", self._regions()[0]).describe_repositories(maxResults=1)
        return {"ok": True, "regions": self._regions()}

    def sync(self) -> SyncResult:
        client, out = self._session_clients(), SyncResult()
        for region in self._regions():
            ecr = client("ecr", region)
            for repo in ecr.describe_repositories(maxResults=1000).get("repositories", []):
                arn, name = repo["repositoryArn"], repo["repositoryName"]
                out.assets.append({"type": "container-registry-repo", "id": arn})
                if not repo.get("imageScanningConfiguration", {}).get("scanOnPush"):
                    out.findings.append({"engine": "cloud", "rule_id": "NM-AWS-ECR-001", "title": f"ECR {name}: scan on push disabled",
                                         "severity": "medium", "repo": f"aws:{region}", "file": arn, "exposure": "internal",
                                         "remediation": "Enable scan on push or enhanced scanning (Amazon Inspector)."})
                if repo.get("imageTagMutability") == "MUTABLE":
                    out.findings.append({"engine": "cloud", "rule_id": "NM-AWS-ECR-002", "title": f"ECR {name}: mutable image tags",
                                         "severity": "medium", "repo": f"aws:{region}", "file": arn, "exposure": "internal",
                                         "remediation": "Set imageTagMutability=IMMUTABLE and deploy by digest."})
            try:
                sh = client("securityhub", region).get_findings(
                    Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                             "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}, {"Value": "HIGH", "Comparison": "EQUALS"}]},
                    MaxResults=100)
            except Exception as e:  # noqa: BLE001 — Security Hub may be disabled in a region
                out.assets.append({"type": "note", "id": f"securityhub:{region}", "detail": type(e).__name__})
                continue
            for f in sh.get("Findings", []):
                out.findings.append({"engine": "cloud", "rule_id": "AWS-" + f.get("GeneratorId", "")[-40:], "title": f.get("Title", "Security Hub finding"),
                                     "severity": f.get("Severity", {}).get("Label", "MEDIUM").lower(), "repo": f"aws:{region}",
                                     "file": (f.get("Resources") or [{}])[0].get("Id", ""), "exposure": "internal", "source": "aws-securityhub"})
        return out
