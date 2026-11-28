# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Built-in cloud infrastructure checks for Terraform, CloudFormation, ARM and Bicep (AWS, Azure, Google Cloud),
plus Kubernetes network, RBAC and secret objects. Runs offline with no external tool.

Rules are grouped by security domain:

  NM-IAC-1xx  network     exposure to the internet, segmentation, TLS at the edge
  NM-IAC-2xx  data        public storage, encryption at rest and in transit, backups, deletion protection
  NM-IAC-3xx  compute     instance metadata, public IPs, privileged containers, platform hardening
  NM-IAC-4xx  identity    wildcard permissions, public principals, long-lived keys, password policy
  NM-IAC-5xx  logging     audit trails, flow logs, threat detection, access logs

A check flags only what the template states (a literal value) or what the provider does by default when the setting
is left out; values computed at plan time (variables, references) are never guessed.
"""
from __future__ import annotations

import json
import re

from .iac_parse import Expr, is_lit, resources as parse_resources

ADMIN = {22: "SSH", 3389: "RDP", 23: "Telnet", 5985: "WinRM", 5986: "WinRM", 2375: "Docker API", 2376: "Docker API",
         6443: "Kubernetes API", 10250: "kubelet"}
DATA = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB", 6379: "Redis",
        9200: "Elasticsearch", 5601: "Kibana", 11211: "Memcached", 9042: "Cassandra", 5984: "CouchDB", 8086: "InfluxDB",
        9092: "Kafka", 2181: "ZooKeeper", 5672: "RabbitMQ", 15672: "RabbitMQ admin", 8020: "HDFS", 50070: "HDFS"}
OPEN = {"0.0.0.0/0", "::/0", "*", "internet", "any", "0.0.0.0", "<nw>/0", "/0"}

RULES: list[dict] = []
DOMAINS = {"network": "Network security", "data": "Data security", "compute": "Compute and workload security",
           "identity": "Identity and access", "logging": "Logging and monitoring"}


def rule(rid, domain, sev, title, types, fix, ref="", cwe=None):
    def deco(fn):
        RULES.append({"id": rid, "domain": domain, "severity": sev, "title": title, "types": set(types), "check": fn,
                      "fix": fix, "ref": ref, "cwe": cwe or CWE[domain]})
        return fn
    return deco


CWE = {"network": "CWE-284", "data": "CWE-311", "compute": "CWE-1188", "identity": "CWE-269", "logging": "CWE-778"}


# ------------------------------------------------------------------------------------------ helpers
def get(d, path, default=None):
    """Nested lookup: 'a.b.c' through dicts and the first element of nested block lists."""
    cur = d
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[0] if cur else None
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    if isinstance(cur, list) and cur and isinstance(cur[0], dict) and "__line__" in cur[0]:
        return cur[0]
    return cur


def blocks(d, key):
    v = (d or {}).get(key)
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    if isinstance(v, dict):
        return [v]
    return []


def true(v):
    return v is True or (is_lit(v) and str(v).lower() == "true")


def false(v):
    return v is False or (is_lit(v) and str(v).lower() == "false")


def absent(v):
    return v is None


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def open_cidr(v):
    return any(is_lit(x) and str(x).strip().lower() in OPEN for x in as_list(v))


def ports(frm, to=None, proto=None):
    """Set of interesting ports in a range, or 'all'."""
    if is_lit(proto) and str(proto) in ("-1", "all", "*", "ALL"):
        return "all"
    try:
        lo = int(frm) if frm not in (None, "*") else 0
        hi = int(to) if to not in (None, "*", "") else lo
    except (TypeError, ValueError):
        if is_lit(frm) and str(frm).strip() == "*":
            return "all"
        return set()
    if lo <= 0 and hi >= 65535 or (lo == 0 and hi == 0 and is_lit(proto) and str(proto) == "-1"):
        return "all"
    return {p for p in list(ADMIN) + list(DATA) if lo <= p <= hi}


def range_ports(spec):
    """Azure '22', '3389-3390', '*' (or a list of them)."""
    out = set()
    for s in as_list(spec):
        if not is_lit(s):
            continue
        s = str(s).strip()
        if s == "*":
            return "all"
        a, _, b = s.partition("-")
        r = ports(a, b or a, "tcp")
        if r == "all":
            return "all"
        out |= r
    return out


def describe(ps):
    if ps == "all":
        return "all ports"
    return ", ".join(f"{p} ({ADMIN.get(p) or DATA.get(p)})" for p in sorted(ps))


def exposure_sev(ps):
    if ps == "all":
        return "critical"
    if ps & set(ADMIN):
        return "high"
    return "high" if ps else None


def policy_doc(v):
    """An IAM policy as a dict, from a jsonencode object, a JSON string or a heredoc."""
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and not isinstance(v, Expr) or (isinstance(v, Expr) and v.strip().startswith("{") and "${" not in v):
        try:
            return json.loads(str(v))
        except ValueError:
            return None
    return None


def statements(doc):
    if not isinstance(doc, dict):
        return []
    st = doc.get("Statement") or doc.get("statement") or []
    return [s for s in as_list(st) if isinstance(s, dict)]


def _star(v):
    return any(is_lit(x) and str(x) in ("*", "*:*") for x in as_list(v))


def wildcard_findings(doc):
    out = []
    for s in statements(doc):
        if str(s.get("Effect", s.get("effect", "Allow"))) != "Allow":
            continue
        act = s.get("Action", s.get("actions"))
        res = s.get("Resource", s.get("resources"))
        if _star(act) and (_star(res) or res is None):
            out.append(("critical", "Action \"*\" on Resource \"*\" (full administrator)"))
        elif s.get("NotAction") is not None:
            out.append(("high", "Allow with NotAction grants everything except the listed actions"))
        elif any(is_lit(a) and re.fullmatch(r"(iam|sts|kms|organizations):\*", str(a)) for a in as_list(act)) and _star(res):
            out.append(("high", f"{', '.join(str(a) for a in as_list(act) if str(a).endswith(':*'))} on every resource"))
        elif any(is_lit(a) and str(a).endswith(":*") for a in as_list(act)) and _star(res):
            out.append(("medium", f"service-wide wildcards ({', '.join(str(a) for a in as_list(act) if str(a).endswith(':*'))[:120]}) on every resource"))
    return out


def public_principal(doc):
    for s in statements(doc):
        if str(s.get("Effect", "Allow")) != "Allow" or s.get("Condition"):
            continue
        p = s.get("Principal")
        if _star(p) or (isinstance(p, dict) and any(_star(v) for v in p.values())):
            return True
    return False


# ------------------------------------------------------------------------------------------ AWS network
def _sg_ingress(a):
    for r in blocks(a, "ingress"):
        cidr = as_list(r.get("cidr_blocks")) + as_list(r.get("ipv6_cidr_blocks"))
        if open_cidr(cidr):
            yield ports(r.get("from_port"), r.get("to_port"), r.get("protocol")), r.get("__line__")


@rule("NM-IAC-101", "network", "high", "Security group allows the internet to reach administration or data ports",
      ["aws_security_group"], "Restrict ingress to known address ranges or a bastion/VPN; never open SSH, RDP or database ports to 0.0.0.0/0.",
      "CIS AWS Foundations 5.2")
def _aws_sg(a, r, ctx):
    out = []
    for ps, line in _sg_ingress(a):
        sev = exposure_sev(ps)
        if sev:
            out.append({"evidence": f"ingress from 0.0.0.0/0 to {describe(ps)}", "severity": sev, "line": line})
    return out


@rule("NM-IAC-101", "network", "high", "Security group rule allows the internet to reach administration or data ports",
      ["aws_security_group_rule", "aws_vpc_security_group_ingress_rule"],
      "Restrict ingress to known address ranges or a bastion/VPN.", "CIS AWS Foundations 5.2")
def _aws_sgr(a, r, ctx):
    if r["type"] == "aws_security_group_rule" and str(a.get("type")) != "ingress":
        return None
    cidr = as_list(a.get("cidr_blocks")) + as_list(a.get("ipv6_cidr_blocks")) + as_list(a.get("cidr_ipv4")) + as_list(a.get("cidr_ipv6"))
    if not open_cidr(cidr):
        return None
    ps = ports(a.get("from_port"), a.get("to_port"), a.get("protocol") or a.get("ip_protocol"))
    sev = exposure_sev(ps)
    return {"evidence": f"ingress from the internet to {describe(ps)}", "severity": sev} if sev else None


@rule("NM-IAC-102", "network", "low", "Default security group has rules (it should deny all traffic)",
      ["aws_default_security_group"], "Leave the default security group with no ingress or egress rules; attach purpose-built groups.",
      "CIS AWS Foundations 5.4")
def _aws_default_sg(a, r, ctx):
    if blocks(a, "ingress") or blocks(a, "egress"):
        return "the default security group allows traffic"


@rule("NM-IAC-103", "network", "medium", "Network ACL allows the internet to reach administration ports",
      ["aws_network_acl_rule"], "Deny 0.0.0.0/0 to administration ports in network ACLs.", "CIS AWS Foundations 5.1")
def _aws_nacl(a, r, ctx):
    if true(a.get("egress")) or str(a.get("rule_action", "")).lower() != "allow" or not open_cidr([a.get("cidr_block"), a.get("ipv6_cidr_block")]):
        return None
    ps = ports(a.get("from_port"), a.get("to_port"), a.get("protocol"))
    if ps == "all" or (ps and ps & set(ADMIN)):
        return f"allow from the internet to {describe(ps)}"


@rule("NM-IAC-104", "network", "medium", "Instance gets a public IP address", ["aws_instance"],
      "Place instances in private subnets behind a load balancer or NAT; remove associate_public_ip_address.")
def _aws_pubip(a, r, ctx):
    if true(a.get("associate_public_ip_address")):
        return "associate_public_ip_address = true"


@rule("NM-IAC-105", "network", "low", "Subnet assigns public IP addresses to everything launched in it", ["aws_subnet"],
      "Set map_public_ip_on_launch = false and give public IPs only to load balancers or bastions.")
def _aws_subnet(a, r, ctx):
    if true(a.get("map_public_ip_on_launch")):
        return "map_public_ip_on_launch = true"


@rule("NM-IAC-106", "network", "medium", "Load balancer listener accepts plain HTTP without redirecting to HTTPS",
      ["aws_lb_listener", "aws_alb_listener"], "Redirect port 80 to HTTPS (default_action type = redirect) and serve over TLS.", cwe="CWE-319")
def _aws_listener(a, r, ctx):
    if str(a.get("protocol", "")).upper() == "HTTP" and not any(str(x.get("type")) == "redirect" for x in blocks(a, "default_action")):
        return "protocol = HTTP with no redirect action"


@rule("NM-IAC-107", "network", "medium", "Load balancer listener allows TLS versions below 1.2",
      ["aws_lb_listener", "aws_alb_listener"], "Use an ELBSecurityPolicy-TLS13-1-2-2021-06 (or newer) policy.", cwe="CWE-326")
def _aws_listener_tls(a, r, ctx):
    pol = a.get("ssl_policy")
    if is_lit(pol) and re.search(r"2015-05|2016-08|TLS-1-0|TLS-1-1|-1-0-|Legacy", str(pol)):
        return f"ssl_policy = {pol}"


@rule("NM-IAC-108", "network", "low", "Application load balancer does not drop invalid HTTP headers",
      ["aws_lb", "aws_alb"], "Set drop_invalid_header_fields = true (protects against request smuggling).", cwe="CWE-444")
def _aws_alb_hdr(a, r, ctx):
    if str(a.get("load_balancer_type", "application")) == "application" and not true(a.get("drop_invalid_header_fields")):
        return "drop_invalid_header_fields is not true"


@rule("NM-IAC-109", "network", "medium", "CloudFront distribution allows plain HTTP to viewers", ["aws_cloudfront_distribution"],
      "Set viewer_protocol_policy to redirect-to-https or https-only in every cache behaviour.", cwe="CWE-319")
def _aws_cf_http(a, r, ctx):
    for b in blocks(a, "default_cache_behavior") + blocks(a, "ordered_cache_behavior"):
        if str(b.get("viewer_protocol_policy")) == "allow-all":
            return {"evidence": "viewer_protocol_policy = allow-all", "line": b.get("__line__")}


@rule("NM-IAC-110", "network", "medium", "CloudFront distribution allows TLS versions below 1.2", ["aws_cloudfront_distribution"],
      "Set viewer_certificate.minimum_protocol_version = TLSv1.2_2021.", cwe="CWE-326")
def _aws_cf_tls(a, r, ctx):
    vc = get(a, "viewer_certificate") or {}
    v = vc.get("minimum_protocol_version")
    if true(vc.get("cloudfront_default_certificate")) or (is_lit(v) and str(v) in ("SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016")):
        return f"minimum_protocol_version = {v or 'default certificate (TLSv1)'}"


@rule("NM-IAC-111", "network", "low", "CloudFront distribution has no web application firewall", ["aws_cloudfront_distribution"],
      "Associate an AWS WAF web ACL (web_acl_id).")
def _aws_cf_waf(a, r, ctx):
    if absent(a.get("web_acl_id")):
        return "no web_acl_id"


@rule("NM-IAC-112", "network", "medium", "API Gateway method has no authorisation", ["aws_api_gateway_method"],
      "Set authorization to AWS_IAM, COGNITO_USER_POOLS or CUSTOM (or require an API key) for non-public operations.", cwe="CWE-306")
def _aws_apigw(a, r, ctx):
    if str(a.get("authorization", "")).upper() == "NONE" and str(a.get("http_method", "")).upper() != "OPTIONS" and not true(a.get("api_key_required")):
        return "authorization = NONE"


@rule("NM-IAC-112", "network", "medium", "API Gateway route has no authorisation", ["aws_apigatewayv2_route"],
      "Set authorization_type to JWT, AWS_IAM or CUSTOM for non-public routes.", cwe="CWE-306")
def _aws_apigw2(a, r, ctx):
    if str(a.get("authorization_type", "NONE")).upper() == "NONE" and not str(a.get("route_key", "")).startswith("OPTIONS"):
        return f"authorization_type is NONE for {a.get('route_key')}"


@rule("NM-IAC-113", "network", "high", "Lambda function URL accepts unauthenticated calls", ["aws_lambda_function_url"],
      "Use authorization_type = AWS_IAM, or put the function behind API Gateway with authorisation.", cwe="CWE-306")
def _aws_lambda_url(a, r, ctx):
    if str(a.get("authorization_type", "")).upper() == "NONE":
        return "authorization_type = NONE"


@rule("NM-IAC-114", "network", "high", "Lambda function can be invoked by anyone", ["aws_lambda_permission"],
      "Set principal to the calling service and restrict source_arn / source_account.", cwe="CWE-284")
def _aws_lambda_perm(a, r, ctx):
    if str(a.get("principal")) == "*":
        return "principal = \"*\""


@rule("NM-IAC-115", "network", "high", "EKS cluster API endpoint is open to the whole internet", ["aws_eks_cluster"],
      "Set endpoint_public_access = false, or restrict public_access_cidrs to known ranges.", "CIS Amazon EKS 5.4")
def _aws_eks_ep(a, r, ctx):
    vpc = get(a, "vpc_config") or {}
    if false(vpc.get("endpoint_public_access")):
        return None
    cidrs = vpc.get("public_access_cidrs")
    if cidrs is None or open_cidr(cidrs):
        return "public endpoint with public_access_cidrs " + ("left at the default (0.0.0.0/0)" if cidrs is None else "0.0.0.0/0")


@rule("NM-IAC-116", "network", "high", "Database is publicly accessible",
      ["aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_dms_replication_instance"],
      "Set publicly_accessible = false and reach the database through private networking.", "CIS AWS Foundations 2.3.3")
def _aws_db_public(a, r, ctx):
    v = a.get("publicly_accessible")
    if true(v) or (r["type"] == "aws_redshift_cluster" and absent(v)):
        return "publicly_accessible = " + ("true" if v is not None else "left at the default (true)")


@rule("NM-IAC-117", "network", "high", "Search domain is not inside a VPC", ["aws_elasticsearch_domain", "aws_opensearch_domain"],
      "Deploy the domain with vpc_options so it has no public endpoint.")
def _aws_es_vpc(a, r, ctx):
    if not blocks(a, "vpc_options"):
        return "no vpc_options: the domain has a public endpoint"


@rule("NM-IAC-118", "network", "medium", "Notebook instance has direct internet access", ["aws_sagemaker_notebook_instance"],
      "Set direct_internet_access = Disabled and use a VPC with controlled egress.")
def _aws_sm(a, r, ctx):
    if str(a.get("direct_internet_access", "Enabled")) == "Enabled":
        return "direct_internet_access is Enabled"


@rule("NM-IAC-119", "network", "medium", "Kafka cluster allows unencrypted client connections", ["aws_msk_cluster"],
      "Set encryption_info.encryption_in_transit.client_broker = TLS.", cwe="CWE-319")
def _aws_msk(a, r, ctx):
    v = get(a, "encryption_info.encryption_in_transit.client_broker")
    if is_lit(v) and str(v) in ("PLAINTEXT", "TLS_PLAINTEXT"):
        return f"client_broker = {v}"


# ------------------------------------------------------------------------------------------ AWS data
def _refers(ctx, rtypes, attr, target):
    """Is there a resource of rtypes whose attr references target ('aws_s3_bucket.name') or its literal name?"""
    ref, lit_name = target
    for x in ctx["by_type"].get(rtypes[0], []) + [y for t in rtypes[1:] for y in ctx["by_type"].get(t, [])]:
        v = str(x["attrs"].get(attr, ""))
        if ref in v or (lit_name and v == lit_name):
            return x
    return None


def _bucket_target(r):
    return (f"aws_s3_bucket.{r['name']}.", r["attrs"].get("bucket") if is_lit(r["attrs"].get("bucket")) else None)


@rule("NM-IAC-201", "data", "critical", "S3 bucket is public through its ACL", ["aws_s3_bucket", "aws_s3_bucket_acl"],
      "Use the private ACL (or BucketOwnerEnforced object ownership) and serve public content through CloudFront with origin access control.",
      "CIS AWS Foundations 2.1.4", "CWE-732")
def _aws_s3_acl(a, r, ctx):
    acl = a.get("acl")
    if is_lit(acl) and str(acl) in ("public-read", "public-read-write", "authenticated-read", "website"):
        return f"acl = {acl}"


@rule("NM-IAC-202", "data", "medium", "S3 bucket has no public access block", ["aws_s3_bucket"],
      "Add aws_s3_bucket_public_access_block with all four settings true (or confirm the account-level block is on).",
      "CIS AWS Foundations 2.1.4", "CWE-732")
def _aws_s3_pab(a, r, ctx):
    if not _refers(ctx, ["aws_s3_bucket_public_access_block"], "bucket", _bucket_target(r)) and not ctx["by_type"].get("aws_s3_account_public_access_block"):
        return "no aws_s3_bucket_public_access_block for this bucket and no account-level block in these templates"


@rule("NM-IAC-203", "data", "high", "S3 public access block is partly disabled", ["aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"],
      "Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets to true.", "CIS AWS Foundations 2.1.4", "CWE-732")
def _aws_pab(a, r, ctx):
    off = [k for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets") if false(a.get(k)) or absent(a.get(k))]
    if off:
        return ", ".join(off) + " not true"


@rule("NM-IAC-204", "data", "high", "Bucket policy grants access to everyone", ["aws_s3_bucket_policy"],
      "Remove Principal \"*\" statements or add conditions (aws:SourceVpce, aws:PrincipalOrgID, aws:SecureTransport).", cwe="CWE-732")
def _aws_s3_policy(a, r, ctx):
    if public_principal(policy_doc(a.get("policy"))):
        return "Allow to Principal \"*\" with no condition"


@rule("NM-IAC-205", "data", "low", "S3 bucket versioning is not enabled", ["aws_s3_bucket"],
      "Enable versioning (aws_s3_bucket_versioning) so deleted or overwritten objects can be recovered (ransomware).")
def _aws_s3_ver(a, r, ctx):
    if true(get(a, "versioning.enabled")):
        return None
    x = _refers(ctx, ["aws_s3_bucket_versioning"], "bucket", _bucket_target(r))
    if x and str(get(x["attrs"], "versioning_configuration.status")) == "Enabled":
        return None
    return "no versioning configuration"


@rule("NM-IAC-206", "data", "high", "Database storage is not encrypted",
      ["aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster", "aws_redshift_cluster"],
      "Set storage_encrypted (encrypted for Redshift) = true with a KMS key.", "CIS AWS Foundations 2.3.1")
def _aws_db_enc(a, r, ctx):
    k = "encrypted" if r["type"] == "aws_redshift_cluster" else "storage_encrypted"
    if r["type"] == "aws_rds_cluster" and str(a.get("engine_mode")) == "serverless":
        return None
    if r["type"] == "aws_db_instance" and a.get("replicate_source_db") is not None:
        return None                                   # read replicas inherit the source's encryption
    v = a.get(k)
    if false(v) or absent(v):
        return f"{k} = " + ("false" if v is not None else "left at the default (false)")


@rule("NM-IAC-207", "data", "medium", "Block storage volume is not encrypted", ["aws_ebs_volume"],
      "Set encrypted = true (and enable EBS encryption by default in the account).", "CIS AWS Foundations 2.2.1")
def _aws_ebs(a, r, ctx):
    if not true(a.get("encrypted")) and not ctx["by_type"].get("aws_ebs_encryption_by_default"):
        return "encrypted is not true"


@rule("NM-IAC-207", "data", "medium", "Instance disks are not encrypted", ["aws_instance", "aws_launch_template", "aws_launch_configuration"],
      "Set encrypted = true on root and EBS block devices.", "CIS AWS Foundations 2.2.1")
def _aws_inst_disk(a, r, ctx):
    if ctx["by_type"].get("aws_ebs_encryption_by_default"):
        return None
    devs = blocks(a, "root_block_device") + blocks(a, "ebs_block_device")
    for bd in blocks(a, "block_device_mappings"):
        devs += blocks(bd, "ebs")
    bad = [d for d in devs if false(d.get("encrypted"))]
    if bad:
        return {"evidence": "encrypted = false on a block device", "line": bad[0].get("__line__")}


@rule("NM-IAC-208", "data", "high", "File system is not encrypted", ["aws_efs_file_system", "aws_fsx_lustre_file_system"],
      "Set encrypted = true with a KMS key.", "CIS AWS Foundations 2.4.1")
def _aws_efs(a, r, ctx):
    if r["type"] == "aws_efs_file_system" and not true(a.get("encrypted")):
        return "encrypted is not true"


@rule("NM-IAC-209", "data", "medium", "Cache is not encrypted at rest or in transit", ["aws_elasticache_replication_group"],
      "Set at_rest_encryption_enabled and transit_encryption_enabled to true (and use an AUTH token or RBAC).")
def _aws_cache(a, r, ctx):
    off = [k for k in ("at_rest_encryption_enabled", "transit_encryption_enabled") if not true(a.get(k))]
    if off:
        return ", ".join(off) + " not true"


@rule("NM-IAC-210", "data", "medium", "Stream or queue data is not encrypted", ["aws_kinesis_stream", "aws_sqs_queue", "aws_sns_topic"],
      "Encrypt with KMS: encryption_type = KMS (Kinesis), sqs_managed_sse_enabled or kms_master_key_id (SQS), kms_master_key_id (SNS).")
def _aws_msg(a, r, ctx):
    t = r["type"]
    if t == "aws_kinesis_stream" and str(a.get("encryption_type", "NONE")) == "NONE":
        return "encryption_type is NONE"
    if t == "aws_sqs_queue" and false(a.get("sqs_managed_sse_enabled")) and absent(a.get("kms_master_key_id")):
        return "sqs_managed_sse_enabled = false and no KMS key"
    if t == "aws_sns_topic" and absent(a.get("kms_master_key_id")):
        return {"evidence": "no kms_master_key_id", "severity": "low"}


@rule("NM-IAC-211", "data", "high", "Search domain data is not encrypted", ["aws_elasticsearch_domain", "aws_opensearch_domain"],
      "Enable encrypt_at_rest, node_to_node_encryption and domain_endpoint_options.enforce_https.")
def _aws_es_enc(a, r, ctx):
    off = []
    if not true(get(a, "encrypt_at_rest.enabled")):
        off.append("encryption at rest")
    if not true(get(a, "node_to_node_encryption.enabled")):
        off.append("node-to-node encryption")
    if false(get(a, "domain_endpoint_options.enforce_https")):
        off.append("HTTPS enforcement")
    if off:
        return "disabled: " + ", ".join(off)


@rule("NM-IAC-212", "data", "medium", "Database backups are disabled or kept for less than 7 days", ["aws_db_instance", "aws_rds_cluster"],
      "Set backup_retention_period to 7 days or more.")
def _aws_backup(a, r, ctx):
    v = a.get("backup_retention_period")
    try:
        if v is not None and is_lit(v) and int(v) < 7:
            return f"backup_retention_period = {v}"
    except (TypeError, ValueError):
        return None


@rule("NM-IAC-213", "data", "low", "Database has no deletion protection", ["aws_db_instance", "aws_rds_cluster"],
      "Set deletion_protection = true for production databases.")
def _aws_delprot(a, r, ctx):
    if not true(a.get("deletion_protection")):
        return "deletion_protection is not true"


@rule("NM-IAC-214", "data", "medium", "KMS key rotation is disabled", ["aws_kms_key"], "Set enable_key_rotation = true.",
      "CIS AWS Foundations 3.6", "CWE-320")
def _aws_kms(a, r, ctx):
    if str(a.get("customer_master_key_spec", "SYMMETRIC_DEFAULT")) == "SYMMETRIC_DEFAULT" and not true(a.get("enable_key_rotation")):
        return "enable_key_rotation is not true"


@rule("NM-IAC-215", "data", "medium", "Sensitive parameter stored as plain text", ["aws_ssm_parameter"],
      "Use type = SecureString (encrypted with KMS) for passwords, tokens and keys.", cwe="CWE-312")
def _aws_ssm(a, r, ctx):
    if str(a.get("type")) == "String" and re.search(r"(?i)pass|secret|token|key|credential", str(a.get("name", ""))):
        return f"type = String for {a.get('name')}"


@rule("NM-IAC-216", "data", "low", "Container registry allows image tags to be overwritten", ["aws_ecr_repository"],
      "Set image_tag_mutability = IMMUTABLE so a deployed tag always means the same image.", cwe="CWE-494")
def _aws_ecr_mut(a, r, ctx):
    if str(a.get("image_tag_mutability", "MUTABLE")) == "MUTABLE":
        return "image_tag_mutability is MUTABLE"


@rule("NM-IAC-217", "data", "low", "DynamoDB table has no point-in-time recovery", ["aws_dynamodb_table"],
      "Enable point_in_time_recovery.")
def _aws_ddb(a, r, ctx):
    if not true(get(a, "point_in_time_recovery.enabled")):
        return "point_in_time_recovery is not enabled"


@rule("NM-IAC-218", "data", "high", "Secret is stored in plain text in the template",
      ["aws_db_instance", "aws_rds_cluster", "aws_redshift_cluster", "aws_docdb_cluster", "aws_elasticache_replication_group",
       "azurerm_mssql_server", "azurerm_sql_server", "azurerm_postgresql_server", "azurerm_mysql_server",
       "azurerm_postgresql_flexible_server", "azurerm_mysql_flexible_server", "azurerm_linux_virtual_machine",
       "azurerm_windows_virtual_machine", "google_sql_user"],
      "Generate the password (random_password, manage_master_user_password, Key Vault) instead of writing it in the template.", cwe="CWE-798")
def _plain_pw(a, r, ctx):
    for k in ("password", "master_password", "administrator_login_password", "admin_password", "auth_token"):
        v = a.get(k)
        if is_lit(v) and isinstance(v, str) and len(v) >= 4 and not v.startswith(("var.", "random_", "data.")):
            return f"{k} is a literal value"


# ------------------------------------------------------------------------------------------ AWS compute
@rule("NM-IAC-301", "compute", "medium", "Instance metadata service v1 is allowed (IMDSv2 not required)",
      ["aws_instance", "aws_launch_template", "aws_launch_configuration"],
      "Set metadata_options.http_tokens = required (blocks SSRF-driven credential theft).", "CIS AWS Foundations 5.6", "CWE-918")
def _aws_imds(a, r, ctx):
    m = get(a, "metadata_options") or {}
    if str(m.get("http_endpoint", "enabled")) == "disabled":
        return None
    if str(m.get("http_tokens", "optional")) != "required" and not isinstance(m.get("http_tokens"), Expr):
        return "http_tokens is " + (str(m.get("http_tokens")) if m.get("http_tokens") else "left at the default (optional)")


@rule("NM-IAC-302", "compute", "high", "ECS task runs a privileged container", ["aws_ecs_task_definition"],
      "Remove privileged = true; add only the Linux capabilities the container needs.", cwe="CWE-250")
def _aws_ecs_priv(a, r, ctx):
    cd = a.get("container_definitions")
    try:
        defs = cd if isinstance(cd, list) else json.loads(str(cd)) if is_lit(cd) or (isinstance(cd, Expr) and str(cd).lstrip().startswith("[")) else []
    except ValueError:
        return None
    out = []
    for c in defs if isinstance(defs, list) else []:
        if isinstance(c, dict) and c.get("privileged") is True:
            out.append(f"container {c.get('name')} privileged")
    if str(a.get("network_mode")) == "host":
        out.append("network_mode = host")
    if str(a.get("pid_mode")) == "host":
        out.append("pid_mode = host")
    return "; ".join(out) or None


@rule("NM-IAC-303", "compute", "low", "Container registry does not scan images on push", ["aws_ecr_repository"],
      "Enable image_scanning_configuration.scan_on_push (or registry-level enhanced scanning).", cwe="CWE-1104")
def _aws_ecr_scan(a, r, ctx):
    if not true(get(a, "image_scanning_configuration.scan_on_push")):
        return "scan_on_push is not true"


@rule("NM-IAC-304", "compute", "medium", "Notebook instance gives users root access", ["aws_sagemaker_notebook_instance"],
      "Set root_access = Disabled.", cwe="CWE-250")
def _aws_sm_root(a, r, ctx):
    if str(a.get("root_access", "Enabled")) == "Enabled":
        return "root_access is Enabled"


@rule("NM-IAC-305", "compute", "low", "Database minor-version upgrades are turned off", ["aws_db_instance", "aws_rds_cluster_instance"],
      "Set auto_minor_version_upgrade = true so security patches are applied.", cwe="CWE-1104")
def _aws_minor(a, r, ctx):
    if false(a.get("auto_minor_version_upgrade")):
        return "auto_minor_version_upgrade = false"


# ------------------------------------------------------------------------------------------ AWS identity
@rule("NM-IAC-401", "identity", "high", "IAM policy grants wildcard permissions",
      ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy_document"],
      "Grant only the actions and resources the workload needs; replace \"*\" with explicit actions and ARNs.",
      "CIS AWS Foundations 1.16", "CWE-269")
def _aws_iam_wild(a, r, ctx):
    doc = policy_doc(a.get("policy"))
    if r["type"] == "aws_iam_policy_document":
        doc = {"Statement": [{"Effect": s.get("effect", "Allow"), "Action": s.get("actions"), "NotAction": s.get("not_actions"),
                              "Resource": s.get("resources")} for s in blocks(a, "statement")]}
        for s in doc["Statement"]:
            if s["NotAction"] is None:
                s.pop("NotAction")
    out = [{"evidence": ev, "severity": sev} for sev, ev in wildcard_findings(doc)]
    return out[:3] or None


@rule("NM-IAC-402", "identity", "critical", "Role can be assumed by anyone", ["aws_iam_role"],
      "Name the trusted account, service or federated identity in the trust policy, and add conditions (sts:ExternalId, aws:PrincipalOrgID).",
      cwe="CWE-284")
def _aws_trust(a, r, ctx):
    if public_principal(policy_doc(a.get("assume_role_policy"))):
        return "trust policy allows Principal \"*\""


@rule("NM-IAC-403", "identity", "low", "IAM policy is attached directly to a user", ["aws_iam_user_policy", "aws_iam_user_policy_attachment"],
      "Attach policies to groups or roles, not users.", "CIS AWS Foundations 1.15")
def _aws_user_pol(a, r, ctx):
    return "permissions attached to a user"


@rule("NM-IAC-404", "identity", "medium", "Long-lived access key created for an IAM user", ["aws_iam_access_key"],
      "Use roles (instance profiles, IRSA, OIDC federation for CI) instead of access keys.", "CIS AWS Foundations 1.14", "CWE-798")
def _aws_key(a, r, ctx):
    return "aws_iam_access_key creates a static credential"


@rule("NM-IAC-405", "identity", "medium", "Account password policy is weak", ["aws_iam_account_password_policy"],
      "Require at least 14 characters, prevent reuse of 24 passwords and enforce complexity.", "CIS AWS Foundations 1.8")
def _aws_pwpol(a, r, ctx):
    bad = []
    try:
        if int(a.get("minimum_password_length", 8)) < 14:
            bad.append(f"minimum length {a.get('minimum_password_length', 8)}")
    except (TypeError, ValueError):
        pass
    try:
        if int(a.get("password_reuse_prevention", 0) or 0) < 24:
            bad.append("reuse prevention below 24")
    except (TypeError, ValueError):
        pass
    return ", ".join(bad) or None


@rule("NM-IAC-406", "identity", "medium", "Database does not use IAM authentication", ["aws_db_instance", "aws_rds_cluster"],
      "Set iam_database_authentication_enabled = true and use short-lived tokens instead of static passwords.")
def _aws_db_iam(a, r, ctx):
    if false(a.get("iam_database_authentication_enabled")) and str(a.get("engine", "")) in ("mysql", "postgres", "aurora-mysql", "aurora-postgresql"):
        return "iam_database_authentication_enabled = false"


# ------------------------------------------------------------------------------------------ AWS logging
@rule("NM-IAC-501", "logging", "medium", "CloudTrail trail is single-region or does not validate log files", ["aws_cloudtrail"],
      "Set is_multi_region_trail = true and enable_log_file_validation = true; encrypt with kms_key_id.", "CIS AWS Foundations 3.1-3.2")
def _aws_trail(a, r, ctx):
    bad = []
    if not true(a.get("is_multi_region_trail")):
        bad.append("not multi-region")
    if not true(a.get("enable_log_file_validation")):
        bad.append("log file validation off")
    if absent(a.get("kms_key_id")):
        bad.append("not encrypted with KMS")
    if false(a.get("enable_logging")):
        bad.append("logging disabled")
    return ", ".join(bad) or None


@rule("NM-IAC-502", "logging", "medium", "VPC has no flow logs", ["aws_vpc"], "Add aws_flow_log for the VPC (REJECT at least).",
      "CIS AWS Foundations 3.9")
def _aws_flow(a, r, ctx):
    if not _refers(ctx, ["aws_flow_log"], "vpc_id", (f"aws_vpc.{r['name']}.", None)):
        return "no aws_flow_log references this VPC"


@rule("NM-IAC-503", "logging", "medium", "EKS control-plane audit logs are not enabled", ["aws_eks_cluster"],
      "Set enabled_cluster_log_types to include api, audit and authenticator.", "CIS Amazon EKS 2.1.1")
def _aws_eks_log(a, r, ctx):
    v = a.get("enabled_cluster_log_types")
    if v is None or (isinstance(v, list) and "audit" not in [str(x) for x in v]):
        return "audit log type not enabled"


@rule("NM-IAC-504", "data", "medium", "Kubernetes Secrets are not encrypted with a KMS key", ["aws_eks_cluster"],
      "Add encryption_config with resources = [\"secrets\"] and a KMS key.", "CIS Amazon EKS 5.3.1")
def _aws_eks_kms(a, r, ctx):
    if not blocks(a, "encryption_config"):
        return "no encryption_config"


@rule("NM-IAC-505", "logging", "low", "Access logging is not enabled",
      ["aws_s3_bucket", "aws_lb", "aws_alb", "aws_cloudfront_distribution", "aws_api_gateway_stage"],
      "Enable access logs (S3 server access logging, load balancer access_logs, CloudFront logging_config, API Gateway access_log_settings).",
      "CIS AWS Foundations 3.6")
def _aws_access_logs(a, r, ctx):
    t = r["type"]
    if t == "aws_s3_bucket":
        if blocks(a, "logging") or _refers(ctx, ["aws_s3_bucket_logging"], "bucket", _bucket_target(r)):
            return None
        # buckets that are themselves log targets do not need logging
        if re.search(r"(?i)log", str(a.get("bucket", "")) + r["name"]):
            return None
        return "no server access logging"
    if t in ("aws_lb", "aws_alb"):
        return None if true(get(a, "access_logs.enabled")) else "access_logs not enabled"
    if t == "aws_cloudfront_distribution":
        return None if blocks(a, "logging_config") else "no logging_config"
    return None if blocks(a, "access_log_settings") else "no access_log_settings"


@rule("NM-IAC-506", "logging", "medium", "Search domain does not publish audit or error logs", ["aws_elasticsearch_domain", "aws_opensearch_domain"],
      "Add log_publishing_options for AUDIT_LOGS and ES_APPLICATION_LOGS.")
def _aws_es_log(a, r, ctx):
    if not blocks(a, "log_publishing_options"):
        return "no log_publishing_options"


@rule("NM-IAC-507", "logging", "medium", "Threat detection is turned off", ["aws_guardduty_detector"],
      "Set enable = true for GuardDuty in every region.", "CIS AWS Foundations 4.x")
def _aws_gd(a, r, ctx):
    if false(a.get("enable")):
        return "enable = false"


# ------------------------------------------------------------------------------------------ Azure
AZ_OPEN = {"*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "<nw>/0", "/0"}


def _az_rule_open(rule_):
    if str(rule_.get("direction", "")).lower() != "inbound" or str(rule_.get("access", "")).lower() != "allow":
        return None
    srcs = as_list(rule_.get("source_address_prefix")) + as_list(rule_.get("source_address_prefixes"))
    if not any(is_lit(s) and str(s).lower() in AZ_OPEN for s in srcs):
        return None
    ps = range_ports(as_list(rule_.get("destination_port_range")) + as_list(rule_.get("destination_port_ranges")))
    return ps if (ps == "all" or ps) else None


@rule("NM-IAC-121", "network", "high", "Network security group allows the internet to reach administration or data ports",
      ["azurerm_network_security_group", "azurerm_network_security_rule"],
      "Allow inbound only from known ranges, Azure Bastion or a VPN; use just-in-time VM access for SSH/RDP.", "CIS Microsoft Azure Foundations 6.1-6.4")
def _az_nsg(a, r, ctx):
    rules = blocks(a, "security_rule") if r["type"] == "azurerm_network_security_group" else [a]
    out = []
    for x in rules:
        ps = _az_rule_open(x)
        if ps:
            out.append({"evidence": f"inbound Allow from the internet to {describe(ps)}", "severity": exposure_sev(ps), "line": x.get("__line__")})
    return out or None


@rule("NM-IAC-122", "network", "critical", "Database firewall allows the whole internet",
      ["azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule", "azurerm_postgresql_firewall_rule", "azurerm_mysql_firewall_rule",
       "azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule", "azurerm_mariadb_firewall_rule",
       "azurerm_redis_firewall_rule", "azurerm_synapse_firewall_rule"],
      "Allow only the client ranges that need access, or use private endpoints.", "CIS Microsoft Azure Foundations 4.1.2")
def _az_dbfw(a, r, ctx):
    s, e = str(a.get("start_ip_address", "")), str(a.get("end_ip_address", ""))
    if s == "0.0.0.0" and e == "255.255.255.255":
        return "0.0.0.0 - 255.255.255.255"
    if s == "0.0.0.0" and e == "0.0.0.0":
        return {"evidence": "0.0.0.0 - 0.0.0.0 allows every Azure service, including other tenants'", "severity": "medium"}


@rule("NM-IAC-123", "network", "medium", "Service accepts connections from public networks",
      ["azurerm_storage_account", "azurerm_mssql_server", "azurerm_sql_server", "azurerm_postgresql_server", "azurerm_mysql_server",
       "azurerm_cosmosdb_account", "azurerm_container_registry", "azurerm_key_vault", "azurerm_redis_cache", "azurerm_search_service",
       "azurerm_cognitive_account", "azurerm_eventhub_namespace", "azurerm_servicebus_namespace", "azurerm_data_factory"],
      "Disable public network access and use private endpoints, or restrict network rules to known ranges (default_action = Deny).",
      "CIS Microsoft Azure Foundations")
def _az_public(a, r, ctx):
    pub = a.get("public_network_access_enabled")
    if false(pub):
        return None
    acl = get(a, "network_rules") or get(a, "network_acls") or get(a, "network_rule_set")
    if isinstance(acl, dict) and str(acl.get("default_action", "")).lower() == "deny":
        return None
    if true(pub):
        return "public_network_access_enabled = true" + ("" if acl is None else " and network rules allow by default")
    if pub is None and acl is None and r["type"] in ("azurerm_storage_account", "azurerm_key_vault", "azurerm_cosmosdb_account"):
        return {"evidence": "no network rules: the endpoint accepts traffic from all networks (provider default)", "severity": "low"}
    if isinstance(acl, dict) and str(acl.get("default_action", "")).lower() == "allow":
        return "network rules default_action = Allow"
    return None


@rule("NM-IAC-124", "network", "high", "AKS API server is reachable from the whole internet", ["azurerm_kubernetes_cluster"],
      "Use private_cluster_enabled = true, or set api_server_access_profile.authorized_ip_ranges.", "CIS Azure Kubernetes Service 5.4")
def _az_aks_ep(a, r, ctx):
    if true(a.get("private_cluster_enabled")):
        return None
    if a.get("api_server_authorized_ip_ranges") or get(a, "api_server_access_profile.authorized_ip_ranges"):
        return None
    return "public API server with no authorised IP ranges"


@rule("NM-IAC-125", "network", "medium", "AKS cluster has no network policy", ["azurerm_kubernetes_cluster"],
      "Set network_profile.network_policy (azure, calico or cilium) and apply NetworkPolicies.", "CIS Azure Kubernetes Service 5.4")
def _az_aks_np(a, r, ctx):
    if absent(get(a, "network_profile.network_policy")) and absent(get(a, "network_profile.network_data_plane")):
        return "network_profile.network_policy not set"


@rule("NM-IAC-126", "network", "medium", "App Service accepts plain HTTP or old TLS",
      ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_function_app",
       "azurerm_linux_function_app", "azurerm_windows_function_app"],
      "Set https_only = true and site_config.minimum_tls_version = 1.2.", "CIS Microsoft Azure Foundations 9.2-9.3", "CWE-319")
def _az_app_tls(a, r, ctx):
    bad = []
    if not true(a.get("https_only")):
        bad.append("https_only is not true")
    tls = get(a, "site_config.minimum_tls_version") or get(a, "site_config.min_tls_version")
    if is_lit(tls) and str(tls) in ("1.0", "1.1"):
        bad.append(f"minimum TLS {tls}")
    return ", ".join(bad) or None


@rule("NM-IAC-127", "network", "medium", "Service allows TLS versions below 1.2",
      ["azurerm_storage_account", "azurerm_mssql_server", "azurerm_redis_cache", "azurerm_postgresql_server", "azurerm_mysql_server"],
      "Set the minimum TLS version to 1.2.", "CIS Microsoft Azure Foundations", "CWE-326")
def _az_tls(a, r, ctx):
    for k in ("min_tls_version", "minimum_tls_version", "ssl_minimal_tls_version_enforced"):
        v = a.get(k)
        if is_lit(v) and re.search(r"1[._]?[01]\b|TLS1_0|TLS1_1|TLSEnforcementDisabled", str(v)):
            return f"{k} = {v}"


@rule("NM-IAC-128", "network", "high", "Cache accepts unencrypted connections", ["azurerm_redis_cache"],
      "Set non_ssl_port_enabled (enable_non_ssl_port) = false.", cwe="CWE-319")
def _az_redis(a, r, ctx):
    if true(a.get("enable_non_ssl_port")) or true(a.get("non_ssl_port_enabled")):
        return "non-TLS port 6379 enabled"


@rule("NM-IAC-129", "network", "high", "Database does not enforce TLS", ["azurerm_postgresql_server", "azurerm_mysql_server", "azurerm_mariadb_server"],
      "Set ssl_enforcement_enabled = true.", "CIS Microsoft Azure Foundations 4.3.1", "CWE-319")
def _az_ssl(a, r, ctx):
    if false(a.get("ssl_enforcement_enabled")) or false(a.get("ssl_enforcement")):
        return "ssl_enforcement_enabled = false"


@rule("NM-IAC-130", "network", "medium", "Plain FTP deployment is allowed",
      ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app"],
      "Set site_config.ftps_state = FtpsOnly or Disabled.", "CIS Microsoft Azure Foundations 9.10", "CWE-319")
def _az_ftp(a, r, ctx):
    v = get(a, "site_config.ftps_state")
    if (is_lit(v) and str(v) == "AllAllowed") or (v is None and r["type"] == "azurerm_app_service"):
        return "ftps_state = " + (str(v) if v else "left at the default (AllAllowed)")


@rule("NM-IAC-221", "data", "high", "Storage container allows anonymous access", ["azurerm_storage_container"],
      "Set container_access_type = private and serve public content through a CDN with authentication.", "CIS Microsoft Azure Foundations 3.7", "CWE-732")
def _az_container(a, r, ctx):
    v = a.get("container_access_type")
    if is_lit(v) and str(v) in ("blob", "container"):
        return f"container_access_type = {v}"


@rule("NM-IAC-222", "data", "high", "Storage account allows public blob access", ["azurerm_storage_account"],
      "Set allow_nested_items_to_be_public (allow_blob_public_access) = false.", "CIS Microsoft Azure Foundations 3.7", "CWE-732")
def _az_blob_public(a, r, ctx):
    if true(a.get("allow_nested_items_to_be_public")) or true(a.get("allow_blob_public_access")):
        return "public blob access allowed"


@rule("NM-IAC-223", "data", "medium", "Storage account accepts plain HTTP", ["azurerm_storage_account"],
      "Set https_traffic_only_enabled (enable_https_traffic_only) = true.", "CIS Microsoft Azure Foundations 3.1", "CWE-319")
def _az_https(a, r, ctx):
    if false(a.get("enable_https_traffic_only")) or false(a.get("https_traffic_only_enabled")):
        return "HTTPS-only traffic disabled"


@rule("NM-IAC-224", "data", "medium", "Key vault has no purge protection", ["azurerm_key_vault"],
      "Set purge_protection_enabled = true so deleted keys and secrets cannot be destroyed immediately.", "CIS Microsoft Azure Foundations 8.5")
def _az_kv_purge(a, r, ctx):
    if not true(a.get("purge_protection_enabled")):
        return "purge_protection_enabled is not true"


@rule("NM-IAC-225", "data", "low", "Key vault secret or key has no expiry", ["azurerm_key_vault_secret", "azurerm_key_vault_key"],
      "Set expiration_date and rotate before it.", "CIS Microsoft Azure Foundations 8.1-8.4")
def _az_kv_exp(a, r, ctx):
    if absent(a.get("expiration_date")) and absent(get(a, "rotation_policy")):
        return "no expiration_date"


@rule("NM-IAC-226", "data", "high", "Container registry allows anonymous pulls", ["azurerm_container_registry"],
      "Set anonymous_pull_enabled = false.", cwe="CWE-284")
def _az_acr_anon(a, r, ctx):
    if true(a.get("anonymous_pull_enabled")):
        return "anonymous_pull_enabled = true"


@rule("NM-IAC-227", "data", "medium", "Database has no geo-redundant or long-enough backups",
      ["azurerm_postgresql_server", "azurerm_mysql_server", "azurerm_mariadb_server"],
      "Enable geo_redundant_backup_enabled and keep backups for 7 days or more.")
def _az_backup(a, r, ctx):
    v = a.get("backup_retention_days")
    try:
        if v is not None and int(v) < 7:
            return f"backup_retention_days = {v}"
    except (TypeError, ValueError):
        return None


@rule("NM-IAC-321", "compute", "medium", "Linux VM allows password sign-in", ["azurerm_linux_virtual_machine", "azurerm_virtual_machine"],
      "Set disable_password_authentication = true and use SSH keys (or Entra ID sign-in).", "CIS Microsoft Azure Foundations 7.x", "CWE-521")
def _az_vm_pw(a, r, ctx):
    v = a.get("disable_password_authentication")
    if r["type"] == "azurerm_virtual_machine":
        v = get(a, "os_profile_linux_config.disable_password_authentication")
        if not blocks(a, "os_profile_linux_config"):
            return None
    if false(v):
        return "disable_password_authentication = false"


@rule("NM-IAC-322", "compute", "high", "Remote debugging is enabled",
      ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app"],
      "Set site_config.remote_debugging_enabled = false.", cwe="CWE-489")
def _az_debug(a, r, ctx):
    if true(get(a, "site_config.remote_debugging_enabled")) or true(get(a, "site_config.remote_debugging")):
        return "remote debugging on"


@rule("NM-IAC-323", "compute", "low", "VM disks are not encrypted at host", ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"],
      "Set encryption_at_host_enabled = true (or use customer-managed keys with disk encryption sets).", cwe="CWE-311")
def _az_vm_enc(a, r, ctx):
    if not true(a.get("encryption_at_host_enabled")) and absent(get(a, "os_disk.disk_encryption_set_id")):
        return "encryption_at_host_enabled is not true"


@rule("NM-IAC-421", "identity", "critical", "AKS cluster has Kubernetes RBAC disabled", ["azurerm_kubernetes_cluster"],
      "Set role_based_access_control_enabled = true (with Entra ID integration).", "CIS Azure Kubernetes Service")
def _az_aks_rbac(a, r, ctx):
    if false(a.get("role_based_access_control_enabled")) or false(get(a, "role_based_access_control.enabled")):
        return "RBAC disabled"


@rule("NM-IAC-422", "identity", "medium", "AKS local accounts are enabled", ["azurerm_kubernetes_cluster"],
      "Set local_account_disabled = true and sign in with Entra ID.")
def _az_aks_local(a, r, ctx):
    if not true(a.get("local_account_disabled")):
        return "local_account_disabled is not true"


@rule("NM-IAC-423", "identity", "high", "Container registry admin account is enabled", ["azurerm_container_registry"],
      "Set admin_enabled = false; use managed identities or scoped tokens.", cwe="CWE-798")
def _az_acr_admin(a, r, ctx):
    if true(a.get("admin_enabled")):
        return "admin_enabled = true"


@rule("NM-IAC-424", "identity", "high", "Custom role grants every action", ["azurerm_role_definition"],
      "List only the actions the role needs; never \"*\".", "CIS Microsoft Azure Foundations 1.23")
def _az_role_def(a, r, ctx):
    for p in blocks(a, "permissions"):
        if _star(p.get("actions")):
            return "actions = [\"*\"]"


@rule("NM-IAC-425", "identity", "medium", "Owner role assigned at subscription or management-group scope", ["azurerm_role_assignment"],
      "Assign narrower roles at resource-group or resource scope; use PIM for eligible Owner access.")
def _az_owner(a, r, ctx):
    scope = str(a.get("scope", ""))
    if str(a.get("role_definition_name", "")) == "Owner" and (re.fullmatch(r"/subscriptions/[^/]+/?", scope) or "managementGroups" in scope
                                                              or "subscription" in scope and "resourceGroups" not in scope):
        return f"Owner on {scope[:80]}"


@rule("NM-IAC-426", "identity", "low", "Key-based authentication is enabled where Entra ID is available",
      ["azurerm_storage_account", "azurerm_cosmosdb_account", "azurerm_cognitive_account", "azurerm_eventhub_namespace", "azurerm_servicebus_namespace"],
      "Disable shared keys / local authentication and use Entra ID with managed identities.")
def _az_local_auth(a, r, ctx):
    if false(a.get("local_authentication_disabled")) or true(a.get("shared_access_key_enabled")) or true(a.get("local_auth_enabled")):
        return "key-based authentication allowed"


@rule("NM-IAC-521", "logging", "medium", "Microsoft Defender for Cloud plan is on the free tier", ["azurerm_security_center_subscription_pricing"],
      "Set tier = Standard for the resource types you run.", "CIS Microsoft Azure Foundations 2.1")
def _az_defender(a, r, ctx):
    if str(a.get("tier", "")) == "Free":
        return f"tier = Free ({a.get('resource_type', 'VirtualMachines')})"


@rule("NM-IAC-522", "logging", "low", "NSG flow logs are disabled", ["azurerm_network_watcher_flow_log"],
      "Set enabled = true and keep logs for at least 90 days.", "CIS Microsoft Azure Foundations 6.5")
def _az_flow(a, r, ctx):
    if false(a.get("enabled")):
        return "enabled = false"


@rule("NM-IAC-523", "logging", "low", "AKS cluster does not send logs to Azure Monitor", ["azurerm_kubernetes_cluster"],
      "Enable oms_agent / Container insights and diagnostic settings for kube-audit.")
def _az_aks_log(a, r, ctx):
    if not blocks(a, "oms_agent") and not blocks(a, "monitor_metrics"):
        return "no oms_agent"


@rule("NM-IAC-524", "logging", "low", "SQL server auditing is not configured", ["azurerm_mssql_server", "azurerm_sql_server"],
      "Add azurerm_mssql_server_extended_auditing_policy (retention 90 days or more).", "CIS Microsoft Azure Foundations 4.1.1")
def _az_sql_audit(a, r, ctx):
    if blocks(a, "extended_auditing_policy"):
        return None
    if _refers(ctx, ["azurerm_mssql_server_extended_auditing_policy"], "server_id", (f"{r['type']}.{r['name']}.", None)):
        return None
    return "no auditing policy for this server"


@rule("NM-IAC-525", "logging", "medium", "SQL threat detection is off or alerts are suppressed", ["azurerm_mssql_server_security_alert_policy"],
      "Set state = Enabled, leave disabled_alerts empty, and send alerts to email_addresses / email_account_admins.",
      "CIS Microsoft Azure Foundations 4.2")
def _az_sql_alert(a, r, ctx):
    bad = []
    if str(a.get("state", "")) == "Disabled":
        bad.append("state = Disabled")
    if a.get("disabled_alerts"):
        bad.append(f"disabled_alerts = {a.get('disabled_alerts')}")
    if not a.get("email_addresses") and not true(a.get("email_account_admins")):
        bad.append("no alert recipients")
    return ", ".join(bad) or None


@rule("NM-IAC-526", "logging", "low", "PostgreSQL connection or checkpoint logging is off",
      ["azurerm_postgresql_configuration", "azurerm_postgresql_flexible_server_configuration"],
      "Set log_checkpoints, log_connections, log_disconnections and connection_throttling to on.", "CIS Microsoft Azure Foundations 4.3.2-4.3.5")
def _az_pg_conf(a, r, ctx):
    if str(a.get("name")) in ("log_checkpoints", "log_connections", "log_disconnections", "connection_throttling", "log_retention_days") \
            and str(a.get("value", "")).lower() in ("off", "false", "0", "1", "2"):
        return f"{a.get('name')} = {a.get('value')}"


@rule("NM-IAC-527", "logging", "low", "Security alerts are not sent to the security contact", ["azurerm_security_center_contact"],
      "Set alert_notifications = true and alerts_to_admins = true.", "CIS Microsoft Azure Foundations 2.1.19")
def _az_contact(a, r, ctx):
    if false(a.get("alert_notifications")) or false(a.get("alerts_to_admins")):
        return "alert notifications off"


@rule("NM-IAC-528", "logging", "low", "Activity log is kept for less than a year", ["azurerm_monitor_log_profile"],
      "Set retention_policy.days to 365 or more (or 0 for indefinite with enabled = true).", "CIS Microsoft Azure Foundations 5.1.2")
def _az_logprof(a, r, ctx):
    rp = get(a, "retention_policy") or {}
    try:
        if true(rp.get("enabled")) and 0 < int(rp.get("days", 0)) < 365:
            return f"retention {rp.get('days')} days"
    except (TypeError, ValueError):
        return None


@rule("NM-IAC-131", "network", "medium", "Storage account network rules allow all networks", ["azurerm_storage_account_network_rules"],
      "Set default_action = Deny and allow only the virtual networks and IP ranges that need access.", "CIS Microsoft Azure Foundations 3.8")
def _az_sa_rules(a, r, ctx):
    if str(a.get("default_action", "")).lower() == "allow":
        return "default_action = Allow"


@rule("NM-IAC-132", "network", "low", "Application gateway has no web application firewall", ["azurerm_application_gateway"],
      "Use a WAF_v2 SKU with waf_configuration enabled (Prevention mode) or attach a WAF policy.")
def _az_agw(a, r, ctx):
    sku = str(get(a, "sku.tier", ""))
    waf = get(a, "waf_configuration") or {}
    if absent(a.get("firewall_policy_id")) and (not sku.startswith("WAF") or false(waf.get("enabled"))):
        return f"sku tier {sku or 'not WAF'}" + (", waf_configuration disabled" if false(waf.get("enabled")) else "")


@rule("NM-IAC-120", "network", "medium", "Classic load balancer listens on plain HTTP or has no access logs", ["aws_elb"],
      "Use HTTPS/SSL listeners with an ACM certificate and enable access_logs (or move to an Application Load Balancer).", cwe="CWE-319")
def _aws_elb(a, r, ctx):
    bad = [f"{l.get('lb_protocol')} listener on {l.get('lb_port')}" for l in blocks(a, "listener") if str(l.get("lb_protocol", "")).lower() in ("http", "tcp")]
    if not true(get(a, "access_logs.enabled")) and not blocks(a, "access_logs"):
        bad.append("no access logs")
    return ", ".join(bad) or None


@rule("NM-IAC-100", "network", "low", "Security group allows all outbound traffic to the internet", ["aws_security_group"],
      "Limit egress to the destinations and ports the workload needs (data exfiltration and command-and-control).")
def _aws_egress(a, r, ctx):
    for e in blocks(a, "egress"):
        if open_cidr(as_list(e.get("cidr_blocks")) + as_list(e.get("ipv6_cidr_blocks"))) and ports(e.get("from_port"), e.get("to_port"), e.get("protocol")) == "all":
            return {"evidence": "egress to 0.0.0.0/0 on all ports", "line": e.get("__line__")}


# ------------------------------------------------------------------------------------------ Google Cloud
@rule("NM-IAC-141", "network", "high", "Firewall rule allows the internet to reach administration or data ports", ["google_compute_firewall"],
      "Restrict source_ranges to known ranges or Identity-Aware Proxy (35.235.240.0/20).", "CIS Google Cloud Platform Foundation 3.6-3.7")
def _gcp_fw(a, r, ctx):
    if str(a.get("direction", "INGRESS")) != "INGRESS" or true(a.get("disabled")) or not open_cidr(a.get("source_ranges")):
        return None
    worst, ev = None, []
    for al in blocks(a, "allow"):
        proto = str(al.get("protocol", ""))
        ps = "all" if proto == "all" or (proto in ("tcp", "udp") and al.get("ports") is None) else range_ports(al.get("ports"))
        if ps:
            ev.append(describe(ps))
            sev = exposure_sev(ps)
            worst = sev if worst != "critical" else worst
    if ev:
        return {"evidence": "ingress from 0.0.0.0/0 to " + "; ".join(ev), "severity": worst}


@rule("NM-IAC-142", "network", "medium", "VM has a public IP address", ["google_compute_instance", "google_compute_instance_template"],
      "Remove access_config and use Cloud NAT and Identity-Aware Proxy for administration.", "CIS Google Cloud Platform Foundation 4.9")
def _gcp_pubip(a, r, ctx):
    for ni in blocks(a, "network_interface"):
        if blocks(ni, "access_config"):
            return {"evidence": "network_interface has access_config", "line": ni.get("__line__")}


@rule("NM-IAC-143", "network", "medium", "VM can forward IP packets", ["google_compute_instance", "google_compute_instance_template"],
      "Set can_ip_forward = false unless the VM is a router or NAT appliance.", "CIS Google Cloud Platform Foundation 4.6")
def _gcp_fwd(a, r, ctx):
    if true(a.get("can_ip_forward")):
        return "can_ip_forward = true"


@rule("NM-IAC-144", "network", "critical", "Database accepts connections from the internet", ["google_sql_database_instance"],
      "Remove 0.0.0.0/0 from authorized_networks; use private IP or the Cloud SQL Auth Proxy.", "CIS Google Cloud Platform Foundation 6.5")
def _gcp_sql_open(a, r, ctx):
    ipc = get(a, "settings.ip_configuration") or {}
    for n in blocks(ipc, "authorized_networks"):
        if open_cidr(n.get("value")):
            return {"evidence": f"authorized network {n.get('value')}", "line": n.get("__line__")}


@rule("NM-IAC-145", "network", "medium", "Database has a public IP and does not require TLS", ["google_sql_database_instance"],
      "Set ip_configuration.ipv4_enabled = false (private IP) and ssl_mode = ENCRYPTED_ONLY (or require_ssl = true).",
      "CIS Google Cloud Platform Foundation 6.4", "CWE-319")
def _gcp_sql_tls(a, r, ctx):
    ipc = get(a, "settings.ip_configuration") or {}
    bad = []
    if not false(ipc.get("ipv4_enabled")):
        bad.append("public IP")
    if not (true(ipc.get("require_ssl")) or str(ipc.get("ssl_mode")) in ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")):
        bad.append("TLS not required")
    return ", ".join(bad) if "TLS not required" in bad else None


@rule("NM-IAC-146", "network", "high", "GKE control plane is reachable from the whole internet", ["google_container_cluster"],
      "Add master_authorized_networks_config with known ranges, or a private endpoint.", "CIS Google Kubernetes Engine 5.6.3")
def _gcp_gke_ep(a, r, ctx):
    if true(get(a, "private_cluster_config.enable_private_endpoint")):
        return None
    m = blocks(a, "master_authorized_networks_config")
    if not m:
        return "no master_authorized_networks_config"
    for c in blocks(m[0], "cidr_blocks"):
        if open_cidr(c.get("cidr_block")):
            return "authorised network 0.0.0.0/0"


@rule("NM-IAC-147", "network", "medium", "GKE cluster does not enforce network policy", ["google_container_cluster"],
      "Enable network_policy (or Dataplane V2: datapath_provider = ADVANCED_DATAPATH).", "CIS Google Kubernetes Engine 5.6.7")
def _gcp_gke_np(a, r, ctx):
    if str(a.get("datapath_provider")) == "ADVANCED_DATAPATH" or true(get(a, "network_policy.enabled")):
        return None
    return "network policy not enabled"


@rule("NM-IAC-148", "network", "medium", "GKE nodes have public IP addresses", ["google_container_cluster"],
      "Set private_cluster_config.enable_private_nodes = true.", "CIS Google Kubernetes Engine 5.6.5")
def _gcp_gke_private(a, r, ctx):
    if not true(get(a, "private_cluster_config.enable_private_nodes")) and not true(get(a, "enable_autopilot")):
        return "enable_private_nodes is not true"


@rule("NM-IAC-149", "network", "medium", "SSL policy allows TLS versions below 1.2", ["google_compute_ssl_policy"],
      "Set min_tls_version = TLS_1_2 and profile MODERN or RESTRICTED.", "CIS Google Cloud Platform Foundation 3.9", "CWE-326")
def _gcp_ssl(a, r, ctx):
    v = a.get("min_tls_version", "TLS_1_0")
    if str(v) in ("TLS_1_0", "TLS_1_1"):
        return f"min_tls_version = {v}"


@rule("NM-IAC-150", "network", "medium", "Function or service can be invoked by anyone",
      ["google_cloudfunctions_function_iam_member", "google_cloudfunctions_function_iam_binding", "google_cloud_run_service_iam_member",
       "google_cloud_run_service_iam_binding", "google_cloud_run_v2_service_iam_member", "google_cloudfunctions2_function_iam_member"],
      "Remove allUsers from the invoker role unless the endpoint is meant to be public, and authenticate callers.", cwe="CWE-306")
def _gcp_invoker(a, r, ctx):
    members = as_list(a.get("member")) + as_list(a.get("members"))
    if any(str(m) in ("allUsers", "allAuthenticatedUsers") for m in members):
        return f"{a.get('role')} granted to {', '.join(str(m) for m in members if str(m).startswith('all'))}"


@rule("NM-IAC-241", "data", "critical", "Storage bucket or dataset is readable by anyone",
      ["google_storage_bucket_iam_member", "google_storage_bucket_iam_binding", "google_storage_bucket_access_control",
       "google_storage_default_object_access_control", "google_bigquery_dataset_iam_member", "google_bigquery_dataset_iam_binding",
       "google_bigquery_dataset"],
      "Remove allUsers / allAuthenticatedUsers; grant access to specific identities.", "CIS Google Cloud Platform Foundation 5.1", "CWE-732")
def _gcp_public(a, r, ctx):
    members = as_list(a.get("member")) + as_list(a.get("members")) + as_list(a.get("entity"))
    for ac in blocks(a, "access"):
        members += as_list(ac.get("special_group")) + as_list(ac.get("iam_member"))
    hit = [str(m) for m in members if str(m) in ("allUsers", "allAuthenticatedUsers")]
    if hit:
        return f"granted to {', '.join(hit)}"


@rule("NM-IAC-242", "data", "medium", "Bucket does not use uniform bucket-level access", ["google_storage_bucket"],
      "Set uniform_bucket_level_access = true and public_access_prevention = enforced.", "CIS Google Cloud Platform Foundation 5.2")
def _gcp_ubla(a, r, ctx):
    bad = []
    if not true(a.get("uniform_bucket_level_access")):
        bad.append("uniform_bucket_level_access is not true")
    if str(a.get("public_access_prevention", "inherited")) != "enforced":
        bad.append("public_access_prevention is not enforced")
    return ", ".join(bad) if "uniform_bucket_level_access is not true" in bad else None


@rule("NM-IAC-243", "data", "medium", "Database automated backups are disabled", ["google_sql_database_instance"],
      "Set settings.backup_configuration.enabled = true (with point-in-time recovery).", "CIS Google Cloud Platform Foundation 6.7")
def _gcp_sql_backup(a, r, ctx):
    if not true(get(a, "settings.backup_configuration.enabled")):
        return "backup_configuration not enabled"


@rule("NM-IAC-244", "data", "medium", "Encryption key is not rotated at least every 90 days", ["google_kms_crypto_key"],
      "Set rotation_period = 7776000s or shorter.", "CIS Google Cloud Platform Foundation 1.10", "CWE-320")
def _gcp_kms(a, r, ctx):
    v = a.get("rotation_period")
    if v is None:
        return "no rotation_period"
    m = re.match(r"^(\d+)(?:\.\d+)?s$", str(v))
    if m and int(m.group(1)) > 7776000:
        return f"rotation_period = {v}"


@rule("NM-IAC-341", "compute", "high", "VM uses the default service account with full API access",
      ["google_compute_instance", "google_compute_instance_template"],
      "Run VMs as a dedicated service account with only the roles they need; avoid the cloud-platform scope.",
      "CIS Google Cloud Platform Foundation 4.1-4.2", "CWE-250")
def _gcp_sa(a, r, ctx):
    for sa in blocks(a, "service_account"):
        email = str(sa.get("email", ""))
        scopes = [str(s) for s in as_list(sa.get("scopes"))]
        if (not email or email.endswith("-compute@developer.gserviceaccount.com") or email == "default") and \
                any(s in ("cloud-platform", "https://www.googleapis.com/auth/cloud-platform") for s in scopes):
            return "default compute service account with the cloud-platform scope"


@rule("NM-IAC-342", "compute", "medium", "Interactive serial console is enabled", ["google_compute_instance", "google_compute_instance_template"],
      "Set metadata serial-port-enable = false.", "CIS Google Cloud Platform Foundation 4.5")
def _gcp_serial(a, r, ctx):
    md = a.get("metadata") or {}
    if isinstance(md, dict) and str(md.get("serial-port-enable", "")).lower() in ("true", "1"):
        return "serial-port-enable = true"


@rule("NM-IAC-343", "compute", "low", "Shielded VM secure boot is not enabled", ["google_compute_instance", "google_compute_instance_template"],
      "Set shielded_instance_config.enable_secure_boot = true.", "CIS Google Cloud Platform Foundation 4.8")
def _gcp_shield(a, r, ctx):
    if not true(get(a, "shielded_instance_config.enable_secure_boot")):
        return "enable_secure_boot is not true"


@rule("NM-IAC-344", "compute", "low", "GKE node auto-upgrade or auto-repair is off", ["google_container_node_pool"],
      "Set management.auto_upgrade and auto_repair to true.", "CIS Google Kubernetes Engine 5.5.2-5.5.3", "CWE-1104")
def _gcp_np_mgmt(a, r, ctx):
    m = get(a, "management") or {}
    if false(m.get("auto_upgrade")) or false(m.get("auto_repair")):
        return "auto_upgrade or auto_repair = false"


@rule("NM-IAC-345", "compute", "medium", "GKE cluster has no Shielded GKE nodes or Workload Identity", ["google_container_cluster"],
      "Set enable_shielded_nodes = true and configure workload_identity_config.", "CIS Google Kubernetes Engine 5.2.1, 5.5.5")
def _gcp_gke_wi(a, r, ctx):
    bad = []
    if false(a.get("enable_shielded_nodes")):
        bad.append("shielded nodes disabled")
    if not blocks(a, "workload_identity_config") and not true(a.get("enable_autopilot")):
        bad.append("no Workload Identity")
    return ", ".join(bad) or None


@rule("NM-IAC-441", "identity", "high", "GKE uses legacy authorisation or basic authentication", ["google_container_cluster"],
      "Set enable_legacy_abac = false, remove master_auth username/password and disable client certificates.", "CIS Google Kubernetes Engine 5.8")
def _gcp_gke_auth(a, r, ctx):
    bad = []
    if true(a.get("enable_legacy_abac")):
        bad.append("legacy ABAC enabled")
    ma = get(a, "master_auth") or {}
    if is_lit(ma.get("username")) and ma.get("username"):
        bad.append("basic authentication")
    if true(get(ma, "client_certificate_config.issue_client_certificate")):
        bad.append("client certificates issued")
    return ", ".join(bad) or None


@rule("NM-IAC-442", "identity", "medium", "Primitive Owner or Editor role granted at project level",
      ["google_project_iam_member", "google_project_iam_binding", "google_organization_iam_member", "google_folder_iam_member"],
      "Grant predefined or custom roles with only the permissions needed.", "CIS Google Cloud Platform Foundation 1.5")
def _gcp_primitive(a, r, ctx):
    role = str(a.get("role", ""))
    members = [str(m) for m in as_list(a.get("member")) + as_list(a.get("members"))]
    if any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
        return {"evidence": f"{role} granted to {', '.join(members)}", "severity": "critical"}
    if role in ("roles/owner", "roles/editor"):
        return f"{role} granted to {', '.join(members)[:120]}"
    if role in ("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"):
        return {"evidence": f"{role} at project level lets members act as every service account", "severity": "medium"}


@rule("NM-IAC-443", "identity", "medium", "User-managed service account key created", ["google_service_account_key"],
      "Use Workload Identity Federation or attached service accounts instead of exported keys.", "CIS Google Cloud Platform Foundation 1.4", "CWE-798")
def _gcp_sakey(a, r, ctx):
    return "google_service_account_key creates a long-lived credential"


@rule("NM-IAC-541", "logging", "low", "Subnet has no VPC flow logs", ["google_compute_subnetwork"],
      "Add log_config (aggregation_interval and flow_sampling).", "CIS Google Cloud Platform Foundation 3.8")
def _gcp_flow(a, r, ctx):
    if not blocks(a, "log_config") and str(a.get("purpose", "PRIVATE")) == "PRIVATE":
        return "no log_config"


@rule("NM-IAC-542", "logging", "medium", "GKE logging or monitoring is disabled", ["google_container_cluster"],
      "Leave logging_service / monitoring_service at the Cloud Logging and Monitoring defaults.", "CIS Google Kubernetes Engine 5.7")
def _gcp_gke_log(a, r, ctx):
    if str(a.get("logging_service")) == "none" or str(a.get("monitoring_service")) == "none":
        return "logging or monitoring service = none"


@rule("NM-IAC-543", "logging", "low", "DNS zone has DNSSEC turned off", ["google_dns_managed_zone"],
      "Set dnssec_config.state = on for public zones.", "CIS Google Cloud Platform Foundation 3.3", "CWE-350")
def _gcp_dnssec(a, r, ctx):
    if str(a.get("visibility", "public")) == "public" and str(get(a, "dnssec_config.state", "off")) != "on":
        return "DNSSEC not on"


# ------------------------------------------------------------------------------------------ CloudFormation and ARM/Bicep
# Each maps the template's properties to the Terraform attribute names of the equivalent check.
def _cfn_sg(p):
    rules = []
    for x in as_list(p.get("SecurityGroupIngress")):
        if isinstance(x, dict):
            rules.append({"cidr_blocks": [x.get("CidrIp"), x.get("CidrIpv6")], "from_port": x.get("FromPort"), "to_port": x.get("ToPort"),
                          "protocol": x.get("IpProtocol")})
    return {"ingress": rules}


CFN = {
    "AWS::EC2::SecurityGroup": ("aws_security_group", _cfn_sg),
    "AWS::EC2::SecurityGroupIngress": ("aws_security_group_rule", lambda p: {"type": "ingress", "cidr_blocks": [p.get("CidrIp"), p.get("CidrIpv6")],
                                                                            "from_port": p.get("FromPort"), "to_port": p.get("ToPort"), "protocol": p.get("IpProtocol")}),
    "AWS::S3::Bucket": ("aws_s3_bucket", lambda p: {"acl": {"PublicRead": "public-read", "PublicReadWrite": "public-read-write",
                                                            "AuthenticatedRead": "authenticated-read"}.get(str(p.get("AccessControl")), None),
                                                    "versioning": [{"enabled": (p.get("VersioningConfiguration") or {}).get("Status") == "Enabled"}],
                                                    "logging": [p["LoggingConfiguration"]] if p.get("LoggingConfiguration") else [],
                                                    "__pab__": p.get("PublicAccessBlockConfiguration")}),
    "AWS::S3::BucketPolicy": ("aws_s3_bucket_policy", lambda p: {"policy": p.get("PolicyDocument")}),
    "AWS::RDS::DBInstance": ("aws_db_instance", lambda p: {"publicly_accessible": p.get("PubliclyAccessible"),
                                                           "storage_encrypted": p.get("StorageEncrypted"), "backup_retention_period": p.get("BackupRetentionPeriod"),
                                                           "deletion_protection": p.get("DeletionProtection"), "password": p.get("MasterUserPassword"),
                                                           "auto_minor_version_upgrade": p.get("AutoMinorVersionUpgrade")}),
    "AWS::RDS::DBCluster": ("aws_rds_cluster", lambda p: {"storage_encrypted": p.get("StorageEncrypted"), "deletion_protection": p.get("DeletionProtection"),
                                                          "backup_retention_period": p.get("BackupRetentionPeriod"), "engine_mode": p.get("EngineMode"),
                                                          "master_password": p.get("MasterUserPassword")}),
    "AWS::EC2::Volume": ("aws_ebs_volume", lambda p: {"encrypted": p.get("Encrypted")}),
    "AWS::EC2::Instance": ("aws_instance", lambda p: {"associate_public_ip_address": next((n.get("AssociatePublicIpAddress") for n in as_list(p.get("NetworkInterfaces")) if isinstance(n, dict)), None),
                                                      "block_device_mappings": [{"ebs": [m.get("Ebs") or {}]} for m in as_list(p.get("BlockDeviceMappings")) if isinstance(m, dict)]}),
    "AWS::EC2::LaunchTemplate": ("aws_launch_template", lambda p: {"metadata_options": [{"http_tokens": ((p.get("LaunchTemplateData") or {}).get("MetadataOptions") or {}).get("HttpTokens"),
                                                                                         "http_endpoint": ((p.get("LaunchTemplateData") or {}).get("MetadataOptions") or {}).get("HttpEndpoint", "enabled")}]}),
    "AWS::EFS::FileSystem": ("aws_efs_file_system", lambda p: {"encrypted": p.get("Encrypted")}),
    "AWS::IAM::Policy": ("aws_iam_policy", lambda p: {"policy": p.get("PolicyDocument")}),
    "AWS::IAM::ManagedPolicy": ("aws_iam_policy", lambda p: {"policy": p.get("PolicyDocument")}),
    "AWS::IAM::Role": ("aws_iam_role", lambda p: {"assume_role_policy": p.get("AssumeRolePolicyDocument"), "__inline__": p.get("Policies")}),
    "AWS::IAM::AccessKey": ("aws_iam_access_key", lambda p: {}),
    "AWS::CloudTrail::Trail": ("aws_cloudtrail", lambda p: {"is_multi_region_trail": p.get("IsMultiRegionTrail"), "enable_log_file_validation": p.get("EnableLogFileValidation"),
                                                            "kms_key_id": p.get("KMSKeyId"), "enable_logging": p.get("IsLogging")}),
    "AWS::KMS::Key": ("aws_kms_key", lambda p: {"enable_key_rotation": p.get("EnableKeyRotation"), "customer_master_key_spec": p.get("KeySpec", "SYMMETRIC_DEFAULT")}),
    "AWS::EKS::Cluster": ("aws_eks_cluster", lambda p: {"vpc_config": [{"endpoint_public_access": (p.get("ResourcesVpcConfig") or {}).get("EndpointPublicAccess", True),
                                                                         "public_access_cidrs": (p.get("ResourcesVpcConfig") or {}).get("PublicAccessCidrs")}],
                                                        "encryption_config": as_list(p.get("EncryptionConfig")),
                                                        "enabled_cluster_log_types": [t.get("Type") for t in ((p.get("Logging") or {}).get("ClusterLogging") or {}).get("EnabledTypes") or []]}),
    "AWS::Lambda::Url": ("aws_lambda_function_url", lambda p: {"authorization_type": p.get("AuthType")}),
    "AWS::Lambda::Permission": ("aws_lambda_permission", lambda p: {"principal": p.get("Principal")}),
    "AWS::ElastiCache::ReplicationGroup": ("aws_elasticache_replication_group", lambda p: {"at_rest_encryption_enabled": p.get("AtRestEncryptionEnabled"),
                                                                                           "transit_encryption_enabled": p.get("TransitEncryptionEnabled"), "auth_token": p.get("AuthToken")}),
    "AWS::Kinesis::Stream": ("aws_kinesis_stream", lambda p: {"encryption_type": "KMS" if p.get("StreamEncryption") else "NONE"}),
    "AWS::SNS::Topic": ("aws_sns_topic", lambda p: {"kms_master_key_id": p.get("KmsMasterKeyId")}),
    "AWS::SQS::Queue": ("aws_sqs_queue", lambda p: {"sqs_managed_sse_enabled": p.get("SqsManagedSseEnabled"), "kms_master_key_id": p.get("KmsMasterKeyId")}),
    "AWS::ApiGateway::Method": ("aws_api_gateway_method", lambda p: {"authorization": p.get("AuthorizationType"), "http_method": p.get("HttpMethod"),
                                                                     "api_key_required": p.get("ApiKeyRequired")}),
    "AWS::ECR::Repository": ("aws_ecr_repository", lambda p: {"image_tag_mutability": p.get("ImageTagMutability", "MUTABLE"),
                                                              "image_scanning_configuration": [{"scan_on_push": (p.get("ImageScanningConfiguration") or {}).get("ScanOnPush")}]}),
    "AWS::DynamoDB::Table": ("aws_dynamodb_table", lambda p: {"point_in_time_recovery": [{"enabled": (p.get("PointInTimeRecoverySpecification") or {}).get("PointInTimeRecoveryEnabled")}]}),
    "AWS::GuardDuty::Detector": ("aws_guardduty_detector", lambda p: {"enable": p.get("Enable")}),
    "AWS::Redshift::Cluster": ("aws_redshift_cluster", lambda p: {"publicly_accessible": p.get("PubliclyAccessible", True), "encrypted": p.get("Encrypted"),
                                                                  "master_password": p.get("MasterUserPassword")}),
    "AWS::OpenSearchService::Domain": ("aws_opensearch_domain", lambda p: {"vpc_options": [p["VPCOptions"]] if p.get("VPCOptions") else [],
                                                                           "encrypt_at_rest": [{"enabled": (p.get("EncryptionAtRestOptions") or {}).get("Enabled")}],
                                                                           "node_to_node_encryption": [{"enabled": (p.get("NodeToNodeEncryptionOptions") or {}).get("Enabled")}],
                                                                           "domain_endpoint_options": [{"enforce_https": (p.get("DomainEndpointOptions") or {}).get("EnforceHTTPS")}],
                                                                           "log_publishing_options": [1] if p.get("LogPublishingOptions") else []}),
    "AWS::SageMaker::NotebookInstance": ("aws_sagemaker_notebook_instance", lambda p: {"direct_internet_access": p.get("DirectInternetAccess", "Enabled"),
                                                                                       "root_access": p.get("RootAccess", "Enabled")}),
    "AWS::ElasticLoadBalancingV2::Listener": ("aws_lb_listener", lambda p: {"protocol": p.get("Protocol"), "ssl_policy": p.get("SslPolicy"),
                                                                            "default_action": [{"type": str(x.get("Type", "")).replace("redirect", "redirect")} for x in as_list(p.get("DefaultActions")) if isinstance(x, dict)]}),
    "AWS::SSM::Parameter": ("aws_ssm_parameter", lambda p: {"type": p.get("Type"), "name": p.get("Name")}),
}


def _arm_props(a):
    return a.get("properties") if isinstance(a.get("properties"), dict) else {}


def _arm_nsg(a):
    rules = []
    for x in as_list(_arm_props(a).get("securityRules")) + ([{"properties": _arm_props(a)}] if "direction" in _arm_props(a) else []):
        p = (x or {}).get("properties") or {}
        rules.append({"direction": p.get("direction"), "access": p.get("access"), "source_address_prefix": p.get("sourceAddressPrefix"),
                      "source_address_prefixes": p.get("sourceAddressPrefixes"), "destination_port_range": p.get("destinationPortRange"),
                      "destination_port_ranges": p.get("destinationPortRanges")})
    return {"security_rule": rules}


ARM = {
    "microsoft.network/networksecuritygroups": ("azurerm_network_security_group", _arm_nsg),
    "microsoft.network/networksecuritygroups/securityrules": ("azurerm_network_security_group", _arm_nsg),
    "microsoft.storage/storageaccounts": ("azurerm_storage_account", lambda a: {
        "allow_nested_items_to_be_public": _arm_props(a).get("allowBlobPublicAccess"), "min_tls_version": _arm_props(a).get("minimumTlsVersion"),
        "enable_https_traffic_only": _arm_props(a).get("supportsHttpsTrafficOnly"),
        "public_network_access_enabled": {"Enabled": True, "Disabled": False}.get(str(_arm_props(a).get("publicNetworkAccess")), None),
        "network_rules": [{"default_action": (_arm_props(a).get("networkAcls") or {}).get("defaultAction")}] if _arm_props(a).get("networkAcls") else None,
        "shared_access_key_enabled": _arm_props(a).get("allowSharedKeyAccess")}),
    "microsoft.storage/storageaccounts/blobservices/containers": ("azurerm_storage_container", lambda a: {
        "container_access_type": {"Blob": "blob", "Container": "container"}.get(str(_arm_props(a).get("publicAccess")), None)}),
    "microsoft.keyvault/vaults": ("azurerm_key_vault", lambda a: {
        "purge_protection_enabled": _arm_props(a).get("enablePurgeProtection"),
        "network_acls": [{"default_action": (_arm_props(a).get("networkAcls") or {}).get("defaultAction")}] if _arm_props(a).get("networkAcls") else None,
        "public_network_access_enabled": {"Enabled": True, "Disabled": False}.get(str(_arm_props(a).get("publicNetworkAccess")), None)}),
    "microsoft.sql/servers/firewallrules": ("azurerm_mssql_firewall_rule", lambda a: {
        "start_ip_address": _arm_props(a).get("startIpAddress"), "end_ip_address": _arm_props(a).get("endIpAddress")}),
    "microsoft.dbforpostgresql/servers/firewallrules": ("azurerm_postgresql_firewall_rule", lambda a: {
        "start_ip_address": _arm_props(a).get("startIpAddress"), "end_ip_address": _arm_props(a).get("endIpAddress")}),
    "microsoft.dbformysql/servers/firewallrules": ("azurerm_mysql_firewall_rule", lambda a: {
        "start_ip_address": _arm_props(a).get("startIpAddress"), "end_ip_address": _arm_props(a).get("endIpAddress")}),
    "microsoft.sql/servers": ("azurerm_mssql_server", lambda a: {
        "minimum_tls_version": _arm_props(a).get("minimalTlsVersion"),
        "public_network_access_enabled": {"Enabled": True, "Disabled": False}.get(str(_arm_props(a).get("publicNetworkAccess")), None),
        "administrator_login_password": _arm_props(a).get("administratorLoginPassword"), "extended_auditing_policy": [1]}),
    "microsoft.dbforpostgresql/servers": ("azurerm_postgresql_server", lambda a: {
        "ssl_enforcement_enabled": {"Enabled": True, "Disabled": False}.get(str(_arm_props(a).get("sslEnforcement")), None),
        "ssl_minimal_tls_version_enforced": _arm_props(a).get("minimalTlsVersion")}),
    "microsoft.dbformysql/servers": ("azurerm_mysql_server", lambda a: {
        "ssl_enforcement_enabled": {"Enabled": True, "Disabled": False}.get(str(_arm_props(a).get("sslEnforcement")), None),
        "ssl_minimal_tls_version_enforced": _arm_props(a).get("minimalTlsVersion")}),
    "microsoft.cache/redis": ("azurerm_redis_cache", lambda a: {
        "enable_non_ssl_port": _arm_props(a).get("enableNonSslPort"), "minimum_tls_version": _arm_props(a).get("minimumTlsVersion")}),
    "microsoft.web/sites": ("azurerm_linux_web_app", lambda a: {
        "https_only": _arm_props(a).get("httpsOnly"),
        "site_config": [{"minimum_tls_version": (_arm_props(a).get("siteConfig") or {}).get("minTlsVersion"),
                         "ftps_state": (_arm_props(a).get("siteConfig") or {}).get("ftpsState"),
                         "remote_debugging_enabled": (_arm_props(a).get("siteConfig") or {}).get("remoteDebuggingEnabled")}]}),
    "microsoft.containerregistry/registries": ("azurerm_container_registry", lambda a: {
        "admin_enabled": _arm_props(a).get("adminUserEnabled"), "anonymous_pull_enabled": _arm_props(a).get("anonymousPullEnabled"),
        "public_network_access_enabled": {"Enabled": True, "Disabled": False}.get(str(_arm_props(a).get("publicNetworkAccess")), None)}),
    "microsoft.containerservice/managedclusters": ("azurerm_kubernetes_cluster", lambda a: {
        "role_based_access_control_enabled": _arm_props(a).get("enableRBAC"),
        "private_cluster_enabled": (_arm_props(a).get("apiServerAccessProfile") or {}).get("enablePrivateCluster"),
        "api_server_authorized_ip_ranges": (_arm_props(a).get("apiServerAccessProfile") or {}).get("authorizedIPRanges"),
        "network_profile": [{"network_policy": (_arm_props(a).get("networkProfile") or {}).get("networkPolicy")}],
        "local_account_disabled": _arm_props(a).get("disableLocalAccounts"),
        "oms_agent": [1] if ((_arm_props(a).get("addonProfiles") or {}).get("omsagent") or {}).get("enabled") else []}),
    "microsoft.compute/virtualmachines": ("azurerm_linux_virtual_machine", lambda a: {
        "disable_password_authentication": (((_arm_props(a).get("osProfile") or {}).get("linuxConfiguration") or {}).get("disablePasswordAuthentication")),
        "encryption_at_host_enabled": (_arm_props(a).get("securityProfile") or {}).get("encryptionAtHost", True if not (_arm_props(a).get("osProfile") or {}).get("linuxConfiguration") else None),
        "admin_password": (_arm_props(a).get("osProfile") or {}).get("adminPassword")}),
    "microsoft.authorization/roledefinitions": ("azurerm_role_definition", lambda a: {
        "permissions": [{"actions": p.get("actions")} for p in as_list(_arm_props(a).get("permissions")) if isinstance(p, dict)]}),
    "microsoft.documentdb/databaseaccounts": ("azurerm_cosmosdb_account", lambda a: {
        "public_network_access_enabled": {"Enabled": True, "Disabled": False}.get(str(_arm_props(a).get("publicNetworkAccess")), None),
        "network_rules": [{"default_action": "Deny"}] if _arm_props(a).get("isVirtualNetworkFilterEnabled") else None,
        "local_authentication_disabled": _arm_props(a).get("disableLocalAuth")}),
}


# ------------------------------------------------------------------------------------------ Kubernetes objects
def k8s_findings(root: str, repo: str) -> list[dict]:
    """Network exposure, ingress TLS, RBAC wildcards, anonymous bindings, committed Secret objects and namespaces
    with workloads but no NetworkPolicy (pod hardening is in iac_checks)."""
    import os

    import yaml
    out, workloads, policies = [], set(), set()
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules", "vendor", ".terraform")]
        for fn in files:
            if not fn.endswith((".yaml", ".yml")):
                continue
            p = os.path.join(d, fn)
            rel = os.path.relpath(p, root).replace("\\", "/")
            try:
                text = open(p, encoding="utf-8", errors="replace").read()
                if "apiVersion" not in text or "{{" in text:
                    continue
                docs = list(yaml.safe_load_all(text))
            except Exception:  # noqa: BLE001 - not plain YAML (templates)
                continue
            for doc in docs:
                if not isinstance(doc, dict) or "kind" not in doc:
                    continue
                kind, md = doc.get("kind"), doc.get("metadata") or {}
                name, ns = md.get("name", ""), md.get("namespace", "default")
                m = re.search(rf"(?m)^\s*name:\s*['\"]?{re.escape(str(name))}['\"]?\s*$", text) if name else None
                line = text.count("\n", 0, m.start()) + 1 if m else 1

                def f(rid, domain, sev, title, ev, fix, cwe):
                    out.append(_finding({"id": rid, "domain": domain, "severity": sev, "title": title, "fix": fix, "ref": "", "cwe": cwe},
                                        {"file": rel, "line": line, "type": f"kubernetes {kind}", "name": name}, ev, repo))
                spec = doc.get("spec") or {}
                if kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob", "ReplicaSet"):
                    workloads.add(ns)
                if kind == "NetworkPolicy":
                    policies.add(ns)
                if kind == "Service" and spec.get("type") in ("LoadBalancer",) and not spec.get("loadBalancerSourceRanges"):
                    internal = any("internal" in str(k).lower() and str(v).lower() in ("true", "internal") for k, v in (md.get("annotations") or {}).items())
                    if not internal:
                        f("NM-IAC-151", "network", "medium", f"Service '{name}' is exposed to the internet by a load balancer",
                          "type LoadBalancer without loadBalancerSourceRanges or an internal annotation",
                          "Restrict loadBalancerSourceRanges, make the load balancer internal, or publish through an Ingress with authentication.", "CWE-284")
                if kind == "Ingress" and not spec.get("tls"):
                    f("NM-IAC-152", "network", "medium", f"Ingress '{name}' serves plain HTTP (no TLS section)", "spec.tls missing",
                      "Add spec.tls with a certificate (for example from cert-manager) and redirect HTTP to HTTPS.", "CWE-319")
                if kind in ("ClusterRole", "Role"):
                    for r in doc.get("rules") or []:
                        if not isinstance(r, dict):
                            continue
                        if "*" in (r.get("verbs") or []) and ("*" in (r.get("resources") or []) or "*" in (r.get("apiGroups") or [])):
                            f("NM-IAC-451", "identity", "high", f"{kind} '{name}' grants every verb on every resource", "verbs [*] on resources [*]",
                              "List only the API groups, resources and verbs the subject needs.", "CWE-269")
                            break
                        if "secrets" in (r.get("resources") or []) and {"get", "list", "watch", "*"} & set(r.get("verbs") or []):
                            f("NM-IAC-452", "identity", "medium", f"{kind} '{name}' can read Secrets", f"verbs {r.get('verbs')} on secrets",
                              "Grant Secret access only to the controllers that need it, scoped to named Secrets (resourceNames).", "CWE-269")
                            break
                        if {"escalate", "bind", "impersonate"} & set(r.get("verbs") or []):
                            f("NM-IAC-453", "identity", "high", f"{kind} '{name}' can escalate privileges", f"verbs {r.get('verbs')}",
                              "Remove escalate, bind and impersonate verbs.", "CWE-269")
                            break
                if kind in ("ClusterRoleBinding", "RoleBinding"):
                    ref = (doc.get("roleRef") or {}).get("name")
                    for s in doc.get("subjects") or []:
                        sname = str((s or {}).get("name", ""))
                        if sname in ("system:anonymous", "system:unauthenticated", "system:authenticated"):
                            f("NM-IAC-454", "identity", "critical", f"{kind} '{name}' grants {ref} to {sname}", f"subject {sname}",
                              "Bind roles only to named users, groups or service accounts.", "CWE-284")
                        elif ref == "cluster-admin" and kind == "ClusterRoleBinding" and not sname.startswith("system:"):
                            f("NM-IAC-455", "identity", "high", f"cluster-admin granted to {s.get('kind')} '{sname}'", "roleRef cluster-admin",
                              "Grant a narrower role; keep cluster-admin for break-glass accounts.", "CWE-269")
                if kind == "Secret" and (doc.get("data") or doc.get("stringData")) and str(doc.get("type", "Opaque")) != "kubernetes.io/service-account-token":
                    vals = list((doc.get("stringData") or {}).values()) + list((doc.get("data") or {}).values())
                    if any(v and "${" not in str(v) and "{{" not in str(v) and str(v) not in ("", "changeme") for v in vals):
                        f("NM-IAC-251", "data", "high", f"Secret '{name}' is committed with its values",
                          f"{len(vals)} value(s) in data/stringData", "Keep secret values out of Git: use External Secrets, Sealed Secrets or SOPS.", "CWE-312")
                if kind == "ConfigMap":
                    for k, v in (doc.get("data") or {}).items():
                        if re.search(r"(?i)(password|secret|token|api[_-]?key)$", str(k)) and v and len(str(v)) >= 6 and "${" not in str(v):
                            f("NM-IAC-252", "data", "high", f"ConfigMap '{name}' holds a credential ({k})", f"{k} has a literal value",
                              "Move credentials to a Secret managed outside Git.", "CWE-312")
                            break
    # only where the repository uses NetworkPolicies (so a namespace without one is a gap, not a partial manifest set)
    for ns in sorted(workloads - policies) if policies else []:
        if True:
            out.append(_finding({"id": "NM-IAC-153", "domain": "network", "severity": "low",
                                 "title": f"Namespace '{ns}' has workloads but no NetworkPolicy in this repository",
                                 "fix": "Add a default-deny NetworkPolicy and allow only the traffic each workload needs.", "ref": "CIS Kubernetes 5.3.2",
                                 "cwe": "CWE-284"}, {"file": "(kubernetes manifests)", "line": None, "type": "namespace", "name": ns},
                                "no NetworkPolicy objects for this namespace", repo))
            if len(out) > 400:
                break
    return out


# ------------------------------------------------------------------------------------------ run
def _finding(rule_, res, ev, repo):
    sev = ev.get("severity") if isinstance(ev, dict) else None
    evidence = ev.get("evidence") if isinstance(ev, dict) else str(ev)
    line = ev.get("line") if isinstance(ev, dict) and ev.get("line") else res.get("line")
    where = f"{res['type']}.{res['name']}" if res.get("name") else res["type"]
    return {"engine": "iac", "rule_id": rule_["id"], "domain": rule_["domain"], "category": DOMAINS[rule_["domain"]],
            "title": f"{rule_['title']} ({where})", "severity": sev or rule_["severity"], "cwe": rule_["cwe"],
            "repo": repo, "file": res["file"], "line": line, "resource": where, "evidence": evidence,
            "remediation": rule_["fix"], "benchmark": rule_["ref"] or None}


def scan(root: str, repo: str) -> list[dict]:
    res = parse_resources(root)
    for r in res:                                    # CloudFormation / ARM: map onto the Terraform attribute model
        if r["fmt"] == "cfn" and r["type"] in CFN:
            tf, conv = CFN[r["type"]]
            try:
                r["attrs"], r["tf_type"] = conv(r["attrs"]), tf
            except (AttributeError, TypeError):
                r["tf_type"] = None
            if r["type"] == "AWS::S3::Bucket":
                pab = r["attrs"].pop("__pab__", None)
                if isinstance(pab, dict):
                    res.append({"fmt": "cfn", "type": "AWS::S3::PAB", "tf_type": "aws_s3_bucket_public_access_block", "name": r["name"],
                                "file": r["file"], "line": r["line"], "attrs": {"bucket": f"aws_s3_bucket.{r['name']}.",
                                                                                 **{k: pab.get(v) for k, v in (("block_public_acls", "BlockPublicAcls"),
                                                                                                                ("block_public_policy", "BlockPublicPolicy"),
                                                                                                                ("ignore_public_acls", "IgnorePublicAcls"),
                                                                                                                ("restrict_public_buckets", "RestrictPublicBuckets"))}}})
            if r["type"] == "AWS::IAM::Role":
                for pol in as_list(r["attrs"].pop("__inline__", None)):
                    if isinstance(pol, dict):
                        res.append({"fmt": "cfn", "type": "AWS::IAM::Policy", "tf_type": "aws_iam_role_policy", "name": f"{r['name']}/{pol.get('PolicyName')}",
                                    "file": r["file"], "line": r["line"], "attrs": {"policy": pol.get("PolicyDocument")}})
        elif r["fmt"] == "arm" and r["type"] in ARM:
            tf, conv = ARM[r["type"]]
            try:
                r["attrs"], r["tf_type"] = conv(r["attrs"]), tf
            except (AttributeError, TypeError):
                r["tf_type"] = None
        elif r["fmt"] == "tf":
            r["tf_type"] = r["type"]
        else:
            r.setdefault("tf_type", None)
    by_type: dict = {}
    for r in res:
        if r.get("tf_type"):
            by_type.setdefault(r["tf_type"], []).append(r)
    ctx = {"by_type": by_type, "all": res}
    out = []
    for rule_ in RULES:
        for t in rule_["types"]:
            for r in by_type.get(t, []):
                if r.get("kind") == "data" and t != "aws_iam_policy_document":
                    continue
                try:
                    ev = rule_["check"](r["attrs"], {**r, "type": t}, ctx)
                except (AttributeError, TypeError, ValueError, KeyError, IndexError):
                    continue
                for e in (ev if isinstance(ev, list) else [ev] if ev else []):
                    out.append(_finding(rule_, {**r, "type": t}, e, repo))
    out += k8s_findings(root, repo)
    return out


# ------------------------------------------------------------------------------------------ overlap with external IaC scanners
CONCEPTS = {
    "encrypt": ("encrypt", "kms", "cmk", "customer managed key", "sse"), "public": ("public", "anonymous", "allusers", "0.0.0.0"),
    "tls": ("tls", "ssl", "https", "http only", "plain http", "insecure transport"), "logging": ("log", "trail", "audit", "monitor"),
    "versioning": ("versioning", "point in time", "recovery"), "rotation": ("rotation", "rotate"), "metadata": ("imds", "metadata"),
    "backup": ("backup", "retention"), "deletion": ("deletion protection", "purge"), "password": ("password", "credential", "secret"),
    "ingress": ("ingress", "port", "ssh", "rdp", "security group", "nsg", "firewall"), "wildcard": ("wildcard", "\"*\"", "admin", "full"),
    "network-policy": ("network policy",), "rbac": ("rbac", "abac", "role"), "flow": ("flow log",), "debug": ("debug",),
    "ftp": ("ftp",), "registry": ("admin user", "admin account", "tag", "scan"), "private": ("private", "authorized network", "endpoint"),
}


def _concepts(text: str) -> set:
    t = text.lower()
    return {c for c, words in CONCEPTS.items() if any(w in t for w in words)}


def drop_duplicates(builtin: list[dict], external: list[dict]) -> list[dict]:
    """External IaC findings that report what a built-in check already reported for the same resource are dropped;
    their other checks are kept."""
    seen = {}
    for f in builtin:
        res = (f.get("resource") or "").split(" ")[0]
        seen.setdefault((f.get("file"), res), set()).update(_concepts(f["title"] + " " + (f.get("evidence") or "")))
    out = []
    for f in external:
        key = (str(f.get("file") or "").lstrip("/"), f.get("resource") or "")
        cs = seen.get(key)
        if cs and _concepts(f.get("title") or "") & cs:
            continue
        out.append(f)
    return out
