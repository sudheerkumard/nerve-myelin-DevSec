# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Live AWS collection (read-only) with boto3.

Permissions: the AWS managed SecurityAudit policy, or config/connectors/aws-iam-policy.json. Credentials: a cross-account
role assumed with an ExternalId ({"role_arn", "external_id"}), or the ambient boto3 credential chain when the collector
runs inside the account. `client` may be injected (tests): callable(service, region) -> client."""
import csv
import io
import json
import time
import urllib.parse
from datetime import datetime, timezone

from . import http
from .inventory import empty, parse_ports, resource

READ_PREFIXES = ("get", "list", "describe", "head", "view", "lookup", "search", "query", "scan", "select", "batchget", "check")
ESCALATION = {"iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:attachuserpolicy", "iam:attachrolepolicy",
              "iam:attachgrouppolicy", "iam:putuserpolicy", "iam:putrolepolicy", "iam:putgrouppolicy", "iam:createaccesskey",
              "iam:createloginprofile", "iam:updateloginprofile", "iam:updateassumerolepolicy", "iam:addusertogroup"}
PASSROLE_TARGETS = {"lambda:createfunction", "ec2:runinstances", "cloudformation:createstack", "glue:createdevendpoint",
                    "ecs:runtask", "sagemaker:createnotebookinstance", "datapipeline:createpipeline"}


def clients(cred: dict | None):
    cred = cred or {}
    if cred.get("role_arn") and not cred.get("external_id"):
        raise http.CollectorError("external_id is required when assuming a role (confused-deputy protection)")
    try:
        import boto3
    except ImportError as e:
        raise http.CollectorError("the AWS collector needs boto3: pip install -r backend/requirements-cloud.txt") from e
    if cred.get("role_arn"):
        c = boto3.client("sts").assume_role(RoleArn=cred["role_arn"], RoleSessionName="nerve-myelin-cspm",
                                            ExternalId=cred["external_id"], DurationSeconds=3600)["Credentials"]
        sess = boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])
    else:
        sess = boto3.Session()
    return lambda svc, region: sess.client(svc, region_name=region)


def _try(fn, default=None):
    """Call one read API; a missing permission or an unconfigured feature (for example no bucket policy) returns the
    default instead of stopping the collection."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return default


def _days(ts) -> int | None:
    if not ts or ts in ("N/A", "no_information", "not_supported"):
        return None
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - ts).days)


def _ingress(perms):
    out = []
    for p in perms or []:
        proto = str(p.get("IpProtocol", "-1"))
        ports = [[0, 65535]] if proto == "-1" else [[int(p.get("FromPort", 0)), int(p.get("ToPort", 65535))]]
        for rng in (p.get("IpRanges") or []):
            out.append({"source": rng.get("CidrIp"), "ports": ports, "protocol": "all" if proto == "-1" else proto, "allow": True})
        for rng in (p.get("Ipv6Ranges") or []):
            out.append({"source": rng.get("CidrIpv6"), "ports": ports, "protocol": "all" if proto == "-1" else proto, "allow": True})
    return out


def _doc(d):
    if isinstance(d, str):
        d = json.loads(urllib.parse.unquote(d))
    return d or {}


def policy_actions(doc) -> list[str]:
    acts = []
    for st in _list(_doc(doc).get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        a = _list(st.get("Action"))
        res = _list(st.get("Resource"))
        acts += [f"{x}@{'*' if '*' in res else 'scoped'}" for x in a]
    return acts[:300]


def _list(x):
    return x if isinstance(x, list) else [x] if x else []


def privilege(actions: list[str]) -> str:
    names = {a.split("@")[0].lower() for a in actions}
    if any(a in ("*", "*:*", "iam:*") for a in names) or ("*@*" in actions):
        return "admin"
    if names & ESCALATION or ("iam:passrole" in names and names & PASSROLE_TARGETS):
        return "admin"
    if any(not a.split(":")[-1].startswith(READ_PREFIXES) for a in names if ":" in a):
        return "write"
    return "read"


def _trust(doc):
    """Who may assume a role: any principal, other accounts, and whether an ExternalId condition is required."""
    out = {"public": False, "accounts": [], "services": [], "external_id": False, "federated": []}
    for st in _list(_doc(doc).get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        pr = st.get("Principal")
        cond = json.dumps(st.get("Condition") or {})
        if pr == "*" or (isinstance(pr, dict) and "*" in _list(pr.get("AWS"))):
            out["public"] = "aws:PrincipalOrgID" not in cond and "aws:SourceAccount" not in cond
        if isinstance(pr, dict):
            out["accounts"] += [a.split(":")[4] if a.startswith("arn:") else a for a in _list(pr.get("AWS")) if a != "*"]
            out["services"] += _list(pr.get("Service"))
            out["federated"] += _list(pr.get("Federated"))
        if "sts:ExternalId" in cond:
            out["external_id"] = True
    return out


def collect(regions: list[str], cred: dict | None = None, client=None, account: str = "") -> dict:
    client = client or clients(cred)
    regions = regions or ["us-east-1"]
    home = regions[0]
    acct = account or _try(lambda: client("sts", home).get_caller_identity()["Account"], "aws")
    inv = empty("aws", acct)
    R = inv["resources"]
    # ---------- account-level S3 Block Public Access
    acct_bpa = _try(lambda: client("s3control", home).get_public_access_block(AccountId=acct)["PublicAccessBlockConfiguration"], {})
    s3 = client("s3", home)
    for b in _try(lambda: s3.list_buckets().get("Buckets", []), []):
        name = b["Name"]
        bpa = _try(lambda: s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"], {})
        merged = {k: bool(bpa.get(k) or acct_bpa.get(k)) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
        pol_public = _try(lambda: s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"], False)
        acl = _try(lambda: s3.get_bucket_acl(Bucket=name).get("Grants", []), [])
        acl_public = any(str((g.get("Grantee") or {}).get("URI", "")).endswith(("/AllUsers", "/AuthenticatedUsers")) for g in acl)
        public = (pol_public and not merged["RestrictPublicBuckets"]) or (acl_public and not merged["IgnorePublicAcls"])
        tags = {t["Key"]: t["Value"] for t in _try(lambda: s3.get_bucket_tagging(Bucket=name).get("TagSet", []), [])}
        R.append(resource(f"arn:aws:s3:::{name}", "aws.s3_bucket", name, "", tags, public=public,
                          public_reason=("bucket policy is public" if pol_public else "ACL grants AllUsers/AuthenticatedUsers") if public else "",
                          block_public_access=merged, versioning=_try(lambda: s3.get_bucket_versioning(Bucket=name).get("Status"), "") or "",
                          logging=bool(_try(lambda: s3.get_bucket_logging(Bucket=name).get("LoggingEnabled"), None)), data_store=True))
    # ---------- regional services
    trails_multi = False
    for region in regions:
        ec2 = client("ec2", region)
        for sg in _try(lambda: ec2.describe_security_groups().get("SecurityGroups", []), []):
            R.append(resource(f"arn:aws:ec2:{region}:{acct}:security-group/{sg['GroupId']}", "aws.security_group", sg.get("GroupName") or sg["GroupId"],
                              region, {t["Key"]: t["Value"] for t in sg.get("Tags") or []}, ingress=_ingress(sg.get("IpPermissions")),
                              group_id=sg["GroupId"], vpc=sg.get("VpcId")))
        for res in _try(lambda: ec2.describe_instances().get("Reservations", []), []):
            for i in res.get("Instances", []):
                if (i.get("State") or {}).get("Name") == "terminated":
                    continue
                tags = {t["Key"]: t["Value"] for t in i.get("Tags") or []}
                R.append(resource(f"arn:aws:ec2:{region}:{acct}:instance/{i['InstanceId']}", "aws.instance", tags.get("Name") or i["InstanceId"], region, tags,
                                  public_ip=i.get("PublicIpAddress") or "", imds_v2=(i.get("MetadataOptions") or {}).get("HttpTokens") == "required",
                                  role=(i.get("IamInstanceProfile") or {}).get("Arn", ""), security_groups=[g["GroupId"] for g in i.get("SecurityGroups") or []],
                                  image=i.get("ImageId"), workload=True))
        ebs = _try(lambda: ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"], None)
        gd = _try(lambda: bool(client("guardduty", region).list_detectors().get("DetectorIds")), None)
        R.append(resource(f"arn:aws:::{acct}/region/{region}", "aws.region_settings", region, region, None, ebs_default_encryption=ebs, guardduty=gd))
        for d in _try(lambda: client("rds", region).describe_db_instances().get("DBInstances", []), []):
            R.append(resource(d["DBInstanceArn"], "aws.rds_instance", d["DBInstanceIdentifier"], region, {t["Key"]: t["Value"] for t in d.get("TagList") or []},
                              public=d.get("PubliclyAccessible") is True, encrypted=d.get("StorageEncrypted") is True,
                              backup_days=d.get("BackupRetentionPeriod", 0), deletion_protection=d.get("DeletionProtection") is True,
                              engine=d.get("Engine"), security_groups=[g["VpcSecurityGroupId"] for g in d.get("VpcSecurityGroups") or []], data_store=True))
        eks = client("eks", region)
        for name in _try(lambda: eks.list_clusters().get("clusters", []), []):
            c = _try(lambda: eks.describe_cluster(name=name)["cluster"], {})
            vpc = c.get("resourcesVpcConfig") or {}
            logs = [t for lg in (c.get("logging") or {}).get("clusterLogging", []) if lg.get("enabled") for t in lg.get("types", [])]
            R.append(resource(c.get("arn", f"eks/{name}"), "aws.eks", name, region, c.get("tags"), public_endpoint=vpc.get("endpointPublicAccess") is True,
                              public_cidrs=vpc.get("publicAccessCidrs") or [], logging=logs, secrets_encryption=bool(c.get("encryptionConfig")),
                              version=c.get("version", "")))
        lam = client("lambda", region)
        for fn in _try(lambda: lam.list_functions().get("Functions", []), []):
            urls = _try(lambda: lam.list_function_url_configs(FunctionName=fn["FunctionName"]).get("FunctionUrlConfigs", []), [])
            R.append(resource(fn["FunctionArn"], "aws.lambda", fn["FunctionName"], region, None, runtime=fn.get("Runtime", ""), role=fn.get("Role", ""),
                              url_auth=urls[0].get("AuthType") if urls else None, workload=bool(urls)))
        kms = client("kms", region)
        for k in _try(lambda: kms.list_keys().get("Keys", []), []):
            meta = _try(lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"], {})
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled" or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                continue
            R.append(resource(meta.get("Arn", k["KeyId"]), "aws.kms_key", k["KeyId"], region, None,
                              rotation=_try(lambda: kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"], None)))
        ct = client("cloudtrail", region)
        for t in _try(lambda: ct.describe_trails(includeShadowTrails=False).get("trailList", []), []):
            logging = _try(lambda: ct.get_trail_status(Name=t["TrailARN"])["IsLogging"], False)
            if t.get("IsMultiRegionTrail") and logging:
                trails_multi = True
            R.append(resource(t["TrailARN"], "aws.trail", t["Name"], region, None, multi_region=t.get("IsMultiRegionTrail") is True,
                              logging=logging, validation=t.get("LogFileValidationEnabled") is True))
    # ---------- IAM (global)
    iam = client("iam", home)
    summary = _try(lambda: iam.get_account_summary()["SummaryMap"], {})
    ppol = _try(lambda: iam.get_account_password_policy()["PasswordPolicy"], {})
    R.append(resource(f"arn:aws:iam::{acct}:root", "aws.account", acct, "global", None, multi_region_trail=trails_multi,
                      root_mfa=summary.get("AccountMFAEnabled") == 1 if summary else None,
                      root_keys=summary.get("AccountAccessKeysPresent", 0) > 0 if summary else None, password_policy=ppol or None))
    _iam(inv, iam, acct)
    inv["collector"] = {"source": "aws-api", "regions": regions}
    return inv


def _credential_report(iam):
    for _ in range(10):
        st = _try(lambda: iam.generate_credential_report().get("State"), "COMPLETE")
        if st == "COMPLETE":
            break
        time.sleep(1)
    raw = _try(lambda: iam.get_credential_report()["Content"], b"")
    if isinstance(raw, bytes):
        raw = raw.decode()
    return {r["user"]: r for r in csv.DictReader(io.StringIO(raw or ""))}


def _iam(inv, iam, acct):
    report = _credential_report(iam)
    pols, users, groups, roles = {}, [], [], []
    marker = None
    for _ in range(50):
        page = _try(lambda: iam.get_account_authorization_details(**({"Marker": marker} if marker else {})), {})
        users += page.get("UserDetailList", [])
        groups += page.get("GroupDetailList", [])
        roles += page.get("RoleDetailList", [])
        for p in page.get("Policies", []):
            ver = next((v for v in p.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), {})
            pols[p["Arn"]] = {"name": p["PolicyName"], "doc": ver.get("Document"), "aws_managed": p["Arn"].startswith("arn:aws:iam::aws:")}
        marker = page.get("Marker")
        if not page.get("IsTruncated"):
            break

    def grants_for(principal, kind, attached, inline, scope_name):
        out = []
        for a in attached or []:
            p = pols.get(a["PolicyArn"], {"name": a.get("PolicyName"), "doc": None, "aws_managed": True})
            acts = policy_actions(p["doc"]) if p["doc"] else (["*@*"] if a.get("PolicyName") == "AdministratorAccess" else [])
            out.append({"principal": principal, "principal_kind": kind, "role": p["name"] or a.get("PolicyName"), "scope": scope_name,
                        "scope_level": "account", "actions": acts, "privilege": privilege(acts), "builtin": p["aws_managed"]})
        for ip in inline or []:
            acts = policy_actions(ip.get("PolicyDocument"))
            out.append({"principal": principal, "principal_kind": kind, "role": f"inline:{ip.get('PolicyName')}", "scope": scope_name,
                        "scope_level": "account", "actions": acts, "privilege": privilege(acts), "builtin": False})
        return out

    gmap = {g["GroupName"]: g for g in groups}
    for u in users:
        r = report.get(u["UserName"], {})
        keys = []
        for n in ("1", "2"):
            if r.get(f"access_key_{n}_active") == "true":
                keys.append({"id": f"key{n}", "age_days": _days(r.get(f"access_key_{n}_last_rotated")),
                             "last_used_days": _days(r.get(f"access_key_{n}_last_used_date")), "active": True})
        last = [d for d in [_days(r.get("password_last_used"))] + [k["last_used_days"] for k in keys] if d is not None]
        inv["identities"].append({"id": u["Arn"], "name": u["UserName"], "kind": "user", "console": r.get("password_enabled") == "true",
                                  "mfa": r.get("mfa_active") == "true" if r else None, "keys": keys,
                                  "last_used_days": min(last) if last else None, "created_days": _days(u.get("CreateDate"))})
        inv["grants"] += grants_for(u["Arn"], "user", u.get("AttachedManagedPolicies"), u.get("UserPolicyList"), acct)
        for gname in u.get("GroupList") or []:
            g = gmap.get(gname) or {}
            for gr in grants_for(u["Arn"], "user", g.get("AttachedManagedPolicies"), g.get("GroupPolicyList"), acct):
                gr["role"] = f"group {gname}: {gr['role']}"
                inv["grants"].append(gr)
    for ro in roles:
        if ro.get("Path", "/").startswith("/aws-service-role/"):
            continue
        last = (ro.get("RoleLastUsed") or {}).get("LastUsedDate")
        inv["identities"].append({"id": ro["Arn"], "name": ro["RoleName"], "kind": "role", "trust": _trust(ro.get("AssumeRolePolicyDocument")),
                                  "last_used_days": _days(last), "created_days": _days(ro.get("CreateDate"))})
        inv["grants"] += grants_for(ro["Arn"], "role", ro.get("AttachedManagedPolicies"), ro.get("RolePolicyList"), acct)
        for prof in ro.get("InstanceProfileList") or []:
            inv["identities"][-1].setdefault("instance_profiles", []).append(prof.get("Arn"))
    root = report.get("<root_account>")
    if root:
        inv["identities"].append({"id": f"arn:aws:iam::{acct}:root", "name": "root", "kind": "root", "mfa": root.get("mfa_active") == "true",
                                  "last_used_days": _days(root.get("password_last_used")),
                                  "keys": [{"id": f"key{n}", "active": True, "age_days": _days(root.get(f"access_key_{n}_last_rotated"))}
                                           for n in ("1", "2") if root.get(f"access_key_{n}_active") == "true"]})


__all__ = ["collect", "privilege", "policy_actions", "parse_ports"]
