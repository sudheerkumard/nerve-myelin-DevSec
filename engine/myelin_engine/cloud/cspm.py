# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Cloud security posture (CSPM) rules for Microsoft Azure, Amazon Web Services and Google Cloud.

Rules read the normalised inventory (inventory.py) and never call a cloud API, so the same checks run on a live
collection, on an inventory carried into an air-gapped site and in tests. The CIS reference names the benchmark
section a check belongs to; titles and remediation are RAT Flea DevSec's own wording."""
from .inventory import exposed_ports, is_internet
from .rules import Rule, run

RULES: list[Rule] = []
CIS_AZ, CIS_AWS, CIS_GCP = "CIS Microsoft Azure Foundations", "CIS AWS Foundations", "CIS Google Cloud Platform Foundation"
DEPRECATED_LAMBDA = {"python2.7", "python3.6", "python3.7", "python3.8", "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x",
                     "nodejs12.x", "nodejs14.x", "nodejs16.x", "ruby2.5", "ruby2.7", "java8", "dotnetcore1.0", "dotnetcore2.0",
                     "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0", "dotnet6", "go1.x"}


def rule(rid, rtype, sev, title, category, remediation, cis="", internet=False):
    def deco(fn):
        RULES.append(Rule(rid, rtype, sev, title, category, remediation, fn, cis, internet))
        return fn
    return deco


def _tls_below_12(v) -> bool:
    v = str(v or "").upper().replace("TLS", "").replace("_", ".").strip(" .")
    return v in ("1.0", "1.1", "1", "", "1.0.0")


def _net(props, what):
    """Severity and evidence for an ingress rule set: all ports -> critical, admin -> high, service -> high."""
    e = exposed_ports(props.get("ingress"))
    if what == "admin":
        if e["all"]:
            return "all ports are open to the internet", "critical"
        if e["admin"]:
            return "open to the internet: " + ", ".join(f"{p} ({n})" for p, n in sorted(e["admin"].items())), "high"
    if what == "service" and e["service"] and not e["all"]:
        return "open to the internet: " + ", ".join(f"{p} ({n})" for p, n in sorted(e["service"].items())), "high"
    return None


# ================================================================ Azure
@rule("NM-AZ-001", "azure.storage_account", "high", "anonymous blob access is allowed", "data",
      "Set allowBlobPublicAccess to false on the account; serve public content through a CDN with signed URLs.", f"{CIS_AZ} §Storage", True)
def _(p, c, r): return p.get("public_blob") and "allowBlobPublicAccess = true"


@rule("NM-AZ-002", "azure.storage_account", "medium", "secure transfer (HTTPS only) is not required", "encryption",
      "Enable supportsHttpsTrafficOnly.", f"{CIS_AZ} §Storage")
def _(p, c, r): return not p.get("https_only") and "supportsHttpsTrafficOnly = false"


@rule("NM-AZ-003", "azure.storage_account", "medium", "minimum TLS version is below 1.2", "encryption",
      "Set minimumTlsVersion to TLS1_2.", f"{CIS_AZ} §Storage")
def _(p, c, r): return _tls_below_12(p.get("min_tls")) and f"minimumTlsVersion = {p.get('min_tls')}"


@rule("NM-AZ-004", "azure.storage_account", "medium", "accepts traffic from all networks", "exposure",
      "Set the network default action to Deny and allow only private endpoints or selected networks.", f"{CIS_AZ} §Storage", True)
def _(p, c, r): return p.get("public_network") and "publicNetworkAccess enabled with defaultAction = Allow"


@rule("NM-AZ-005", "azure.storage_account", "low", "shared key (account key) authorisation is allowed", "identity",
      "Set allowSharedKeyAccess to false and use Entra ID roles.", f"{CIS_AZ} §Storage")
def _(p, c, r): return p.get("shared_key") and "allowSharedKeyAccess is not disabled"


@rule("NM-AZ-006", "azure.key_vault", "medium", "purge protection is disabled", "data",
      "Enable purge protection so deleted keys and secrets cannot be destroyed during the retention period.", f"{CIS_AZ} §Key Vault")
def _(p, c, r): return not p.get("purge_protection") and "enablePurgeProtection is not set"


@rule("NM-AZ-007", "azure.key_vault", "medium", "accepts traffic from all networks", "exposure",
      "Disable public network access and use a private endpoint, or restrict the firewall to selected networks.", f"{CIS_AZ} §Key Vault", True)
def _(p, c, r): return p.get("public_network") and "public network access with defaultAction = Allow"


@rule("NM-AZ-008", "azure.key_vault", "low", "uses access policies instead of Azure RBAC", "identity",
      "Switch the vault to the Azure RBAC permission model.", f"{CIS_AZ} §Key Vault")
def _(p, c, r): return not p.get("rbac") and "enableRbacAuthorization = false"


@rule("NM-AZ-009", "azure.sql_server", "critical", "firewall allows connections from the internet", "exposure",
      "Remove broad firewall rules; use private endpoints or specific client addresses.", f"{CIS_AZ} §Database Services", True)
def _(p, c, r):
    for f in p.get("firewall") or []:
        if f.get("start") == "0.0.0.0" and f.get("end") == "255.255.255.255":
            return f"firewall rule {f.get('name')} allows 0.0.0.0-255.255.255.255"
        if f.get("start") == "0.0.0.0" and f.get("end") == "0.0.0.0":
            return f"firewall rule {f.get('name')} allows all Azure services, including other customers' resources", "medium"
    return None


@rule("NM-AZ-010", "azure.sql_server", "medium", "public network access is enabled", "exposure",
      "Disable public network access and connect through a private endpoint.", f"{CIS_AZ} §Database Services")
def _(p, c, r): return p.get("public_network") and "publicNetworkAccess = Enabled"


@rule("NM-AZ-011", "azure.sql_server", "medium", "no Microsoft Entra ID administrator", "identity",
      "Configure an Entra ID administrator and prefer Entra-only authentication.", f"{CIS_AZ} §Database Services")
def _(p, c, r): return not p.get("aad_admin") and "administrators.login not set"


@rule("NM-AZ-012", "azure.nsg", "high", "remote administration open to the internet", "exposure",
      "Restrict SSH/RDP to a bastion or VPN range; use Azure Bastion or just-in-time access.", f"{CIS_AZ} §Networking", True)
def _(p, c, r): return _net(p, "admin")


@rule("NM-AZ-013", "azure.nsg", "high", "database or management service open to the internet", "exposure",
      "Remove the internet source from the rule; reach data services over private endpoints.", f"{CIS_AZ} §Networking", True)
def _(p, c, r): return _net(p, "service")


@rule("NM-AZ-014", "azure.vm", "low", "encryption at host is not enabled", "encryption",
      "Enable encryption at host so temporary disks and caches are encrypted.", f"{CIS_AZ} §Virtual Machines")
def _(p, c, r): return not p.get("encryption_at_host") and "securityProfile.encryptionAtHost is not true"


@rule("NM-AZ-015", "azure.vm", "medium", "Linux password authentication is enabled", "identity",
      "Disable password authentication and use SSH keys or Entra ID login.", f"{CIS_AZ} §Virtual Machines")
def _(p, c, r): return p.get("password_auth") and "disablePasswordAuthentication = false"


@rule("NM-AZ-016", "azure.aks", "critical", "Kubernetes RBAC is disabled", "kubernetes",
      "Recreate the cluster with Kubernetes RBAC and Entra ID integration.", f"{CIS_AZ} §AKS")
def _(p, c, r): return not p.get("rbac") and "enableRBAC = false"


@rule("NM-AZ-017", "azure.aks", "medium", "local cluster accounts are enabled", "identity",
      "Set disableLocalAccounts so every access goes through Entra ID.", f"{CIS_AZ} §AKS")
def _(p, c, r): return p.get("local_accounts") and "disableLocalAccounts is not true"


@rule("NM-AZ-018", "azure.aks", "high", "API server is reachable from the whole internet", "exposure",
      "Use a private cluster or set authorised IP ranges for the API server.", f"{CIS_AZ} §AKS", True)
def _(p, c, r): return not p.get("private") and not p.get("authorized_ranges") and "public API server without authorizedIPRanges"


@rule("NM-AZ-019", "azure.aks", "medium", "no network policy engine", "kubernetes",
      "Enable Azure, Calico or Cilium network policy and default-deny traffic between namespaces.", f"{CIS_AZ} §AKS")
def _(p, c, r): return not p.get("network_policy") and "networkProfile.networkPolicy is empty"


@rule("NM-AZ-020", "azure.webapp", "medium", "HTTPS only is disabled", "encryption", "Enable httpsOnly.", f"{CIS_AZ} §App Service")
def _(p, c, r): return not p.get("https_only") and "httpsOnly = false"


@rule("NM-AZ-021", "azure.webapp", "medium", "minimum TLS version is below 1.2", "encryption",
      "Set siteConfig.minTlsVersion to 1.2 or higher.", f"{CIS_AZ} §App Service")
def _(p, c, r): return p.get("min_tls") and _tls_below_12(p.get("min_tls")) and f"minTlsVersion = {p.get('min_tls')}"


@rule("NM-AZ-022", "azure.webapp", "medium", "plain FTP deployment is allowed", "encryption",
      "Set ftpsState to FtpsOnly or Disabled.", f"{CIS_AZ} §App Service")
def _(p, c, r): return p.get("ftps") == "AllAllowed" and "ftpsState = AllAllowed"


@rule("NM-AZ-023", "azure.webapp", "high", "remote debugging is enabled", "workload",
      "Disable remote debugging outside short, supervised sessions.", f"{CIS_AZ} §App Service", True)
def _(p, c, r): return p.get("remote_debugging") and "remoteDebuggingEnabled = true"


@rule("NM-AZ-024", "azure.acr", "high", "registry admin user is enabled", "identity",
      "Disable the admin user; use Entra ID roles (AcrPull / AcrPush) and workload identity.", f"{CIS_AZ} §Container Registry")
def _(p, c, r): return p.get("admin_user") and "adminUserEnabled = true"


@rule("NM-AZ-025", "azure.acr", "high", "anonymous image pull is enabled", "data",
      "Disable anonymous pull unless the registry is intentionally public.", f"{CIS_AZ} §Container Registry", True)
def _(p, c, r): return p.get("anonymous_pull") and "anonymousPullEnabled = true"


@rule("NM-AZ-026", "azure.cosmos", "medium", "accepts traffic from all networks", "exposure",
      "Add IP or virtual-network rules, or disable public network access.", f"{CIS_AZ} §Database Services", True)
def _(p, c, r): return p.get("public_network") and "public network access without IP or VNet rules"


@rule("NM-AZ-027", "azure.cosmos", "low", "key-based (local) authentication is enabled", "identity",
      "Set disableLocalAuth and use Entra ID data-plane roles.", f"{CIS_AZ} §Database Services")
def _(p, c, r): return p.get("local_auth") and "disableLocalAuth is not true"


@rule("NM-AZ-028", "azure.defender_plan", "medium", "Microsoft Defender for Cloud plan is not enabled", "logging",
      "Enable the Defender plan for this resource type (Standard tier).", f"{CIS_AZ} §Microsoft Defender")
def _(p, c, r): return str(p.get("tier", "")).lower() == "free" and f"pricingTier = Free for {p.get('plan')}"


# ================================================================ AWS
@rule("NM-AWS-001", "aws.s3_bucket", "critical", "bucket is publicly accessible", "data",
      "Remove public grants and policy statements; enable S3 Block Public Access at account and bucket level.", f"{CIS_AWS} §Storage", True)
def _(p, c, r): return p.get("public") and (p.get("public_reason") or "bucket policy or ACL grants public access")


@rule("NM-AWS-002", "aws.s3_bucket", "medium", "S3 Block Public Access is not fully enabled", "data",
      "Enable all four Block Public Access settings on the account and the bucket.", f"{CIS_AWS} §Storage")
def _(p, c, r):
    b = p.get("block_public_access") or {}
    off = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets") if not b.get(k)]
    return off and "not enabled: " + ", ".join(off)


@rule("NM-AWS-003", "aws.s3_bucket", "low", "versioning is disabled", "data",
      "Enable versioning (and MFA delete or Object Lock for critical data) to recover from deletion and ransomware.", f"{CIS_AWS} §Storage")
def _(p, c, r): return p.get("versioning") != "Enabled" and f"versioning = {p.get('versioning') or 'never enabled'}"


@rule("NM-AWS-004", "aws.s3_bucket", "low", "server access logging is disabled", "logging",
      "Enable server access logging or CloudTrail data events for the bucket.", f"{CIS_AWS} §Logging")
def _(p, c, r): return not p.get("logging") and "no LoggingEnabled configuration"


@rule("NM-AWS-005", "aws.security_group", "high", "remote administration open to the internet", "exposure",
      "Restrict SSH/RDP to known ranges; prefer AWS Systems Manager Session Manager.", f"{CIS_AWS} §Networking", True)
def _(p, c, r): return _net(p, "admin")


@rule("NM-AWS-006", "aws.security_group", "high", "database or management service open to the internet", "exposure",
      "Remove 0.0.0.0/0 and ::/0 sources; reach data services from inside the VPC.", f"{CIS_AWS} §Networking", True)
def _(p, c, r): return _net(p, "service")


@rule("NM-AWS-007", "aws.instance", "medium", "instance metadata service v1 (IMDSv1) is allowed", "workload",
      "Require IMDSv2 (HttpTokens = required) so SSRF cannot read instance credentials.", f"{CIS_AWS} §Compute")
def _(p, c, r):
    if p.get("imds_v2"):
        return None
    return ("HttpTokens = optional on an instance with a public IP and an IAM role", "high") if p.get("public_ip") and p.get("role") else "HttpTokens = optional"


@rule("NM-AWS-008", "aws.region_settings", "medium", "EBS encryption by default is disabled", "encryption",
      "Enable EBS encryption by default in every region you use.", f"{CIS_AWS} §Storage")
def _(p, c, r): return p.get("ebs_default_encryption") is False and f"disabled in {r.get('region')}"


@rule("NM-AWS-009", "aws.region_settings", "medium", "Amazon GuardDuty is not enabled", "logging",
      "Enable GuardDuty in every region (delegated administrator for the organisation).", f"{CIS_AWS} §Monitoring")
def _(p, c, r): return p.get("guardduty") is False and f"no GuardDuty detector in {r.get('region')}"


@rule("NM-AWS-010", "aws.rds_instance", "high", "database is publicly accessible", "exposure",
      "Set PubliclyAccessible to false and place the instance in private subnets.", f"{CIS_AWS} §Database", True)
def _(p, c, r): return p.get("public") and "PubliclyAccessible = true"


@rule("NM-AWS-011", "aws.rds_instance", "high", "storage is not encrypted", "encryption",
      "Restore from an encrypted snapshot copy; encryption cannot be turned on in place.", f"{CIS_AWS} §Database")
def _(p, c, r): return p.get("encrypted") is False and "StorageEncrypted = false"


@rule("NM-AWS-012", "aws.rds_instance", "low", "automated backups are kept for less than 7 days", "data",
      "Set BackupRetentionPeriod to at least 7 days.", f"{CIS_AWS} §Database")
def _(p, c, r): return int(p.get("backup_days") or 0) < 7 and f"BackupRetentionPeriod = {p.get('backup_days') or 0}"


@rule("NM-AWS-013", "aws.rds_instance", "low", "deletion protection is disabled", "data",
      "Enable deletion protection for production databases.", f"{CIS_AWS} §Database")
def _(p, c, r): return p.get("deletion_protection") is False and "DeletionProtection = false"


@rule("NM-AWS-014", "aws.account", "high", "no multi-region CloudTrail trail is logging", "logging",
      "Create an organisation or multi-region trail with management events and keep it logging.", f"{CIS_AWS} §Logging")
def _(p, c, r): return p.get("multi_region_trail") is False and "no trail with IsMultiRegionTrail and IsLogging"


@rule("NM-AWS-015", "aws.trail", "medium", "log file validation is disabled", "logging",
      "Enable log file integrity validation.", f"{CIS_AWS} §Logging")
def _(p, c, r): return p.get("validation") is False and "LogFileValidationEnabled = false"


@rule("NM-AWS-016", "aws.kms_key", "medium", "automatic key rotation is disabled", "encryption",
      "Enable automatic rotation for customer-managed symmetric keys.", f"{CIS_AWS} §Logging")
def _(p, c, r): return p.get("rotation") is False and "KeyRotationEnabled = false"


@rule("NM-AWS-017", "aws.eks", "high", "cluster API endpoint is open to the whole internet", "exposure",
      "Disable the public endpoint or restrict publicAccessCidrs to known ranges.", f"{CIS_AWS} §EKS", True)
def _(p, c, r): return p.get("public_endpoint") and any(is_internet(x) for x in p.get("public_cidrs") or ["0.0.0.0/0"]) and "endpointPublicAccess with 0.0.0.0/0"


@rule("NM-AWS-018", "aws.eks", "medium", "control-plane audit logging is disabled", "logging",
      "Enable the api, audit and authenticator log types.", f"{CIS_AWS} §EKS")
def _(p, c, r): return "audit" not in (p.get("logging") or []) and "audit log type not enabled"


@rule("NM-AWS-019", "aws.eks", "medium", "Kubernetes Secrets are not envelope-encrypted with KMS", "encryption",
      "Associate a KMS key for secrets encryption.", f"{CIS_AWS} §EKS")
def _(p, c, r): return not p.get("secrets_encryption") and "no encryptionConfig for secrets"


@rule("NM-AWS-020", "aws.lambda", "high", "function URL allows unauthenticated calls", "exposure",
      "Set the function URL AuthType to AWS_IAM or put the function behind API Gateway with authorisation.", f"{CIS_AWS} §Compute", True)
def _(p, c, r): return p.get("url_auth") == "NONE" and "FunctionUrlConfig AuthType = NONE"


@rule("NM-AWS-021", "aws.lambda", "medium", "runtime is deprecated and no longer patched", "workload",
      "Move the function to a supported runtime version.", f"{CIS_AWS} §Compute")
def _(p, c, r): return str(p.get("runtime", "")).lower() in DEPRECATED_LAMBDA and f"Runtime = {p.get('runtime')}"


# ================================================================ Google Cloud
@rule("NM-GCP-001", "gcp.bucket", "critical", "bucket is readable by allUsers or allAuthenticatedUsers", "data",
      "Remove allUsers / allAuthenticatedUsers bindings and enforce public access prevention.", f"{CIS_GCP} §Storage", True)
def _(p, c, r): return p.get("public") and "IAM policy grants a public principal"


@rule("NM-GCP-002", "gcp.bucket", "medium", "uniform bucket-level access is disabled", "identity",
      "Enable uniform bucket-level access so only IAM controls access.", f"{CIS_GCP} §Storage")
def _(p, c, r): return not p.get("uniform_access") and "uniformBucketLevelAccess.enabled = false"


@rule("NM-GCP-003", "gcp.bucket", "low", "object versioning is disabled", "data", "Enable object versioning or a retention policy.", f"{CIS_GCP} §Storage")
def _(p, c, r): return not p.get("versioning") and not p.get("retention") and "versioning disabled and no retention policy"


@rule("NM-GCP-004", "gcp.firewall", "high", "remote administration open to the internet", "exposure",
      "Restrict SSH/RDP to IAP (35.235.240.0/20) or known ranges.", f"{CIS_GCP} §Networking", True)
def _(p, c, r): return _net(p, "admin")


@rule("NM-GCP-005", "gcp.firewall", "high", "database or management service open to the internet", "exposure",
      "Remove 0.0.0.0/0 from the source ranges.", f"{CIS_GCP} §Networking", True)
def _(p, c, r): return _net(p, "service")


@rule("NM-GCP-006", "gcp.instance", "high", "default compute service account with full cloud-platform scope", "identity",
      "Use a dedicated least-privilege service account and limit access scopes.", f"{CIS_GCP} §Virtual Machines")
def _(p, c, r):
    return (str(p.get("service_account", "")).endswith("-compute@developer.gserviceaccount.com")
            and any(s.endswith("/cloud-platform") for s in p.get("scopes") or []) and f"{p.get('service_account')} with cloud-platform scope")


@rule("NM-GCP-007", "gcp.instance", "medium", "interactive serial console is enabled", "workload",
      "Set metadata serial-port-enable to false.", f"{CIS_GCP} §Virtual Machines")
def _(p, c, r): return p.get("serial_port") and "serial-port-enable = true"


@rule("NM-GCP-008", "gcp.instance", "low", "Shielded VM secure boot is disabled", "workload",
      "Enable Shielded VM secure boot, vTPM and integrity monitoring.", f"{CIS_GCP} §Virtual Machines")
def _(p, c, r): return not p.get("shielded") and "enableSecureBoot = false"


@rule("NM-GCP-009", "gcp.instance", "low", "OS Login is not enabled", "identity",
      "Set enable-oslogin = TRUE (project or instance metadata).", f"{CIS_GCP} §Virtual Machines")
def _(p, c, r): return not p.get("os_login") and "enable-oslogin not set"


@rule("NM-GCP-010", "gcp.sql_instance", "critical", "database accepts connections from the internet", "exposure",
      "Remove 0.0.0.0/0 from authorised networks; use private IP or the Cloud SQL Auth Proxy.", f"{CIS_GCP} §Cloud SQL", True)
def _(p, c, r): return p.get("public_ip") and any(is_internet(n) for n in p.get("authorized") or []) and "authorizedNetworks contains 0.0.0.0/0"


@rule("NM-GCP-011", "gcp.sql_instance", "medium", "SSL/TLS is not required for connections", "encryption",
      "Require SSL (sslMode ENCRYPTED_ONLY or client certificates).", f"{CIS_GCP} §Cloud SQL")
def _(p, c, r): return not p.get("require_ssl") and "requireSsl = false"


@rule("NM-GCP-012", "gcp.sql_instance", "medium", "automated backups are disabled", "data", "Enable automated backups.", f"{CIS_GCP} §Cloud SQL")
def _(p, c, r): return not p.get("backups") and "backupConfiguration.enabled = false"


@rule("NM-GCP-013", "gcp.gke", "high", "legacy ABAC authorisation is enabled", "kubernetes", "Disable legacy ABAC; use RBAC.", f"{CIS_GCP} §GKE")
def _(p, c, r): return p.get("legacy_abac") and "legacyAbac.enabled = true"


@rule("NM-GCP-014", "gcp.gke", "high", "control plane is reachable from the whole internet", "exposure",
      "Enable master authorised networks or a private endpoint.", f"{CIS_GCP} §GKE", True)
def _(p, c, r): return not p.get("private_endpoint") and not p.get("authorized_networks") and "public endpoint without authorised networks"


@rule("NM-GCP-015", "gcp.gke", "medium", "Workload Identity is not enabled", "identity",
      "Enable Workload Identity so pods do not use the node service account.", f"{CIS_GCP} §GKE")
def _(p, c, r): return not p.get("workload_identity") and "workloadIdentityConfig not set"


@rule("NM-GCP-016", "gcp.gke", "medium", "network policy is not enforced", "kubernetes",
      "Enable network policy (or GKE Dataplane V2).", f"{CIS_GCP} §GKE")
def _(p, c, r): return not p.get("network_policy") and "networkPolicy disabled"


@rule("NM-GCP-017", "gcp.gke", "high", "basic authentication is configured", "identity",
      "Remove the static username/password; use Google identities.", f"{CIS_GCP} §GKE")
def _(p, c, r): return p.get("basic_auth") and "masterAuth.username is set"


@rule("NM-GCP-018", "gcp.kms_key", "medium", "key is not rotated at least every 90 days", "encryption",
      "Set a rotation period of 90 days or less.", f"{CIS_GCP} §Cryptographic Keys")
def _(p, c, r):
    if p.get("purpose") not in ("", "ENCRYPT_DECRYPT"):
        return None
    rp = str(p.get("rotation") or "")
    secs = int(rp.rstrip("s")) if rp.rstrip("s").isdigit() else None
    return (secs is None or secs > 90 * 86400) and f"rotationPeriod = {rp or 'none'}"


def evaluate(inv: dict) -> list[dict]:
    if inv.get("provider") not in ("azure", "aws", "gcp"):
        return []
    return run(inv, RULES, {})


def catalogue() -> list[dict]:
    return [{"id": r.id, "type": r.rtype, "severity": r.severity, "title": r.title, "category": r.category, "cis": r.cis} for r in RULES]
