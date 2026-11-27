# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""RAT Flea cloud inventory: one normalised shape for Azure, AWS, Google Cloud and Kubernetes.

    {"schema": "myelin-cloud-inventory/1", "provider": "azure|aws|gcp|kubernetes", "account": "<subscription|account|project|cluster>",
     "collected_at": ISO-8601, "resources": [{"id", "type", "name", "region", "tags", "props"}],
     "identities": [{"id", "name", "kind", "mfa", "console", "last_used_days", "keys", "external", "trust"}],
     "grants": [{"principal", "principal_kind", "role", "scope", "scope_level", "actions", "privilege", "builtin"}]}

Live collectors (collect_*.py) and the importers below all produce this shape, so every rule, the identity analysis and
the attack-path graph work the same for live collection, for an inventory collected elsewhere (air-gapped sites) and for
the provider-native exports customers already have:

    Azure        Azure Resource Graph rows (`az graph query -q "resources | ..." --first 1000 -o json`, including
                 authorizationresources for role assignments and definitions)
    Google Cloud Cloud Asset Inventory export (`gcloud asset export --content-type=resource|iam-policy`, JSON lines)
    Kubernetes   `kubectl get <kinds> -A -o json` (a v1 List)

Secret values are never collected: Kubernetes Secrets are not read, and environment variables are kept only as names
plus a "looks like a literal secret" flag.
"""
import json
import re
from datetime import datetime, timezone

SCHEMA = "myelin-cloud-inventory/1"
PROVIDERS = ("azure", "aws", "gcp", "kubernetes")
INTERNET = {"*", "0.0.0.0/0", "::/0", "internet", "any", "0.0.0.0", "<nw>/0"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}
SERVICE_PORTS = {1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
                 5601: "Kibana", 2375: "Docker API", 2376: "Docker API", 6443: "Kubernetes API", 10250: "kubelet", 11211: "Memcached",
                 9042: "Cassandra", 5984: "CouchDB", 8086: "InfluxDB"}
SECRETISH = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential|conn(ection)?[_-]?str)")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def empty(provider: str, account: str) -> dict:
    return {"schema": SCHEMA, "provider": provider, "account": account, "collected_at": now(),
            "resources": [], "identities": [], "grants": []}


def resource(rid, rtype, name, region="", tags=None, **props) -> dict:
    return {"id": str(rid), "type": rtype, "name": str(name or rid).split("/")[-1], "region": region or "",
            "tags": {str(k): str(v) for k, v in (tags or {}).items()}, "props": props}


# ------------------------------------------------------------------ network helpers (shared by every provider)
def parse_ports(spec) -> list[list[int]]:
    """'22', '20-25', '*', 22, ['80','443'] -> [[lo, hi], ...]."""
    if spec is None:
        return [[0, 65535]]
    if isinstance(spec, (list, tuple)):
        out = []
        for s in spec:
            out += parse_ports(s)
        return out
    s = str(spec).strip()
    if s in ("*", "", "all", "-1", "0-65535"):
        return [[0, 65535]]
    if "-" in s:
        lo, hi = s.split("-", 1)
        return [[int(lo), int(hi)]] if lo.isdigit() and hi.isdigit() else [[0, 65535]]
    return [[int(s), int(s)]] if s.isdigit() else []


def is_internet(src) -> bool:
    return str(src or "").strip().lower() in INTERNET


def exposed_ports(ingress: list[dict]) -> dict:
    """Which sensitive ports an ingress rule set opens to the internet: {'all': bool, 'admin': {...}, 'service': {...}}."""
    out = {"all": False, "admin": {}, "service": {}, "any": False}
    for r in ingress or []:
        if not r.get("allow", True) or not is_internet(r.get("source")):
            continue
        out["any"] = True
        for lo, hi in r.get("ports") or [[0, 65535]]:
            if lo <= 1 and hi >= 65535:
                out["all"] = True
            for p, n in ADMIN_PORTS.items():
                if lo <= p <= hi:
                    out["admin"][p] = n
            for p, n in SERVICE_PORTS.items():
                if lo <= p <= hi:
                    out["service"][p] = n
    return out


# ------------------------------------------------------------------ Azure Resource Graph
def _az_ingress(rules):
    out = []
    for r in rules or []:
        p = r.get("properties", r)
        if str(p.get("direction", "")).lower() != "inbound":
            continue
        srcs = p.get("sourceAddressPrefixes") or [p.get("sourceAddressPrefix")]
        ports = p.get("destinationPortRanges") or [p.get("destinationPortRange")]
        for s in srcs:
            out.append({"source": s, "ports": parse_ports(ports), "protocol": str(p.get("protocol", "*")).lower(),
                        "allow": str(p.get("access", "")).lower() == "allow", "priority": p.get("priority"),
                        "name": r.get("name") or p.get("name")})
    return out


def _ident(row):
    i = row.get("identity") or {}
    ids = []
    if i.get("principalId"):
        ids.append(i["principalId"])
    for v in (i.get("userAssignedIdentities") or {}).values():
        if isinstance(v, dict) and v.get("principalId"):
            ids.append(v["principalId"])
    return ids


AZ_PRIV_ADMIN = {"owner", "user access administrator", "role based access control administrator"}
AZ_PRIV_WRITE = {"contributor"}


def _az_privilege(role_name, actions, not_actions=()):
    n = (role_name or "").lower()
    blocks_iam = any(a.lower().startswith("microsoft.authorization/") for a in not_actions or [])
    if n in AZ_PRIV_WRITE or ("*" in actions and blocks_iam):
        return "write"
    if n in AZ_PRIV_ADMIN or "*" in actions or any(a.lower().startswith("microsoft.authorization/") and a.endswith(("/write", "/*")) for a in actions):
        return "admin"
    if n in AZ_PRIV_WRITE or any(a.endswith("/*") or a.endswith("/write") or a.endswith("/delete") for a in actions):
        return "write"
    return "read"


def _az_scope_level(scope):
    s = (scope or "").lower()
    if s.startswith("/providers/microsoft.management/managementgroups") or s == "/":
        return "organisation"
    parts = [x for x in s.split("/") if x]
    if len(parts) == 2:
        return "account"
    if len(parts) == 4 and parts[2] == "resourcegroups":
        return "resource_group"
    return "resource"


def from_azure_graph(rows: list[dict], account: str = "") -> dict:
    """Azure Resource Graph rows (resources + securityresources + authorizationresources tables) -> inventory."""
    rows = rows.get("data", rows) if isinstance(rows, dict) else rows
    subs = sorted({str(r.get("subscriptionId")) for r in rows if r.get("subscriptionId")})
    inv = empty("azure", account or ",".join(subs) or "azure")
    roledefs, assignments = {}, []
    for r in rows:
        t, p, rid = str(r.get("type", "")).lower(), r.get("properties") or {}, r.get("id", "")
        loc, tags, name = r.get("location", ""), r.get("tags") or {}, r.get("name")
        R = lambda typ, **kw: inv["resources"].append(resource(rid, typ, name, loc, tags, subscription=r.get("subscriptionId"),  # noqa: E731
                                                                resource_group=r.get("resourceGroup"), **kw))
        acls = p.get("networkAcls") or {}
        if t == "microsoft.storage/storageaccounts":
            R("azure.storage_account", public_blob=p.get("allowBlobPublicAccess") is True,
              https_only=p.get("supportsHttpsTrafficOnly", True) is not False, min_tls=p.get("minimumTlsVersion") or "TLS1_0",
              public_network=p.get("publicNetworkAccess") != "Disabled" and acls.get("defaultAction", "Allow") == "Allow",
              shared_key=p.get("allowSharedKeyAccess") is not False, data_store=True)
        elif t == "microsoft.keyvault/vaults":
            R("azure.key_vault", soft_delete=p.get("enableSoftDelete", True) is not False, purge_protection=p.get("enablePurgeProtection") is True,
              public_network=p.get("publicNetworkAccess") != "Disabled" and acls.get("defaultAction", "Allow") == "Allow",
              rbac=p.get("enableRbacAuthorization") is True, data_store=True)
        elif t == "microsoft.sql/servers":
            R("azure.sql_server", public_network=p.get("publicNetworkAccess", "Enabled") == "Enabled", min_tls=p.get("minimalTlsVersion") or "",
              firewall=[{"name": f.get("name"), "start": (f.get("properties") or f).get("startIpAddress"),
                         "end": (f.get("properties") or f).get("endIpAddress")} for f in r.get("firewallRules") or []],
              aad_admin=bool((p.get("administrators") or {}).get("login")), auditing=r.get("auditing"), data_store=True)
        elif t == "microsoft.network/networksecuritygroups":
            R("azure.nsg", ingress=_az_ingress(p.get("securityRules")),
              attached=[x.get("id") for x in (p.get("networkInterfaces") or []) + (p.get("subnets") or []) if x.get("id")])
        elif t == "microsoft.network/networkinterfaces":
            cfgs = p.get("ipConfigurations") or []
            R("azure.nic", nsg=(p.get("networkSecurityGroup") or {}).get("id"), vm=(p.get("virtualMachine") or {}).get("id"),
              public_ips=[((c.get("properties") or {}).get("publicIPAddress") or {}).get("id") for c in cfgs
                          if ((c.get("properties") or {}).get("publicIPAddress") or {}).get("id")],
              subnets=[((c.get("properties") or {}).get("subnet") or {}).get("id") for c in cfgs if ((c.get("properties") or {}).get("subnet") or {}).get("id")])
        elif t == "microsoft.network/publicipaddresses":
            R("azure.public_ip", ip=p.get("ipAddress"), sku=(r.get("sku") or {}).get("name", "Basic"))
        elif t == "microsoft.compute/virtualmachines":
            sec = p.get("securityProfile") or {}
            R("azure.vm", nics=[n.get("id") for n in (p.get("networkProfile") or {}).get("networkInterfaces") or []],
              identities=_ident(r), encryption_at_host=sec.get("encryptionAtHost") is True,
              os=((p.get("storageProfile") or {}).get("osDisk") or {}).get("osType", ""), workload=True,
              password_auth=((p.get("osProfile") or {}).get("linuxConfiguration") or {}).get("disablePasswordAuthentication") is False)
        elif t == "microsoft.containerservice/managedclusters":
            ap, npf = p.get("apiServerAccessProfile") or {}, p.get("networkProfile") or {}
            R("azure.aks", rbac=p.get("enableRBAC", True) is not False, aad=bool(p.get("aadProfile")),
              local_accounts=p.get("disableLocalAccounts") is not True, private=ap.get("enablePrivateCluster") is True,
              authorized_ranges=ap.get("authorizedIPRanges") or [], network_policy=npf.get("networkPolicy") or "",
              version=p.get("kubernetesVersion", ""), identities=_ident(r))
        elif t == "microsoft.web/sites":
            sc = p.get("siteConfig") or {}
            R("azure.webapp", https_only=p.get("httpsOnly") is True, min_tls=sc.get("minTlsVersion") or "",
              ftps=sc.get("ftpsState") or "", remote_debugging=sc.get("remoteDebuggingEnabled") is True,
              public_network=p.get("publicNetworkAccess") != "Disabled", identities=_ident(r), workload=True,
              hostnames=p.get("defaultHostName") or "", kind=r.get("kind", ""))
        elif t == "microsoft.containerregistry/registries":
            R("azure.acr", admin_user=p.get("adminUserEnabled") is True, public_network=p.get("publicNetworkAccess", "Enabled") == "Enabled",
              anonymous_pull=p.get("anonymousPullEnabled") is True)
        elif t == "microsoft.documentdb/databaseaccounts":
            R("azure.cosmos", public_network=p.get("publicNetworkAccess", "Enabled") == "Enabled" and not p.get("ipRules")
              and not p.get("isVirtualNetworkFilterEnabled"), local_auth=p.get("disableLocalAuth") is not True, data_store=True)
        elif t == "microsoft.security/pricings":
            R("azure.defender_plan", tier=p.get("pricingTier", "Free"), plan=name)
        elif t == "microsoft.insights/diagnosticsettings" or t == "microsoft.insights/activitylogalerts":
            R("azure.monitoring", kind=t.split("/")[-1])
        elif t == "microsoft.authorization/roledefinitions":
            perms = p.get("permissions") or [{}]
            roledefs[rid.lower()] = {"name": p.get("roleName", name), "builtin": p.get("type") == "BuiltInRole",
                                     "actions": [a for x in perms for a in x.get("actions") or []],
                                     "not_actions": [a for x in perms for a in x.get("notActions") or []]}
            if p.get("type") != "BuiltInRole":
                R("azure.custom_role", role=p.get("roleName", name), actions=roledefs[rid.lower()]["actions"],
                  scopes=p.get("assignableScopes") or [])
        elif t == "microsoft.authorization/roleassignments":
            assignments.append(p)
    seen = set()
    for a in assignments:
        rd = roledefs.get(str(a.get("roleDefinitionId", "")).lower()) or {"name": a.get("roleName") or str(a.get("roleDefinitionId", "")).split("/")[-1],
                                                                             "builtin": True, "actions": []}
        pid, kind = a.get("principalId"), str(a.get("principalType", "User")).lower()
        kind = {"serviceprincipal": "service", "foreigngroup": "group", "msi": "service"}.get(kind, kind)
        inv["grants"].append({"principal": pid, "principal_kind": kind, "role": rd["name"], "scope": a.get("scope", ""),
                              "scope_level": _az_scope_level(a.get("scope")), "actions": rd["actions"],
                              "privilege": _az_privilege(rd["name"], rd["actions"], rd.get("not_actions")), "builtin": rd["builtin"]})
        if pid not in seen:
            seen.add(pid)
            inv["identities"].append({"id": pid, "name": a.get("principalName") or pid, "kind": kind,
                                      "external": "#ext#" in str(a.get("principalName", "")).lower() or a.get("principalUserType") == "Guest"})
    return inv


# ------------------------------------------------------------------ Google Cloud Asset Inventory
GCP_ADMIN = {"roles/owner", "roles/resourcemanager.organizationadmin", "roles/resourcemanager.projectiamadmin", "roles/iam.securityadmin",
             "roles/iam.organizationroleadmin", "roles/iam.roleadmin"}
GCP_ESCALATE = {"roles/iam.serviceaccounttokencreator", "roles/iam.serviceaccountuser", "roles/iam.serviceaccountkeyadmin",
                "roles/iam.workloadidentityuser", "roles/deploymentmanager.editor", "roles/cloudfunctions.developer"}


def _gcp_priv(role):
    r = role.lower()
    if r in GCP_ADMIN:
        return "admin"
    if r == "roles/editor" or r in GCP_ESCALATE or r.endswith(".admin"):
        return "write"
    return "write" if any(x in r for x in ("writer", "editor", "creator", "developer")) else "read"


def _gcp_fw_ingress(d):
    out = []
    if d.get("direction", "INGRESS") != "INGRESS" or d.get("disabled"):
        return out
    for src in d.get("sourceRanges") or []:
        for a in d.get("allowed") or []:
            proto = str(a.get("IPProtocol", "all")).lower()
            out.append({"source": src, "ports": parse_ports(a.get("ports") or "*"), "protocol": proto, "allow": True})
    return out


def from_gcp_assets(items, account: str = "") -> dict:
    """Cloud Asset Inventory export (resource and iam-policy content, JSON lines or a JSON array) -> inventory."""
    if isinstance(items, str):
        items = [json.loads(x) for x in items.splitlines() if x.strip()]
    items = items.get("assets", items) if isinstance(items, dict) else items
    proj = account or next((str(i.get("name", "")).split("/projects/")[1].split("/")[0] for i in items if "/projects/" in str(i.get("name", ""))), "gcp")
    inv = empty("gcp", proj)
    sa_keys, sas = {}, {}
    for a in items:
        t, name = a.get("assetType", ""), a.get("name", "")
        d = (a.get("resource") or {}).get("data") or {}
        loc = (a.get("resource") or {}).get("location", "") or d.get("location", "") or str(d.get("zone", "")).split("/")[-1]
        labels = d.get("labels") or {}
        R = lambda typ, **kw: inv["resources"].append(resource(name, typ, d.get("name") or name, loc, labels, **kw))  # noqa: E731
        if t == "storage.googleapis.com/Bucket":
            iam = (d.get("iamConfiguration") or {})
            R("gcp.bucket", uniform_access=(iam.get("uniformBucketLevelAccess") or iam.get("bucketPolicyOnly") or {}).get("enabled") is True,
              public_prevention=iam.get("publicAccessPrevention") == "enforced", versioning=(d.get("versioning") or {}).get("enabled") is True,
              logging=bool(d.get("logging")), retention=bool(d.get("retentionPolicy")), public=False, data_store=True)
        elif t == "compute.googleapis.com/Firewall":
            R("gcp.firewall", ingress=_gcp_fw_ingress(d), network=str(d.get("network", "")).split("/")[-1],
              targets=d.get("targetTags") or [], target_sas=d.get("targetServiceAccounts") or [], logging=(d.get("logConfig") or {}).get("enable") is True)
        elif t == "compute.googleapis.com/Instance":
            nics = d.get("networkInterfaces") or []
            sa = (d.get("serviceAccounts") or [{}])[0] if d.get("serviceAccounts") else {}
            md = {i.get("key"): i.get("value") for i in (d.get("metadata") or {}).get("items") or []}
            R("gcp.instance", public_ip=any(n.get("accessConfigs") for n in nics), network=[str(n.get("network", "")).split("/")[-1] for n in nics],
              net_tags=(d.get("tags") or {}).get("items") or [], service_account=sa.get("email", ""), scopes=sa.get("scopes") or [],
              shielded=(d.get("shieldedInstanceConfig") or {}).get("enableSecureBoot") is True,
              serial_port=str(md.get("serial-port-enable", "false")).lower() in ("true", "1"),
              os_login=str(md.get("enable-oslogin", "")).lower() in ("true", "1"), workload=True)
        elif t == "sqladmin.googleapis.com/Instance":
            ipc = (d.get("settings") or {}).get("ipConfiguration") or {}
            R("gcp.sql_instance", public_ip=ipc.get("ipv4Enabled", True) is not False,
              authorized=[n.get("value") for n in ipc.get("authorizedNetworks") or []],
              require_ssl=ipc.get("requireSsl") is True or ipc.get("sslMode") in ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"),
              backups=((d.get("settings") or {}).get("backupConfiguration") or {}).get("enabled") is True, version=d.get("databaseVersion", ""), data_store=True)
        elif t == "container.googleapis.com/Cluster":
            pc, man = d.get("privateClusterConfig") or {}, d.get("masterAuthorizedNetworksConfig") or {}
            R("gcp.gke", legacy_abac=(d.get("legacyAbac") or {}).get("enabled") is True, private_nodes=pc.get("enablePrivateNodes") is True,
              private_endpoint=pc.get("enablePrivateEndpoint") is True, authorized_networks=man.get("enabled") is True,
              workload_identity=bool((d.get("workloadIdentityConfig") or {}).get("workloadPool")),
              network_policy=(d.get("networkPolicy") or {}).get("enabled") is True or bool(d.get("networkConfig", {}).get("datapathProvider") == "ADVANCED_DATAPATH"),
              basic_auth=bool((d.get("masterAuth") or {}).get("username")), version=d.get("currentMasterVersion", ""))
        elif t == "cloudkms.googleapis.com/CryptoKey":
            R("gcp.kms_key", rotation=d.get("rotationPeriod") or "", purpose=d.get("purpose", ""))
        elif t == "iam.googleapis.com/ServiceAccount":
            sas[d.get("email", name)] = d
            inv["identities"].append({"id": d.get("email", name), "name": d.get("email", name), "kind": "service_account",
                                      "disabled": d.get("disabled") is True, "keys": []})
        elif t == "iam.googleapis.com/ServiceAccountKey":
            if d.get("keyType") == "USER_MANAGED":
                email = name.split("/serviceAccounts/")[-1].split("/")[0]
                created = d.get("validAfterTime")
                sa_keys.setdefault(email, []).append({"id": name.split("/")[-1], "age_days": _age(created), "active": not d.get("disabled")})
        if a.get("iamPolicy"):
            scope_level = "organisation" if "/organizations/" in name else "account" if t == "cloudresourcemanager.googleapis.com/Project" else "resource"
            for b in a["iamPolicy"].get("bindings") or []:
                for m in b.get("members") or []:
                    kind, _, who = m.partition(":")
                    kind = {"serviceAccount": "service_account", "user": "user", "group": "group", "domain": "group",
                            "allUsers": "public", "allAuthenticatedUsers": "public"}.get(kind if who else m, "user")
                    inv["grants"].append({"principal": who or m, "principal_kind": kind, "role": b.get("role", ""), "scope": name,
                                          "scope_level": scope_level, "actions": [], "privilege": _gcp_priv(b.get("role", "")),
                                          "builtin": str(b.get("role", "")).startswith("roles/")})
                    if kind == "public" and t == "storage.googleapis.com/Bucket":
                        for res in inv["resources"]:
                            if res["id"] == name:
                                res["props"]["public"] = True
    for i in inv["identities"]:
        i["keys"] = sa_keys.get(i["id"], [])
    users = {g["principal"] for g in inv["grants"] if g["principal_kind"] == "user"}
    for u in sorted(users):
        inv["identities"].append({"id": u, "name": u, "kind": "user", "external": "gmail.com" in u})
    return inv


def _age(ts) -> int | None:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - d).days)
    except ValueError:
        return None


# ------------------------------------------------------------------ Kubernetes
WORKLOAD_KINDS = ("Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "Pod", "ReplicaSet")


def _pod_spec(obj):
    k, spec = obj.get("kind"), obj.get("spec") or {}
    if k == "Pod":
        return spec
    if k == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def _env_summary(containers):
    out = []
    for c in containers:
        for e in c.get("env") or []:
            literal = "value" in e and bool(e.get("value"))
            out.append({"container": c.get("name"), "name": e.get("name"),
                        "literal_secret": literal and bool(SECRETISH.search(e.get("name", ""))) and len(str(e.get("value"))) >= 8})
    return out


def from_kubernetes(doc, cluster: str = "") -> dict:
    """A `kubectl get ... -o json` List (or a list of such Lists) -> inventory. Secrets are never kept."""
    items = []
    for d in (doc if isinstance(doc, list) else [doc]):
        items += d.get("items", [d]) if isinstance(d, dict) else []
    inv = empty("kubernetes", cluster or "cluster")
    for o in items:
        kind, md = o.get("kind", ""), o.get("metadata") or {}
        ns, name = md.get("namespace", ""), md.get("name", "")
        rid = f"{kind}/{ns + '/' if ns else ''}{name}"
        meta = {"labels": md.get("labels") or {}, "annotations": {k: v for k, v in (md.get("annotations") or {}).items()
                                                                   if not k.startswith("kubectl.kubernetes.io/last-applied")}}
        if kind == "Secret":
            continue
        if kind in WORKLOAD_KINDS:
            if kind in ("Pod", "ReplicaSet", "Job") and md.get("ownerReferences"):
                owner = md["ownerReferences"][0]
                if kind == "Pod":
                    spec = o.get("spec") or {}
                    inv["resources"].append(resource(rid, "k8s.pod", name, ns, md.get("labels"), namespace=ns, owner=f"{owner.get('kind')}/{owner.get('name')}",
                                                     images=[c.get("image") for c in spec.get("containers") or []],
                                                     image_ids=[s.get("imageID") for s in (o.get("status") or {}).get("containerStatuses") or []],
                                                     service_account=spec.get("serviceAccountName", "default"), node=spec.get("nodeName", ""), **meta))
                continue
            spec = _pod_spec(o)
            containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
            inv["resources"].append(resource(rid, "k8s.workload", name, ns, md.get("labels"), namespace=ns, kind=kind, spec=_strip_spec(spec),
                                             images=[c.get("image") for c in containers], env=_env_summary(containers),
                                             service_account=spec.get("serviceAccountName", "default"),
                                             pod_labels=((o.get("spec") or {}).get("template") or {}).get("metadata", {}).get("labels") or md.get("labels") or {},
                                             workload=True, **meta))
        elif kind == "Namespace":
            inv["resources"].append(resource(rid, "k8s.namespace", name, "", md.get("labels"), **meta))
        elif kind == "Service":
            sp = o.get("spec") or {}
            ingress = (o.get("status") or {}).get("loadBalancer", {}).get("ingress") or []
            inv["resources"].append(resource(rid, "k8s.service", name, ns, md.get("labels"), namespace=ns, service_type=sp.get("type", "ClusterIP"),
                                             selector=sp.get("selector") or {}, ports=[p.get("port") for p in sp.get("ports") or []],
                                             source_ranges=sp.get("loadBalancerSourceRanges") or [], external=bool(ingress) or sp.get("type") in ("LoadBalancer", "NodePort"),
                                             internal_lb=_internal_lb(md.get("annotations") or {}), **meta))
        elif kind == "Ingress":
            sp = o.get("spec") or {}
            backends = set()
            for rule in sp.get("rules") or []:
                for p in ((rule.get("http") or {}).get("paths") or []):
                    svc = ((p.get("backend") or {}).get("service") or {}).get("name") or (p.get("backend") or {}).get("serviceName")
                    if svc:
                        backends.add(svc)
            inv["resources"].append(resource(rid, "k8s.ingress", name, ns, md.get("labels"), namespace=ns, services=sorted(backends),
                                             tls=bool(sp.get("tls")), hosts=[r.get("host") for r in sp.get("rules") or [] if r.get("host")], **meta))
        elif kind == "NetworkPolicy":
            sp = o.get("spec") or {}
            inv["resources"].append(resource(rid, "k8s.network_policy", name, ns, None, namespace=ns, selector=sp.get("podSelector") or {},
                                             types=sp.get("policyTypes") or ["Ingress"]))
        elif kind == "ServiceAccount":
            inv["resources"].append(resource(rid, "k8s.service_account", name, ns, None, namespace=ns,
                                             automount=o.get("automountServiceAccountToken") is not False,
                                             cloud_identity=(md.get("annotations") or {}).get("eks.amazonaws.com/role-arn") or
                                             (md.get("annotations") or {}).get("iam.gke.io/gcp-service-account") or
                                             (md.get("annotations") or {}).get("azure.workload.identity/client-id") or ""))
            inv["identities"].append({"id": f"system:serviceaccount:{ns}:{name}", "name": f"{ns}/{name}", "kind": "service_account"})
        elif kind in ("Role", "ClusterRole"):
            inv["resources"].append(resource(rid, "k8s.role", name, ns, md.get("labels"), namespace=ns, cluster_scoped=kind == "ClusterRole",
                                             rules=o.get("rules") or [], aggregated=bool(o.get("aggregationRule"))))
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            ref = o.get("roleRef") or {}
            for s in o.get("subjects") or []:
                sk = s.get("kind")
                pid = f"system:serviceaccount:{s.get('namespace') or ns}:{s.get('name')}" if sk == "ServiceAccount" else s.get("name")
                inv["grants"].append({"principal": pid, "principal_kind": {"ServiceAccount": "service_account", "Group": "group"}.get(sk, "user"),
                                      "role": f"{ref.get('kind')}/{ref.get('name')}", "scope": ns or "cluster",
                                      "scope_level": "account" if kind == "ClusterRoleBinding" else "namespace",
                                      "binding": f"{kind}/{ns + '/' if ns else ''}{name}", "actions": [], "privilege": "", "builtin": False})
        elif kind == "Node":
            info = (o.get("status") or {}).get("nodeInfo") or {}
            inv["resources"].append(resource(rid, "k8s.node", name, (md.get("labels") or {}).get("topology.kubernetes.io/region", ""), None,
                                             kubelet=info.get("kubeletVersion", ""), os_image=info.get("osImage", ""),
                                             runtime=info.get("containerRuntimeVersion", "")))
    return inv


def _internal_lb(ann: dict) -> bool:
    """Cloud annotations that make a LoadBalancer Service private (AKS, EKS, GKE)."""
    for k, v in ann.items():
        k, v = k.lower(), str(v).lower()
        if ("internal" in k and v == "true") or (k.endswith("load-balancer-scheme") and v == "internal") or \
                (k.endswith("load-balancer-type") and v == "internal"):
            return True
    return False


def _strip_spec(spec: dict) -> dict:
    """Keep the security-relevant parts of a pod spec; never environment values."""
    keep = {k: spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC", "securityContext", "automountServiceAccountToken",
                                      "serviceAccountName", "volumes", "shareProcessNamespace") if k in spec}
    keep["containers"] = [{k: c.get(k) for k in ("name", "image", "securityContext", "resources", "ports", "imagePullPolicy",
                                                 "livenessProbe", "readinessProbe") if k in c}
                          for c in (spec.get("containers") or []) + (spec.get("initContainers") or [])]
    if keep.get("volumes"):
        keep["volumes"] = [{k: v.get(k) for k in ("name", "hostPath", "secret", "projected", "emptyDir") if k in v} for v in keep["volumes"]]
    return keep


# ------------------------------------------------------------------ loader
def load(doc, provider: str = "", account: str = "") -> dict:
    """Accept a RAT Flea inventory or a provider-native export and return a RAT Flea inventory."""
    if isinstance(doc, (bytes, bytearray)):
        doc = doc.decode("utf-8-sig")
    if isinstance(doc, str):
        s = doc.strip()
        try:
            doc = json.loads(s)
        except json.JSONDecodeError:
            doc = [json.loads(x) for x in s.splitlines() if x.strip()]      # JSON lines (Cloud Asset export)
    if isinstance(doc, dict) and doc.get("schema") == SCHEMA:
        if doc.get("provider") not in PROVIDERS:
            raise ValueError("unknown provider in inventory")
        for k in ("resources", "identities", "grants"):
            doc.setdefault(k, [])
        if account:
            doc["account"] = account
        return doc
    p = provider.lower()
    if not p:
        if isinstance(doc, dict) and doc.get("kind") == "List" or isinstance(doc, dict) and doc.get("apiVersion"):
            p = "kubernetes"
        else:
            rows = doc.get("data", doc) if isinstance(doc, dict) else doc
            first = (rows or [{}])[0] if isinstance(rows, list) else {}
            p = "gcp" if "assetType" in first else "azure" if "subscriptionId" in first or str(first.get("type", "")).lower().startswith("microsoft.") else ""
    if p == "kubernetes":
        return from_kubernetes(doc, account)
    if p == "gcp":
        return from_gcp_assets(doc, account)
    if p == "azure":
        return from_azure_graph(doc, account)
    raise ValueError("unrecognised inventory: expected a RAT Flea inventory, Azure Resource Graph rows, a Cloud Asset export or a kubectl List")
