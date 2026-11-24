# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Live Azure collection through Azure Resource Graph (read-only).

Permissions: Reader at the subscription or management-group scope (config/connectors/azure-role-definition.json lists
the read actions). Credentials (JSON): {"tenant_id", "client_id", "client_secret"} or {"tenant_id", "client_id",
"federated_token_file"} for workload identity federation, or {"access_token"} obtained elsewhere
(for example `az account get-access-token`)."""
from . import http
from .inventory import from_azure_graph

ARM = "https://management.azure.com"
GRAPH_API = "2022-10-01"
TYPES = ["microsoft.storage/storageaccounts", "microsoft.keyvault/vaults", "microsoft.sql/servers", "microsoft.network/networksecuritygroups",
         "microsoft.network/networkinterfaces", "microsoft.network/publicipaddresses", "microsoft.compute/virtualmachines",
         "microsoft.containerservice/managedclusters", "microsoft.web/sites", "microsoft.containerregistry/registries",
         "microsoft.documentdb/databaseaccounts"]
PROJECT = "| project id, name, type, location, resourceGroup, subscriptionId, tags, properties, identity, sku, kind"
QUERIES = [
    "resources | where type in~ (" + ", ".join(f"'{t}'" for t in TYPES) + ") " + PROJECT,
    "securityresources | where type =~ 'microsoft.security/pricings' " + PROJECT,
    "authorizationresources | where type in~ ('microsoft.authorization/roleassignments', 'microsoft.authorization/roledefinitions') "
    "| project id, name, type, location='', resourceGroup='', subscriptionId, tags=dynamic({}), properties, identity=dynamic({}), sku=dynamic({}), kind=''",
]
MAX_ROWS = 50000


def token(cred: dict, scope: str = f"{ARM}/.default") -> str:
    if cred.get("access_token") and scope.startswith(ARM):
        return cred["access_token"]
    if cred.get("access_token"):
        raise http.CollectorError("no token for Microsoft Graph")
    form = {"grant_type": "client_credentials", "client_id": cred["client_id"], "scope": scope}
    if cred.get("federated_token_file"):
        form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        with open(cred["federated_token_file"]) as fh:
            form["client_assertion"] = fh.read().strip()
    elif cred.get("client_secret"):
        form["client_secret"] = cred["client_secret"]
    else:
        raise http.CollectorError("Azure credential needs client_secret, federated_token_file or access_token")
    from urllib.parse import urlencode
    status, raw = http.request("POST", f"https://login.microsoftonline.com/{cred['tenant_id']}/oauth2/v2.0/token",
                               {"Content-Type": "application/x-www-form-urlencoded"}, urlencode(form).encode())
    body = http._json(raw)
    if status != 200 or "access_token" not in body:
        raise http.CollectorError(f"Azure sign-in failed ({status}): {body.get('error_description', body.get('error', ''))[:200]}")
    return body["access_token"]


def query(tok: str, subscriptions: list[str], q: str) -> list[dict]:
    rows, skip = [], None
    while len(rows) < MAX_ROWS:
        opts = {"$top": 1000, "resultFormat": "objectArray", **({"$skipToken": skip} if skip else {})}
        status, body = http.post_json(f"{ARM}/providers/Microsoft.ResourceGraph/resources?api-version={GRAPH_API}",
                                      {"subscriptions": subscriptions, "query": q, "options": opts}, {"Authorization": f"Bearer {tok}"})
        if status == 403:
            raise http.CollectorError("Azure Resource Graph: permission denied (assign Reader on the subscriptions)")
        if status != 200:
            raise http.CollectorError(f"Azure Resource Graph query failed ({status}): {str(body)[:200]}")
        rows += body.get("data") or []
        skip = body.get("$skipToken")
        if not skip:
            break
    return rows


def collect(cred: dict, subscriptions: list[str], account: str = "") -> dict:
    if not subscriptions:
        raise http.CollectorError("at least one subscription id is required")
    tok = token(cred)
    rows = []
    for q in QUERIES:
        rows += query(tok, subscriptions, q)
    for r in rows:      # SQL firewall rules are child resources that Resource Graph does not index
        if str(r.get("type", "")).lower() == "microsoft.sql/servers":
            status, body = http.get_json(f"{ARM}{r['id']}/firewallRules?api-version=2021-11-01", {"Authorization": f"Bearer {tok}"})
            r["firewallRules"] = body.get("value", []) if status == 200 else []
    _resolve_principals(cred, rows)
    inv = from_azure_graph(rows, account or ",".join(subscriptions))
    inv["collector"] = {"source": "azure-resource-graph", "subscriptions": subscriptions, "rows": len(rows)}
    return inv


def _resolve_principals(cred: dict, rows: list[dict]) -> None:
    """Optional: names and guest status of role-assignment principals from Microsoft Graph (needs the application
    permission Directory.Read.All). Without it, identities are shown by object ID and guest detection is skipped."""
    ras = [r["properties"] for r in rows if str(r.get("type", "")).lower() == "microsoft.authorization/roleassignments" and r.get("properties")]
    ids = sorted({p.get("principalId") for p in ras if p.get("principalId")})
    if not ids or cred.get("resolve_names") is False:
        return
    try:
        tok = token(cred, "https://graph.microsoft.com/.default")
    except (http.CollectorError, KeyError):
        return
    names = {}
    for i in range(0, len(ids), 1000):
        status, body = http.post_json("https://graph.microsoft.com/v1.0/directoryObjects/getByIds",
                                      {"ids": ids[i:i + 1000], "types": ["user", "group", "servicePrincipal"]}, {"Authorization": f"Bearer {tok}"})
        if status != 200:
            return
        for o in body.get("value") or []:
            names[o.get("id")] = (o.get("userPrincipalName") or o.get("displayName") or o.get("appDisplayName") or o.get("id"), o.get("userType"))
    for p in ras:
        n = names.get(p.get("principalId"))
        if n:
            p["principalName"], p["principalUserType"] = n
