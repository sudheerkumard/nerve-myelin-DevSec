# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Microsoft Azure connector (Azure Resource Manager, read-only).

Least privilege: a dedicated app registration / user-assigned identity with the custom role in
config/connectors/azure-role-definition.json (read-only actions only) or built-in Reader + Security
Reader, scoped to the chosen subscriptions. Preferred auth: workload identity federation (no secret);
fallback: client secret from the customer's Key Vault.
Secret (JSON): {"tenant_id": "...", "client_id": "...", "client_secret": "..."}   or
               {"tenant_id": "...", "client_id": "...", "federated_token_file": "/var/run/secrets/azure/tokens/azure-identity-token"}
"""
from .base import Connector, ConnectorError, SyncResult, register

ARM = "https://management.azure.com"


@register
class AzureConnector(Connector):
    kind = "azure"
    title = "Microsoft Azure (Resource Manager, read-only)"
    config_fields = {"subscription_ids": "Comma-separated subscription IDs"}
    least_privilege = {"summary": "Custom role 'NERvvE DevSecOps Reader' (read-only: Defender assessments, ACR, AKS, Key Vault metadata) at subscription scope",
                       "policy_file": "config/connectors/azure-role-definition.json"}

    def _token(self) -> str:
        c = self.secret_json()
        data = {"grant_type": "client_credentials", "client_id": c["client_id"], "scope": f"{ARM}/.default"}
        if c.get("federated_token_file"):
            data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data["client_assertion"] = open(c["federated_token_file"]).read().strip()
        elif c.get("client_secret"):
            data["client_secret"] = c["client_secret"]
        else:
            raise ConnectorError("Azure credential needs client_secret or federated_token_file")
        r = self.http.post(f"https://login.microsoftonline.com/{c['tenant_id']}/oauth2/v2.0/token", data=data)
        if r.status_code != 200:
            raise ConnectorError(f"Azure token request failed ({r.status_code})")
        return r.json()["access_token"]

    def _list(self, tok, path, api):
        url, items = f"{ARM}{path}?api-version={api}", []
        while url and len(items) < 5000:
            r = self.http.get(url, headers={"Authorization": f"Bearer {tok}"})
            if r.status_code == 403:
                raise ConnectorError(f"permission denied for {path} — check the role assignment")
            if r.status_code != 200:
                break
            j = r.json()
            items += j.get("value", [])
            url = j.get("nextLink")
        return items

    def _subs(self):
        return [s.strip() for s in self.config["subscription_ids"].split(",") if s.strip()]

    def test(self) -> dict:
        tok = self._token()
        return {"ok": True, "subscriptions": [s for s in self._subs() if self.http.get(
            f"{ARM}/subscriptions/{s}?api-version=2022-12-01", headers={"Authorization": f"Bearer {tok}"}).status_code == 200]}

    def sync(self) -> SyncResult:
        tok, out = self._token(), SyncResult()
        for sub in self._subs():
            for a in self._list(tok, f"/subscriptions/{sub}/providers/Microsoft.Security/assessments", "2021-06-01"):
                p = a.get("properties", {})
                if p.get("status", {}).get("code") != "Unhealthy":
                    continue
                sev = (p.get("metadata", {}).get("severity") or "Medium").lower()
                out.findings.append({"engine": "cloud", "rule_id": "AZ-" + a.get("name", "")[:36], "title": p.get("displayName", "Defender recommendation"),
                                     "severity": sev if sev in ("high", "medium", "low") else "medium", "repo": f"azure:{sub}",
                                     "file": p.get("resourceDetails", {}).get("Id", ""), "exposure": "internal", "source": "azure-defender"})
            for reg in self._list(tok, f"/subscriptions/{sub}/providers/Microsoft.ContainerRegistry/registries", "2023-07-01"):
                rp = reg.get("properties", {})
                out.assets.append({"type": "container-registry", "id": reg["id"]})
                if rp.get("adminUserEnabled"):
                    out.findings.append({"engine": "cloud", "rule_id": "NM-AZ-ACR-001", "title": f"ACR {reg['name']}: admin user enabled",
                                         "severity": "high", "repo": f"azure:{sub}", "file": reg["id"], "exposure": "internet",
                                         "remediation": "Disable the admin user; use Entra ID roles (AcrPull/AcrPush) and workload identity."})
                if rp.get("publicNetworkAccess", "Enabled") == "Enabled":
                    out.findings.append({"engine": "cloud", "rule_id": "NM-AZ-ACR-002", "title": f"ACR {reg['name']}: public network access enabled",
                                         "severity": "medium", "repo": f"azure:{sub}", "file": reg["id"], "exposure": "internet",
                                         "remediation": "Restrict with private endpoints or selected networks."})
            for aks in self._list(tok, f"/subscriptions/{sub}/providers/Microsoft.ContainerService/managedClusters", "2024-02-01"):
                kp = aks.get("properties", {})
                out.assets.append({"type": "kubernetes-cluster", "id": aks["id"]})
                if not kp.get("disableLocalAccounts"):
                    out.findings.append({"engine": "cloud", "rule_id": "NM-AZ-AKS-001", "title": f"AKS {aks['name']}: local accounts enabled",
                                         "severity": "high", "repo": f"azure:{sub}", "file": aks["id"], "exposure": "internal",
                                         "remediation": "Set disableLocalAccounts=true and use Entra ID integration with Kubernetes RBAC."})
                if not (kp.get("addonProfiles", {}).get("azurepolicy", {}).get("enabled")):
                    out.findings.append({"engine": "cloud", "rule_id": "NM-AZ-AKS-002", "title": f"AKS {aks['name']}: Azure Policy add-on disabled",
                                         "severity": "medium", "repo": f"azure:{sub}", "file": aks["id"], "exposure": "internal",
                                         "remediation": "Enable the Azure Policy add-on; NERvvE DevSecOps admission policies can run alongside."})
        return out
