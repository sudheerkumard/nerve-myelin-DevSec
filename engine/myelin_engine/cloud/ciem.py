# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Cloud identity and entitlement analysis (CIEM).

Works on the identities and grants of an inventory (Azure role assignments, AWS IAM users / roles / policies, Google
Cloud IAM bindings and service-account keys, Kubernetes RBAC) and answers: who holds administrative or escalation
rights, which of those identities are unused, unprotected (no MFA, old keys), external or public, and which roles
or policies grant everything. `identities()` returns the effective-privilege view used by the console."""
from .rules import Rule, finding

KEY_MAX_AGE = 90
DORMANT_DAYS = 90
RANK = {"admin": 3, "write": 2, "read": 1, "": 0, None: 0}
CIS = {"azure": "CIS Microsoft Azure Foundations §Identity", "aws": "CIS AWS Foundations §Identity and Access Management",
       "gcp": "CIS Google Cloud Platform Foundation §Identity and Access Management", "kubernetes": "CIS Kubernetes Benchmark §RBAC"}
K8S_ADMIN_ROLES = {"cluster-admin"}


def _r(rid, sev, title, remediation, category="identity"):
    return Rule(rid, "identity", sev, title, category, remediation, lambda *a: None, "", False, engine="ciem")


R = {
    "001": _r("NM-IAM-001", "high", "workload identity holds broad rights over the whole account", "Replace the role with a least-privilege custom role scoped to the resources it uses."),
    "002": _r("NM-IAM-002", "critical", "privileged user without multi-factor authentication", "Enforce MFA (Conditional Access, IAM policy condition aws:MultiFactorAuthPresent or 2-Step Verification)."),
    "003": _r("NM-IAM-003", "medium", "access key older than 90 days", "Rotate the key, or replace it with federation, roles or workload identity."),
    "004": _r("NM-IAM-004", "medium", "active access key has not been used for 90 days", "Deactivate and delete unused keys."),
    "005": _r("NM-IAM-005", "medium", "privileged identity has been inactive for 90 days", "Remove the role assignment or the identity; use just-in-time elevation."),
    "006": _r("NM-IAM-006", "high", "external or guest identity holds a privileged role", "Remove the assignment or move the guest to a time-bound, approved elevation process."),
    "007": _r("NM-IAM-007", "critical", "access is granted to the public", "Remove allUsers / allAuthenticatedUsers / Principal \"*\" grants."),
    "008": _r("NM-IAM-008", "high", "custom role or policy grants every action", "Replace wildcards with the actions the role needs."),
    "009": _r("NM-IAM-009", "high", "identity can escalate its own privileges", "Remove permissions that change policies, role assignments or other identities' credentials."),
    "010": _r("NM-IAM-010", "high", "role can be assumed by any AWS account", "Restrict the trust policy to named principals and require sts:ExternalId for third parties."),
    "011": _r("NM-IAM-011", "critical", "root account is not protected", "Enable hardware MFA on the root user, delete root access keys and stop using root for daily work."),
    "012": _r("NM-IAM-012", "medium", "account password policy is weak", "Require at least 14 characters and prevent reuse of the last 24 passwords."),
    "013": _r("NM-IAM-013", "medium", "more than three owners at subscription scope", "Keep subscription Owner to a small break-glass group; use Contributor plus PIM for daily work."),
    "014": _r("NM-IAM-014", "medium", "service account uses user-managed keys", "Use workload identity federation or attached service accounts instead of downloadable keys."),
}
def _k8s_privilege(grant, roles):
    kind, _, name = grant["role"].partition("/")
    if name in K8S_ADMIN_ROLES:
        return "admin"
    role = roles.get((kind, "" if kind == "ClusterRole" else grant["scope"], name))
    rules = (role or {}).get("props", {}).get("rules") or []
    if any("*" in (r.get("verbs") or []) and "*" in (r.get("resources") or []) for r in rules):
        return "admin"
    if any({"escalate", "bind", "impersonate"} & set(r.get("verbs") or []) for r in rules):
        return "admin"
    if any(set(r.get("verbs") or []) - {"get", "list", "watch"} for r in rules) or any("secrets" in (r.get("resources") or []) for r in rules):
        return "write"
    return "read" if role else ("write" if name in ("admin", "edit") else "read")


def _grants(inv):
    gs = inv.get("grants") or []
    if inv["provider"] == "kubernetes":
        roles = {("ClusterRole" if r["props"].get("cluster_scoped") else "Role", "" if r["props"].get("cluster_scoped") else r["props"].get("namespace", ""),
                  r["name"]): r for r in inv.get("resources") or [] if r["type"] == "k8s.role"}
        for g in gs:
            if not g.get("privilege"):
                g["privilege"] = _k8s_privilege(g, roles)
            if "secrets" not in g:
                kind, _, name = g["role"].partition("/")
                rules = (roles.get((kind, "" if kind == "ClusterRole" else g["scope"], name)) or {}).get("props", {}).get("rules") or []
                g["secrets"] = name == "cluster-admin" or any(("secrets" in (r.get("resources") or []) or "*" in (r.get("resources") or [])) and
                                                              ({"get", "list", "watch", "*"} & set(r.get("verbs") or [])) for r in rules)
    return gs


def identities(inv: dict) -> list[dict]:
    """Effective privilege per identity: highest privilege, where it applies and the risk flags behind it."""
    gs = _grants(inv)
    by = {}
    for i in inv.get("identities") or []:
        by[i["id"]] = {**i, "provider": inv["provider"], "account": inv["account"], "grants": [], "privilege": "none", "flags": []}
    for g in gs:
        rec = by.setdefault(g["principal"], {"id": g["principal"], "name": g["principal"], "kind": g.get("principal_kind"), "provider": inv["provider"],
                                             "account": inv["account"], "grants": [], "privilege": "none", "flags": []})
        rec["grants"].append({"role": g["role"], "scope": g["scope"], "scope_level": g.get("scope_level"), "privilege": g.get("privilege")})
        if RANK.get(g.get("privilege"), 0) > RANK.get(rec["privilege"], 0):
            rec["privilege"] = g["privilege"]
    for rec in by.values():
        f = rec["flags"]
        broad = [g for g in rec["grants"] if g["privilege"] == "admin" and g["scope_level"] in ("organisation", "account")]
        if broad:
            f.append("admin over the whole " + ("organisation" if any(g["scope_level"] == "organisation" for g in broad) else "account"))
        if rec.get("mfa") is False and rec.get("console", rec.get("kind") in ("user", "root")):
            f.append("no MFA")
        if any((k.get("age_days") or 0) > KEY_MAX_AGE for k in rec.get("keys") or []):
            f.append("old access key")
        if rec["privilege"] in ("admin", "write") and (rec.get("last_used_days") or 0) >= DORMANT_DAYS:
            f.append("dormant")
        if rec.get("external") or rec.get("kind") == "guest":
            f.append("external")
        if rec.get("kind") == "public":
            f.append("public")
        rec["risk"] = min(100, RANK.get(rec["privilege"], 0) * 20 + 15 * len(f))
        rec["grants"] = rec["grants"][:50]
    return sorted(by.values(), key=lambda x: (-x["risk"], x["name"] or ""))


WORKLOAD_SERVICES = ("ec2.", "lambda.", "ecs-tasks.", "eks.", "batch.", "states.", "glue.", "sagemaker.", "codebuild.", "apprunner.")


def _is_workload(i) -> bool:
    """Machine identities: Azure service principals / managed identities, GCP service accounts, AWS roles trusted by a
    compute service or an OIDC provider (CI, Kubernetes). Human break-glass roles assumed by people are not."""
    k = i.get("kind")
    if k in ("service", "service_account"):
        return True
    if k == "role":
        t = i.get("trust") or {}
        return any(str(s).startswith(WORKLOAD_SERVICES) for s in t.get("services") or []) or bool(t.get("federated"))
    return False


def _res(inv, ident):
    return {"id": f"identity/{ident['id']}", "type": "identity", "name": ident.get("name") or ident["id"], "region": "", "tags": {}, "props": {}}


def _f(inv, ident, key, evidence, sev=None):
    rule = R[key]
    rule.cis = CIS.get(inv["provider"], "")
    return finding(inv, _res(inv, ident), rule, evidence, sev, extra={"principal": ident["id"], "principal_kind": ident.get("kind")})


def evaluate(inv: dict) -> list[dict]:
    out = []
    prov = inv["provider"]
    view = identities(inv)
    for i in view:
        kind, priv = i.get("kind"), i["privilege"]
        broad = sorted({g["privilege"] for g in i["grants"] if g["privilege"] in ("admin", "write") and g["scope_level"] in ("organisation", "account")})
        if prov != "kubernetes" and broad and _is_workload(i):
            top = "admin" if "admin" in broad else "write"
            out.append(_f(inv, i, "001", f"{top} rights at account scope: " + ", ".join(sorted({g["role"] for g in i["grants"] if g["privilege"] == top}))[:300],
                          "high" if top == "admin" else "medium"))
        if i.get("mfa") is False and kind in ("user",) and i.get("console", True) and priv in ("admin", "write"):
            out.append(_f(inv, i, "002", f"{priv} rights, console access, MFA not active", "critical" if priv == "admin" else "high"))
        for k in i.get("keys") or []:
            if k.get("active", True) and (k.get("age_days") or 0) > KEY_MAX_AGE and kind != "root":
                out.append(_f(inv, i, "003", f"key {k.get('id')} is {k['age_days']} days old"))
                break
        for k in i.get("keys") or []:
            if k.get("active", True) and k.get("last_used_days") is not None and k["last_used_days"] >= DORMANT_DAYS:
                out.append(_f(inv, i, "004", f"key {k.get('id')} last used {k['last_used_days']} days ago"))
                break
        if priv in ("admin", "write") and (i.get("last_used_days") or 0) >= DORMANT_DAYS and kind != "root":
            out.append(_f(inv, i, "005", f"{priv} rights, last activity {i['last_used_days']} days ago"))
        if (i.get("external") or kind == "guest") and priv in ("admin", "write"):
            out.append(_f(inv, i, "006", f"external identity with {priv} rights", "critical" if priv == "admin" else "high"))
        if kind == "public" and prov != "kubernetes":
            out.append(_f(inv, i, "007", "granted roles: " + ", ".join(sorted({g["role"] for g in i["grants"]}))[:300]))
        if prov == "gcp" and kind == "service_account" and [k for k in i.get("keys") or [] if k.get("active", True)]:
            out.append(_f(inv, i, "014", f"{len(i['keys'])} user-managed key(s)"))
        if prov == "aws" and kind == "role" and (i.get("trust") or {}).get("public"):
            out.append(_f(inv, i, "010", "trust policy allows Principal \"*\" without an organisation or account condition"))
        if prov == "aws" and kind == "root":
            issues = (["no MFA"] if i.get("mfa") is False else []) + (["access keys exist"] if i.get("keys") else []) + \
                     ([f"used {i['last_used_days']} days ago"] if i.get("last_used_days") is not None and i["last_used_days"] < 30 else [])
            if issues:
                out.append(_f(inv, i, "011", ", ".join(issues), None if (i.get("mfa") is False or i.get("keys")) else "medium"))
    # escalation and wildcard roles (per grant, de-duplicated per identity)
    seen = set()
    names = {i["id"]: i.get("name") or i["id"] for i in view}
    for g in _grants(inv):
        acts = {a.split("@")[0].lower() for a in g.get("actions") or []}
        ident = {"id": g["principal"], "name": names.get(g["principal"], g["principal"]), "kind": g.get("principal_kind")}
        if prov == "kubernetes":
            continue
        if not g.get("builtin") and ("*" in acts or "*:*" in acts) and (g["principal"], "008") not in seen:
            seen.add((g["principal"], "008"))
            out.append(_f(inv, ident, "008", f"{g['role']} allows every action"))
        esc = None
        if prov == "aws" and g.get("privilege") == "admin" and "*" not in acts and "*:*" not in acts and "iam:*" not in acts:
            esc = "can change its own or others' policies or credentials: " + ", ".join(sorted(a for a in acts if a.startswith(("iam:", "sts:"))))[:250]
        if prov == "azure" and any(a.lower().startswith("microsoft.authorization/roleassignments/write") for a in g.get("actions") or []) \
                and g["role"].lower() not in ("owner", "user access administrator", "role based access control administrator"):
            esc = f"{g['role']} can create role assignments"
        if prov == "gcp" and g["role"].lower() in ("roles/iam.serviceaccounttokencreator", "roles/iam.serviceaccountuser", "roles/iam.serviceaccountkeyadmin") \
                and g.get("scope_level") in ("account", "organisation"):
            esc = f"{g['role']} on the whole project lets it act as any service account"
        if esc and (g["principal"], "009") not in seen:
            seen.add((g["principal"], "009"))
            out.append(_f(inv, ident, "009", esc))
    if prov == "azure":
        owners = {g["principal"] for g in _grants(inv) if g["role"].lower() == "owner" and g.get("scope_level") == "account"}
        if len(owners) > 3:
            out.append(_f(inv, {"id": f"owners/{inv['account']}", "name": f"subscription {inv['account']}"}, "013", f"{len(owners)} principals hold Owner"))
    if prov == "aws":
        for res in inv.get("resources") or []:
            if res["type"] != "aws.account":
                continue
            pp = res["props"].get("password_policy")
            if pp is None and res["props"].get("root_mfa") is not None:
                out.append(_f(inv, {"id": f"password-policy/{inv['account']}", "name": "account password policy"}, "012", "no password policy is set"))
            elif pp and (int(pp.get("MinimumPasswordLength", 0)) < 14 or int(pp.get("PasswordReusePrevention", 0)) < 24):
                out.append(_f(inv, {"id": f"password-policy/{inv['account']}", "name": "account password policy"}, "012",
                              f"minimum length {pp.get('MinimumPasswordLength')}, reuse prevention {pp.get('PasswordReusePrevention', 0)}"))
            if res["props"].get("root_mfa") is False and not any(i.get("kind") == "root" for i in inv.get("identities") or []):
                out.append(_f(inv, {"id": f"arn:aws:iam::{inv['account']}:root", "name": "root", "kind": "root"}, "011", "no MFA on the root user"))
    return out


def catalogue() -> list[dict]:
    return [{"id": r.id, "type": "identity", "severity": r.severity, "title": r.title, "category": r.category} for r in R.values()]
