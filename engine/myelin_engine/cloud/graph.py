# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Code-to-cloud correlation and attack paths across cloud accounts, clusters and repositories.

An attack path is reported when three things line up on one workload:
  1. exposure   the workload is reachable from the internet (public IP + open security group / NSG / firewall,
                a public LoadBalancer or Ingress, an unauthenticated function URL, a public web app);
  2. weakness   it runs code or an image with an exploitable weakness (critical/high or known-exploited vulnerability
                in the linked repository or image, a critical misconfiguration on the workload, or a runtime detection);
  3. impact     its identity holds administrative or write rights, or it can reach a data store.

Workloads are linked to repositories by IaC tags (git_repo / git_file / git_commit), myelin.io/repo annotations, or the
image name; links are shown with the evidence they came from so an analyst can confirm them."""
import hashlib

from .inventory import exposed_ports, is_internet
from .rules import repo_key

WEAK_ENGINES = {"sca", "container", "sast", "secrets", "supply", "dast"}
DATA_TYPES = {"azure.storage_account", "azure.sql_server", "azure.key_vault", "azure.cosmos", "aws.s3_bucket", "aws.rds_instance",
              "gcp.bucket", "gcp.sql_instance"}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def image_repo(image: str, repos: set[str]) -> str | None:
    """ghcr.io/acme/payments-web:1.4.2 -> payments-web when a repository of that name is known."""
    if not image:
        return None
    name = image.split("@")[0].rsplit("/", 1)[-1].split(":")[0].lower()
    for r in repos:
        rl = r.lower().rsplit("/", 1)[-1]
        if rl == name or (len(rl) > 3 and (name.startswith(rl + "-") or rl.startswith(name + "-")) and abs(len(rl) - len(name)) <= 8):
            return r
    return None


def _workloads(inv, all_inv, repos):
    """Workloads with exposure evidence, attached identities and repository links."""
    res = inv.get("resources") or []
    by_id = {r["id"].lower(): r for r in res}
    out = []
    p = inv["provider"]
    if p == "azure":
        nsgs = [r for r in res if r["type"] == "azure.nsg"]
        nics = {r["id"].lower(): r for r in res if r["type"] == "azure.nic"}
        for vm in [r for r in res if r["type"] == "azure.vm"]:
            exposure = []
            for nid in vm["props"].get("nics") or []:
                nic = nics.get(str(nid).lower())
                if not nic or not nic["props"].get("public_ips"):
                    continue
                ids = {str(nid).lower()} | {str(s).lower() for s in nic["props"].get("subnets") or []}
                if nic["props"].get("nsg"):
                    ids.add(str(nic["props"]["nsg"]).lower())
                applied = [g for g in nsgs if g["id"].lower() in ids or {str(a).lower() for a in g["props"].get("attached") or []} & ids]
                if not applied:
                    sku = (by_id.get(str(nic["props"]["public_ips"][0]).lower()) or {}).get("props", {}).get("sku", "Basic")
                    if str(sku).lower() == "basic":
                        exposure.append("public IP (Basic SKU) without a network security group")
                for g in applied:
                    e = exposed_ports(g["props"].get("ingress"))
                    if e["any"]:
                        exposure.append(f"public IP; {g['name']} allows internet traffic" + (" on all ports" if e["all"] else ""))
            out.append({"res": vm, "exposure": exposure, "identities": vm["props"].get("identities") or []})
        for w in [r for r in res if r["type"] == "azure.webapp"]:
            out.append({"res": w, "exposure": [f"public endpoint {w['props'].get('hostnames') or ''}".strip()] if w["props"].get("public_network") else [],
                        "identities": w["props"].get("identities") or []})
    elif p == "aws":
        sgs = {r["props"].get("group_id"): r for r in res if r["type"] == "aws.security_group"}
        roles = {pr: i["id"] for i in inv.get("identities") or [] for pr in i.get("instance_profiles") or []}
        for i in [r for r in res if r["type"] == "aws.instance"]:
            exposure = []
            if i["props"].get("public_ip"):
                for gid in i["props"].get("security_groups") or []:
                    e = exposed_ports((sgs.get(gid) or {}).get("props", {}).get("ingress"))
                    if e["any"]:
                        exposure.append(f"public IP {i['props']['public_ip']}; {gid} allows internet traffic" + (" on all ports" if e["all"] else ""))
            role = roles.get(i["props"].get("role")) or i["props"].get("role")
            out.append({"res": i, "exposure": exposure, "identities": [role] if role else []})
        for f in [r for r in res if r["type"] == "aws.lambda"]:
            out.append({"res": f, "exposure": ["function URL without authentication"] if f["props"].get("url_auth") == "NONE" else [],
                        "identities": [f["props"]["role"]] if f["props"].get("role") else []})
    elif p == "gcp":
        fws = [r for r in res if r["type"] == "gcp.firewall"]
        for i in [r for r in res if r["type"] == "gcp.instance"]:
            exposure = []
            if i["props"].get("public_ip"):
                for fw in fws:
                    tg, nets = fw["props"].get("targets") or [], i["props"].get("network") or []
                    if fw["props"].get("network") and nets and fw["props"]["network"] not in nets:
                        continue
                    if tg and not set(tg) & set(i["props"].get("net_tags") or []):
                        continue
                    if fw["props"].get("target_sas") and i["props"].get("service_account") not in fw["props"]["target_sas"]:
                        continue
                    e = exposed_ports(fw["props"].get("ingress"))
                    if e["any"]:
                        exposure.append(f"external IP; firewall {fw['name']} allows internet traffic" + (" on all ports" if e["all"] else ""))
            sa = i["props"].get("service_account")
            out.append({"res": i, "exposure": exposure, "identities": [sa] if sa else []})
    elif p == "kubernetes":
        services = [r for r in res if r["type"] == "k8s.service"]
        ingresses = [r for r in res if r["type"] == "k8s.ingress"]
        sas = {f"{r['props'].get('namespace')}/{r['name']}": r for r in res if r["type"] == "k8s.service_account"}
        for w in [r for r in res if r["type"] == "k8s.workload"]:
            ns, labels = w["props"].get("namespace"), w["props"].get("pod_labels") or {}
            exposure = []
            for s in services:
                sel = s["props"].get("selector") or {}
                if s["props"].get("namespace") != ns or not sel or any(labels.get(k) != v for k, v in sel.items()):
                    continue
                if s["props"].get("service_type") == "LoadBalancer" and not s["props"].get("internal_lb") and \
                        (not s["props"].get("source_ranges") or any(is_internet(x) for x in s["props"]["source_ranges"])):
                    exposure.append(f"public LoadBalancer {s['name']}")
                for ing in ingresses:
                    if ing["props"].get("namespace") == ns and s["name"] in (ing["props"].get("services") or []):
                        exposure.append(f"ingress {ing['name']} ({', '.join(ing['props'].get('hosts') or ['*'])})")
            sa_name = f"{ns}/{w['props'].get('service_account', 'default')}"
            ids = [f"system:serviceaccount:{ns}:{w['props'].get('service_account', 'default')}", "system:authenticated",
                   "system:serviceaccounts", f"system:serviceaccounts:{ns}"]
            cloud_id = (sas.get(sa_name) or {}).get("props", {}).get("cloud_identity")
            if cloud_id:
                ids.append(cloud_id)
            out.append({"res": w, "exposure": exposure, "identities": ids, "display": f"service account {sa_name}"})
    for w in out:
        w["inv"] = inv
        w["links"] = _links(w["res"], repos)
    return out


def _links(res, repos):
    from .rules import code_link
    links = []
    cl = code_link(res)
    if cl and cl["repo"] in repos:
        links.append({**cl, "via": "IaC tags" if res["type"] != "k8s.workload" else "annotation"})
    elif cl:
        match = next((r for r in repos if r.lower().rsplit("/", 1)[-1] == cl["repo"].lower()), None)
        if match:
            links.append({**cl, "repo": match, "via": "IaC tags"})
    for img in (res.get("props") or {}).get("images") or []:
        r = image_repo(img, repos)
        if r and not any(x["repo"] == r for x in links):
            links.append({"repo": r, "via": f"image {img}"})
    return links


def _identity_impact(ids, all_inv):
    """Highest privilege and data stores reachable by the identities, across every inventory (IRSA / workload identity).
    Data reach: administrative rights at account scope reach every data store; write rights at account scope reach them
    when the role is not action-scoped (Azure Contributor, GCP Editor); otherwise grants reach data stores inside their
    scope, AWS policies through data-service actions (s3:, rds:, dynamodb:) and Kubernetes roles through Secret access."""
    from .ciem import _grants
    best, grants, data, name = "", [], [], ""
    rank = {"admin": 3, "write": 2, "read": 1, "": 0}
    wanted = {str(i).lower() for i in ids if i}
    for inv in all_inv:
        names = {str(i["id"]).lower(): i.get("name") for i in inv.get("identities") or []}
        stores = [r for r in inv.get("resources") or [] if r["type"] in DATA_TYPES]
        for g in _grants(inv):
            if str(g.get("principal", "")).lower() not in wanted:
                continue
            name = name or names.get(str(g["principal"]).lower()) or g["principal"]
            pr = g.get("privilege") or "read"
            grants.append({"role": g["role"], "scope": g["scope"], "privilege": pr, "account": inv["account"]})
            if rank.get(pr, 0) > rank.get(best, 0):
                best = pr
            acts = {a.split("@")[0].lower() for a in g.get("actions") or []}
            broad = g.get("scope_level") in ("organisation", "account")
            if broad and (pr == "admin" or (pr == "write" and (not acts or "*" in acts))):
                data += stores
            elif g.get("scope") and not broad:
                data += [r for r in stores if r["id"].lower().startswith(str(g["scope"]).lower())]
            for r in stores:
                prefix = {"aws.s3_bucket": ("s3:",), "aws.rds_instance": ("rds:", "rds-data:", "rds-db:")}.get(r["type"])
                if prefix and any(a.startswith(prefix) for a in acts):
                    data.append(r)
            if g.get("secrets"):
                data.append({"id": f"secrets/{inv['account']}/{g['scope']}", "type": "k8s.secrets",
                             "name": "Kubernetes Secrets (all namespaces)" if g["scope"] == "cluster" else f"Kubernetes Secrets in {g['scope']}"})
    uniq = {r["id"]: r for r in data}
    return best, grants[:10], list(uniq.values())[:10], name


def attack_paths(inventories: list[dict], findings: list[dict], repos: list[str]) -> list[dict]:
    repos_s = set(repos or [])
    open_f = [f for f in findings if f.get("status", "open") == "open"]
    by_repo, by_file = {}, {}
    for f in open_f:
        by_repo.setdefault(f.get("repo"), []).append(f)
        by_file.setdefault(f.get("file"), []).append(f)
    runtime = {}
    for f in open_f:
        if f.get("engine") == "runtime":
            runtime.setdefault((f.get("account"), f.get("namespace"), f.get("workload")), []).append(f)
    paths = []
    for inv in inventories:
        for w in _workloads(inv, inventories, repos_s):
            if not w["exposure"]:
                continue
            res = w["res"]
            weak = []
            for link in w["links"]:
                for f in by_repo.get(link["repo"], []):
                    if f.get("engine") in WEAK_ENGINES and (f.get("severity") in ("critical", "high") or f.get("kev")):
                        weak.append(f)
            weak += [f for f in by_file.get(res["id"], []) if f.get("severity") in ("critical", "high") and f.get("engine") in ("cspm", "kspm")
                     and f.get("category") != "exposure"]
            rt = runtime.get((inv["account"], res["props"].get("namespace"), res["name"]), []) if inv["provider"] == "kubernetes" else []
            weak = sorted({f.get("fingerprint") or f.get("id"): f for f in weak}.values(), key=lambda f: (-int(bool(f.get("kev"))), -SEV_RANK.get(f.get("severity"), 0), -float(f.get("mrs") or 0)))
            if not weak and not rt:
                continue
            priv, grants, data, who = _identity_impact(w["identities"], inventories)
            if priv != "admin" and not data:
                continue
            score = 55 + (20 if any(f.get("kev") or f.get("severity") == "critical" for f in weak) else 10 if weak else 0) + \
                (15 if rt else 0) + (15 if priv == "admin" else 8 if priv == "write" else 0) + (10 if data else 0)
            score = min(100, score)
            steps = [{"kind": "internet", "label": "Internet"},
                     {"kind": "exposure", "label": w["exposure"][0], "detail": w["exposure"][1:4]},
                     {"kind": "workload", "label": f"{res['name']} ({res['type'].split('.')[-1]})", "id": res["id"],
                      "repo": [l["repo"] for l in w["links"]]}]
            if weak:
                top = weak[0]
                steps.append({"kind": "weakness", "label": top.get("title"), "finding": top.get("id"), "severity": top.get("severity"),
                              "kev": bool(top.get("kev")), "more": len(weak) - 1})
            if rt:
                steps.append({"kind": "runtime", "label": rt[0].get("title"), "finding": rt[0].get("id"), "count": sum(int(x.get("event_count") or 1) for x in rt)})
            if priv:
                steps.append({"kind": "identity", "label": f"{w.get('display') or who or w['identities'][0]} ({priv})", "grants": grants[:5]})
            if data:
                steps.append({"kind": "data", "label": ", ".join(d["name"] for d in data[:3]) + (f" and {len(data) - 3} more" if len(data) > 3 else ""),
                              "items": [d["name"] for d in data[:10]]})
            pid = hashlib.sha256(f"{inv['provider']}|{inv['account']}|{res['id']}".encode()).hexdigest()[:12]
            title = (f"{res['name']}: internet-exposed, " + ("under active runtime attack" if rt else "vulnerable") +
                     (", with administrative cloud rights" if priv == "admin" else ", with write rights" if priv == "write" else "") +
                     (f" and access to {len(data)} data store(s)" if data else ""))
            paths.append({"id": f"PATH-{pid.upper()}", "title": title, "score": score, "severity": "critical" if score >= 85 else "high",
                          "provider": inv["provider"], "account": inv["account"], "resource": {"id": res["id"], "type": res["type"], "name": res["name"]},
                          "steps": steps, "links": w["links"], "weaknesses": [f.get("id") for f in weak[:10]], "runtime": [f.get("id") for f in rt[:5]],
                          "repo": repo_key(inv)})
    return sorted(paths, key=lambda x: -x["score"])


def path_findings(paths: list[dict]) -> list[dict]:
    out = []
    for p in paths:
        out.append({"engine": "paths", "rule_id": "NM-PATH-001", "title": p["title"], "severity": p["severity"], "file": p["resource"]["id"],
                    "line": None, "repo": p["repo"], "category": "path", "provider": p["provider"], "account": p["account"],
                    "resource": p["resource"], "path": p["steps"], "path_id": p["id"], "linked_repos": [l["repo"] for l in p["links"]],
                    "evidence": " → ".join(s["label"] for s in p["steps"])[:900], "exposure": "internet", "reachable": True,
                    "exploited_weakness": any(s["kind"] == "runtime" or (s["kind"] == "weakness" and s.get("kev")) for s in p["steps"]),
                    "remediation": "Break the path at its cheapest link: close the exposure, fix the weakness (linked findings), or reduce the "
                                   "identity's rights to what the workload needs.", "cis": ""})
    return out


def code_to_cloud(inventories: list[dict], repos: list[str]) -> list[dict]:
    """Every cloud or cluster resource linked to a repository, with the evidence of the link."""
    out = []
    for inv in inventories:
        for r in inv.get("resources") or []:
            if r["type"] == "k8s.pod":          # running pods are shown through their workload
                continue
            for link in _links(r, set(repos or [])):
                out.append({"repo": link["repo"], "via": link["via"], "file": link.get("file"), "commit": link.get("commit"),
                            "resource": {"id": r["id"], "type": r["type"], "name": r["name"]}, "provider": inv["provider"], "account": inv["account"]})
    return out
