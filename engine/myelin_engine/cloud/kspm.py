# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Kubernetes security posture (KSPM): workload hardening (Pod Security Standards), namespace isolation, exposure and
RBAC, evaluated on the normalised inventory of a live cluster (read-only service account) or `kubectl get -o json`.

System namespaces are excluded from workload rules by default (MYELIN_KSPM_EXCLUDE_NS); RBAC rules always run."""
import os
import re

from .rules import Rule, finding

CIS_K8S = "CIS Kubernetes Benchmark"
PSS = "Pod Security Standards"
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF", "PERFMON", "SYS_BOOT"}
CRITICAL_HOSTPATHS = re.compile(r"^(/|/etc/?|/root/?|/var/run/docker\.sock|/var/run/containerd.*|/run/containerd.*|/var/lib/kubelet.*|/proc/?|/sys/?|/var/run/crio.*)$")
BUILTIN_ROLES = {"cluster-admin", "admin", "edit", "view"}
SYSTEM_SUBJECT = re.compile(r"^(system:(masters|kube-|node|serviceaccount:kube-system:|controller|certificates|bootstrap|volume-scheduler|monitoring|public-info)|eks:|aks-|gke-|cloud-provider)")
BENIGN_PUBLIC_ROLES = {"system:basic-user", "system:discovery", "system:public-info-viewer", "system:service-account-issuer-discovery"}
PUBLIC_GROUPS = {"system:anonymous", "system:unauthenticated", "system:authenticated"}
RULES: list[Rule] = []


def _excluded():
    return {x.strip() for x in os.environ.get("MYELIN_KSPM_EXCLUDE_NS", "kube-system,kube-public,kube-node-lease").split(",") if x.strip()}


def min_minor() -> int:
    try:
        return int(os.environ.get("MYELIN_K8S_MIN_MINOR", "31"))
    except ValueError:
        return 31


def rule(rid, rtype, sev, title, category, remediation, cis=CIS_K8S, internet=False):
    def deco(fn):
        RULES.append(Rule(rid, rtype, sev, title, category, remediation, fn, cis, internet, engine="kspm"))
        return fn
    return deco


def _containers(p):
    return (p.get("spec") or {}).get("containers") or []


def _sc(c):
    return c.get("securityContext") or {}


def _psc(p):
    return (p.get("spec") or {}).get("securityContext") or {}


def _each(p, pred):
    hits = [c.get("name") for c in _containers(p) if pred(c)]
    return hits and "containers: " + ", ".join(str(h) for h in hits)


# ---------------------------------------------------------------- workloads
@rule("NM-K8S-001", "k8s.workload", "critical", "privileged container", "workload",
      "Remove privileged: true; grant only the specific capability the workload needs.", f"{PSS} (baseline)")
def _(p, c, r): return _each(p, lambda x: _sc(x).get("privileged") is True)


@rule("NM-K8S-002", "k8s.workload", "medium", "privilege escalation is not blocked", "workload",
      "Set allowPrivilegeEscalation: false in every container's securityContext.", f"{PSS} (restricted)")
def _(p, c, r): return _each(p, lambda x: _sc(x).get("allowPrivilegeEscalation") is not False)


@rule("NM-K8S-003", "k8s.workload", "medium", "containers may run as root", "workload",
      "Set runAsNonRoot: true (and a non-zero runAsUser) at pod or container level.", f"{PSS} (restricted)")
def _(p, c, r):
    pod = _psc(p)
    def root(x):
        s = _sc(x)
        nonroot = s.get("runAsNonRoot", pod.get("runAsNonRoot"))
        uid = s.get("runAsUser", pod.get("runAsUser"))
        return not (nonroot is True or (isinstance(uid, int) and uid > 0)) or uid == 0
    return _each(p, root)


@rule("NM-K8S-004", "k8s.workload", "high", "shares the host network, PID or IPC namespace", "workload",
      "Remove hostNetwork, hostPID and hostIPC.", f"{PSS} (baseline)")
def _(p, c, r):
    s = p.get("spec") or {}
    on = [k for k in ("hostNetwork", "hostPID", "hostIPC") if s.get(k)]
    return on and ", ".join(on) + " = true"


@rule("NM-K8S-005", "k8s.workload", "high", "mounts a host path", "workload",
      "Replace hostPath volumes with persistent volumes, ConfigMaps or CSI drivers.", f"{PSS} (baseline)")
def _(p, c, r):
    paths = [(v.get("hostPath") or {}).get("path", "") for v in (p.get("spec") or {}).get("volumes") or [] if v.get("hostPath")]
    if not paths:
        return None
    crit = [x for x in paths if CRITICAL_HOSTPATHS.match(x)]
    return ("mounts " + ", ".join(crit) + " from the node (container escape)", "critical") if crit else "hostPath: " + ", ".join(paths)


@rule("NM-K8S-006", "k8s.workload", "high", "adds dangerous Linux capabilities", "workload",
      "Drop ALL capabilities and add back only NET_BIND_SERVICE if needed.", f"{PSS} (baseline)")
def _(p, c, r):
    hits = []
    for x in _containers(p):
        add = {str(a).upper().replace("CAP_", "") for a in ((_sc(x).get("capabilities") or {}).get("add") or [])}
        if add & DANGEROUS_CAPS:
            hits.append(f"{x.get('name')}: {', '.join(sorted(add & DANGEROUS_CAPS))}")
    return hits and "; ".join(hits)


@rule("NM-K8S-007", "k8s.workload", "low", "capabilities are not dropped", "workload",
      "Add capabilities.drop: [ALL] to every container.", f"{PSS} (restricted)")
def _(p, c, r): return _each(p, lambda x: "ALL" not in {str(d).upper() for d in ((_sc(x).get("capabilities") or {}).get("drop") or [])})


@rule("NM-K8S-008", "k8s.workload", "low", "root filesystem is writable", "workload",
      "Set readOnlyRootFilesystem: true and mount emptyDir volumes for paths that must be written.", CIS_K8S)
def _(p, c, r): return _each(p, lambda x: _sc(x).get("readOnlyRootFilesystem") is not True)


@rule("NM-K8S-009", "k8s.workload", "low", "no CPU or memory limit", "workload",
      "Set resources.limits for memory (and CPU) so one workload cannot exhaust the node.", CIS_K8S)
def _(p, c, r): return _each(p, lambda x: not ((x.get("resources") or {}).get("limits") or {}).get("memory"))


@rule("NM-K8S-010", "k8s.workload", "medium", "image is not pinned (latest or no tag)", "workload",
      "Deploy an immutable tag or, better, the image digest (image@sha256:...).", CIS_K8S)
def _(p, c, r):
    bad = [i for i in p.get("images") or [] if i and "@sha256:" not in i and (":" not in i.rsplit("/", 1)[-1] or i.endswith(":latest"))]
    return bad and "images: " + ", ".join(bad)


@rule("NM-K8S-011", "k8s.workload", "high", "secret value set as a literal environment variable", "data",
      "Move the value to a Secret (or an external secret store) and reference it with secretKeyRef.", CIS_K8S)
def _(p, c, r):
    hits = [f"{e['container']}.{e['name']}" for e in p.get("env") or [] if e.get("literal_secret")]
    return hits and "literal values in: " + ", ".join(hits)


@rule("NM-K8S-012", "k8s.workload", "low", "default service account token is mounted", "identity",
      "Use a dedicated service account, or set automountServiceAccountToken: false when the API is not needed.", CIS_K8S)
def _(p, c, r):
    s = p.get("spec") or {}
    return p.get("service_account", "default") == "default" and s.get("automountServiceAccountToken") is not False \
        and c.get("sa_automount", {}).get(f"{p.get('namespace')}/default", True) and "uses the default service account with a mounted token"


@rule("NM-K8S-013", "k8s.workload", "low", "no seccomp profile", "workload",
      "Set seccompProfile.type: RuntimeDefault at pod level.", f"{PSS} (restricted)")
def _(p, c, r):
    pod = (_psc(p).get("seccompProfile") or {}).get("type")
    return _each(p, lambda x: ((_sc(x).get("seccompProfile") or {}).get("type") or pod) not in ("RuntimeDefault", "Localhost"))


@rule("NM-K8S-014", "k8s.workload", "low", "runs in the default namespace", "kubernetes",
      "Deploy workloads into dedicated namespaces with their own policies and quotas.", CIS_K8S)
def _(p, c, r): return p.get("namespace") == "default" and "namespace = default"


# ---------------------------------------------------------------- namespaces and exposure
@rule("NM-K8S-015", "k8s.namespace", "medium", "no NetworkPolicy isolates this namespace", "exposure",
      "Add a default-deny NetworkPolicy and allow only the flows the applications need.", CIS_K8S)
def _(p, c, r): return r["name"] not in c["netpol_ns"] and c["workload_ns"].get(r["name"]) and "no NetworkPolicy in a namespace with workloads"


@rule("NM-K8S-016", "k8s.namespace", "medium", "Pod Security admission is not enforcing", "kubernetes",
      "Label the namespace pod-security.kubernetes.io/enforce=restricted (or baseline).", f"{PSS}")
def _(p, c, r):
    lvl = (p.get("labels") or {}).get("pod-security.kubernetes.io/enforce")
    return c["workload_ns"].get(r["name"]) and lvl in (None, "", "privileged") and f"enforce label = {lvl or 'not set'}"


@rule("NM-K8S-017", "k8s.service", "medium", "LoadBalancer is open to the internet without source ranges", "exposure",
      "Set loadBalancerSourceRanges, use an internal load balancer, or publish through an authenticated ingress.", CIS_K8S, True)
def _(p, c, r):
    return p.get("service_type") == "LoadBalancer" and not p.get("internal_lb") and \
        (not p.get("source_ranges") or any(x in ("0.0.0.0/0", "::/0") for x in p["source_ranges"])) and \
        f"type LoadBalancer on ports {', '.join(str(x) for x in p.get('ports') or [])}"


@rule("NM-K8S-018", "k8s.service", "low", "NodePort opens a port on every node", "exposure",
      "Prefer ClusterIP behind an ingress or an internal load balancer.", CIS_K8S)
def _(p, c, r): return p.get("service_type") == "NodePort" and "type NodePort"


@rule("NM-K8S-019", "k8s.ingress", "medium", "ingress serves traffic without TLS", "encryption",
      "Add a tls section with a certificate (for example from cert-manager).", CIS_K8S, True)
def _(p, c, r): return not p.get("tls") and "no tls section for hosts: " + ", ".join(p.get("hosts") or ["*"])


# ---------------------------------------------------------------- RBAC
def _rule_hits(rules, verbs, resources):
    for x in rules or []:
        v = {str(a) for a in x.get("verbs") or []}
        res = {str(a) for a in x.get("resources") or []}
        if (v & verbs or "*" in v) and (res & resources or "*" in res):
            return True
    return False


@rule("NM-K8S-022", "k8s.role", "high", "role grants every verb on every resource", "rbac",
      "Replace wildcards with the specific verbs and resources the subject needs.", f"{CIS_K8S} §RBAC")
def _(p, c, r):
    if r["name"] in BUILTIN_ROLES or r["name"].startswith("system:") or p.get("aggregated"):
        return None
    return any("*" in (x.get("verbs") or []) and "*" in (x.get("resources") or []) for x in p.get("rules") or []) and "verbs: [*], resources: [*]"


@rule("NM-K8S-023", "k8s.role", "medium", "role can read Secrets", "rbac",
      "Limit Secret access to named secrets (resourceNames) in one namespace.", f"{CIS_K8S} §RBAC")
def _(p, c, r):
    if r["name"] in BUILTIN_ROLES or r["name"].startswith("system:") or p.get("aggregated"):
        return None
    if not _rule_hits(p.get("rules"), {"get", "list", "watch"}, {"secrets"}):
        return None
    return ("cluster-wide read access to Secrets", "high") if p.get("cluster_scoped") else "read access to Secrets in the namespace"


@rule("NM-K8S-024", "k8s.role", "high", "role allows privilege escalation", "rbac",
      "Remove escalate, bind and impersonate, and pod creation or exec, unless the subject is a trusted controller.", f"{CIS_K8S} §RBAC")
def _(p, c, r):
    if r["name"] in BUILTIN_ROLES or r["name"].startswith("system:") or p.get("aggregated"):
        return None
    hits = []
    if _rule_hits(p.get("rules"), {"escalate", "bind"}, {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}):
        hits.append("escalate/bind on roles")
    if _rule_hits(p.get("rules"), {"impersonate"}, {"users", "groups", "serviceaccounts"}):
        hits.append("impersonate")
    if _rule_hits(p.get("rules"), {"create"}, {"pods/exec", "pods/attach"}):
        hits.append("pods/exec")
    if _rule_hits(p.get("rules"), {"create"}, {"pods", "deployments", "daemonsets", "jobs", "cronjobs"}):
        hits.append("create workloads")
    if _rule_hits(p.get("rules"), {"create"}, {"serviceaccounts/token"}):
        hits.append("mint service-account tokens")
    return hits and ", ".join(hits)


@rule("NM-K8S-025", "k8s.node", "medium", "node runs an unsupported Kubernetes version", "kubernetes",
      "Upgrade the cluster and node pools to a supported Kubernetes minor version.", CIS_K8S)
def _(p, c, r):
    m = re.match(r"v?1\.(\d+)", str(p.get("kubelet") or ""))
    return m and int(m.group(1)) < min_minor() and f"kubelet {p.get('kubelet')} (minimum supported 1.{min_minor()})"


def _binding_findings(inv, roles):
    out = []
    R020 = Rule("NM-K8S-020", "k8s.binding", "high", "cluster-admin is bound to a non-system subject", "rbac",
                "Bind narrower roles; keep cluster-admin for break-glass identities only.", lambda *a: None, cis=f"{CIS_K8S} §RBAC", engine="kspm")
    R021 = Rule("NM-K8S-021", "k8s.binding", "critical", "role is granted to anonymous or all authenticated users", "rbac",
                "Remove system:anonymous, system:unauthenticated and system:authenticated subjects.", lambda *a: None, cis=f"{CIS_K8S} §RBAC", engine="kspm")
    for g in inv.get("grants") or []:
        who, role = str(g.get("principal")), str(g.get("role", ""))
        res = {"id": g.get("binding") or f"binding/{who}/{role}", "type": "k8s.binding", "name": (g.get("binding") or role).split("/")[-1],
               "region": g.get("scope", ""), "tags": {}, "props": {}}
        if who in PUBLIC_GROUPS and role.split("/")[-1] not in BENIGN_PUBLIC_ROLES:
            out.append(finding(inv, res, R021, f"{role} granted to {who}", extra={"principal": who}))
        elif role.split("/")[-1] == "cluster-admin" and not SYSTEM_SUBJECT.match(who):
            sev = "critical" if g.get("principal_kind") == "service_account" else "high"
            out.append(finding(inv, res, R020, f"cluster-admin granted to {g.get('principal_kind')} {who}", sev, extra={"principal": who}))
    return out


def evaluate(inv: dict) -> list[dict]:
    if inv.get("provider") != "kubernetes":
        return []
    excl = _excluded()
    res = inv.get("resources") or []
    ctx = {"netpol_ns": {r["props"].get("namespace") for r in res if r["type"] == "k8s.network_policy"},
           "workload_ns": {}, "sa_automount": {}}
    for r in res:
        if r["type"] == "k8s.workload":
            ctx["workload_ns"][r["props"].get("namespace")] = True
        if r["type"] == "k8s.service_account":
            ctx["sa_automount"][f"{r['props'].get('namespace')}/{r['name']}"] = r["props"].get("automount", True)
    out = []
    roles = {r["id"]: r for r in res if r["type"] == "k8s.role"}
    for r in res:
        ns = r["props"].get("namespace") if r["type"] != "k8s.namespace" else r["name"]
        if r["type"] in ("k8s.workload", "k8s.namespace", "k8s.service", "k8s.ingress") and ns in excl:
            continue
        for ru in RULES:
            if ru.rtype != r["type"]:
                continue
            got = ru.check(r["props"], ctx, r)
            if got:
                ev, sev = got if isinstance(got, tuple) else (got, None)
                out.append(finding(inv, r, ru, ev if isinstance(ev, str) else ru.title, sev, extra={"namespace": ns} if ns else None))
    return out + _binding_findings(inv, roles)


def catalogue() -> list[dict]:
    return [{"id": r.id, "type": r.rtype, "severity": r.severity, "title": r.title, "category": r.category, "cis": r.cis} for r in RULES] + [
        {"id": "NM-K8S-020", "type": "k8s.binding", "severity": "high", "title": "cluster-admin is bound to a non-system subject", "category": "rbac", "cis": f"{CIS_K8S} §RBAC"},
        {"id": "NM-K8S-021", "type": "k8s.binding", "severity": "critical", "title": "role is granted to anonymous or all authenticated users", "category": "rbac", "cis": f"{CIS_K8S} §RBAC"}]
