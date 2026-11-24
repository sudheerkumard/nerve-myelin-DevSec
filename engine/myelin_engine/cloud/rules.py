# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Rule framework shared by cloud posture (CSPM), Kubernetes posture (KSPM) and identity (CIEM) checks."""
from dataclasses import dataclass, field
from typing import Callable

CATEGORIES = {
    "exposure": "Network exposure", "data": "Data protection", "encryption": "Encryption in transit and at rest",
    "identity": "Identity and access", "logging": "Logging and threat detection", "workload": "Workload hardening",
    "kubernetes": "Kubernetes control plane", "rbac": "Kubernetes RBAC", "runtime": "Runtime threat", "path": "Attack path",
}
# Category -> framework controls the finding bears on (same structure as frameworks.BY_ENGINE).
CONTROLS = {
    "exposure": {"pci": ["1.3.1"], "iso": ["8.20"], "nist": ["SC-7"], "soc2": ["CC6.6"]},
    "data": {"pci": ["3.5.1"], "iso": ["8.3", "8.12"], "nist": ["AC-3", "SC-28"], "soc2": ["CC6.1"]},
    "encryption": {"pci": ["4.2.1"], "iso": ["8.24"], "nist": ["SC-8", "SC-13"], "soc2": ["CC6.7"]},
    "identity": {"pci": ["7.2.1", "8.4.2"], "iso": ["5.15", "5.18", "8.2"], "nist": ["AC-2", "AC-6", "IA-2"], "soc2": ["CC6.1", "CC6.3"]},
    "logging": {"pci": ["10.2.1"], "iso": ["8.15", "8.16"], "nist": ["AU-2", "SI-4"], "soc2": ["CC7.2"]},
    "workload": {"pci": ["2.2"], "iso": ["8.9"], "nist": ["CM-6", "CM-7"], "soc2": ["CC7.1"]},
    "kubernetes": {"pci": ["2.2"], "iso": ["8.9", "8.20"], "nist": ["CM-6", "SC-7"], "soc2": ["CC6.6"]},
    "rbac": {"pci": ["7.2.1"], "iso": ["5.15", "8.2"], "nist": ["AC-6"], "soc2": ["CC6.3"]},
    "runtime": {"pci": ["11.5.1"], "iso": ["8.16"], "nist": ["SI-4", "IR-4"], "soc2": ["CC7.2", "CC7.3"]},
    "path": {"pci": ["6.3.1"], "iso": ["8.8"], "nist": ["RA-3", "RA-5"], "soc2": ["CC3.2", "CC7.1"]},
}


@dataclass
class Rule:
    id: str
    rtype: str
    severity: str
    title: str
    category: str
    remediation: str
    check: Callable = field(repr=False)
    cis: str = ""
    internet: bool = False
    engine: str = "cspm"


def repo_key(inv: dict) -> str:
    return f"k8s:{inv['account']}" if inv["provider"] == "kubernetes" else f"cloud:{inv['provider']}:{inv['account']}"


CODE_TAGS = {"git_repo": "repo", "myelin_repo": "repo", "myelin.io/repo": "repo", "app.myelin.io/repo": "repo", "repository": "repo",
             "git_file": "file", "myelin.io/file": "file", "git_commit": "commit", "myelin.io/commit": "commit", "git_org": "org"}


def code_link(res: dict) -> dict | None:
    """Code-to-cloud: the repository (and IaC file / commit) that created a resource, from tags written by the IaC
    pipeline (git_repo / git_file / git_commit, or myelin.io/repo annotations on Kubernetes objects)."""
    src = {}
    for bag in (res.get("tags") or {}, (res.get("props") or {}).get("labels") or {}, (res.get("props") or {}).get("annotations") or {}):
        for k, v in bag.items():
            key = CODE_TAGS.get(str(k).lower())
            if key and v and key not in src:
                src[key] = str(v).rstrip("/").split("/")[-1] if key == "repo" else str(v)
    return {k: src[k] for k in ("repo", "file", "commit") if k in src} if src.get("repo") else None


def finding(inv: dict, res: dict, rule: Rule, evidence: str, severity: str | None = None, extra: dict | None = None) -> dict:
    f = {"engine": rule.engine, "rule_id": rule.id, "title": f"{res.get('name') or res['id']}: {rule.title}",
         "severity": severity or rule.severity, "file": res["id"], "line": None, "repo": repo_key(inv),
         "resource": {"id": res["id"], "type": res["type"], "name": res.get("name"), "region": res.get("region", "")},
         "provider": inv["provider"], "account": inv["account"], "category": rule.category, "remediation": rule.remediation,
         "evidence": evidence, "exposure": "internet" if rule.internet else "internal", "cis": rule.cis, "reachable": True}
    link = code_link(res)
    if link:
        f["source"] = link
    if extra:
        f.update(extra)
    return f


def run(inv: dict, rules: list[Rule], ctx) -> list[dict]:
    out = []
    for res in inv.get("resources") or []:
        for r in rules:
            if r.rtype != res["type"]:
                continue
            got = r.check(res["props"], ctx, res)
            if not got:
                continue
            ev, sev = (got if isinstance(got, tuple) else (got, None))
            out.append(finding(inv, res, r, ev if isinstance(ev, str) else r.title, sev))
    return out
