# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Continuous-delivery (CD) posture: how code reaches production.

  GitOps        Argo CD Applications / AppProjects, Flux GitRepository / HelmRelease / Kustomization
  Packaging     Helm values (image tags, secrets), Kustomize image overrides
  Deploy jobs   GitHub Actions, GitLab CI, Azure Pipelines: production deployments without an approval gate,
                deployments triggered by pull requests, `terraform apply -auto-approve`, deployments of
                images that were never verified (signature / attestation)
  Cloud CD      AWS CodeBuild buildspec, Google Cloud Build, Tekton

Findings use engine "cicd" (one pipeline view) and rule ids NM-CD-*, mapped to the OWASP Top 10 CI/CD risks.
"""
import os
import re

import yaml

RULES = {
    "NM-CD-001": ("Argo CD project allows any source repository, destination or cluster-wide resource", "high", "CICD-SEC-1",
                  "Restrict the AppProject: list the allowed sourceRepos, destinations (server + namespace) and only the cluster "
                  "resources the team needs; never '*'."),
    "NM-CD-002": ("GitOps application deploys a moving branch with automatic sync", "medium", "CICD-SEC-4",
                  "Pin targetRevision to a release tag or commit, or require manual sync for production; automated prune + "
                  "self-heal from a branch deploys whatever is pushed."),
    "NM-CD-003": ("GitOps source fetched over plain HTTP", "high", "CICD-SEC-3",
                  "Use https:// or ssh:// for repository and chart sources."),
    "NM-CD-004": ("Flux source does not verify commit or artifact signatures", "medium", "CICD-SEC-9",
                  "Add spec.verify (provider: cosign or gpg) to GitRepository / OCIRepository / HelmRepository sources."),
    "NM-CD-005": ("Helm release or chart version not pinned", "medium", "CICD-SEC-3",
                  "Pin chart versions (e.g. 1.4.2) instead of '*', ranges or 'latest'."),
    "NM-CD-006": ("Deployment image tag is 'latest' or empty", "medium", "CICD-SEC-3",
                  "Deploy immutable tags or digests (image@sha256:...) so what runs is what was scanned and signed."),
    "NM-CD-007": ("Secret value in deployment values / overlays", "high", "CICD-SEC-6",
                  "Reference a Kubernetes Secret, External Secrets / Sealed Secrets or the cloud secret manager instead."),
    "NM-CD-008": ("Production deployment without an approval gate", "high", "CICD-SEC-1",
                  "Run deploy jobs in a protected environment with required reviewers (GitHub `environment:`, Azure Pipelines "
                  "deployment job + environment checks, GitLab protected environments)."),
    "NM-CD-009": ("Deployment triggered by pull requests", "critical", "CICD-SEC-4",
                  "Deploy only from protected branches or tags after merge; pull-request code is untrusted."),
    "NM-CD-010": ("Infrastructure applied without a reviewed plan (terraform apply -auto-approve)", "medium", "CICD-SEC-1",
                  "Save a plan, require approval, then apply that plan file (terraform apply plan.tfplan)."),
    "NM-CD-011": ("Images deployed without signature or attestation verification", "medium", "CICD-SEC-9",
                  "Verify before deploying (cosign verify / verify-attestation, `myelin gate`) and enforce at admission "
                  "(for example a Kyverno verifyImages policy)."),
    "NM-CD-012": ("Plain-text secret in cloud build definition", "high", "CICD-SEC-6",
                  "AWS: env.secrets-manager / parameter-store; Google Cloud Build: availableSecrets + secretEnv."),
    "NM-CD-013": ("Build step runs privileged", "high", "CICD-SEC-7",
                  "Remove privileged mode; build images with rootless tools (BuildKit rootless, kaniko, buildah)."),
    "NM-CD-014": ("Deployment does not run the RAT Flea DevSec gate", "low", "CICD-SEC-1",
                  "Add `myelin gate` before deploying so commits blocked by policy never reach an environment."),
}
SECRET_KEY = re.compile(r"(?i)(passw(or)?d|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret)$")
NOT_SECRET = re.compile(r"(?i)(_?(file|path|ref|name|key_?ref|secret_?name|existing_?secret|env))$")
PLACEHOLDER = re.compile(r"^\s*$|^\$|^\{\{|^<.*>$|^(changeme|change-me|example|xxx+|\*+|todo|dummy|none|null|true|false|~)$", re.I)
DEPLOY_CMD = re.compile(r"\b(kubectl\s+(apply|set\s+image|rollout)|helm\s+(upgrade|install)|az\s+(webapp|containerapp|functionapp)\b[^\n]*\b(deploy|up|update|create)"
                        r"|az\s+deployment\s+\w+\s+create|aws\s+(ecs\s+update-service|deploy\s+create-deployment|lambda\s+update-function-code|cloudformation\s+deploy)"
                        r"|gcloud\s+(run\s+deploy|app\s+deploy|deploy\s+releases\s+create|functions\s+deploy)|terraform\s+apply|argocd\s+app\s+sync"
                        r"|flux\s+reconcile|kustomize\s+build[^\n]*\|\s*kubectl|serverless\s+deploy|cdk\s+deploy)", re.I)
PROD = re.compile(r"(?i)\b(prod|production|prd|live)\b")
VERIFY = re.compile(r"(?i)cosign\s+verify|verify-attestation|notation\s+verify|myelin\s+gate|slsa-verifier")


def _f(rule, file, line, repo, evidence=""):
    title, sev, owasp, fix = RULES[rule]
    return {"engine": "cicd", "rule_id": rule, "title": title, "severity": sev, "file": file, "line": line, "repo": repo,
            "owasp_cicd": owasp, "remediation": fix, "evidence": (evidence or "")[:200], "exposure": "internal", "stage": "cd"}


def _line(text, needle, default=1):
    for i, ln in enumerate(text.splitlines(), 1):
        if needle and needle in ln:
            return i
    return default


def _walk(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            yield path + (str(k),), v
            yield from _walk(v, path + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, path + (str(i),))


def _image_tag_bad(tag):
    return tag is None or str(tag).strip() in ("", "latest")


# ------------------------------------------------------------------ GitOps manifests
def gitops(docs, text, rel, repo):
    out = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        kind, api = d.get("kind"), str(d.get("apiVersion", ""))
        spec = d.get("spec") or {}
        name = (d.get("metadata") or {}).get("name", "?")
        if kind == "AppProject" and "argoproj.io" in api:
            wild = [x for x in spec.get("sourceRepos") or [] if str(x).strip() == "*"]
            wild += [x for x in spec.get("destinations") or [] if isinstance(x, dict) and
                     (str(x.get("server", "")) == "*" or str(x.get("name", "")) == "*") and str(x.get("namespace", "")) == "*"]
            wild += [x for x in spec.get("clusterResourceWhitelist") or [] if isinstance(x, dict) and
                     str(x.get("group")) == "*" and str(x.get("kind")) == "*"]
            if wild:
                out.append(_f("NM-CD-001", rel, _line(text, "'*'", _line(text, '"*"', _line(text, "*"))), repo, f"AppProject {name}"))
        if kind in ("Application", "ApplicationSet") and "argoproj.io" in api:
            sources = [spec.get("source")] + list(spec.get("sources") or [])
            tmpl = ((spec.get("template") or {}).get("spec") or {}) if kind == "ApplicationSet" else {}
            sources += [tmpl.get("source")] if tmpl else []
            auto = ((spec.get("syncPolicy") or tmpl.get("syncPolicy") or {}).get("automated"))
            for src in [s for s in sources if isinstance(s, dict)]:
                url = str(src.get("repoURL", ""))
                if url.startswith("http://"):
                    out.append(_f("NM-CD-003", rel, _line(text, url), repo, url))
                rev = str(src.get("targetRevision", "HEAD"))
                moving = rev in ("HEAD", "main", "master", "develop", "") or rev.endswith("*") or (not re.match(r"^v?\d+(\.\d+)*", rev) and
                                                                                                 not re.match(r"^[0-9a-f]{40}$", rev))
                if auto is not None and moving and not src.get("chart"):
                    out.append(_f("NM-CD-002", rel, _line(text, "automated"), repo, f"{kind} {name}: targetRevision {rev}, automated sync"))
                if src.get("chart") and (str(rev) in ("*", "", "latest", "HEAD") or re.search(r"[*x^~><]", str(rev))):
                    out.append(_f("NM-CD-005", rel, _line(text, "targetRevision"), repo, f"chart {src.get('chart')} {rev}"))
        if "fluxcd.io" in api:
            if kind in ("GitRepository", "OCIRepository", "HelmRepository", "Bucket"):
                url = str(spec.get("url", ""))
                if url.startswith("http://"):
                    out.append(_f("NM-CD-003", rel, _line(text, url), repo, url))
                if kind in ("GitRepository", "OCIRepository") and not spec.get("verify"):
                    out.append(_f("NM-CD-004", rel, _line(text, f"name: {name}"), repo, f"{kind} {name}"))
            if kind == "HelmRelease":
                ver = str((((spec.get("chart") or {}).get("spec") or {}).get("version")) or "")
                if ver in ("", "*", "latest") or re.search(r"[*x^~><]", ver):
                    out.append(_f("NM-CD-005", rel, _line(text, "version", _line(text, "chart")), repo, f"HelmRelease {name}: version '{ver or 'unset'}'"))
                out += _values(spec.get("values") or {}, text, rel, repo, f"HelmRelease {name}")
        if kind == "Kustomization" and "kustomize.config.k8s.io" in api:
            for img in d.get("images") or []:
                if isinstance(img, dict) and "newTag" in img and _image_tag_bad(img.get("newTag")) and not img.get("digest"):
                    out.append(_f("NM-CD-006", rel, _line(text, "newTag"), repo, f"{img.get('name')}: newTag {img.get('newTag')!r}"))
    return out


ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")                 # MYELIN_SESSION_SECRET: the name of an env var / external secret
K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")     # myelin-tls: the name of a Kubernetes Secret object


def _reference(key, v):
    v = str(v).strip()
    if ENV_NAME.match(v):
        return True
    return key.lower().endswith("secret") and "-" in v and len(v) <= 63 and bool(K8S_NAME.match(v)) and not any(c.isdigit() for c in v)


def _values(values, text, rel, repo, where):
    out = []
    for path, v in _walk(values):
        key = path[-1]
        # an empty Helm tag conventionally means "the chart's pinned appVersion": only an explicit `latest` is a problem
        if key == "tag" and len(path) >= 2 and path[-2] in ("image", "images") and str(v).strip() == "latest":
            out.append(_f("NM-CD-006", rel, _line(text, "tag:"), repo, f"{where}: {'.'.join(path)} = {v!r}"))
        if isinstance(v, (str, int)) and SECRET_KEY.search(key) and not NOT_SECRET.search(key) and not PLACEHOLDER.search(str(v)) \
                and len(str(v)) >= 6 and not _reference(key, v):
            out.append(_f("NM-CD-007", rel, _line(text, f"{key}:"), repo, f"{where}: {'.'.join(path)} = ***"))
    return out


# ------------------------------------------------------------------ deploy jobs in CI/CD systems
def _job_deploys(job_text):
    return bool(DEPLOY_CMD.search(job_text))


def github_deploys(wf, text, rel, repo):
    out = []
    on = wf.get(True, wf.get("on", {}))
    triggers = set(on) if isinstance(on, (dict, list)) else {on}
    whole_verify = bool(VERIFY.search(text))
    for jname, job in (wf.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        body = yaml.safe_dump(job, sort_keys=False)
        if not _job_deploys(body):
            continue
        ln = _line(text, f"{jname}:")
        env = job.get("environment")
        env_name = env.get("name") if isinstance(env, dict) else env
        if triggers & {"pull_request", "pull_request_target"}:
            out.append(_f("NM-CD-009", rel, ln, repo, f"job {jname} deploys on {', '.join(sorted(triggers & {'pull_request', 'pull_request_target'}))}"))
        if not env_name and (PROD.search(jname) or PROD.search(body)):      # only production targets: dev deploys may run freely
            out.append(_f("NM-CD-008", rel, ln, repo, f"job {jname} deploys to production without `environment:`"))
        if re.search(r"terraform\s+apply\b[^\n]*-auto-approve", body):
            out.append(_f("NM-CD-010", rel, _line(text, "-auto-approve", ln), repo, f"job {jname}"))
        if re.search(r"(?i)(kubectl|helm|gcloud\s+run|az\s+containerapp|aws\s+ecs)", body) and not whole_verify:
            out.append(_f("NM-CD-011", rel, ln, repo, f"job {jname}"))
    return out


def gitlab_deploys(doc, text, rel, repo):
    out = []
    for name, job in (doc or {}).items():
        if not isinstance(job, dict) or name.startswith(".") or name in ("stages", "variables", "default", "include", "workflow"):
            continue
        body = yaml.safe_dump(job, sort_keys=False)
        if not _job_deploys(body):
            continue
        ln = _line(text, f"{name}:")
        env = job.get("environment")
        env_name = env.get("name") if isinstance(env, dict) else env
        manual = job.get("when") == "manual" or any(isinstance(r, dict) and r.get("when") == "manual" for r in job.get("rules") or [])
        targets_prod = PROD.search(str(env_name or "")) or (not env_name and PROD.search(name + body))
        if targets_prod and not manual and not (isinstance(env, dict) and env.get("deployment_tier") in ("development", "testing")):
            out.append(_f("NM-CD-008", rel, ln, repo, f"job {name}: production environment {env_name or 'not declared'}, automatic"))
        if any(isinstance(r, dict) and "merge_request" in str(r.get("if", "")) for r in job.get("rules") or []) or \
                "merge_requests" in [str(x) for x in job.get("only") or []]:
            out.append(_f("NM-CD-009", rel, ln, repo, f"job {name} runs for merge requests"))
        if re.search(r"terraform\s+apply\b[^\n]*-auto-approve", body):
            out.append(_f("NM-CD-010", rel, _line(text, "-auto-approve", ln), repo, f"job {name}"))
    return out


def azure_deploys(doc, text, rel, repo):
    out = []
    jobs = []
    for path, v in _walk(doc):
        if isinstance(v, dict) and ("steps" in v or "strategy" in v) and ("job" in v or "deployment" in v):
            jobs.append(v)
    for j in jobs:
        body = yaml.safe_dump(j, sort_keys=False)
        if not _job_deploys(body):
            continue
        name = j.get("deployment") or j.get("job")
        ln = _line(text, str(name))
        if "job" in j and "deployment" not in j and PROD.search(body):
            out.append(_f("NM-CD-008", rel, ln, repo, f"job {name} deploys to production outside a deployment job / environment"))
        if re.search(r"terraform\s+apply\b[^\n]*-auto-approve", body):
            out.append(_f("NM-CD-010", rel, _line(text, "-auto-approve", ln), repo, f"job {name}"))
    return out


# ------------------------------------------------------------------ cloud build services
def buildspec(doc, text, rel, repo):
    out = []
    for k, v in (((doc or {}).get("env") or {}).get("variables") or {}).items():
        if SECRET_KEY.search(str(k)) and not PLACEHOLDER.search(str(v)) and len(str(v)) >= 6:
            out.append(_f("NM-CD-012", rel, _line(text, f"{k}:"), repo, f"env.variables.{k} = ***"))
    return out


def cloudbuild(doc, text, rel, repo):
    out = []
    for k, v in ((doc or {}).get("substitutions") or {}).items():
        if SECRET_KEY.search(str(k).lstrip("_")) and not PLACEHOLDER.search(str(v)) and len(str(v)) >= 6:
            out.append(_f("NM-CD-012", rel, _line(text, f"{k}:"), repo, f"substitutions.{k} = ***"))
    for step in (doc or {}).get("steps") or []:
        for e in (step or {}).get("env") or []:
            k, _, v = str(e).partition("=")
            if SECRET_KEY.search(k) and v and not PLACEHOLDER.search(v):
                out.append(_f("NM-CD-012", rel, _line(text, k), repo, f"step env {k} = ***"))
    return out


def tekton(docs, text, rel, repo):
    out = []
    for d in docs:
        if not isinstance(d, dict) or "tekton.dev" not in str(d.get("apiVersion", "")):
            continue
        for path, v in _walk(d):
            if path[-1] == "privileged" and v is True:
                out.append(_f("NM-CD-013", rel, _line(text, "privileged"), repo, f"{d.get('kind')} {(d.get('metadata') or {}).get('name')}"))
    return out


# ------------------------------------------------------------------ entry point
SKIP = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", ".pytest_cache"}


def scan_path(root: str, repo: str = "local") -> list[dict]:
    out = []
    deploys_anywhere, gate_anywhere = [], False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for fn in filenames:
            if not fn.lower().endswith((".yml", ".yaml")) and fn not in ("Jenkinsfile",):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace("\\", "/")
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            if VERIFY.search(text) and "myelin" in text.lower():
                gate_anywhere = True
            if "{{" in text and "templates/" in rel:            # Helm templates are not plain YAML
                continue
            try:
                docs = [d for d in yaml.safe_load_all(text) if d is not None]
            except yaml.YAMLError:
                continue
            if not docs:
                continue
            low = fn.lower()
            try:
                found = []
                if ".github/workflows/" in rel and isinstance(docs[0], dict):
                    found = github_deploys(docs[0], text, rel, repo)
                elif low == ".gitlab-ci.yml" and isinstance(docs[0], dict):
                    found = gitlab_deploys(docs[0], text, rel, repo)
                elif low.startswith("azure-pipelines") and isinstance(docs[0], dict):
                    found = azure_deploys(docs[0], text, rel, repo)
                elif low in ("buildspec.yml", "buildspec.yaml") and isinstance(docs[0], dict):
                    found = buildspec(docs[0], text, rel, repo)
                elif low in ("cloudbuild.yaml", "cloudbuild.yml") and isinstance(docs[0], dict):
                    found = cloudbuild(docs[0], text, rel, repo)
                else:
                    found = gitops(docs, text, rel, repo) + tekton(docs, text, rel, repo)
                    if re.match(r"values(-[\w.-]+)?\.ya?ml$", low) and isinstance(docs[0], dict) and "kind" not in docs[0]:
                        found += _values(docs[0], text, rel, repo, f"Helm values {rel}")
                if any(f["rule_id"] in ("NM-CD-008", "NM-CD-009", "NM-CD-011") for f in found):
                    deploys_anywhere.append((rel, found[0]["line"]))
                out += found
            except (AttributeError, TypeError, ValueError):
                continue
    if deploys_anywhere and not gate_anywhere:
        rel, ln = deploys_anywhere[0]
        out.append(_f("NM-CD-014", rel, ln, repo, "deploy pipeline without `myelin gate`"))
    return out
