# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""What a scan actually assessed.

A domain counts as *assessed* only when the repository contains something that domain applies to (source files for
SAST, manifests for SCA, pipeline files for CI/CD...) and at least one engine for it ran. Reports and dashboards show
assessed domains only, with the tools, their versions, the files examined and any tool that failed — never a green
tick for an area that was not examined.
"""
import fnmatch
import os
import re
import shutil
import subprocess
from functools import lru_cache

SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "vendor", ".tox", ".pytest_cache",
        ".mypy_cache", "target", "bin", "obj", ".gradle", ".idea", ".next", "coverage", "site-packages"}

LANG_EXT = {
    "Python": (".py",), "JavaScript": (".js", ".jsx", ".mjs", ".cjs"), "TypeScript": (".ts", ".tsx"),
    "Java": (".java",), "Kotlin": (".kt", ".kts"), "Go": (".go",), "C#": (".cs",), "PHP": (".php",),
    "Ruby": (".rb",), "Scala": (".scala",), "Rust": (".rs",), "C/C++": (".c", ".cc", ".cpp", ".h", ".hpp"),
    "Swift": (".swift",),
}
# languages the bundled NERvvE taint rule pack covers (engine/myelin_engine/rules/sast)
DEEP_SAST = {"Python", "JavaScript", "TypeScript", "Java", "Go", "C#", "PHP", "Ruby"}
# languages the built-in pattern rules cover
PATTERN_SAST = {"Python", "JavaScript", "TypeScript", "Java", "Kotlin", "Go", "C#", "PHP", "Ruby"}

MANIFESTS = ("requirements*.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py", "uv.lock",
             "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
             "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "go.mod", "go.sum", "Cargo.toml",
             "Cargo.lock", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock", "*.csproj", "packages.config",
             "packages.lock.json", "Directory.Packages.props", "mix.exs", "mix.lock", "pubspec.yaml", "Podfile.lock")
IAC_FILES = ("Dockerfile", "Dockerfile.*", "*.dockerfile", "*.tf", "*.tfvars", "*.bicep", "Chart.yaml",
             "docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml", "*.template.json",
             "kustomization.yaml", "kustomization.yml", "serverless.yml", "*.cfn.yaml", "*.cfn.json")
K8S_HINT = re.compile(r"^\s*(apiVersion:\s*\S+|kind:\s*(Deployment|Pod|Service|Ingress|StatefulSet|DaemonSet|CronJob|Job|"
                      r"Role|ClusterRole|RoleBinding|ClusterRoleBinding|NetworkPolicy|ConfigMap|Secret|Application|"
                      r"Kustomization|HelmRelease))", re.M)
PIPELINES = (".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml", "azure-pipelines*.yml",
             "Jenkinsfile", "bitbucket-pipelines.yml", ".circleci/config.yml", ".drone.yml", "buildspec.yml",
             "cloudbuild.yaml", ".travis.yml", "argocd/*.yaml", "flux-system/*.yaml")
AI_HINT = re.compile(r"\b(openai|anthropic|langchain|llama_index|transformers|huggingface_hub|vertexai|bedrock|"
                     r"ollama|mcp|semantic_kernel|autogen|crewai)\b", re.I)
AI_FILES = ("*.gguf", "*.safetensors", "*.onnx", "*.pt", "*.ckpt", "mcp.json", ".mcp.json", "*.prompt", "*.prompty",
            "AGENTS.md", "CLAUDE.md", ".cursorrules")


def inventory(root: str) -> dict:
    """Count what is in the repository, per domain (cheap walk; no file over 1 MB is read)."""
    inv = {"files": 0, "languages": {}, "manifests": [], "iac": [], "pipelines": [], "ai": []}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP and not d.startswith(".") or d in (".github", ".circleci", ".gitlab")]
        rel_dir = os.path.relpath(dirpath, root)
        for fn in filenames:
            rel = os.path.normpath(os.path.join(rel_dir, fn)).replace(os.sep, "/")
            inv["files"] += 1
            ext = os.path.splitext(fn)[1].lower()
            for lang, exts in LANG_EXT.items():
                if ext in exts:
                    inv["languages"][lang] = inv["languages"].get(lang, 0) + 1
                    break
            if any(fnmatch.fnmatch(fn, m) for m in MANIFESTS):
                inv["manifests"].append(rel)
            if any(fnmatch.fnmatch(fn, m) for m in IAC_FILES):
                inv["iac"].append(rel)
            elif ext in (".yml", ".yaml", ".json") and _looks_k8s(os.path.join(dirpath, fn), ext):
                inv["iac"].append(rel)
            if any(fnmatch.fnmatch(rel, p) for p in PIPELINES):
                inv["pipelines"].append(rel)
            if any(fnmatch.fnmatch(fn, m) for m in AI_FILES):
                inv["ai"].append(rel)
            elif ext in (".py", ".js", ".ts", ".mjs") and len(inv["ai"]) < 200 and _mentions_ai(os.path.join(dirpath, fn)):
                inv["ai"].append(rel)
    return inv


def _looks_k8s(path, ext):
    if ext == ".json":
        return False
    try:
        if os.path.getsize(path) > 1_000_000:
            return False
        with open(path, encoding="utf-8", errors="ignore") as fh:
            head = fh.read(4000)
        return bool(K8S_HINT.search(head)) and "kind:" in head
    except OSError:
        return False


def _mentions_ai(path):
    try:
        if os.path.getsize(path) > 500_000:
            return False
        with open(path, encoding="utf-8", errors="ignore") as fh:
            head = fh.read(6000)
        return bool(re.search(r"^\s*(import|from)\s+(openai|anthropic|langchain|llama_index|transformers|mcp)\b|"
                              r"require\(['\"](openai|@anthropic-ai/sdk|langchain|@modelcontextprotocol/sdk)['\"]\)|"
                              r"from ['\"](openai|@anthropic-ai/sdk|langchain|@modelcontextprotocol/sdk)", head, re.M))
    except OSError:
        return False


@lru_cache(maxsize=None)
def tool_version(tool: str) -> str:
    """Installed version of an external scanner ('' when it is not installed)."""
    exe = shutil.which(tool)
    if not exe:
        return ""
    argv = {"gitleaks": [exe, "version"], "checkov": [exe, "--version"], "trivy": [exe, "--version"],
            "bandit": [exe, "--version"], "opengrep": [exe, "--version"], "semgrep": [exe, "--version"]}.get(tool, [exe, "--version"])
    try:
        from .orchestrator import _tool_env
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=_tool_env()).stdout
    except (OSError, subprocess.SubprocessError):
        return "installed"
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", out or "")
    return m.group(1) if m else "installed"


DOMAIN_TOOLS = {
    "sast": ("NERvvE pattern rules", "opengrep", "semgrep", "bandit"),
    "sca": ("OSV", "trivy"),
    "license": ("NERvvE licence policy",),
    "secrets": ("NERvvE secret rules", "gitleaks", "trivy"),
    "iac": ("NERvvE IaC rules", "checkov", "trivy"),
    "cicd": ("NERvvE pipeline rules",),
    "aibom": ("NERvvE AI-BOM rules",),
    "supply": ("NERvvE supply-chain rules",),
}


def build(inv: dict, engines: list[str], tools_used: list[str], findings: list[dict], components: int,
          intel: dict | None = None, deep_rules: int = 0) -> dict:
    """Per-domain record: assessed or not, why, what was examined, which tools ran, and errors."""
    errors = {}
    for f in findings:
        if f.get("engine") == "meta" and str(f.get("rule_id", "")).startswith("tool-error:"):
            errors[f["rule_id"].split(":", 1)[1]] = f.get("title", "")
    counts = {}
    for f in findings:
        if f.get("engine") != "meta":
            counts[f.get("engine")] = counts.get(f.get("engine"), 0) + 1
    langs = inv.get("languages") or {}
    deep_langs = sorted(lang for lang in langs if lang in DEEP_SAST)
    pattern_langs = sorted(lang for lang in langs if lang in PATTERN_SAST)

    def tools_for(domain, applicable_tools):
        names = []
        for t in applicable_tools:
            if t.startswith(("NERvvE", "OSV")):
                names.append({"name": t, "version": ""})
            elif t in tools_used:
                names.append({"name": t, "version": tool_version(t), "error": errors.get(t)})
        return names

    cov = {}
    # SAST
    sast_tools = ["NERvvE pattern rules"] if pattern_langs else []
    if deep_langs and ("opengrep" in tools_used or "semgrep" in tools_used):
        sast_tools += [t for t in ("opengrep", "semgrep") if t in tools_used]
    if "Python" in langs and "bandit" in tools_used:
        sast_tools.append("bandit")
    unsupported = sorted(lang for lang in langs if lang not in PATTERN_SAST and lang not in DEEP_SAST)
    cov["sast"] = {"applicable": bool(langs), "assessed": "sast" in engines and bool(sast_tools),
                   "examined": f"{sum(langs.values())} source files: " + ", ".join(f"{k} ({v})" for k, v in sorted(langs.items(), key=lambda x: -x[1])) if langs else "",
                   "depth": ("Data-flow (taint) analysis for " + ", ".join(deep_langs) + "; " if deep_langs and len(sast_tools) > 1 else "")
                   + ("pattern rules for " + ", ".join(pattern_langs) if pattern_langs else ""),
                   "not_covered": unsupported, "rules": deep_rules, "tools": tools_for("sast", sast_tools)}
    # SCA and licences
    has_deps = components > 0
    cov["sca"] = {"applicable": has_deps, "assessed": "sca" in engines and has_deps,
                  "examined": f"{components} components from {len(inv.get('manifests') or [])} manifest/lock files" if has_deps else "",
                  "depth": "Known vulnerabilities (CVE/GHSA/OSV) with CVSS, EPSS, CISA KEV and import reachability"
                           + (" — offline: bundled advisory data only" if (intel or {}).get("offline") else ""),
                  "tools": tools_for("sca", ["OSV"] + (["trivy"] if "trivy" in tools_used else [])),
                  "errors": (intel or {}).get("errors") or []}
    cov["license"] = {"applicable": components > 0, "assessed": "license" in engines and components > 0,
                      "examined": f"{components} components" if components else "", "depth": "Licence of every component against the policy",
                      "tools": [{"name": "NERvvE licence policy", "version": ""}]}
    cov["supply"] = {"applicable": components > 0, "assessed": "supply" in engines and components > 0,
                     "examined": f"{components} components" if components else "",
                     "depth": "Known-malicious and typosquatted packages, install scripts, dependency confusion",
                     "tools": [{"name": "NERvvE supply-chain rules", "version": ""}]}
    # Secrets: every repository has files
    sec_tools = ["NERvvE secret rules"] + [t for t in ("gitleaks", "trivy") if t in tools_used]
    cov["secrets"] = {"applicable": inv.get("files", 0) > 0, "assessed": "secrets" in engines and inv.get("files", 0) > 0,
                      "examined": f"{inv.get('files', 0)} files" + (" and git history" if inv.get("git_history") else ""),
                      "depth": "Credentials, keys and tokens, with high-entropy and provider-format detection",
                      "tools": tools_for("secrets", sec_tools)}
    iac_tools = ["NERvvE IaC rules"] + [t for t in ("checkov", "trivy") if t in tools_used]
    cov["iac"] = {"applicable": bool(inv.get("iac")), "assessed": "iac" in engines and bool(inv.get("iac")),
                  "examined": f"{len(inv.get('iac') or [])} files (Dockerfile, Kubernetes, Helm, Terraform, Bicep, Compose)" if inv.get("iac") else "",
                  "depth": "Misconfiguration against CIS and cloud-provider baselines", "tools": tools_for("iac", iac_tools)}
    cov["cicd"] = {"applicable": bool(inv.get("pipelines")), "assessed": "cicd" in engines and bool(inv.get("pipelines")),
                   "examined": f"{len(inv.get('pipelines') or [])} pipeline definitions" if inv.get("pipelines") else "",
                   "depth": "OWASP Top 10 CI/CD Security Risks", "tools": [{"name": "NERvvE pipeline rules", "version": ""}]}
    cov["aibom"] = {"applicable": bool(inv.get("ai")), "assessed": "aibom" in engines and bool(inv.get("ai")),
                    "examined": f"{len(inv.get('ai') or [])} files using models, agents or MCP" if inv.get("ai") else "",
                    "depth": "OWASP Top 10 for LLM Applications", "tools": [{"name": "NERvvE AI-BOM rules", "version": ""}]}
    for k, c in cov.items():
        if counts.get(k) and k in engines:         # an engine found something, so the domain was examined
            c["applicable"] = c["assessed"] = True
            c.pop("reason", None)
            c["examined"] = c.get("examined") or "files with matching content"
        c["findings"] = counts.get(k, 0) if c["assessed"] else 0
        if not c["applicable"]:
            c["reason"] = {"sast": "no source code",
                           "sca": ("dependency manifests found but no resolvable versions (commit a lock file)" if inv.get("manifests")
                                   else "no dependency manifests"), "license": "no third-party components",
                           "supply": "no third-party components", "iac": "no infrastructure-as-code files",
                           "cicd": "no pipeline definitions", "aibom": "no AI models, agents or MCP servers",
                           "secrets": "empty repository"}.get(k, "not applicable")
        elif not c["assessed"]:
            c["reason"] = "engine not selected for this scan"
    return cov


def assessed(cov: dict | None) -> list[str]:
    return [k for k, c in (cov or {}).items() if c.get("assessed")]
