# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Pipeline Posture Management (PPM): static analysis of CI/CD definitions.

Rules are mapped to the OWASP Top 10 CI/CD Security Risks (CICD-SEC-1..10).
Supports GitHub Actions, GitLab CI, Azure Pipelines, Jenkinsfile, Bitbucket Pipelines.
"""
import os
import re

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
INJECTION_RE = re.compile(
    r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|head_commit|discussion)"
    r"\.[\w.]*(title|body|message|name|ref|label|email)|github\.head_ref)\s*\}\}")
CURL_PIPE_RE = re.compile(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh")
SECRET_LITERAL_RE = re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{12,}")
SIGN_RE = re.compile(r"(?i)\b(cosign|notation|sigstore|slsa-github-generator|attest-build-provenance|myelin attest|myelin-attest)\b")
BUILD_PUSH_RE = re.compile(r"(?i)(docker (build|push)|buildx|docker/build-push-action|kaniko|buildah|Docker@2)")
SECURITY_JOB_RE = re.compile(r"(?i)(sast|secret|scan|trivy|semgrep|myelin|dependency)")

RULES = {
    "NM-CICD-001": ("Third-party action not pinned to a full commit SHA", "medium", "CICD-SEC-3",
                    "Pin `uses:` to a 40-char commit SHA (keep the tag as a comment); enable Dependabot/Renovate for actions."),
    "NM-CICD-002": ("pull_request_target checks out untrusted PR code (Poisoned Pipeline Execution)", "critical", "CICD-SEC-4",
                    "Never check out `github.event.pull_request.head.*` under pull_request_target. Split into an unprivileged `pull_request` build + a privileged `workflow_run` job."),
    "NM-CICD-003": ("Script injection via untrusted GitHub context in `run:`", "high", "CICD-SEC-4",
                    "Pass untrusted values through `env:` and reference them as \"$VAR\" in the script; never interpolate `${{ github.event.* }}` directly."),
    "NM-CICD-004": ("Workflow token granted excessive permissions", "medium", "CICD-SEC-5",
                    "Declare least-privilege `permissions:` at workflow level (e.g. `contents: read`) and elevate per job only where required."),
    "NM-CICD-005": ("Self-hosted runner in use", "medium", "CICD-SEC-7",
                    "Use ephemeral, isolated runners (one job per VM/pod); never attach self-hosted runners to public repos."),
    "NM-CICD-006": ("Hard-coded credential in pipeline definition", "high", "CICD-SEC-6",
                    "Move to the CI secret store / OIDC federation; rotate the exposed value."),
    "NM-CICD-007": ("Remote script piped to shell (curl | bash)", "high", "CICD-SEC-3",
                    "Download to file, verify checksum/signature, then execute; or use a pinned, signed action/image."),
    "NM-CICD-008": ("Mutable `:latest` image used in pipeline", "low", "CICD-SEC-3",
                    "Reference images by digest (`image@sha256:…`)."),
    "NM-CICD-009": ("Artifacts built/pushed without signing or provenance", "high", "CICD-SEC-9",
                    "Sign images after build (for example cosign keyless with SLSA provenance) and verify signatures at deploy with an admission controller."),
    "NM-CICD-010": ("Security gate allowed to fail (insufficient flow control)", "medium", "CICD-SEC-1",
                    "Remove `allow_failure` / `continue-on-error` from security jobs; enforce via required status checks."),
    "NM-CICD-012": ("Default branch not protected (no required reviews or status checks)", "high", "CICD-SEC-1",
                    "Protect the default branch: require pull-request review, required status checks (including NERvvE DevSecOps) and block force pushes."),
    "NM-CICD-011": ("Long-lived cloud credentials instead of OIDC federation", "medium", "CICD-SEC-2",
                    "Replace static cloud keys with OIDC workload identity (azure/login with federated credentials, aws-actions/configure-aws-credentials role-to-assume)."),
    "NM-CICD-013": ("Workflow serialises every repository secret", "critical", "CICD-SEC-6",
                    "Never pass `${{ toJSON(secrets) }}` to a step: reference only the secrets a step needs, by name. Worms such as "
                    "Shai-Hulud inject exactly this line to steal every secret in one run."),
    "NM-CICD-014": ("All secrets passed to a reusable workflow (`secrets: inherit`)", "medium", "CICD-SEC-6",
                    "Pass only the named secrets the called workflow needs (`secrets: { TOKEN: ${{ secrets.TOKEN }} }`)."),
    "NM-CICD-015": ("Packages installed with lifecycle scripts enabled in a job that holds secrets", "medium", "CICD-SEC-3",
                    "Install with `npm ci --ignore-scripts` (or pnpm `strictDepBuilds`) in jobs that can read secrets or publish; "
                    "worm payloads run from preinstall/postinstall scripts and steal NPM_TOKEN and GITHUB_TOKEN."),
    "NM-CICD-016": ("Cache restored or saved in a privileged workflow run by untrusted events", "high", "CICD-SEC-4",
                    "Do not use actions/cache (or setup-* `cache:`) in pull_request_target / workflow_run workflows; an attacker "
                    "can poison the cache that release workflows later restore."),
    "NM-CICD-017": ("Checkout credentials uploaded as a build artifact", "high", "CICD-SEC-6",
                    "Set `persist-credentials: false` on actions/checkout and never upload the whole workspace; the .git folder "
                    "contains the job token."),
    "NM-CICD-018": ("Insecure workflow commands re-enabled (ACTIONS_ALLOW_UNSECURE_COMMANDS)", "high", "CICD-SEC-7",
                    "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS; use $GITHUB_ENV / $GITHUB_PATH files instead of set-env / add-path."),
    "NM-CICD-019": ("Cloud identity token (OIDC) available to a workflow run by untrusted events", "high", "CICD-SEC-2",
                    "Grant `id-token: write` only in workflows triggered by trusted events (push to protected branches, "
                    "release, manual dispatch) and restrict the cloud trust policy to that branch and environment."),
    "NM-CICD-020": ("Artifacts from an untrusted run are downloaded into a privileged workflow", "high", "CICD-SEC-4",
                    "Treat artifacts from the triggering run as untrusted data: download to a temporary folder, validate them, "
                    "and never execute or source them in a workflow_run job that has secrets or write permissions."),
    "NM-CICD-021": ("Package published with a long-lived registry token and no provenance", "medium", "CICD-SEC-9",
                    "Publish with trusted publishing (OIDC, no stored token) and `npm publish --provenance`, so a stolen token "
                    "cannot publish and consumers can verify where the package was built."),
}
UNTRUSTED_TRIGGERS = {"pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment", "workflow_run",
                      "pull_request_review_comment"}
INSTALL_RE = re.compile(r"\b(npm\s+(install|i|ci)|yarn(\s+install)?|pnpm\s+(install|i)|bun\s+install)\b(?![^\n]*--ignore-scripts)")
SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)\w+|NODE_AUTH_TOKEN|NPM_TOKEN")


def _f(rule, file, line, repo, evidence=""):
    title, sev, owasp, fix = RULES[rule]
    exposure = "internet" if rule in ("NM-CICD-002", "NM-CICD-003") else "internal"
    return {"engine": "cicd", "rule_id": rule, "title": title, "severity": sev, "file": file,
            "line": line, "repo": repo, "owasp_cicd": owasp, "remediation": fix, "evidence": evidence[:160],
            "exposure": exposure}


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _job_line(text: str, job: str, needle: str) -> int:
    """Line of `needle` inside the YAML block of `job` (falls back to the first occurrence in the file)."""
    m = re.search(rf"(?m)^(\s+){re.escape(str(job))}\s*:", text)
    start = m.start() if m else 0
    idx = text.find(needle, start)
    if idx < 0:
        idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _generic_text_rules(text, rel, repo):
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        if CURL_PIPE_RE.search(ln):
            out.append(_f("NM-CICD-007", rel, i, repo, ln.strip()))
        if SECRET_LITERAL_RE.search(ln) and "secrets." not in ln and "$(" not in ln and "${" not in ln:
            out.append(_f("NM-CICD-006", rel, i, repo, re.sub(r"[:=].*", ": ****", ln.strip())))
        if re.search(r"image:\s*['\"]?[\w./-]+:latest", ln) or re.search(r"\bdocker://[\w./-]+:latest", ln):
            out.append(_f("NM-CICD-008", rel, i, repo, ln.strip()))
        if re.search(r"(AWS_SECRET_ACCESS_KEY|ARM_CLIENT_SECRET|AZURE_CLIENT_SECRET)", ln) and "id-token" not in text:
            out.append(_f("NM-CICD-011", rel, i, repo, ln.strip()))
    if BUILD_PUSH_RE.search(text) and not SIGN_RE.search(text):
        out.append(_f("NM-CICD-009", rel, _line_of(text, BUILD_PUSH_RE.search(text).group(0)), repo))
    return out


def _line_fallback(text, rel, repo):
    """When a workflow is not valid YAML, still report the two highest-signal issues line by line."""
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", ln)
        if m and "@" in m.group(1) and not m.group(1).startswith(("./", "docker://")) and not SHA_RE.match(m.group(1).split("@", 1)[1]):
            f = _f("NM-CICD-001", rel, i, repo, m.group(1))
            if not m.group(1).startswith(("actions/", "github/")):
                f["severity"] = "high"
            out.append(f)
        if re.match(r"^\s*-?\s*run:", ln) and INJECTION_RE.search(ln):
            out.append(_f("NM-CICD-003", rel, i, repo, INJECTION_RE.search(ln).group(0)))
    return out


def scan_github(text, rel, repo):
    out = _generic_text_rules(text, rel, repo)
    try:
        wf = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return out + _line_fallback(text, rel, repo)
    on = wf.get(True, wf.get("on", {}))  # PyYAML parses bare `on` as True
    triggers = set(on) if isinstance(on, (dict, list)) else {on}
    perms = wf.get("permissions")
    if perms in ("write-all",) or perms is None:
        f = _f("NM-CICD-004", rel, 1, repo, f"permissions: {perms or '(default — inherits repo setting)'}")
        if perms is None:
            f["severity"] = "low"
        out.append(f)
    untrusted = bool(triggers & UNTRUSTED_TRIGGERS)
    if "ACTIONS_ALLOW_UNSECURE_COMMANDS" in text and re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS['\"]?\s*:\s*['\"]?true", text, re.I):
        out.append(_f("NM-CICD-018", rel, _line_of(text, "ACTIONS_ALLOW_UNSECURE_COMMANDS"), repo, "ACTIONS_ALLOW_UNSECURE_COMMANDS: true"))
    for i, ln in enumerate(text.splitlines(), 1):
        if re.search(r"\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}", ln):
            out.append(_f("NM-CICD-013", rel, i, repo, ln.strip()))
    wf_oidc = isinstance(perms, dict) and str(perms.get("id-token")) == "write"
    for jname, job in (wf.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        jtext = yaml.safe_dump(job, sort_keys=False)
        jperms = job.get("permissions")
        oidc = wf_oidc or (isinstance(jperms, dict) and str(jperms.get("id-token")) == "write")
        if oidc and untrusted:
            out.append(_f("NM-CICD-019", rel, _line_of(text, "id-token"), repo,
                          f"job {jname}: id-token: write on {', '.join(sorted(triggers & UNTRUSTED_TRIGGERS))}"))
        juses = str(job.get("uses") or "")
        if job.get("secrets") == "inherit":
            f = _f("NM-CICD-014", rel, _line_of(text, "secrets: inherit"), repo, f"job {jname}: uses {juses or '(reusable)'}")
            if juses.startswith("./"):
                f["severity"] = "low"
            out.append(f)
        holds_secrets = bool(SECRET_REF_RE.search(jtext))
        steps = [s_ for s_ in (job.get("steps") or []) if isinstance(s_, dict)]
        for step in steps:
            uses, run, with_ = str(step.get("uses") or ""), str(step.get("run") or ""), step.get("with") or {}
            if untrusted and (uses.startswith("actions/cache") or (uses.startswith("actions/setup-") and with_.get("cache"))):
                out.append(_f("NM-CICD-016", rel, _line_of(text, uses), repo, f"job {jname}: {uses} on {', '.join(sorted(triggers & UNTRUSTED_TRIGGERS))}"))
            if "workflow_run" in triggers and (uses.startswith("actions/download-artifact") and (with_.get("run-id") or with_.get("github-token"))
                                               or uses.startswith("dawidd6/action-download-artifact")):
                out.append(_f("NM-CICD-020", rel, _line_of(text, uses), repo, f"job {jname}: {uses} from the triggering run"))
            if run:
                for rl in run.splitlines():
                    m = INSTALL_RE.search(rl)
                    if m and holds_secrets:
                        out.append(_f("NM-CICD-015", rel, _job_line(text, jname, rl.strip()), repo, f"job {jname}: {rl.strip()}"))
                    if re.search(r"\bnpm\s+publish\b", rl) and "--provenance" not in rl and re.search(r"NODE_AUTH_TOKEN|NPM_TOKEN", jtext) \
                            and not oidc:
                        out.append(_f("NM-CICD-021", rel, _job_line(text, jname, rl.strip()), repo, f"job {jname}: {rl.strip()} with a stored token"))
            if uses.startswith("actions/upload-artifact") and str(with_.get("path", "")).strip() in (".", "./", "${{ github.workspace }}", "*", "**"):
                co = next((x for x in steps if str(x.get("uses") or "").startswith("actions/checkout")), None)
                if co is not None and str((co.get("with") or {}).get("persist-credentials", "true")).lower() != "false":
                    out.append(_f("NM-CICD-017", rel, _line_of(text, uses), repo, f"job {jname}: uploads {with_.get('path')} after checkout with persisted credentials"))
        ro = job.get("runs-on")
        if ro and "self-hosted" in str(ro):
            out.append(_f("NM-CICD-005", rel, _line_of(text, "self-hosted"), repo, f"job {jname}: runs-on {ro}"))
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if uses and not uses.startswith(("./", "docker://")) and "@" in uses:
                ref = uses.split("@", 1)[1]
                if not SHA_RE.match(ref):
                    f = _f("NM-CICD-001", rel, _line_of(text, uses), repo, uses)
                    if not uses.startswith(("actions/", "github/")):
                        f["severity"] = "high"
                    out.append(f)
            if "pull_request_target" in triggers and uses and uses.startswith("actions/checkout"):
                ref = str((step.get("with") or {}).get("ref", ""))
                if "pull_request.head" in ref or "head_ref" in ref:
                    out.append(_f("NM-CICD-002", rel, _line_of(text, ref), repo, f"ref: {ref}"))
            run = step.get("run")
            if run and INJECTION_RE.search(run):
                out.append(_f("NM-CICD-003", rel, _line_of(text, INJECTION_RE.search(run).group(0)), repo,
                              INJECTION_RE.search(run).group(0)))
            if step.get("continue-on-error") and SECURITY_JOB_RE.search(str(step.get("name", "")) + str(uses) + str(run)):
                out.append(_f("NM-CICD-010", rel, _line_of(text, "continue-on-error"), repo, f"step: {step.get('name', uses)}"))
    return out


def scan_gitlab(text, rel, repo):
    out = _generic_text_rules(text, rel, repo)
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return out
    for name, job in doc.items():
        if isinstance(job, dict) and job.get("allow_failure") and SECURITY_JOB_RE.search(name):
            out.append(_f("NM-CICD-010", rel, _line_of(text, f"{name}:"), repo, f"job {name}: allow_failure: true"))
        if isinstance(job, dict) and "tags" in job and any("shell" in str(t) for t in job["tags"]):
            out.append(_f("NM-CICD-005", rel, _line_of(text, f"{name}:"), repo, f"job {name} on shell runner"))
    return out


def scan_path(root: str, repo: str = "local") -> list[dict]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules"}]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            if ".github/workflows" in rel.replace("\\", "/") and fn.endswith((".yml", ".yaml")):
                out += scan_github(text, rel, repo)
            elif fn == ".gitlab-ci.yml":
                out += scan_gitlab(text, rel, repo)
            elif fn in ("azure-pipelines.yml", "azure-pipelines.yaml", "bitbucket-pipelines.yml", "Jenkinsfile"):
                out += _generic_text_rules(text, rel, repo)
                if re.search(r"continueOnError:\s*true", text) and SECURITY_JOB_RE.search(text):
                    out.append(_f("NM-CICD-010", rel, _line_of(text, "continueOnError"), repo))
                code = "\n".join(l for l in text.splitlines() if not l.strip().startswith(("//", "#", "*")))
                if fn == "Jenkinsfile" and re.search(r"^\s*agent\s+any\b", code, re.M):
                    out.append(_f("NM-CICD-005", rel, _line_of(text, "agent any"), repo, "agent any (shared controller/agents)"))
    return out
