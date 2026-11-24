# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Repository security posture: how a repository is run, not only what its code contains.

Nineteen automated checks score the practices attackers exploit in modern supply-chain attacks (dangerous workflows,
broad tokens, unpinned dependencies, no review, no security policy, AI agent guardrails...). Each check scores 0-10
and is weighted by risk (critical 10, high 7.5, medium 5, low 2.5); the repository score is the weighted mean.

Results are mapped to the OpenSSF Open Source Project Security Baseline (OSPS Baseline, version 2026.08.28).
Controls that cannot be verified from repository content (MFA, collaborator reviews, documentation of support
periods...) are listed as needing attestation; they are never shown as met.
"""
import os
import re

SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "vendor", ".tox"}
WEIGHT = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5}

OSPS_VERSION = "2026.08.28"
OSPS = {   # control: (level, requirement)
    "OSPS-AC-01.01": (1, "Require MFA for access to sensitive resources"),
    "OSPS-AC-02.01": (1, "New collaborators get minimal privileges by default"),
    "OSPS-AC-03.01": (1, "Block direct commits to the primary branch"),
    "OSPS-AC-03.02": (1, "Require confirmation before the primary branch can be deleted"),
    "OSPS-BR-01.01": (1, "Sanitize and validate untrusted metadata used in CI/CD pipelines"),
    "OSPS-BR-01.03": (1, "Keep privileged CI/CD credentials away from untrusted code"),
    "OSPS-BR-03.01": (1, "Deliver official project channel URIs over encrypted connections"),
    "OSPS-BR-03.02": (1, "Protect distribution channels with authenticated connections"),
    "OSPS-BR-07.01": (1, "Prevent unencrypted secrets from being stored in version control"),
    "OSPS-DO-01.01": (1, "Provide user guides for basic functionality"),
    "OSPS-DO-02.01": (1, "Provide a defect reporting guide"),
    "OSPS-GV-02.01": (1, "Provide public forums for proposed changes and usage problems"),
    "OSPS-GV-03.01": (1, "Explain the contribution process"),
    "OSPS-LE-02.01": (1, "Use an OSI- or FSF-approved licence for the source code"),
    "OSPS-LE-02.02": (1, "Use an OSI- or FSF-approved licence for released assets"),
    "OSPS-LE-03.01": (1, "Keep the source code licence in a standard licence file"),
    "OSPS-LE-03.02": (1, "Include the licence with released assets"),
    "OSPS-QA-01.01": (1, "Source repository publicly readable at a static URL"),
    "OSPS-QA-01.02": (1, "Public record of all changes, authors and timestamps"),
    "OSPS-QA-02.01": (1, "Dependency list for direct language dependencies in the repository"),
    "OSPS-QA-04.01": (1, "Document all codebases of a multi-repository project"),
    "OSPS-QA-05.01": (1, "Do not store generated executable artifacts in version control"),
    "OSPS-QA-05.02": (1, "Do not store unreviewable binary artifacts in version control"),
    "OSPS-VM-02.01": (1, "Publish security contacts in project documentation"),
    "OSPS-AC-04.01": (2, "Default CI/CD task permissions to the lowest level"),
    "OSPS-BR-02.01": (2, "Assign each release a unique version identifier"),
    "OSPS-BR-04.01": (2, "Descriptive log of functional and security changes per release"),
    "OSPS-BR-05.01": (2, "Standardized tooling when ingesting dependencies in build and release"),
    "OSPS-BR-06.01": (2, "Sign each release, or list assets and hashes in a signed manifest"),
    "OSPS-DO-06.01": (2, "Document how dependencies are selected, obtained and tracked"),
    "OSPS-DO-07.01": (2, "Document how to build the software"),
    "OSPS-GV-01.01": (2, "Document the members with access to sensitive resources"),
    "OSPS-GV-01.02": (2, "Document roles and responsibilities of project members"),
    "OSPS-GV-03.02": (2, "Contributor guide with requirements for acceptable contributions"),
    "OSPS-LE-01.01": (2, "Contributors attest legal authorization for each commit"),
    "OSPS-QA-03.01": (2, "Automated status checks pass before primary-branch commits"),
    "OSPS-QA-06.01": (2, "Run at least one automated test suite in CI/CD before accepting a commit"),
    "OSPS-SA-01.01": (2, "Design documentation showing system actions and actors"),
    "OSPS-SA-02.01": (2, "Document all external software interfaces"),
    "OSPS-SA-03.01": (2, "Security assessment of the most likely and impactful threats"),
    "OSPS-VM-01.01": (2, "Coordinated vulnerability disclosure policy with response timeframes"),
    "OSPS-VM-03.01": (2, "Private channel for reporting vulnerabilities"),
    "OSPS-VM-04.01": (2, "Publicly publish data about discovered vulnerabilities"),
    "OSPS-AC-04.02": (3, "Assign only the minimum CI/CD job privileges each activity needs"),
    "OSPS-BR-01.04": (3, "Sanitize input from trusted collaborators before pipeline use"),
    "OSPS-BR-02.02": (3, "Associate release assets with the release identifier"),
    "OSPS-BR-07.02": (3, "Policy for storing, accessing and rotating secrets"),
    "OSPS-DO-03.01": (3, "Document how to verify release integrity and authenticity"),
    "OSPS-DO-03.02": (3, "Document how to verify the identity of the release author or process"),
    "OSPS-DO-04.01": (3, "Describe the scope and duration of support for each release"),
    "OSPS-DO-05.01": (3, "Describe when releases stop receiving security updates"),
    "OSPS-GV-04.01": (3, "Review collaborators before granting escalated permissions"),
    "OSPS-QA-02.02": (3, "Deliver compiled released assets with an SBOM"),
    "OSPS-QA-04.02": (3, "Subprojects enforce security requirements at least as strict"),
    "OSPS-QA-06.02": (3, "Document when and how tests are run"),
    "OSPS-QA-06.03": (3, "Require major changes to add or update automated tests"),
    "OSPS-QA-07.01": (3, "At least one non-author human approval before merging"),
    "OSPS-SA-03.02": (3, "Threat modeling and attack surface analysis on critical code paths"),
    "OSPS-VM-04.02": (3, "Document non-affecting vulnerabilities in a VEX document"),
    "OSPS-VM-05.01": (3, "Define a remediation threshold for SCA findings"),
    "OSPS-VM-05.02": (3, "Address SCA violations before any release"),
    "OSPS-VM-05.03": (3, "Automatically check changes against a dependency policy and block violations"),
    "OSPS-VM-06.01": (3, "Define a remediation threshold for SAST findings"),
    "OSPS-VM-06.02": (3, "Automatically check changes against a security weakness policy and block violations"),
}

BINARY_EXT = (".exe", ".dll", ".so", ".dylib", ".jar", ".war", ".ear", ".class", ".pyc", ".o", ".a", ".lib", ".bin", ".msi", ".apk")
OSI = re.compile(r"(?i)\b(MIT License|Apache License|BSD|GNU (Affero |Lesser )?General Public License|Mozilla Public License|ISC License|"
                 r"Eclipse Public License|The Unlicense)\b")
SECURITY_TOOLS = re.compile(r"(?i)\b(myelin|codeql|semgrep|snyk|trivy|grype|osv-scanner|bandit|sonar\w*|dependency-review-action|"
                            r"gitleaks|trufflehog|checkov|zizmor|scorecard)\b")
TEST_CMDS = re.compile(r"(?i)\b(pytest|npm (run )?test|yarn test|pnpm test|go test|mvn (-\S+ )*(test|verify)|gradle\S* test|dotnet test|"
                       r"cargo test|rspec|phpunit|tox|nox|jest|vitest|make test)\b")
SIGNING = re.compile(r"(?i)\b(cosign|sigstore|attest-build-provenance|slsa-github-generator|notation|myelin attest|gpg --(detach-)?sign)\b")
SBOM_GEN = re.compile(r"(?i)\b(syft|cyclonedx|spdx-sbom-generator|myelin sbom|sbom-action|--sbom)\b")


def _files(root):
    out = []
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP]
        for fn in fns:
            out.append(os.path.relpath(os.path.join(dp, fn), root).replace("\\", "/"))
    return out


def _read(root, rel, limit=200_000):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _find(files, *patterns):
    rx = re.compile("|".join(patterns), re.I)
    return [f for f in files if rx.search(f)]


def assess(root: str, findings: list[dict] | None = None, repo_meta: dict | None = None) -> dict:
    findings = [f for f in (findings or []) if f.get("status", "open") == "open" and f.get("engine") != "meta"]
    rules = {}
    for f in findings:
        rules.setdefault(f.get("rule_id"), []).append(f)
    files = _files(root)
    workflows = [f for f in files if re.match(r"(\.github/workflows/.+\.ya?ml|\.gitlab-ci\.yml|azure-pipelines\.ya?ml|"
                                              r"bitbucket-pipelines\.yml|Jenkinsfile|\.circleci/config\.yml)$", f)]
    ci_text = "\n".join(_read(root, w) for w in workflows)
    meta = repo_meta or {}
    checks = []

    def add(cid, name, risk, score, evidence, remediation, osps=(), applicable=True):
        checks.append({"id": cid, "name": name, "risk": risk, "score": None if not applicable else max(0, min(10, round(score, 1))),
                       "status": "n/a" if not applicable else "pass" if score >= 10 else "partial" if score > 0 else "fail",
                       "evidence": evidence, "remediation": remediation, "osps": list(osps)})

    def has(*ids):
        return sum(len(rules.get(i, [])) for i in ids)

    # 1 security policy
    sec = _find(files, r"^(\.github/|docs/)?SECURITY(\.md|\.txt|\.rst)?$")
    sec_text = _read(root, sec[0]) if sec else ""
    private = bool(re.search(r"(?i)[\w.+-]+@[\w-]+\.[\w.]+|security advisor(y|ies)|report a vulnerability|private(ly)? report", sec_text))
    timeframe = bool(re.search(r"(?i)\b\d+\s*(business\s+)?(days?|hours?)\b", sec_text))
    add("security-policy", "Security policy and disclosure", "high", (5 if sec else 0) + (3 if private else 0) + (2 if timeframe else 0),
        f"{sec[0]}" + (" · private reporting channel" if private else "") + (" · response timeframe" if timeframe else "") if sec
        else "no SECURITY.md", "Add SECURITY.md with a private reporting channel (email or private advisories) and response times.",
        ["OSPS-VM-02.01"] + (["OSPS-VM-03.01"] if private else []) + (["OSPS-VM-01.01"] if private and timeframe else []))
    # 2 licence
    lic = _find(files, r"^(LICEN[CS]E|COPYING)(\.md|\.txt)?$")
    lic_text = _read(root, lic[0], 4000) if lic else ""
    add("license", "Licence file", "low", 10 if lic else 0, lic[0] if lic else "no LICENSE file",
        "Add a LICENSE file at the repository root.", ["OSPS-LE-03.01"] + (["OSPS-LE-02.01"] if OSI.search(lic_text) else []))
    # 3 dependency list
    manifests = _find(files, r"(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|go\.mod|pom\.xml|build\.gradle(\.kts)?|"
                             r"Gemfile|composer\.json|Cargo\.toml|[^/]+\.csproj|Pipfile)$")
    add("dependency-list", "Dependencies declared in manifests", "low", 10 if manifests else 0,
        f"{len(manifests)} manifest(s)" if manifests else "no dependency manifest", "Declare direct dependencies in a manifest.",
        ["OSPS-QA-02.01"], applicable=bool(manifests) or bool(_find(files, r"\.(py|js|ts|go|java|cs|rb|php|rs)$")))
    # 4 pinned dependencies
    unpinned = has("NM-SUP-005", "NM-SUP-006", "NM-CICD-001", "NM-CICD-008", "NM-CD-005", "NM-CD-006", "NM-IAC-012", "NM-AI-023")
    add("pinned-dependencies", "Dependencies, actions and images pinned", "medium", max(0, 10 - 2 * unpinned),
        "everything locked or pinned" if not unpinned else f"{unpinned} unpinned dependency, action, image or MCP server reference(s)",
        "Commit lockfiles, pin actions to commit SHAs, images to digests and MCP servers to exact versions.", ["OSPS-BR-05.01"])
    # 5 token permissions
    broad = [f for f in rules.get("NM-CICD-004", [])]
    add("token-permissions", "Least-privilege pipeline tokens", "high",
        10 if not broad else 5 if all(f.get("severity") == "low" for f in broad) else 0,
        "all workflows declare minimal permissions" if not broad else f"{len(broad)} workflow(s) with default or write-all token permissions",
        "Set `permissions: contents: read` at the top of every workflow and grant more per job only where needed.",
        ["OSPS-AC-04.01"] + (["OSPS-AC-04.02"] if not broad else []), applicable=bool(workflows))
    # 6 dangerous workflows
    danger = has("NM-CICD-002", "NM-CICD-003", "NM-CICD-013", "NM-CICD-016", "NM-CICD-019", "NM-CICD-020", "NM-SUP-010", "NM-AI-031")
    add("dangerous-workflow", "No dangerous workflow patterns", "critical", 0 if danger else 10,
        "no script injection, untrusted checkout, cache poisoning or secret dumps" if not danger else f"{danger} dangerous pattern(s)",
        "Fix the reported pipeline findings: never run untrusted pull-request code or text with secrets.",
        ["OSPS-BR-01.01", "OSPS-BR-01.03"], applicable=bool(workflows))
    # 7 secrets in version control
    sec_found = sum(1 for f in findings if f.get("engine") == "secrets")
    add("no-committed-secrets", "No secrets committed", "critical", 0 if sec_found else 10,
        "no secrets detected" if not sec_found else f"{sec_found} secret(s) in the repository",
        "Remove and rotate the secrets; load them from a secret manager or CI secret store.", ["OSPS-BR-07.01"])
    # 8 tests in CI
    tests = bool(TEST_CMDS.search(ci_text))
    add("ci-tests", "Automated tests run in CI", "low", 10 if tests else 0, "test command found in CI" if tests else "no test step found",
        "Run the test suite on every pull request.", ["OSPS-QA-06.01"], applicable=bool(workflows))
    # 9 security scanning in CI
    tools = sorted({m.lower() for m in SECURITY_TOOLS.findall(ci_text)})
    add("security-scanning", "Security scanning blocks changes in CI", "medium", 10 if tools else 0,
        "CI runs " + ", ".join(tools) if tools else "no security scanning in CI",
        "Add `myelin scan` (or another SAST/SCA scanner) as a required check.", ["OSPS-VM-05.03", "OSPS-VM-06.02"] if tools else [],
        applicable=bool(workflows))
    # 10 dependency update tool
    upd = _find(files, r"^\.github/dependabot\.ya?ml$|^(\.github/)?renovate\.json5?$|^\.renovaterc(\.json)?$")
    add("dependency-update-tool", "Automated dependency updates", "high", 10 if upd else 0, upd[0] if upd else "no Dependabot or Renovate config",
        "Enable Dependabot or Renovate (with a cooldown) for packages and GitHub Actions.", ["OSPS-DO-06.01"] if upd else [],
        applicable=bool(manifests or workflows))
    # 11 signed releases / provenance
    signed = bool(SIGNING.search(ci_text)) or bool(meta.get("signed"))
    add("signed-releases", "Signed releases and build provenance", "high", 10 if signed else 0,
        "signing / provenance step found" if signed else "no signing or provenance step",
        "Sign artifacts (cosign / Sigstore) and publish SLSA provenance (`actions/attest-build-provenance`).",
        ["OSPS-BR-06.01"] if signed else [], applicable=bool(workflows))
    # 12 binary artifacts
    bins = [f for f in files if f.lower().endswith(BINARY_EXT)]
    add("binary-artifacts", "No binary artifacts committed", "high", 10 if not bins else max(0, 10 - len(bins)),
        "none" if not bins else ", ".join(bins[:5]) + ("…" if len(bins) > 5 else ""),
        "Remove compiled binaries; build them in CI from source.", ["OSPS-QA-05.01", "OSPS-QA-05.02"] if not bins else [])
    # 13 code review
    owners = _find(files, r"^(\.github/|docs/)?CODEOWNERS$")
    bp = meta.get("branch_protection")
    unprotected = has("NM-CICD-012")
    review = 10 if bp and owners else 7 if bp else 0 if unprotected else 4 if owners else 0
    add("code-review", "Changes reviewed before merge", "high", review,
        ("branch protection on" if bp else "branch protection off" if unprotected else "branch protection not checked (connect the source platform)")
        + (" · CODEOWNERS" if owners else " · no CODEOWNERS"),
        "Protect the default branch: required review by a code owner and required status checks.",
        (["OSPS-AC-03.01", "OSPS-QA-03.01", "OSPS-QA-07.01"] if bp else []) + (["OSPS-GV-01.02"] if owners else []))
    # 14 contribution guide
    contrib = _find(files, r"^(\.github/|docs/)?CONTRIBUTING(\.md|\.rst|\.txt)?$")
    add("contributing", "Contribution guide", "low", 10 if contrib else 0, contrib[0] if contrib else "no CONTRIBUTING file",
        "Explain how to contribute and what reviews changes need.", ["OSPS-GV-03.01", "OSPS-GV-03.02"] if contrib else [])
    # 15 changelog
    chg = _find(files, r"^(CHANGELOG|CHANGES|HISTORY|RELEASES?)(\.md|\.rst|\.txt)?$")
    add("changelog", "Release change log", "low", 10 if chg else 0, chg[0] if chg else "no CHANGELOG",
        "Keep a CHANGELOG that records functional and security changes per release.", ["OSPS-BR-04.01"] if chg else [])
    # 16 SBOM and VEX
    sbom_ci = bool(SBOM_GEN.search(ci_text)) or bool(_find(files, r"\.(cdx|spdx)\.json$|(^|/)sbom[^/]*\.json$"))
    vex = bool(_find(files, r"(\.vex|openvex)\.json$|(^|/)vex[^/]*\.json$"))
    add("sbom-vex", "SBOM (and VEX) published with releases", "low", (7 if sbom_ci else 0) + (3 if vex else 0),
        ("SBOM generated" if sbom_ci else "no SBOM step") + (" · VEX present" if vex else ""),
        "Generate a CycloneDX SBOM in the release pipeline and publish VEX for non-affecting vulnerabilities.",
        (["OSPS-QA-02.02"] if sbom_ci else []) + (["OSPS-VM-04.02"] if vex else []))
    # 17 threat model
    tm = _find(files, r"(?i)(^|/)threat[-_ ]?model[^/]*\.(md|txt|pdf|json|yaml|yml|tm7)$")
    add("threat-model", "Threat model documented", "low", 10 if tm else 0, tm[0] if tm else "no threat model document",
        "Document a threat model for the critical paths (e.g. THREAT_MODEL.md).", ["OSPS-SA-03.01", "OSPS-SA-03.02"] if tm else [])
    # 18 dependency cooldown
    cool = has("NM-SUP-008")
    js = bool(_find(files, r"(^|/)package\.json$"))
    add("dependency-cooldown", "Dependency cooldown (minimum release age)", "medium", 0 if cool else 10,
        "minimum release age configured" if not cool else "no minimum release age",
        "Set npm `min-release-age`, pnpm `minimumReleaseAge` or Yarn `npmMinimalAgeGate`.", [], applicable=js)
    # 19 AI agent guardrails
    agent_issues = has("NM-AI-028", "NM-AI-029", "NM-AI-030", "NM-AI-031", "NM-AI-032")
    agent_files = _find(files, r"(^|/)(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md|"
                               r"\.claude/settings(\.local)?\.json|\.vscode/settings\.json|mcp\.json)$")
    add("ai-agent-guardrails", "AI coding agent guardrails", "high", 0 if agent_issues else 10,
        "no unsafe agent instructions or approvals" if not agent_issues else f"{agent_issues} unsafe agent setting(s)",
        "Keep approvals on for agents, review agent instruction files like code, and never run agents on untrusted issue text with write access.",
        [], applicable=bool(agent_files) or bool(agent_issues))

    return summarise(checks)


ASSESSED = {
    "OSPS-VM-02.01", "OSPS-VM-03.01", "OSPS-VM-01.01", "OSPS-LE-03.01", "OSPS-LE-02.01", "OSPS-QA-02.01", "OSPS-BR-05.01",
    "OSPS-AC-04.01", "OSPS-AC-04.02", "OSPS-BR-01.01", "OSPS-BR-01.03", "OSPS-BR-07.01", "OSPS-QA-06.01", "OSPS-VM-05.03",
    "OSPS-VM-06.02", "OSPS-DO-06.01", "OSPS-BR-06.01", "OSPS-QA-05.01", "OSPS-QA-05.02", "OSPS-AC-03.01", "OSPS-QA-03.01",
    "OSPS-QA-07.01", "OSPS-GV-01.02", "OSPS-GV-03.01", "OSPS-GV-03.02", "OSPS-BR-04.01", "OSPS-QA-02.02", "OSPS-VM-04.02",
    "OSPS-SA-03.01", "OSPS-SA-03.02"}


def summarise(checks: list[dict]) -> dict:
    """Weighted score, grade and OSPS Baseline coverage from a list of check results."""
    scored = [c for c in checks if c["score"] is not None]
    total_w = sum(WEIGHT[c["risk"]] for c in scored)
    score = round(sum(WEIGHT[c["risk"]] * c["score"] for c in scored) / total_w, 1) if total_w else 0.0
    met = {ctl for c in checks if c["status"] == "pass" for ctl in c["osps"]}
    partial = {ctl for c in checks if c["status"] == "partial" for ctl in c["osps"]} - met
    assessed = ASSESSED
    levels = {}
    for lvl in (1, 2, 3):
        ids = [k for k, (l_, _) in OSPS.items() if l_ == lvl]
        levels[lvl] = {"controls": len(ids), "met": sum(1 for k in ids if k in met),
                       "not_met": sum(1 for k in ids if k in assessed and k not in met and k not in partial),
                       "partial": sum(1 for k in ids if k in partial),
                       "attestation_needed": sum(1 for k in ids if k not in assessed)}
    controls = [{"id": k, "level": l_, "requirement": t,
                 "status": "met" if k in met else "partial" if k in partial else "not_met" if k in assessed else "attestation"}
                for k, (l_, t) in OSPS.items()]
    grade = "A" if score >= 9 else "B" if score >= 7.5 else "C" if score >= 6 else "D" if score >= 4 else "E"
    return {"score": score, "grade": grade, "checks": checks, "osps": {"version": OSPS_VERSION, "levels": levels, "controls": controls}}


# The OSPS controls each check evidences when it fully passes (used to build posture records from other sources).
FULL_OSPS = {
    "security-policy": ["OSPS-VM-02.01", "OSPS-VM-03.01", "OSPS-VM-01.01"], "license": ["OSPS-LE-03.01", "OSPS-LE-02.01"],
    "dependency-list": ["OSPS-QA-02.01"], "pinned-dependencies": ["OSPS-BR-05.01"], "token-permissions": ["OSPS-AC-04.01", "OSPS-AC-04.02"],
    "dangerous-workflow": ["OSPS-BR-01.01", "OSPS-BR-01.03"], "no-committed-secrets": ["OSPS-BR-07.01"], "ci-tests": ["OSPS-QA-06.01"],
    "security-scanning": ["OSPS-VM-05.03", "OSPS-VM-06.02"], "dependency-update-tool": ["OSPS-DO-06.01"],
    "signed-releases": ["OSPS-BR-06.01"], "binary-artifacts": ["OSPS-QA-05.01", "OSPS-QA-05.02"],
    "code-review": ["OSPS-AC-03.01", "OSPS-QA-03.01", "OSPS-QA-07.01", "OSPS-GV-01.02"], "contributing": ["OSPS-GV-03.01", "OSPS-GV-03.02"],
    "changelog": ["OSPS-BR-04.01"], "sbom-vex": ["OSPS-QA-02.02", "OSPS-VM-04.02"], "threat-model": ["OSPS-SA-03.01", "OSPS-SA-03.02"],
    "dependency-cooldown": [], "ai-agent-guardrails": [],
}
