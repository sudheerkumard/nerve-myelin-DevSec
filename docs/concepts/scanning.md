# How scanning works

A repository scan runs every engine that applies to the code in front of it, merges the results into one finding per
weakness, and records exactly what it examined. Reports and dashboards show only the areas that were actually
assessed.

## Engines per area

| Area | Engines | Depth |
|---|---|---|
| Source code (SAST) | **Opengrep** with the NERvvE rule pack · NERvvE pattern rules · **Bandit** (Python) | Data-flow (taint) analysis: untrusted input from a web request, the command line or the environment is followed through variables and function calls in the same file to a dangerous operation (SQL, OS command, code evaluation, file path, outbound request, redirect, HTML output, deserialisation, LDAP, XPath, templates). Sanitisers such as `int()`, `parseInt`, `escapeshellarg`, `htmlspecialchars` or `Path.GetFileName` stop the flow. Configuration rules cover TLS verification, JWT verification, weak cryptography and hard-coded framework secrets. |
| Open-source dependencies (SCA) | **OSV** · **Trivy** | Every component from manifests and lock files (direct and transitive) against OSV and the Trivy vulnerability database, with CVSS, EPSS, CISA KEV and import reachability |
| Secrets | NERvvE secret rules · **Gitleaks** · **Trivy** | Provider formats and high-entropy credentials in the files; the git history too when the repository was cloned with git (pipelines, Git and CodeCommit sources) |
| Infrastructure as Code | NERvvE IaC rules · **Checkov** · **Trivy** | Dockerfile, Compose, Kubernetes, Helm, Terraform, Bicep, CloudFormation |
| CI/CD pipelines | NERvvE pipeline rules | OWASP Top 10 CI/CD Security Risks for GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, Bitbucket, Argo CD, Flux |
| Licences, supply chain, AI-BOM | NERvvE rules | Licence policy; malicious, look-alike and unpublished packages; models, agents, prompts and MCP servers |
| Live applications (DAST) | NERvvE DAST · **OWASP ZAP** (optional service) | Read-only checks, crawler and multi-user authorisation tests; ZAP spider and passive analysis of every response on verified targets; ZAP active scan and NERvvE active checks only where the owner enabled them |

The rule pack (`engine/myelin_engine/rules/sast`) is NERvvE's own work under the AGPL-3.0, tested against annotated
fixtures (`engine/tests/sast_rules`). No Semgrep Registry rules are used. Add rules you own or have licensed with
`MYELIN_SAST_RULES` (a file or folder); they run alongside the bundled pack.

Language coverage: data-flow analysis for Python, JavaScript, TypeScript, Java, Go, C#, PHP and Ruby; pattern rules also
for Kotlin. Other languages (Scala, Rust, C/C++, Swift) are listed under "not covered" in the scan's coverage record.

## One finding per weakness

When two engines report the same thing, the scan keeps one finding:

- A data-flow result replaces a pattern match for the same weakness on the same line; the pattern rule's id is kept as
  an alias, so an existing `myelin:ignore[NM-SAST-...]` suppression still applies.
- Bandit results on a line already reported by NERvvE or Opengrep are dropped.
- Gitleaks or Trivy secrets on a line NERvvE already reports are dropped (NERvvE's finding carries validation and the
  rotation workflow).
- A Trivy dependency finding with the same package, version and advisory as an OSV finding is dropped.
- A Trivy misconfiguration on a line another IaC engine reports is dropped.

A data-flow finding shows its path in the evidence, for example
``untrusted input `req.query` (line 15) → url → sink at line 16``. Proven flows from a request into SQL, an OS command,
code evaluation, file inclusion, templates or deserialisation are rated **critical**.

## Coverage record and reports

Every scan stores a coverage record per area:

- **assessed** only when the repository contains something the area applies to (source files, resolvable dependencies,
  IaC files, pipeline definitions, AI components) and an engine for it ran;
- what was examined (files and languages, components, pipeline files), the depth of analysis, the tools and their
  versions, and any tool that failed;
- the reason an area was not assessed, for example "no infrastructure-as-code files" or "dependency manifests found but
  no resolvable versions (commit a lock file)".

The assessment report is built from this record: its scope table, findings, framework mapping, CVE register, SBOM and
methodology include **only the areas that were assessed**. Framework controls that no assessed area tests are left
out. A tool that failed is named in the methodology; it is never shown as a clean result.

The command line prints the same record:

```text
  Assessed: sast, sca, license, supply, secrets, iac, cicd
    sast     44 source files: JavaScript (44)                     NERvvE pattern rules, opengrep 1.33.0
    sca      1110 components from 2 manifest/lock files           OSV, trivy 0.76.0
    secrets  96 files and git history                             NERvvE secret rules, gitleaks 8.30.1, trivy 0.76.0
  Not assessed: aibom (no AI models, agents or MCP servers)
```

## Where the scanners run

| Where | What you get |
|---|---|
| Platform image (`docker-compose.enterprise.yml`, Helm) | All scanners bundled; repository scans from the console use them |
| CLI image (`Dockerfile.cli`) for pipelines | All scanners bundled, plus Cosign |
| `pip install .` on a workstation | Built-in engines and Bandit; Opengrep, Trivy, Gitleaks and Checkov run when they are on `PATH` |
| Demo (`demo/start-demo.*`) | Built-in engines on the sample data |

The first scan downloads the Trivy vulnerability database (about 1 GB with the Java index) into the scanner cache
(`MYELIN_CACHE_DIR`, a volume in Compose and an `emptyDir` in Helm). With `MYELIN_OFFLINE=1`, Trivy uses a mirrored
database if one is in the cache, and dependency scanning otherwise relies on OSV exports and bundled data.

On networks that inspect HTTPS, put the company root certificate in `config/certs`: the images, the API's CA bundle and
the scanners then trust it (see [first-time setup](../getting-started/first-time-setup.md)).

## Deep DAST with OWASP ZAP

ZAP runs as an optional service that only the API can reach:

=== "Windows"

    ```powershell
    powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1 -Dast
    ```

=== "Docker Compose"

    ```bash
    # in config/backend/enterprise.env: MYELIN_ZAP_URL=http://zap:8090 and MYELIN_ZAP_API_KEY=<random>
    docker compose -f docker-compose.enterprise.yml --env-file config/backend/enterprise.env --profile dast up -d
    ```

=== "Helm"

    ```yaml
    dast:
      zap: { enabled: true }      # add the key MYELIN_ZAP_API_KEY to the platform secret
    ```

For a verified target, each run then adds ZAP's spider and passive scanner (the spider does not submit forms, so nothing
is written). When the owner enables **active checks** on the target, ZAP's active scanner also runs. Scans are
serialised and each starts a fresh ZAP session limited to the target's origin, so results never mix between targets
or organisations.

## Limits

- Data-flow analysis follows values within one file. A flow that crosses files (for example a route handler passing
  input to a data-access module) is found when the sink pattern itself is unsafe (string-built SQL), not as a traced
  flow.
- Static analysis does not see runtime configuration or business-logic flaws; combine it with DAST and review.
- Repository archives downloaded from GitHub, GitLab, Bitbucket and Azure DevOps do not include git history; scan the
  history in the pipeline with the CLI image, where the checkout includes `.git`.
