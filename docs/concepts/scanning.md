# How scanning works

A repository scan runs every engine that applies to the code in front of it, merges the results into one finding per
weakness, and records exactly what it examined. Reports and dashboards show only the areas that were actually
assessed.

## Engines per area

| Area | Engines | Depth |
|---|---|---|
| Source code (SAST) | **Opengrep** with the RAT Flea rule pack · RAT Flea pattern rules · **Bandit** (Python) | Data-flow (taint) analysis: untrusted input from a web request, the command line or the environment is followed through variables and function calls in the same file to a dangerous operation (SQL, OS command, code evaluation, file path, outbound request, redirect, HTML output, deserialisation, LDAP, XPath, templates). Sanitisers such as `int()`, `parseInt`, `escapeshellarg`, `htmlspecialchars` or `Path.GetFileName` stop the flow. Configuration rules cover TLS verification, JWT verification, weak cryptography and hard-coded framework secrets. |
| Open-source dependencies (SCA) | **OSV** · **Trivy** · **Grype** | Every component from manifests and lock files (direct and transitive) against OSV and the Trivy vulnerability database, with CVSS, EPSS, CISA KEV and import reachability. Transitive dependencies are resolved the way a build would when there is no lock file: Maven (Trivy inventory), Gradle (build files and version catalogs), NuGet (registry dependency graph), npm (a lock file is generated with scripts disabled, where npm is installed: the CLI on a developer machine or CI runner; the container images do not include npm) and Python (PyPI metadata) |
| Secrets | RAT Flea secret rules · **Gitleaks** · **Trivy** | Provider formats and high-entropy credentials in the files; the git history too when the repository was cloned with git (pipelines, Git and CodeCommit sources) |
| Infrastructure as Code | RAT Flea IaC rules · **Checkov** · **Trivy** | Dockerfile, Compose, Kubernetes, Helm, Terraform, Bicep, CloudFormation |
| CI/CD pipelines | RAT Flea pipeline rules | OWASP Top 10 CI/CD Security Risks for GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, Bitbucket, Argo CD, Flux |
| Licences, supply chain, AI-BOM | RAT Flea rules | Licence policy; malicious, look-alike and unpublished packages; models, agents, prompts and MCP servers |
| Live applications (DAST) | RAT Flea DAST · **OWASP ZAP** (optional service) | Read-only checks, crawler and multi-user authorisation tests; ZAP spider and passive analysis of every response on verified targets; ZAP active scan and RAT Flea active checks only where the owner enabled them |

The rule pack (`engine/myelin_engine/rules/sast`) is RAT Flea's own work under the AGPL-3.0, tested against annotated
fixtures (`engine/tests/sast_rules`). No Semgrep Registry rules are used. Add rules you own or have licensed with
`MYELIN_SAST_RULES` (a file or folder); they run alongside the bundled pack.

Language coverage: data-flow analysis for Python, JavaScript, TypeScript, Java, Go, C#, PHP and Ruby; pattern rules also
for Kotlin. Other languages (Scala, Rust, C/C++, Swift) are listed under "not covered" in the scan's coverage record.

## Accuracy

The Java rule pack is measured against the [OWASP Benchmark](https://owasp.org/www-project-benchmark/) v1.2: 2,740
labelled test cases across 11 categories (command, SQL, LDAP and XPath injection, path traversal, XSS, weak encryption,
weak hashing, weak randomness, insecure cookies, trust boundary). The score is the true-positive rate minus the
false-positive rate, averaged over the categories, as in the official scorecard:

| Category | True positives found | False positive rate | Score |
|---|---|---|---|
| Command injection | 100% | 12% | 88% |
| Weak encryption | 100% | 0% | 100% |
| Weak hashing | 100% | 0% | 100% |
| LDAP injection | 100% | 16% | 84% |
| Path traversal | 100% | 7% | 93% |
| Insecure cookie | 100% | 0% | 100% |
| SQL injection | 100% | 12% | 88% |
| Trust boundary | 100% | 14% | 86% |
| Weak randomness | 100% | 9% | 91% |
| XPath injection | 100% | 5% | 95% |
| Cross-site scripting | 100% | 10% | 90% |
| **Average** | | | **92%** |

The rules were tuned with this benchmark, so treat the figure as an upper bound for Java servlet code, not a promise
for every code base. Two techniques produce it:

- **Precision pass.** After the data-flow analysis, findings whose path is proven impossible are removed: a branch
  under a constant condition, a `switch` on a constant, or a list or map element that is known to hold a literal. A
  finding is removed only when the value reaching the sink is proven to be a literal; anything the pass cannot evaluate
  is kept.
- **Configured algorithms.** When an algorithm name is read from configuration (`props.getProperty("hashAlg", ...)`),
  the value is looked up in the project's `.properties` files, falling back to the default in the code.

## Secrets: one finding per credential

Gitleaks reports a result for every commit that touched a secret, so one leaked key could fill a report. RAT Flea groups
the results:

- **One finding per secret** (same rule and value). The finding lists every file, line and commit where it appears
  (`occurrences`, `locations`). The secret's value is never stored, only a hash used to group it.
- **Present now or history only.** A secret still in the files is rated by provider (critical for cloud, source-control
  and payment keys, high for generic credentials). A secret removed from the files but still in the git history is
  rated high and titled "in git history".
- **Context.** A secret in a test or fixture file is rated low and one in documentation medium, both marked with
  `context`. A live secret (confirmed by the provider) keeps its full severity everywhere.
- **Placeholders are dropped**: values such as `your_api_key_here`, `changeme`, `xxxx`, `${VAR}` or `<token>`, and
  generic matches with low randomness.

## Mitigation steps

Every finding carries developer guidance: what to change, step by step, how to confirm the fix and a reference
(OWASP Cheat Sheet Series, CIS, SLSA). The steps are chosen by rule, weakness (CWE) and engine. For example, a Google
API key finding explains how to rotate it, restrict it by application and API, and purge it from history. A dependency
finding gives the exact upgrade and how to pin a transitive dependency for npm, Maven, Gradle, NuGet or pip.

The guidance appears in:

- the finding detail in the console,
- the CSV/Excel export (`how_to_fix`, `mitigation_steps`, `how_to_verify`, `reference`, `occurrences`,
  `other_locations` columns),
- the PDF/HTML assessment report, under each finding.

## One finding per weakness

When two engines identify the same SAST weakness on the same line, the scan keeps the better supported result.
A data flow result replaces the matching pattern result and retains its rule ID as an alias for existing suppressions.
Bandit findings with a different CWE stay visible, even when another engine reports a finding on that line.
Infrastructure findings from separate engines can describe different configuration problems at the same location.
The CVE register groups results for the same dependency version and advisory. It does not count untested areas as clean.

## Coverage record and reports

A scan records the areas it assessed, the tools it used, and any known gaps. For SAST, the source file inventory is
reported separately from the number of files the data flow engine scanned. A missing or failed data flow engine,
a partial advisory feed, and errors reported by an external scanner appear as coverage limitations. Repository
rescans retain earlier findings when incomplete coverage cannot establish a fix.

The HTML report includes only assessed areas and lists all current open findings from the scan. It omits the
CVE register and software inventory unless those areas were assessed. An older scan without a coverage
record can show the areas evidenced by its findings; run a fresh scan to report current scope.

## Scanning on a laptop

The offline demo console displays sample data. A repository scan started in the local enterprise console
(`myelin.localtest.me`) fetches and scans the selected repository snapshot using the scanners bundled in the
platform image. A CLI scan reads the actual folder you pass to it. It uses built-in engines and runs installed
external tools from `PATH`, including Opengrep (or Semgrep), Bandit, Trivy, Grype, Gitleaks and Checkov where
applicable.

```sh
myelin scan . --report assessment.html --json scan.json
```

The report's **Assessment scope** and **Methodology** show what ran. On a workstation, verify that Opengrep
is on `PATH` for data flow analysis; `--builtin-only` skips all external scanners. For deeper dependency
coverage, commit current lockfiles and ensure the scanner can reach the advisory feeds. For offline scans,
configure a current OSV export and mirrored Trivy database; the bundled advisory pack alone has limited coverage.
The first Trivy scan can take longer while it downloads its database to the scanner cache.

A repository scan assesses source and other files. A DAST report comes from a separate run against a live
application, and lists the checks recorded by that run. Outputs from different tools are only comparable on
the same revision, lockfiles, advisory snapshot and scan scope. Use a labelled set of known findings to
measure recall and precision; matching finding counts alone does not establish accuracy.



<!-- /coderabbit-ai-generated:v1 -->## Deep DAST with OWASP ZAP

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
- Dependency vulnerabilities depend on the advisory source. When OSV cannot be reached (an air-gapped network or a
  proxy that blocks `api.osv.dev`), only the bundled advisory subset is used. The CLI prints a warning and the report
  methodology has a "Limitation" row. Allow the host, set `MYELIN_OSV_URL` to a mirror or load an OSV export
  (`MYELIN_OSV_EXPORT_DIR`).
- Commercial SCA products add proprietary advisories and snippet (copied-code) matching. RAT Flea uses public advisory
  data (OSV, GitHub, NVD-derived) and package manifests only.
- Repository archives downloaded from GitHub, GitLab, Bitbucket and Azure DevOps do not include git history; scan the
  history in the pipeline with the CLI image, where the checkout includes `.git`.
