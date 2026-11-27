# Add RAT Flea DevSec to your pipeline

Two commands do the work in any CI/CD system:

| Command | Where | What it does |
|---|---|---|
| `myelin scan` | Pull requests and builds | Scans the checkout on your runner, uploads findings, and returns the policy decision |
| `myelin gate` | Deployment jobs | Asks the platform whether the exact commit being deployed may go to that environment |

The exit code is the gate: `0` pass or warn, `1` blocked by policy. Source code is read on your runner and is never
uploaded; only findings, the SBOM and the decision are sent to the platform.

## Before you start

| You need | Where it comes from |
|---|---|
| The `myelin` CLI | `pip install .` from the repository, or the `myelin-cli` container image built with `Dockerfile.cli` |
| `MYELIN_SERVER` | The URL of your RAT Flea DevSec platform (optional: without it, `myelin scan` runs fully offline) |
| `MYELIN_API_KEY` | An integration API key, created in the console by a tenant administrator (**Create API key**). Store it as a CI secret |
| A policy file | Start from [`policies/myelin-policy.yaml`](https://github.com/sudheerkumard/nervve-devsecops/blob/main/policies/myelin-policy.yaml) and commit it as `.myelin/policy.yaml` |

Integration keys carry the narrow integration role: upload scans and read findings and decisions. They cannot
administer the tenant.

## Roll out without stopping delivery

1. **Audit.** Set the policy `mode: audit`. Every pipeline reports, nothing blocks. Use the first week to fix the
   noisiest findings and record exceptions.
2. **Warn.** Switch to `mode: warn`. Pipelines show warnings and owners get tickets, still without blocking.
3. **Enforce.** Switch to `mode: enforce` and add the deployment gate with `--scope new`, so only findings a commit
   introduces can block it. Tighten to `--scope all` once the backlog is under control.

## Pull requests and builds

=== "GitHub Actions"

    ```yaml
    # .github/workflows/myelin.yml
    name: myelin
    on:
      pull_request:          # untrusted pull request code runs without secrets
      push:
        branches: [main]
    permissions:
      contents: read
    jobs:
      scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
            with: { fetch-depth: 0, persist-credentials: false }   # full history for secrets-in-history checks
          - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
            with: { python-version: "3.12" }
          - run: pip install "${{ vars.MYELIN_CLI_PACKAGE }}"
          - run: myelin scan . --policy .myelin/policy.yaml --sarif myelin.sarif --sbom sbom.cdx.json --fail-on block
            env:
              MYELIN_SERVER: ${{ vars.MYELIN_SERVER }}
              MYELIN_API_KEY: ${{ secrets.MYELIN_API_KEY }}
    ```

    Add your code-scanning upload step for `myelin.sarif` to see findings as pull request annotations. Pin every
    `uses:` to a full commit SHA (RAT Flea DevSec reports rule NM-CICD-001 until you do).

=== "Azure Pipelines"

    ```yaml
    # azure-pipelines.yml
    trigger: [main]
    pr: [main]
    variables:
      - group: myelin              # MYELIN_SERVER, MYELIN_API_KEY (secret), MYELIN_CLI_PACKAGE
    steps:
      - checkout: self
        fetchDepth: 0
      - task: UsePythonVersion@0
        inputs: { versionSpec: "3.12" }
      - script: pip install "$(MYELIN_CLI_PACKAGE)"
      - script: >
          myelin scan . --policy .myelin/policy.yaml
          --sarif $(Build.ArtifactStagingDirectory)/CodeAnalysisLogs/myelin.sarif --fail-on block
        env: { MYELIN_SERVER: $(MYELIN_SERVER), MYELIN_API_KEY: $(MYELIN_API_KEY) }
    ```

    Link the variable group to Azure Key Vault so the API key never sits in pipeline settings.

=== "GitLab CI"

    ```yaml
    # .gitlab-ci.yml
    myelin-scan:
      stage: test
      image: ghcr.io/sudheerkumard/myelin-cli@sha256:<digest of your myelin-cli image>
      script:
        - myelin scan . --policy .myelin/policy.yaml --sarif gl-sast-report.sarif --sbom gl-sbom.cdx.json --fail-on block
      artifacts:
        when: always
        paths: [gl-sast-report.sarif, gl-sbom.cdx.json]
    ```

    Set `MYELIN_SERVER` and `MYELIN_API_KEY` as masked, protected CI/CD variables.

=== "Jenkins"

    ```groovy
    // Jenkinsfile
    pipeline {
      agent { docker { image 'ghcr.io/sudheerkumard/myelin-cli@sha256:<digest>' } }
      environment { MYELIN_SERVER = 'https://myelin.example.com' }
      stages {
        stage('RAT Flea DevSec scan') {
          steps {
            withCredentials([string(credentialsId: 'myelin-api-key', variable: 'MYELIN_API_KEY')]) {
              sh 'myelin scan . --policy .myelin/policy.yaml --sarif myelin.sarif --fail-on block'
            }
          }
        }
      }
    }
    ```

=== "Bitbucket Pipelines"

    ```yaml
    # bitbucket-pipelines.yml
    image: ghcr.io/sudheerkumard/myelin-cli@sha256:<digest>
    pipelines:
      pull-requests:
        "**":
          - step:
              name: RAT Flea DevSec scan
              script:
                - myelin scan . --policy .myelin/policy.yaml --sarif myelin.sarif --fail-on block
              artifacts: [myelin.sarif]
    ```

    Add `MYELIN_SERVER` and `MYELIN_API_KEY` as secured repository variables.

## Container images

Scan the image you built, before it is pushed to production registries:

```bash
myelin scan --image registry.example.com/payments-api@sha256:<digest> --policy .myelin/policy.yaml --fail-on block
```

Image scanning uses Trivy, which is included in the `myelin-cli` image. Stored SBOMs are re-matched automatically when
new advisories arrive, so an image that was clean at build time is flagged if a vulnerability is published later.

## Deployment gate

Run the gate in the deployment job, immediately before the deploy step:

```bash
myelin gate --repo payments-api --commit "$COMMIT_SHA" --environment production \
  --scope new --require sast,sca,secrets
```

- **Fails closed.** A commit that was never scanned is blocked (`--allow-unscanned` turns this off; use it only while onboarding).
- **`--scope new`.** Only findings this commit introduced can block, so old issues do not stall unrelated releases.
- **`--require`.** Blocks when a required engine did not run, so a green gate always means complete coverage.
- **`--environment`.** Recorded in the audit trail with the decision.

The same command works in GitHub Actions protected environments, Azure Pipelines environments, GitLab manual
production jobs and an Argo CD PreSync hook, which stops a sync when the gate blocks.

## Developer machines

`myelin precommit` checks staged files before each commit, and `myelin mcp` lets AI coding assistants check code and
packages before they write them. See [Developer tools](DEVELOPER-TOOLS.md).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `401 Unauthorized` | The API key is missing, expired or for another tenant. Create a new integration key |
| Gate blocks with "commit not scanned" | The scan ran on a different commit (for example a merge commit). Scan the commit you deploy |
| Gate blocks with "required engine missing" | An engine in `--require` did not run or failed. Check the scan log for that engine |
| Scan is slow on large repositories | List vendored and generated folders in `.myelinignore` so they are skipped |
