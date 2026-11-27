# Quick start

Three ways to see RAT Flea DevSec, from a minute to a production-like stack.

!!! note "Before you start"
    Clone the open-source Community edition first:
    `git clone https://github.com/sudheerkumard/nervve-devsecops && cd nervve-devsecops`.
    See [Get RAT Flea DevSec](evaluate.md) for the options.

=== "Demo in 60 seconds"

    ```bash
    ./demo/start-demo.sh          # Windows: demo\start-demo.ps1   →  http://localhost:8080
    ```

    The demo runs the real engines against the fictional tenant *Orion Financial Group*, including sample cloud
    accounts, a Kubernetes cluster and runtime detections. **Live scan** scans `demo/vulnerable-app` in front of you.

=== "No server at all"

    Open `demo/offline/RAT-Flea-DevSec-Demo-Console.html` in a browser. Every view works on a recorded snapshot; actions
    that change data are available once an API is connected.

=== "Enterprise stack on one host"

    ```bash
    scripts/ops/gen-secrets.sh > config/backend/enterprise.env
    docker compose -f docker-compose.enterprise.yml --env-file config/backend/enterprise.env up -d
    ```

    PostgreSQL with row-level security, Keycloak with MFA, migrations, the API and TLS. Windows laptops:
    `scripts\windows\start-enterprise.ps1`.

    !!! warning "First installation?"
        Read [First-time setup and common issues](first-time-setup.md) first: corporate networks that inspect
        HTTPS, creating organisations and linking users to them.

## Your first scan from a pipeline

```bash
pip install .                              # from the repository root; provides the `myelin` command
export MYELIN_SERVER=https://myelin.example.com MYELIN_API_KEY=<integration key>
myelin scan . --policy policies/myelin-policy.yaml --sarif out.sarif --fail-on block
```

The exit code is the gate: `0` pass or warn, `1` blocked by policy. Examples for GitHub Actions, Azure Pipelines,
GitLab CI, Jenkins and Bitbucket are in [Add to your pipeline](../CI-INTEGRATION.md).

## Next steps

<div class="grid cards" markdown>

-   :material-source-repository: **[Scan a repository from the console](../SCAN-A-REPOSITORY.md)** — one click, any Git host
-   :material-gate: **[Gate deployments](../CD-PIPELINE-SECURITY.md)** — commit-bound CD gate and admission control
-   :material-cloud-search-outline: **[Connect a cloud account](../CLOUD-SECURITY.md)** — read-only, minutes to first findings
-   :material-ticket-outline: **[Send findings to Jira or ServiceNow](../TICKETING.md)** — routed, de-duplicated, auto-resolved

</div>
