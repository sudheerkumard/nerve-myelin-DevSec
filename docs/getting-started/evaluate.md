# Get NERvvE DevSecOps

The NERvvE DevSecOps **Community edition** is free and open source under the GNU AGPL-3.0. Every feature is included and
no licence key is needed: download it, run it on your own machines, and scan your own code today.

## 1. Explore

- Read the [feature tour](features.md), the [architecture](architecture.md) and the [data flow](data-flow.md).
- Open the [interactive architecture explorer](../assets/explorer/index.html): click any component to see what it
  receives, what it sends and how it is protected, or play the flows step by step.
- Browse the [rule catalogue](../reference/rules.md) to see exactly what is checked.

## 2. Run it

```bash
git clone https://github.com/sudheerkumard/nervve-devsecops
cd nervve-devsecops
./demo/start-demo.sh                  # Windows: demo\start-demo.ps1  ->  http://localhost:8080
```

The demo runs the real engines on a fictional organisation with sample repositories, cloud accounts, a cluster and
runtime events, so every view has data. For a production-like stack (PostgreSQL, Keycloak, TLS), see the
[quick start](quick-start.md) and, before a first installation, [First-time setup and common issues](first-time-setup.md).

## 3. Scan your own code

```bash
pip install .                         # provides the `myelin` command
myelin scan /path/to/your/repo --policy policies/myelin-policy.yaml
```

To add NERvvE DevSecOps to a pipeline, see [Add to your pipeline](../CI-INTEGRATION.md).

## What you need

- A Linux, macOS or Windows machine with Python 3.10+ and Docker, or a Kubernetes cluster you control.
- For Kubernetes: each API pod requests 0.25 CPU and 512 MiB (limit 2 CPU, 2 GiB), with three replicas by default;
  PostgreSQL 16, an OIDC identity provider and a secrets vault. The full list is in [Operations](../enterprise/OPERATIONS.md).
- Optional: read-only access to a non-production cloud account or cluster for the cloud and runtime views.

## Your code and data stay with you

- **Scans run on your runner.** Source code is read where the scan runs; findings are uploaded, code is not.
- **Cloud access is read-only.** The collectors use the [least-privilege permission files](../CLOUD-SECURITY.md) in
  this repository and never read data or Kubernetes Secrets.
- **Nothing is sent to us.** The platform runs fully in your environment, and can run air-gapped.

## Help, contributions and commercial options

- **Questions and ideas:** open an issue in the repository. Never post credentials, code or internal details.
- **Security vulnerabilities:** report privately as described in `SECURITY.md`, never in a public issue.
- **Contributing:** see `CONTRIBUTING.md`; contributions are accepted under the contributor licence agreement (`CLA.md`).
- **Commercial licences, support and enterprise options:** available from the author. Use the
  **Request an evaluation** issue form to get in touch.
