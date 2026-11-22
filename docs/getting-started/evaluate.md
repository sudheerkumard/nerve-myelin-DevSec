# Evaluate NERVE Myelin

NERVE Myelin is proprietary software supplied under subscription. You can explore it from this documentation today,
see it working in a guided demo, and then run it in your own environment under an evaluation licence.

## 1. Explore

- Read the [feature tour](features.md), the [architecture](architecture.md) and the [data flow](data-flow.md).
- Open the [interactive architecture explorer](../assets/explorer/index.html): click any component to see what it
  receives, what it sends and how it is protected, or play the flows step by step.
- Browse the [rule catalogue](../reference/rules.md) to see exactly what is checked.

## 2. See a guided demo

A guided demo walks through the console on a fictional organisation: the executive overview, findings and their risk
score, pipeline and supply-chain checks, cloud, Kubernetes and runtime views, policies and reports, focused on the
areas you care about most.

## 3. Request an evaluation

Open a **Request an evaluation** issue in
[github.com/sudheerkumard/nerve-myelin-DevSec](https://github.com/sudheerkumard/nerve-myelin-DevSec/issues/new/choose).
Issues are public, so give only your name, organisation and the areas you want to evaluate; never post credentials,
code or internal details. We follow up privately to agree the scope.

## What an evaluation includes

| You receive | Details |
|---|---|
| Evaluation licence key | Signed key for the agreed period (30 days unless stated otherwise), for assessment only and not for production use |
| Container images | API, console, worker and CLI images, pulled with registry credentials issued to your organisation |
| Deployment bundle | Docker Compose for one host, or a Helm chart for Kubernetes, with the deployment guide and CI/CD templates |
| Demo data | A fictional tenant with sample repositories, cloud accounts, a cluster and runtime events, so every view has data on day one |
| Help | A setup session and answers to questions during the evaluation |

## What you need

- A Linux host with Docker, or a Kubernetes cluster you control (a Windows laptop with Docker Desktop is fine for a
  first look).
- For Kubernetes: each API pod requests 0.25 CPU and 512 MiB (limit 2 CPU, 2 GiB), with three replicas by default;
  PostgreSQL 16, an OIDC identity provider and a secrets vault. The full list is in [Operations](../enterprise/OPERATIONS.md).
- Optional: a test repository, a CI pipeline, and read-only access to a non-production cloud account or cluster.
- To add NERVE Myelin to a pipeline, see [Add to your pipeline](../CI-INTEGRATION.md).

## Your code and data stay with you

- **Scans run on your runner.** Source code is read where the scan runs; findings are uploaded, code is not.
- **Cloud access is read-only.** The collectors use the [least-privilege permission files](../CLOUD-SECURITY.md) in
  this repository and never read data or Kubernetes Secrets.
- **Nothing is sent to us.** The platform runs fully in your environment, and can run air-gapped.

## Getting help

During an evaluation, ask in your evaluation request or in the setup session. Customers raise support requests as set
out in [Support and Service Levels](../legal/SUPPORT-AND-SERVICE-LEVELS.md). Report security vulnerabilities privately,
as described in the repository's `SECURITY.md`, never in a public issue.

## After the evaluation

Move to a subscription with a new licence key. Findings, history and settings from the evaluation carry over. If a
licence expires, the platform switches to read-only and never deletes your data. Terms are in the
[Subscription Agreement](../legal/SUBSCRIPTION-AGREEMENT.md).
