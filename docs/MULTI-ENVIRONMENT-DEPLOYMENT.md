# NERVE MYELIN multi-environment deployment standard

## Deployment decision

The repository's production deployment model is Kubernetes + Helm. The Compose stacks are for local development, offline demonstration and single-host evaluation. `deploy/compose/Caddyfile` uses Caddy's internal CA and explicitly describes local TLS; it is not the production ingress.

The same Helm chart is promoted through three isolated environments:

| Environment | Values overlay | Intended use | Availability profile |
|---|---|---|---|
| Development | `deploy/environments/development.yaml` | Feature integration and developer validation | 1 replica, autoscaling/PDB/backups disabled |
| Staging | `deploy/environments/staging.yaml` | Release candidate, migration and acceptance testing | 2 replicas, autoscaling and daily backup |
| Production | `deploy/environments/production.yaml` | Customer-facing workload | 3+ replicas, autoscaling, PDB, daily backup, production issuer |

## Isolation rules

Prefer a separate Kubernetes cluster for production and staging. Development may share a non-production cluster. If a shared cluster is used, each environment must have its own namespace, database, database credentials, OIDC client/issuer configuration, ExternalSecret path, evidence storage container/prefix, backup destination, hostname and TLS secret.

Never promote a database, evidence container, API key, signing key, OIDC secret or tenant dataset between environments. Only promote the same immutable application application and backup image digests and matching Helm chart/configuration after validation.

The overlays currently contain deliberately non-routable `.example.invalid` hostnames and `REPLACE_WITH_*` markers, including ingress proxy, database and egress CIDRs. These are guardrails, not working endpoints. The deployment workflow refuses to deploy an overlay while those placeholders remain.

## Cluster prerequisites

Each target cluster must have:

- Kubernetes and Helm 3, an ingress controller, DNS and a working TLS issuer/certificate.
- PostgreSQL reachable privately from the API and migration job. Provision separate databases and least-privilege owner/app logins per environment.
- External Secrets Operator plus a ClusterSecretStore named for the target environment (`myelin-development`, `myelin-staging`, `myelin-production`), connected to that environment's secret vault.
- The seven chart secrets under the configured prefix: `MYELIN_DATABASE_URL`, `MYELIN_MIGRATIONS_DATABASE_URL`, `MYELIN_SESSION_SECRET`, `MYELIN_API_KEY_PEPPER`, `MYELIN_EVIDENCE_SIGNING_KEY`, `MYELIN_OIDC_CLIENT_SECRET`, and `MYELIN_LICENSE`.
- A private object store/container for evidence and a separate backup destination. Configure provider workload identity for both; do not put storage credentials in Helm values.
- A registry pull secret if the GHCR package is private. The chart expects the secret name in `imagePullSecrets`.
- NetworkPolicy-compatible CNI, ingress namespace and database/egress CIDRs narrowed to the real network paths.
- For production monitoring resources, Prometheus Operator CRDs must be installed because the production overlay enables ServiceMonitor and PrometheusRule.
- A licence, production IdP application, DNS hostname and approved change window.

For Azure, the existing customer example demonstrates Azure Key Vault via External Secrets, Azure Workload Identity and Azure Blob Storage. The same chart can target other Kubernetes providers by using the appropriate secret store, workload identity and object-storage URI. Do not copy the sample tenant IDs, client IDs, storage accounts or CIDRs into a live deployment.

## GitHub environment configuration

Create GitHub Environments named `development`, `staging` and `production`. Add environment-specific values and secrets:

| Name | Type | Purpose |
|---|---|---|
| `MYELIN_IMAGE_REPOSITORY` | Variable | Signed API image repository, e.g. `ghcr.io/sudheerkumard/nerve-myelin` |
| `MYELIN_BACKUP_IMAGE_REPOSITORY` | Variable | Signed backup runtime repository, e.g. `ghcr.io/sudheerkumard/nerve-myelin-backup` |
| `MYELIN_NAMESPACE` | Variable | Dedicated namespace, e.g. `nerve-myelin-dev` |
| `KUBE_CONTEXT` | Variable | Expected kubeconfig context name |
| `MYELIN_PUBLIC_URL` | Variable | Environment health-check URL |
| `KUBECONFIG_B64` | Secret | Base64 kubeconfig for a namespace-scoped deployment identity |

Use a namespace-scoped deployment identity with only the permissions needed for Helm-managed resources. Protect staging and production with required reviewers and branch restrictions. Rotate the credential and prefer short-lived federation/OIDC to long-lived kubeconfig credentials where the Kubernetes provider supports it. Never reuse a production credential in development or staging.

## Promotion procedure

1. Merge code to `main`. CI runs tests, security checks, Helm validation, image scanning and image publication.
2. Obtain the immutable `sha256:` digest from the successful image build. Do not use `latest` or a mutable tag.
3. Configure and deploy development first using Actions → `deploy-environment` → Run workflow. Select `development` and supply both the application image digest and the backup runtime image digest from the same successful main CI run.
4. Run login, tenant-isolation, scan ingestion, evidence retrieval, graph, backup and restore smoke tests.
5. Promote the exact same digest to staging. Complete migration compatibility, integration, load and security acceptance tests.
6. Promote that same digest to production after approval. Production additionally requires typing `DEPLOY` in the confirmation input and any GitHub Environment reviewer approval.
7. Confirm deployment revision, image digest, healthy replicas, `/healthz`, `/readyz`, logs, metrics and a successful backup.

The workflow verifies the keyless signatures of both images against the main-branch CI workflow before connecting to Kubernetes. The workflow is manual by design. It does not deploy every commit automatically. The `--atomic` Helm upgrade rolls back Kubernetes release resources when the upgrade fails, but it does not reverse database migrations or restore database contents. Database migrations must remain backward-compatible; database restore is a separate, approved recovery operation.

## Rollback

For an application-only rollback, inspect `helm history myelin -n <namespace>`, then use `helm rollback myelin <revision> -n <namespace> --wait`. Verify the prior image digest and health endpoints. Do not roll back the database independently without checking schema compatibility. For data corruption, use the approved database point-in-time restore and evidence-store recovery runbook.

## Current deployment boundary

This repository contains the chart, overlays and a manual deployment workflow. A live cluster deployment still requires the actual cluster context, DNS, registry access, database, secret stores, identity provider, storage accounts, licence and environment-scoped credentials to be provisioned. No production host, Kubernetes context or live deployment credential is present in the repository. The deployment workflow intentionally fails closed until the target environment is configured.


## Dedicated database backup runtime and workload identity

The database backup CronJob uses the dedicated `Dockerfile.backup` image, not the minimal API image or the upstream PostgreSQL image. It includes PostgreSQL 16 client tools, AWS CLI and Azure CLI. CI builds and scans this image separately, then keylessly signs it. The deployment workflow requires both immutable image digests and verifies both signatures before Helm deployment.

The staging and production overlays enable the dedicated backup image and use a separate backup service account. The API and backup pod templates add the `azure.workload.identity/use: "true"` label when the corresponding service account has an Azure client-ID annotation. Configure distinct least-privilege client IDs for application access and backup writes.

For Azure Workload Identity, configure the AKS OIDC issuer and federated credentials for the API and backup service principals. The backup process uses the projected federated token to authenticate with Azure CLI. For AWS, configure the backup service account with an IRSA role annotation and a write-only bucket policy; the AWS CLI uses the projected role credentials.

Remote object-store retention is enforced by the bucket/container lifecycle policy. The script's `BACKUP_RETENTION_DAYS` cleanup applies only to `file://` storage. Configure S3 lifecycle expiration or Azure Blob lifecycle management for the remote backup prefix. Test restores on a schedule.

## Backup acceptance checks

- Confirm the CronJob completes and emits a SHA-256 manifest.
- Verify the archive with `pg_restore --list`.
- Verify object versioning, encryption and lifecycle policy on the destination.
- Restore into an isolated recovery database and run application health and tenant-isolation tests.
- Keep managed database point-in-time recovery enabled in addition to logical dumps. A successful upload alone is not proof of recoverability.
