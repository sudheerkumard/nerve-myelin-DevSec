# NERvvE DevSecOps — Configuration

*© 2026 Sudheer Kumar. Licensed under the GNU AGPL-3.0; see `LICENSE`.*

All runtime configuration lives here. Code reads these files; nothing customer-specific is hard-coded.

| File | Configures | Used by |
|---|---|---|
| `backend/myelin.env.example` | **Production** API settings template: API keys, demo mode off, CORS, tenant, plan, policy file | Copy to `backend/myelin.env` (git-ignored), or inject as environment variables / Kubernetes secrets |
| `backend/myelin.env.demo` | **Customer live demo** settings: sample tenant, read-only access on localhost | `demo/start-demo.*`, `docker-compose.yml` (default) |
| `frontend/console.config.json` | **Console**: product name, company, contact details, notice, default theme, default demo customer, API base URL | Baked into `console/index.html` by `scripts/build_console.py` |
| `deploy/values-customer.example.yaml` | **Customer self-hosted** Helm override: image and digest, replicas, ingress host, TLS, resources | `helm install myelin deploy/helm/myelin -f config/deploy/values-customer.example.yaml` |
| `certs/` | **Corporate HTTPS inspection**: company root certificates (`.crt`, git-ignored) that container builds trust | `Dockerfile`, `Dockerfile.demo`, `Dockerfile.cli`; filled automatically by `scripts/windows/start-enterprise.ps1` |

Related configuration elsewhere in the repository:

| Path | Purpose |
|---|---|
| `policies/myelin-policy.yaml`, `policies/rego/` | Security gate policy (YAML or OPA/Rego) |
| `deploy/helm/myelin/` | Helm chart for the platform |
| `ci-templates/` | GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, Bitbucket |
| `docker-compose.yml`, `Dockerfile`, `Dockerfile.cli` | Container builds and local run |

## Backend settings reference

| Variable | Default | Notes |
|---|---|---|
| `MYELIN_MODE` | `demo` (image: `enterprise`) | `enterprise` = PostgreSQL + OIDC + RLS; `demo` = in-memory sample tenant |
| `MYELIN_ENV_FILE` | `config/backend/myelin.env` | Which env file to load |
| `MYELIN_API_KEYS` | demo key | Comma-separated; generate with `openssl rand -hex 24` |
| `MYELIN_DEMO_OPEN` | `true` | **Set `false` in every non-demo environment** |
| `MYELIN_CORS` | `*` | Restrict to the console origin in production |
| `MYELIN_TENANT_NAME` / `_PLAN` / `_DEVS` / `_REGION` / `_SSO` | sample tenant | Plan sets feature entitlements |
| `MYELIN_SEED_DEMO_DATA` | `true` | `false` starts empty; findings arrive from `myelin scan --server` |
| `MYELIN_POLICY_FILE` | built-in default | e.g. `policies/myelin-policy.yaml` |
| `MYELIN_LIVE_SCAN_ROOT` | repository root | Live-scan requests cannot read outside this directory |
| `MYELIN_LOG_LEVEL` | `info` | |

### Enterprise mode

| Variable | Default | Notes |
|---|---|---|
| `MYELIN_DATABASE_URL` | — | Least-privilege API login (member of `myelin_app`, NOBYPASSRLS); may be a secret reference |
| `MYELIN_MIGRATIONS_DATABASE_URL` | — | Owner connection; only `myelin migrate` and `myelin admin` use it |
| `MYELIN_IDP_CONFIG` | `config/backend/identity-providers.yaml` | Trusted IdPs, presets, role mapping, MFA requirement |
| `MYELIN_SESSION_SECRET_REF` | `env://MYELIN_SESSION_SECRET` | ≥ 32 random bytes |
| `MYELIN_API_KEY_PEPPER_REF` | `env://MYELIN_API_KEY_PEPPER` | ≥ 32 random bytes |
| `MYELIN_EVIDENCE_SIGNING_KEY_REF` | `env://MYELIN_EVIDENCE_SIGNING_KEY` | Ed25519 private key (PEM or base64 raw) |
| `MYELIN_EVIDENCE_STORE` | `file://<repo>/var/evidence` | `s3://bucket/prefix?region=…`, `azblob://account/container/prefix`, `file:///path` |
| `MYELIN_PUBLIC_URL` | — | External URL for OIDC redirects and CORS |
| `MYELIN_SESSION_IDLE_MINUTES` / `_ABSOLUTE_HOURS` | `30` / `12` | Console session lifetime |
| `MYELIN_METRICS_ENABLED` | `true` | Exposes `/metrics` |
| `MYELIN_LICENSE_REF` | `env://MYELIN_LICENSE` | Licence key issued for NERvvE DevSecOps; missing/expired → restricted (read-only) mode |
| `MYELIN_DEPLOYMENT_ID` | — | Only if the licence is bound to one installation |

Secret references: `env://NAME`, `file:///path`, `azkv://vault/secret`, `awssm://region/name`, `vault://path#key`. Connector credentials must use a vault scheme and include the tenant id. Generate platform secrets with `scripts/ops/gen-secrets.sh`.

Environment variables always override file values. Never commit a real `myelin.env`; it is listed in `.gitignore`.

## After editing the console config

```bash
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
python scripts/build_console.py      # rebuilds console/index.html and demo/offline/NERvvE-DevSecOps-Demo-Console.html
```
