# Live application testing with RAT Flea DevSec — quick start (Windows / PowerShell)

> **Step-by-step guide (offline and online, with tokens, ownership verification and timings):** [LIVE-APP-TESTING-GUIDE.md](LIVE-APP-TESTING-GUIDE.md)

> **Authorisation first.** Scan only APIs you own or have **written permission** to test. Agree the time window,
> target URL and contact person with the API owner. The default scan is read-only, but it still sends a few
> hundred requests and may show up in their monitoring.

## 1. One-time laptop setup (about 5 minutes)

```powershell
# Prerequisites (skip what you already have)
winget install -e --id Python.Python.3.12
winget install -e --id Git.Git
winget install -e --id GitHub.cli                 # easiest way to clone the private repository
# optional, only for the deeper OWASP ZAP scan:  winget install -e --id Docker.DockerDesktop

# Open a NEW PowerShell window, then:
gh auth login                                     # sign in to GitHub once
gh repo clone sudheerkumard/nerve-myelin
cd nerve-myelin
powershell -ExecutionPolicy Bypass -File scripts\windows\setup-myelin.ps1 -WithConsole
```

In every new PowerShell window, activate the environment before using `myelin`:

```powershell
cd nerve-myelin
.\.venv\Scripts\Activate.ps1
```

If activation is blocked by policy, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

## 2. Collect three things from the API owner

| Item | Example | Why |
|---|---|---|
| Base URL | `https://api.client.com` | What to scan |
| OpenAPI / Swagger spec | `https://api.client.com/swagger/v1/swagger.json` or a file | Lets RAT Flea test every operation that should require login |
| Test credentials (optional) | a bearer token or API key for a **test** user | Lets RAT Flea compare logged-in and anonymous behaviour |

## 3. Run the safe (read-only) scan

```powershell
$env:MYELIN_DAST_AUTH = "Bearer eyJ..."           # only if you have a token; kept out of command history
myelin dast --target https://api.client.com `
            --openapi https://api.client.com/swagger/v1/swagger.json `
            --name client-payments-api --criticality high `
            --json result.json --sarif result.sarif
Remove-Item Env:MYELIN_DAST_AUTH                  # clear the token afterwards
```

For an API key header instead of a bearer token: `--header "X-API-Key: <key>"`.

What it checks (GET/HEAD/OPTIONS only, at most 300 requests, 0.2 s apart):

| Rule | Check | OWASP API Top 10 |
|---|---|---|
| NM-DAST-001 | Plain HTTP, or HTTP not redirected to HTTPS | API8 |
| NM-DAST-002 / 013 / 014 | Untrusted certificate, legacy TLS 1.0/1.1, certificate expiring | API8 |
| NM-DAST-003 / 004 / 012 | HSTS, nosniff, CSP / frame protection | API8 |
| NM-DAST-005 | CORS reflecting any origin or wildcard with credentials | API8 |
| NM-DAST-006 / 007 | Version disclosure; TRACE enabled | API8 |
| NM-DAST-009 | Stack traces / framework internals in errors | API8 |
| NM-DAST-011 | Cookies without Secure / HttpOnly / SameSite | API8 |
| NM-DAST-008 | Swagger / OpenAPI / GraphQL docs public | API9 |
| NM-DAST-010 | Operation the spec says needs login answers **without** credentials | API2 |

Exit code: `0` pass, `1` the policy gate blocked (e.g. an unauthenticated operation), `2` usage error.
Useful options: `--fail-on never` (report only), `--max-requests`, `--delay`, `--insecure` (continue past an untrusted certificate; still reported).

## 4. Multi-user authorisation testing (the most important API risks)

Ask the API owner for **two or more test users** (ideally two ordinary customers and one admin) in a test or UAT
environment. Put their tokens in environment variables and describe them in a small file, e.g. `users.yaml`:

```yaml
identities:
  - name: customer-a
    role: customer
    headers: { Authorization: "env:TOKEN_A" }     # "Bearer …" read from the environment, never stored in the file
  - name: customer-b
    role: customer
    headers: { Authorization: "env:TOKEN_B" }
  - name: admin
    role: admin
    headers: { Authorization: "env:TOKEN_ADMIN" }
cross_user_roles: [admin]                        # roles allowed to see everyone's data
privileged:                                      # operations only these roles may call (paths tagged "admin" are found automatically)
  - path: /api/*/admin/*
    roles: [admin]
```

```powershell
$env:TOKEN_A = "Bearer eyJ..."; $env:TOKEN_B = "Bearer eyJ..."; $env:TOKEN_ADMIN = "Bearer eyJ..."
myelin dast --target https://uat-api.client.com --openapi swagger.json --identities users.yaml `
            --name client-payments-api --report assessment.html --customer "Client name"
```

What it tests (still read-only — GET requests only):

| Rule | Check | OWASP API Top 10 |
|---|---|---|
| NM-DAST-020 | Customer B can read customer A's objects by changing the ID in the URL (BOLA / IDOR) | API1 |
| NM-DAST-021 | The same objects are readable without any login | API2 |
| NM-DAST-022 | Responses contain sensitive fields (password hashes, secrets, PAN/Aadhaar, card numbers) | API3 |
| NM-DAST-023 | A non-admin can call admin operations | API5 |

How it works: RAT Flea calls every list endpoint as each user, collects the IDs each user owns, then requests each
user's objects as the other users and anonymously. A finding is raised only when the other user receives the
**same object** — properly protected endpoints are not flagged.

`assessment.html` is a self-contained report (executive summary, scope, method, findings with evidence, reproduction
steps and fixes) that you can share or print to PDF. Tokens are never written to it.

## 5. Online — run from the RAT Flea platform

1. Open the console → **Live app testing** → **Register target**: name, base URL, OpenAPI URL and the test users.
   In enterprise installations the user credentials are **vault references** (`vault://…/tenants/<tenant-id>/…`,
   `azkv://…`, `awssm://…`), never tokens.
2. **Verify ownership** (hosted/SaaS scans): publish the shown token at
   `https://<your-api>/.well-known/myelin-verification.txt`, then click **Verify**.
3. Click **Run**. Results appear in the table, in **Findings**, in the policy gate, and as a downloadable **Report**.

Platform safeguards: read-only mode, request budget, scope locked to the target host, refusal of loopback, link-local,
cloud-metadata and (unless a self-hosted installation enables `MYELIN_DAST_ALLOW_PRIVATE`) private addresses,
licence and role checks (`dast:manage`, `dast:run`), and a full audit trail.

## 6. Deeper scan with OWASP ZAP (optional, needs Docker Desktop)

```powershell
myelin dast --target https://api.client.com --zap                    # + ZAP passive baseline (no attacks)
myelin dast --target https://uat-api.client.com --openapi spec.json `
            --zap --active --authorized                               # ZAP active scan: SENDS ATTACK PAYLOADS
```

Use `--active` only against a test/UAT environment, with written permission and a backup of its data — active scans
try injections and can create or change records.

## 7. Upload offline results to the console

```powershell
powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1         # console at http://localhost:8080
$env:MYELIN_API_KEY = "nm_demo_9f2c41e7b8"                            # demo key from config\backend\myelin.env.demo
myelin dast --target https://api.client.com --openapi <spec> --name client-payments-api --server http://localhost:8080
```

Open **Findings**, choose the repository `client-payments-api`: each issue shows its risk score, evidence, CWE,
compliance mapping and fix advice. `result.sarif` can also be opened in VS Code (SARIF Viewer) or uploaded to GitHub code scanning.

## 8. Practise on the built-in demo API first

```powershell
python demo\vulnerable-api\app.py                                    # fictional insecure API on http://127.0.0.1:8090
myelin dast --target http://127.0.0.1:8090 --openapi http://127.0.0.1:8090/openapi.json `
            --identities demo\vulnerable-api\identities.example.yaml --report demo-report.html --fail-on never
```

Expect 12 findings including two **critical**: `/api/v1/accounts` returns data without a token, and `bob` can read
`alice`'s account through `/api/v2/accounts/{accountId}`. The card and audit endpoints are correctly protected and are not flagged.

## Limits of the safe scan

It does not attempt injection, write operations across users (changing or deleting another user's data),
business-logic abuse or rate-limit testing — use the ZAP active scan in UAT and a manual penetration test for those.
