# Production-style RAT Flea DevSec on a Windows laptop

> **First installation?** Read [First-time setup and common issues](getting-started/first-time-setup.md): corporate networks, organisations and users.

> **Step-by-step guide (offline and online, with tokens, ownership verification and timings):** [LIVE-APP-TESTING-GUIDE.md](LIVE-APP-TESTING-GUIDE.md)

Runs the same components as a customer production deployment on one machine with Docker Desktop:
PostgreSQL 16 (row-level security) · Keycloak 26 (single sign-on, mandatory MFA) · RAT Flea DevSec API and console ·
HTTPS proxy. Use it for evaluation, demos with real sign-in, and your own testing. Customer production uses the
Helm chart on Kubernetes (`docs/enterprise/OPERATIONS.md`).

## Prerequisites (once)



1. **Docker Desktop** running ("Engine running"), with at least 6 GB memory in Settings → Resources.
2. A checkout of the repository. The Docker console does not require a host Python environment. Run `scripts\windows\setup-myelin.ps1` if you also want the laptop CLI or need to generate a local licence with the optional licensing tool.
3. An authenticator app on your phone: Microsoft Authenticator or Google Authenticator.

<!-- /coderabbit-ai-generated:v1 -->

## Start

```powershell
cd $HOME\nervve-devsecops
powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1
```

The first run takes several minutes (it builds the image and downloads PostgreSQL, Keycloak and Caddy). It:

- generates secrets into `config\backend\enterprise.env` (private; git-ignored);
- Community edition: no licence key is needed and every feature is enabled;
- on networks that inspect HTTPS, saves the company root certificate to `config\certs` so the image build trusts it
  (see [Troubleshooting](#troubleshooting));
- starts the stack, creates two organisations (Acme Bank, Globex Insurance) and links them to Keycloak;
- trusts the local HTTPS certificate for your Windows user (confirm the Windows prompt with **Yes**);
- opens **https://myelin.localtest.me:8443**.

## Sign in

| User | Organisation | Role |
|---|---|---|
| `alice-admin` | Acme Bank | Tenant administrator |
| `sam-lead` | Acme Bank | Security lead (registers and runs scans) |
| `dev-dana` | Acme Bank | Developer |
| `audit-arun` | Acme Bank | Auditor (read-only + evidence review) |
| `gary-admin` | Globex Insurance | Tenant administrator — sees none of Acme's data |

First password for every user: `ChangeMe!Myelin-2026`. On first sign-in you **scan a QR code** with your
authenticator app, enter the 6-digit code, then **choose a new password**. Afterwards each sign-in asks for the
password and a fresh code.

Manage users, roles and MFA in Keycloak: **https://auth.localtest.me:8444/admin** — user `kcadmin`, password shown
at the end of the start script (also `KEYCLOAK_ADMIN_PASSWORD` in `config\backend\enterprise.env`).
To add a user to an existing organisation: **Users → Add user** (or open an existing user), set the field
**RAT Flea DevSec tenant** to `acme` or `globex`, save, then **Role mapping → Assign role** (for example
`myelin-security-lead`). The user enrols MFA at first sign-in.

## Add your own organisation (tenant)

Each organisation is a tenant with its own data, isolated by PostgreSQL row-level security. Pick a short slug
(lower-case letters, digits and `-`), then run, with the stack started:

```powershell
# create the organisation and link your Keycloak user to it as tenant administrator
powershell -ExecutionPolicy Bypass -File scripts\windows\new-tenant.ps1 -Slug rat-flea -Name "RAT Flea Labs" -User "sudheer kumar"
```

Sign out of the console and sign in again: you land in the new, empty organisation. Start with **Integrations** (connect
a Git provider) or **Live scan**. Without `-User`, the script only creates the organisation and tells you what to set in
Keycloak. Other roles: `-Role myelin-security-lead`, `myelin-developer`, `myelin-auditor` or `myelin-viewer`.

What the script does, if you prefer to do it by hand:

1. Create the organisation and bind it to the Keycloak realm (claim value = slug):

   ```powershell
   docker compose -f docker-compose.enterprise.yml --env-file config\backend\enterprise.env run --rm migrate `
     admin tenant-create --slug rat-flea --name "RAT Flea Labs" --plan enterprise `
     --bind "https://auth.localtest.me:8444/realms/myelin=rat-flea"
   ```

2. In Keycloak (realm `myelin`) open the user, set **RAT Flea DevSec tenant** to `rat-flea`, save, and assign the realm
   role `myelin-tenant-admin`.

List organisations: `docker compose -f docker-compose.enterprise.yml --env-file config\backend\enterprise.env run --rm migrate admin tenants`.
A user belongs to one organisation at a time; to switch, change the field and sign in again.

## Live scans with test accounts (multi-user authorisation)

The stack includes a local secret vault (OpenBao). The start script initialises it once, unseals it on every start and
gives the API a read-only token. The unseal key and root token are saved to `%USERPROFILE%\nerve-keys\openbao-init.json`
— back that file up; it is not in the repository and without it the stored credentials cannot be recovered.

1. Create two ordinary customer accounts in **your own** application (and optionally an admin account) and obtain a token for each.
2. Store each one (the value is typed hidden; enter the full header value, e.g. `Bearer eyJ...`):

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows\myelin-secret.ps1 -Tenant globex -Name customer-a
   powershell -ExecutionPolicy Bypass -File scripts\windows\myelin-secret.ps1 -Tenant globex -Name customer-b
   powershell -ExecutionPolicy Bypass -File scripts\windows\myelin-secret.ps1 -Tenant globex -Name admin -Role admin
   ```

   `-Tenant` is the organisation of the account you sign in with: `acme` for alice-admin / sam-lead, `globex` for gary-admin.
3. Each command prints an identity line. Paste them, comma-separated inside `[ ]`, into **Live app testing → Register target → Test identities**.
4. Publish the verification token at `https://<your-host>/.well-known/myelin-verification.txt`, click **Verify**, then **Run**.

Tokens expire in your application: when a run reports authentication failures, store a fresh value with the same command
(same name — the reference does not change). Only test applications you own or are authorised in writing to test.

## Stop, restart, reset

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1 -Stop     # keeps all data
powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1           # start again
powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1 -Reset    # delete ALL data
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Docker is not running" | Start Docker Desktop and wait for "Engine running" |
| `auth.localtest.me does not resolve` | Add `127.0.0.1 myelin.localtest.me auth.localtest.me` to `C:\Windows\System32\drivers\etc\hosts` (Notepad as Administrator) |
| Browser says "Not secure" | Accept once, or re-run the start script and confirm the certificate prompt; restart the browser |
| Authenticator code rejected | Check the phone's time is set automatically; codes change every 30 seconds |
| "We couldn't sign you in — not linked to an organisation" | Set the user's **RAT Flea DevSec tenant** field in Keycloak to an existing organisation (`acme`, `globex`, or one you added with `new-tenant.ps1`), then sign in again |
| Build fails: `CERTIFICATE_VERIFY_FAILED … self-signed certificate in certificate chain` | Your network inspects HTTPS. The start script normally saves the company root certificate to `config\certs` automatically. If not: `certmgr.msc` → Trusted Root Certification Authorities → Certificates → right-click the company root → All Tasks → Export → Base-64 encoded X.509, save as `config\certs\company-root.crt`, and run the start script again. Certificate checking stays on |
| Anything else | `docker compose -f docker-compose.enterprise.yml logs --tail 80 myelin-api keycloak` |

## Differences from customer production

Same software and security controls; for production also use: a managed PostgreSQL with backups and point-in-time
recovery, the customer's own identity provider (Entra ID, Okta, …) or a hardened Keycloak, a public certificate,
and a vault for secrets. See [Operations](enterprise/OPERATIONS.md).
