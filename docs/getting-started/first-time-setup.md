# First-time setup: checklist and common issues

Read this before you install the full platform (PostgreSQL, Keycloak, API and console) for the first time, in your
own environment or a client's. Most first-run problems come from the network or from users who are not yet linked to
an organisation, and each one has a short fix. The demo (`demo/start-demo.*`) and the offline console need none of it.

## 1. Before you start

| Check | Why | How |
|---|---|---|
| Docker Desktop (or Docker Engine) running, **6 GB memory or more** | Keycloak, PostgreSQL and the API run together | Docker Desktop → Settings → Resources |
| Ports **8443** and **8444** free on 127.0.0.1 | Console and Keycloak sign-in | `netstat -ano \| findstr ":8443 :8444"` (Windows) · `lsof -i :8443 -i :8444` (macOS/Linux) |
| `myelin.localtest.me` and `auth.localtest.me` resolve to **127.0.0.1** | The local HTTPS addresses | `nslookup auth.localtest.me`. If it fails, add `127.0.0.1 myelin.localtest.me auth.localtest.me` to the hosts file |
| Internet access to Docker Hub, quay.io and PyPI | Images and Python packages are downloaded on the first run | Corporate networks: see [HTTPS inspection](#3-corporate-networks-https-inspection-and-proxies) |
| An authenticator app (Microsoft or Google Authenticator) | MFA is mandatory for every console user | Scan the QR code at first sign-in |
| Windows: PowerShell may block scripts | Execution policy | Run scripts as `powershell -ExecutionPolicy Bypass -File <script>` |

No licence key is needed: the Community edition enables every feature.

## 2. Start the stack

=== "Windows"

    ```powershell
    git clone https://github.com/sudheerkumard/nervve-devsecops; cd nervve-devsecops
    powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1
    ```

    The script generates secrets, saves a corporate root certificate if the network inspects HTTPS, builds and
    starts the stack, creates the sample organisations **acme** and **globex**, links them to Keycloak and trusts
    the local HTTPS certificate. Details: [Windows evaluation](../ENTERPRISE-WINDOWS.md).

=== "macOS / Linux"

    ```bash
    git clone https://github.com/sudheerkumard/nervve-devsecops && cd nervve-devsecops
    scripts/ops/gen-secrets.sh > config/backend/enterprise.env
    # corporate network with HTTPS inspection? copy the company root certificate first (section 3)
    docker compose -f docker-compose.enterprise.yml --env-file config/backend/enterprise.env up -d --build
    # create the sample organisations used by the bundled Keycloak users
    DC="docker compose -f docker-compose.enterprise.yml --env-file config/backend/enterprise.env"
    $DC run --rm migrate admin tenant-create --slug acme --name "Acme Bank" --plan enterprise \
      --bind https://auth.localtest.me:8444/realms/myelin=acme
    $DC run --rm migrate admin tenant-create --slug globex --name "Globex Insurance" --plan enterprise \
      --bind https://auth.localtest.me:8444/realms/myelin=globex
    ```

    The browser shows a certificate warning for the local HTTPS proxy until you trust its root certificate:
    `docker compose -f docker-compose.enterprise.yml cp edge:/data/caddy/pki/authorities/local/root.crt ./local-ca.crt`,
    then add `local-ca.crt` to the system trust store (macOS: Keychain Access → System → Always Trust).

    The secret vault for live-scan test accounts (OpenBao) is initialised by the Windows script only; on macOS and
    Linux, initialise and unseal it yourself (`docker compose ... exec vault bao operator init`) before storing
    test-account tokens. Everything else works without it.

Open **https://myelin.localtest.me:8443**. Bundled test users (first password `ChangeMe!Myelin-2026`):
`alice-admin`, `sam-lead`, `dev-dana`, `audit-arun` (organisation acme) and `gary-admin` (organisation globex).
At first sign-in each user scans a QR code for MFA and chooses a new password.

The Keycloak admin console is at **https://auth.localtest.me:8444/admin**, user `kcadmin`. The password is
`KEYCLOAK_ADMIN_PASSWORD` in `config/backend/enterprise.env` (the Windows script also prints it).

## 3. Corporate networks: HTTPS inspection and proxies

**Symptom:** the build stops at `pip install` with
`CERTIFICATE_VERIFY_FAILED: self-signed certificate in certificate chain`, or `No matching distribution found`.

**Cause:** the network re-signs HTTPS traffic with the company's own root certificate. Your computer trusts it; the
container build does not.

**Fix:** give the build the company root certificate. Certificate checking stays on.

- **Windows:** `start-enterprise.ps1` (and `demo\start-demo.ps1 -Docker`) detect inspection and save the certificate
  to `config\certs` for you. If that does not work, export it by hand: `certmgr.msc` → Trusted Root Certification
  Authorities → Certificates → right-click the company root (often named after the company or a security vendor such
  as Zscaler or Netskope) → All Tasks → Export → **Base-64 encoded X.509**, save as `config\certs\company-root.crt`.
- **macOS:** Keychain Access → System → find the company root → File → Export Items → `.pem`, then save it as
  `config/certs/company-root.crt`.
- **Linux:** ask IT for the root certificate (PEM) and save it as `config/certs/company-root.crt`.

Then build again (`--build`). Every image build adds the `.crt` files in `config/certs` to its trusted
certificates; those files are git-ignored. Some companies publish the certificate on their intranet; IT can confirm
which one is in use.

**Proxy required?** Builds time out instead of failing on the certificate. Set the proxy in Docker Desktop →
Settings → Resources → Proxies (Docker Engine: `/etc/systemd/system/docker.service.d/http-proxy.conf`), then
build again.

## 4. Users and organisations

Every console user must belong to exactly **one organisation (tenant)** that exists on the platform. Data is isolated
per organisation by PostgreSQL row-level security.

| Message after sign-in | Meaning | Fix |
|---|---|---|
| *Your account is not linked to an organisation … the 'tenant' claim is missing* | The Keycloak user has no organisation set | Set the user's **NERvvE DevSecOps tenant** field and a role (below) |
| *Your account names an organisation that does not exist … tenant not provisioned* | The field is set, but no organisation with that slug was created | Create the organisation (below), then sign in again |
| *Multi-factor authentication is required* | MFA not completed | Sign in again and enter the authenticator code |
| *Client secret does not match* | Keycloak's client secret changed | Windows: run `start-enterprise.ps1` again; otherwise set `MYELIN_OIDC_CLIENT_SECRET` to the secret of the `myelin-console` client |

### Add an organisation and link a user

=== "Windows (one command)"

    ```powershell
    powershell -ExecutionPolicy Bypass -File scripts\windows\new-tenant.ps1 -Slug nervve -Name "NERvvE Labs" -User "<keycloak username>"
    ```

    Creates the organisation, links it to Keycloak, sets the user's organisation and assigns `myelin-tenant-admin`
    (choose another with `-Role`). Leave out `-User` to create the organisation only.

=== "Any platform"

    1. Create the organisation (slug: lower-case letters, digits and `-`):

        ```bash
        docker compose -f docker-compose.enterprise.yml --env-file config/backend/enterprise.env run --rm migrate \
          admin tenant-create --slug nervve --name "NERvvE Labs" --plan enterprise \
          --bind https://auth.localtest.me:8444/realms/myelin=nervve
        ```

    2. In Keycloak (realm **myelin**) → **Users** → open or create the user → set **NERvvE DevSecOps tenant** to
       `nervve` → **Save**.
    3. **Role mapping → Assign role** → `myelin-tenant-admin` (or `myelin-security-lead`, `myelin-developer`,
       `myelin-auditor`, `myelin-viewer`).
    4. Sign out of the console and sign in again.

List organisations with `... run --rm migrate admin tenants`. To move a user, change the field and sign in again.

### Your own identity provider

With Entra ID, Okta, Auth0, Ping or Google instead of the bundled Keycloak, the organisation comes from a claim in
the token (for example `tid` for Entra ID). Bind each organisation to its issuer and claim value with
`admin tenant-create --bind <issuer>=<claim value>` or `admin bind`. See [Identity and access](../enterprise/IDENTITY.md).

## 5. Other first-run issues

| Symptom | Fix |
|---|---|
| "Docker is not running" | Start Docker Desktop and wait for **Engine running** |
| Containers keep restarting, Keycloak never becomes healthy | Give Docker more memory (6 GB or more); check `docker compose ... logs keycloak` |
| Browser says "Not secure" | Trust the local root certificate (section 2), or accept the warning once; restart the browser |
| Authenticator code rejected | Set the phone's time to automatic; codes change every 30 seconds |
| A port is already in use | Stop the program using 8443/8444, or change the published ports of the `edge` service in `docker-compose.enterprise.yml` (and the URLs that use them) |
| Changed secrets in `enterprise.env` and now nothing signs in | Secrets are applied when data is first created. Reset the evaluation stack (Windows: `start-enterprise.ps1 -Reset`; otherwise `docker compose ... down -v`). This **deletes all data** |
| Anything else | `docker compose -f docker-compose.enterprise.yml --env-file config/backend/enterprise.env logs --tail 80 myelin-api keycloak migrate` |

## 6. Before a client production deployment

The single-host stack is for evaluation. For production use the Helm chart on Kubernetes with a managed PostgreSQL
(backups and point-in-time recovery), the client's own identity provider, a public TLS certificate and a secret
vault. See [Operations](../enterprise/OPERATIONS.md) and [Multi-tenancy](../enterprise/MULTI-TENANCY.md).
