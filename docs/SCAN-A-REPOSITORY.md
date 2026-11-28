# Scan a repository from the console

![Repositories: one-click scans and full reports](assets/screenshots/repos.webp){ .nm-shot }

The quickest way to get a full code security report. No command line, no API keys.

1. Sign in to the console and open **Repositories**.
2. Click **＋ Add repository**.
3. Paste the repository address — GitHub, GitLab, Bitbucket, Azure DevOps, AWS CodeCommit, Google Cloud or any Git
   server (see [SOURCE-PROVIDERS.md](SOURCE-PROVIDERS.md) for each address format and credential). Leave **Branch** empty for the default branch.
4. **Private repository?** Paste a read-only access token:
   - **GitHub:** Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → *Generate new token* →
     Repository access: *Only select repositories* → choose the repository → Permissions → **Contents: Read-only**.
   - **GitLab:** the project → Settings → **Access tokens** → scope **read_repository**, role *Reporter*.

   The token goes straight into the secret vault. The platform keeps only a reference, and the token is never shown again.
5. Click **Add and scan**. A typical repository takes under a minute; the row refreshes by itself.

When the scan finishes, the row shows the gate decision (**PASS / WARN / BLOCK**) and the findings by severity and engine.

| Button | What you get |
|---|---|
| **Full report** | One HTML report with every engine: code analysis (SAST), open-source dependencies (SCA), secrets, Infrastructure as Code, pipeline posture, licences, AI components and the full SBOM. **Download PDF / print** at the top saves it as PDF. |
| **SBOM** | The CycloneDX 1.5 software bill of materials (JSON). |
| **Scan again** | A fresh snapshot of the same branch. |
| **Remove** | Removes the repository and deletes its token from the vault. Findings history is kept. |

The findings also appear in **Findings**, **Supply chain**, **Pipelines & posture** and **Executive overview**, together with
results from CI pipelines and live-app tests.

## What each engine checks

| Engine | How it works |
|---|---|
| Open-source dependencies (SCA) | Every component from the manifests and build files (package.json, requirements, pyproject, Pipfile, pom.xml with `${property}` versions, Gradle and version catalogs, .csproj/.fsproj with central package management, Cargo.toml, composer.json, Gemfile, go.mod) **and its transitive dependencies** from the lock files. Vulnerabilities come live from **OSV** (CVSS severity, fixed versions, EPSS, CISA KEV), and from the offline advisory pack when offline or when OSV cannot be reached. Each finding says whether the package is direct or comes in through another one. |
| Components copied into the repository | Libraries that no manifest declares: minified scripts identified by their banner or version constant (jQuery, Bootstrap, AngularJS, lodash, Vue, React and about 30 more), jar/war files by their Maven metadata, NuGet and wheel archives, committed `node_modules`, `bower_components`, Composer and Go `vendor` folders. They are checked for vulnerabilities like declared dependencies and listed in the SBOM with CycloneDX evidence. |
| End of life | Runtimes, base images and frameworks past (or within 180 days of) end of support: Dockerfile and Compose images, `.nvmrc`, `.python-version`, `global.json`, `TargetFramework`, `go.mod`, `engines`, `setup-*` actions, and libraries such as AngularJS, Django, Spring Boot or log4j 1. Each finding names the supported release to move to. Lifecycle data from endoflife.date. |
| Operating systems, binaries, firmware, drivers | OS package databases in committed or mounted root filesystems, native libraries and executables (by version string and CPE), Go/Rust build information, firmware images, Windows drivers and Android/iOS packages. See [What RAT Flea DevSec scans](WHAT-WE-SCAN.md). |
| Databases, middleware and platforms in IaC | Managed databases, Kubernetes versions and function runtimes in Terraform, CloudFormation and Bicep (end of life); database and middleware images in Kubernetes, Helm, Compose and Terraform (known vulnerabilities of the version in the tag); Kubernetes API versions that were removed. |
| Licences | Licence of every component from the manifests and package registries, evaluated against the licence policy. The repository's own licence files, SPDX headers and copyright notices are read too: copyleft code copied into the tree, copyleft SPDX headers, and dependency licences that **conflict with the project licence** (for example GPL-3.0 in an MIT project, or Apache-2.0 in a GPL-2.0-only one) are reported with the obligations. |
| Code analysis (SAST) | RAT Flea DevSec rules (injection, SSRF and `file://` URL access, disabled TLS/JWT verification, unsafe deserialisation, weak crypto, predictable tokens, XXE, DOM XSS, command injection) plus **Bandit** for Python. |
| Secrets | Cloud keys, tokens, private keys, credential assignments, and **default/demo passwords written in code, config, docs or login pages**. Test folders are skipped. |
| Infrastructure as Code | Dockerfiles (root user, health check, unpinned base, TLS-off installs, `curl | sh`, secrets in ENV/ARG), Docker Compose (privileged, Docker socket, host namespaces, dangerous capabilities, published database ports, hard-coded secrets) and Kubernetes (privileged, host namespaces, root, privilege escalation, capabilities, limits, image pinning, service-account tokens, secrets in env); Terraform/Bicep patterns. |
| Pipeline posture, AI components | GitHub Actions / GitLab / Azure Pipelines risks; models, prompts and agent tools. |

The report's **Vulnerability data** line shows which sources were reachable during the scan.
**Air-gapped installations:** set `MYELIN_OFFLINE=1` to scan from the offline advisory pack and lifecycle snapshot
bundled in the images (see [Offline and air-gapped scanning](OFFLINE-ADVISORY-PACK.md)), or point to internal mirrors with
`MYELIN_OSV_URL`, `MYELIN_PYPI_URL`, `MYELIN_NPM_URL`, `MYELIN_EOL_URL`.

## What happens to the code

The platform downloads a read-only snapshot through the provider's API (github.com or gitlab.com only), extracts it into a
private temporary folder (links, devices and path escapes are skipped; size limits apply), scans it and deletes it. Source
code is not retained. Only users with the scan permission (security lead, tenant admin) can add or scan repositories;
viewers and auditors can read the reports. Each organisation sees only its own repositories.

## Export and remove repositories

**⇩ Export all** on the Repositories page downloads one ZIP: `repositories.csv` (every repository with its status,
gate decision, findings by severity, components and areas assessed) and the latest full report of each scanned
repository under `reports/`.

**Remove** asks what to do with the data:

- *Remove the repository only*: the repository leaves the list; its findings history and reports stay.
- *Remove and delete all its data*: also deletes its findings, scan history, SBOM and reports. The audit log keeps a
  record of the deletion. Use it for a repository you scanned once and do not need any more.

The API equivalents are `GET /api/v1/repos/sources/export` and `DELETE /api/v1/repos/sources/{id}?purge=true`.

## Troubleshooting

| Message | Fix |
|---|---|
| "the provider answered HTTP 404 / 403 ..." | The address is wrong, or the repository is private and the token is missing, expired or lacks **Contents: Read-only** (GitHub) / **read_repository** (GitLab). Remove the repository and add it again with a new token. |
| "private repositories need a secret vault" | The installation has no vault configured. The Windows evaluation stack includes one; in production configure Vault / OpenBao (`VAULT_ADDR`). |
| "cannot reach the provider: The read operation timed out" | Very large repositories (for example SDK monorepositories) can take minutes before the provider starts sending the archive. The platform now waits up to `MYELIN_SCM_READ_TIMEOUT` seconds (default 300) between data, and on a timeout falls back to a shallow `git clone`. Behind a slow proxy raise the value on the API service. |
| "the repository archive is larger than 500 MB" | Raise `MYELIN_SCM_MAX_ARCHIVE_MB` (and `MYELIN_SCM_MAX_EXTRACTED_MB`, default 3072, and the scan volume size `scanning.tmpSize` in Helm), or scan the repository in CI with `myelin scan`. The platform tries a shallow `git clone` automatically when the archive is too large. |
| "cloning took longer than 30 minutes" | Raise `MYELIN_SCM_CLONE_TIMEOUT` (seconds), or scan in CI. |
| "the vault refused to store the token" | The vault policy is read-only. Re-run `start-enterprise.ps1` (it updates the policy), or ask your vault administrator to allow create/update on `secret/data/myelin/tenants/*`. |
