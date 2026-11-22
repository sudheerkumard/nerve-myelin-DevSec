# Repositories on any platform: GitHub, GitLab, Bitbucket, Azure, AWS, Google Cloud, any Git server

Scanning works the same everywhere: **Repositories → ＋ Add repository → paste the address → Add and scan**.
The platform detects where the repository is hosted from the address. Choose **Hosted on** only for
self-hosted servers whose address does not reveal the product (e.g. GitHub Enterprise at `https://code.acme.com`).

| Hosted on | Address to paste (as shown by the **Clone** button) | Read-only credential for private repositories |
|---|---|---|
| **GitHub** / GitHub Enterprise Server | `https://github.com/org/repo` · `https://ghe.acme.com/org/repo` | Fine-grained token → this repository → **Contents: Read-only** |
| **GitLab** / self-managed | `https://gitlab.com/group/sub/project` | Project access token, scope **read_repository**, role Reporter |
| **Bitbucket Cloud** | `https://bitbucket.org/workspace/repo` | Repository access token (Read), or `username:app-password` |
| **Azure DevOps Repos** | `https://dev.azure.com/org/project/_git/repo` (also `org.visualstudio.com/...`) | Personal access token, scope **Code (Read)** |
| **AWS CodeCommit** | `https://git-codecommit.<region>.amazonaws.com/v1/repos/<name>` or the console URL | IAM user → Security credentials → **HTTPS Git credentials for AWS CodeCommit**, pasted as `username:password` (policy: `codecommit:GitPull` on the repository) |
| **Google Cloud** Source Repositories / Secure Source Manager | `https://source.developers.google.com/p/<project>/r/<repo>` · `https://<instance>-<project>-git.<region>.sourcemanager.dev/<project>/<repo>` | **Service-account key JSON** (role *Source Repository Reader* / *Secure Source Manager Repo Reader*) — the platform exchanges it for a 1-hour token at each scan — or a short-lived access token |
| **Any Git server** (Gitea, Bitbucket Data Center, self-hosted GitHub/GitLab) | `https://git.acme.com/team/repo.git` | `username:password`, a personal access token, or `Bearer <token>` |

GitHub, GitLab, Bitbucket and Azure DevOps are downloaded as archives through their APIs. CodeCommit, Google Cloud and other
servers are fetched with a hardened, shallow `git clone`.

## Security of the fetch

* Credentials are written to the secret vault under the organisation's path; the database keeps only a reference. They are
  sent as an HTTP header — never in the URL, the command line or logs — and deleted when the repository is removed.
* Only `https`. Addresses that resolve to loopback, link-local (cloud metadata) or private networks are refused, so a
  repository address cannot be used to reach internal systems. **On-premises Git servers:** set `MYELIN_SCM_ALLOW_PRIVATE=1`
  on the platform (single-tenant installations).
* Git runs with no user or system configuration, no hooks, no symlinks, no submodules, no LFS and no redirects.
* Archives are limited to 300 MB download / 1 GB extracted / 100,000 files and extracted with path-traversal, link and device
  protection. The source is deleted after the scan; only findings and the SBOM are kept.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| "returned a sign-in page instead of the repository" | Azure DevOps / Bitbucket answer an invalid or expired token with a login page. Create a new token with read access to code, remove the repository and add it again. |
| "HTTP 401 / 403 / 404" | Wrong address or branch, or the credential cannot read this repository. |
| "git: ... check the address and that the credential can read this repository" | CodeCommit / Google Cloud / Git server refused the credential. For CodeCommit use the HTTPS Git credentials (not access keys). |
| "resolves to an internal address" | Self-hosted server on a private network: set `MYELIN_SCM_ALLOW_PRIVATE=1`. |
| "Google refused the service-account key" | The key was deleted or the service account lacks the reader role on the repository. |
