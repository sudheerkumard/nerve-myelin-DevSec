# Developer tools: pre-commit hook, MCP server, AutoFix and air-gapped intelligence

NERvvE DevSecOps Product designed and developed by Sudheer Kumar · <https://github.com/sudheerkumard/nervve-devsecops>

## Pre-commit hook

`myelin precommit` scans exactly what is about to be committed (the staged version of each file) with the secrets,
code, configuration, pipeline, supply-chain and AI-agent engines, and exits 1 when the policy blocks.

```bash
# plain git hook
printf '#!/bin/sh\nexec myelin precommit\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

# or with the pre-commit framework (.pre-commit-config.yaml)
repos:
  - repo: <your NERvvE DevSecOps repository or mirror>
    rev: v1.5.0
    hooks:
      - id: nerve-myelin
```

Options: `--policy FILE`, `--fail-on warn`, or pass file names to check specific files.

## MCP server for AI coding assistants

`myelin mcp` runs a Model Context Protocol server on stdio. Tools:

| Tool | What it does |
|---|---|
| `scan_path` | Scan a folder and return the highest-priority findings |
| `scan_snippet` | Check a code or configuration snippet (with its intended file name) before it is written |
| `check_package` | Known malicious release or look-alike of a popular npm / PyPI package |
| `explain_rule` | What a NERvvE DevSecOps rule detects and how to fix it |
| `gate` | Pass / warn / block for a folder under the default or a given policy |

The server only reads folders under `MYELIN_MCP_ROOTS` (default: the working directory), works offline and never sends
code anywhere. Example registration (Claude Code, Cursor and VS Code use the same shape):

```json
{ "mcpServers": { "nerve-myelin": { "command": "myelin", "args": ["mcp"], "env": { "MYELIN_MCP_ROOTS": "/path/to/projects" } } } }
```

## AutoFix pull requests

`POST /api/findings/{id}/autofix` returns the fix computed from the repository's own file at the scanned commit (unified
diff), or guidance when no safe mechanical change exists. Rules with automatic fixes:

| Area | Fix |
|---|---|
| Dependencies (requirements.txt, package.json, pom.xml, go.mod) | Bump to the fixed version; lockfile findings edit the manifest (regenerate the lockfile in the branch) |
| NM-CICD-001 | Pin the action to the commit SHA of its tag (resolved through the GitHub API) |
| NM-CICD-004 | Add `permissions: contents: read` |
| NM-CICD-015 / 018 / 021 | `--ignore-scripts`; remove insecure workflow commands; `npm publish --provenance` |
| NM-SAST-004 / 005 / 006 / 008 / 013 / 016 / 029 | Restore TLS verification, SHA-256, `yaml.safe_load`, remove debug mode, `mkstemp`, explicit CORS origins, Go TLS verification (changes that can alter behaviour are marked for review) |
| NM-SUP-008 | Add `min-release-age=3` to `.npmrc` |

`POST /api/findings/{id}/autofix/pull-request` opens the pull request (GitHub), merge request (GitLab) or pull request
(Azure DevOps) for a repository connected under Repositories. The repository token needs write access to contents and
pull requests (GitHub fine-grained: Contents and Pull requests read/write; GitLab: `api`; Azure DevOps: Code read &
write). The finding closes when a re-scan no longer reports it.

## Live secret validation (opt-in)

Set `MYELIN_VALIDATE_SECRETS=1` to confirm detected GitHub, Slack, Stripe, OpenAI, Anthropic and Hugging Face credentials
with a read-only identity call to the issuing provider. Only then is a secret marked **live**. Never runs in offline mode.

## Air-gapped vulnerability intelligence

```bash
# on a connected host
myelin advisories download ./osv-exports --ecosystems PyPI,npm,Maven,Go
# carry the folder in, then on the offline site
export MYELIN_OFFLINE=1 MYELIN_OSV_EXPORT_DIR=/data/osv-exports
myelin scan .
```

Every component is matched locally against the full OSV records (explicit versions and ECOSYSTEM / SEMVER ranges),
including malicious-package (MAL-) records.

## Kubernetes admission decisions

Apply `deploy/k8s/kyverno-myelin-admission.yaml`, then forward Kyverno's policy reports to the platform:

```bash
kubectl get policyreports -A -o json | jq '{reports: .items, cluster: "aks-prod"}' \
  | curl -sS -X POST -H "X-API-Key: $MYELIN_API_KEY" -H "Content-Type: application/json" \
         --data @- https://<console>/api/v1/admission/reports
```

Allowed and blocked deployments then appear under **Artifact integrity**.
