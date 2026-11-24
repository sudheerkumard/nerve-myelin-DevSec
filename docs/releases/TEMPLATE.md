# NERvvE DevSecOps {{VERSION}} — Release notes

**Release date:** {{DATE}} · **Release type:** {{KIND}} release

{{BODY}}

## How to upgrade

Self-hosted (Kubernetes) — during your change window:

```bash
# 1. Review "Upgrade notes" above and complete any action required
# 2. Back up (the scheduled backup is sufficient if it ran in the last 24 hours)
kubectl -n nerve-myelin create job --from=cronjob/myelin-myelin-backup pre-upgrade-{{VERSION}}
# 3. Upgrade — database migrations run automatically before the new pods start
helm upgrade myelin {{CHART}} --version {{VERSION}} -n nerve-myelin -f values-customer.yaml
# 4. Verify
kubectl -n nerve-myelin rollout status deploy/myelin-myelin-api
curl -s https://<your-myelin-host>/api/health        # "version": "{{VERSION}}"
```

Rollback: `helm rollback myelin -n nerve-myelin`. Restore the pre-upgrade backup only if the rollback alone does not recover the service.

## Artefacts and verification

| Artefact | Reference |
|---|---|
| Container image | `{{IMAGE}}:{{VERSION}}` |
| Image digest | `{{DIGEST}}` |
| Helm chart | `{{CHART}}` version `{{VERSION}}` |
| SBOM | CycloneDX, attached to the release and attested to the image |

Verify the image signature before deploying:

```bash
cosign verify {{IMAGE}}@{{DIGEST}} \
  --certificate-identity-regexp 'https://github.com/.+/.github/workflows/release.yml@refs/tags/v{{VERSION}}' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Support

Community support: [GitHub issues](https://github.com/sudheerkumard/nervve-devsecops/issues). Report vulnerabilities privately as described in `SECURITY.md`.
Commercial support and licences are available from the author.

*© 2026 Sudheer Kumar. Licensed under the GNU AGPL-3.0.*
