# NERVE Myelin 1.2.0 — Release notes

**Release date:** 2026-11-14 · **Release type:** feature release · **Classification:** Customer confidential

## Highlights
- Licence keys: installations are activated with a signed licence key that works fully offline, including air-gapped sites.
- Release pipeline: every version is built, scanned, signed and published as an image and Helm chart with release notes.

## Added
- Offline-verifiable licence keys (Ed25519-signed) carrying plan, add-ons, developer and tenant limits, expiry and optional installation binding.
- Graceful licence enforcement: 30-day expiry warnings, 30-day grace period, then restricted mode in which all data stays readable and exportable while new scans, triage, connector syncs and evidence collection pause.
- Licence features cap plan entitlements; tenant creation honours the licensed tenant limit.
- `GET /api/v1/license` (state, limits, usage for administrators) and `myelin admin license-status` (deployment-wide usage).
- Console banner for expiring, grace and restricted licences; `X-Myelin-License` response header.
- Prometheus metrics `myelin_license_days_remaining`, `myelin_license_usable` and alerts *MyelinLicenseExpiring*, *MyelinLicenseRestricted*.
- Helm value `deploymentId` and secret key `MYELIN_LICENSE`; Compose variable `MYELIN_LICENSE`.

## Changed
- Version 1.2.0 across image, chart, CLI and CI templates.

## Upgrade notes
- **Action required before upgrading:** add the licence key issued for NERVE Myelin to your secret store as `MYELIN_LICENSE` (Helm: `secrets.keys.license`). Without it the platform starts in restricted mode — data remains available, but new scans are paused.
- `helm upgrade` runs database migrations automatically; this release has no schema changes.

## How to upgrade

Self-hosted (Kubernetes) — during your change window:

```bash
# 1. Review "Upgrade notes" above and complete any action required
# 2. Back up (the scheduled backup is sufficient if it ran in the last 24 hours)
kubectl -n nerve-myelin create job --from=cronjob/myelin-myelin-backup pre-upgrade-1.2.0
# 3. Upgrade — database migrations run automatically before the new pods start
helm upgrade myelin oci://ghcr.io/sudheerkumard/charts/myelin --version 1.2.0 -n nerve-myelin -f values-customer.yaml
# 4. Verify
kubectl -n nerve-myelin rollout status deploy/myelin-myelin-api
curl -s https://<your-myelin-host>/api/health        # "version": "1.2.0"
```

Rollback: `helm rollback myelin -n nerve-myelin`. Restore the pre-upgrade backup only if NERVE Support advises it.

Dedicated SaaS: the NERVE Myelin operations team applies this release in the maintenance window agreed in your order form and confirms by email.

## Artefacts and verification

| Artefact | Reference |
|---|---|
| Container image | `ghcr.io/sudheerkumard/nerve-myelin:1.2.0` |
| Image digest | `(published with the release)` |
| Helm chart | `oci://ghcr.io/sudheerkumard/charts/myelin` version `1.2.0` |
| SBOM | CycloneDX, attached to the release and attested to the image |

Verify the image signature before deploying:

```bash
cosign verify ghcr.io/sudheerkumard/nerve-myelin@(published with the release) \
  --certificate-identity-regexp 'https://github.com/.+/.github/workflows/release.yml@refs/tags/v1.2.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Support

Version 1.2.x receives security fixes for 12 months from this release date. Contact the NERVE Myelin product owner with your licence id (shown under Settings → Licence or by `myelin admin license-status`).

*© 2026 Sudheer Kumar. Proprietary and confidential.*
