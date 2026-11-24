# NERvvE DevSecOps — Google Cloud read-only access

Grant the collector's service account these predefined roles on the project, folder or organisation it should cover
(the parent given to `myelin cloud scan --parent` or the cloud account in the console):

| Role | Why |
|---|---|
| `roles/cloudasset.viewer` | Read resource configuration and IAM policies through the Cloud Asset Inventory API |
| `roles/iam.securityReviewer` | Read IAM policies and service-account key metadata |

Enable the Cloud Asset API (`cloudasset.googleapis.com`) on the project that owns the service account.
Prefer workload identity federation and pass a short-lived `access_token`; a downloadable key works but is itself
reported by the identity analysis (NM-IAM-014).

Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only.
