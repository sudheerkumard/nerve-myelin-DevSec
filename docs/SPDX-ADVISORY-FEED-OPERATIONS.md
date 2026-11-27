# MYELIN SPDX and advisory feed operations

Copyright (c) 2026 Sudheer Kumar. Licensed under the GNU AGPL-3.0; see LICENSE.

## SPDX 2.x JSON intake

Use the authenticated scanner intake endpoint. The tenant is derived from the validated identity, not the request body.

```http
POST /api/v1/scanners/import
Content-Type: application/json
Authorization: Bearer <tenant-access-token>

{
  "repo": "payments-service",
  "branch": "main",
  "commit": "abc1234",
  "format": "spdx",
  "document": {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "payments-service",
    "packages": [
      {
        "SPDXID": "SPDXRef-Package",
        "name": "requests",
        "versionInfo": "2.31.0",
        "licenseDeclared": "Apache-2.0",
        "externalRefs": [
          {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:pypi/requests@2.31.0"
          }
        ]
      }
    ],
    "relationships": []
  }
}
```

An SPDX SBOM-only import is stored as inventory evidence. It does not represent a vulnerability scan, does not close findings and does not imply clean scanner coverage. SPDX 2.x JSON is supported; SPDX 3.x, tag/value and RDF serializations are not supported in this increment.



## Advisory synchronization

The API queues jobs; the separately deployed MYELIN worker claims them using a PostgreSQL lease and an explicit
tenant allowlist. The worker stores normalized records with their source, revision time and content digest. Repository
scans read the current tenant catalog and match installed dependency versions. Syncing a feed does not itself change
finding status or scan an application.

| Feed | Inventory mode | Changes mode |
|---|---|---|
| [OSV](https://google.github.io/osv.dev/data/) | Queries PURLs from stored SBOMs; follows per-package pages and hydrates full records by ID | Reads selected ecosystem modification indexes and fetches full records |
| [NVD](https://nvd.nist.gov/developers/vulnerabilities) | Retrieves CVE records for tenant findings | Pages through the requested last-modified interval |
| [GitHub Advisory Database](https://docs.github.com/en/rest/security-advisories/global-advisories) | Looks up the tenant's existing CVEs | Retrieves reviewed advisories using the modified interval and continuation cursors |
| [Red Hat CSAF](https://security.access.redhat.com/data/csaf/v2/provider-metadata.json) | — | Reads the provider's change index and fetches security advisory documents |
| CISA KEV and FIRST EPSS | KEV catalog and EPSS for existing tenant CVEs | — |

Use **Vulnerability intelligence** in the console or call
`POST /api/v1/intelligence/feeds/{source}/sync` with scanner-write permission. The default request keeps
inventory mode for existing integrations; Red Hat uses changes mode. For a bounded OSV refresh:

```json
{"mode":"changes","ecosystems":["PyPI","npm"],"limit":500}
```

A changes job accepts an optional `since` and `until` (RFC 3339 timestamps with timezones, at most one day apart).
Without `since`, the worker starts with a recent window or resumes from the latest successful rolling window for
that exact source and ecosystem selection. Rolling windows overlap briefly, and the same record can be processed
safely more than once. Explicit `since` requests are backfills; they do not move the rolling cursor.
If a window exceeds its record or request budget, its job is marked partial and does not advance the cursor.
Use a narrower `until` on the next rolling request to catch up. For unattended updates, schedule authenticated
sync requests with your existing automation and monitor job outcomes.

- `GET /api/v1/intelligence/feeds/jobs`: inspect requested windows, counts and failure reasons.
- `POST /api/v1/intelligence/feeds/jobs/{job_id}/retry`: requeue a failed job. A worker can reclaim a stale lease.
- `GET /api/v1/intelligence/feeds/{source}`: inspect stored records and the last successful sync.

Set `MYELIN_WORKER_TENANT_IDS` in the worker environment. Set `NVD_API_KEY` and `GITHUB_ADVISORY_TOKEN` there
for higher upstream quotas. Run a fresh repository scan after successful synchronization to evaluate the dependency
inventory against the updated records. Standalone CLI scans continue to use their own online or offline intelligence
configuration; they do not directly connect to the enterprise database.

### Matching and integrity

- OSV and GitHub require a package identity and an affected version. Database lookup uses indexed package keys
  and then compares the installed version with the advisory range. A newer withdrawal supersedes the older
  record from that source. A withdrawal does not erase independent evidence from another source.
- NVD supplies CVSS and references for a matched CVE. CPE configurations are retained as evidence and are not
  guessed into package findings. Red Hat product statuses are retained as issued; the scanner requires a
  vendor-declared affected product with an exact matching PURL.
- Fixed versions, references and source attribution are retained with findings when available. Missing,
  late or unavailable sources do not establish that a package is safe. Check the source job and scan coverage.
- Provider hosts are fixed, redirects are disabled, and links in advisories are stored as evidence only.

### Migration

Apply Alembic revisions through `0011`. Revision `0009` creates the advisory and job tables with forced row
level security. Revision `0011` adds indexed package and CVE lookups. Refresh existing feeds to populate the
normalized matching fields on records stored by earlier releases.


<!-- /coderabbit-ai-generated:v1 -->