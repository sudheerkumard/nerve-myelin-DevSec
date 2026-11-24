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

The following routes require an authenticated identity with scanner-write permission:

- `POST /api/v1/intelligence/feeds/OSV/sync`: queries OSV using PURLs found in tenant SBOMs.
- `POST /api/v1/intelligence/feeds/KEV/sync`: imports the CISA Known Exploited Vulnerabilities catalog.
- `POST /api/v1/intelligence/feeds/EPSS/sync`: retrieves EPSS scores for CVEs already present in tenant findings.
- `POST /api/v1/intelligence/feeds/NVD/sync`: retrieves NVD CVE 2.0 records for tenant CVEs. Set `NVD_API_KEY` in the worker environment for higher rate limits; unauthenticated jobs are capped at 10 CVEs.
- `POST /api/v1/intelligence/feeds/GITHUB/sync`: retrieves GitHub Advisory Database records by CVE. Set `GITHUB_ADVISORY_TOKEN` in the worker environment for higher rate limits; unauthenticated jobs are capped at 20 CVEs.
- `GET /api/v1/intelligence/feeds/jobs`: lists durable tenant-scoped job state and counters.
- `POST /api/v1/intelligence/feeds/jobs/{job_id}/retry`: retries a failed job or a running job whose 15-minute lease has elapsed.
- `GET /api/v1/intelligence/feeds/{source}`: returns retained source records.

Optional request body:

```json
{"limit": 500}
```

The limit is capped at 5,000. OSV requests are batched at 1,000 PURLs; EPSS requests are batched at 100 CVEs. Requests use fixed vendor hosts, bounded timeouts, no redirects and limited retries for rate limits/transient server errors. Imported advisory text is treated as untrusted data. The platform does not dereference links inside advisory payloads.

## Current coverage boundaries

- OSV coverage depends on valid PURLs in imported CycloneDX or SPDX SBOMs.
- KEV, EPSS, NVD and GitHub Advisory coverage is bounded to CVEs already present in tenant findings.
- NVD and GitHub Advisory Database are queried by CVE already present in tenant findings. Unauthenticated batches are deliberately capped; configure the respective worker environment tokens for higher throughput.
- A feed with zero matching records is not evidence that a package is safe.
- Advisory records enrich intelligence and prioritization; they do not silently close findings or override mandatory policy gates.
- SPDX licence values are retained as evidence and evaluated by the licence policy engine (`GET /api/v1/licenses/report`): expression parsing, allow / review / deny decisions and policy-version binding. Legal conclusions remain with the customer's counsel.

## Job execution and recovery

Job metadata, target snapshots, results, timestamps and errors are persisted per tenant with PostgreSQL row-level security. This increment dispatches work using FastAPI in-process background tasks. Failed jobs and stale running jobs can be retried through the API, but there is no separate durable queue/worker with automatic crash recovery or an at-least-once processing guarantee. Deploy a managed worker/queue before relying on unattended production synchronization.

## Migration

Apply Alembic revision `0009` after `0008` using the schema-owner migration connection. It creates `advisory_records` and `import_jobs` with forced row-level security, tenant isolation policies and application/admin grants. Validate migration and cross-tenant isolation against PostgreSQL 16 before production rollout.
