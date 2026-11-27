# Third-party notices — RAT Flea DevSec 1.1

RAT Flea DevSec Community edition is open-source software under the GNU AGPL-3.0 (see `LICENSE`). It uses or interoperates with the open-source
components below, each under its own licence. Keep this file in every distribution, container image
and customer delivery. Re-check versions and licences at every release; licence terms can change.

## Runtime dependencies (Python, platform and CLI)

| Component | Use | Licence | Obligation |
|---|---|---|---|
| FastAPI | API framework | MIT | Keep copyright and licence notice |
| Uvicorn | ASGI server | BSD-3-Clause | Keep notice; no endorsement |
| Pydantic | Data validation | MIT | Keep notice |
| PyYAML | Policy files | MIT | Keep notice |
| HTTPX | HTTP client (IdP, connectors) | BSD-3-Clause | Keep notice; no endorsement |
| SQLAlchemy | Data access | MIT | Keep notice |
| Alembic | Schema migrations | MIT | Keep notice |
| psycopg 3 (binary) | PostgreSQL driver | LGPL-3.0 | Distributed unmodified as a separate wheel; keep licence; users may replace it |
| PyJWT | JWT verification | MIT | Keep notice |
| cryptography | Ed25519, AES-GCM, X.509 | Apache-2.0 OR BSD-3-Clause | Keep licence and NOTICE |
| prometheus_client | Metrics | Apache-2.0 | Keep licence and NOTICE |
| boto3 (optional) | AWS connector, Secrets Manager, S3 | Apache-2.0 | Keep licence and NOTICE |
| azure-identity, azure-keyvault-secrets, azure-storage-blob (optional) | Azure integration | MIT | Keep notice |
| Python 3.12 (base image) | Runtime | PSF License | Keep notice |
| packaging | Dependency version/specifier/marker evaluation | Apache-2.0 OR BSD-2-Clause | Keep licence and notice |
| Bandit (PyCQA) | Python static analysis engine (run unmodified) | Apache-2.0 | Keep licence and NOTICE |
| stevedore, rich (Bandit dependencies) | Plugin loading, console output | Apache-2.0, MIT | Keep licence and notice |
| Git (Debian package in the platform image) | Fetching CodeCommit / Google Cloud / Git-server repositories, run as a separate program | GPL-2.0 | Unmodified; source available from the Debian archive; not linked with RAT Flea DevSec code |

## Scanners bundled in `Dockerfile.cli` (run as separate, unmodified executables)

| Component | Licence | Obligation |
|---|---|---|
| Trivy (Aqua Security) | Apache-2.0 | Keep licence and NOTICE files; state changes (none made) |
| Gitleaks | MIT | Keep notice |
| Checkov (Bridgecrew / Palo Alto Networks) | Apache-2.0 | Keep licence and NOTICE |
| Cosign (Sigstore) | Apache-2.0 | Keep licence and NOTICE |

## Not bundled — deliberately excluded

| Component | Reason |
|---|---|
| Semgrep Registry / `semgrep-rules` | Semgrep Rules License v1.0 restricts use to internal, non-competing, non-SaaS contexts. RAT Flea never calls `--config auto` or the registry. |
| Semgrep CE / Opengrep engine | Optional, customer-supplied. Runs only when `MYELIN_SAST_RULES` points to rules RAT Flea or the customer owns or has licensed. Engine is LGPL-2.1; if RAT Flea ever bundles it, ship it unmodified, with its licence and a source offer. |

## Deployment components pulled by customers (not redistributed in the RAT Flea image)

| Component | Licence | Use |
|---|---|---|
| PostgreSQL 16 | PostgreSQL License | Database (Compose / managed service) |
| Keycloak 26 | Apache-2.0 | Bundled IdP in the evaluation stack |
| Caddy 2 | Apache-2.0 | TLS proxy in the evaluation stack |
| cert-manager, External Secrets Operator, Prometheus Operator, Kyverno | Apache-2.0 | Kubernetes add-ons referenced by the chart |

## Customer-installed integrations (not distributed by RAT Flea)

Kyverno (Apache-2.0), OPA / Gatekeeper / Conftest (Apache-2.0), Sigstore Rekor/Fulcio services (Apache-2.0).

## Build tooling for sales collateral (not shipped in the product)

| Component | Licence | Note |
|---|---|---|
| pptxgenjs | MIT | Deck generation |
| docx | MIT | SOP and architecture pack generation |
| @mermaid-js/mermaid-cli | MIT | Architecture diagram rendering |
| React, react-dom | MIT | Icon rendering |
| react-icons → Font Awesome Free icons | Icons CC BY 4.0 | Attribution: "Icons: Font Awesome Free by Fonticons, Inc., CC BY 4.0" (included in deck metadata) |
| sharp | Apache-2.0 | Image rasterising |

## Console fonts

Inter and JetBrains Mono are loaded from Google Fonts at view time (SIL Open Font License 1.1); they are not bundled.

## Vulnerability intelligence sources (planned advisory sync)

OSV, NVD, GitHub Advisory Database, CISA KEV and FIRST EPSS each publish their own terms of use, and some require attribution. Review each source's current terms before turning on the production sync and add the required attributions to the console's About page.


## Vulnerability and package data (fetched at scan time, not redistributed)

| Source | Use | Terms |
|---|---|---|
| OSV.dev API | Vulnerabilities for PyPI, npm, Maven, Go, crates.io, NuGet, RubyGems, Packagist | Aggregated advisory data, including the GitHub Advisory Database and PyPA Advisory Database (CC-BY-4.0): attribution kept in reports ("Vulnerability data: OSV") |
| PyPI JSON API | Python package metadata, licences and the PyPA advisory fallback | PyPI terms of use |
| npm registry | JavaScript package licences | npm terms of use |

Scans can run fully offline (`MYELIN_OFFLINE=1`) with the bundled advisory pack, or against internal mirrors
(`MYELIN_OSV_URL`, `MYELIN_PYPI_URL`, `MYELIN_NPM_URL`).
