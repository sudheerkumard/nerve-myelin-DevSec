# NERvvE DevSecOps — Third-Party Notices and Attributions

NERvvE DevSecOps Community edition is free and open-source software, Copyright © 2026 Sudheer Kumar, licensed under the
GNU Affero General Public License v3.0 (`LICENSE`). Commercial licences are available from the author.

NERvvE DevSecOps uses the third-party software, data and specifications listed below. Each is the property of its respective
owners and is used under its own licence. Nothing in the NERvvE DevSecOps licence restricts the rights granted by those
licences. Third-party components are used **unmodified**; NERvvE DevSecOps's own code does not copy third-party source code.

Full texts of the licence families referenced here are in `docs/legal/licenses/` (Apache-2.0, MIT, BSD-3-Clause,
MPL-2.0, LGPL-3.0, GPL-2.0, GPL-3.0).

## 1. Software libraries (Python)

The complete, generated list of Python components (name, version, licence, project) is in
[`docs/legal/python-dependencies.md`](docs/legal/python-dependencies.md). Summary of licence families:

| Licence family | Examples | Obligations met by NERvvE DevSecOps |
|---|---|---|
| MIT, BSD, ISC, PSF | FastAPI, Starlette, Pydantic, SQLAlchemy, PyJWT, PyYAML, httpx, uvicorn, Alembic, Mako, boto3 dependencies, Azure SDK | Copyright and licence notices retained in each package's `dist-info` and listed here |
| Apache-2.0 | cryptography (Apache-2.0 / BSD), Bandit, Checkov, boto3, botocore, prometheus_client | Licence text in `docs/legal/licenses/Apache-2.0.txt`; NOTICE files retained in packages; no modification |
| MPL-2.0 (file-level) | certifi (CA bundle), parts of orjson and tqdm | Files used unmodified; source available from the project; licence text included |
| LGPL-3.0 | psycopg 3 (PostgreSQL driver) | Used unmodified as a separately installed, dynamically loaded library that customers may replace with their own build; licence text included |

## 2. Tools bundled in the CLI container image (`myelin-cli`)

| Component | Licence | Project |
|---|---|---|
| Trivy (Aqua Security) | Apache-2.0 | https://github.com/aquasecurity/trivy |
| Gitleaks (Zachary Rice) | MIT | https://github.com/gitleaks/gitleaks |
| Cosign (Sigstore, The Linux Foundation) | Apache-2.0 | https://github.com/sigstore/cosign |
| Checkov (Bridgecrew / Palo Alto Networks) | Apache-2.0 | https://github.com/bridgecrewio/checkov |
| Bandit (PyCQA) | Apache-2.0 | https://github.com/PyCQA/bandit |

These binaries are copied unmodified from their official release images. Semgrep / Opengrep are **not** bundled.

## 3. Operating-system packages in container images

The platform, demo, backup and CLI images are built on the official `python:3.12-slim` / `debian:bookworm-slim` images and
include Debian packages (for example `git`, GPL-2.0) under their own licences. These are unmodified distribution
packages. The corresponding source code is available from Debian (https://snapshot.debian.org/ and
https://sources.debian.org/) for the package versions listed in each image (`dpkg -l`). On written request to the
Licensor within three years of an image release, the Licensor will provide the corresponding source for any
GPL-licensed package in that image, for no more than the cost of distribution.

## 4. Services used by the reference deployment (not distributed by NERvvE DevSecOps)

The Compose stack and Helm chart pull these images directly from their publishers; they are not modified or
redistributed by NERvvE DevSecOps.

| Component | Licence |
|---|---|
| PostgreSQL | PostgreSQL License |
| Keycloak | Apache-2.0 |
| OpenBao | MPL-2.0 |
| Caddy | Apache-2.0 |
| Alpine Linux base image | various (per package) |
| Kyverno (customer cluster) | Apache-2.0 |
| Falco and Falcosidekick (customer cluster, runtime sensor) | Apache-2.0 (Falco), MIT (Falcosidekick) — installed by the customer from the upstream charts; NERvvE DevSecOps ships only its own configuration and rule files |
| Tetragon (customer cluster, runtime sensor) | Apache-2.0 — installed by the customer; NERvvE DevSecOps ships only its own tracing policies |

## 5. Console and documents

| Item | Licence / attribution |
|---|---|
| Navigation icons in the web console are adapted from **Feather** icons | MIT — Copyright (c) 2013-2023 Cole Bemis. The MIT licence text is in `docs/legal/licenses/MIT.txt`. |
| Icons in the sales presentations: **Font Awesome Free** by Fonticons, Inc., rendered through react-icons (MIT) | Icons: CC BY 4.0 (https://fontawesome.com/license/free); attribution is printed on the closing slide |
| Presentation / document generators (build-time only): pptxgenjs (MIT), docx (MIT), sharp (Apache-2.0), React (MIT) | Not shipped in the product |
| Documentation and whitepaper build tools (build-time only): MkDocs (BSD-2-Clause), Material for MkDocs (MIT), Puppeteer (Apache-2.0), python-qrcode (BSD-3-Clause); the whitepaper PDF embeds subsets of the Inter typeface (SIL Open Font License 1.1) | Not shipped in the product; the built site contains Material for MkDocs theme assets under the MIT licence |
| Fonts | The console and reports use the viewer's system fonts; no font files are embedded |

## 6. Vulnerability and threat intelligence (fetched at run time)

| Source | Terms |
|---|---|
| OSV.dev (Open Source Vulnerabilities) | Data aggregated from many sources, each under its own licence (largely CC BY 4.0); see https://osv.dev |
| GitHub Advisory Database | CC BY 4.0 — https://github.com/github/advisory-database |
| NVD (NIST National Vulnerability Database) | U.S. Government work; this product uses NVD data but is not endorsed or certified by the NVD |
| CISA Known Exploited Vulnerabilities catalog | U.S. Government public information |
| EPSS — Exploit Prediction Scoring System | FIRST.org usage agreement; see EPSS at https://www.first.org/epss |
| PyPI and npm registry metadata | Public registry APIs, used within their terms of use |

Advisory text is shown to users with a link to the original record; NERvvE DevSecOps does not claim ownership of it.

## 7. Standards and frameworks referenced

NERvvE DevSecOps maps findings to the frameworks below by **identifier** and shows **short summarised titles** written for
this product; it does not reproduce the standards' text. All names are trademarks or publications of their owners, and
no endorsement or certification is implied.

| Framework | Owner |
|---|---|
| OWASP Top 10 (2025), API Security Top 10, Top 10 CI/CD Security Risks, Top 10 for LLM Applications, Top 10 for Agentic Applications | OWASP Foundation (content licensed CC BY-SA 4.0) |
| CWE and CWE Top 25 | The MITRE Corporation (CWE is used under MITRE's terms of use) |
| OpenSSF Open Source Project Security Baseline | OSPS Baseline contributors, a Series of LF Projects, LLC |
| SLSA, OpenSSF Scorecard concepts | OpenSSF / The Linux Foundation |
| CycloneDX (SBOM, CBOM, VEX) | OWASP Foundation / Ecma International (ECMA-424) |
| SPDX | The Linux Foundation |
| OpenVEX, CSAF 2.0 | OpenSSF; OASIS Open |
| CISA SSVC | Carnegie Mellon University Software Engineering Institute and CISA |
| PCI DSS v4.0 | PCI Security Standards Council (control titles summarised) |
| ISO/IEC 27001:2022 | ISO / IEC (control titles summarised) |
| NIST SSDF (SP 800-218), NIST SP 800-53 | NIST (U.S. Government works) |
| SOC 2 Trust Services Criteria | AICPA |
| CIS Benchmarks (Docker, Kubernetes, Microsoft Azure Foundations, AWS Foundations, Google Cloud Platform Foundation) | Center for Internet Security — referenced by benchmark and section name only; check titles and remediation text are NERvvE DevSecOps's own wording; not endorsed by CIS |
| Kubernetes Pod Security Standards | The Kubernetes Authors (CC BY 4.0 documentation) |
| MITRE ATT&CK® | The MITRE Corporation — tactic names and technique IDs are referenced; © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation |
| EU Cyber Resilience Act (Regulation (EU) 2024/2847) | European Union (requirements summarised; not legal advice) |

## 8. Trademarks

GitHub, GitLab, Azure DevOps, Bitbucket, AWS, Google Cloud, Microsoft Entra ID, Okta, Jira, ServiceNow, Slack, Microsoft
Teams, Microsoft Azure, Amazon Web Services, Kubernetes, Kyverno, Falco, Tetragon, Cilium, Argo CD, Flux, Helm, Terraform, Docker, Anthropic, OpenAI, Hugging Face and other product
names are trademarks of their respective owners and are used only to identify compatible products. NERvvE DevSecOps is not
affiliated with or endorsed by them.

## 9. Your own content

Source code, scan results and reports remain the customer's property (see the Subscription Agreement, section 6).
