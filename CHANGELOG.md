# Changelog — RAT Flea DevSec

All notable changes to RAT Flea DevSec are recorded here. Versions follow [Semantic Versioning](https://semver.org):
MAJOR for breaking changes, MINOR for new features, PATCH for fixes. Each section is turned into release notes by
`scripts/release/notes.py` when a version is tagged.

## [Unreleased]

## [1.5.0] - 2026-11-24

### Highlights
- **First open-source release: RAT Flea DevSec Community edition**, licensed under the GNU AGPL-3.0. No licence key is
  needed; every feature in this repository is enabled.
- Fifteen engines from code to cloud to runtime: SCA with reachability, SAST, secrets, IaC, containers, pipeline posture
  (OWASP Top 10 CI/CD risks), licences, DAST / API, AI-BOM, provenance, CSPM, KSPM, CIEM, runtime (Falco, Tetragon)
  and attack paths, in one finding schema with the RAT Flea Risk Score.
- Web console, multi-tenant API (OIDC, MFA, RBAC, PostgreSQL row-level security), VEX and CSAF triage, AutoFix pull
  requests, policy as code, compliance mapping, pipeline templates, Helm chart and a searchable documentation site.

### Upgrade notes
- The product was previously published under another name. Code identifiers are unchanged: the `myelin` command,
  `myelin_engine`, `MYELIN_*` settings and image names.
