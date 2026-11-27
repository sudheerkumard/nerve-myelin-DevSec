# Changelog — RAT Flea DevSec

All notable changes to RAT Flea DevSec are recorded here. Versions follow [Semantic Versioning](https://semver.org):
MAJOR for breaking changes, MINOR for new features, PATCH for fixes. Each section is turned into release notes by
`scripts/release/notes.py` when a version is tagged.

## [Unreleased]

## [1.6.0] - 2026-11-27

### Highlights
- **Renamed to RAT Flea DevSec.** The product name changes in the console, reports, documentation and CLI output.
  Code identifiers are unchanged (`myelin` command, `myelin_engine`, `MYELIN_*` settings, image and chart names, IdP
  app-role names), so existing pipelines and configuration keep working.
- **Much deeper code analysis.** The Java rule pack scores 92% on the OWASP Benchmark v1.2 (true-positive rate minus
  false-positive rate over 2,740 labelled cases; it was 12%). A precision pass removes data flows proven impossible
  (constant conditions, constant `switch`, known collection contents), and algorithms read from `.properties` files
  are resolved before weak-crypto findings are raised.
- **Complete dependency inventory.** Lock files for npm, pnpm, Yarn, Poetry, uv, PDM, Pipenv, Cargo, Go, Composer,
  Bundler, NuGet, Hex, Dart and CocoaPods; transitive resolution for Maven, Gradle, NuGet and npm projects without a
  lock file; Grype as a second advisory scanner beside OSV and Trivy.
- **Richer vulnerability intelligence.** NVD CVSS, EPSS percentile, CISA KEV and SSVC, exploit and patch references,
  and verified (manifest and checksum) offline OSV bundles for air-gapped sites.
- **Secrets without the noise.** One finding per leaked credential with every file, line and commit listed; secrets
  only in git history, in tests or in documentation are labelled and rated accordingly; placeholders are dropped.
- **Mitigation steps for every finding** in the console, the CSV/Excel export and the assessment report: numbered fix
  steps, how to verify the fix and a reference.

### Added
- Framework and configuration rules: session cookie flags, hard-coded session and JWT secrets, template auto-escaping
  turned off, MongoDB `$where` injection, log injection, mass assignment, ReDoS, CSRF protection disabled, wildcard
  CORS, unauthenticated-by-default security configuration, TLS verification disabled.
- Java: trust-boundary violation, insecure cookie, weak hash (CWE-328), weak randomness used for cookies, sessions and
  tokens, `Cipher.getInstance("AES")` default mode, LDAP and XPath injection with fully qualified types.
- `myelin gate --results scan.json --require sast,sca,secrets` blocks when a required area is missing or partial.
- CSV export columns `how_to_fix`, `mitigation_steps`, `how_to_verify`, `reference`, `occurrences`, `other_locations`.
- Node.js and npm in the API and CLI images, used to resolve npm dependency trees without running package scripts.

### Fixed
- Offline OSV exports: a leftover loader made every offline scan fail; the download test could fill the disk.
- Online advisory tests no longer depend on the order the test suite runs in.

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
