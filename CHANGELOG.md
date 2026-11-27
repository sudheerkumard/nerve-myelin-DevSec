# Changelog — RAT Flea DevSec

All notable changes to RAT Flea DevSec are recorded here. Versions follow [Semantic Versioning](https://semver.org):
MAJOR for breaking changes, MINOR for new features, PATCH for fixes. Each section is turned into release notes by
`scripts/release/notes.py` when a version is tagged.

## [Unreleased]

## [1.6.1] - 2026-11-28

### Added
- **SBOM analysis.** Upload CycloneDX (JSON or XML) or SPDX JSON files, or a ZIP of them, as one project. Every component
  gets a licence decision and is matched against known vulnerabilities. The result is a separate report (HTML with
  mitigation steps, CSV, merged CycloneDX); it does not add findings to the dashboard.
- **Remediation plan** on the Findings page: the filtered findings grouped into fix items with numbered steps, how to
  verify and every affected location.
- **Repositories: Export all** downloads one ZIP with a CSV of every repository and the latest report of each.
- **Repositories: Remove and delete all data** removes a repository with its findings, scan history, SBOM and reports.
- **Product demo** walks through the real screens of the console (repositories, findings, licences, SBOM analysis,
  pipelines, compliance) with a talk track, on live or sample data.
- The logo turns continuously (paused when the system asks for reduced motion).

### Changed
- Licence governance gives a specific reason per package (licence, category, policy decision), the obligations and the
  action to take; licences missing from the SBOM are looked up in the package registry, including Maven parent POMs.
  The table has fixed column widths, filters by repository/SBOM project, decision and text, and exports to CSV.
- Advisory feed sync (OSV, CISA KEV, EPSS, NVD, GitHub, Red Hat) runs in the API by default, so the Sync buttons work
  without a separate worker. Source cards show never synced / sync running / synced / failed and refresh while a sync runs.
- Large repositories: the archive download waits up to 5 minutes between data (`MYELIN_SCM_READ_TIMEOUT`) and falls
  back to a shallow git clone on a timeout or when the archive is too large; limits raised to 500 MB archives and 3 GB
  extracted (configurable).
- Secrets in test folders are recognised in more layouts (`TestCertificates/`, `Foo.UnitTests/`, `samples/`) and rated
  low; the published Azure Storage and Cosmos DB emulator keys and AWS documentation keys are not reported.

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
  Bundler, NuGet, Hex, Dart and CocoaPods; transitive resolution for Maven, Gradle and NuGet, and for npm projects without a lock file where
  npm is installed (CLI on a developer machine or CI runner); Grype as a second advisory scanner beside OSV and Trivy.
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
