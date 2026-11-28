# Changelog — RAT Flea DevSec

All notable changes to RAT Flea DevSec are recorded here. Versions follow [Semantic Versioning](https://semver.org):
MAJOR for breaking changes, MINOR for new features, PATCH for fixes. Each section is turned into release notes by
`scripts/release/notes.py` when a version is tagged.

## [Unreleased]

## [1.7.0] - 2026-11-28

### Highlights
- **Offline scanning is now as complete as online scanning.** The platform and CLI images include an offline advisory
  pack: every reviewed GitHub advisory for ten ecosystems, the OpenSSF list of known malicious packages and the CISA
  Known Exploited Vulnerabilities catalog, checksum-verified. Air-gapped scans, and online scans where OSV cannot be
  reached, match every component against the same data. On six public test applications scanned offline, dependency
  advisories found went from 9 to 672.
- **Every report carries the RAT Flea DevSec logo**: the assessment report cover, the API/live-application report,
  the remediation plan and the SBOM report.

### Added
- **End-of-life detection (NM-EOL-001, NM-EOL-002).** Runtimes, base images and frameworks past end of support, or
  within 180 days of it: Dockerfile and Compose images (including Debian/Ubuntu codenames and Alpine), `.nvmrc`,
  `.python-version`, `global.json`, `TargetFramework`, `go.mod`, `engines`, `setup-*` actions, and libraries such as
  AngularJS, Django, Spring Boot, Vue 2 and log4j 1. Each finding names the supported release to move to. Lifecycle
  data for about 390 products is bundled and refreshed from endoflife.date when online. Uploaded SBOMs get the same
  check.
- **Components copied into the repository** are found and checked like declared dependencies: minified scripts by
  banner or version constant (jQuery, Bootstrap, AngularJS, lodash, Vue, React and about 30 more), jar/war/ear files
  by their Maven metadata (nested libraries included), NuGet and wheel archives, committed `node_modules`,
  `bower_components`, Composer and Go `vendor` folders. The SBOM lists them with CycloneDX evidence.
- **Repository licensing.** Licence texts, SPDX headers and copyright notices in the repository are read. New
  findings: copyleft code copied into the tree (NM-LIC-101), copyleft SPDX headers (NM-LIC-102), dependency licences
  that conflict with the project licence (NM-LIC-103, for example GPL-3.0 in an MIT project or Apache-2.0 in a
  GPL-2.0-only one) and source-available or restricted licences (NM-LIC-104). The report lists the project licence,
  the licence files and the copyright notices for the attribution file.
- **Build files read without Trivy**: .NET projects (`PackageReference`, central package management with
  `Directory.Packages.props`, `$(Property)` versions), Maven `${property}` versions and dependencyManagement, Gradle
  and version catalogs, `pyproject.toml` (PEP 621 and Poetry), `Pipfile`, `Cargo.toml`, `composer.json` and
  `Gemfile`.
- Mitigation steps for end-of-life, licence and copied-component findings in every report and in the remediation
  plan.
- `docs/OFFLINE-ADVISORY-PACK.md`: what is used online and offline, and how to refresh the pack on an air-gapped
  network.

### Changed
- The offline advisory index loads only the ecosystems present in the scanned project (a Python and Java project:
  1.5 s and 170 MB instead of loading everything).
- Maven plugins are no longer listed as dependencies; test and provided scopes are marked optional.
- A dependency whose licence conflicts with the project licence is reported once, as a conflict, instead of also as a
  generic copyleft finding.

### Fixed
- The enterprise Compose file used Alpine 3.20 and OpenBao 2.6, both past end of life; they are now 3.24 and 2.7.3.

### Upgrade notes
- Images are about 110 MB larger because of the advisory pack. Build with `--build-arg ADVISORY_PACK=0` to leave it
  out; set `MYELIN_OSV_EXPORT_DIR` to use a pack mounted from elsewhere.
- Expect more findings after upgrading, mainly dependency advisories in projects without lock files, copied libraries
  and end-of-life runtimes. They are real issues that earlier versions did not see.

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
