# Changelog — RAT Flea DevSec

All notable changes to RAT Flea DevSec are recorded here. Versions follow [Semantic Versioning](https://semver.org):
MAJOR for breaking changes, MINOR for new features, PATCH for fixes. Each section is turned into release notes by
`scripts/release/notes.py` when a version is tagged.

## [Unreleased]

## [1.9.0] - 2026-11-28

### Highlights
- **Every security domain is covered by every testing type, online and offline.** Findings now carry a security
  domain (application, network, data, compute, identity, logging, supply chain), and the enterprise report shows a
  matrix of findings by domain and testing type (SAST, SCA, secrets, IaC, container, DAST). The same checks run with
  the built-in engine when the external scanners are not installed or the machine has no network access.
- **Built-in cloud infrastructure checks for AWS, Azure and Google Cloud** across Terraform, CloudFormation, ARM and
  Bicep, plus Kubernetes network, RBAC and secret checks, with duplicates against the external IaC scanners removed.

### Added
- **Cloud IaC rules (NM-IAC-1xx to 5xx, 128 rules).** Network exposure (open security groups and NSGs, public
  databases, load balancers without TLS, public IPs on VMs), data protection (encryption at rest, public buckets and
  storage, backups, key rotation, TLS minimum versions), compute (IMDSv2, public images, unencrypted disks, serial
  console), identity (wildcard policies, public principals, admin roles, MFA, service account keys) and logging
  (CloudTrail, flow logs, SQL auditing, diagnostic settings, log retention). A built-in parser reads Terraform HCL,
  CloudFormation YAML/JSON with intrinsic functions, ARM JSON and Bicep, with no extra tools.
- **Kubernetes checks**: LoadBalancer services without source ranges (NM-IAC-151), Ingress without TLS (152),
  namespaces without a NetworkPolicy where the repository uses them elsewhere (153), RBAC wildcards, secret readers,
  escalate/bind/impersonate, anonymous bindings and cluster-admin (451–455), Secret objects and credentials in
  ConfigMaps committed to the repository (251, 252).
- **Application and server configuration checks (NM-CFG, 37 rules)**: AndroidManifest and network security config,
  iOS App Transport Security, Spring Boot properties and YAML, ASP.NET web.config, Django settings, php.ini, nginx,
  Apache, sshd, Redis and MongoDB configuration.
- **SAST for more languages**: C and C++ (including use-after-free, double free and allocation-size overflow), Kotlin (including Android), Swift, Scala, Rust and shell scripts, and
  hardening rule packs for Python, JavaScript/TypeScript, Java, C#, Go, PHP and Ruby. The pack now has 181 rules across
  15 languages, each with a test fixture, and regex fallbacks (NM-SAST-048 to 055) when Opengrep is not installed.
- **Secret detection**: 59 credential patterns (up from 15), adding source-control, package-registry, CI/CD, cloud
  (GCP, Azure SAS and connection strings, Alibaba, Tencent, DigitalOcean), secrets-manager, payment, messaging and
  webhook, observability, identity-provider and AI-provider tokens, database connection strings, kubeconfig keys,
  PGP/Age/PuTTY keys and keystore passwords.
- **DAST exposure checks**: exposed sensitive files such as `.git`, `.env` and backups, confirmed by content
  (NM-DAST-040), directory listing (041), GraphQL introspection (042), Host header reflection (043), weak
  Content-Security-Policy (044), and missing Referrer-Policy or Permissions-Policy (045).
- **Container image configuration (NM-CTR-001 to 007)**: running as root, secrets in environment variables, exposed
  administrative ports, no health check, images older than 180 days, SSH or telnet servers installed, and unexpected
  setuid/setgid files.
- **Security-domain matrix** in the enterprise report and a coverage-by-domain table in `docs/WHAT-WE-SCAN.md`.

### Changed
- Remediation steps for the new rule families start with the rule's own fix, followed by guidance for the weakness
  family (exposure, transport security, encryption at rest, least privilege, logging, configuration hardening, memory
  safety, credentials, integrity).
- External IaC findings that duplicate a built-in check on the same file and resource are dropped, so the same issue
  is not reported twice.
- Passive DAST makes about 25 extra GET requests for the exposure checks; it still sends no attack payloads.

### Upgrade notes
- Expect more findings on repositories with cloud IaC, mobile apps, C/C++, Kotlin, Swift, Rust or shell code, and
  server configuration files. Review them before turning on blocking policies for the new rule IDs.

## [1.8.0] - 2026-11-28

### Highlights
- **Every layer of software is scanned, online and offline**: operating systems, native libraries and executables,
  firmware, device drivers, mobile packages, and the databases, middleware and platforms declared in infrastructure
  code, in addition to application dependencies. See `docs/WHAT-WE-SCAN.md` for the full coverage table.
- **The offline advisory pack covers all of it**: Debian, Ubuntu, Alpine, Wolfi, Chainguard, AlmaLinux, Rocky Linux
  (also used for RHEL, CentOS and Oracle Linux) and Amazon Linux package advisories; every NVD CVE with its CPE ranges
  (about 414,000 CVEs across 97,000 products); and the LOLDrivers list of vulnerable and malicious Windows drivers.

### Added
- **Operating-system packages (NM-OS-001, NM-OS-002).** dpkg (including distroless), apk, RPM (SQLite database) and
  opkg databases are read from container images, root filesystems, VM and device images. Matching uses OSV online and
  the pack offline, with each distribution's own version ordering. Findings are grouped the way they are fixed: one
  per source package and fixed version, listing every CVE the update fixes; vulnerabilities without a released fix
  are grouped per package. Distribution releases and kernels past end of life are reported.
- **Built-in container image scanning without Docker or Trivy**: `myelin scan --image image.tar` reads `docker save`,
  `podman save` and OCI archives or layout directories, applies the layers with whiteouts and scans the result.
- **Native libraries and executables (NM-BIN-002).** Version strings of OpenSSL, zlib, curl, SQLite, libpng, expat,
  glibc, OpenSSH, Dropbear, BusyBox, nginx, Apache httpd, PostgreSQL, U-Boot, the Linux kernel and about 20 more are
  read from ELF, PE and Mach-O files and matched by CPE. Go executables give their modules and Go toolchain version;
  Rust executables built with cargo-auditable give their crates.
- **Executable hardening (NM-BIN-001)**: dynamically linked ELF executables without NX, PIE, RELRO or stack protector.
- **Firmware.** Raw images, uImage and TRX files are searched inside their compressed sections (gzip, xz, LZMA,
  zlib); root filesystems are unpacked with unblob, sasquatch or unsquashfs when installed (the images ship
  squashfs-tools) and scanned for packages, binaries, secrets, accounts with empty or weak password hashes
  (NM-FW-001) and telnet at boot (NM-FW-002). When a filesystem cannot be unpacked, the report says so.
- **Drivers**: Windows drivers matched against known vulnerable (NM-DRV-001) and malicious (NM-DRV-002) drivers;
  Linux kernel modules report the kernel they were built for.
- **Mobile packages**: AndroidX/Jetpack versions and native libraries inside .apk, .aab, .aar and .ipa files.
- **Databases, middleware and platforms in infrastructure code**: end of life of managed databases (RDS, Aurora,
  ElastiCache, MemoryDB, Azure Database, Cloud SQL), Kubernetes control planes (EKS, AKS, GKE), function and app
  runtimes (Lambda, Azure Functions and App Service, Cloud Functions), MSK, OpenSearch and Amazon MQ in Terraform,
  CloudFormation and Bicep; known vulnerabilities of database and middleware versions in image tags in Kubernetes,
  Helm, Kustomize, Compose, Terraform and Dockerfiles (NM-IMG-001); Kubernetes API versions that were removed
  (NM-K8S-001).
- **SBOM analysis** reads operating-system packages (`pkg:deb`, `pkg:rpm`, `pkg:apk`) and components identified only
  by CPE (firmware, devices, operating systems), which were skipped before.
- Lifecycle data now covers about 490 products, including managed cloud services.
- `scripts/build_offline_pack.sh` builds the complete pack in one step; `docs/WHAT-WE-SCAN.md` lists every component
  type and its data sources.

### Changed
- The dependency engine is reported as "Software components (SCA)".
- AWS Lambda runtimes are end of life when standard support ends (security patches stop), and the suggested upgrade
  stays in the same language.

### Upgrade notes
- The offline advisory pack in the images grows to about 190 MB. `--build-arg PLATFORM_PACK=0` builds the previous,
  application-only pack (about 110 MB); building the full pack needs about 6 GB of temporary disk for the NVD mirror.
- Scans of container images, root filesystems, firmware and infrastructure code report more findings. Application
  repositories without these see no change.

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
