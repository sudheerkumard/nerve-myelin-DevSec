# Expanded SCA inventory and scanner coverage

## What this change adds

NERvvE's built-in dependency inventory now reads exact package versions from the following lockfile families:

| Ecosystem | Lockfile / source | Notes |
|---|---|---|
| npm | package-lock.json, npm-shrinkwrap.json | v1 and packages-based lock formats |
| Yarn | yarn.lock | Parsed package/version selectors |
| pnpm | pnpm-lock.yaml | Legacy slash keys and modern package keys |
| Python | poetry.lock, Pipfile.lock, uv.lock, pdm.lock | Exact locked package versions |
| Python | requirements*.txt | Direct pins; unpinned requirements are resolved from registry metadata when online |
| Rust | Cargo.lock | Registry packages; workspace/root packages are not treated as third-party libraries |
| PHP | composer.lock | Production and development packages |
| Ruby | Gemfile.lock | Packages under the lockfile specs section |
| Java / Kotlin | gradle.lockfile | Group, artifact and locked version coordinates |
| .NET | packages.lock.json, packages.config | Resolved package versions |
| Go | go.mod | Declared module requirements, including indirect requirements where versioned |

Maven pom.xml and Go go.mod manifests are also parsed by the existing manifest inventory. A go.sum entry alone is deliberately not treated as proof that a version is in the selected build graph: it can retain checksums for versions no longer selected by the module graph.

## Independent advisory engines

When installed, the source scan invokes Trivy and Grype independently. Their normalized findings are correlated with NERvvE's OSV / PyPI advisory matching and merged by the existing finding correlation layer.

Grype uses its own Syft-backed package cataloging and vulnerability database. This gives the scan a second package discovery and advisory-matching path rather than relying exclusively on NERvvE's manifest parser.

The Docker runtime now includes a pinned Grype release. Offline deployments must maintain the required Grype vulnerability database through an approved mirror or database transfer process; a missing database must be visible as a scanner error, not interpreted as zero vulnerabilities.

## Accuracy boundaries

- Lockfile parsers provide exact package versions, but a parser does not by itself prove runtime reachability.
- A lockfile may contain development, optional, platform-specific or inactive dependency groups. Scope metadata must be retained and used for risk context, not silently discarded.
- Go go.sum is a checksum ledger, not a definitive selected dependency graph.
- Different scanners can disagree because their package catalogs, advisory sources, affected-version logic and CPE/PURL matching differ.
- A clean scan is meaningful only when the dependency inventory is complete and each configured scanner/advisory source completed successfully.
- NERvvE must report unsupported or malformed lockfiles and unavailable scanner databases as coverage gaps.

## Regression tests

`engine/tests/test_lockfile_parsers.py` covers modern and legacy pnpm keys, Cargo, Composer, RubyGems, Gradle, NuGet, uv, PDM, malformed lockfile isolation and Grype normalization/selection.

## Vulnerability intelligence and coverage status

The advisory correlation pipeline combines package-aware affected-version matching with independent CVE context. OSV remains the package/version matching source; NVD is enrichment, not a replacement for ecosystem-specific affected ranges.

- **OSV.dev**: package/ecosystem/version queries and affected ranges, including advisories aggregated from upstream sources such as GitHub Security Advisories where available.
- **NVD CVE API 2.0**: CVSS v2/v3/v4 metrics when published, vector strings, CWE weakness mappings, publication/modification timestamps, references and vulnerability status. NVD lookups are cached for 24 hours. Set `NVD_API_KEY` to use the authenticated API quota; without a key, rate limits can delay enrichment. An NVD record is not assumed to exist for every advisory.
- **FIRST EPSS**: daily exploitation probability and percentile for CVE-backed findings. Attribute FIRST when presenting these scores.
- **CISA KEV**: known-exploited status plus catalog context such as date added, remediation due date, ransomware-campaign use and required action.
- **PyPI**: independent Python package advisory fallback, queried even when OSV responds.

NVD CVSS is used as the finding score only when the advisory did not already provide a score. Existing ecosystem advisory severity is retained, and NVD data is preserved separately for auditability. A missing score, CWE or enrichment record remains unknown rather than being guessed.


Online CVE-backed findings are enriched with the FIRST EPSS probability and CISA Known Exploited Vulnerabilities (KEV) status when those feeds are reachable. Feed results are cached. If either source is unavailable, the report records the enrichment error and leaves the corresponding value unknown rather than assigning a misleading zero probability or false exploitation status.

The built-in inventory also parses Hex (mix.lock), Dart (pubspec.lock) and CocoaPods (Podfile.lock) package records. Their package coordinates are queried against OSV where the ecosystem is supported, while Trivy and Grype provide independent artifact and source-tree analysis.

SCA coverage exposes complete and status fields. A scan with advisory-feed errors or a failed configured scanner is partial, even if it found no vulnerabilities. A zero-finding result is not a proof that the repository is vulnerability-free.

## Vulnerability classes and product coverage

NERvvE combines multiple analysis methods because vulnerability detection is not one scanner task:

- **Source-code weaknesses:** injection (SQL, OS command, LDAP and template), path traversal, SSRF, insecure deserialization, XSS, broken access control patterns, weak cryptography, unsafe TLS validation and insecure file handling. Coverage depends on the language and available rule pack; the scan report lists unsupported languages.
- **Dependency and supply-chain risks:** known CVEs and ecosystem advisories (including GHSA/PYSEC where published), vulnerable version ranges, malicious packages, typosquatting and dependency confusion. Package inventory comes from manifests, lockfiles, imported SBOMs and supported artifact scanners.
- **Secrets:** provider-specific credentials, private keys, generic credentials and Git history when a Git clone is available.
- **Build and infrastructure configuration:** Docker, Kubernetes, Terraform, Bicep, Helm, Compose and CI/CD workflow weaknesses.
- **Container and artifact vulnerabilities:** operating-system and application packages discovered by Trivy and Grype when their databases and target format are available.
- **Live application and API weaknesses:** safe read-only checks by default; active testing requires explicit authorisation and a suitable non-production target.
- **Cloud, identity and runtime posture:** configuration, excessive privilege, exposure and runtime detections through the corresponding collectors and integrations.

No static scanner can guarantee detection of every vulnerability. Dynamic behavior, unsupported languages, proprietary package sources, generated code, platform-specific dependency resolution, unreachable code and vulnerabilities not yet disclosed in an advisory feed can all create blind spots. NERvvE therefore reports the files, ecosystems, scanners, intelligence sources, errors and partial-coverage status. Missing data is not reported as a clean bill of health.


## Advisory precision, exploit evidence and VEX

OSV affected-version records can express explicit version lists and ecosystem, semantic-version or Git commit ranges. A correct matcher must evaluate the range type and event sequence, not compare version strings lexicographically or assume every advisory has a simple fixed version. In particular, `last_affected` is inclusive while `fixed` identifies the first non-affected version. Git ranges require repository ancestry and cannot be treated as ordinary package versions. See the [OSV schema](https://ossf.github.io/osv-schema/).

NVD enrichment now retains reference classifications (including exploit and patch references) and NVD's CISA catalog fields when supplied. These are evidence links and metadata, not proof that an exploit works against the scanned application. CISA KEV is a catalog of vulnerabilities known to have been exploited; its dates and required actions should remain visible to operators. The canonical feed schema is maintained in the [CISA KEV data repository](https://github.com/cisagov/kev-data).

VEX is a separate product-context assertion, not another vulnerability feed. A future VEX workflow should accept CycloneDX VEX or CSAF VEX statements, validate issuer, product identity, component identity, vulnerability identifier, status, justification and timestamp, and preserve the original signed/source document. It must never auto-mark a finding `not_affected` merely because static reachability was not detected. CycloneDX describes VEX as exploitability information for a component in the context of a product: https://www.cyclonedx.org/capabilities/vex/.

Operational rule: a missing exploit reference does not mean no exploit exists; a missing KEV entry does not mean not exploitable; and an unobserved import path does not prove non-reachability. Keep these states separate in the finding model and risk prioritisation.


## Structured prioritisation evidence (NVD SSVC and affected products)

When NVD supplies structured SSVC metrics or CVE-record affected-product data, NERvvE preserves those source records as evidence on the finding. These fields are supplemental context: the scanner does not translate an unrecognised SSVC schema into an invented priority, and it does not use NVD product CPE/CVE affected-product records as a substitute for ecosystem-specific OSV package ranges. Product matching requires an explicit, validated mapping between the scanned component and the vendor/product identity.

SCA findings also carry EPSS percentile, CISA KEV catalog details and the NVD evidence object so downstream reporting can display the source values and timestamps. A missing field remains unknown. Risk ranking should combine exploit evidence, package reachability, deployment exposure, business criticality and fix availability, while retaining each underlying source field for audit.
