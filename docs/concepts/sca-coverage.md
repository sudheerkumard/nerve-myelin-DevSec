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
