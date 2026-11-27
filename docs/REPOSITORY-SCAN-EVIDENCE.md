<!-- coderabbit-ai-generated:v1 -->

# Repository scan, SBOM and accuracy evidence

From the checkout, install the engine with `pip install .`. Use the scanner image or install the additional tools listed in [the scanning guide](concepts/scanning.md) for deeper analysis.

```sh
myelin scan . --policy policies/myelin-policy.yaml \
  --require sast,sca,secrets,iac,cicd \
  --json scan.json --sarif scan.sarif --sbom source.cdx.json --report assessment.html
myelin gate --results scan.json --require sast,sca,secrets
```

Choose the required areas for the repository. A required area that is partial, disabled, inapplicable or unassessed blocks the gate. Scanner process failures and invalid or partial scanner reports are also policy inputs. Use `--fail-on never` on a scan that should write evidence without failing a CI step; the recorded decision is still present.

| Evidence | What to check |
|---|---|
| HTML / JSON scan | Inspect each area's status, coverage gaps, tools and versions. A completed area ran its available configured checks within the indicated scope. A partial area may still have confirmed findings. |
| SARIF | Import source findings into an editor or code scanning tool. Scanner errors are included as separate records. |
| Source CycloneDX 1.5 SBOM | Review versioned components, source paths and the composition status. A known inventory gap is marked `incomplete`; otherwise repository-based inventory is `unknown` because it does not prove what shipped. Unresolved dependency relationships are omitted. |
| Build and image | CI separately checks container images and attaches an image SBOM. Build-time and OS components may differ from the source inventory. |
| Cloud and running services | Require their own inventories or targets. A repository scan does not supply cloud, runtime or live application evidence. |

Coverage counts describe candidate files. Test fixtures, ignored paths, generated files and files unsupported by a selected scanner can fall outside individual tools' scope. Reports distinguish bundled pattern checks from optional data-flow analysis and record whether Git history was scanned. Use [the SCA guide](concepts/sca-coverage.md) for supported lockfiles and advisory sources. Offline advisory scans with missing, invalid or incomplete OSV exports are partial.

## Verification in CI

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:9905ae58813cb43c6cb786580e0612d6a1cb4fd7cd2dd1fece4f9a36c6087149 -->

Run both benchmark commands from the checkout:

```sh
python scripts/scan_benchmark.py --output scan-accuracy.json
python scripts/scan_profiles.py --output scan-profiles.json
```

| Test profile | Evidence measured |
|---|---|
| Offline repository corpus | SAST, SCA, secrets, IaC, CI/CD, licence and supply chain rules, AI inventory, and versioned SBOM components. Advisory matching uses only the bundled subset. |
| Connected repository fixture | OSV pagination, withdrawn advisories, PyPI advisories, registry licence evidence and SBOM identities through a local HTTP service. |
| Verified offline export | Checksum and age checked OSV archives, version matching including unaffected controls, and licence gaps where there is no release metadata. |
| Read-only web baseline | Local HTTP fixtures with and without selected security headers. |

Both commands emit true positives, false positives, false negatives, precision and recall against labels. CI uploads them as **scan-validation** and fails on discrepancies. The results measure the listed fixtures; they do not measure production feed availability, broad real-world recall or the accuracy of a specific scan.

The report opens with the release gate, open findings, scan coverage and SBOM inventory. Clicking each card jumps to that detail. A zero finding count with material coverage gaps leaves the overall risk undetermined. For licences, the SBOM identifies lockfile, registry and bundled evidence. Missing or conflicting release evidence is shown as a coverage gap; bundled hints are useful for triage.

<!-- /coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:02310746c2a46b528fb6a50a6e94dedfa7ecbd72714b8080f3a0e10904bcff01 -->

For one-click scans and new CLI uploads, findings are closed automatically when the area completed or the selected area had no inputs in the new snapshot. A partial scan leaves prior findings open; a subsequent positive finding can reopen a fixed finding.

<!-- /coderabbit-ai-generated:v1 -->
