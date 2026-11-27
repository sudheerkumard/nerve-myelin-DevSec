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

```sh
python scripts/scan_benchmark.py --output scan-accuracy.json
```

The command uses built-in engines and bundled offline advisories. It compares finding rule, path and line against reviewed labels, and compares SBOM package identities against a separate list of expected components. It emits true positives, false positives, false negatives, precision, recall, mismatches and duplicate component counts. CI uploads the result as **scan-validation** and fails on discrepancies. The fixture metrics measure regression performance on that corpus; they are not an accuracy percentage for a specific repository or for additional scanners.

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:02310746c2a46b528fb6a50a6e94dedfa7ecbd72714b8080f3a0e10904bcff01 -->

For one-click scans and new CLI uploads, findings are closed automatically when the area completed or the selected area had no inputs in the new snapshot. A partial scan leaves prior findings open; a subsequent positive finding can reopen a fixed finding.

<!-- /coderabbit-ai-generated:v1 -->
