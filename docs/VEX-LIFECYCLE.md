# RAT Flea DevSec: VEX and advisory lifecycle

RAT Flea DevSec can ingest CycloneDX VEX documents and CSAF 2.0 VEX documents through
`myelin_engine.vex`. The importer normalizes dispositions and applies them to scan
findings only when it can match both a vulnerability identifier and an exact package URL
(PURL). Package-name-only or CVE-only matching is intentionally rejected.

## Supported dispositions

| Source disposition | MYELIN lifecycle behaviour |
|---|---|
| not_affected / known_not_affected | Marks the exact CVE + PURL finding as `not_affected`; preserves issuer, source, justification and detail |
| fixed | Marks the exact CVE + PURL finding as `fixed` |
| affected / known_affected | Keeps the finding open and records the advisory statement |
| under_investigation | Keeps the finding open and records the statement; no risk reduction |
| conflicting statements | Marks the VEX annotation `ambiguous`; leaves the finding open |

Only the existing policy evaluator's terminal lifecycle states are excluded from gates.
`not_affected` is intentionally not a terminal state in the current policy evaluator:
a VEX disposition is retained as evidence but does not bypass policy gates by default.
This prevents an imported supplier statement from silently suppressing a security control.
A customer may review the evidence and apply a separately governed risk acceptance or
exception using the existing policy workflow.

## Python integration

```python
from myelin_engine import orchestrator, vex

result = orchestrator.scan("./source", repo="payments")
summary = vex.apply(result["findings"], [cyclonedx_vex_document, csaf_vex_document])
result["vex"] = summary
```

The importer is deterministic and offline. It does not fetch external documents or
trust a supplier statement as proof of non-exploitability. The organization remains
responsible for validating the justification and approval evidence before changing
finding status.

## Security boundaries

- Exact PURL and vulnerability identifier are both required.
- Missing or ambiguous product mappings never suppress a finding.
- Conflicting dispositions are surfaced as ambiguous.
- Under-investigation is annotation only.
- Imported evidence is not a substitute for reachability analysis, exploit validation,
  or an authorized risk acceptance.


## CycloneDX dependency graph

The generated CycloneDX 1.5 SBOM now includes:
- A unique application BOM reference and PURL-based component references
- A `dependencies` graph derived from resolved `introduced-by` relationships
- Manifest path and dependency-scope properties on each component
- Explicit empty dependency lists for leaf components

MYELIN does not invent a parent relationship when the inventory cannot resolve one
unambiguously. Such a component is retained as an application-level dependency, with its
manifest and package identity preserved. Package hashes are not fabricated when the
source manifest or lockfile does not provide a verifiable artifact digest.
