# Finding remediation contract

NERvvE enriches each normalized finding with consistent developer-facing guidance.

## Fields

- `remediation`: actionable corrective instruction. Existing detailed scanner guidance is preserved.
- `remediation_steps`: a display-friendly list derived from the remediation text.
- `verification`: a concrete validation step developers can use after applying the fix.
- `remediation_source`: whether guidance came from the scanner, a CWE mapping or NERvvE engine guidance.
- `remediation_version`: version of the guidance contract.

## Safety and accuracy

Guidance is selected using normalized engine and CWE identifiers. A finding title alone is not treated as proof of a vulnerability class. For SCA, the engine uses the advisory's fixed version when available; otherwise it explicitly says no fixed version is recorded and recommends checking the vendor advisory for a workaround or replacement. Developers must validate upgrades against the actual lockfile and built artifact.

Remediation is guidance, not an automatic change to source code or infrastructure. Production changes require normal review and testing.
