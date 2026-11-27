# Accuracy: how RAT Flea DevSec keeps false positives and misses under control

No static scanner can promise zero false positives on every codebase. RAT Flea DevSec controls them with four mechanisms:

1. **Accuracy gate in CI.** `engine/tests/benchmark/corpus` contains real weaknesses next to safe look-alikes
   (parameterised queries, constant URLs, safe YAML loaders, hardened Dockerfile and Kubernetes manifests, `${VAR}`
   references, password hashes, test fixtures). `backend/tests/test_benchmark.py` requires every expected finding
   (no false negatives) and nothing else (no false positives); bundled engines may never flag a line marked `SAFE`.
   Any rule change that alters the result fails the build until the expectation is reviewed.
2. **Precision by design.** Rules look at structure, not single lines, where it matters (Dockerfile stages, Compose services,
   Kubernetes workloads); references (`${VAR}`, `vault://`, file paths) are not secrets; hashes, e-mails and test folders are
   excluded from credential checks; constant HTML is not an XSS sink; import-only notices are dropped; duplicates from
   different engines are merged.
3. **Evidence for every finding.** CVE / advisory id with source, CVSS when published, fixed version, whether a dependency is
   direct or transitive and through which package, file and line, the matching code (secrets redacted).
4. **Decisions that stick.** *Mark false positive* and *Accept risk* (with reason, kept in the audit trail) are tied to the
   finding's fingerprint, so the same finding stays closed on every later scan. Fixed findings close themselves and reopen
   if the issue returns.

Report suspected false positives with the finding id; each confirmed case becomes a new `SAFE` sample in the corpus.
