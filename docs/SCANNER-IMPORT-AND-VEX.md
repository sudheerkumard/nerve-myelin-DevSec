# Import other scanners' results, VEX, gates and exports

## Bring your own scanner

You can bring results from tools you already run. They are then handled the same way as findings from RAT Flea DevSec's own engines:

- de-duplicated
- risk-scored (RAT Flea Risk Score, priority, SLA)
- gated by policy
- ticketed in Jira, ServiceNow or Azure Boards
- shown on the dashboards and in the reports
- exported as VEX

| Format | Typical producers |
|---|---|
| SARIF 2.1.0 | any SARIF tool, e.g. CodeQL or Semgrep. `security-severity` and CWE tags are used when present. |
| CycloneDX 1.4+ JSON | SBOMs with a `vulnerabilities` section. A plain SBOM is matched against RAT Flea DevSec's vulnerability intelligence. |
| Trivy JSON | dependencies, OS packages, misconfigurations, secrets |
| Grype JSON | dependencies |
| Semgrep JSON | code |
| Gitleaks JSON | secrets, including git history |
| Checkov JSON | infrastructure as code |
| Bandit JSON | Python code |
| OWASP ZAP JSON | running web applications |

The format is detected automatically.

There are three ways to import:
- **Console:** Integrations → *Import results from other scanners* → choose the repository and the file.
- **CLI:** `myelin import results.sarif --repo payments-api --server https://myelin.example.com`
- **Explicit-format API:** `POST /api/v1/scanners/import` takes a parsed JSON document with a named format (Scanner intake page).
  - The API key is read from `MYELIN_API_KEY`.
  - Without `--server`, the CLI evaluates the policy locally and exits 1 on a block.
- **API:** `POST /api/v1/scans/import` with body `{repo, branch, commit, filename, format: "auto", content_base64}`.

An import never auto-closes other findings: only a new scan by the same RAT Flea DevSec engines closes what it no longer reports.

## VEX (Vulnerability Exploitability eXchange)

A VEX document is built from your triage decisions on each repository's dependency vulnerabilities:

| Your decision in RAT Flea DevSec | VEX status |
|---|---|
| Fixed (confirmed by a re-scan) | `fixed` |
| Marked as false positive | `not_affected`. The justification comes from your reason (for example "not in execute path", "mitigated by WAF"). |
| Risk accepted | `affected`, with the reason and the expiry date in the action statement |
| Open with an available fix | `affected`, with "upgrade to X" |
| Open, untriaged | `under_investigation` |

- **Export:** Repositories → **VEX**, which downloads OpenVEX 0.2.0. Or call `GET /api/v1/vex?repo=…&format=openvex|cyclonedx`.
  - Give the file to your customers so their scanners stop reporting vulnerabilities that do not affect your product.
  - Trivy and Grype both accept `--vex`.
- **Import:** Integrations → *VEX document*. Or call `POST /api/v1/vex/import` with `{content_base64, repo, dry_run}`. OpenVEX, CycloneDX VEX and CSAF 2.0 are accepted.
  - A VEX statement never changes a finding by itself. The API previews by default (`dry_run` is true); an analyst with triage rights applies the matches with `dry_run: false`.
  - Only exact matches count: the same vulnerability (or alias) **and** the same component purl, including version. Conflicting statements for the same pair are reported as ambiguous and ignored.
  - A supplier's `not_affected` statement closes the matching finding as a false positive, keeping the justification.
  - `fixed` closes it as fixed.
  - The console shows how many findings match before applying anything.
  - Every change is audited.

## Accepted risk always expires

To accept a risk you must give a reason and an expiry date (at most one year away). On the expiry date the finding reopens automatically. The reopening is recorded in the audit trail, and the finding counts against gates, SLAs and reports again.

## Gate only what a change introduces

```bash
myelin gate --repo payments-api --commit "$GIT_SHA" --scope new --require sast,sca,secrets,iac,cicd
```

- **`--scope new`:** only findings first introduced by the commit can block the deployment. Existing issues are still reported and tracked; they do not block unrelated changes.
- **`--require`:** blocks when one of the listed engines did not run for that commit, so a green gate always means every check ran.

## Exports

| What | Where |
|---|---|
| Findings (CSV, opens in Excel) | Findings → **⇩ Export CSV**, or `GET /api/v1/findings/export?status=open&repo=…`. Includes CVE links and triage decisions; cells are protected against spreadsheet formula injection. |
| SBOM | Repositories → **SBOM** (CycloneDX 1.5) |
| VEX | Repositories → **VEX** |
| Audit trail for a SIEM | Audit log → JSON lines / CSV, or `GET /api/v1/audit/export?format=jsonl\|csv` |
| Corporate report | Repositories / Live app testing → **Full report** (HTML → PDF) |
