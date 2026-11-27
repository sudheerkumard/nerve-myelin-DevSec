# SBOM analysis

Upload SBOMs you received (from a supplier, another team or a build system) and get a licence and vulnerability
report for them, without adding anything to the security dashboard.

## Upload

Open **SBOM analysis** in the console, give the project a name and choose the files:

- CycloneDX JSON (1.2 to 1.6) or CycloneDX XML,
- SPDX 2.x JSON,
- a ZIP containing any number of them (folders inside the ZIP are fine; other files are ignored).

All files of one upload become **one project**. A product made of several services or modules therefore gets one
report: components are merged by package and version, and each one lists the SBOM files it came from. Uploading
again with the same project name replaces the project.

Limits: 500 files and 70 MB per upload in the console (100 MB per API request); zip large sets, SBOMs compress well.
XML files with DOCTYPE or entity declarations are rejected.

## What is checked

| Check | How |
|---|---|
| Licence | Each component's SPDX licence expression is evaluated against the licence policy: allowed, needs review or denied, with the specific reason, the obligations (notice, source disclosure, network use) and the action to take. Licences missing from the SBOM are looked up in the package registry (npm, PyPI, Maven Central including parent POMs, NuGet, Packagist, RubyGems, crates.io). |
| Vulnerabilities | Every component version is matched against OSV (and PyPI, NVD, EPSS and CISA KEV enrichment), the same as a repository scan. |

Components without a package URL (purl) cannot be identified and are counted in the file list as skipped.

## Results

The project page shows the files read (and any that could not be), the licence table and the vulnerabilities. Each
project offers:

- **Report**: a self-contained HTML report (prints to PDF) with the licence findings and every vulnerability with its
  numbered mitigation steps.
- **CSV**: licences and vulnerabilities in one sheet for Excel.
- **CycloneDX**: the merged inventory as a CycloneDX 1.5 SBOM.
- **Delete**: removes the project and its report.

The project also appears in **Licence governance** (choose "SBOM: <project>" in the list), so licence review works the
same way for scanned repositories and uploaded SBOMs.

## API

```text
POST   /api/v1/sbom-projects                 {"name": "...", "files": [{"filename": "x.zip", "content_b64": "..."}]}
GET    /api/v1/sbom-projects
GET    /api/v1/sbom-projects/{name}
GET    /api/v1/sbom-projects/{name}/report?format=html|csv|cyclonedx
DELETE /api/v1/sbom-projects/{name}
```

Uploading needs the scan-write permission; reading needs findings-read. The licence decisions are triage, not legal
advice.
