# Offline and air-gapped scanning

RAT Flea DevSec scans the same way with or without internet access. What changes is where vulnerability, licence
and lifecycle data comes from.

| Data | Online | Offline (`MYELIN_OFFLINE=1`) or OSV unreachable |
|---|---|---|
| Vulnerabilities in dependencies | OSV.dev, enriched with NVD, EPSS and CISA KEV | Offline advisory pack: every reviewed GitHub advisory for npm, PyPI, Maven, NuGet, Go, Packagist, RubyGems, crates.io, Hex and Pub |
| Malicious packages | OSV (MAL- records) | Offline advisory pack (OpenSSF Malicious Packages) |
| Licences missing from manifests | Package registries | Licences in the files themselves (manifest fields, committed licence texts) |
| End-of-life runtimes and frameworks | endoflife.date API (refreshed per product) | Bundled lifecycle snapshot (about 390 products) |
| Components copied into the repository | Same | Same (read from file banners, archive metadata and vendor folders) |

If the platform is online but OSV cannot be reached (a proxy that blocks it, an outage), the scan falls back to the
offline advisory pack automatically and says so in the report's intelligence sources, instead of reporting no
vulnerabilities.

## The offline advisory pack

The platform image and the CLI image include the pack at `/opt/myelin/advisories`. It is an OSV export: one zip per
ecosystem and a `manifest.json` with the generation time and a SHA-256 checksum for each archive. The scanner checks
every checksum before it uses the pack and loads only the ecosystems present in the scanned project.

To use a pack somewhere else (a newer copy, a shared volume), set `MYELIN_OSV_EXPORT_DIR` to its directory. To refuse
a pack older than a number of days, set `MYELIN_OSV_MAX_AGE_DAYS`.

Image builds include the pack by default. Build without it (about 110 MB smaller) with
`--build-arg ADVISORY_PACK=0`.

## Refreshing the pack on an air-gapped network

On a machine with internet access:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database ghsa
git -C ghsa sparse-checkout set advisories/github-reviewed
git clone --depth 1 --filter=blob:none --sparse https://github.com/ossf/malicious-packages malp
git -C malp sparse-checkout set osv/malicious
python scripts/build_advisory_pack.py ghsa advisories malp
```

Copy the `advisories` folder across (it is checksummed, so a damaged copy is rejected), mount it into the containers,
and set `MYELIN_OSV_EXPORT_DIR` to the mount path. Weekly refreshes keep new advisories flowing; the report shows the
pack's generation date so readers know how current the data is.

## Refreshing the lifecycle snapshot

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/endoflife-date/endoflife.date eold
git -C eold sparse-checkout set products
python scripts/build_eol_data.py eold
```

This rewrites `engine/myelin_engine/data/eol.json.gz`. Online scans do not need it: they ask the endoflife.date API for
each product they find (`MYELIN_EOL_URL` points to a mirror).

## Data licences

The GitHub Advisory Database is CC BY 4.0, OpenSSF Malicious Packages is Apache-2.0 and endoflife.date is MIT. See
THIRD-PARTY-NOTICES.md.
