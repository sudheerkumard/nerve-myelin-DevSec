# Offline and air-gapped scanning

RAT Flea DevSec scans the same way with or without internet access. What changes is where vulnerability, licence
and lifecycle data comes from.

| Data | Online | Offline (`MYELIN_OFFLINE=1`) or OSV unreachable |
|---|---|---|
| Vulnerabilities in dependencies | OSV.dev, enriched with NVD, EPSS and CISA KEV | Every reviewed GitHub advisory for npm, PyPI, Maven, NuGet, Go, Packagist, RubyGems, crates.io, Hex and Pub |
| Malicious packages | OSV (MAL- records) | OpenSSF Malicious Packages |
| Exploited in the wild | CISA KEV feed | CISA KEV catalog |
| Operating-system packages | OSV (Debian, Ubuntu, Alpine, AlmaLinux, Rocky, Red Hat, SUSE, Wolfi, Chainguard and more) | Debian, Ubuntu, Alpine, Wolfi, Chainguard, AlmaLinux, Rocky Linux (also RHEL, CentOS, Oracle Linux), Amazon Linux |
| Native libraries, firmware, kernels, databases, middleware, devices (by CPE) | NVD API | Every NVD CVE with its CPE ranges and CVSS (about 414,000 CVEs, 97,000 products) |
| Vulnerable and malicious Windows drivers | LOLDrivers (from the pack) | LOLDrivers |
| Licences missing from manifests | Package registries | Licences in the files themselves (manifest fields, committed licence texts) |
| End-of-life runtimes, operating systems, databases, managed services | endoflife.date API (refreshed per product) | Bundled lifecycle data (about 490 products) |
| Components copied into the repository | Same | Same (read from file banners, archive metadata and vendor folders) |

See [What RAT Flea DevSec scans](WHAT-WE-SCAN.md) for every component type.

If the platform is online but OSV cannot be reached (a proxy that blocks it, an outage), the scan falls back to the
offline advisory pack automatically and says so in the report's intelligence sources, instead of reporting no
vulnerabilities.

## The offline advisory pack

The platform image and the CLI image include the pack at `/opt/myelin/advisories`. It is an OSV export: one zip per
ecosystem and a `manifest.json` with the generation time and a SHA-256 checksum for each archive. The scanner checks
every checksum before it uses the pack and loads only the ecosystems present in the scanned project.

To use a pack somewhere else (a newer copy, a shared volume), set `MYELIN_OSV_EXPORT_DIR` to its directory. To refuse
a pack older than a number of days, set `MYELIN_OSV_MAX_AGE_DAYS`.

Image builds include the pack by default (about 190 MB). Build without it with `--build-arg ADVISORY_PACK=0`, or with
only the application-ecosystem part (about 110 MB) with `--build-arg PLATFORM_PACK=0`.

## Refreshing the pack on an air-gapped network

On a machine with internet access (git, Python 3 and about 6 GB of temporary disk for the NVD mirror):

```bash
sh scripts/build_offline_pack.sh ./advisories            # PLATFORM=0 for application ecosystems only
```

Copy the `advisories` folder across (every file is checksummed, so a damaged copy is rejected), mount it into the
containers, and set `MYELIN_OSV_EXPORT_DIR` to the mount path. Weekly refreshes keep new advisories flowing; the
report shows the pack's generation date so readers know how current the data is. The individual steps
(`build_advisory_pack.py`, `build_os_pack.py`, `build_cpe_pack.py`, `build_driver_pack.py`) can also be run on their
own.

## Refreshing the lifecycle snapshot

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/endoflife-date/endoflife.date eold
git -C eold sparse-checkout set products
python scripts/build_eol_data.py eold
```

This rewrites `engine/myelin_engine/data/eol.json.gz`. Online scans do not need it: they ask the endoflife.date API for
each product they find (`MYELIN_EOL_URL` points to a mirror).

## Data licences

Each source keeps its own terms (GitHub Advisory Database CC BY 4.0, OpenSSF and LOLDrivers Apache-2.0, CISA KEV
CC0, NVD public domain, Ubuntu notices CC BY-SA 4.0, endoflife.date MIT, and the distributions' own advisory
data). See THIRD-PARTY-NOTICES.md.
