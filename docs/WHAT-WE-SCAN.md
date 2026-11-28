# What RAT Flea DevSec scans

Every kind of software component, from application code down to firmware, and where the vulnerability data comes
from online and offline. "Offline" means `MYELIN_OFFLINE=1` or an air-gapped network using the
[offline advisory pack](OFFLINE-ADVISORY-PACK.md); the same pack is used automatically when an online source cannot
be reached.

## Coverage by component type

| Component type | What is read | Matched against (online) | Matched against (offline) |
|---|---|---|---|
| **First-party code** | Source code in the supported languages | SAST rules (built-in, optional deep taint analysis) | Same |
| **Application libraries and frameworks** | Manifests, lock files and build files for npm, PyPI, Maven/Gradle, NuGet, Go, Cargo, Composer, RubyGems, Hex, Pub, CocoaPods | OSV, PyPI, GitHub advisories, with EPSS, CISA KEV and NVD | Every reviewed GitHub advisory, OpenSSF malicious packages, CISA KEV |
| **Libraries copied into the repository** | Minified scripts, jar/war/ear, nupkg, wheels, vendor folders, committed node_modules | As above | As above |
| **Operating systems** | `os-release` and package databases (dpkg, apk, rpm sqlite, opkg) in container images, root filesystems, VM and device images | OSV: Debian, Ubuntu, Alpine, AlmaLinux, Rocky, Red Hat, SUSE, Wolfi, Chainguard and more | Debian, Ubuntu, Alpine, Wolfi, Chainguard, AlmaLinux, Rocky Linux (also RHEL, CentOS, Oracle Linux), Amazon Linux |
| **OS and runtime end of life** | Distribution release, kernel, base images, runtimes in version files | endoflife.date API | Bundled lifecycle data for about 490 products |
| **Native libraries and executables** | ELF, PE and Mach-O files and static archives: version strings of OpenSSL, zlib, curl, SQLite, libpng, expat, glibc, OpenSSH, nginx, Apache httpd, PostgreSQL and about 30 more | NVD (by CPE) | Every NVD CVE with its CPE ranges |
| **Go and Rust executables** | Go build information (modules and Go toolchain), cargo-auditable data | OSV (Go, crates.io) | Offline pack |
| **Executable hardening** | NX, PIE, RELRO, stack protector of dynamically linked ELF executables | Rule-based | Same |
| **Firmware** | Raw flash dumps, uImage, TRX, compressed sections (gzip, xz, LZMA, zlib), squashfs root filesystems (with unblob, sasquatch or unsquashfs installed): kernel, U-Boot, BusyBox, Dropbear, OpenSSL, dnsmasq, lighttpd, mbed TLS, wolfSSL, FreeRTOS, Zephyr, lwIP; empty or weak password hashes; telnet at boot | NVD (by CPE) | Every NVD CVE |
| **Device drivers** | Windows `.sys` drivers (SHA-256 against known vulnerable and malicious drivers); Linux kernel modules (the kernel they were built for) | LOLDrivers, NVD | Same, from the pack |
| **Mobile apps** | `.apk`, `.aab`, `.aar`, `.ipa`: AndroidX/Jetpack versions and native libraries inside | OSV, NVD | Offline pack |
| **Databases and storage** | Container images (PostgreSQL, MySQL, MariaDB, Redis, MongoDB, Elasticsearch, OpenSearch, Cassandra, CouchDB, InfluxDB, Neo4j, ClickHouse, MinIO); managed services in Terraform, CloudFormation and Bicep (RDS, Aurora, ElastiCache, MemoryDB, Azure Database, Cloud SQL) | NVD (image application version), endoflife.date | Offline pack and lifecycle data |
| **Middleware, servers and APIs** | Images and IaC for nginx, Apache httpd, Tomcat, Jetty, HAProxy, Traefik, Envoy, Kafka, RabbitMQ, ActiveMQ, NATS, Mosquitto, Keycloak, Vault, Consul, etcd, ZooKeeper, Jenkins, Grafana and more; Lambda, Azure Functions/App Service and Cloud Functions runtimes; API specifications for live API testing | NVD, endoflife.date | Offline pack and lifecycle data |
| **Platforms** | Kubernetes control planes (EKS, AKS, GKE) and API versions removed from Kubernetes | endoflife.date, Kubernetes API removals | Same |
| **Infrastructure as Code and pipelines** | Terraform, Bicep, CloudFormation, Kubernetes, Helm, Compose, Dockerfiles, CI/CD files | Rule-based | Same |
| **Secrets** | Code, configuration, history, images and firmware root filesystems | Rule-based (optional provider validation online) | Same |
| **Supplier SBOMs** | CycloneDX and SPDX: package URLs (including `pkg:deb`, `pkg:rpm`, `pkg:apk`) and CPE-only components (firmware, devices, operating systems) | As above | As above |
| **Running applications** | Live web applications and APIs (DAST) | Active and passive tests | Same |

## How to scan each kind of target

| Target | Command or console action |
|---|---|
| Repository | `myelin scan <path>` or **Repositories → Add** |
| Container image from a registry | `myelin scan --image <name>` (uses Trivy or Grype) |
| Container image without registry access or scanner tools | `docker save -o image.tar <name>` (or `skopeo copy docker://<name> oci-archive:image.tar`), then `myelin scan --image image.tar` |
| Root filesystem, VM image or device image | Mount or extract it, then `myelin scan <mount point>` |
| Firmware file | Put the file in a folder and `myelin scan <folder>` (install unblob, sasquatch or squashfs-tools to unpack root filesystems; the images ship squashfs-tools) |
| Windows drivers | Scan the folder that holds the `.sys` files |
| Supplier or device SBOM | **SBOM analysis** in the console |

## Reading the results

* OS package findings are grouped the way they are fixed: one finding per source package and fixed version, listing
  every CVE the update fixes (NM-OS-001). Vulnerabilities without a released fix for that distribution release are
  grouped per package (NM-OS-002) and become NM-OS-001 when the update ships.
* Native components, firmware and image application versions give one finding per component (NM-BIN-002,
  NM-IMG-001) with every matching CVE and the newest fixed version.
* Components that cannot be identified exactly are not guessed. For example, when a distribution strips a library's
  version string, the OS package database (if present) is what identifies it.

## Limits

* Windows hosts, macOS hosts and network appliances are not scanned directly; scan their software inventory as an SBOM.
* The built-in scanner reads RPM databases in SQLite format (RHEL 9 and later, Fedora, Amazon Linux 2023, recent
  SUSE). Older Berkeley DB databases (RHEL/CentOS 7, Amazon Linux 2) are reported as needing a Trivy scan.
* Encrypted or vendor-specific firmware formats cannot be unpacked; ask the vendor for an SBOM.
* Matching by CPE depends on NVD's product data; a component NVD has not analysed yet shows no CVEs until it is.
