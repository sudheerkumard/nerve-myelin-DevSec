#!/bin/sh
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
# Build the complete offline advisory pack into $1 (default /opt/myelin/advisories). Needs git, python3 and about
# 6 GB of temporary disk (the NVD mirror). Set PLATFORM=0 to build only the application-ecosystem part.
#
#   application packages  GitHub Advisory Database (reviewed), OpenSSF malicious packages, CISA KEV
#   operating systems     Debian, Ubuntu, Alpine, Wolfi, Chainguard, AlmaLinux, Rocky Linux (also used for RHEL,
#                         CentOS and Oracle Linux), Amazon Linux
#   everything by CPE     NVD: native libraries, firmware, kernels, databases, middleware, servers, devices
#   drivers               LOLDrivers known vulnerable and malicious Windows drivers
set -eu
DEST="${1:-/opt/myelin/advisories}"
WORK="${WORK:-$(mktemp -d)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
clone_sparse() { git clone -q --depth 1 --filter=blob:none --sparse "$1" "$2" && git -C "$2" sparse-checkout set $3; }
clone_sparse https://github.com/github/advisory-database "$WORK/ghsa" advisories/github-reviewed
clone_sparse https://github.com/ossf/malicious-packages "$WORK/malp" osv/malicious
git clone -q --depth 1 https://github.com/cisagov/kev-data "$WORK/kev"
python3 "$HERE/build_advisory_pack.py" "$WORK/ghsa" "$DEST" "$WORK/malp" "$WORK/kev/known_exploited_vulnerabilities.json"
rm -rf "$WORK/ghsa" "$WORK/malp" "$WORK/kev"
if [ "${PLATFORM:-1}" = "1" ]; then
  git clone -q --depth 1 https://github.com/aquasecurity/vuln-list-debian "$WORK/debian"
  clone_sparse https://github.com/canonical/ubuntu-security-notices "$WORK/usn" osv/cve
  clone_sparse https://github.com/aquasecurity/vuln-list "$WORK/vl" "alpine wolfi chainguard alma rocky amazon"
  python3 "$HERE/build_os_pack.py" "$DEST" --debian "$WORK/debian" --ubuntu "$WORK/usn" --vuln-list "$WORK/vl"
  rm -rf "$WORK/debian" "$WORK/usn" "$WORK/vl"
  git clone -q --depth 1 https://github.com/aquasecurity/vuln-list-nvd "$WORK/nvd"
  python3 "$HERE/build_cpe_pack.py" "$WORK/nvd" "$DEST"
  rm -rf "$WORK/nvd"
  git clone -q --depth 1 --filter=blob:none --sparse https://github.com/magicsword-io/LOLDrivers "$WORK/lold"
  git -C "$WORK/lold" sparse-checkout set loldrivers.io/content/api
  python3 "$HERE/build_driver_pack.py" "$WORK/lold/loldrivers.io/content/api/drivers.json" "$DEST"
  rm -rf "$WORK/lold"
fi
echo "offline advisory pack ready in $DEST"
