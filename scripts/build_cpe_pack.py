#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Build the CPE section of the offline advisory pack from NVD CVE records (U.S. Government work, public domain).

For every CVE: CVSS score and severity, CWE, a short summary, and every vulnerable CPE match (vendor:product with the
exact version or the version range). This is what matches components that have no package-manager identity: native
libraries and binaries (OpenSSL, zlib, curl, BusyBox), firmware (Linux kernel, U-Boot, Dropbear), operating systems,
databases, middleware and servers (PostgreSQL, Redis, nginx, Tomcat, Kafka), and SBOM components that carry a CPE.

    git clone --depth 1 https://github.com/aquasecurity/vuln-list-nvd /tmp/nvd      # NVD API 2.0 records
    python scripts/build_cpe_pack.py /tmp/nvd /opt/myelin/advisories

Writes cpe.pack (a zip: one entry per product, CVE metadata in shards) into the pack directory and records it in manifest.json (run after build_advisory_pack.py).
"""
import hashlib
import json
import os
import sys

FIELDS = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")


def _score(m):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = (m or {}).get(key) or []
        row = next((r for r in rows if r.get("type") == "Primary"), rows[0] if rows else None)
        if row:
            d = row.get("cvssData") or {}
            sev = d.get("baseSeverity") or row.get("baseSeverity")
            return d.get("baseScore"), (sev or "").lower() or None
    return None, None


def _shard(cve: str) -> str:
    return hashlib.sha1(cve.encode()).hexdigest()[:3]


def main(src, dest):
    meta, products = {}, {}
    n = 0
    for d, _, files in os.walk(os.path.join(src, "api")):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            try:
                doc = json.load(open(os.path.join(d, fn), encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if doc.get("vulnStatus") == "Rejected":
                continue
            cve = doc.get("id")
            n += 1
            score, sev = _score(doc.get("metrics"))
            cwe = next((x["value"] for w in doc.get("weaknesses") or [] for x in w.get("description") or []
                        if str(x.get("value", "")).startswith("CWE-")), None)
            summary = next((x["value"] for x in doc.get("descriptions") or [] if x.get("lang") == "en"), "")
            meta[cve] = [score, sev, cwe, summary[:160]]
            for conf in doc.get("configurations") or []:
                for node in conf.get("nodes") or []:
                    if node.get("negate"):
                        continue
                    for m in node.get("cpeMatch") or []:
                        if not m.get("vulnerable"):
                            continue
                        parts = (m.get("criteria") or "").split(":")
                        if len(parts) < 6:
                            continue
                        part, vendor, product, version, update = parts[2], parts[3], parts[4], parts[5], parts[6]
                        exact = None if version in ("*", "-") else version + ("" if update in ("*", "-") else update)
                        rng = [m.get(f) for f in FIELDS]
                        if exact is None and not any(rng):
                            if version == "-":
                                continue                        # "no version" entries cannot be matched to an install
                            rng = [None, None, None, None]      # every version
                        products.setdefault(f"{part}:{vendor}:{product}", []).append([cve, exact] + rng)
    for v in products.values():
        v.sort(key=lambda r: r[0])
    # One zip member per product and CVE metadata in 1000 shards, read on demand (memory stays small).
    import zipfile
    os.makedirs(dest, exist_ok=True)
    path = os.path.join(dest, "cpe.pack")
    shards = {}
    for cve, row in meta.items():
        shards.setdefault(_shard(cve), {})[cve] = row
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for prod, rows in sorted(products.items()):
            z.writestr("p/" + prod.replace("/", "%2F") + ".json", json.dumps(rows, separators=(",", ":")))
        for sh, rows in sorted(shards.items()):
            z.writestr(f"m/{sh}.json", json.dumps(rows, separators=(",", ":")))
    sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
    mpath = os.path.join(dest, "manifest.json")
    manifest = json.load(open(mpath)) if os.path.isfile(mpath) else {"schema_version": 1, "archives": []}
    manifest["cpe"] = {"file": "cpe.pack", "sha256": sha, "records": n, "products": len(products)}
    src_note = "NVD CVE and CPE data (public domain, U.S. Government), https://nvd.nist.gov"
    if src_note not in manifest.get("source", ""):
        manifest["source"] = (manifest.get("source", "") + "; " + src_note).lstrip("; ")
    json.dump(manifest, open(mpath, "w"), indent=1)
    print(f"{n} CVEs, {len(products)} products -> {path} ({os.path.getsize(path) // (1024 * 1024)} MB)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
