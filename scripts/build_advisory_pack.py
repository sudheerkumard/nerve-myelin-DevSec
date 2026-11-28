#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Build the bundled offline advisory pack from the GitHub Advisory Database (CC-BY-4.0) and, optionally, the
OpenSSF Malicious Packages repository (Apache-2.0: MAL- records of known malicious package releases).

The pack is an OSV export in the format MYELIN_OSV_EXPORT_DIR reads (one zip per ecosystem plus a checksummed
manifest), so offline and air-gapped scans match every component against every reviewed advisory, not a sample.
Records are trimmed to what matching and reporting use (id, aliases, summary, severity, affected ranges,
CWE, references to the advisory and the fix).

    git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database /tmp/ghsa
    git -C /tmp/ghsa sparse-checkout set advisories/github-reviewed
    git clone --depth 1 --filter=blob:none --sparse https://github.com/ossf/malicious-packages /tmp/malp
    git -C /tmp/malp sparse-checkout set osv/malicious
    git clone --depth 1 https://github.com/cisagov/kev-data /tmp/kev
    python scripts/build_advisory_pack.py /tmp/ghsa /opt/myelin/advisories /tmp/malp /tmp/kev/known_exploited_vulnerabilities.json
"""
import datetime
import hashlib
import json
import os
import sys
import zipfile

ECOS = {"npm", "PyPI", "Maven", "NuGet", "Go", "Packagist", "RubyGems", "crates.io", "Hex", "Pub"}
KEEP_REF = ("ADVISORY", "FIX", "PACKAGE", "WEB")


def slim(doc):
    refs = [r for r in doc.get("references") or [] if r.get("type") in KEEP_REF][:6]
    ds = doc.get("database_specific") or {}
    return {"id": doc["id"], "modified": doc.get("modified"), "published": doc.get("published"),
            "aliases": doc.get("aliases") or [], "summary": (doc.get("summary") or "")[:300],
            "details": (doc.get("details") or "")[:600], "severity": doc.get("severity") or [],
            "affected": [{k: a[k] for k in ("package", "ranges", "versions") if k in a} for a in doc.get("affected") or []],
            "references": refs, "database_specific": {k: ds[k] for k in ("cwe_ids", "severity") if k in ds}}


def slim_mal(doc):
    return {"id": doc["id"], "modified": doc.get("modified"), "aliases": [], "summary": (doc.get("summary") or
            "Malicious package")[:200], "affected": [{k: a[k] for k in ("package", "ranges", "versions") if k in a}
                                                      for a in doc.get("affected") or []],
            "database_specific": {"malicious": True}}


def main(src, dest, malicious=None, kev=None):
    os.makedirs(dest, exist_ok=True)
    by_eco = {}
    roots = [(os.path.join(src, "advisories", "github-reviewed"), slim)]
    if malicious:
        roots.append((os.path.join(malicious, "osv", "malicious"), slim_mal))
    for root, fn_slim in roots:
      for d, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            try:
                doc = json.load(open(os.path.join(d, fn), encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if doc.get("withdrawn") or not doc.get("id"):
                continue
            ecos = {(a.get("package") or {}).get("ecosystem") for a in doc.get("affected") or []} & ECOS
            for eco in ecos:
                by_eco.setdefault(eco, []).append(fn_slim(doc))
    entries = []
    for eco, docs in sorted(by_eco.items()):
        name = eco.replace("/", "_").replace(".", "_") + ".zip"
        path = os.path.join(dest, name)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for doc in docs:
                z.writestr(doc["id"] + ".json", json.dumps(doc, separators=(",", ":")))
        h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        entries.append({"file": name, "ecosystem": eco, "sha256": h, "size_bytes": os.path.getsize(path),
                        "records": len(docs)})
    kev_entry = None
    if kev:                                              # CISA KEV catalog (CC0): exploited-in-the-wild flags offline
        import gzip
        rows = json.load(open(kev, encoding="utf-8")).get("vulnerabilities") or []
        keep = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate", "requiredAction",
                "knownRansomwareCampaignUse", "notes")
        data = json.dumps({"vulnerabilities": [{k: r.get(k) for k in keep} for r in rows if r.get("cveID")]},
                          separators=(",", ":")).encode()
        kp = os.path.join(dest, "kev.json.gz")
        with gzip.GzipFile(kp, "wb", mtime=0) as fh:
            fh.write(data)
        kev_entry = {"file": "kev.json.gz", "sha256": hashlib.sha256(open(kp, "rb").read()).hexdigest(), "records": len(rows)}
    manifest = {"schema_version": 1, "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source": "GitHub Advisory Database, reviewed advisories (CC-BY-4.0), https://github.com/github/advisory-database"
                          + ("; OpenSSF Malicious Packages (Apache-2.0), https://github.com/ossf/malicious-packages" if malicious else ""),
                "archives": entries, **({"kev": kev_entry} if kev_entry else {})}
    if kev_entry:
        manifest["source"] += "; CISA Known Exploited Vulnerabilities catalog (CC0-1.0), https://github.com/cisagov/kev-data"
    json.dump(manifest, open(os.path.join(dest, "manifest.json"), "w"), indent=1)
    total = sum(e["records"] for e in entries)
    print(f"{total} advisory records in {len(entries)} ecosystems -> {dest} "
          f"({sum(e['size_bytes'] for e in entries) // (1024 * 1024)} MB)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else None,
         sys.argv[4] if len(sys.argv) > 4 else None)
