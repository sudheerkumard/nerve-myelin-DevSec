#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Add the LOLDrivers list of known vulnerable and malicious Windows drivers (Apache-2.0) to the advisory pack.

Only the catalogue (drivers.json) is read; the repository's sample driver binaries are never opened.

    git clone --depth 1 https://github.com/magicsword-io/LOLDrivers /tmp/lold
    python scripts/build_driver_pack.py /tmp/lold/loldrivers.io/content/api/drivers.json /opt/myelin/advisories
"""
import gzip
import hashlib
import json
import os
import sys


def main(src, dest):
    out = {}
    for d in json.load(open(src, encoding="utf-8")):
        name = next(iter(d.get("Tags") or []), "")
        for s in d.get("KnownVulnerableSamples") or []:
            for h in filter(None, [s.get("SHA256"), (s.get("Authentihash") or {}).get("SHA256")]):
                out[h.lower()] = [d.get("Id"), (d.get("Category") or "").lower(), s.get("OriginalFilename") or s.get("Filename") or name]
    path = os.path.join(dest, "drivers.json.gz")
    with gzip.GzipFile(path, "wb", mtime=0) as fh:
        fh.write(json.dumps(out, separators=(",", ":")).encode())
    mpath = os.path.join(dest, "manifest.json")
    manifest = json.load(open(mpath)) if os.path.isfile(mpath) else {"schema_version": 1, "archives": []}
    manifest["drivers"] = {"file": "drivers.json.gz", "records": len(out),
                           "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest()}
    note = "LOLDrivers (Apache-2.0), https://github.com/magicsword-io/LOLDrivers"
    if note not in manifest.get("source", ""):
        manifest["source"] = (manifest.get("source", "") + "; " + note).lstrip("; ")
    json.dump(manifest, open(mpath, "w"), indent=1)
    print(f"{len(out)} driver hashes -> {path}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
