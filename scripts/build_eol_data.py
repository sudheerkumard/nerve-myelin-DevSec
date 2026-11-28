#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Build the bundled end-of-life snapshot (engine/myelin_engine/data/eol.json.gz) from the endoflife.date project
(MIT licence, https://github.com/endoflife-date/endoflife.date). Usage:

    git clone --depth 1 https://github.com/endoflife-date/endoflife.date /tmp/eold
    python scripts/build_eol_data.py /tmp/eold
"""
import datetime
import gzip
import json
import os
import sys

import yaml

KEEP_TYPES = ("docker", "oci", "npm", "pypi", "maven", "nuget", "composer", "golang", "gem", "generic", "cargo", "hex")
KEEP_CATEGORIES = ("lang", "framework", "server-app", "db", "os")


def _d(v):
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()[:10]
    return v


def main(src):
    out = {}
    for fn in sorted(os.listdir(os.path.join(src, "products"))):
        if not fn.endswith(".md"):
            continue
        text = open(os.path.join(src, "products", fn), encoding="utf-8").read()
        if not text.startswith("---"):
            continue
        meta = yaml.safe_load(text.split("---", 2)[1]) or {}
        purls = [i["purl"] for i in meta.get("identifiers") or [] if isinstance(i, dict) and "purl" in i
                 and i["purl"].split(":", 1)[1].split("/", 1)[0] in KEEP_TYPES]
        # every product is kept: services (managed databases, Kubernetes, Lambda runtimes), devices and firmware
        # have no package URL but are matched by the infrastructure and binary scanners
        rel = []
        for r in meta.get("releases") or []:
            rel.append({k: _d(r[k]) for k in ("releaseCycle", "releaseDate", "eol", "eoas", "eoes", "lts", "latest")
                        if k in r and r[k] is not None})
        if rel:
            out[fn[:-3]] = {"title": meta.get("title") or fn[:-3], "category": meta.get("category"), "purls": purls,
                            "releases": rel}
    doc = {"source": "https://endoflife.date (MIT licence)", "generated": datetime.date.today().isoformat(),
           "products": out}
    dest = os.path.join(os.path.dirname(__file__), "..", "engine", "myelin_engine", "data", "eol.json.gz")
    with gzip.open(dest, "wt", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"), sort_keys=True)
    print(f"{len(out)} products -> {os.path.normpath(dest)} ({os.path.getsize(dest) // 1024} KB)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/eold")
