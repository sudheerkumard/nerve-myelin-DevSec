#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Generate the Python dependency section of THIRD-PARTY-NOTICES.md from the installed distributions.

    python scripts/third_party_notices.py > docs/legal/python-dependencies.md

Resolves the runtime requirements (backend/requirements.txt, requirements-cloud.txt and the CLI package) and all of
their transitive dependencies, and lists name, version, licence and project URL from each package's metadata.
Packages are used unmodified as separate libraries; their own licence files ship inside every image
(site-packages/*.dist-info).
"""
import os
import re
import sys
from importlib import metadata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQ_FILES = ["backend/requirements.txt", "backend/requirements-cloud.txt"]
EXTRA = ["pyyaml", "packaging", "bandit", "checkov"]           # CLI package and the CLI image


def _req_names(path):
    out = []
    for ln in open(os.path.join(ROOT, path), encoding="utf-8"):
        ln = ln.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)", ln)
        if m:
            out.append(m.group(1))
    return out


def _norm(n):
    return re.sub(r"[-_.]+", "-", n).lower()


def _licence(dist):
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return expr
    cls = [c.split(" :: ")[-1] for c in md.get_all("Classifier") or [] if c.startswith("License :: ")]
    lic = (md.get("License") or "").strip()
    if cls:
        return "; ".join(sorted(set(cls)))
    if lic and len(lic) < 80 and "\n" not in lic:
        return lic
    return "see package licence file"


def _url(dist):
    md = dist.metadata
    for v in md.get_all("Project-URL") or []:
        label, _, u = v.partition(",")
        if label.strip().lower() in ("source", "homepage", "repository", "source code", "code"):
            return u.strip()
    return (md.get("Home-page") or "").strip()


def main():
    roots = [n for f in REQ_FILES for n in _req_names(f)] + EXTRA
    seen, queue, rows = set(), list(roots), []
    while queue:
        n = _norm(queue.pop())
        if n in seen:
            continue
        seen.add(n)
        try:
            d = metadata.distribution(n)
        except metadata.PackageNotFoundError:
            rows.append((n, "not installed here", "", ""))
            continue
        rows.append((d.metadata["Name"], d.version, _licence(d), _url(d)))
        for r in d.requires or []:
            if "extra ==" in r:
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)", r)
            if m:
                queue.append(m.group(1))
    print("| Package | Version | Licence | Project |\n|---|---|---|---|")
    for name, ver, lic, url in sorted(rows, key=lambda r: r[0].lower()):
        print(f"| {name} | {ver} | {lic} | {url} |")


if __name__ == "__main__":
    sys.exit(main())
