#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar. All rights reserved.
# Proprietary and confidential. Unauthorised copying or distribution is prohibited. See LICENSE.
"""Single place to read, bump and verify the product version.

  python scripts/release/version.py show
  python scripts/release/version.py bump 1.3.0          # updates every file below
  python scripts/release/version.py check v1.3.0        # release gate: tag, files and CHANGELOG agree
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SEMVER = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?"
FILES = {   # path -> regex with one group around the version
    "engine/myelin_engine/__init__.py": rf'__version__ = "({SEMVER})"',
    "pyproject.toml": rf'(?m)^version = "({SEMVER})"',
    "deploy/helm/myelin/Chart.yaml": rf"(?m)^version: ({SEMVER})",
    "deploy/helm/myelin/Chart.yaml#app": rf'(?m)^appVersion: "({SEMVER})"',
    "deploy/helm/myelin/values.yaml": rf'(?m)^  tag: "({SEMVER})"',
    "config/deploy/values-customer.example.yaml": rf'(?m)^  tag: "({SEMVER})"',
    "docker-compose.yml": rf"ghcr.io/sudheerkumard/nerve-myelin-demo:({SEMVER})",
    "docker-compose.enterprise.yml": rf"ghcr.io/sudheerkumard/nerve-myelin:({SEMVER})",
    "Dockerfile": rf"ghcr.io/sudheerkumard/nerve-myelin:({SEMVER})",
    "ci-templates/github-actions.yml": rf"ghcr.io/sudheerkumard/myelin-cli:({SEMVER})",
    "ci-templates/azure-pipelines.yml": rf"nervve-devsecops@v({SEMVER})",
}


def _path(key):
    return os.path.join(ROOT, key.split("#")[0])


def current():
    found = {}
    for key, rx in FILES.items():
        found[key] = sorted(set(re.findall(rx, open(_path(key)).read())))
    return found


def show():
    for k, v in current().items():
        print(f"{', '.join(v) or 'MISSING':12} {k}")


def bump(new):
    if not re.fullmatch(SEMVER, new):
        sys.exit(f"not a semantic version: {new}")
    for key, rx in FILES.items():
        p = _path(key)
        s = open(p).read()
        s2, n = re.subn(rx, lambda m: m.group(0).replace(m.group(1), new), s)
        if n == 0:
            sys.exit(f"version pattern not found in {key}")
        open(p, "w").write(s2)
    print(f"bumped to {new}; now add a '## [{new}] - YYYY-MM-DD' section to CHANGELOG.md")


def check(tag):
    v = tag[1:] if tag.startswith("v") else tag
    errors = [f"{k}: {got or 'missing'} != {v}" for k, got in current().items() if got != [v]]
    if not re.search(rf"(?m)^## \[{re.escape(v)}\] - \d{{4}}-\d{{2}}-\d{{2}}", open(os.path.join(ROOT, "CHANGELOG.md")).read()):
        errors.append(f"CHANGELOG.md has no dated '## [{v}]' section")
    if errors:
        print("version check failed:\n  " + "\n  ".join(errors), file=sys.stderr)
        sys.exit(1)
    print(f"version {v} consistent across {len(FILES)} files and CHANGELOG")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "show"
    {"show": lambda: show(), "bump": lambda: bump(sys.argv[2]), "check": lambda: check(sys.argv[2])}[cmd]()
