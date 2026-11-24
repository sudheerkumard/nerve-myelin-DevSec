#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar. All rights reserved.
# Proprietary and confidential. Unauthorised copying or distribution is prohibited. See LICENSE.
"""Build customer release notes for one version from CHANGELOG.md + docs/releases/TEMPLATE.md.

  python scripts/release/notes.py 1.2.0 [--image ghcr.io/org/nerve-myelin] [--chart oci://ghcr.io/org/charts/myelin] > notes.md
"""
import argparse
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def section(version: str) -> tuple[str, str]:
    text = open(os.path.join(ROOT, "CHANGELOG.md")).read()
    m = re.search(rf"(?ms)^## \[{re.escape(version)}\] - (\d{{4}}-\d{{2}}-\d{{2}})\n(.*?)(?=^## \[|\Z)", text)
    if not m:
        sys.exit(f"CHANGELOG.md has no section for {version}")
    return m.group(1), m.group(2).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--image", default="<your registry>/nerve-myelin")
    ap.add_argument("--chart", default="oci://<your registry>/charts/myelin")
    ap.add_argument("--digest", default="(published with the release)")
    a = ap.parse_args()
    v = a.version.lstrip("v")
    date, body = section(v)
    body = re.sub(r"(?m)^### ", "## ", body)
    major, minor, _ = v.split("-")[0].split(".")
    kind = "major" if minor == "0" and _ == "0" and major != "0" else "feature" if _ == "0" else "maintenance"
    tpl = open(os.path.join(ROOT, "docs", "releases", "TEMPLATE.md")).read()
    out = (tpl.replace("{{VERSION}}", v).replace("{{DATE}}", date).replace("{{KIND}}", kind).replace("{{BODY}}", body)
              .replace("{{IMAGE}}", a.image).replace("{{CHART}}", a.chart).replace("{{DIGEST}}", a.digest)
              .replace("{{MINOR}}", f"{major}.{minor}"))
    sys.stdout.write(out)


if __name__ == "__main__":
    main()
