#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Build the documentation site: diagrams, generated reference pages, then MkDocs (strict).

    pip install -r docs/requirements.txt
    python scripts/build_docs.py            # -> site/  (static, offline: open site/index.html or serve it)
    python scripts/build_docs.py --serve    # live preview on http://127.0.0.1:8000
"""
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run(*cmd):
    print("$", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


if __name__ == "__main__":
    run(sys.executable, "scripts/docs_diagrams.py")
    run(sys.executable, "scripts/build_docs_reference.py")
    run(sys.executable, "-m", "mkdocs", "serve" if "--serve" in sys.argv else "build", *([] if "--serve" in sys.argv else ["--strict"]))
