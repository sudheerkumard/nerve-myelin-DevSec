# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""The production image must not contain deliberately vulnerable demo applications."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_production_docker_context_excludes_demo_fixtures():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "COPY --chown=root:root demo demo" not in dockerfile
    assert "COPY --chown=root:root scripts/build_enterprise_console.py scripts/build_enterprise_console.py" in dockerfile
    assert "RUN python scripts/build_enterprise_console.py && rm -rf scripts" in dockerfile
    assert "COPY --chown=root:root demo/vulnerable-app" not in dockerfile
    assert "demo/*" in [line.strip() for line in ignore]
    assert "!demo/vulnerable-app/**" in [line.strip() for line in ignore]
    assert "config/backend/*.env*" in [line.strip() for line in ignore]
    assert "!config/backend/myelin.env.demo" not in ignore
    assert (ROOT / "demo" / "vulnerable-app" / "src" / "app.py").is_file()
