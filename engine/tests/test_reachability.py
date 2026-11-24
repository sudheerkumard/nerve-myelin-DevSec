# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Regression tests for conservative cross-ecosystem dependency import evidence."""
from myelin_engine.orchestrator import _imported_packages


def test_python_and_javascript_imports_are_detected(tmp_path):
    (tmp_path / "app.py").write_text("from yaml import safe_load\nimport requests\n", encoding="utf-8")
    (tmp_path / "client.ts").write_text("import axios from 'axios';\n", encoding="utf-8")
    components = [
        {"name": "pyyaml", "ecosystem": "pypi"},
        {"name": "requests", "ecosystem": "pypi"},
        {"name": "axios", "ecosystem": "npm"},
        {"name": "left-pad", "ecosystem": "npm"},
    ]

    reachable, unknown = _imported_packages(str(tmp_path), components)

    assert reachable == {"pyyaml", "requests", "axios"}
    assert "left-pad" in unknown


def test_absent_ecosystem_is_unknown_not_unreachable(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    components = [
        {"name": "serde", "ecosystem": "cargo"},
        {"name": "requests", "ecosystem": "pypi"},
    ]

    reachable, unknown = _imported_packages(str(tmp_path), components)

    assert reachable == set()
    assert unknown == {"serde", "requests"}


def test_dependency_and_generated_directories_are_excluded(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "app.js").write_text("require('left-pad')", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("console.log('safe')", encoding="utf-8")
    components = [{"name": "left-pad", "ecosystem": "npm"}]

    reachable, unknown = _imported_packages(str(tmp_path), components)

    assert reachable == set()
    assert unknown == {"left-pad"}
