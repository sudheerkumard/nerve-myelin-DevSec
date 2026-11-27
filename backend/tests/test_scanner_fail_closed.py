# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Scanner failure semantics: invalid or missing output must be a blocking gate input."""
import json
import os
import sys
from types import SimpleNamespace

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import orchestrator, policy


def test_external_scanner_empty_output_is_required_error(monkeypatch):
    monkeypatch.setitem(orchestrator.EXTERNAL, "fake", (lambda p: ["fake"], lambda d, r: []))
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="", stderr="crash", returncode=2))
    findings = orchestrator._run_external("fake", ".", "repo")
    assert findings[0]["scanner_status"] == "required_error"
    assert findings[0]["required"] is True
    assert policy.evaluate(findings)["decision"] == "block"


def test_external_scanner_json_null_is_required_error(monkeypatch):
    monkeypatch.setitem(orchestrator.EXTERNAL, "fake", (lambda p: ["fake"], lambda d, r: []))
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="null", stderr="", returncode=0))
    findings = orchestrator._run_external("fake", ".", "repo")
    assert findings[0]["scanner_status"] == "required_error"
    assert policy.evaluate(findings)["decision"] == "block"


def _mock_report(monkeypatch, document, exit_code=0, stderr=""):
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **k: SimpleNamespace(
        stdout=json.dumps(document), stderr=stderr, returncode=exit_code))


@pytest.mark.parametrize("tool,document,exit_code", [
    ("grype", {}, 0), ("grype", {"matches": []}, 2), ("trivy", {"SchemaVersion": 2}, 1),
    ("trivy", {"Results": []}, 0), ("checkov", {"results": {"failed_checks": []}}, 0),
    ("bandit", {"errors": [], "results": []}, 1), ("bandit", {"errors": [], "results": "bad"}, 0),
])
def test_wrong_schema_or_failure_exit_blocks(monkeypatch, tool, document, exit_code):
    _mock_report(monkeypatch, document, exit_code, stderr="sensitive-scanner-output")
    findings = orchestrator._run_external(tool, ".", "repo")
    assert policy.evaluate(findings)["decision"] == "block"
    assert "sensitive-scanner-output" not in str(findings)


def test_bandit_findings_exit_is_normalized_and_partial_errors_still_block(monkeypatch):
    document = {"results": [{"filename": "app.py", "test_id": "B324", "issue_severity": "HIGH",
                            "issue_confidence": "HIGH"}], "errors": []}
    _mock_report(monkeypatch, document, 1)
    findings = orchestrator._run_external("bandit", ".", "repo")
    assert [f["rule_id"] for f in findings] == ["BANDIT-B324"]
    document["errors"].append({"filename": "unreadable.py"})
    findings = orchestrator._run_external("bandit", ".", "repo")
    assert [f["rule_id"] for f in findings] == ["BANDIT-B324", "tool-error:bandit"]
    assert policy.evaluate(findings)["decision"] == "block"


def test_trivy_empty_report_is_valid_but_image_scanner_exit_is_not(monkeypatch):
    _mock_report(monkeypatch, {"SchemaVersion": 2})
    assert orchestrator._run_external("trivy", ".", "repo") == []
    _mock_report(monkeypatch, {"SchemaVersion": 2}, 2)
    monkeypatch.setattr(orchestrator.shutil, "which", lambda tool: "/test/trivy" if tool == "trivy" else None)
    res = orchestrator.scan_image("image:local")
    assert policy.evaluate(res["findings"])["decision"] == "block"
