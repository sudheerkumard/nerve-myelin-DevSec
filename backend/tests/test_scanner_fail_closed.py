# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Scanner failure semantics: invalid or missing output must be a blocking gate input."""
import os
import sys
from types import SimpleNamespace

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


def test_valid_scanner_output_is_normalized_even_when_exit_code_is_nonzero(monkeypatch):
    monkeypatch.setitem(orchestrator.EXTERNAL, "fake", (lambda p: ["fake"], lambda d, r: [{"engine": "sast", "repo": r}]))
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout='{"results":[]}', stderr="", returncode=1))
    assert orchestrator._run_external("fake", ".", "repo") == [{"engine": "sast", "repo": "repo"}]
