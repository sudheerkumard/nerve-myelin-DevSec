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


def test_malformed_sast_report_cannot_look_clean(monkeypatch):
    monkeypatch.setitem(orchestrator.EXTERNAL, "opengrep", (lambda p: ["opengrep"], lambda d, r: []))
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout='{}', stderr="", returncode=0))
    findings = orchestrator._run_external("opengrep", ".", "repo")
    assert policy.evaluate(findings)["decision"] == "block"


def test_sast_report_keeps_findings_and_errors(monkeypatch, tmp_path):
    from myelin_engine import suppress

    monkeypatch.setitem(orchestrator.EXTERNAL, "opengrep", (lambda p: ["opengrep"], lambda d, r: [{"engine": "sast"}]))
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **k: SimpleNamespace(
        stdout='{"results":[{}],"errors":[{"type":"Timeout"}],"paths":{"scanned":["app.py"]}}', stderr="", returncode=0))
    run_info = {}
    findings = orchestrator._run_external("opengrep", ".", "repo", run_info=run_info)
    assert run_info["scanned_files"] == 1
    assert findings[0]["engine"] == "sast" and findings[1]["scanner_status"] == "required_error"
    (tmp_path / ".myelinignore").write_text("*\n")
    kept, _ = suppress.apply(str(tmp_path), findings)
    assert kept == findings[1:]
    assert policy.evaluate(kept)["decision"] == "block"
