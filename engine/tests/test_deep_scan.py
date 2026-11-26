# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Deep scanning: rule pack, normalisation, de-duplication, coverage and coverage-driven reports."""
import os
import re
import shutil
import subprocess

import pytest

from myelin_engine import coverage, normalize, orchestrator
from myelin_engine import report_enterprise as R

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
RULES = os.path.join(ROOT, "engine", "myelin_engine", "rules", "sast")


@pytest.mark.skipif(not shutil.which("opengrep"), reason="opengrep not installed")
def test_rule_pack_passes_annotated_fixtures():
    cp = subprocess.run(["opengrep", "scan", "--test", "--taint-intrafile", "--config", RULES, os.path.join(HERE, "sast_rules")],
                        capture_output=True, text=True, timeout=600)
    assert "All tests passed" in cp.stdout + cp.stderr, cp.stdout[-2000:] + cp.stderr[-2000:]


def test_rule_pack_is_original_and_well_formed():
    yaml = pytest.importorskip("yaml")
    ids = []
    for fn in sorted(os.listdir(RULES)):
        text = open(os.path.join(RULES, fn), encoding="utf-8").read()
        assert "SPDX-License-Identifier: AGPL-3.0-only" in text and "not derived" in text
        assert "<<:" not in text, "merge keys are ignored by the engine: write metadata out in full"
        for r in yaml.safe_load(text)["rules"]:
            assert r["id"].startswith("nervve."), r["id"]
            assert re.match(r"CWE-\d+$", r["metadata"]["cwe"]), r["id"]
            assert r["severity"] in ("ERROR", "WARNING", "INFO") and len(r["message"]) > 40
            ids.append(r["id"])
    assert len(ids) == len(set(ids)) and len(ids) >= 70
    assert orchestrator.rule_count() == len(ids)


def test_semgrep_normaliser_strips_prefix_maps_aliases_and_escalates_proven_injection():
    doc = {"results": [{
        "check_id": "tmp.repo.engine.myelin_engine.rules.sast.nervve.python.command-injection", "path": "/src/app.py",
        "start": {"line": 9}, "extra": {
            "severity": "ERROR", "lines": "os.system('ping ' + host)",
            "message": "Operating-system command built from untrusted input. An attacker can run any command. Pass an argument list.",
            "metadata": {"cwe": "CWE-78", "confidence": "high"},
            "dataflow_trace": {"taint_source": ["CliLoc", [{"start": {"line": 7}}, "request.args"]],
                               "intermediate_vars": [{"content": "host"}]}}}]}
    f = normalize.semgrep(doc, "r")[0]
    assert f["rule_id"] == "nervve.python.command-injection" and f["rule_aliases"] == ["NM-SAST-003"]
    assert f["severity"] == "critical" and f["reachable"] and f["dataflow"]
    assert f["title"] == "Operating-system command built from untrusted input" and f["remediation"] == "Pass an argument list."
    assert "`request.args` (line 7) → host → sink at line 9" in f["evidence"]


def test_deep_result_replaces_pattern_match_on_the_same_line(tmp_path):
    builtin = {"engine": "sast", "rule_id": "NM-SAST-003", "file": "app.py", "line": 9, "cwe": "CWE-78", "title": "x"}
    deep = {"engine": "sast", "rule_id": "nervve.python.command-injection", "file": str(tmp_path / "app.py"), "line": 9,
            "cwe": "CWE-78", "source_tool": "opengrep", "title": "y"}
    other = {"engine": "sast", "rule_id": "NM-SAST-005", "file": "app.py", "line": 3, "cwe": "CWE-327", "title": "z"}
    out = orchestrator._merge_duplicates(str(tmp_path), [builtin, deep, other])
    assert [f["rule_id"] for f in out] == ["nervve.python.command-injection", "NM-SAST-005"]
    assert out[0]["rule_aliases"] == ["NM-SAST-003"] and out[0]["file"] == "app.py"


def test_dependency_duplicates_from_trivy_are_merged(tmp_path):
    osv = {"engine": "sca", "rule_id": "GHSA-aaaa", "cve": "CVE-2024-1", "package": "lodash", "version": "4.17.20", "file": "package.json"}
    trivy = {"engine": "sca", "rule_id": "CVE-2024-1", "cve": "CVE-2024-1", "package": "lodash", "version": "4.17.20",
             "file": "package-lock.json", "source_tool": "trivy"}
    extra = dict(trivy, rule_id="CVE-2024-9", cve="CVE-2024-9")
    out = orchestrator._merge_duplicates(str(tmp_path), [osv, trivy, extra])
    assert [f["rule_id"] for f in out] == ["GHSA-aaaa", "CVE-2024-9"]


def test_coverage_marks_only_applicable_domains(tmp_path):
    (tmp_path / "app.py").write_text("import os\nos.system('ls')\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs: {}\n")
    inv = coverage.inventory(str(tmp_path))
    assert inv["languages"] == {"Python": 1} and inv["pipelines"] == [".github/workflows/ci.yml"] and not inv["iac"]
    cov = coverage.build(inv, list(orchestrator.DEFAULT_ENGINES), ["myelin-builtin"], [], 0)
    assert coverage.assessed(cov) == ["sast", "secrets", "cicd"]
    assert cov["sca"]["reason"] == "no dependency manifests" and cov["iac"]["reason"] == "no infrastructure-as-code files"
    (tmp_path / "requirements.txt").write_text("flask\n")      # manifest without pinned versions
    cov = coverage.build(coverage.inventory(str(tmp_path)), list(orchestrator.DEFAULT_ENGINES), ["myelin-builtin"], [], 0)
    assert not cov["sca"]["assessed"] and "lock file" in cov["sca"]["reason"]


def test_scan_records_coverage_and_report_lists_only_assessed_areas(tmp_path):
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    res = orchestrator.scan(str(tmp_path), repo="small", use_external=False)
    assert res["engines"] == ["sast", "secrets"] and res["coverage"]["sast"]["assessed"]
    html = R.render(res, issuer="Org", source_url="https://example.com/small")
    assert re.findall(r'<h3 id="d-(\w+)">', html) == ["sast", "secrets"]
    for absent in ("Open-source dependencies (SCA)", "Infrastructure as Code", "Vulnerability register", "Software bill of materials",
                   "Not assessed", "Not in scope"):
        assert absent not in html, absent
    assert re.findall(r'<span class="no">(\w+)</span>Methodology', html) == ["9"]
    assert "Areas examined: Source code analysis (SAST), Secrets exposure." in html


def test_failed_tool_is_reported_not_hidden():
    inv = {"files": 3, "languages": {"Python": 3}, "manifests": [], "iac": [], "pipelines": [], "ai": []}
    err = {"engine": "meta", "rule_id": "tool-error:opengrep", "title": "opengrep failed: timeout"}
    cov = coverage.build(inv, ["sast", "secrets"], ["myelin-builtin", "opengrep"], [err], 0)
    tool = next(t for t in cov["sast"]["tools"] if t["name"] == "opengrep")
    assert tool["error"] == "opengrep failed: timeout"
    html = R.render({"findings": [err], "coverage": cov, "repo": "r", "tools": ["myelin-builtin", "opengrep"]})
    assert "Tool errors" in html and "opengrep" in html
