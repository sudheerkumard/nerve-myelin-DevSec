# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
import json
from concurrent.futures import ThreadPoolExecutor

from myelin_engine import cli, orchestrator, report_enterprise, vulndb


def _write(root, path, data):
    dest = root / path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(data, encoding="utf-8")


def test_monorepo_retains_pins_and_all_evidence_without_treating_ranges_as_versions(monkeypatch, tmp_path):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    _write(tmp_path, "a/package.json", '{"dependencies":{"library":"^1.0.0","other":"latest"}}')
    _write(tmp_path, "a/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"library": "^1.0.0"}},
        "node_modules/library": {"version": "1.1.0"}, "node_modules/nested": {"version": "2.0.0"},
    }}))
    _write(tmp_path, "b/package.json", '{"dependencies":{"library":"3.1.0"}}')
    _write(tmp_path, "c/package.json", '{"dependencies":{"library":"3.1.0"}}')
    _write(tmp_path, "b/requirements.txt", "second==1.2.3\nunknown==1.*\n")
    _write(tmp_path, "c/pyproject.toml", '[project]\ndependencies = ["independent==3.0"]\n')
    _write(tmp_path, "bad/Cargo.lock", "invalid = [TOML")
    _write(tmp_path, "bad/package-lock.json", '{"packages":{"node_modules/library":{"version":3}}}')
    res = orchestrator.scan(str(tmp_path), use_external=False)

    sbom = res["sbom"]
    by_purl = {c["purl"]: c for c in sbom["components"]}
    assert set(by_purl) == {"pkg:npm/library@1.1.0", "pkg:npm/library@3.1.0", "pkg:npm/nested@2.0.0",
                           "pkg:pypi/second@1.2.3", "pkg:pypi/independent@3.0"}
    manifest_paths = lambda purl: {p["value"] for p in by_purl[purl]["properties"] if p["name"] == "myelin:manifest"}
    assert manifest_paths("pkg:npm/library@1.1.0") == {"a/package.json", "a/package-lock.json"}
    assert manifest_paths("pkg:npm/library@3.1.0") == {"b/package.json", "c/package.json"}
    root = sbom["metadata"]["component"]["bom-ref"]
    dependencies = next(d["dependsOn"] for d in sbom["dependencies"] if d["ref"] == root)
    assert "pkg:npm/nested@2.0.0" not in dependencies
    assert sbom["compositions"][0]["aggregate"] == "incomplete"
    assert res["coverage"]["sca"]["status"] == "partial"
    assert any("bad/Cargo.lock" in issue for issue in res["coverage"]["sca"]["errors"])
    assert any("bad/package-lock.json" in issue for issue in res["coverage"]["sca"]["errors"])
    assert "sca" not in res["complete_engines"]


def test_trivy_reports_only_the_selected_and_available_modes(monkeypatch, tmp_path):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    monkeypatch.setattr(orchestrator, "TRIVY_CACHE", str(tmp_path / "missing-db"))
    monkeypatch.setattr(orchestrator.shutil, "which", lambda tool: "trivy" if tool == "trivy" else None)
    monkeypatch.setattr(orchestrator.coverage, "tool_version", lambda tool: "test")
    invoked = []
    monkeypatch.setattr(orchestrator, "_run_external", lambda tool, path, repo, argv_override: invoked.append(argv_override) or [])
    _write(tmp_path, "package.json", '{"dependencies":{"library":"1.2.3"}}')
    res = orchestrator.scan(str(tmp_path), engines=["sca", "secrets"])
    argv = invoked[0]
    assert argv[argv.index("--scanners") + 1] == "secret"
    assert all(t["name"] != "trivy" for t in res["coverage"]["sca"]["tools"])
    assert res["coverage"]["sca"]["status"] == "partial"
    assert res["coverage"]["iac"]["status"] == "not_selected"


def test_unknown_source_language_and_unresolved_dependency_are_visible_to_report_and_gate(monkeypatch, tmp_path):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    _write(tmp_path, "main.rs", "fn main() {}\n")
    _write(tmp_path, "package.json", '{"dependencies":{"library":"^1.0.0"}}')
    res = orchestrator.scan(str(tmp_path), use_external=False)
    assert not res["coverage"]["sast"]["assessed"] and not res["coverage"]["sca"]["assessed"]
    html = report_enterprise.render(res)
    assert "unsupported source languages: Rust" in html and "unresolved version for library in package.json" in html
    decision = cli._with_required_coverage(res, cli.policy.evaluate(res["findings"]), "sast,sca")
    assert decision["decision"] == "block" and decision["missing_engines"] == ["sast", "sca"]


def test_parallel_scans_keep_their_intelligence_evidence_separate(monkeypatch, tmp_path):
    from threading import Barrier

    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    for name in ("first", "second"):
        _write(tmp_path, f"{name}/requirements.txt", f"{name}==1.0.0\n")
    barrier = Barrier(2)

    def advisories(comps):
        name = comps[0]["name"]
        # Advisory fetches in real scans may run in a worker thread.
        with ThreadPoolExecutor(max_workers=1) as threads:
            list(vulndb.scan_map(threads, vulndb.current_status()["errors"].add, [name]))
        barrier.wait(timeout=5)
        return []

    monkeypatch.setattr(vulndb, "vulnerabilities", advisories)
    with ThreadPoolExecutor(max_workers=2) as threads:
        first, second = threads.map(lambda name: orchestrator.scan(str(tmp_path / name), use_external=False), ("first", "second"))
    assert first["intelligence"]["errors"] == ["first"]
    assert second["intelligence"]["errors"] == ["second"]
