"""Precision-oriented regression tests: known vulnerable vs fixed dependencies and safe vs unsafe code."""
from myelin_engine import builtin_rules, sbom


def test_sca_flags_vulnerable_lodash_but_not_fixed_version(monkeypatch):
    monkeypatch.setattr("myelin_engine.vulndb.vulnerabilities", lambda components: [])
    vulnerable = {
        "ecosystem": "npm", "name": "lodash", "version": "4.17.20",
        "file": "package-lock.json", "scope": "required",
        "purl": "pkg:npm/lodash@4.17.20", "license": "MIT",
    }
    fixed = {**vulnerable, "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
    findings = sbom.match_advisories([vulnerable, fixed], repo="fixture")
    lodash = [f for f in findings if f.get("package") == "lodash"]
    assert len(lodash) == 1
    assert lodash[0]["version"] == "4.17.20"
    assert lodash[0]["rule_id"] == "CVE-2021-23337"
    assert lodash[0]["fixed_version"] == "4.17.21"
    assert lodash[0]["file"] == "package-lock.json"


def test_sca_does_not_flag_unrelated_or_fixed_dependencies(monkeypatch):
    monkeypatch.setattr("myelin_engine.vulndb.vulnerabilities", lambda components: [])
    components = [
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.21",
         "file": "package-lock.json", "scope": "required", "purl": "pkg:npm/lodash@4.17.21"},
        {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0",
         "file": "package-lock.json", "scope": "transitive", "purl": "pkg:npm/left-pad@1.3.0"},
    ]
    assert sbom.match_advisories(components, repo="fixture") == []


def test_sast_flags_dynamic_sql_but_not_parameterized_query(tmp_path):
    unsafe = tmp_path / "unsafe.py"
    unsafe.write_text('cursor.execute("SELECT * FROM users WHERE id = " + user_id)\\n', encoding="utf-8")
    safe = tmp_path / "safe.py"
    safe.write_text('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\\n', encoding="utf-8")

    findings = builtin_rules.scan_path(str(tmp_path), repo="fixture")
    sql_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
    assert any(f["file"] == "unsafe.py" for f in sql_findings)
    assert not any(f["file"] == "safe.py" for f in sql_findings)
