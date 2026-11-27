# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Precision pass, secret consolidation, mitigation guidance and dependency resolution helpers."""
import os

from myelin_engine import mitigation, normalize, precision, resolve, secrets


def _trace(*pairs):
    return {"intermediate_vars": [{"location": {"start": {"line": ln}}, "content": var} for ln, var in pairs]}


def test_constant_ternary_and_if_are_pruned():
    src = ['int num = 106;', 'bar = (7 * 18) + num > 200 ? "always" : param;'] 
    assert precision.infeasible(src, _trace((2, "bar")))
    live = ['int num = 196;', 'if ((500 / 42) + num > 200) bar = param;', 'else bar = "never";']
    assert not precision.infeasible(live, _trace((2, "bar")))
    dead = ['int num = 86;', 'if ((7 * 42) - num > 200) bar = "always";', 'else bar = param;']
    assert precision.infeasible(dead, _trace((3, "bar")))
    unknown = ['bar = flag ? "x" : param;']
    assert not precision.infeasible(unknown, _trace((1, "bar")))


def test_switch_on_constant_is_pruned_only_when_safe_case_runs():
    src = ['String guess = "ABC";', "char switchTarget = guess.charAt(1);", "switch (switchTarget) {", "  case 'A':",
           "    bar = param;", "    break;", "  case 'B':", '    bar = "bob";', "    break;", "  default:",
           "    bar = param;", "    break;", "}"]
    assert precision.infeasible(src, _trace((5, "bar")))
    src[1] = "char switchTarget = guess.charAt(0);"
    assert not precision.infeasible(src, _trace((5, "bar")))


def test_collection_contents_are_tracked():
    lst = ["java.util.List<String> values = new java.util.ArrayList<String>();", 'values.add("safe");', "values.add(param);",
           'values.add("moresafe");', "values.remove(0);", "bar = values.get(1);"]
    assert precision.infeasible(lst, _trace((6, "bar")))
    lst[5] = "bar = values.get(0);"
    assert not precision.infeasible(lst, _trace((6, "bar")))
    mp = ["java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();", 'map.put("keyA", "a-Value");',
          'map.put("keyB", param);', 'bar = (String) map.get("keyA");']
    assert precision.infeasible(mp, _trace((4, "bar")))
    mp[3] = 'bar = (String) map.get("keyB");'
    assert not precision.infeasible(mp, _trace((4, "bar")))
    mp.insert(3, "map.putAll(other);")                      # an operation the pass does not model: keep the finding
    assert not precision.infeasible(mp, _trace((5, "bar")))


def test_configured_algorithm_is_resolved_from_properties(tmp_path):
    (tmp_path / "app.properties").write_text("hashAlg1=MD5\nhashAlg2=SHA-256\ncipher=AES/GCM/NoPadding\n")
    def res(kind, key, default):
        return {"path": "A.java", "extra": {"metadata": {"nervve-config-check": kind}, "lines": "x",
                                             "metavars": {"$KEY": {"abstract_content": key}, "$DEF": {"abstract_content": default}}}}
    doc = {"results": [res("hash", "hashAlg1", "SHA512"), res("hash", "hashAlg2", "MD5"), res("cipher", "cipher", "DES"),
                       res("cipher", "missing", "DES/CBC/PKCS5Padding")]}
    kept = precision.refine(doc, str(tmp_path))["results"]
    assert len(kept) == 2 and "hashAlg1 = MD5" in kept[0]["extra"]["lines"] and "missing = DES" in kept[1]["extra"]["lines"]


def test_gitleaks_results_are_grouped_per_secret(tmp_path):
    key = "AKIAIOSFODNN7EXAMPLQ"
    (tmp_path / "config.py").write_text(f'AWS = "{key}"\n')
    raw = [{"RuleID": "aws-access-token", "Description": "AWS key", "Secret": key, "File": "config.py", "StartLine": 1,
            "Commit": f"{i}" * 40, "Date": f"2026-01-0{i}", "Entropy": 4.0} for i in range(1, 6)]
    raw.append({"RuleID": "generic-api-key", "Description": "Generic", "Secret": "your_api_key_here", "File": "a.py",
                "StartLine": 3, "Commit": "a" * 40, "Entropy": 3.9})
    raw.append({"RuleID": "generic-api-key", "Description": "Generic", "Secret": "q8Zr3Lw9Xk2Vb7Tn", "File": "old/settings.py",
                "StartLine": 9, "Commit": "b" * 40, "Entropy": 4.0})
    raw.append({"RuleID": "github-pat", "Description": "GitHub PAT", "Secret": "ghp_" + "a1B2" * 9, "File": "tests/test_x.py",
                "StartLine": 2, "Commit": "c" * 40, "Entropy": 4.2})
    grouped = secrets.consolidate_gitleaks(raw, str(tmp_path))
    fs = {f["rule_id"]: f for f in normalize.gitleaks(grouped, "r")}
    assert set(fs) == {"aws-access-token", "generic-api-key", "github-pat"}          # placeholder dropped
    aws = fs["aws-access-token"]
    assert aws["occurrences"] == 5 and aws["commits"] == 5 and aws["severity"] == "critical" and aws["line"] == 1
    assert key not in str(aws)                                                          # the value is never kept
    assert "git history" in fs["generic-api-key"]["title"] and fs["generic-api-key"]["severity"] == "high"
    assert fs["github-pat"]["severity"] == "low" and fs["github-pat"]["context"] == "test"


def test_builtin_secret_in_several_files_is_one_finding(tmp_path):
    key = "AIza" + "Sy" + "B1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R"
    for name in ("a.js", "b.js", "web/c.js"):
        p = tmp_path / name
        os.makedirs(p.parent, exist_ok=True)
        p.write_text(f'const k = "{key}";\n')
    fs = [f for f in secrets.scan_path(str(tmp_path), "r") if f["rule_id"] == "NM-SEC-007"]
    assert len(fs) == 1 and fs[0]["occurrences"] == 3 and len(fs[0]["locations"]) == 3 and "_value" not in fs[0]


def test_every_finding_gets_mitigation_steps():
    cases = [{"engine": "sast", "cwe": "CWE-89", "rule_id": "nervve.java.sql-injection"},
             {"engine": "secrets", "rule_id": "NM-SEC-007", "title": "Google API key committed to source", "occurrences": 3},
             {"engine": "secrets", "rule_id": "NM-SEC-011", "title": "Default or demo password documented in source"},
             {"engine": "sca", "package": "lodash", "version": "4.17.11", "fixed_version": "4.17.21"},
             {"engine": "iac", "rule_id": "CKV_AZURE_1"}, {"engine": "cicd"}, {"engine": "license"}, {"engine": "sast"},
             {"engine": "dast", "cwe": "CWE-614"}, {"engine": "somethingnew"}]
    for f in cases:
        g = mitigation.guidance(f)
        assert g["steps"] and g["verify"] and g["reference"].startswith("https://") and g["summary"], f
    g = mitigation.guidance(cases[1])
    assert "3 places" in g["steps"][0] and any("Restrict the new key" in s for s in g["steps"])
    assert "4.17.21" in mitigation.guidance(cases[3])["steps"][0]
    assert mitigation.as_text(cases[0]).startswith("1. ")


def test_cyclonedx_components_keep_direct_and_transitive():
    doc = {"metadata": {"component": {"bom-ref": "root"}},
           "components": [{"bom-ref": "a", "purl": "pkg:maven/org.x/a@1.0", "name": "a", "version": "1.0",
                           "licenses": [{"license": {"id": "MIT"}}]},
                          {"bom-ref": "b", "purl": "pkg:maven/org.y/b@2.0", "name": "b", "version": "2.0"}],
           "dependencies": [{"ref": "root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]}]}
    comps = {c["name"]: c for c in resolve._cdx_components(doc)}
    assert len(comps) == 2
    names = sorted(comps)
    assert any("a" in n for n in names) and any("b" in n for n in names)


def test_nuget_lowest_applicable_version():
    avail = ["1.0.0", "1.2.0", "2.0.0", "2.1.0-beta", "3.0.0"]
    assert resolve._nuget_lowest("[1.1.0, )", avail) == "1.2.0"
    assert resolve._nuget_lowest("2.0.0", avail) == "2.0.0"
    assert resolve._nuget_lowest("[1.0.0]", avail) == "1.0.0"


def test_test_paths_and_public_emulator_keys(tmp_path):
    from myelin_engine.secrets import TEST_PATH
    for p in ("src/Shared/TestCertificates/leaf.key", "src/Foo.UnitTests/a.cs", "samples/x/appsettings.json", "tests/a.py"):
        assert TEST_PATH.search(p), p
    for p in ("src/latest/a.py", "app/Testimonials/a.js", "src/Attestation/a.cs", "src/Api/Startup.cs"):
        assert not TEST_PATH.search(p), p
    (tmp_path / "Helper.cs").write_text('var c = "DefaultEndpointsProtocol=https;AccountName=devstoreaccount1;AccountKey='
                                        'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";\n')
    assert not [f for f in secrets.scan_path(str(tmp_path), "r") if f["rule_id"] == "NM-SEC-006"]


def test_licence_reasons_are_specific():
    from myelin_engine.license_policy import evaluate_components
    rows = evaluate_components([{"name": "a", "version": "1", "license": "MIT"}, {"name": "b", "version": "2", "license": "unknown"},
                                {"name": "c", "version": "3", "license": "AGPL-3.0-only"},
                                {"name": "d", "version": "4", "license": "MIT OR GPL-2.0-only"}])
    assert "a 1 is licensed under MIT, a permissive licence" in rows[0]["reason"]
    assert "declares no licence" in rows[1]["reason"] and rows[1]["decision"] == "review"
    assert rows[2]["category"] == "network_copyleft" and "network" in rows[2]["obligations"]
    assert "choice of licences" in rows[3]["reason"] and "Record which licence" in rows[3]["action"]
    assert all(r["obligations"] and r["action"] for r in rows)


def test_maven_licence_follows_parent_pom(monkeypatch):
    from myelin_engine import vulndb
    poms = {"maven-compiler-plugin-3.13.0.pom": "<project><parent><groupId>org.apache.maven.plugins</groupId><artifactId>maven-plugins"
            "</artifactId><version>41</version></parent></project>",
            "maven-plugins-41.pom": "<project><parent><groupId>org.apache.maven</groupId><artifactId>maven-parent</artifactId>"
            "<version>41</version></parent></project>",
            "maven-parent-41.pom": "<project><licenses><license><name>Apache-2.0</name></license></licenses></project>"}
    monkeypatch.setattr(vulndb, "_http_text", lambda url, ttl=0: poms.get(url.rsplit("/", 1)[-1], ""))
    lic = vulndb.licence({"ecosystem": "maven", "name": "org.apache.maven.plugins:maven-compiler-plugin", "version": "3.13.0"})
    assert lic == "Apache-2.0"
