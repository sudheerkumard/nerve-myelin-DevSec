import json

from myelin_engine import vulndb


def _write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_parses_pnpm_v9_scoped_and_unscoped_packages(tmp_path):
    _write(tmp_path, "pnpm-lock.yaml", """lockfileVersion: '9.0'
packages:
  lodash@4.17.20:
    resolution: {integrity: sha512-test}
  '@scope/pkg@2.3.4(peer@1.0.0)':
    resolution: {integrity: sha512-test}
""")
    items = vulndb.parse_lockfiles(str(tmp_path))
    found = {(x["ecosystem"], x["name"], x["version"]) for x in items}
    assert ("npm", "lodash", "4.17.20") in found
    assert ("npm", "@scope/pkg", "2.3.4") in found


def test_parses_legacy_pnpm_lock_keys(tmp_path):
    _write(tmp_path, "pnpm-lock.yaml", """lockfileVersion: '5.4'
packages:
  /lodash/4.17.20:
    resolution: {integrity: sha512-test}
  /@scope/pkg/2.3.4:
    resolution: {integrity: sha512-test}
""")
    items = vulndb.parse_lockfiles(str(tmp_path))
    found = {(x["name"], x["version"]) for x in items}
    assert ("lodash", "4.17.20") in found
    assert ("@scope/pkg", "2.3.4") in found


def test_parses_cargo_registry_packages_only(tmp_path):
    _write(tmp_path, "Cargo.lock", """version = 3
[[package]]
name = "serde"
version = "1.0.203"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-app"
version = "0.1.0"
""")
    items = vulndb.parse_lockfiles(str(tmp_path))
    assert [(x["ecosystem"], x["name"], x["version"]) for x in items] == [("cargo", "serde", "1.0.203")]


def test_parses_composer_gem_gradle_and_nuget_lockfiles(tmp_path):
    _write(tmp_path, "composer.lock", json.dumps({
        "packages": [{"name": "vendor/library", "version": "1.2.3"}],
        "packages-dev": [{"name": "vendor/test-tool", "version": "2.0.0"}]}))
    _write(tmp_path, "Gemfile.lock", """GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.8)
    rails (7.1.3)
      rack (>= 2.2.4)

PLATFORMS
  ruby
""")
    _write(tmp_path, "gradle.lockfile", """# lockfile
org.example:library:1.2.3=runtimeClasspath
""")
    _write(tmp_path, "packages.lock.json", json.dumps({
        "version": 1, "dependencies": {
            "net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1", "contentHash": "x"}}
        }}))
    items = vulndb.parse_lockfiles(str(tmp_path))
    found = {(x["ecosystem"], x["name"], x["version"]) for x in items}
    assert ("composer", "vendor/library", "1.2.3") in found
    assert ("composer", "vendor/test-tool", "2.0.0") in found
    assert ("gem", "rack", "3.0.8") in found
    assert ("gem", "rails", "7.1.3") in found
    assert ("maven", "org.example:library", "1.2.3") in found
    assert ("nuget", "Newtonsoft.Json", "13.0.1") in found


def test_malformed_lockfile_does_not_hide_other_ecosystem_inventory(tmp_path):
    _write(tmp_path, "Cargo.lock", "not = [valid toml")
    _write(tmp_path, "composer.lock", json.dumps({"packages": [{"name": "vendor/pkg", "version": "1.0.0"}]}))
    items = vulndb.parse_lockfiles(str(tmp_path))
    assert any(x["ecosystem"] == "composer" and x["name"] == "vendor/pkg" for x in items)
    assert any("Cargo.lock" in error for error in vulndb.STATUS["errors"])


def test_parses_uv_pdm_and_nuget_packages_config(tmp_path):
    _write(tmp_path, "uv.lock", """version = 1
[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }
""")
    _write(tmp_path, "pdm.lock", """[[package]]
name = "requests"
version = "2.32.3"
groups = ["default"]
[[package]]
name = "pytest"
version = "8.3.2"
groups = ["dev"]
""")
    _write(tmp_path, "packages.config", """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" />
  <package id="NUnit" version="3.14.0" targetFramework="net472" developmentDependency="true" />
</packages>
""")
    items = vulndb.parse_lockfiles(str(tmp_path))
    found = {(x["ecosystem"], x["name"], x["version"], x["scope"]) for x in items}
    assert ("pypi", "httpx", "0.27.0", "transitive") in found
    assert ("pypi", "requests", "2.32.3", "transitive") in found
    assert ("pypi", "pytest", "8.3.2", "dev") in found
    assert ("nuget", "Newtonsoft.Json", "13.0.1", "transitive") in found
    assert ("nuget", "NUnit", "3.14.0", "dev") in found


def test_grype_is_selected_for_source_dependency_scans():
    from myelin_engine import orchestrator

    inventory = {"languages": {"Python": 2}, "manifests": ["poetry.lock"], "files": 3}
    assert orchestrator._applies("grype", inventory, ["sca"])
    assert not orchestrator._applies("grype", inventory, ["secrets"])
    assert not orchestrator._applies("grype", {**inventory, "manifests": []}, ["sca"])


def test_grype_normalizer_preserves_package_and_fixed_version():
    from myelin_engine import normalize

    findings = normalize.grype({"matches": [{
        "vulnerability": {"id": "CVE-2025-1234", "severity": "High", "fix": {"versions": ["2.0.0"]}},
        "artifact": {"name": "sample-lib", "version": "1.0.0", "purl": "pkg:pypi/sample-lib@1.0.0"}
    }]}, "sample")
    assert len(findings) == 1
    assert findings[0]["engine"] == "sca"
    assert findings[0]["package"] == "sample-lib"
    assert findings[0]["fixed_version"] == "2.0.0"


def test_malformed_nuget_xml_does_not_abort_other_lockfiles(tmp_path):
    _write(tmp_path, "packages.config", "<packages><package")
    _write(tmp_path, "Gemfile.lock", "GEM\n  specs:\n    rack (3.0.8)\n")
    items = vulndb.parse_lockfiles(str(tmp_path))
    assert any(x["ecosystem"] == "gem" and x["name"] == "rack" for x in items)
    assert any("packages.config" in error for error in vulndb.STATUS["errors"])


def test_npm_lockfile_distinguishes_direct_dev_and_transitive_packages(tmp_path):
    _write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0.0"}},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/jest": {"version": "29.7.0", "dev": True},
            "node_modules/express/node_modules/cookie": {"version": "0.6.0"}
        }}))
    items = vulndb.parse_lockfiles(str(tmp_path))
    found = {(x["name"], x["version"]): x["scope"] for x in items}
    assert found[("express", "4.18.2")] == "required"
    assert found[("jest", "29.7.0")] == "dev"
    assert found[("cookie", "0.6.0")] == "transitive"


def test_local_workspace_packages_are_not_reported_as_registry_dependencies(tmp_path):
    _write(tmp_path, "uv.lock", """version = 1
[[package]]
name = "workspace-app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
""")
    items = vulndb.parse_lockfiles(str(tmp_path))
    assert not any(x["name"] == "workspace-app" for x in items)
    assert any(x["name"] == "httpx" for x in items)


def test_parses_hex_pub_and_cocoapods_lockfiles(tmp_path):
    _write(tmp_path, "mix.lock", '''"decimal": {:hex, :decimal, "2.1.0", "checksum", [:mix], [], "hexpm", "checksum"}
''')
    _write(tmp_path, "pubspec.lock", """packages:
  http:
    dependency: "direct main"
    description: {name: http, sha256: abc, url: "https://pub.dev"}
    source: hosted
    version: "1.2.0"
  flutter:
    dependency: "direct main"
    source: sdk
    version: "0.0.0"
""")
    _write(tmp_path, "Podfile.lock", """PODS:
  - Alamofire (5.9.1)
  - Firebase/CoreOnly (10.20.0)
DEPENDENCIES:
  - Alamofire
""")
    items = vulndb.parse_lockfiles(str(tmp_path))
    found = {(x["ecosystem"], x["name"], x["version"]) for x in items}
    assert ("hex", "decimal", "2.1.0") in found
    assert ("pub", "http", "1.2.0") in found
    assert not any(x[0] == "pub" and x[1] == "flutter" for x in found)
    assert ("cocoapods", "Alamofire", "5.9.1") in found
    assert ("cocoapods", "Firebase", "10.20.0") in found


def test_cve_threat_intelligence_enrichment(monkeypatch):
    vulndb._THREAT_INTEL["kev"] = None
    def fake(url, body=None, ttl=None):
        if url.startswith(vulndb.EPSS_URL):
            return {"data": [{"cve": "CVE-2025-1234", "epss": "0.87", "percentile": "0.99"}]}
        if url == vulndb.CISA_KEV_URL:
            return {"vulnerabilities": [{"cveID": "CVE-2025-1234"}]}
        return None
    monkeypatch.setattr(vulndb, "_http_json", fake)
    vulndb.STATUS["sources"].clear()
    vulndb.STATUS["errors"].clear()
    component = vulndb._c("npm", "sample", "1.0.0", "package-lock.json", "required")
    enriched = vulndb._enrich_threat_intel([(component, {"id": "GHSA-test", "cve": "CVE-2025-1234"})])
    advisory = enriched[0][1]
    assert advisory["epss"] == 0.87
    assert advisory["kev"] is True
    assert "FIRST EPSS" in vulndb.STATUS["sources"]
    assert "CISA KEV" in vulndb.STATUS["sources"]


def test_unavailable_kev_feed_does_not_claim_not_exploited(monkeypatch):
    vulndb._THREAT_INTEL["kev"] = None
    monkeypatch.setattr(vulndb, "_http_json", lambda *a, **k: None)
    vulndb.STATUS["errors"].clear()
    component = vulndb._c("npm", "sample", "1.0.0", "package-lock.json", "required")
    enriched = vulndb._enrich_threat_intel([(component, {"id": "GHSA-test", "cve": "CVE-2025-1234"})])
    assert "kev" not in enriched[0][1]
    assert any("CISA KEV enrichment unavailable" in e for e in vulndb.STATUS["errors"])


def test_sca_coverage_is_partial_when_advisory_or_scanner_sources_fail():
    from myelin_engine import coverage
    inv = {"files": 2, "languages": {}, "manifests": ["package-lock.json"], "iac": [], "pipelines": [], "ai": []}
    err = {"engine": "meta", "rule_id": "tool-error:grype", "title": "grype failed: database unavailable"}
    cov = coverage.build(inv, ["sca"], ["myelin-builtin", "grype"], [err], 3,
                         {"errors": ["OSV unavailable"]})
    assert cov["sca"]["assessed"] is True
    assert cov["sca"]["complete"] is False
    assert cov["sca"]["status"] == "partial"
    assert any("database unavailable" in x for x in cov["sca"]["errors"])


def test_nvd_cvss_cwe_and_references_enrichment(monkeypatch):
    from myelin_engine import vulndb

    component = vulndb._c("npm", "sample", "1.0.0", "package-lock.json", "required")
    advisory = {"id": "GHSA-test", "cve": "CVE-2025-1234", "cvss": None,
                "severity": "medium", "severity_known": False, "cwe": None}
    record = {
        "cvss": {"version": "3.1", "score": 9.8, "severity": "CRITICAL",
                 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "cwes": ["CWE-89"], "references": ["https://example.test/advisory"],
        "published": "2025-01-01T00:00:00.000", "modified": "2025-01-02T00:00:00.000",
        "source": "NVD", "vuln_status": "Analyzed",
    }
    monkeypatch.setattr(vulndb, "_nvd_record", lambda cve: record)
    enriched = vulndb._enrich_nvd([(component, advisory)], ["CVE-2025-1234"])
    result = enriched[0][1]
    assert result["cvss"] == 9.8
    assert result["severity"] == "critical"
    assert result["severity_known"] is True
    assert result["cwe"] == "CWE-89"
    assert result["nvd_cvss"]["vector"].startswith("CVSS:3.1")
    assert "https://example.test/advisory" in result["references"]


def test_nvd_unavailable_does_not_invent_cvss_or_cwe(monkeypatch):
    from myelin_engine import vulndb

    component = vulndb._c("npm", "sample", "1.0.0", "package-lock.json", "required")
    advisory = {"id": "GHSA-test", "cve": "CVE-2025-1234", "cvss": None,
                "severity": "medium", "severity_known": False}
    monkeypatch.setattr(vulndb, "_nvd_record", lambda cve: None)
    result = vulndb._enrich_nvd([(component, advisory)], ["CVE-2025-1234"])[0][1]
    assert result["cvss"] is None
    assert result["severity_known"] is False
    assert "cwe" not in result


def test_nvd_exploit_patch_and_cisa_catalog_context(monkeypatch):
    from myelin_engine import vulndb

    component = vulndb._c("npm", "sample", "1.0.0", "package-lock.json", "required")
    advisory = {"id": "GHSA-test", "cve": "CVE-2025-1234", "cvss": None,
                "severity": "medium", "severity_known": False}
    record = {
        "cvss": {"version": "3.1", "score": 8.8, "severity": "HIGH", "vector": "CVSS:3.1/AV:N"},
        "cwes": ["CWE-79"], "references": ["https://example.test/exploit", "https://example.test/patch"],
        "reference_types": {"exploit": ["https://example.test/exploit"],
                            "patch": ["https://example.test/patch"], "third_party_advisory": []},
        "cisa_exploit_add": "2025-01-01", "cisa_action_due": "2025-02-01",
        "cisa_required_action": "Apply vendor mitigations", "cisa_vulnerability_name": "Example RCE",
        "published": "2025-01-01T00:00:00.000", "modified": "2025-01-02T00:00:00.000",
        "source": "NVD", "vuln_status": "Analyzed",
    }
    monkeypatch.setattr(vulndb, "_nvd_record", lambda cve: record)
    result = vulndb._enrich_nvd([(component, advisory)], ["CVE-2025-1234"])[0][1]
    assert result["nvd"]["reference_types"]["exploit"] == ["https://example.test/exploit"]
    assert result["nvd"]["reference_types"]["patch"] == ["https://example.test/patch"]
    assert result["nvd"]["cisa_action_due"] == "2025-02-01"
    assert result["nvd"]["cisa_required_action"] == "Apply vendor mitigations"


def test_nvd_record_preserves_ssvc_and_affected_product_evidence(monkeypatch):
    from myelin_engine import vulndb

    payload = {"vulnerabilities": [{"cve": {
        "published": "2026-01-01T00:00:00.000",
        "lastModified": "2026-02-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "metrics": {
            "cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 9.3,
                "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/AV:N"}}],
            "ssvcMetricV203": [{"other": {"content": "SSVC source record"}}],
        },
        "weaknesses": [{"description": [{"value": "CWE-89"}]}],
        "references": [{"url": "https://example.test/exploit", "tags": ["Exploit"]}],
        "affected": [{"vendor": "example", "product": "sample", "versions": [{"version": "1.0", "status": "affected"}]}],
        "cisaExploitAdd": "2026-01-10",
        "cisaActionDue": "2026-02-10",
        "cisaRequiredAction": "Apply vendor mitigations",
        "cisaVulnerabilityName": "Sample vulnerability",
    }}]}
    monkeypatch.setattr(vulndb, "_http_json", lambda *args, **kwargs: payload)
    record = vulndb._nvd_record("CVE-2026-1234")
    assert record["cvss"]["version"] == "4.0"
    assert record["ssvc"] == payload["vulnerabilities"][0]["cve"]["metrics"]["ssvcMetricV203"]
    assert record["affected_products"][0]["product"] == "sample"
    assert record["reference_types"]["exploit"] == ["https://example.test/exploit"]


def test_osv_truncated_batch_is_reported(monkeypatch):
    monkeypatch.setattr(vulndb, "_http_json", lambda *a, **kw: {"results": []})
    with vulndb.scan_intelligence():
        assert vulndb._osv([{"ecosystem": "pypi", "name": "pyyaml", "version": "6.0"}]) is None
        assert "OSV query batch returned missing or incomplete results" in vulndb.scan_status()["errors"]
    assert "OSV query batch returned missing or incomplete results" not in vulndb.scan_status()["errors"]
