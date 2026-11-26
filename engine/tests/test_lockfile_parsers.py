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
