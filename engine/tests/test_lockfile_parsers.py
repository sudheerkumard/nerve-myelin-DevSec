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
