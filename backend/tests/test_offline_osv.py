# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Air-gapped scans match components against OSV ecosystem exports on disk."""
import hashlib
import json
import os
import time
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import orchestrator, sbom, vulndb  # noqa: E402

DOCS = [
    {"id": "GHSA-test-pyyaml", "aliases": ["CVE-2020-14343"], "summary": "Arbitrary code execution in full_load",
     "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-20"]},
     "affected": [{"package": {"ecosystem": "PyPI", "name": "PyYAML"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]},
    {"id": "GHSA-test-lodash", "aliases": ["CVE-2021-23337"], "summary": "Command injection in template",
     "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]}]},
    {"id": "MAL-2026-0001", "summary": "Malicious code in evil-pkg",
     "affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"}, "versions": ["1.0.0"]}]},
    {"id": "GHSA-test-last", "summary": "last_affected range",
     "affected": [{"package": {"ecosystem": "npm", "name": "semver"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "7.0.0"}, {"last_affected": "7.5.1"}]}]}]},
]


def _export(tmp_path):
    d = tmp_path / "osv"
    d.mkdir()
    entries = []
    for ecosystem in ("PyPI", "npm"):
        filename = ecosystem.replace("/", "_") + ".zip"
        path = d / filename
        with zipfile.ZipFile(path, "w") as z:
            for doc in DOCS:
                if any((x.get("package") or {}).get("ecosystem") == ecosystem for x in doc.get("affected", [])):
                    z.writestr(doc["id"] + ".json", json.dumps(doc))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({"ecosystem": ecosystem, "file": filename, "sha256": digest,
                        "size_bytes": path.stat().st_size})
    (d / "manifest.json").write_text(json.dumps({
        "schema_version": 1, "source": "OSV ecosystem exports",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "archives": entries
    }), encoding="utf-8")
    return str(d)

def test_version_ranges():
    assert vulndb.affected(DOCS[0], "pypi", "pyyaml", "5.3.1") and not vulndb.affected(DOCS[0], "pypi", "pyyaml", "5.4")
    assert vulndb.affected(DOCS[1], "npm", "lodash", "4.17.15") and not vulndb.affected(DOCS[1], "npm", "lodash", "3.10.1")
    assert vulndb.affected(DOCS[3], "npm", "semver", "7.5.1") and not vulndb.affected(DOCS[3], "npm", "semver", "7.5.2")


def test_offline_scan_uses_exports(tmp_path, monkeypatch):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    monkeypatch.setenv("MYELIN_OSV_EXPORT_DIR", _export(tmp_path))
    comps = [{"ecosystem": "pypi", "name": "pyyaml", "version": "5.3.1", "file": "requirements.txt", "purl": "pkg:pypi/pyyaml@5.3.1", "license": "MIT", "via": None},
             {"ecosystem": "npm", "name": "lodash", "version": "4.17.15", "file": "package.json", "purl": "pkg:npm/lodash@4.17.15", "license": "MIT", "via": None},
             {"ecosystem": "npm", "name": "evil-pkg", "version": "1.0.0", "file": "package.json", "purl": "pkg:npm/evil-pkg@1.0.0", "license": "unknown", "via": None}]
    fs = sbom.match_advisories(comps)
    ids = {(f["engine"], f["rule_id"]) for f in fs}
    assert ("sca", "CVE-2020-14343") in ids and ("sca", "CVE-2021-23337") in ids and ("supply", "NM-SUP-001") in ids
    y = next(f for f in fs if f["rule_id"] == "CVE-2020-14343")
    assert y["fixed_version"] == "5.4" and y["severity"] == "critical"
    res = orchestrator.scan(os.path.join(ROOT, "demo", "vulnerable-app"), "x", use_external=False)
    assert "OSV offline export" in res["intelligence"]["sources"]



def test_offline_export_rejects_checksum_mismatch(tmp_path, monkeypatch):
    directory = _export(tmp_path)
    archive = tmp_path / "osv" / "npm.zip"
    archive.write_bytes(archive.read_bytes() + b"tampered")
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    monkeypatch.setenv("MYELIN_OSV_EXPORT_DIR", directory)
    assert vulndb._export_index() is None
    assert any("checksum mismatch" in error for error in vulndb.STATUS["errors"])


def test_offline_export_requires_manifest(tmp_path, monkeypatch):
    directory = tmp_path / "osv"
    directory.mkdir()
    with zipfile.ZipFile(directory / "all.zip", "w") as archive:
        archive.writestr("empty.json", "{}")
    monkeypatch.setenv("MYELIN_OSV_EXPORT_DIR", str(directory))
    assert vulndb._export_index() is None
    assert any("offline OSV export invalid" in error for error in vulndb.STATUS["errors"])
