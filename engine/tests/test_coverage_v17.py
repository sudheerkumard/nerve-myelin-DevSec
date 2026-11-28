# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""End-of-life detection, components found outside manifests, file-level licensing and the offline advisory pack."""
import io
import json
import os
import subprocess
import sys
import zipfile

import pytest

from myelin_engine import brand, discovery, eol, licence_scan, mitigation, vulndb

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setenv("MYELIN_OFFLINE", "1")


PAD = "\n" + "var pad=0;" * 40    # the discovery skips stub files under 200 bytes


def _w(root, rel, text, mode="w"):
    if rel.endswith(".js"):
        text += PAD
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if mode == "wb":
        p.write_bytes(text)
    else:
        p.write_text(text)
    return p


# ----------------------------------------------------------------------------- end of life
def test_eol_runtimes_images_and_frameworks(tmp_path):
    _w(tmp_path, "Dockerfile", "FROM python:3.7-slim-buster\nRUN true\n")
    _w(tmp_path, ".nvmrc", "14\n")
    _w(tmp_path, "global.json", json.dumps({"sdk": {"version": "5.0.100"}}))
    _w(tmp_path, "app/app.csproj", "<Project><PropertyGroup><TargetFramework>netcoreapp3.1</TargetFramework></PropertyGroup></Project>")
    _w(tmp_path, "go.mod", "module x\n\ngo 1.19\n")
    comps = [{"ecosystem": "pypi", "name": "django", "version": "2.2.28", "file": "requirements.txt", "scope": "required",
              "purl": "pkg:pypi/django@2.2.28"}]
    fs = eol.scan(str(tmp_path), "r", comps)
    got = {(f["eol_product"], f["version"].split(".")[0]) for f in fs}
    assert ("python", "3") in got and ("nodejs", "14") in got and ("go", "1") in got
    assert any(f["eol_product"] == "debian" for f in fs)          # the buster base image
    assert any(f["eol_product"] in ("dotnet", "dotnetfx") for f in fs)
    assert any(f["eol_product"] == "django" for f in fs)
    for f in fs:
        assert f["rule_id"] in ("NM-EOL-001", "NM-EOL-002") and f["cwe"] == "CWE-1104"
        assert f["fixed_version"], f                                # a supported release to move to
    py = next(f for f in fs if f["eol_product"] == "python")
    assert py["severity"] == "high"                                 # runtimes are high, libraries medium
    assert next(f for f in fs if f["eol_product"] == "django")["severity"] == "medium"


def test_eol_supported_versions_are_quiet(tmp_path):
    target = eol.upgrade_target("python")
    _w(tmp_path, "Dockerfile", f"FROM python:{target}-slim\n")
    _w(tmp_path, ".nvmrc", eol.upgrade_target("nodejs") + "\n")
    assert eol.scan(str(tmp_path), "r", []) == []


# ----------------------------------------------------------------------------- embedded components
def test_embedded_js_jar_and_vendor_folders(tmp_path):
    _w(tmp_path, "web/js/jquery.min.js", "/*! jQuery v1.10.2 | (c) 2005, 2013 jQuery Foundation, Inc. */\n!function(){}")
    _w(tmp_path, "web/js/jquery.form.js", "/*!\n * jQuery Form Plugin\n * version: 3.51.0-2014.06.20\n * Requires jQuery v1.5 or later\n */")
    _w(tmp_path, "web/lib/bootstrap.min.js", "/*!\n * Bootstrap v3.1.1 (http://getbootstrap.com)\n */")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
                   "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n")
    _w(tmp_path, "lib/log4j-core.jar", buf.getvalue(), "wb")
    _w(tmp_path, "node_modules/lodash/package.json", json.dumps({"name": "lodash", "version": "4.17.11", "license": "MIT"}))
    comps = discovery.embedded_components(str(tmp_path))
    got = {(c["ecosystem"], c["name"], c["version"]) for c in comps}
    assert ("npm", "jquery", "1.10.2") in got
    assert ("npm", "jquery-form", "3.51.0") in got
    assert ("npm", "jquery", "1.5") not in got                     # the plugin's "Requires jQuery" line is not a jQuery copy
    assert ("npm", "bootstrap", "3.1.1") in got
    assert ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1") in got
    assert ("npm", "lodash", "4.17.11") in got
    assert all(c["scope"] == "embedded" and c["detection"] and c["purl"].startswith("pkg:") for c in comps)


def test_embedded_components_reach_the_sbom_with_evidence(tmp_path):
    from myelin_engine import sbom
    _w(tmp_path, "static/jquery-1.10.2.min.js", "/*! jQuery v1.10.2 | (c) jQuery Foundation */")
    inv = sbom.inventory(str(tmp_path))
    c = next(c for c in inv if c["name"] == "jquery")
    assert c["scope"] == "embedded"
    doc = sbom.cyclonedx(inv)
    comp = next(x for x in doc["components"] if x["name"] == "jquery")
    assert comp["evidence"]["occurrences"][0]["location"].endswith("jquery-1.10.2.min.js")


# ----------------------------------------------------------------------------- licensing
GPL2 = ("GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n... This program is free software; you can redistribute it "
        "and/or modify it under the terms of the GNU General Public License as published by the Free Software "
        "Foundation; either version 2 of the License, or (at your option) any later version.")
MIT = ("MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software "
       "... THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND")


def test_licence_inventory_and_conflicts(tmp_path):
    _w(tmp_path, "LICENSE", "Copyright (c) 2020 Example Ltd\n\n" + MIT)
    _w(tmp_path, "src/a.c", "// SPDX-License-Identifier: GPL-3.0-only\nint x;\n")
    _w(tmp_path, "third_party/lib/COPYING", GPL2)
    inv = licence_scan.inventory(str(tmp_path))
    assert inv["project_licence"] == "MIT"
    assert any("Example Ltd" in c for c in inv["copyrights"])
    comps = [{"ecosystem": "npm", "name": "gpl-thing", "version": "1.0.0", "license": "GPL-3.0-only", "file": "package.json",
              "scope": "required", "purl": "pkg:npm/gpl-thing@1.0.0"}]
    fs = licence_scan.findings(str(tmp_path), "r", comps, inv)
    rules = {f["rule_id"] for f in fs}
    assert {"NM-LIC-101", "NM-LIC-102", "NM-LIC-103"} <= rules
    conflict = next(f for f in fs if f["rule_id"] == "NM-LIC-103")
    assert conflict["package"] == "gpl-thing" and "MIT" in conflict["title"] + conflict.get("evidence", "")


def test_licence_identify_texts():
    assert licence_scan.identify(MIT) == "MIT"
    assert licence_scan.identify(GPL2).startswith("GPL-2.0")
    assert licence_scan.identify("hello world") is None


# ----------------------------------------------------------------------------- offline advisory pack
def _advisory(gid, eco, name, introduced, fixed, malicious=False):
    d = {"id": gid, "modified": "2026-01-01T00:00:00Z", "summary": f"{name} issue", "aliases": ["CVE-2099-0001"],
         "affected": [{"package": {"ecosystem": eco, "name": name},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else [])}]}],
         "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]}}
    if malicious:
        d["database_specific"] = {"malicious-packages-origins": [{"source": "test"}]}
    return d


def test_advisory_pack_build_and_lazy_offline_matching(tmp_path, monkeypatch):
    src = tmp_path / "ghsa" / "advisories" / "github-reviewed" / "2026" / "01"
    src.mkdir(parents=True)
    (src / "GHSA-aaaa-bbbb-cccc.json").write_text(json.dumps(_advisory("GHSA-aaaa-bbbb-cccc", "npm", "leftpadx", "0", "2.0.0")))
    (src / "GHSA-dddd-eeee-ffff.json").write_text(json.dumps(_advisory("GHSA-dddd-eeee-ffff", "PyPI", "pyx", "0", "1.5")))
    mal = tmp_path / "mal" / "osv" / "malicious" / "npm" / "evilpkg"
    mal.mkdir(parents=True)
    (mal / "MAL-2026-1.json").write_text(json.dumps(_advisory("MAL-2026-1", "npm", "evilpkg", "0", None, malicious=True)))
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-0001", "vendorProject": "x", "dateAdded": "2026-01-01"}]}))
    out = tmp_path / "pack"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_advisory_pack.py"), str(tmp_path / "ghsa"),
                        str(out), str(tmp_path / "mal"), str(kev)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    manifest = json.loads((out / "manifest.json").read_text())
    assert {a["ecosystem"] for a in manifest["archives"]} == {"npm", "PyPI"}
    monkeypatch.setenv("MYELIN_OSV_EXPORT_DIR", str(out))
    monkeypatch.setattr(vulndb, "_EXPORT", {"signature": None, "index": None, "loaded": set()})
    monkeypatch.setitem(vulndb._THREAT_INTEL, "kev", None)
    comps = [{"ecosystem": "npm", "name": "leftpadx", "version": "1.2.0", "file": "package.json", "scope": "required",
              "purl": "pkg:npm/leftpadx@1.2.0", "via": None},
             {"ecosystem": "npm", "name": "evilpkg", "version": "1.0.0", "file": "package.json", "scope": "required",
              "purl": "pkg:npm/evilpkg@1.0.0", "via": None}]
    pairs = vulndb.vulnerabilities(comps)
    ids = {(c["name"], v["id"]) for c, v in pairs}
    assert ("leftpadx", "GHSA-aaaa-bbbb-cccc") in ids and ("evilpkg", "MAL-2026-1") in ids
    left = next(v for c, v in pairs if c["name"] == "leftpadx")
    assert left.get("kev") is True                                 # exploited-in-the-wild flag from the bundled KEV catalog
    assert vulndb._EXPORT["loaded"] == {"npm.zip"}                 # only the ecosystems in the inventory are loaded
    fixed = [dict(c, version="2.0.0") for c in comps[:1]]
    assert vulndb.vulnerabilities(fixed) == []


# ----------------------------------------------------------------------------- guidance and branding
def test_mitigation_for_new_rule_families():
    g = mitigation.guidance({"engine": "sca", "rule_id": "NM-EOL-001", "package": "Python", "version": "3.7",
                             "fixed_version": "3.13"})
    assert "3.13" in g["steps"][0] and "endoflife" in g["reference"]
    g = mitigation.guidance({"engine": "license", "rule_id": "NM-LIC-103", "package": "x"})
    assert any("compatible" in s for s in g["steps"])
    g = mitigation.guidance({"engine": "sca", "rule_id": "CVE-2020-11023", "package": "jquery", "version": "1.10.2",
                             "fixed_version": "3.5.0", "detection": "file banner", "file": "js/jquery.min.js"})
    assert any("declared dependency" in s for s in g["steps"]) and "js/jquery.min.js" in g["summary"]


def test_reports_carry_the_product_mark():
    plan = mitigation.plan_html([{"engine": "sast", "rule_id": "NM-SAST-001", "title": "x", "severity": "high", "repo": "r"}])
    assert 'aria-label="RAT Flea DevSec logo"' in plan and brand.ATTRIBUTION in plan
    from myelin_engine import report_enterprise
    html = report_enterprise.render({"repo": "r", "findings": [], "engines": ["sast"], "coverage": {}})
    assert html.count('aria-label="RAT Flea DevSec logo"') >= 2


def test_licence_scanner_precision_regressions(tmp_path):
    gpl3 = ("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n... TERMS AND CONDITIONS ...\n13. Use with the GNU Affero "
            "General Public License. ... GNU Lesser General Public License ...\nHow to Apply These Terms ... either version "
            "3 of the License, or (at your option) any later version.")
    assert licence_scan.identify(gpl3) == "GPL-3.0-only"          # §13 and the how-to appendix do not change the licence
    _w(tmp_path, "COPYING", gpl3)
    _w(tmp_path, "src/license_policy.py", "# SPDX-License-Identifier: GPL-3.0-only. See LICENSE.\nTEXT = 'commons clause license condition'\n")
    inv = licence_scan.inventory(str(tmp_path))
    assert [f["file"] for f in inv["licence_files"]] == ["COPYING"]      # source files named like licences are code
    assert set(inv["spdx_tags"]) == {"GPL-3.0-only"}                     # no trailing prose in the identifier
    assert inv["project_licence"] == "GPL-3.0-only"
