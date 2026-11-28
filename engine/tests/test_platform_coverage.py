# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Operating systems, native binaries, firmware, drivers, databases/middleware in IaC, image archives and SBOMs with
OS packages or CPEs. Each test builds its own small advisory pack, so no network or bundled data is needed."""
import gzip
import hashlib
import io
import json
import lzma
import os
import tarfile
import zipfile

import pytest

from myelin_engine import binaries, cpe, image_tar, infra, ospkg, platform_scan, sbom_analysis, vulndb


# ----------------------------------------------------------------------------------------------- version ordering
@pytest.mark.parametrize("a,b", [("1.0~rc1", "1.0"), ("3.0.11-1~deb12u2", "3.0.11-1"), ("1.2.3-1", "1.2.3-1ubuntu0.1"),
                                 ("2.36-9+deb12u4", "2.36-9+deb12u10"), ("1.0", "1:0.1")])
def test_dpkg_order(a, b):
    assert ospkg.dpkg_cmp(a, b) < 0 < ospkg.dpkg_cmp(b, a)


@pytest.mark.parametrize("a,b", [("1:3.0.7-17.el9_2", "1:3.0.7-24.el9"), ("2.34-60.el9", "2.34-100.el9"), ("1.0~beta", "1.0")])
def test_rpm_order(a, b):
    assert ospkg.rpm_cmp(a, b) < 0 < ospkg.rpm_cmp(b, a)


@pytest.mark.parametrize("a,b", [("3.1.4-r0", "3.1.4-r5"), ("1.2.3_rc1-r0", "1.2.3-r0"), ("1.36.1-r3", "1.36.1-r29"),
                                 ("1.9.9-r0", "1.10.0-r0")])
def test_apk_order(a, b):
    assert ospkg.apk_cmp(a, b) < 0 < ospkg.apk_cmp(b, a)


@pytest.mark.parametrize("a,b", [("1.1.1k", "1.1.1l"), ("1.1.1", "1.1.1a"), ("4.19.0-rc3", "4.19.0"), ("7.88.1", "8.0.0")])
def test_cpe_order(a, b):
    assert cpe.vcmp(a, b) < 0 < cpe.vcmp(b, a)


# ----------------------------------------------------------------------------------------------- a tiny pack
@pytest.fixture
def pack(tmp_path, monkeypatch):
    d = tmp_path / "pack"
    d.mkdir()
    npm = io.BytesIO()
    with zipfile.ZipFile(npm, "w") as z:
        z.writestr("GHSA-x.json", json.dumps({"id": "GHSA-x", "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/net"},
                                                                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.17.0"}]}]}]}))
    (d / "Go.zip").write_bytes(npm.getvalue())
    os_deb = {"11": {"openssl": [["1.1.1n-0+deb11u4", ["CVE-2023-0286"], None, ""], [None, ["CVE-2099-1"], None, ""]]}}
    (d / "os-debian.json.gz").write_bytes(gzip.compress(json.dumps(os_deb).encode()))
    with zipfile.ZipFile(d / "cpe.pack", "w") as z:
        z.writestr("p/a:busybox:busybox.json", json.dumps([["CVE-2022-48174", None, None, None, None, "1.35.0"]]))
        z.writestr("p/a:f5:nginx.json", json.dumps([["CVE-2021-23017", None, "0.6.18", None, None, "1.21.0"]]))
        z.writestr("p/a:denx:u-boot.json", json.dumps([["CVE-2018-18439", None, None, None, "2018.09", None]]))
        for cve, row in {"CVE-2022-48174": [9.8, "critical", "CWE-787", "busybox ash overflow"],
                         "CVE-2021-23017": [7.7, "high", "CWE-193", "nginx resolver"],
                         "CVE-2018-18439": [9.8, "critical", "CWE-119", "u-boot tftp"],
                         "CVE-2023-0286": [7.4, "high", "CWE-843", "openssl x400"]}.items():
            z.writestr(f"m/{hashlib.sha1(cve.encode()).hexdigest()[:3]}.json", json.dumps({cve: row}))
    drivers = {"ab" * 32: ["0123-driver", "vulnerable driver", "RTCore64.sys"]}
    (d / "drivers.json.gz").write_bytes(gzip.compress(json.dumps(drivers).encode()))

    def entry(name):
        return {"file": name, "sha256": hashlib.sha256((d / name).read_bytes()).hexdigest()}
    manifest = {"schema_version": 1, "generated_at": "2026-11-28T00:00:00Z", "source": "test",
                "archives": [{"file": "Go.zip", "ecosystem": "Go", "records": 1, **entry("Go.zip")}],
                "os": {"debian": entry("os-debian.json.gz")}, "cpe": entry("cpe.pack"), "drivers": entry("drivers.json.gz")}
    (d / "manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    monkeypatch.setenv("MYELIN_OSV_EXPORT_DIR", str(d))
    monkeypatch.setattr(vulndb, "_EXPORT", {"signature": None, "index": None, "loaded": set()})
    monkeypatch.setattr(cpe, "_PACK", {"loaded": False, "data": None})
    monkeypatch.setattr(ospkg, "_PACK", {"sig": None, "data": {}})
    monkeypatch.setattr(binaries, "_DRIVERS", {"loaded": False, "data": {}})
    return d


def _rootfs(root):
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=debian\nVERSION_ID="11"\nPRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\n')
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(
        "Package: libssl1.1\nStatus: install ok installed\nSource: openssl\nVersion: 1.1.1n-0+deb11u3\nArchitecture: amd64\n\n"
        "Package: openssl\nStatus: install ok installed\nVersion: 1.1.1n-0+deb11u3\nArchitecture: amd64\n\n"
        "Package: removed\nStatus: deinstall ok config-files\nVersion: 1\n\n")
    (root / "etc/passwd").write_text("root::0:0:root:/root:/bin/sh\ndaemon:x:1:1::/:/usr/sbin/nologin\n")
    (root / "etc/inittab").write_text("::respawn:/usr/sbin/telnetd -l /bin/sh\n")


# ----------------------------------------------------------------------------------------------- operating systems
def test_os_packages_inventory_match_and_grouping(tmp_path, pack):
    _rootfs(tmp_path / "rootfs")
    inv = ospkg.inventory(str(tmp_path / "rootfs"), "rootfs")
    assert inv["distro"]["id"] == "debian" and {p["name"] for p in inv["packages"]} == {"libssl1.1", "openssl"}
    comps, fs = platform_scan.os_findings(inv, "r")
    fixed = next(f for f in fs if f["rule_id"] == "NM-OS-001")
    assert fixed["fixed_version"] == "1.1.1n-0+deb11u4" and fixed["severity"] == "high"     # severity from NVD data
    assert set(fixed["binary_packages"]) == {"libssl1.1", "openssl"}                          # one finding per source fix
    assert any(f["rule_id"] == "NM-OS-002" for f in fs)                                        # no fix released yet
    assert all(c["purl"].startswith("pkg:deb/debian/") for c in comps)


def test_rootfs_weak_accounts_and_telnet(tmp_path, pack):
    _rootfs(tmp_path / "rootfs")
    fs = platform_scan.rootfs_checks(str(tmp_path / "rootfs"), "rootfs", "r")
    rules = {(f["rule_id"], f["file"]) for f in fs}
    assert ("NM-FW-001", "rootfs/etc/passwd") in rules and ("NM-FW-002", "rootfs/etc/inittab") in rules
    assert not any("daemon" in f["title"] for f in fs)


# ----------------------------------------------------------------------------------------------- binaries and firmware
def test_firmware_compressed_sections_and_cpe(tmp_path, pack):
    kernel = b"BusyBox v1.31.1 (2020-01-01) multi-call binary\x00" + os.urandom(6000)
    blob = b"\x00" * 64 + b"U-Boot 2016.01 (Jan 12 2018)\x00" + gzip.compress(kernel) + lzma.compress(b"nginx/1.18.0\x00" + os.urandom(5000), format=lzma.FORMAT_ALONE)
    (tmp_path / "router.bin").write_bytes(blob)
    res = platform_scan.scan(str(tmp_path), "r")
    by = {f["package"]: f for f in res["findings"] if f["rule_id"] == "NM-BIN-002"}
    assert set(by) == {"busybox", "u-boot", "nginx"}
    assert by["busybox"]["fixed_version"] == "1.35.0" and by["busybox"]["severity"] == "critical"
    assert any(c["cpe"].startswith("cpe:2.3:a:busybox:busybox:1.31.1") for c in res["components"] if c["ecosystem"] == "binary")


def test_go_buildinfo_and_elf_hardening(tmp_path, pack):
    elf = bytearray(b"\x7fELF\x02\x01\x01" + b"\x00" * 9)
    elf += b"\x02\x00" + b"\x00" * 46                                # ET_EXEC; no program headers (no NX, no RELRO)
    go = bytes(elf) + b"\xff Go buildinf:\x08\x02" + b"\x00" * 16 + b"go1.20.1" + b"\npath\texample.com/app\nmod\texample.com/app\t(devel)\t\n" \
        + b"dep\tgolang.org/x/net\tv0.10.0\th1:abc=\n" + b"\x00" * 300
    (tmp_path / "app").write_bytes(go)
    r = binaries.scan(str(tmp_path), "r")
    names = {(c["ecosystem"], c["name"], c["version"]) for c in r["components"]}
    assert ("go", "golang.org/x/net", "v0.10.0") in names and ("go", "stdlib", "v1.20.1") in names
    assert not r["findings"]                                          # Go executables are not judged on C hardening
    assert binaries.elf_hardening(bytes(elf) + b"\x00" * 64) == []    # static (no interpreter): not judged


def test_vulnerable_windows_driver(tmp_path, pack, monkeypatch):
    data = b"MZ" + b"\x00" * 200
    (tmp_path / "RTCore64.sys").write_bytes(data)
    monkeypatch.setattr(binaries, "_DRIVERS", {"loaded": True, "data": {hashlib.sha256(data).hexdigest(): ["d1", "vulnerable driver", "RTCore64.sys"]}})
    r = binaries.scan(str(tmp_path), "r")
    assert [f["rule_id"] for f in r["findings"]] == ["NM-DRV-001"]


def test_android_package_versions(tmp_path, pack):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/androidx.core_core.version", "1.6.0")
        z.writestr("classes.dex", b"dex\n035")
    (tmp_path / "app.apk").write_bytes(buf.getvalue())
    comps = binaries.scan(str(tmp_path), "r")["components"]
    assert ("maven", "androidx.core:core", "1.6.0") in {(c["ecosystem"], c["name"], c["version"]) for c in comps}


# ----------------------------------------------------------------------------------------------- infrastructure
def test_databases_middleware_and_k8s_apis(tmp_path, pack):
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "db" {\n  engine = "postgres"\n  engine_version = "11.22"\n}\n'
                                      'resource "aws_lambda_function" "f" {\n  runtime = "python3.8"\n}\n')
    (tmp_path / "deploy.yaml").write_text("apiVersion: extensions/v1beta1\nkind: Ingress\n---\napiVersion: apps/v1\nkind: Deployment\n"
                                          "spec:\n  template:\n    spec:\n      containers:\n        - image: nginx:1.18.0\n")
    fs = infra.scan(str(tmp_path), "r")
    titles = " | ".join(f["title"] for f in fs)
    assert "Amazon RDS for PostgreSQL 11 is end of life" in titles
    assert "AWS Lambda python3.8 is end of life" in titles
    assert any(f["rule_id"] == "NM-K8S-001" for f in fs)
    img = next(f for f in fs if f["rule_id"] == "NM-IMG-001")
    assert img["package"] == "nginx" and img["cve"] == "CVE-2021-23017"
    lam = next(f for f in fs if "Lambda" in f["title"])
    assert lam["fixed_version"].startswith("python3.")               # same runtime family


# ----------------------------------------------------------------------------------------------- image archives and SBOMs
def _layer(files):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        for name, data in files:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return b.getvalue()


def test_image_archive_layers_and_whiteouts(tmp_path):
    l1 = _layer([("etc/os-release", b"ID=alpine\nVERSION_ID=3.20.3\n"), ("etc/old", b"x"), ("../escape", b"no")])
    l2 = _layer([("etc/.wh.old", b""), ("srv/new", b"y")])
    arc = tmp_path / "img.tar"
    with tarfile.open(arc, "w") as t:
        for name, data in [("a/layer.tar", l1), ("b/layer.tar", l2), ("c.json", b"{}"),
                           ("manifest.json", json.dumps([{"Config": "c.json", "RepoTags": ["x:1"], "Layers": ["a/layer.tar", "b/layer.tar"]}]).encode())]:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    dest = tmp_path / "root"
    dest.mkdir()
    meta = image_tar.unpack(str(arc), str(dest))
    assert meta["repo_tags"] == ["x:1"] and meta["layers"] == 2
    assert (dest / "srv/new").exists() and not (dest / "etc/old").exists()
    assert not (tmp_path / "escape").exists()


def test_sbom_with_os_packages_and_cpe_only_components(pack):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "libssl1.1", "version": "1.1.1n-0+deb11u3",
         "purl": "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u3?arch=amd64&upstream=openssl&distro=debian-11"},
        {"type": "firmware", "name": "U-Boot", "version": "2016.01", "cpe": "cpe:2.3:a:denx:u-boot:2016.01:*:*:*:*:*:*:*"}]}
    rec = sbom_analysis.analyse("vendor", [("v.cdx.json", json.dumps(doc).encode())])
    rules = {v["rule_id"] for v in rec["vulnerabilities"]}
    assert {"NM-OS-001", "NM-BIN-002"} <= rules
    assert "skipped" not in rec["files"][0]["format"]
    assert not any(r["package"] == "libssl1.1" for r in rec["licences"])   # OS packages are not licence-evaluated


def test_firmware_root_filesystem_unpacked_with_installed_extractor(tmp_path, pack, monkeypatch):
    """The squashfs inside a firmware image is handed to the extractor on PATH; the unpacked root is scanned."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tool = bindir / "unsquashfs"
    tool.write_text("#!/bin/sh\nwhile [ $# -gt 1 ]; do [ \"$1\" = -d ] && d=\"$2\"; shift; done\n"
                    "mkdir -p \"$d/etc\" && printf 'root::0:0::/root:/bin/sh\\n' > \"$d/etc/passwd\" && "
                    "printf 'ID=openwrt\\nVERSION_ID=19.07\\n' > \"$d/etc/os-release\"\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    fw = b"HDR0" + b"\x00" * 60 + b"hsqs" + (10).to_bytes(4, "little") + b"\x00" * 200
    (tmp_path / "fw").mkdir()
    (tmp_path / "fw" / "router.trx").write_bytes(fw)
    res = platform_scan.scan(str(tmp_path / "fw"), "r")
    assert any("unpacked with unsquashfs" in n for n in res["notes"])
    acct = [f for f in res["findings"] if f["rule_id"] == "NM-FW-001"]
    assert acct and acct[0]["file"].startswith("router.trx!/")


def test_firmware_without_extractor_says_so(tmp_path, pack, monkeypatch):
    monkeypatch.setattr(binaries, "extractors", lambda: [])
    (tmp_path / "fw.bin").write_bytes(b"\x00" * 64 + b"hsqs" + (10).to_bytes(4, "little") + b"\x00" * 200)
    res = platform_scan.scan(str(tmp_path), "r")
    assert any("install unblob, sasquatch or squashfs-tools" in n for n in res["notes"])
