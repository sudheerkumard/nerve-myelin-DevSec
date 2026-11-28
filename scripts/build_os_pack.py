#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Build the operating-system section of the offline advisory pack.

Each distribution becomes one ``os-<name>.json.gz``: ``{release: {package: [[fixed, [ids], severity, title], ...]}}``
where ``fixed`` is the first fixed version in that release (null: affected, no fix released). Severity is filled
from NVD at scan time when the distribution does not publish one.

Sources (each under its own terms, see THIRD-PARTY-NOTICES.md):

* Debian security tracker             vuln-list-debian/tracker/CVE    (via github.com/aquasecurity/vuln-list-debian)
* Ubuntu security notices (OSV)       ubuntu-security-notices/osv/cve (github.com/canonical/ubuntu-security-notices)
* Alpine, Wolfi, Chainguard secdb      vuln-list/{alpine,wolfi,chainguard}
* AlmaLinux and Rocky Linux errata, Amazon Linux ALAS   vuln-list/{alma,rocky,amazon}

Rocky Linux errata carry the same package versions as Red Hat Enterprise Linux, so RHEL, UBI, CentOS Stream and Oracle
Linux are matched against them.

    python scripts/build_os_pack.py --debian /tmp/debian --vuln-list /tmp/vl --ubuntu /tmp/usn /opt/myelin/advisories
"""
import argparse
import glob
import gzip
import hashlib
import json
import os
import re

UNFIXED = {"unfixed", "no-dsa", "postponed", "ignored", "end-of-life"}


def _add(table, rel, pkg, fixed, ids, sev=None, title=""):
    table.setdefault(rel, {}).setdefault(pkg, []).append([fixed, ids, sev, title[:120]])


def _deb_archive(base, codenames):
    """{codename: {source package: newest version in the release and its security/updates archive}}."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("ospkg", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "engine",
                                                            "myelin_engine", "ospkg.py"))
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = {}
    for code in codenames:
        vers = out.setdefault(code, {})
        for sub in ("source", "updates-source"):
            for path in glob.iglob(os.path.join(base, sub, code, "*", "*", "*.json")):
                try:
                    doc = json.load(open(path, encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                name = (doc.get("Package") or [None])[0]
                for v in doc.get("Version") or []:
                    if name and (name not in vers or mod.dpkg_cmp(v, vers[name]) > 0):
                        vers[name] = v
    return out, mod.dpkg_cmp


def debian(src):
    """Per release: the release's own fix (CVE list or DSA/DLA), else the unstable fix if the release already ships a
    version at or above it, else affected without a fix in that release (the security tracker's own rule)."""
    base = os.path.join(src, "tracker")
    dist = json.load(open(os.path.join(base, "distributions.json")))
    majors = {k: v["major-version"] for k, v in dist.items() if v.get("major-version")}
    archive, cmp = _deb_archive(base, majors)
    explicit = {}                                       # (cve, package) -> {codename: (kind, version)}
    sid, skip = {}, set()
    for kind_dir in ("CVE", "DSA", "DLA"):
        for path in glob.iglob(os.path.join(base, kind_dir, "**", "*.json"), recursive=True):
            try:
                doc = json.load(open(path, encoding="utf-8"))
            except (OSError, ValueError):
                continue
            hid = (doc.get("Header") or {}).get("ID") or ""
            cves = [hid] if hid.startswith("CVE-") else [b for a in doc.get("Annotations") or [] if a.get("Type") == "xref"
                                                          for b in a.get("Bugs") or [] if str(b).startswith("CVE-")]
            for a in doc.get("Annotations") or []:
                if a.get("Type") != "package" or not a.get("Package"):
                    continue
                for cve in cves:
                    key = (cve, a["Package"])
                    if a.get("Severity") == "unimportant" and kind_dir == "CVE":
                        skip.add(key)
                    if a.get("Release"):
                        explicit.setdefault(key, {}).setdefault(a["Release"], (a.get("Kind"), a.get("Version")))
                    elif kind_dir == "CVE":
                        sid[key] = (a.get("Kind"), a.get("Version"))
    out = {}
    for key in set(sid) | set(explicit):
        if key in skip:
            continue
        cve, pkg = key
        for code, major in majors.items():
            kind, ver = (explicit.get(key) or {}).get(code) or (None, None)
            if kind is None:
                skind, sver = sid.get(key, (None, None))
                if skind == "fixed" and sver and sver != "0":
                    have = archive.get(code, {}).get(pkg)
                    if not have:
                        continue                          # the release does not ship this package
                    kind, ver = ("fixed", sver) if cmp(have, sver) >= 0 else ("unfixed", None)
                elif skind in UNFIXED:
                    if pkg not in archive.get(code, {}):
                        continue
                    kind, ver = skind, None
                else:
                    continue
            if kind == "fixed" and ver and ver != "0":
                _add(out, major, pkg, ver, [cve])
            elif kind in UNFIXED:
                _add(out, major, pkg, None, [cve])
    return out


def ubuntu(src):
    out = {}
    for path in glob.iglob(os.path.join(src, "osv", "cve", "*", "*.json")):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        ids = [i for i in [doc.get("id")] + (doc.get("upstream") or []) + (doc.get("aliases") or []) if i]
        cve = next((i for i in ids if i.startswith("CVE-")), ids[0] if ids else None)
        sev = next((s.get("score") for s in doc.get("severity") or [] if s.get("type") == "Ubuntu"), None)
        for a in doc.get("affected") or []:
            eco = (a.get("package") or {}).get("ecosystem", "")
            m = re.match(r"^Ubuntu:(\d+\.\d+)(?::LTS)?$", eco)
            if not m:
                continue                                      # Ubuntu Pro / FIPS streams are not matched
            fixed = None
            for r in a.get("ranges") or []:
                for e in r.get("events") or []:
                    fixed = e.get("fixed") or fixed
            _add(out, m.group(1), a["package"]["name"], fixed, [cve] + [i for i in ids if i != cve][:3], sev,
                 doc.get("summary") or "")
    return out


def secdb(src, name, release_from_path=True):
    out = {}
    for path in glob.iglob(os.path.join(src, name, "**", "*.json"), recursive=True):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rel = os.path.relpath(path, os.path.join(src, name)).split(os.sep)[0] if release_from_path else ""
        if name in ("wolfi", "chainguard"):
            rel = ""
        pkg = doc.get("name") or os.path.splitext(os.path.basename(path))[0]
        for fixed, cves in (doc.get("secfixes") or {}).items():
            if fixed in ("0", "") or not cves:
                continue                                      # "0": the package was never affected
            ids = [str(c).split()[0] for c in cves if c]
            for cve in ids:
                _add(out, rel, pkg, fixed, [cve])
    return out


def _evr(p):
    e = str(p.get("epoch") or "0")
    return (f"{e}:" if e not in ("0", "") else "") + f"{p.get('version')}-{p.get('release')}"


def errata(src, name):
    out = {}
    for path in glob.iglob(os.path.join(src, name, "**", "*.json"), recursive=True):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rel = os.path.relpath(path, os.path.join(src, name)).split(os.sep)[0].split(".")[0]
        pkgs = doc.get("packages") or (doc.get("pkglist") or {}).get("packages") or []
        cves = doc.get("cveids") or [r.get("id") for r in doc.get("references") or [] if r.get("type") == "cve"]
        cves = [c for c in cves if c]
        adv = doc.get("id") or doc.get("updateinfo_id")
        if not cves and adv:
            cves = [adv]
        if not pkgs or not cves:
            continue
        seen = set()
        for p in pkgs:
            if not p.get("name") or p["name"] in seen or str(p.get("arch")) == "src":
                continue
            seen.add(p["name"])
            ids = cves + ([adv] if adv and adv not in cves else [])
            _add(out, rel, p["name"], _evr(p), ids, doc.get("severity"), doc.get("title") or "")
    return out


def write(dest, name, data, manifest):
    path = os.path.join(dest, f"os-{name}.json.gz")
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    with gzip.GzipFile(path, "wb", mtime=0, compresslevel=9) as fh:
        fh.write(raw)
    rows = sum(len(v) for rel in data.values() for v in rel.values())
    manifest.setdefault("os", {})[name] = {"file": os.path.basename(path), "records": rows,
                                           "releases": sorted(data), "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest()}
    print(f"{name}: {rows} package advisories, releases {', '.join(sorted(data)) or '(rolling)'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dest")
    ap.add_argument("--debian")
    ap.add_argument("--ubuntu")
    ap.add_argument("--vuln-list")
    a = ap.parse_args()
    os.makedirs(a.dest, exist_ok=True)
    mpath = os.path.join(a.dest, "manifest.json")
    manifest = json.load(open(mpath)) if os.path.isfile(mpath) else {"schema_version": 1, "archives": []}
    notes = []
    if a.debian:
        write(a.dest, "debian", debian(a.debian), manifest)
        notes.append("Debian security tracker data")
    if a.ubuntu:
        write(a.dest, "ubuntu", ubuntu(a.ubuntu), manifest)
        notes.append("Ubuntu security notices (CC BY-SA 4.0)")
    if a.vuln_list:
        for name, key in (("alpine", "alpine"), ("wolfi", "wolfi"), ("chainguard", "chainguard")):
            if os.path.isdir(os.path.join(a.vuln_list, name)):
                write(a.dest, key, secdb(a.vuln_list, name), manifest)
        for name, key in (("alma", "almalinux"), ("rocky", "rocky"), ("amazon", "amzn")):
            if os.path.isdir(os.path.join(a.vuln_list, name)):
                write(a.dest, key, errata(a.vuln_list, name), manifest)
        notes.append("Alpine/Wolfi/Chainguard secdb, AlmaLinux and Rocky Linux errata, Amazon Linux ALAS")
    note = "operating-system advisories: " + ", ".join(notes)
    manifest["source"] = (manifest.get("source", "") + "; " + note).lstrip("; ")
    json.dump(manifest, open(mpath, "w"), indent=1)


if __name__ == "__main__":
    main()
