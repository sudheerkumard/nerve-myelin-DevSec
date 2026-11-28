# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Open-source components that no package manifest declares ("undeclared" or embedded components).

Dependency scanning only sees what a manifest or lock file lists. Code also arrives by copying: a minified library in
``static/js``, a jar in ``lib/``, a committed ``vendor/`` or ``node_modules/`` folder, a wheel or NuGet package checked
in for an offline build. Those copies carry the same vulnerabilities and licences, and are usually older. This module
identifies them from evidence inside the files themselves:

* JavaScript library banners and version constants (jQuery, jQuery UI, jQuery Validation, Bootstrap, AngularJS,
  React, Vue, Lodash, Underscore, Moment, Handlebars, Knockout, Backbone, DOMPurify, D3, Axios, Chart.js, Popper,
  Select2, DataTables, Highcharts, Prototype, PDF.js, Dojo, Ember, Mustache, js-yaml, marked);
* Java archives (.jar/.war/.ear, including WEB-INF/lib inside a war): ``META-INF/maven/**/pom.properties``;
* NuGet packages (.nupkg: the .nuspec), Python wheels (.whl: METADATA) and committed site-packages (``*.dist-info``);
* committed dependency folders: ``vendor/composer/installed.json``, Go ``vendor/modules.txt``,
  ``node_modules/*/package.json`` and ``bower_components/*/.bower.json``.

Every component found this way is marked ``scope: embedded`` with the evidence, and goes through the same advisory
and licence checks as declared dependencies.
"""
from __future__ import annotations

import io
import json
import os
import re
import zipfile

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", "target", "obj", "bin"}
MAX_JS = 6 * 1024 * 1024
MAX_ARCHIVE = 200 * 1024 * 1024
MAX_FILES = 60_000

V = r"v?(\d+\.\d+(?:\.\d+)?(?:[-.](?:alpha|beta|rc)\.?\d*)?)"
# (npm package, banner regex). Banners are matched in the first 2 KB; constants (last entries) in the whole file.
BANNERS = [
    ("jquery-ui", re.compile(r"jQuery UI(?: - v| v|\s+)(\d+\.\d+\.\d+)")),
    ("jquery-validation", re.compile(r"jQuery Validation Plugin - " + V)),
    ("jquery-migrate", re.compile(r"jQuery Migrate - " + V)),
    ("jquery-form", re.compile(r"jQuery Form Plugin\s*\*?\s*version:\s*(\d+\.\d+\.\d+)")),
    ("jquery", re.compile(r"(?:/\*!?\s*|\*\s+)jQuery v(\d+\.\d+\.\d+)\b|jQuery JavaScript Library v(\d+\.\d+\.\d+)")),
    ("bootstrap", re.compile(r"Bootstrap " + V + r" \(https?://getbootstrap")),
    ("angular", re.compile(r"@license AngularJS " + V)),
    ("react-dom", re.compile(r"@license React(?:DOM| React DOM)?[\s\S]{0,40}?react-dom[\s\S]{0,80}?v(\d+\.\d+\.\d+)")),
    ("react", re.compile(r"@license React v(\d+\.\d+\.\d+)")),
    ("vue", re.compile(r"Vue\.js " + V)),
    ("underscore", re.compile(r"Underscore\.js " + V)),
    ("backbone", re.compile(r"Backbone\.js " + V)),
    ("handlebars", re.compile(r"@license handlebars " + V + r"|Handlebars\.js " + V)),
    ("knockout", re.compile(r"Knockout JavaScript library " + V)),
    ("dompurify", re.compile(r"@license DOMPurify " + V)),
    ("d3", re.compile(r"https://d3js\.org " + V)),
    ("axios", re.compile(r"[Aa]xios " + V + r" Copyright")),
    ("chart.js", re.compile(r"Chart\.js " + V)),
    ("popper.js", re.compile(r"Popper\.js " + V)),
    ("@popperjs/core", re.compile(r"@popperjs/core " + V)),
    ("select2", re.compile(r"Select2 " + V)),
    ("datatables.net", re.compile(r"DataTables " + V)),
    ("highcharts", re.compile(r"Highcharts JS " + V)),
    ("prototype", re.compile(r"Prototype JavaScript framework, version " + V)),
    ("dojo", re.compile(r"Dojo Toolkit " + V)),
    ("ember-source", re.compile(r"@version\s+" + V + r"[\s\S]{0,200}Ember")),
    ("js-yaml", re.compile(r"js-yaml " + V)),
    ("marked", re.compile(r"marked " + V + r" - a markdown parser")),
    ("moment", re.compile(r"//! moment\.js[\s\S]{0,60}?//! version : " + V)),
    ("mustache", re.compile(r"mustache\.js - Logic-less[\s\S]{0,400}?version = ['\"](\d+\.\d+\.\d+)['\"]")),
]
CONSTANTS = [
    ("lodash", re.compile(r"lodash\.com[\s\S]{0,4000}?\bVERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]")),
    ("pdfjs-dist", re.compile(r"pdfjsVersion\s*=\s*['\"](\d+\.\d+\.\d+)['\"]")),
    ("jquery", re.compile(r"\bjquery\s*:\s*['\"](\d+\.\d+\.\d+)['\"][\s\S]{0,40}constructor\s*:\s*jQuery")),
]
FILENAME = re.compile(r"(?i)^(jquery|jquery-ui|bootstrap|angular|lodash|underscore|moment|handlebars|knockout|vue|"
                      r"backbone|dompurify|d3|axios|select2)[-.@](\d+\.\d+\.\d+)(?:\.min|\.slim|\.slim\.min)?\.js$")


# Licences of the libraries recognised by banner or constant (their published licence; used when no registry is reachable)
BANNER_LICENCE = {
    "jquery": "MIT", "jquery-ui": "MIT", "jquery-validation": "MIT", "jquery-migrate": "MIT",
    "jquery-form": "MIT OR LGPL-2.1-or-later", "bootstrap": "MIT", "angular": "MIT", "react": "MIT", "react-dom": "MIT",
    "vue": "MIT", "underscore": "MIT", "backbone": "MIT", "handlebars": "MIT", "knockout": "MIT",
    "dompurify": "MPL-2.0 OR Apache-2.0", "d3": "ISC", "axios": "MIT", "chart.js": "MIT", "popper.js": "MIT",
    "@popperjs/core": "MIT", "select2": "MIT", "datatables.net": "MIT", "highcharts": "LicenseRef-Highsoft-commercial",
    "prototype": "MIT", "dojo": "BSD-3-Clause OR AFL-2.1", "ember-source": "MIT", "js-yaml": "MIT", "marked": "MIT",
    "moment": "MIT", "mustache": "MIT", "lodash": "MIT", "pdfjs-dist": "Apache-2.0",
}


def _comp(eco, name, version, rel, how, **extra):
    if eco == "npm" and "license" not in extra and name in BANNER_LICENCE:
        extra["license"] = BANNER_LICENCE[name]
    return {"ecosystem": eco, "name": name, "version": version,
            "purl": f"pkg:{eco}/{name.replace(':', '/').replace('@', '%40', 1) if name.startswith('@') else name.replace(':', '/')}@{version}",
            "file": rel,
            "manifest": rel, "scope": "embedded", "direct": True, "via": None, "license": "unknown", "detection": how, **extra}


def _js(path, rel, out):
    try:
        size = os.path.getsize(path)
        if size > MAX_JS or size < 200:
            return
        with open(path, "rb") as fh:
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return
    head = data[:2048]
    seen = set()
    for name, rx in BANNERS:
        m = rx.search(head)
        if m:
            ver = next(g for g in m.groups() if g)
            if name == "jquery" and re.search(r"jQuery (?:UI|Validation|Migrate)", head[max(0, m.start() - 5):m.end()]):
                continue
            seen.add(name)
            out.append(_comp("npm", name, ver, rel, f"library banner in {os.path.basename(rel)}"))
    for name, rx in CONSTANTS:
        if name in seen:
            continue
        m = rx.search(data[:400_000])
        if m:
            seen.add(name)
            out.append(_comp("npm", name, m.group(1), rel, f"version constant in {os.path.basename(rel)}"))
    m = FILENAME.match(os.path.basename(rel))
    if m and m.group(1).lower() not in seen:
        out.append(_comp("npm", m.group(1).lower().replace("dompurify", "dompurify"), m.group(2), rel,
                         f"file name {os.path.basename(rel)}"))


def _java_archive(data: bytes, rel, out, depth=0):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return
    found = False
    for name in z.namelist():
        if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
            try:
                props = dict(re.findall(r"(?m)^\s*(groupId|artifactId|version)\s*=\s*(\S+)", z.read(name).decode("utf-8", "replace")))
            except (KeyError, zipfile.BadZipFile):
                continue
            if {"groupId", "artifactId", "version"} <= props.keys():
                found = True
                out.append(_comp("maven", f"{props['groupId']}:{props['artifactId']}", props["version"], rel,
                                 "pom.properties inside " + os.path.basename(rel)))
        elif depth == 0 and re.match(r"(WEB-INF|BOOT-INF|lib)/.*\.jar$", name):
            info = z.getinfo(name)
            if info.file_size < MAX_ARCHIVE:
                _java_archive(z.read(name), f"{rel}!/{name}", out, depth + 1)
    if not found and depth == 0 and rel.endswith(".jar"):
        try:
            mf = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
        except KeyError:
            return
        t = re.search(r"(?m)^(?:Bundle-SymbolicName|Implementation-Title):\s*([^;\r\n]+)", mf)
        v = re.search(r"(?m)^(?:Bundle-Version|Implementation-Version):\s*(\S+)", mf)
        if t and v:
            out.append({**_comp("generic", t.group(1).strip(), v.group(1).strip(), rel, "jar manifest"),
                        "purl": f"pkg:generic/{t.group(1).strip()}@{v.group(1).strip()}"})


def _nupkg(data, rel, out):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        spec = next((n for n in z.namelist() if n.endswith(".nuspec") and "/" not in n), None)
        text = z.read(spec).decode("utf-8", "replace") if spec else ""
    except (zipfile.BadZipFile, KeyError):
        return
    i, v = re.search(r"<id>([^<]+)</id>", text), re.search(r"<version>([^<]+)</version>", text)
    if i and v:
        lic = re.search(r"<license type=\"expression\">([^<]+)</license>", text)
        out.append(_comp("nuget", i.group(1).strip(), v.group(1).strip(), rel, "nuspec inside .nupkg",
                         **({"license": lic.group(1)} if lic else {})))


def _wheel_meta(text, rel, out, how):
    n = re.search(r"(?m)^Name:\s*(\S+)", text)
    v = re.search(r"(?m)^Version:\s*(\S+)", text)
    if n and v:
        lic = re.search(r"(?m)^License-Expression:\s*(.+)$", text)
        out.append(_comp("pypi", n.group(1).lower().replace("_", "-"), v.group(1), rel, how,
                         **({"license": lic.group(1).strip()} if lic else {})))


def embedded_components(root: str) -> list[dict]:
    out: list[dict] = []
    count = 0
    for d, dirs, files in os.walk(root):
        rel_dir = os.path.relpath(d, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not (x == "node_modules" and "node_modules" in rel_dir)]
        base = os.path.basename(d)
        if base == "node_modules":
            # committed node_modules: one level (and @scope/name)
            for x in list(dirs):
                pj = os.path.join(d, x, "package.json")
                cands = [pj] if os.path.isfile(pj) else [os.path.join(d, x, y, "package.json")
                                                          for y in (os.listdir(os.path.join(d, x)) if x.startswith("@") else [])]
                for c in cands:
                    try:
                        doc = json.load(open(c, encoding="utf-8"))
                        if doc.get("name") and doc.get("version"):
                            out.append(_comp("npm", doc["name"], doc["version"], os.path.relpath(c, root).replace("\\", "/"),
                                             "committed node_modules", **({"license": doc["license"]} if isinstance(doc.get("license"), str) else {})))
                    except (OSError, ValueError):
                        continue
            dirs[:] = []
            continue
        if base == "bower_components":
            for x in dirs:
                for meta in (".bower.json", "bower.json", "package.json"):
                    p = os.path.join(d, x, meta)
                    if os.path.isfile(p):
                        try:
                            doc = json.load(open(p, encoding="utf-8"))
                        except (OSError, ValueError):
                            continue
                        ver = doc.get("version") or (doc.get("_release") if re.match(r"\d", str(doc.get("_release") or "")) else None)
                        if ver:
                            out.append(_comp("npm", doc.get("name") or x, str(ver).lstrip("v"),
                                             os.path.relpath(p, root).replace("\\", "/"), "committed bower_components"))
                        break
            dirs[:] = []
            continue
        for fn in files:
            count += 1
            if count > MAX_FILES:
                return out
            p = os.path.join(d, fn)
            rel = rel_dir + fn
            low = fn.lower()
            try:
                if low.endswith(".js") and not low.endswith((".test.js", ".spec.js", ".config.js")):
                    _js(p, rel, out)
                elif low.endswith((".jar", ".war", ".ear")) and os.path.getsize(p) < MAX_ARCHIVE:
                    _java_archive(open(p, "rb").read(), rel, out)
                elif low.endswith(".nupkg") and os.path.getsize(p) < MAX_ARCHIVE:
                    _nupkg(open(p, "rb").read(), rel, out)
                elif low.endswith(".whl") and os.path.getsize(p) < MAX_ARCHIVE:
                    z = zipfile.ZipFile(p)
                    meta = next((n for n in z.namelist() if n.endswith(".dist-info/METADATA")), None)
                    if meta:
                        _wheel_meta(z.read(meta).decode("utf-8", "replace"), rel, out, "wheel METADATA")
                elif fn == "METADATA" and d.endswith(".dist-info"):
                    _wheel_meta(open(p, encoding="utf-8", errors="replace").read(20000), rel, out, "committed site-packages")
                elif rel.endswith("vendor/composer/installed.json"):
                    doc = json.load(open(p, encoding="utf-8"))
                    for pkg in (doc.get("packages") if isinstance(doc, dict) else doc) or []:
                        if pkg.get("name") and pkg.get("version"):
                            lic = pkg.get("license")
                            out.append(_comp("composer", pkg["name"], str(pkg["version"]).lstrip("v"), rel,
                                             "committed vendor/ (Composer)",
                                             **({"license": " OR ".join(lic)} if isinstance(lic, list) and lic else {})))
                elif rel.endswith("vendor/modules.txt"):
                    for m in re.finditer(r"(?m)^# (\S+) (v[\w.\-+]+)\s*$", open(p, encoding="utf-8", errors="replace").read()):
                        out.append(_comp("go", m.group(1), m.group(2), rel, "committed vendor/ (Go modules)"))
            except (OSError, ValueError, zipfile.BadZipFile, UnicodeDecodeError):
                continue
    # one entry per component and file
    uniq, seen = [], set()
    for c in out:
        k = (c["ecosystem"], c["name"], c["version"], c["file"])
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    return uniq
