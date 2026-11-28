# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Declared dependencies from build files, read in-process (no build tool, no network).

These cover projects scanned without Trivy (``--builtin-only``, air-gapped runners) and projects without a lock file:

* .NET: ``*.csproj`` / ``*.fsproj`` / ``*.vbproj`` PackageReference (attribute or child ``<Version>``), central package
  management (``Directory.Packages.props`` PackageVersion, VersionOverride), ``$(Property)`` versions from the
  project, ``Directory.Build.props`` and ``Directory.Packages.props``.
* Maven: ``pom.xml`` dependencies and dependencyManagement with ``${property}`` versions from the same POM
  (``project.version`` / ``project.parent.version`` included); plugins are ignored.
* Gradle: ``build.gradle`` / ``build.gradle.kts`` string coordinates and version catalogs (``libs.versions.toml``).
* Python: ``pyproject.toml`` (PEP 621 dependencies and optional-dependencies, Poetry), ``Pipfile``.
* Rust ``Cargo.toml``, PHP ``composer.json``, Ruby ``Gemfile``.

A range keeps its lowest version (``^4.2`` -> 4.2, ``>=1.3,<2`` -> 1.3), the same convention as the package.json
reader: the oldest release the build may resolve to is the one to check. Lock files, when present, override these.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET  # noqa: S405 - build files only; DOCTYPE/ENTITY declarations are rejected below

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    tomllib = None

SKIP = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "target", "bin", "obj", ".gradle", "packages"}
MAX_BYTES = 2_000_000
_LOW = re.compile(r"(\d+(?:\.\d+){0,3}(?:[-.+][0-9A-Za-z.]+)?)")


def _low(spec) -> str | None:
    """The lowest version a requirement allows, or None for unpinned/wildcard/URL requirements."""
    if not isinstance(spec, str):
        return None
    s = spec.strip()
    if not s or s in ("*", "latest") or s.startswith(("http", "git", "file:", "path:", "link:", "workspace:")):
        return None
    if s.startswith("[") or s.startswith("("):          # NuGet / Maven interval: [1.2,2.0)
        inner = s.strip("[]()").split(",")[0].strip()
        return inner or None
    first = re.split(r"\s*(?:,|\|\|)\s*", s)[0]
    if first.startswith(("<", "!=")):
        return None
    m = _LOW.search(first)
    return m.group(1) if m else None


def _read(path) -> str:
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return ""
        with open(path, encoding="utf-8-sig", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def _xml(text):
    if re.search(r"<!(?:DOCTYPE|ENTITY)", text, re.I):
        return None
    try:
        root = ET.fromstring(text)  # noqa: S314 - DOCTYPE/ENTITY rejected above
    except ET.ParseError:
        return None
    for el in root.iter():                                 # drop XML namespaces (pom.xml uses one)
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _c(eco, name, version, rel, scope="required"):
    return {"ecosystem": eco, "name": name, "version": version, "file": rel, "scope": scope, "declared_by": "build file"}


# ----------------------------------------------------------------------------------------- .NET
_PROP = re.compile(r"\$\(([\w.]+)\)")


def _msbuild_props(root_el, props: dict):
    for pg in root_el.iter("PropertyGroup"):
        for el in pg:
            if isinstance(el.tag, str) and (el.text or "").strip():
                props.setdefault(el.tag, el.text.strip())


def _expand(v, props):
    for _ in range(4):
        if not v or "$(" not in v:
            break
        v = _PROP.sub(lambda m: props.get(m.group(1), m.group(0)), v)
    return None if not v or "$(" in v else v


def _dotnet(root: str, files: dict) -> list[dict]:
    out = []
    central: dict[str, dict] = {}                          # directory -> {props, versions}
    for rel in files.get("Directory.Packages.props", []) + files.get("Directory.Build.props", []):
        el = _xml(_read(os.path.join(root, rel)))
        if el is None:
            continue
        d = central.setdefault(os.path.dirname(rel), {"props": {}, "versions": {}, "file": rel})
        _msbuild_props(el, d["props"])
        for pv in el.iter("PackageVersion"):
            name, ver = pv.get("Include") or pv.get("Update"), pv.get("Version")
            if name and ver:
                d["versions"][name.lower()] = (name, ver)
                d["file"] = rel

    def _inherited(rel_dir):
        props, versions, src = {}, {}, None
        parts = rel_dir.split("/") if rel_dir else []
        for i in range(len(parts), -1, -1):                 # nearest directory wins
            d = central.get("/".join(parts[:i]))
            if d:
                for k, v in d["props"].items():
                    props.setdefault(k, v)
                for k, v in d["versions"].items():
                    if k not in versions:
                        versions[k] = v
                        src = src or d["file"]
        return props, versions, src

    for rel in files.get("*proj", []):
        el = _xml(_read(os.path.join(root, rel)))
        if el is None:
            continue
        props, versions, _src = _inherited(os.path.dirname(rel))
        own = {}
        _msbuild_props(el, own)
        props = {**props, **own}
        for pr in el.iter("PackageReference"):
            name = pr.get("Include") or pr.get("Update")
            if not name:
                continue
            child = pr.find("Version")
            raw = pr.get("Version") or pr.get("VersionOverride") or (child.text if child is not None else None)
            if not raw and name.lower() in versions:
                raw = versions[name.lower()][1]
            ver = _low(_expand(raw, props)) if raw else None
            if ver:
                dev = (pr.get("PrivateAssets") or (pr.findtext("PrivateAssets") or "")).lower() == "all"
                out.append(_c("nuget", name, ver, rel, "optional" if dev else "required"))
    return out


# ----------------------------------------------------------------------------------------- Maven
def _maven(root: str, files: dict) -> list[dict]:
    out = []
    for rel in files.get("pom.xml", []):
        el = _xml(_read(os.path.join(root, rel)))
        if el is None:
            continue
        props = {}
        for p in el.findall("properties/*"):
            if isinstance(p.tag, str) and (p.text or "").strip():
                props[p.tag] = p.text.strip()
        for key, path in (("project.version", "version"), ("project.parent.version", "parent/version"),
                          ("project.groupId", "groupId")):
            v = el.findtext(path)
            if v:
                props[key] = v.strip()
        props.setdefault("project.version", props.get("project.parent.version", ""))

        def sub(v):
            for _ in range(4):
                if not v or "${" not in v:
                    break
                v = re.sub(r"\$\{([\w.\-]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
            return None if not v or "${" in v else v.strip()

        for section in ("dependencies/dependency", "dependencyManagement/dependencies/dependency",
                        "profiles/profile/dependencies/dependency"):
            for dep in el.findall(section):
                g, a = sub(dep.findtext("groupId")), sub(dep.findtext("artifactId"))
                v = _low(sub(dep.findtext("version")))
                if not (g and a and v) or dep.findtext("type") == "pom" and dep.findtext("scope") == "import":
                    continue
                scope = (dep.findtext("scope") or "").strip()
                out.append(_c("maven", f"{g}:{a}", v, rel, "optional" if scope in ("test", "provided") else "required"))
    return out


# ----------------------------------------------------------------------------------------- Gradle
def _gradle(root: str) -> list[dict]:
    try:
        from .resolve import gradle_declared
    except ImportError:
        return []
    return [_c("maven", f"{g}:{a}", v, rel) for g, a, v, rel in gradle_declared(root) if _low(v)]


# ----------------------------------------------------------------------------------------- Python / Rust / PHP / Ruby
_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(\(?[^;]*)")


def _pep508(req, rel, scope):
    m = _PEP508.match(req or "")
    if not m:
        return None
    spec = m.group(2).strip().strip("()")
    ver = _low(spec.replace("==", "").replace("~=", "").replace(">=", "")) if spec and not spec.startswith(("<", "!=")) else None
    if not ver:
        return None
    return _c("pypi", re.sub(r"[-_.]+", "-", m.group(1)).lower(), ver, rel, scope)


def _toml(text):
    if tomllib is None:
        return None
    try:
        return tomllib.loads(text)
    except Exception:  # noqa: BLE001 - malformed build file: skip it
        return None


def _python(root, files):
    out = []
    for rel in files.get("pyproject.toml", []):
        doc = _toml(_read(os.path.join(root, rel))) or {}
        proj = doc.get("project") or {}
        for r in proj.get("dependencies") or []:
            out.append(_pep508(r, rel, "required"))
        for reqs in (proj.get("optional-dependencies") or {}).values():
            for r in reqs or []:
                out.append(_pep508(r, rel, "optional"))
        poetry = (doc.get("tool") or {}).get("poetry") or {}
        groups = [("required", poetry.get("dependencies") or {}), ("optional", poetry.get("dev-dependencies") or {})]
        groups += [("optional", (g or {}).get("dependencies") or {}) for g in (poetry.get("group") or {}).values()]
        for scope, deps in groups:
            for n, v in deps.items():
                if n.lower() == "python":
                    continue
                ver = _low(v if isinstance(v, str) else (v or {}).get("version") if isinstance(v, dict) else None)
                if ver:
                    out.append(_c("pypi", re.sub(r"[-_.]+", "-", n).lower(), ver, rel, scope))
    for rel in files.get("Pipfile", []):
        doc = _toml(_read(os.path.join(root, rel))) or {}
        for sect, scope in (("packages", "required"), ("dev-packages", "optional")):
            for n, v in (doc.get(sect) or {}).items():
                ver = _low(v if isinstance(v, str) else (v or {}).get("version") if isinstance(v, dict) else None)
                if ver:
                    out.append(_c("pypi", re.sub(r"[-_.]+", "-", n).lower(), ver, rel, scope))
    return [c for c in out if c]


def _cargo(root, files):
    out = []
    for rel in files.get("Cargo.toml", []):
        doc = _toml(_read(os.path.join(root, rel))) or {}
        for sect, scope in (("dependencies", "required"), ("dev-dependencies", "optional"), ("build-dependencies", "required")):
            for n, v in (doc.get(sect) or {}).items():
                ver = _low(v if isinstance(v, str) else v.get("version") if isinstance(v, dict) else None)
                if ver:
                    out.append(_c("cargo", (v.get("package") if isinstance(v, dict) else None) or n, ver, rel, scope))
    return out


def _composer(root, files):
    out = []
    for rel in files.get("composer.json", []):
        try:
            doc = json.loads(_read(os.path.join(root, rel)) or "{}")
        except ValueError:
            continue
        for sect, scope in (("require", "required"), ("require-dev", "optional")):
            for n, v in (doc.get(sect) or {}).items():
                if "/" not in n:                           # php, ext-*, lib-*
                    continue
                ver = _low(str(v).lstrip("^~v"))
                if ver:
                    out.append(_c("composer", n.lower(), ver, rel, scope))
    return out


_GEM = re.compile(r"""^\s*gem\s+['"]([\w.\-]+)['"]\s*,\s*['"]([~>=<! ]*)(\d[\w.]*)['"]""", re.M)


def _gemfile(root, files):
    out = []
    for rel in files.get("Gemfile", []):
        for n, op, v in _GEM.findall(_read(os.path.join(root, rel))):
            if "<" not in op and "!" not in op:
                out.append(_c("gem", n, v, rel))
    return out


# ----------------------------------------------------------------------------------------- entry point
def declared(root: str) -> list[dict]:
    files: dict[str, list[str]] = {}
    locks = set()
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP and not x.startswith(".")]
        rel_dir = os.path.relpath(d, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        for fn in names:
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            if fn.endswith((".csproj", ".fsproj", ".vbproj")):
                files.setdefault("*proj", []).append(rel)
            elif fn in ("Directory.Packages.props", "Directory.Build.props", "pom.xml", "pyproject.toml", "Pipfile",
                        "Cargo.toml", "composer.json", "Gemfile"):
                files.setdefault(fn, []).append(rel)
            elif fn in ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "Cargo.lock", "composer.lock", "Gemfile.lock"):
                locks.add((rel_dir, fn))
    # a lock file next to the build file is exact; skip the declared ranges there
    lock_dirs = {(d, {"poetry.lock": "pyproject.toml", "uv.lock": "pyproject.toml", "pdm.lock": "pyproject.toml",
                      "Pipfile.lock": "Pipfile", "Cargo.lock": "Cargo.toml", "composer.lock": "composer.json",
                      "Gemfile.lock": "Gemfile"}[f]) for d, f in locks}
    for k in ("pyproject.toml", "Pipfile", "Cargo.toml", "composer.json", "Gemfile"):
        files[k] = [r for r in files.get(k, []) if (os.path.dirname(r), k) not in lock_dirs]
    out = []
    for fn in (_dotnet, _maven, _python, _cargo, _composer, _gemfile):
        try:
            out += fn(root, files)
        except Exception:  # noqa: BLE001 - one unreadable build file must not stop the inventory
            continue
    try:
        out += _gradle(root)
    except Exception:  # noqa: BLE001
        pass
    return out
