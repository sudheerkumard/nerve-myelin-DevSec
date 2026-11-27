# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Dependency intelligence: transitive resolution, live vulnerability data and licences.

Sources (online by default, cached for 24 h; set MYELIN_OFFLINE=1 for air-gapped use):
  * OSV (api.osv.dev)   — vulnerabilities for PyPI, npm, Maven, Go, crates.io, NuGet, RubyGems, Packagist
  * PyPI JSON API       — Python metadata (dependencies, licence) and a vulnerability fallback when OSV is unreachable
  * npm registry        — JavaScript licences
Lockfiles (package-lock.json, yarn.lock, poetry.lock, Pipfile.lock) give exact transitive versions. For a Python
requirements file without a lock, dependencies are resolved from PyPI metadata the way an install today would
(highest release satisfying each constraint).

Mirrors: MYELIN_OSV_URL, MYELIN_PYPI_URL, MYELIN_NPM_URL. Network failures never break a scan: the bundled
advisory pack is always applied and the report says which sources were used.

Air-gapped: download the OSV ecosystem exports on a connected host (`myelin advisories download DIR`), carry the folder
across, and set MYELIN_OSV_EXPORT_DIR=DIR. Offline scans then match every component against the full OSV data locally
(version lists and ECOSYSTEM / SEMVER ranges), including malicious-package (MAL-) records.
"""
import calendar
import hashlib
import http.client
import json
import math
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar, copy_context

from . import coverage

OSV_URL = os.environ.get("MYELIN_OSV_URL", "https://api.osv.dev").rstrip("/")
PYPI_URL = os.environ.get("MYELIN_PYPI_URL", "https://pypi.org").rstrip("/")
NPM_URL = os.environ.get("MYELIN_NPM_URL", "https://registry.npmjs.org").rstrip("/")
OSV_ECO = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "go": "Go", "cargo": "crates.io", "nuget": "NuGet",
           "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub", "cocoapods": "CocoaPods"}
CACHE_TTL = 24 * 3600
MAX_TRANSITIVE = 600
STATUS = {"sources": set(), "errors": set(), "inventory_errors": set()}  # standalone helper calls
_scan_status = ContextVar("scan_status", default=None)


def current_status():
    return _scan_status.get() or STATUS


@contextmanager
def scan_status():
    status = {"sources": set(), "errors": set(), "inventory_errors": set()}
    token = _scan_status.set(status)
    try:
        yield status
    finally:
        _scan_status.reset(token)


def scan_map(pool, fn, values):
    # Each worker gets its own Context, with the evidence sets of the current scan.
    return pool.map(lambda ctx_value: ctx_value[0].run(fn, ctx_value[1]),
                    ((copy_context(), value) for value in values))


def offline() -> bool:
    return os.environ.get("MYELIN_OFFLINE", "").lower() in ("1", "true", "yes")


def _cache_dir():
    d = os.environ.get("MYELIN_CACHE_DIR") or os.path.join(os.path.expanduser("~"), ".cache", "myelin")
    try:
        os.makedirs(d, exist_ok=True)
        return d
    except OSError:
        d = os.path.join(tempfile.gettempdir(), "myelin-cache")
        os.makedirs(d, exist_ok=True)
        return d


def _http_json(url, body=None, ttl=CACHE_TTL, headers=None):
    key = hashlib.sha256((url + "\n" + (json.dumps(body, sort_keys=True) if body else "")).encode()).hexdigest()
    path = os.path.join(_cache_dir(), key + ".json")
    try:
        if time.time() - os.path.getmtime(path) < ttl:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
    except (OSError, ValueError):
        pass
    if offline():
        return None
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"User-Agent": "NERvvE-DevSecOps", "Accept": "application/json",
                                          **({"Content-Type": "application/json"} if data else {}), **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # myelin:ignore[NM-SAST-010] -- URLs are built from fixed OSV/PyPI/npm https endpoints or operator-set mirrors
            out = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            out = None
        else:
            raise
    try:
        tmp = path + f".{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(out, fh)
        os.replace(tmp, path)
    except OSError:
        pass
    return out


def norm_name(eco, name):
    name = re.sub(r"\[.*\]$", "", name.strip())
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pypi" else name


# ------------------------------------------------------------------ lockfiles
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
             "pdm.lock", "Pipfile.lock", "Cargo.lock", "composer.lock", "Gemfile.lock", "gradle.lockfile",
             "packages.lock.json", "packages.config", "mix.lock", "pubspec.lock", "Podfile.lock"}


def _lock_json(fh, *sections):
    data = json.load(fh)
    if not isinstance(data, dict) or not any(key in data for key in sections):
        raise ValueError("unrecognised lockfile structure")
    return data


def parse_lockfiles(root: str) -> list[dict]:
    """Extract exact package versions from supported lockfiles.

    Each parser is isolated so one malformed/unsupported lockfile cannot discard
    inventory from other ecosystems. Components retain the source lockfile path.
    """
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in coverage.SKIP)
        for fn in sorted(filenames):
            if fn not in LOCKFILES:
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                if os.path.islink(p):
                    raise ValueError("lockfile is a symlink")
                if fn in ("package-lock.json", "npm-shrinkwrap.json"):
                    with open(p, encoding="utf-8") as fh:
                        out += _npm_lock(_lock_json(fh, "lockfileVersion", "packages", "dependencies"), rel)
                elif fn == "yarn.lock":
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        out += _yarn_lock(fh.read(), rel)
                elif fn == "pnpm-lock.yaml":
                    with open(p, encoding="utf-8") as fh:
                        out += _pnpm_lock(fh.read(), rel)
                elif fn in ("poetry.lock", "uv.lock", "pdm.lock"):
                    out += _python_toml_lock(p, rel, fn)
                elif fn == "Pipfile.lock":
                    with open(p, encoding="utf-8") as fh:
                        data = _lock_json(fh, "default", "develop", "_meta")
                    for sect, scope in (("default", "transitive"), ("develop", "dev")):
                        for n, v in (data.get(sect) or {}).items():
                            if str(v.get("version", "")).startswith("=="):
                                out.append(_c("pypi", n, v["version"][2:], rel, scope))
                elif fn == "Cargo.lock":
                    out += _cargo_lock(p, rel)
                elif fn == "composer.lock":
                    with open(p, encoding="utf-8") as fh:
                        data = _lock_json(fh, "packages", "packages-dev")
                    for section, scope in (("packages", "transitive"), ("packages-dev", "dev")):
                        for item in data.get(section) or []:
                            if item.get("name") and item.get("version"):
                                component = _c("composer", item["name"], str(item["version"]).lstrip("v"), rel, scope)
                                declared = item.get("license")
                                if isinstance(declared, list) and len(declared) == 1:
                                    _record_lock_licence(component, declared[0])
                                out.append(component)
                elif fn == "Gemfile.lock":
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        out += _gem_lock(fh.read(), rel)
                elif fn == "gradle.lockfile":
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        out += _gradle_lock(fh.read(), rel)
                elif fn == "packages.lock.json":
                    with open(p, encoding="utf-8") as fh:
                        out += _nuget_lock(_lock_json(fh, "dependencies"), rel)
                elif fn == "packages.config":
                    out += _nuget_packages_config(p, rel)
                elif fn == "mix.lock":
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        out += _mix_lock(fh.read(), rel)
                elif fn == "pubspec.lock":
                    with open(p, encoding="utf-8") as fh:
                        out += _pubspec_lock(fh.read(), rel)
                elif fn == "Podfile.lock":
                    with open(p, encoding="utf-8") as fh:
                        out += _podfile_lock(fh.read(), rel)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, ImportError, ET.ParseError):
                current_status()["errors"].add(f"lockfile parse: {rel}")
                continue
    # Keep one exact component per ecosystem/name/version while preserving all source paths.
    unique, by_key = [], {}
    for component in out:
        key = (component["ecosystem"], component["name"], component["version"])
        if key not in by_key:
            by_key[key] = component
            component["evidence_files"] = [component["file"]]
            unique.append(component)
        else:
            primary = by_key[key]
            if component["file"] not in primary["evidence_files"]:
                primary["evidence_files"].append(component["file"])
            if "lock_licences" in primary or "lock_licences" in component:
                primary["lock_licences"] = sorted(set(primary.get("lock_licences", ())) | set(component.get("lock_licences", ())))
            if primary["scope"] in {"dev", "optional"} and component["scope"] in {"required", "transitive"}:
                primary["scope"] = component["scope"]
    return unique


def _python_toml_lock(path, rel, kind):
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            current_status()["errors"].add(f"TOML lock parser unavailable: {rel}")
            return []
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    out = []
    for item in data.get("package") or []:
        name, version = item.get("name"), item.get("version")
        if not name or not version:
            continue
        source = item.get("source") or {}
        # Workspace/editable/path dependencies are first-party local code, not registry packages.
        if any(key in source for key in ("editable", "directory", "path")) or source.get("type") in ("directory", "file", "path"):
            continue
        groups = item.get("groups") or []
        category = item.get("category")
        dev = category == "dev" or (bool(groups) and all(g not in ("default", "main") for g in groups))
        out.append(_c("pypi", name, str(version), rel, "dev" if dev else "transitive"))
    return out


def _nuget_packages_config(path, rel):
    root = ET.parse(path).getroot()
    out = []
    for item in root.findall(".//package"):
        name, version = item.get("id"), item.get("version")
        if name and version:
            scope = "dev" if item.get("developmentDependency", "").lower() == "true" else "transitive"
            out.append(_c("nuget", name, version, rel, scope))
    return out

def _pnpm_lock(text, rel):
    try:
        import yaml
        data = yaml.safe_load(text) or {}
    except Exception as exc:
        current_status()["errors"].add(f"pnpm lock parse: {rel}: {type(exc).__name__}")
        return []
    out = []
    packages = data.get("packages") or {}
    for raw_key, meta in packages.items():
        key = str(raw_key)
        # pnpm v5/v6: /name/version; pnpm v8+: name@version (peer suffix optional).
        key = re.sub(r"\([^)]*\)$", "", key)
        if key.startswith("/"):
            parts = key.strip("/").split("/")
            if len(parts) >= 3 and parts[0].startswith("@"):
                name, version = "/".join(parts[:2]), parts[2]
            elif len(parts) >= 2:
                name, version = parts[0], parts[1]
            else:
                continue
        elif key.startswith("@"):
            marker = key.rfind("@")
            if marker <= key.find("/"):
                continue
            name, version = key[:marker], key[marker + 1:]
        else:
            marker = key.rfind("@")
            if marker <= 0:
                continue
            name, version = key[:marker], key[marker + 1:]
        version = version.split("_", 1)[0]
        if name and version and re.match(r"^[0-9]", version):
            dev = bool((meta or {}).get("dev"))
            out.append(_c("npm", name, version, rel, "dev" if dev else "transitive"))
    # v9 stores package snapshots separately; packages remains authoritative for package identity.
    return out


def _cargo_lock(path, rel):
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            current_status()["errors"].add(f"cargo lock parser unavailable: {rel}")
            return []
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    return [_c("cargo", item["name"], str(item["version"]), rel, "transitive")
            for item in data.get("package") or []
            if item.get("name") and item.get("version") and item.get("source", "").startswith("registry+")]


def _gem_lock(text, rel):
    out, in_specs = [], False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        if not in_specs:
            continue
        match = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)", line)
        if match:
            out.append(_c("gem", match.group(1), match.group(2), rel, "transitive"))
    return out


def _gradle_lock(text, rel):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        coordinate = line.split("=", 1)[0]
        parts = coordinate.split(":")
        if len(parts) == 3 and all(parts):
            out.append(_c("maven", f"{parts[0]}:{parts[1]}", parts[2], rel, "transitive"))
    return out


def _nuget_lock(data, rel):
    out = []
    for framework, packages in (data.get("dependencies") or {}).items():
        if not isinstance(packages, dict):
            continue
        for name, meta in packages.items():
            version = (meta or {}).get("resolved") or (meta or {}).get("version")
            if version:
                out.append(_c("nuget", name, str(version).split(",", 1)[0], rel,
                              "dev" if (meta or {}).get("type") == "Direct" else "transitive"))
    return out

def _record_lock_licence(component, declared):
    if isinstance(declared, str) and declared.strip():
        component["lock_licences"] = [declared.strip()]


def _npm_lock(data, rel):
    out = []
    packages = data.get("packages")
    if packages is not None:
        root = packages.get("") or {}
        direct = set((root.get("dependencies") or {}).keys()) | set((root.get("optionalDependencies") or {}).keys())
        dev = set((root.get("devDependencies") or {}).keys())
        optional = set((root.get("optionalDependencies") or {}).keys())
        for path, meta in packages.items():
            if not path or "node_modules/" not in path or not (meta or {}).get("version"):
                continue
            name = (meta or {}).get("name") or path.split("node_modules/")[-1]
            meta = meta or {}
            # Lockfile package metadata is authoritative for dev/optional entries even
            # when older or hand-authored lockfiles omit root dependency declarations.
            if name in optional or meta.get("optional"):
                scope = "optional"
            elif name in dev or meta.get("dev"):
                scope = "dev"
            elif path == f"node_modules/{name}" and name in direct:
                scope = "required"
            else:
                scope = "transitive"
            component = _c("npm", name, meta["version"], rel, scope)
            _record_lock_licence(component, meta.get("license"))
            out.append(component)
    else:  # lockfile v1: first-level entries are direct dependencies.
        def walk(deps, depth=0):
            for name, meta in (deps or {}).items():
                if (meta or {}).get("version"):
                    scope = ("dev" if meta.get("dev") else "optional" if meta.get("optional") else "required") if depth == 0 else "transitive"
                    component = _c("npm", name, meta["version"], rel, scope)
                    _record_lock_licence(component, meta.get("license"))
                    out.append(component)
                walk((meta or {}).get("dependencies"), depth + 1)
        walk(data.get("dependencies"))
    return out

def _yarn_lock(text, rel):
    out = []
    for m in re.finditer(r'^"?((?:@[^@/\s"]+/)?[^@\s"]+)@[^\n]*:\n\s+version:? "?([^"\n]+)"?', text, re.M):
        out.append(_c("npm", m.group(1), m.group(2), rel, "transitive"))
    return out



def _mix_lock(text, rel):
    """Parse Hex package records from Elixir's mix.lock."""
    out = []
    for name, version in re.findall(r'"([^"]+)"\s*:\s*\{:\w+,\s*:\w+,\s*"([^"]+)"', text):
        if name and version:
            out.append(_c("hex", name, version, rel, "transitive"))
    return out


def _pubspec_lock(text, rel):
    """Parse Dart pubspec.lock package entries (YAML)."""
    try:
        import yaml
        data = yaml.safe_load(text) or {}
    except Exception as exc:
        current_status()["errors"].add(f"pubspec lock parse: {rel}: {type(exc).__name__}")
        return []
    out = []
    for name, meta in (data.get("packages") or {}).items():
        if not isinstance(meta, dict) or not meta.get("version"):
            continue
        source = meta.get("source", "hosted")
        if source in ("sdk", "path", "git"):
            continue
        out.append(_c("pub", name, str(meta["version"]), rel, "transitive"))
    return out


def _podfile_lock(text, rel):
    """Parse the PODS section of CocoaPods lockfiles, retaining exact pod versions."""
    out = []
    in_pods = False
    for line in text.splitlines():
        if line.strip() == "PODS:":
            in_pods = True
            continue
        if in_pods and line and not line.startswith(" "):
            break
        if not in_pods:
            continue
        match = re.match(r"^\s*-\s+([A-Za-z0-9_.+/-]+)(?:\s+\(([^)]+)\))?", line)
        if match and match.group(2):
            name = match.group(1).split("/", 1)[0]
            out.append(_c("cocoapods", name, match.group(2), rel, "transitive"))
    return out

def _c(eco, name, version, file, scope, via=None):
    name = norm_name(eco, name)
    if not name or (version is not None and (not isinstance(version, str) or not version.strip())):
        raise ValueError("invalid component name or version")
    return {"ecosystem": eco, "name": name, "version": version, "file": file, "scope": scope, "via": via,
            "license": "unknown", "purl": f"pkg:{eco}/{name.replace(':', '/')}@{version}"}


# ------------------------------------------------------------------ PyPI transitive resolution
def _pypi_release(name, version):
    return _http_json(f"{PYPI_URL}/pypi/{name}/{version}/json")


def _pypi_project(name):
    return _http_json(f"{PYPI_URL}/pypi/{name}/json")


def resolve_pypi(direct: list[dict]) -> list[dict]:
    """Breadth-first resolution of the dependencies of pinned Python requirements (needs `packaging`)."""
    try:
        from packaging.markers import default_environment
        from packaging.requirements import InvalidRequirement, Requirement
        from packaging.version import InvalidVersion, Version
    except ImportError:
        return []
    env = default_environment()
    seen = {c["name"] for c in direct}
    queue = [(c["name"], c["version"], c.get("extras") or set(), c["name"], c["file"]) for c in direct]
    out = []
    while queue and len(out) < MAX_TRANSITIVE:
        batch, queue = queue[:16], queue[16:]
        with ThreadPoolExecutor(max_workers=8) as ex:
            metas = list(scan_map(ex, lambda q: _safe(_pypi_release, q[0], q[1]), batch))
        for (name, version, extras, root, file), meta in zip(batch, metas):
            reqs = ((meta or {}).get("info") or {}).get("requires_dist") or []
            for raw in reqs:
                try:
                    r = Requirement(raw)
                except InvalidRequirement:
                    continue
                if r.marker and not any(r.marker.evaluate({**env, "extra": e}) for e in (extras or {""}) | {""}):
                    continue
                dep = norm_name("pypi", r.name)
                if dep in seen:
                    continue
                proj = _safe(_pypi_project, dep)
                if not proj:
                    continue
                best = None
                for v, files in (proj.get("releases") or {}).items():
                    try:
                        pv = Version(v)
                    except InvalidVersion:
                        continue
                    if pv.is_prerelease or not files or all(f.get("yanked") for f in files):
                        continue
                    if r.specifier.contains(pv) and (best is None or pv > best):
                        best = pv
                if best is None:
                    continue
                seen.add(dep)
                out.append(_c("pypi", dep, str(best), file, "transitive", via=root))
                queue.append((dep, str(best), set(r.extras), root, file))
    return out


def _safe(fn, *a):
    try:
        return fn(*a)
    except Exception as e:  # noqa: BLE001 - network intelligence is best effort
        current_status()["errors"].add(f"{fn.__name__}: {type(e).__name__}")
        return None


# ------------------------------------------------------------------ licences
SPDX_FROM_CLASSIFIER = {"MIT License": "MIT", "BSD License": "BSD-3-Clause", "Apache Software License": "Apache-2.0",
                        "GNU General Public License v3 (GPLv3)": "GPL-3.0", "GNU General Public License v2 (GPLv2)": "GPL-2.0",
                        "GNU Affero General Public License v3": "AGPL-3.0", "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
                        "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1", "ISC License (ISCL)": "ISC",
                        "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0", "Python Software Foundation License": "PSF-2.0",
                        "The Unlicense (Unlicense)": "Unlicense"}


def licence(c) -> str:
    if c["ecosystem"] == "pypi":
        info = ((_safe(_pypi_release, c["name"], c["version"]) or {}).get("info") or {})
        if info.get("license_expression"):
            return info["license_expression"]
        for cl in info.get("classifiers") or []:
            if cl.startswith("License :: OSI Approved :: ") or cl.startswith("License :: "):
                k = cl.split(" :: ")[-1]
                if k in SPDX_FROM_CLASSIFIER:
                    return SPDX_FROM_CLASSIFIER[k]
        lic = (info.get("license") or "").strip()
        if lic and len(lic) <= 40 and "\n" not in lic:
            return lic
    elif c["ecosystem"] == "npm":
        meta = _safe(_http_json, f"{NPM_URL}/{c['name'].replace('/', '%2F')}/{c['version']}") or {}
        lic = meta.get("license")
        if isinstance(lic, dict):
            lic = lic.get("type")
        if isinstance(lic, str) and lic:
            return lic
    return "unknown"


# ------------------------------------------------------------------ vulnerabilities
def _cvss3(vector: str):
    """CVSS v3.x base score from a vector string."""
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        if imp <= 0:
            return 0.0
        exp = 8.22 * av * ac * pr * ui
        base = min(1.08 * (imp + exp), 10) if changed else min(imp + exp, 10)
        return math.ceil(base * 10 - 1e-9) / 10
    except (KeyError, ValueError):
        return None


def _severity_of(v: dict):
    score = None
    for s in v.get("severity") or []:
        if s.get("type", "").startswith("CVSS_V3"):
            score = _cvss3(s.get("score", ""))
    label = ((v.get("database_specific") or {}).get("severity") or "").upper()
    if score is None and label:
        score = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}.get(label)
    if score is None:
        return None, "unknown"
    return score, "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _fixed_for(v, eco, name):
    fixed = []
    for a in v.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") != OSV_ECO.get(eco) or norm_name(eco, pkg.get("name", "")) != name:
            continue
        for rg in a.get("ranges") or []:
            fixed += [e["fixed"] for e in rg.get("events") or [] if "fixed" in e]
    return fixed


def _osv(comps):
    """Map component indexes to advisory details; record incomplete pages separately."""
    queries = [{"package": {"name": c["name"], "ecosystem": OSV_ECO[c["ecosystem"]]}, "version": c["version"]}
               for c in comps if c["ecosystem"] in OSV_ECO]
    idx = [i for i, c in enumerate(comps) if c["ecosystem"] in OSV_ECO]
    if not queries:
        return {}
    hits = {}
    for start in range(0, len(queries), 500):
        pending = list(zip(idx[start:start + 500], queries[start:start + 500]))
        seen_tokens = set()
        for _ in range(20):
            try:
                res = _http_json(f"{OSV_URL}/v1/querybatch", {"queries": [q for _, q in pending]}, ttl=6 * 3600)
            except (OSError, ValueError, http.client.HTTPException) as exc:
                current_status()["errors"].add(f"OSV query failed: {type(exc).__name__}")
                break
            results = res.get("results") if isinstance(res, dict) else None
            if not isinstance(results, list) or len(results) != len(pending):
                current_status()["errors"].add("OSV returned an incomplete batch")
                break
            current_status()["sources"].add("OSV")
            following = []
            for (i, query), result in zip(pending, results):
                summaries = result.get("vulns", []) if isinstance(result, dict) else None
                if not isinstance(summaries, list) or any(
                    not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"] for v in summaries
                ):
                    current_status()["errors"].add("OSV returned an invalid package result")
                    continue
                hits.setdefault(i, set()).update(v["id"] for v in summaries)
                token = result.get("next_page_token")
                if token:
                    if not isinstance(token, str) or (i, token) in seen_tokens:
                        current_status()["errors"].add("OSV returned an invalid or repeated page token")
                    else:
                        seen_tokens.add((i, token))
                        following.append((i, {**query, "page_token": token}))
            if not following:
                break
            pending = following
        else:
            current_status()["errors"].add("OSV advisory pagination limit reached")
    all_ids = sorted({i for v in hits.values() for i in v})
    with ThreadPoolExecutor(max_workers=8) as ex:
        docs = dict(zip(all_ids, scan_map(ex, lambda i: _safe(_http_json, f"{OSV_URL}/v1/vulns/{urllib.parse.quote(i, safe='')}"), all_ids)))
    usable = {i: doc for i, doc in docs.items() if isinstance(doc, dict) and doc.get("id") == i}
    if len(usable) != len(docs):
        current_status()["errors"].add("OSV advisory details missing or invalid")
    return {k: [usable[i] for i in sorted(v) if i in usable and not usable[i].get("withdrawn")] for k, v in hits.items()}


def _pypi_vulns(c):
    meta = _safe(_pypi_release, c["name"], c["version"])
    if not isinstance(meta, dict) or not isinstance(meta.get("vulnerabilities", []), list):
        current_status()["errors"].add("PyPI advisory response missing or invalid for one or more packages")
        return []
    current_status()["sources"].add("PyPI advisory database")
    out = []
    for v in meta.get("vulnerabilities") or []:
        if not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"]:
            current_status()["errors"].add("PyPI returned an invalid advisory")
            continue
        if v.get("withdrawn"):
            continue
        out.append({"id": v["id"], "aliases": v.get("aliases") or [], "summary": v.get("summary") or v.get("details", "")[:160],
                    "details": v.get("details", ""), "_fixed": v.get("fixed_in") or [], "severity": [], "database_specific": {}})
    return out


# ------------------------------------------------------------------ offline OSV exports (air-gapped)
OSV_EXPORT_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
OSV_EXPORT_MANIFEST = "manifest.json"
OSV_EXPORT_SCHEMA = 1
_EXPORT = {"signature": None, "index": None}


def _export_index():
    """Load only archives declared in a checksum-verified OSV export manifest."""
    d = os.environ.get("MYELIN_OSV_EXPORT_DIR")
    if not d:
        return None
    import zipfile
    try:
        manifest_path = os.path.join(d, OSV_EXPORT_MANIFEST)
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        if manifest.get("schema_version") != OSV_EXPORT_SCHEMA:
            raise ValueError("unsupported OSV export manifest schema")
        generated = manifest.get("generated_at")
        if not generated:
            raise ValueError("OSV export manifest has no generated_at timestamp")
        generated_at = time.strptime(generated, "%Y-%m-%dT%H:%M:%SZ")
        if time.strftime("%Y-%m-%dT%H:%M:%SZ", generated_at) != generated:
            raise ValueError("OSV export generated_at must be a UTC timestamp")
        age_days = (time.time() - calendar.timegm(generated_at)) / 86400
        # Small clock skew is tolerated, but future-dated bundles must not bypass
        # the freshness policy or make a stale export appear current.
        if age_days < -(5 / 1440):
            raise ValueError("OSV export generated_at is in the future")
        max_age = os.environ.get("MYELIN_OSV_MAX_AGE_DAYS")
        if max_age is not None:
            try:
                max_age_days = float(max_age)
            except (TypeError, ValueError):
                raise ValueError("MYELIN_OSV_MAX_AGE_DAYS must be a non-negative number")
            if not math.isfinite(max_age_days) or max_age_days < 0:
                raise ValueError("MYELIN_OSV_MAX_AGE_DAYS must be a non-negative number")
            if age_days > max_age_days:
                raise ValueError(f"OSV export is stale ({age_days:.1f} days; maximum {max_age})")
        entries = manifest.get("archives")
        if not isinstance(entries, list) or not entries:
            raise ValueError("OSV export manifest contains no archives")
        rows, declared = [], set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("invalid OSV export manifest entry")
            name, expected, ecosystem = entry.get("file"), entry.get("sha256"), entry.get("ecosystem")
            if (not isinstance(name, str) or not name or os.path.basename(name) != name
                    or not name.endswith(".zip") or not isinstance(expected, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{64}", expected)):
                raise ValueError("invalid OSV export manifest entry")
            if ecosystem not in OSV_ECO.values():
                raise ValueError("unsupported ecosystem in OSV export manifest")
            if name in declared:
                raise ValueError("duplicate OSV export archive entry")
            declared.add(name)
            path = os.path.join(d, name)
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                raise ValueError("OSV export checksum mismatch: " + name)
            if entry.get("size_bytes") is not None and os.path.getsize(path) != entry["size_bytes"]:
                raise ValueError("OSV export size mismatch: " + name)
            rows.append((name, os.path.getsize(path), os.stat(path).st_mtime_ns, expected, ecosystem))
        actual = {fn for fn in os.listdir(d) if fn.endswith(".zip")}
        if actual != declared:
            raise ValueError("OSV export archive set does not match manifest")
        signature = hashlib.sha256((os.path.realpath(d) + json.dumps(sorted(rows))).encode()).hexdigest()
        ecosystems = {e["ecosystem"] for e in entries}
        cached = _EXPORT.copy()
        idx = cached["index"] if cached["signature"] == signature else None
        if idx is None:
            idx = _index_osv_archives(d, entries)
            _EXPORT.update(signature=signature, index=idx)
        current_status()["sources"].update({"OSV offline export", "OSV export manifest verified",
                                            "OSV export generated: " + generated,
                                            "OSV export ecosystems: " + ", ".join(sorted(ecosystems))})
        current_status()["offline_ecosystems"] = ecosystems
        return idx
    except (OSError, ValueError, TypeError, KeyError, AttributeError, zipfile.BadZipFile) as exc:
        current_status()["errors"].add("offline OSV export invalid: " + str(exc)[:180])
        return None


def _index_osv_archives(directory, entries):
    import zipfile

    idx = {}
    for entry in entries:
        with zipfile.ZipFile(os.path.join(directory, entry["file"])) as archive:
            bad = archive.testzip()
            if bad:
                raise ValueError("corrupt OSV archive member: " + bad)
            for member in archive.namelist():
                if not member.endswith(".json"):
                    continue
                doc = json.loads(archive.read(member))
                for affected_item in doc.get("affected") or []:
                    pkg = affected_item.get("package") or {}
                    eco = next((key for key, value in OSV_ECO.items() if value == pkg.get("ecosystem")), None)
                    if eco:
                        idx.setdefault((eco, norm_name(eco, pkg.get("name", ""))), []).append(doc)
    return idx


def _vkey(eco, v):
    if eco == "pypi":
        try:
            from packaging.version import Version
            return (0, Version(str(v)))
        except Exception:  # noqa: BLE001 - not PEP 440: fall through to the generic order
            pass
    parts = re.split(r"[.\-+]", re.sub(r"^[vV]", "", str(v)))
    return (1, tuple((0, int(x)) if x.isdigit() else (1, x) for x in parts))


def _cmp(eco, a, b):
    ka, kb = _vkey(eco, a), _vkey(eco, b)
    if ka[0] != kb[0]:                                           # mixed schemes: compare generically
        ka, kb = _vkey("generic", a), _vkey("generic", b)
    return (ka > kb) - (ka < kb)


def affected(doc: dict, eco: str, name: str, version: str) -> bool:
    """Does an OSV record affect this exact version? (explicit version list, then ECOSYSTEM / SEMVER ranges)."""
    for a in doc.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") != OSV_ECO.get(eco) or norm_name(eco, pkg.get("name", "")) != name:
            continue
        if version in (a.get("versions") or []):
            return True
        for rg in a.get("ranges") or []:
            if rg.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            inside = False
            for ev in rg.get("events") or []:
                if "introduced" in ev and (ev["introduced"] == "0" or _cmp(eco, version, ev["introduced"]) >= 0):
                    inside = True
                if "fixed" in ev and _cmp(eco, version, ev["fixed"]) >= 0:
                    inside = False
                if "last_affected" in ev and _cmp(eco, version, ev["last_affected"]) > 0:
                    inside = False
            if inside:
                return True
    return False


def _offline_osv(comps):
    idx = _export_index()
    if idx is None:
        return None
    provided = current_status().get("offline_ecosystems") or set()
    required = {OSV_ECO.get(c["ecosystem"], c["ecosystem"]) for c in comps}
    if missing := sorted(required - provided):
        current_status()["errors"].add("offline OSV export missing ecosystems: " + ", ".join(missing))
    out = {}
    for i, c in enumerate(comps):
        docs = [d for d in idx.get((c["ecosystem"], c["name"]), []) if not d.get("withdrawn") and affected(d, c["ecosystem"], c["name"], str(c["version"]))]
        if docs:
            out[i] = list({d["id"]: d for d in docs}.values())
    return out


def download_exports(dest: str, ecosystems=tuple(OSV_ECO.values())) -> list[str]:
    """Download supported OSV ecosystem archives and write a verifiable bundle manifest."""
    os.makedirs(dest, exist_ok=True)
    got, entries = [], []
    for eco in ecosystems:
        if eco not in OSV_ECO.values():
            raise ValueError("unsupported OSV ecosystem: " + str(eco))
        filename = eco.replace("/", "_") + ".zip"
        path = os.path.join(dest, filename)
        url = f"{OSV_EXPORT_BASE}/{urllib.parse.quote(eco, safe='')}/all.zip"
        req = urllib.request.Request(url, headers={"User-Agent": "NERvvE-DevSecOps"})
        with urllib.request.urlopen(req, timeout=300) as response, open(path + ".part", "wb") as fh:  # myelin:ignore[NM-SAST-010] -- fixed OSV export host
            shutil_copy(response, fh)
        os.replace(path + ".part", path)
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        entries.append({"ecosystem": eco, "file": filename, "sha256": digest.hexdigest(),
                        "size_bytes": os.path.getsize(path)})
        got.append(path)
    manifest = {"schema_version": OSV_EXPORT_SCHEMA, "source": "OSV ecosystem exports",
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "archives": entries}
    temporary = os.path.join(dest, OSV_EXPORT_MANIFEST + ".part")
    with open(temporary, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(temporary, os.path.join(dest, OSV_EXPORT_MANIFEST))
    _EXPORT.update(signature=None, index=None)
    return got


def shutil_copy(src, dst, n=1 << 20):
    while True:
        b = src.read(n)
        if not b:
            break
        dst.write(b)


def vulnerabilities(comps: list[dict]) -> list[tuple[dict, dict]]:
    """Return merged OSV and PyPI advisory evidence.

    PyPI is queried for every Python component even when OSV responds successfully:
    OSV and registry advisory datasets can differ, so a successful OSV response is
    not proof that its result set is exhaustive for the package ecosystem.
    """
    if not comps:
        return []
    if offline():
        found = _offline_osv(comps)
        if found is None:
            if not os.environ.get("MYELIN_OSV_EXPORT_DIR"):
                current_status()["errors"].add("offline: no OSV export configured")
            return []
        normalised = _normalise([(comps[i], v) for i, docs in found.items() for v in docs])
        # Offline mode uses only locally cached enrichment; _http_json never reaches the network offline.
        normalised = _enrich_threat_intel(normalised)
        return normalised

    pairs = [(comps[i], v) for i, docs in _osv(comps).items() for v in docs]

    # Independent PyPI enrichment avoids the previous blind spot where a reachable
    # but incomplete OSV response suppressed PyPI-only advisories.
    for c in comps:
        if c.get("ecosystem") == "pypi":
            pairs.extend((c, v) for v in _pypi_vulns(c))

    normalised = _normalise(pairs)
    normalised = _enrich_threat_intel(normalised)
    unique, seen = [], set()
    for component, advisory in normalised:
        key = (component.get("ecosystem"), component.get("name"), component.get("version"),
               advisory.get("id") or advisory.get("cve"))
        if key in seen:
            continue
        seen.add(key)
        unique.append((component, advisory))
    return unique


EPSS_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = os.environ.get("MYELIN_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0").rstrip("/")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
_THREAT_INTEL = {"kev": None}


def _nvd_cvss(cve_item):
    """Return the strongest published NVD CVSS record without inventing a score."""
    metrics = cve_item.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        metric = rows[0].get("cvssData") or {}
        score = metric.get("baseScore")
        if score is not None:
            return {"version": metric.get("version"), "score": score,
                    "severity": metric.get("baseSeverity") or rows[0].get("baseSeverity"),
                    "vector": metric.get("vectorString")}
    return {}


def _nvd_record(cve):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    url = NVD_API_URL + "?" + urllib.parse.urlencode({"cveId": cve})
    data = _http_json(url, ttl=24 * 3600, headers=headers)
    if not data:
        return None
    records = data.get("vulnerabilities") or []
    if not records:
        return None
    c = records[0].get("cve") or {}
    weaknesses = []
    for weakness in c.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in weaknesses:
                weaknesses.append(value)
    references = c.get("references") or []
    refs = [r.get("url") for r in references if r.get("url")]
    tagged = {"exploit": [], "patch": [], "third_party_advisory": []}
    for ref in references:
        url = ref.get("url")
        if not url:
            continue
        tags = {str(tag).lower() for tag in ref.get("tags") or []}
        if "exploit" in tags:
            tagged["exploit"].append(url)
        if "patch" in tags:
            tagged["patch"].append(url)
        if "third party advisory" in tags:
            tagged["third_party_advisory"].append(url)
    metrics = c.get("metrics") or {}
    # NVD added structured SSVC and CVE-record affected-product data in 2026.
    # Preserve source payloads rather than guessing a priority from unknown fields.
    ssvc = metrics.get("ssvcMetricV203") or metrics.get("ssvcMetricV2") or []
    affected = c.get("affected") or []
    return {"cvss": _nvd_cvss(c), "cwes": weaknesses, "published": c.get("published"),
            "modified": c.get("lastModified"), "references": refs[:30], "reference_types": tagged,
            "ssvc": ssvc, "affected_products": affected[:100],
            "cisa_exploit_add": c.get("cisaExploitAdd"), "cisa_action_due": c.get("cisaActionDue"),
            "cisa_required_action": c.get("cisaRequiredAction"),
            "cisa_vulnerability_name": c.get("cisaVulnerabilityName"),
            "source": "NVD", "vuln_status": c.get("vulnStatus")}

def _enrich_nvd(pairs, cves):
    """Add NVD CVSS vectors, CWE mappings and reference metadata; OSV remains authoritative for package ranges."""
    records = {}
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(scan_map(pool, _safe, [lambda c=c: _nvd_record(c) for c in cves]))
        records = {c: r for c, r in zip(cves, results) if r}
        if any(r is not None for r in results):
            current_status()["sources"].add("NVD CVE API 2.0")
        if any(r is None for r in results):
            # A valid no-record response is not a feed failure. Only transport errors
            # are exposed by _safe as None, so do not infer completeness from record count.
            pass
    except Exception as exc:
        current_status()["errors"].add(f"NVD enrichment unavailable: {type(exc).__name__}")
        return pairs

    enriched = []
    for component, advisory in pairs:
        item = dict(advisory)
        record = records.get(item.get("cve"))
        if record:
            item["nvd"] = record
            if record.get("cvss", {}).get("score") is not None:
                item["nvd_cvss"] = record["cvss"]
                if item.get("cvss") is None:
                    item["cvss"] = record["cvss"]["score"]
                    item["severity"] = str(record["cvss"].get("severity") or "UNKNOWN").lower()
                    item["severity_known"] = True
            if record.get("cwes"):
                item["cwes"] = sorted(set((item.get("cwes") or []) + record["cwes"]))
            if not item.get("cwe") and record.get("cwes"):
                item["cwe"] = record["cwes"][0]
            item["references"] = list(dict.fromkeys((item.get("references") or []) + record.get("references", [])))[:30]
        enriched.append((component, item))
    return enriched


def _enrich_threat_intel(pairs):
    """Enrich CVE-backed findings with EPSS, CISA KEV and NVD evidence.

    Each source is independently cached. Missing enrichment remains unknown, never
    represented as EPSS=0 or KEV=false. OSV affected ranges remain the package-match authority.
    """
    cves = sorted({str(v.get("cve")) for _, v in pairs if str(v.get("cve") or "").startswith("CVE-")})
    if not cves:
        return pairs
    epss = {}
    try:
        for start in range(0, len(cves), 100):
            data = _http_json(EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(cves[start:start + 100])}), ttl=6 * 3600)
            if data is None:
                raise RuntimeError("EPSS feed unavailable")
            for row in data.get("data") or []:
                try:
                    epss[row["cve"]] = {"score": float(row["epss"]), "percentile": float(row["percentile"])}
                except (KeyError, TypeError, ValueError):
                    continue
        current_status()["sources"].add("FIRST EPSS")
    except Exception as exc:
        current_status()["errors"].add(f"EPSS enrichment unavailable: {type(exc).__name__}")

    kev_records = _THREAT_INTEL.get("kev")
    kev_available = kev_records is not None
    if not kev_available:
        try:
            data = _http_json(CISA_KEV_URL, ttl=6 * 3600)
            if data is None:
                raise RuntimeError("CISA KEV feed unavailable")
            kev_records = {str(row.get("cveID")): {k: row.get(k) for k in (
                "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate",
                "requiredAction", "knownRansomwareCampaignUse", "notes")}
                for row in data.get("vulnerabilities") or [] if row.get("cveID")}
            _THREAT_INTEL["kev"] = kev_records
            kev_available = True
            current_status()["sources"].add("CISA KEV")
        except Exception as exc:
            current_status()["errors"].add(f"CISA KEV enrichment unavailable: {type(exc).__name__}")
            kev_records = {}

    enriched = []
    for component, advisory in pairs:
        item = dict(advisory)
        cve = item.get("cve")
        if cve in epss:
            item["epss"] = epss[cve]["score"]
            item["epss_percentile"] = epss[cve]["percentile"]
        if kev_available and cve:
            item["kev"] = cve in kev_records
            if cve in kev_records:
                item["kev_details"] = kev_records[cve]
        enriched.append((component, item))
    return _enrich_nvd(enriched, cves)


def _normalise(pairs):
    out = []
    for c, v in pairs:
        cvss, sev = _severity_of(v)
        aliases = v.get("aliases") or []
        ids = [v.get("id", "")] + aliases + (v.get("upstream") or []) + (v.get("related") or [])
        cve = next((a for a in ids if str(a).startswith("CVE-")), None)
        fixed = v.get("_fixed") or _fixed_for(v, c["ecosystem"], c["name"])
        cwe = next(iter((v.get("database_specific") or {}).get("cwe_ids") or []), None)
        out.append((c, {"id": v["id"], "cve": cve, "aliases": aliases, "cvss": cvss, "severity": sev,
                        "severity_known": cvss is not None,
                        "summary": _summary(v),
                        "fixed": _lowest_above(fixed, c["version"]), "cwe": cwe}))
    return out


def _summary(v):
    """One readable sentence: the advisory summary, or the first prose line of its markdown details."""
    if v.get("summary") and not v["summary"].lstrip().startswith("#"):
        return v["summary"].strip()[:200]
    for line in (v.get("details") or "").splitlines():
        line = re.sub(r"[*_`]+", "", line).strip()
        if line and not line.startswith("#") and len(line) > 15:
            return (line[:197] + "...") if len(line) > 200 else line
    return v.get("id", "")


def _lowest_above(fixed, current):
    try:
        from packaging.version import Version
        cand = sorted({Version(f) for f in fixed if Version(f) > Version(current)})
        return str(cand[0]) if cand else (fixed[0] if fixed else None)
    except Exception:  # noqa: BLE001 - non-PEP 440 versions (npm, maven): keep the first published fix
        return fixed[0] if fixed else None
