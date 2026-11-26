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
import hashlib
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

OSV_URL = os.environ.get("MYELIN_OSV_URL", "https://api.osv.dev").rstrip("/")
PYPI_URL = os.environ.get("MYELIN_PYPI_URL", "https://pypi.org").rstrip("/")
NPM_URL = os.environ.get("MYELIN_NPM_URL", "https://registry.npmjs.org").rstrip("/")
OSV_ECO = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "go": "Go", "cargo": "crates.io", "nuget": "NuGet",
           "gem": "RubyGems", "composer": "Packagist"}
CACHE_TTL = 24 * 3600
MAX_TRANSITIVE = 600
STATUS = {"sources": set(), "errors": set()}     # what the last scan could reach, shown in reports


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


def _http_json(url, body=None, ttl=CACHE_TTL):
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
                                          **({"Content-Type": "application/json"} if data else {})})
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
def parse_lockfiles(root: str) -> list[dict]:
    """Extract exact package versions from supported lockfiles.

    Each parser is isolated so one malformed/unsupported lockfile cannot discard
    inventory from other ecosystems. Components retain the source lockfile path.
    """
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".venv", "venv", "vendor"}]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            try:
                if fn in ("package-lock.json", "npm-shrinkwrap.json"):
                    with open(p, encoding="utf-8") as fh:
                        out += _npm_lock(json.load(fh), rel)
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
                        data = json.load(fh)
                    for sect, scope in (("default", "transitive"), ("develop", "dev")):
                        for n, v in (data.get(sect) or {}).items():
                            if str(v.get("version", "")).startswith("=="):
                                out.append(_c("pypi", n, v["version"][2:], rel, scope))
                elif fn == "Cargo.lock":
                    out += _cargo_lock(p, rel)
                elif fn == "composer.lock":
                    with open(p, encoding="utf-8") as fh:
                        data = json.load(fh)
                    for section, scope in (("packages", "transitive"), ("packages-dev", "dev")):
                        for item in data.get(section) or []:
                            if item.get("name") and item.get("version"):
                                out.append(_c("composer", item["name"], str(item["version"]).lstrip("v"), rel, scope))
                elif fn == "Gemfile.lock":
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        out += _gem_lock(fh.read(), rel)
                elif fn == "gradle.lockfile":
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        out += _gradle_lock(fh.read(), rel)
                elif fn == "packages.lock.json":
                    with open(p, encoding="utf-8") as fh:
                        out += _nuget_lock(json.load(fh), rel)
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
            except (OSError, ValueError, KeyError, TypeError, ImportError, ET.ParseError):
                STATUS["errors"].add(f"lockfile parse: {rel}")
                continue
    # Keep one exact component per ecosystem/name/version while preserving all source paths.
    unique, by_key = [], {}
    for component in out:
        key = (component["ecosystem"], component["name"], component["version"])
        if key not in by_key:
            by_key[key] = component
            component["evidence_files"] = [component["file"]]
            unique.append(component)
        elif component["file"] not in by_key[key]["evidence_files"]:
            by_key[key]["evidence_files"].append(component["file"])
    return unique


def _python_toml_lock(path, rel, kind):
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            STATUS["errors"].add(f"TOML lock parser unavailable: {rel}")
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
        STATUS["errors"].add(f"pnpm lock parse: {rel}: {type(exc).__name__}")
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
            STATUS["errors"].add(f"cargo lock parser unavailable: {rel}")
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
            if path == f"node_modules/{name}":
                scope = "optional" if name in optional else "dev" if name in dev else "required" if name in direct else "transitive"
            else:
                scope = "dev" if (meta or {}).get("dev") else "transitive"
            out.append(_c("npm", name, meta["version"], rel, scope))
    else:  # lockfile v1: first-level entries are direct dependencies.
        def walk(deps, depth=0):
            for name, meta in (deps or {}).items():
                if (meta or {}).get("version"):
                    scope = ("dev" if meta.get("dev") else "optional" if meta.get("optional") else "required") if depth == 0 else "transitive"
                    out.append(_c("npm", name, meta["version"], rel, scope))
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
    for name, version in re.findall(r'"([^"]+)"\s*:\s*\{:\w+,\s*:"([^"]+)"', text):
        if name and version:
            out.append(_c("hex", name, version, rel, "transitive"))
    return out


def _pubspec_lock(text, rel):
    """Parse Dart pubspec.lock package entries (YAML)."""
    try:
        import yaml
        data = yaml.safe_load(text) or {}
    except Exception as exc:
        STATUS["errors"].add(f"pubspec lock parse: {rel}: {type(exc).__name__}")
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
            metas = list(ex.map(lambda q: _safe(_pypi_release, q[0], q[1]), batch))
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
        STATUS["errors"].add(f"{fn.__name__}: {type(e).__name__}")
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
        return None, "medium"
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
    """{index: [osv vulnerability documents]} for components OSV knows about, or None if OSV is unreachable."""
    queries = [{"package": {"name": c["name"], "ecosystem": OSV_ECO[c["ecosystem"]]}, "version": c["version"]}
               for c in comps if c["ecosystem"] in OSV_ECO]
    idx = [i for i, c in enumerate(comps) if c["ecosystem"] in OSV_ECO]
    if not queries:
        return {}
    hits = {}
    try:
        for start in range(0, len(queries), 500):
            res = _http_json(f"{OSV_URL}/v1/querybatch", {"queries": queries[start:start + 500]}, ttl=6 * 3600)
            if res is None:
                return None
            for j, r in enumerate(res.get("results") or []):
                ids = [v["id"] for v in (r or {}).get("vulns") or []]
                if ids:
                    hits[idx[start + j]] = ids
    except Exception as e:  # noqa: BLE001
        STATUS["errors"].add(f"osv: {type(e).__name__}")
        return None
    STATUS["sources"].add("OSV")
    all_ids = sorted({i for v in hits.values() for i in v})
    with ThreadPoolExecutor(max_workers=8) as ex:
        docs = dict(zip(all_ids, ex.map(lambda i: _safe(_http_json, f"{OSV_URL}/v1/vulns/{i}"), all_ids)))
    return {k: [docs[i] for i in v if docs.get(i)] for k, v in hits.items()}


def _pypi_vulns(c):
    meta = _safe(_pypi_release, c["name"], c["version"])
    if meta is None:
        return []
    STATUS["sources"].add("PyPI advisory database")
    out = []
    for v in meta.get("vulnerabilities") or []:
        if v.get("withdrawn"):
            continue
        out.append({"id": v["id"], "aliases": v.get("aliases") or [], "summary": v.get("summary") or v.get("details", "")[:160],
                    "details": v.get("details", ""), "_fixed": v.get("fixed_in") or [], "severity": [], "database_specific": {}})
    return out


# ------------------------------------------------------------------ offline OSV exports (air-gapped)
OSV_EXPORT_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
_EXPORT = {"dir": None, "index": None}


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


def _export_index():
    d = os.environ.get("MYELIN_OSV_EXPORT_DIR")
    if not d:
        return None
    if _EXPORT["dir"] == d and _EXPORT["index"] is not None:
        return _EXPORT["index"]
    import zipfile
    idx = {}
    for dp, _, fns in os.walk(d):
        for fn in fns:
            if not fn.endswith(".zip"):
                continue
            try:
                with zipfile.ZipFile(os.path.join(dp, fn)) as z:
                    for member in z.namelist():
                        if not member.endswith(".json"):
                            continue
                        doc = json.loads(z.read(member))
                        for a in doc.get("affected") or []:
                            pkg = a.get("package") or {}
                            eco = next((k for k, v in OSV_ECO.items() if v == pkg.get("ecosystem")), None)
                            if eco:
                                idx.setdefault((eco, norm_name(eco, pkg.get("name", ""))), []).append(doc)
            except (OSError, ValueError, zipfile.BadZipFile) as e:
                STATUS["errors"].add(f"osv export {fn}: {type(e).__name__}")
    _EXPORT.update(dir=d, index=idx)
    return idx


def _offline_osv(comps):
    idx = _export_index()
    if idx is None:
        return None
    STATUS["sources"].add("OSV offline export")
    out = {}
    for i, c in enumerate(comps):
        docs = [d for d in idx.get((c["ecosystem"], c["name"]), []) if affected(d, c["ecosystem"], c["name"], str(c["version"]))]
        if docs:
            out[i] = list({d["id"]: d for d in docs}.values())
    return out


def download_exports(dest: str, ecosystems=("PyPI", "npm", "Maven", "Go", "crates.io", "NuGet", "RubyGems", "Packagist")) -> list[str]:
    """On a connected host: fetch the OSV ecosystem exports (all.zip) into dest for transfer to an air-gapped site."""
    os.makedirs(dest, exist_ok=True)
    got = []
    for eco in ecosystems:
        url = f"{OSV_EXPORT_BASE}/{urllib.request.quote(eco)}/all.zip"
        path = os.path.join(dest, f"{eco}.zip")
        req = urllib.request.Request(url, headers={"User-Agent": "NERvvE-DevSecOps"})
        with urllib.request.urlopen(req, timeout=300) as r, open(path + ".part", "wb") as fh:  # myelin:ignore[NM-SAST-010] -- fixed OSV export host
            shutil_copy(r, fh)
        os.replace(path + ".part", path)
        got.append(path)
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
            STATUS["errors"].add("offline: no OSV export configured")
            return []
        return _normalise([(comps[i], v) for i, docs in found.items() for v in docs])

    found = _osv(comps)
    pairs = []
    if found is not None:
        for i, docs in found.items():
            pairs.extend((comps[i], v) for v in docs)
    else:
        STATUS["errors"].add("OSV unavailable; using available ecosystem fallbacks")

    # Independent PyPI enrichment avoids the previous blind spot where a reachable
    # but incomplete OSV response suppressed PyPI-only advisories.
    for c in comps:
        if c.get("ecosystem") == "pypi":
            pairs.extend((c, v) for v in _pypi_vulns(c))

    normalised = _normalise(pairs)
    unique, seen = [], set()
    for component, advisory in normalised:
        key = (component.get("ecosystem"), component.get("name"), component.get("version"),
               advisory.get("id") or advisory.get("cve"))
        if key in seen:
            continue
        seen.add(key)
        unique.append((component, advisory))
    return unique

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
