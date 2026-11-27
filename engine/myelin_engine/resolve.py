# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Complete dependency inventory, the way build-integrated SCA tools see it.

RAT Flea's own parsers read manifests and lock files. This module adds what they cannot see:

* **Trivy SBOM** for every ecosystem Trivy understands (Maven with parent POMs, properties, BOMs and — when the network
  is available — transitive resolution from the Maven repository; Gradle lock files; NuGet central package management,
  packages.config, packages.lock.json and *.deps.json; Go, Ruby, PHP, Rust, Swift, Dart, Elixir, Conan, jars).
* **npm without a lock file**: the lock file npm would create (``npm install --package-lock-only --ignore-scripts``,
  in a scratch copy; no package scripts run and nothing is written to the repository).
* **Gradle without a lock file**: the declared dependencies (build.gradle, build.gradle.kts, version catalogs) written as
  a scratch pom.xml so Trivy resolves their transitive tree.
* **NuGet transitive dependencies** from the NuGet registration API (NuGet picks the lowest version that satisfies a
  range, so the resolver does the same).

Every step is optional: missing tools, no network or MYELIN_OFFLINE=1 simply leave the inventory as complete as the
files allow, and the gap is recorded in ``STATUS`` for the report.
"""
import gzip
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request

from . import vulndb

PURL_ECO = {"npm": "npm", "pypi": "pypi", "maven": "maven", "nuget": "nuget", "golang": "go", "cargo": "cargo",
            "gem": "gem", "composer": "composer", "hex": "hex", "pub": "pub", "swift": "swift", "cocoapods": "cocoapods",
            "conan": "conan"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "target", "bin", "obj", ".gradle"}
NUGET_URL = os.environ.get("MYELIN_NUGET_URL", "https://api.nuget.org").rstrip("/")
MAX_NUGET = 800


def _env():
    from .orchestrator import _tool_env
    return _tool_env()


def _purl_split(purl: str):
    """pkg:maven/org.apache/commons-text@1.9?type=jar -> ('maven', 'org.apache:commons-text', '1.9')"""
    m = re.match(r"pkg:([^/]+)/(.+)@([^?#]+)", purl or "")
    if not m:
        return None
    eco = PURL_ECO.get(m.group(1))
    if not eco:
        return None
    path = urllib.request.unquote(m.group(2))
    version = urllib.request.unquote(m.group(3))
    if eco == "maven":
        name = path.replace("/", ":", 1)
    elif eco == "go":
        version = version.lstrip("v")
        name = path
    else:
        name = path
    return eco, vulndb.norm_name(eco, name), version


def _cdx_components(doc: dict, root_rel: str = "") -> list[dict]:
    comps = doc.get("components") or []
    by_ref = {c.get("bom-ref"): c for c in comps}
    apps = {c.get("bom-ref") for c in comps if c.get("type") == "application"}
    direct, parent = set(), {}
    for d in doc.get("dependencies") or []:
        ref, deps = d.get("ref"), d.get("dependsOn") or []
        for x in deps:
            if ref in apps or ref == (doc.get("metadata", {}).get("component") or {}).get("bom-ref"):
                direct.add(x)
            else:
                parent.setdefault(x, ref)
    out = []
    for c in comps:
        if c.get("type") == "application":
            continue
        parsed = _purl_split(c.get("purl"))
        if not parsed:
            continue
        eco, name, version = parsed
        props = {p.get("name"): p.get("value") for p in c.get("properties") or []}
        file = props.get("aquasecurity:trivy:FilePath") or root_rel
        lic = None
        for entry in c.get("licenses") or []:
            lic = (entry.get("license") or {}).get("id") or (entry.get("license") or {}).get("name") or entry.get("expression")
            if lic:
                break
        via = None
        ref = c.get("bom-ref")
        if ref not in direct and ref in parent and parent[ref] in by_ref:
            p = _purl_split(by_ref[parent[ref]].get("purl"))
            via = p[1] if p else None
        scope = "optional" if props.get("aquasecurity:trivy:Dev") == "true" else ("required" if ref in direct else "transitive")
        out.append({"ecosystem": eco, "name": name, "version": version, "file": file, "scope": scope, "via": via,
                    "license": lic or "unknown", "purl": f"pkg:{eco}/{name.replace(':', '/')}@{version}", "source": "trivy"})
    return out


def trivy_sbom(path: str, rel: str = "") -> list[dict]:
    """Components Trivy finds under path (CycloneDX). Online, Maven POMs are resolved transitively."""
    if not shutil.which("trivy"):
        return []
    from .orchestrator import TRIVY_CACHE
    argv = ["trivy", "fs", "--quiet", "--format", "cyclonedx", "--include-dev-deps", "--cache-dir", TRIVY_CACHE,
            "--timeout", "10m", "--skip-dirs", "**/node_modules", "--skip-dirs", "**/.git"]
    if vulndb.offline():
        argv += ["--offline-scan", "--skip-db-update", "--skip-java-db-update"]
    try:
        cp = subprocess.run(argv + [path], capture_output=True, text=True, timeout=900, env=_env())
        doc = json.loads(cp.stdout or "{}")
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        vulndb.scan_status()["errors"].add(f"Trivy inventory ({type(e).__name__})")
        return []
    if cp.returncode:
        vulndb.scan_status()["errors"].add("Trivy inventory: " + (cp.stderr or "").strip().splitlines()[-1][:160] if cp.stderr else "Trivy inventory failed")
    comps = _cdx_components(doc, rel)
    if comps:
        vulndb.scan_status().setdefault("resolution", set()).add("Trivy (dependency inventory)")
    return comps


# ------------------------------------------------------------------ npm without a lock file
def _walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        yield dirpath, filenames


def npm_without_lock(root: str) -> list[dict]:
    if vulndb.offline() or not shutil.which("npm"):
        return []
    out = []
    for dirpath, files in _walk(root):
        if "package.json" not in files or {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"} & set(files):
            continue
        rel = os.path.relpath(os.path.join(dirpath, "package.json"), root)
        try:
            pkg = json.load(open(os.path.join(dirpath, "package.json"), encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not (pkg.get("dependencies") or pkg.get("devDependencies")) or pkg.get("workspaces"):
            continue
        scratch = tempfile.mkdtemp(prefix="myelin-npm-")
        try:
            # only the dependency declarations: no scripts, no .npmrc from the repository
            slim = {k: pkg[k] for k in ("name", "version", "dependencies", "devDependencies", "optionalDependencies",
                                        "peerDependencies", "overrides", "resolutions") if k in pkg}
            slim.setdefault("name", "scan-target")
            json.dump(slim, open(os.path.join(scratch, "package.json"), "w"))
            cp = subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                                 "--legacy-peer-deps", "--loglevel=error"], cwd=scratch, capture_output=True, text=True,
                                timeout=600, env=_env())
            lock = os.path.join(scratch, "package-lock.json")
            if cp.returncode == 0 and os.path.exists(lock):
                out += vulndb._npm_lock(json.load(open(lock, encoding="utf-8")), rel)
                vulndb.scan_status().setdefault("resolution", set()).add("npm registry (resolved dependency tree)")
            else:
                vulndb.scan_status()["errors"].add(f"npm resolution for {rel}: " + ((cp.stderr or "").strip().splitlines() or ["failed"])[-1][:120])
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            vulndb.scan_status()["errors"].add(f"npm resolution for {rel} ({type(e).__name__})")
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    return out


# ------------------------------------------------------------------ Gradle without a lock file
GRADLE_DEP = re.compile(r"""\b(?:implementation|api|compile|compileOnly|runtimeOnly|runtime|testImplementation|
                            testRuntimeOnly|kapt|annotationProcessor)\s*\(?\s*["']([\w.\-]+):([\w.\-]+):([\w.\-+\[\],()$]+)["']""", re.X)
GRADLE_CATALOG_REF = re.compile(r"\b(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation)\s*\(?\s*libs\.([\w.]+)")


def _catalog(root):
    """gradle/libs.versions.toml -> {'spring.boot.starter': ('org.springframework.boot', 'spring-boot-starter', '3.2.0')}"""
    p = os.path.join(root, "gradle", "libs.versions.toml")
    if not os.path.exists(p):
        return {}
    try:
        import tomllib
    except ImportError:                                   # Python 3.10
        return {}
    try:
        doc = tomllib.load(open(p, "rb"))
    except (OSError, ValueError):
        return {}
    versions = doc.get("versions") or {}
    out = {}
    for alias, spec in (doc.get("libraries") or {}).items():
        if isinstance(spec, str):
            parts = spec.split(":")
            if len(parts) == 3:
                out[alias.replace("-", ".").replace("_", ".")] = tuple(parts)
            continue
        module = spec.get("module") or (f"{spec.get('group')}:{spec.get('name')}" if spec.get("group") else None)
        ver = spec.get("version")
        if isinstance(ver, dict):
            ver = versions.get(ver.get("ref")) if ver.get("ref") else ver.get("strictly") or ver.get("require")
        if module and ver and ":" in module:
            g, a = module.split(":", 1)
            out[alias.replace("-", ".").replace("_", ".")] = (g, a, str(ver))
    return out


def gradle_declared(root: str) -> list[tuple[str, str, str, str]]:
    deps, cat = [], _catalog(root)
    for dirpath, files in _walk(root):
        for fn in files:
            if fn not in ("build.gradle", "build.gradle.kts"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), root)
            if "gradle.lockfile" in files:
                continue                                  # Trivy reads the lock file
            text = open(os.path.join(dirpath, fn), encoding="utf-8", errors="ignore").read()
            for g, a, v in GRADLE_DEP.findall(text):
                if "$" not in v:
                    deps.append((g, a, v, rel))
            for ref in GRADLE_CATALOG_REF.findall(text):
                if ref in cat:
                    deps.append((*cat[ref], rel))
    return deps


def gradle_transitive(root: str) -> list[dict]:
    declared = gradle_declared(root)
    if not declared:
        return []
    if vulndb.offline() or not shutil.which("trivy"):
        return [vulndb._c("maven", f"{g}:{a}", v, rel, "required") for g, a, v, rel in declared]
    scratch = tempfile.mkdtemp(prefix="myelin-gradle-")
    try:
        deps = "".join(f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version></dependency>"
                       for g, a, v, _ in declared)
        open(os.path.join(scratch, "pom.xml"), "w").write(
            '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
            f"<groupId>scan</groupId><artifactId>gradle-project</artifactId><version>0</version><dependencies>{deps}</dependencies></project>")
        comps = trivy_sbom(scratch)
        files = {f"{g}:{a}": rel for g, a, _, rel in declared}
        first = declared[0][3]
        for c in comps:
            c["file"] = files.get(c["name"], first)
        if comps:
            vulndb.scan_status().setdefault("resolution", set()).add("Maven repository (Gradle dependency tree)")
        return comps or [vulndb._c("maven", f"{g}:{a}", v, rel, "required") for g, a, v, rel in declared]
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# ------------------------------------------------------------------ NuGet transitive resolution
def _nuget_json(url):
    req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip", "User-Agent": "nervve-devsecops"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310  # myelin:ignore[NM-SAST-010] -- fixed NuGet https registry or operator-set mirror
        raw = r.read()
        if r.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return json.loads(raw)


def _nuget_lowest(range_: str, available: list[str]) -> str | None:
    """Lowest available version satisfying a NuGet range ('1.2.3', '[1.2,2.0)', '(,3.0]')."""
    from packaging.version import InvalidVersion, Version

    def v(x):
        try:
            return Version(x)
        except InvalidVersion:
            return None
    r = (range_ or "").strip()
    lo = hi = None
    lo_inc = hi_inc = True
    if r and r[0] in "[(":
        lo_inc, hi_inc = r[0] == "[", r[-1] == "]"
        parts = r[1:-1].split(",")
        lo = v(parts[0].strip()) if parts[0].strip() else None
        hi = v(parts[1].strip()) if len(parts) > 1 and parts[1].strip() else (lo if len(parts) == 1 else None)
    elif r:
        lo = v(r)
    best = None
    for s in available:
        x = v(s)
        if x is None or x.is_prerelease:
            continue
        if lo is not None and (x < lo or (x == lo and not lo_inc)):
            continue
        if hi is not None and (x > hi or (x == hi and not hi_inc)):
            continue
        if best is None or x < best[0]:
            best = (x, s)
    return best[1] if best else None


def _nuget_package(pid: str):
    """{version: [dependency (id, range), ...]} for a package, from the registration index."""
    idx = _nuget_json(f"{NUGET_URL}/v3/registration5-gz-semver2/{pid.lower()}/index.json")
    out = {}
    for page in idx.get("items") or []:
        items = page.get("items")
        if items is None and page.get("@id"):
            items = (_nuget_json(page["@id"]) or {}).get("items") or []
        for leaf in items or []:
            ce = leaf.get("catalogEntry") or {}
            deps = []
            for grp in ce.get("dependencyGroups") or []:
                for d in grp.get("dependencies") or []:
                    if d.get("id"):
                        deps.append((d["id"], d.get("range") or ""))
            out[ce.get("version", "")] = deps
    return out


def nuget_transitive(direct: list[dict]) -> list[dict]:
    if vulndb.offline():
        return []
    todo = [(c["name"], c["version"], c["name"], c["file"]) for c in direct if c["ecosystem"] == "nuget" and c.get("version")]
    seen = {(c["name"].lower(), c["version"]) for c in direct if c["ecosystem"] == "nuget"}
    out, meta = [], {}
    try:
        while todo and len(out) < MAX_NUGET:
            pid, ver, top, rel = todo.pop(0)
            if pid.lower() not in meta:
                meta[pid.lower()] = _nuget_package(pid)
            deps = {}
            for d_id, rng in meta[pid.lower()].get(ver, []):
                deps.setdefault(d_id, rng)                   # first target framework group wins
            for d_id, rng in deps.items():
                if d_id.lower() not in meta:
                    meta[d_id.lower()] = _nuget_package(d_id)
                pick = _nuget_lowest(rng, list(meta[d_id.lower()]))
                if pick and (d_id.lower(), pick) not in seen:
                    seen.add((d_id.lower(), pick))
                    out.append(vulndb._c("nuget", d_id, pick, rel, "transitive", via=top))
                    todo.append((d_id, pick, top, rel))
    except (OSError, ValueError) as e:
        vulndb.scan_status()["errors"].add(f"NuGet resolution ({type(e).__name__})")
    if out:
        vulndb.scan_status().setdefault("resolution", set()).add("NuGet registry (transitive dependencies)")
    return out


def extra_components(root: str, external: bool = True) -> list[dict]:
    """Everything beyond RAT Flea's own manifest and lock-file parsers (see module docstring). external=False keeps
    to in-process work (no Trivy or npm child processes), for --builtin-only scans."""
    comps = trivy_sbom(root) if external else []
    comps += npm_without_lock(root) if external else []
    comps += gradle_transitive(root)
    comps += nuget_transitive(comps)
    return comps
