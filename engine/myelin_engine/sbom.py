# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Manifest parsing -> CycloneDX 1.5 SBOM + offline SCA + licence checks.

In production the orchestrator prefers Syft (SBOM) and Grype/Trivy/OSV (advisories);
this built-in path guarantees results in air-gapped environments and in demos.
"""
import json
import fnmatch
import os
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression
from packaging.requirements import InvalidRequirement, Requirement

from . import __version__, coverage, license_policy, vulndb

# Curated offline advisory pack (subset; the server syncs OSV/NVD/GHSA/KEV/EPSS feeds).
ADVISORIES = [
    # ecosystem, package, vulnerable-below, fixed, cve, cvss, epss, kev, cwe, title
    ("maven", "org.apache.logging.log4j:log4j-core", "2.17.1", "2.17.1", "CVE-2021-44228", 10.0, 0.975, True, "CWE-917", "Log4Shell JNDI remote code execution"),
    ("maven", "org.springframework:spring-beans", "5.3.18", "5.3.18", "CVE-2022-22965", 9.8, 0.974, True, "CWE-94", "Spring4Shell data-binding RCE"),
    ("maven", "org.apache.commons:commons-text", "1.10.0", "1.10.0", "CVE-2022-42889", 9.8, 0.969, False, "CWE-94", "Text4Shell interpolation RCE"),
    ("npm", "lodash", "4.17.21", "4.17.21", "CVE-2021-23337", 7.2, 0.012, False, "CWE-94", "Command injection via template"),
    ("npm", "semver", "7.5.2", "7.5.2", "CVE-2022-25883", 7.5, 0.006, False, "CWE-1333", "ReDoS in range parsing"),
    ("npm", "@babel/traverse", "7.23.2", "7.23.2", "CVE-2023-45133", 9.3, 0.015, False, "CWE-184", "Arbitrary code execution when compiling crafted code"),
    ("npm", "jsonwebtoken", "9.0.0", "9.0.0", "CVE-2022-23529", 7.6, 0.004, False, "CWE-20", "Insecure key handling in verify()"),
    ("npm", "axios", "1.6.0", "1.6.0", "CVE-2023-45857", 6.5, 0.002, False, "CWE-352", "XSRF-TOKEN leaked to third-party hosts"),
    ("pypi", "requests", "2.32.0", "2.32.0", "CVE-2024-35195", 5.6, 0.001, False, "CWE-670", "Session ignores verify=False reset"),  # myelin:ignore[NM-SAST-004] -- advisory description text, not a TLS call
    ("pypi", "django", "4.2.15", "4.2.15", "CVE-2024-42005", 9.8, 0.011, False, "CWE-89", "SQL injection in QuerySet.values()"),
    ("pypi", "pyyaml", "5.4", "5.4", "CVE-2020-14343", 9.8, 0.021, False, "CWE-20", "Arbitrary code execution via full_load"),
    ("pypi", "jinja2", "3.1.4", "3.1.4", "CVE-2024-34064", 5.4, 0.001, False, "CWE-79", "XSS via xmlattr filter"),
    ("go", "golang.org/x/net", "0.17.0", "0.17.0", "CVE-2023-44487", 7.5, 0.94, True, "CWE-400", "HTTP/2 Rapid Reset DoS"),
]


def _spdx(lic):
    if not isinstance(lic, str) or not lic.strip() or len(lic) > 1024:
        return None
    try:
        return str(canonicalize_license_expression(lic))
    except (InvalidLicenseExpression, RecursionError):
        return None


def licence_kind(lic: str | None) -> str | None:
    """Report obligations common to all OR alternatives; AND retains the strongest obligation."""
    expression = _spdx(lic)
    if not expression:
        return None

    def rank(node):
        op = node["op"]
        if op in {"AND", "OR"}:
            return (max if op == "AND" else min)(rank(child) for child in node["args"])
        ident = (node.get("id") or node.get("license")).upper()
        if ident.startswith(("AGPL-", "GPL-", "SSPL-", "EUPL-")):
            return 2
        if ident.startswith(("LGPL-", "MPL-", "EPL-", "CDDL-", "CPL-")):
            return 1
        return 0

    try:
        return (None, "weak", "strong")[rank(license_policy.parse_expression(expression))]
    except (license_policy.LicenseExpressionError, RecursionError):
        return None


def _cyclonedx_licenses(lic):
    if not lic or lic == "unknown":
        return []
    spdx = _spdx(lic)
    if not spdx:
        return [{"license": {"name": lic}}]
    if " " in spdx or spdx.endswith("+") or "LicenseRef-" in spdx:
        return [{"expression": spdx}]
    return [{"license": {"id": spdx}}]


KNOWN_LICENSES = {"lodash": "MIT", "express": "MIT", "axios": "MIT", "semver": "ISC", "requests": "Apache-2.0",
                  "django": "BSD-3-Clause", "flask": "BSD-3-Clause", "pyyaml": "MIT", "jinja2": "BSD-3-Clause",
                  "mongodb": "Apache-2.0", "ghostscript": "AGPL-3.0", "itext7": "AGPL-3.0", "mysql-connector-python": "GPL-2.0",
                  "jsonwebtoken": "MIT", "@babel/traverse": "MIT"}


def _ver(v: str):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", re.sub(r"^[^\d]*", "", v))[:4])


PAIRED_LOCKS = {
    "package.json": {"npm-shrinkwrap.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
    "pyproject.toml": {"uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"},
    "Pipfile": {"Pipfile.lock"}, "setup.py": {"uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"},
    "Cargo.toml": {"Cargo.lock"}, "Gemfile": {"Gemfile.lock"}, "composer.json": {"composer.lock"},
    "go.sum": {"go.mod"}, "build.gradle": {"gradle.lockfile"}, "build.gradle.kts": {"gradle.lockfile"},
    "Directory.Packages.props": {"packages.lock.json", "packages.config"},
    "mix.exs": {"mix.lock"}, "pubspec.yaml": {"pubspec.lock"},
}
NPM_VERSION = re.compile(r"v?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)")


def _manifest_gap(message):
    vulndb.current_status()["inventory_errors"].add(message)


def _python_requirement(raw, rel, scope):
    try:
        req = Requirement(raw)
    except InvalidRequirement:
        _manifest_gap(f"unsupported Python requirement in {rel}")
        return
    pinned = [x.version for x in req.specifier if x.operator == "==" and "*" not in x.version]
    version = pinned[0] if len(pinned) == 1 and req.specifier.contains(pinned[0], prereleases=True) else None
    comp = vulndb._c("pypi", req.name, version, rel, scope)
    comp.update(spec=str(req.specifier), extras=req.extras, registry=not req.url)
    return comp


def parse_manifests(root: str) -> list[dict]:
    comps = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in coverage.SKIP)
        names = set(filenames)
        for fn in sorted(names):
            if fn in vulndb.LOCKFILES or not any(fnmatch.fnmatch(fn, m) for m in coverage.MANIFESTS):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            reqfile = fnmatch.fnmatch(fn, "requirements*.txt")
            try:
                if os.path.islink(p):
                    raise ValueError("manifest is a symlink")
                if fn not in {"package.json", "pyproject.toml", "go.mod", "pom.xml"} and not reqfile:
                    paired = PAIRED_LOCKS.get(fn) or ({"packages.lock.json", "packages.config"} if fn.endswith(".csproj") else set())
                    if not paired & names:
                        _manifest_gap(f"manifest requires a supported lockfile or parser: {rel}")
                    continue
                text = Path(p).read_text(encoding="utf-8")
                if fn == "package.json":
                    data = json.loads(text)
                    for section, scope in (("dependencies", "required"), ("devDependencies", "dev"),
                                           ("optionalDependencies", "optional"), ("peerDependencies", "optional")):
                        for name, spec in (data.get(section) or {}).items():
                            match = NPM_VERSION.fullmatch(spec)
                            comps.append(vulndb._c("npm", name, match[1] if match else None, rel, scope))
                elif reqfile:
                    scope = "optional" if re.search(r"(dev|test|lint|doc)", fn) else "required"
                    for line in text.replace("\\\n", " ").splitlines():
                        # Remove pip hashes and comments, but preserve URL fragments for PEP 508 parsing.
                        raw = re.split(r"\s+(?:#|--hash(?:=|\s))", line.strip(), maxsplit=1)[0]
                        if not raw or raw.startswith("#"):
                            continue
                        if raw.startswith("-"):
                            if re.match(r"-(?:[rce]\s*|-(?:requirement|constraint|editable)\b)", raw):
                                _manifest_gap(f"requirement include, constraint or editable needs review: {rel}")
                            continue
                        if comp := _python_requirement(raw, rel, scope):
                            comps.append(comp)
                elif fn == "pyproject.toml":
                    try:
                        import tomllib
                    except ImportError:
                        import tomli as tomllib
                    data = tomllib.loads(text)
                    project = data.get("project") or {}
                    groups = [(project.get("dependencies") or [], "required")]
                    groups += [(values, "optional") for values in (project.get("optional-dependencies") or {}).values()]
                    groups += [(values, "dev") for values in (data.get("dependency-groups") or {}).values()]
                    if not PAIRED_LOCKS[fn] & names and (
                        {"dependencies", "optional-dependencies"} & set(project.get("dynamic") or [])
                        or (data.get("tool") or {}).get("poetry", {}).get("dependencies")
                    ):
                        _manifest_gap(f"dynamic or tool-specific Python dependencies need a lockfile: {rel}")
                    for values, scope in groups:
                        for raw in values:
                            if isinstance(raw, dict) and set(raw) == {"include-group"}:
                                continue  # already inventoried from the named group
                            if comp := _python_requirement(raw, rel, scope):
                                comps.append(comp)
                elif fn == "go.mod":
                    in_requires = False
                    for line in text.splitlines():
                        directive = line.partition("//")[0].strip()
                        if re.fullmatch(r"require\s*\(", directive):
                            in_requires = True
                        elif in_requires and directive == ")":
                            in_requires = False
                        elif in_requires or re.match(r"^require\s", directive):
                            coordinate = directive if in_requires else directive.split(maxsplit=1)[1]
                            if m := re.fullmatch(r"([\w./\-]+)\s+v([\w.\-+]+)", coordinate):
                                comps.append(vulndb._c("go", m[1], m[2], rel,
                                                       "transitive" if re.search(r"//\s*indirect\b", line) else "required"))
                        elif re.match(r"^replace\b", directive):
                            _manifest_gap(f"Go module replacements are not resolved: {rel}")
                elif fn == "pom.xml":
                    project = ET.fromstring(text)
                    paths = ("./{*}dependencies/{*}dependency", "./{*}profiles/{*}profile/{*}dependencies/{*}dependency")
                    for path in paths:
                        for dep in project.findall(path):
                            group = dep.findtext("{*}groupId", "").strip()
                            artifact = dep.findtext("{*}artifactId", "").strip()
                            version = dep.findtext("{*}version", "").strip()
                            scope = dep.findtext("{*}scope", "").strip()
                            if group and artifact:
                                exact = version if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+\-]*", version) else None
                                comps.append(vulndb._c("maven", f"{group}:{artifact}", exact, rel,
                                                       "optional" if scope in {"test", "provided", "system"} else "required"))
            except (OSError, ValueError, TypeError, AttributeError, ET.ParseError):
                _manifest_gap(f"manifest parse: {rel}")
    return comps


def _pick_pypi(name, spec):
    """Version an install would get today for an unpinned requirement."""
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import InvalidVersion, Version
        proj = vulndb._safe(vulndb._pypi_project, name) or {}
        best = None
        ss = SpecifierSet(spec or "")
        for v, files in (proj.get("releases") or {}).items():
            try:
                pv = Version(v)
            except InvalidVersion:
                continue
            if not pv.is_prerelease and files and not all(f.get("yanked") for f in files) and ss.contains(pv):
                best = pv if best is None or pv > best else best
        return str(best) if best else None
    except Exception:  # noqa: BLE001
        return None


def inventory(root: str, *, resolve_online: bool = True) -> list[dict]:
    """Discover third-party packages; match manifest evidence only against same-project locks."""
    direct = parse_manifests(root)
    locked = vulndb.parse_lockfiles(root)
    online = resolve_online and not vulndb.offline()
    locks = {}
    python_lock_dirs = set()
    for component in locked:
        for evidence in component["evidence_files"]:
            directory = os.path.dirname(evidence)
            locks.setdefault((directory, component["ecosystem"], component["name"]), []).append(component)
            if component["ecosystem"] == "pypi":
                python_lock_dirs.add(directory)

    remaining = []
    for comp in direct:
        directory = os.path.dirname(comp["file"])
        candidates = locks.get((directory, comp["ecosystem"], comp["name"]), [])
        if comp["version"]:
            candidates = [c for c in candidates if c["version"] == comp["version"]]
        if len(candidates) > 1:
            candidates = [c for c in candidates if c["scope"] == comp["scope"]]
        if len(candidates) == 1 and comp.get("registry", True):
            selected = candidates[0]
            selected["evidence_files"] = sorted({*selected["evidence_files"], comp["file"]})
            if comp["scope"] == "required" or selected["scope"] == "transitive":
                selected["scope"] = comp["scope"]
            continue
        if comp["ecosystem"] == "pypi" and not comp["version"] and not candidates and online and comp.get("registry", True):
            comp["version"] = _pick_pypi(comp["name"], comp.get("spec"))
            if comp["version"]:
                comp["resolved"] = True
                _manifest_gap(f"Python version estimated from registry metadata: {comp['file']}")
        if not comp["version"]:
            _manifest_gap(f"unresolved version for {comp['name']} in {comp['file']}")
            continue
        comp["purl"] = vulndb._c(comp["ecosystem"], comp["name"], comp["version"], comp["file"], comp["scope"])["purl"]
        remaining.append(comp)
    python_direct = [c for c in remaining if c["ecosystem"] == "pypi" and
                     os.path.dirname(c["file"]) not in python_lock_dirs]
    # This is a metadata estimate (host markers and latest matching versions), not a lockfile or build graph.
    trans = vulndb.resolve_pypi(python_direct) if online else []
    comps = {}
    for c in locked + remaining + trans:
        k = (c["ecosystem"], c["name"], c["version"])
        paths = set(c.get("evidence_files") or [c["file"]])
        if k not in comps:
            comps[k] = c
        else:
            paths.update(comps[k]["evidence_files"])
            if c["scope"] == "required":
                comps[k]["scope"] = "required"
            if c.get("via") != comps[k].get("via"):
                comps[k]["via"] = None
        comps[k]["evidence_files"] = sorted(paths)
    components = [comps[k] for k in sorted(comps)]
    for c in components:
        declarations = c.pop("lock_licences", [])
        declared = {(_spdx(value) or value) for value in declarations}
        if len(declared) > 1:
            c["licence_source"] = "conflicting lockfiles"
        elif declared:
            value = next(iter(declared))
            if value.casefold() not in {"unknown", "noassertion", "none"}:
                c.update(license=value, licence_source="lockfile")

    if online:
        from concurrent.futures import ThreadPoolExecutor
        todo = [c for c in components if not c.get("licence_source") and c["ecosystem"] in {"npm", "pypi"}]
        with ThreadPoolExecutor(max_workers=8) as ex:
            for c, licence in zip(todo, vulndb.scan_map(ex, vulndb.licence, todo)):
                if isinstance(licence, str) and licence.strip() and licence.lower() not in {"unknown", "noassertion", "none"}:
                    c.update(license=licence.strip(), licence_source="registry")
        if any(c.get("licence_source") == "registry" for c in todo):
            vulndb.current_status()["sources"].add("package registries (licences)")

    fallback_ecosystems = {"@babel/traverse": "npm", "lodash": "npm", "express": "npm", "axios": "npm", "semver": "npm",
                           "mongodb": "npm", "jsonwebtoken": "npm"}
    for c in components:
        pkg = c["name"]
        if not c.get("licence_source") and pkg in KNOWN_LICENSES and c["ecosystem"] == fallback_ecosystems.get(pkg, "pypi"):
            c.update(license=KNOWN_LICENSES[pkg], licence_source="bundled package hint")
    return components


def licence_evidence(components):
    verified = sum(c.get("licence_source") in {"lockfile", "registry"} and bool(_spdx(c.get("license")))
                   for c in components)
    return {"with_release_spdx": verified, "missing_or_unverified": len(components) - verified}


def _reach(pkg, hint):
    if hint is None:
        return None
    hit, unknown = hint
    return None if pkg in unknown else (pkg in hit)


def _dep_type(c):
    return {"required": "direct", "optional": "dev", "dev": "dev", "transitive": "transitive"}.get(c.get("scope"), "direct")


def match_advisories(comps: list[dict], repo: str = "local", reachable_hint: set | None = None, *,
                     check_vulnerabilities: bool = True, check_licences: bool = True) -> list[dict]:
    out, seen = [], set()
    for c, v in (vulndb.vulnerabilities(comps) if check_vulnerabilities else []):                    # live intelligence (OSV / PyPI)
        key = (c["ecosystem"], c["name"], c["version"], v["cve"] or v["id"])
        if key in seen:
            continue
        seen.add(key)
        if str(v.get("id", "")).startswith("MAL-"):             # OSV malicious-package feed: malware, not a CVE
            from . import supply_chain
            out.append(supply_chain.malicious_advisory_finding(c, v, repo))
            continue
        via = f" (via {c['via']})" if c.get("via") else ""
        out.append({
            "engine": "sca", "rule_id": v["cve"] or v["id"], "cve": v["cve"], "advisory": v["id"], "aliases": v["aliases"],
            "title": f"{c['name']}@{c['version']}: {v['summary'] or v['id']}", "severity": v["severity"],
            "cvss": v["cvss"], "epss": v.get("epss"), "epss_percentile": v.get("epss_percentile"),
            "kev": v.get("kev"), "kev_details": v.get("kev_details"), "cwe": v["cwe"],
            "nvd_intelligence": v.get("nvd"), "package": c["name"], "version": c["version"],
            "fixed_version": v["fixed"], "file": c["file"], "repo": repo, "ecosystem": c["ecosystem"], "purl": c["purl"],
            "reachable": _reach(c["via"] or c["name"], reachable_hint), "exposure": "internet",
            "dependency_type": _dep_type(c), "introduced_by": c.get("via"), "autofix": bool(v["fixed"]),
            "evidence": f"{c['name']} {c['version']}{via} · advisory {v['id']}" + ("" if v["severity_known"] else " · severity not published; severity unknown"),
            "remediation": (f"Upgrade {c['name']} to {v['fixed']} or later" + (f" (it comes in through {c['via']}: upgrade {c['via']} to a release that allows it)" if c.get("via") else "") + ".")
            if v["fixed"] else f"No fixed release published for {c['name']}; assess exposure, apply the advisory's workaround or replace the component.",
        })
    for c in comps:
        for eco, pkg, below, fixed, cve, cvss, epss, kev, cwe, title in (ADVISORIES if check_vulnerabilities else []):
            if c["ecosystem"] == eco and c["name"] == pkg and _ver(c["version"]) < _ver(below):
                if (c["ecosystem"], c["name"], c["version"], cve) in seen:
                    continue
                out.append({
                    "engine": "sca", "rule_id": cve, "cve": cve, "title": f"{pkg}@{c['version']}: {title}",
                    "severity": "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium",
                    "cvss": cvss, "epss": epss, "kev": kev, "cwe": cwe, "package": pkg, "version": c["version"],
                    "fixed_version": fixed, "file": c["file"], "repo": repo, "ecosystem": eco, "purl": c["purl"],
                    "reachable": _reach(pkg, reachable_hint),
                    "exposure": "internet", "dependency_type": _dep_type(c),
                    "autofix": True,
                    "remediation": f"Upgrade {pkg} to {fixed} or later. NERvvE DevSecOps AutoFix can open a PR with the upgrade and lockfile refresh.",
                })
        kind = licence_kind(c.get("license")) if check_licences else None
        if kind == "strong":
            out.append({"engine": "license", "rule_id": "NM-LIC-001", "title": f"Copyleft licence {c['license']} in {c['name']}",
                        "severity": "high", "package": c["name"], "version": c["version"], "file": c["file"], "repo": repo,
                        "license": c["license"], "purl": c["purl"], "ecosystem": c["ecosystem"],
                        "licence_source": c.get("licence_source"), "dependency_type": _dep_type(c),
                        "remediation": "Strong copyleft can require releasing your source code when you distribute or host the product. "
                                       "Replace the component or obtain a commercial licence; legal review required."})
        elif kind == "weak":
            out.append({"engine": "license", "rule_id": "NM-LIC-002", "title": f"Weak copyleft licence {c['license']} in {c['name']}",
                        "severity": "info", "package": c["name"], "version": c["version"], "file": c["file"], "repo": repo,
                        "license": c["license"], "purl": c["purl"], "ecosystem": c["ecosystem"],
                        "licence_source": c.get("licence_source"), "dependency_type": _dep_type(c),
                        "remediation": "Usually fine when used unmodified as a separate library; modifications to this component "
                                       "must be published under the same licence. Record it in your third-party notices."})
    return out


def cyclonedx(comps: list[dict], name: str = "application", *, inventory_gaps=()) -> dict:
    """Build a CycloneDX BOM with stable component refs and an explicit dependency graph.

    The graph is based only on dependency relationships resolved by the inventory engine.
    Unknown parent relationships are omitted from the graph.
    """
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", str(name)).strip("-") or "application"
    app_ref = f"urn:myelin:application:{safe_name}"
    components = []
    by_name = {}
    for c in comps:
        purl = c["purl"]
        by_name.setdefault((c["ecosystem"], c["name"]), []).append(purl)
        components.append({
            "type": "library", "bom-ref": purl, "name": c["name"], "version": c["version"],
            "purl": purl,
            "licenses": _cyclonedx_licenses(c.get("license")),
            "scope": "optional" if c.get("scope") in ("optional", "dev") else "required",
            "properties": [
                {"name": "myelin:dependency", "value": _dep_type(c)},
                *({"name": "myelin:manifest", "value": path}
                  for path in sorted(set(c.get("evidence_files") or [c.get("file", "")])) if path),
            ] + ([{"name": "myelin:licence-source", "value": c["licence_source"]}] if c.get("licence_source") else [])
              + ([{"name": "myelin:introduced-by", "value": c["via"]}] if c.get("via") else []),
        })

    edges = {app_ref: set()}
    for c in comps:
        child = c["purl"]
        parent_name = c.get("via")
        parents = by_name.get((c["ecosystem"], parent_name), []) if parent_name else []
        # A relationship is emitted only when the inventory resolved one unambiguous parent.
        if len(parents) == 1 and parents[0] != child:
            edges.setdefault(parents[0], set()).add(child)
            edges.setdefault(child, set())
        elif not parent_name and c.get("scope") != "transitive":
            edges[app_ref].add(child)
            edges.setdefault(child, set())

    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "NERvvE DevSecOps", "name": "NERvvE DevSecOps", "version": __version__}],
            "component": {"type": "application", "bom-ref": app_ref, "name": name},
            "properties": [{"name": "myelin:inventory", "value": "manifest-and-lockfile-derived"}]
                          + [{"name": "myelin:inventory-gap", "value": gap} for gap in inventory_gaps],
        },
        "components": components,
        "compositions": [{"aggregate": "incomplete" if inventory_gaps else "unknown",
                          "assemblies": [app_ref], "dependencies": [app_ref]}],
        "dependencies": [{"ref": ref, "dependsOn": sorted(children)} for ref, children in sorted(edges.items())],
    }
