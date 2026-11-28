# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Manifest parsing -> CycloneDX 1.5 SBOM + offline SCA + licence checks.

In production the orchestrator prefers Syft (SBOM) and Grype/Trivy/OSV (advisories);
this built-in path guarantees results in air-gapped environments and in demos.
"""
import json
import os
import re
import uuid
from datetime import datetime, timezone

from . import vulndb

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
COPYLEFT = {"AGPL-3.0", "GPL-3.0", "GPL-2.0", "SSPL-1.0"}


def licence_kind(lic: str | None) -> str | None:
    """strong (GPL/AGPL/SSPL/EUPL), weak (LGPL/MPL/EPL/CDDL) or None. An 'A OR B' expression is judged by its most
    permissive option, since the user may choose it."""
    if not lic or lic == "unknown":
        return None
    options = [o.strip(" ()").upper() for o in re.split(r"\s+OR\s+", lic)]
    def one(o):
        if re.search(r"\b(AGPL|SSPL|EUPL)|(^|[^L])GPL", o):
            return "strong"
        if re.search(r"\bLGPL|\bMPL|\bEPL|\bCDDL|\bCPL", o):
            return "weak"
        return None
    kinds = [one(o) for o in options]
    return None if None in kinds else "weak" if "weak" in kinds else "strong"
KNOWN_LICENSES = {"lodash": "MIT", "express": "MIT", "axios": "MIT", "semver": "ISC", "requests": "Apache-2.0",
                  "django": "BSD-3-Clause", "flask": "BSD-3-Clause", "pyyaml": "MIT", "jinja2": "BSD-3-Clause",
                  "mongodb": "Apache-2.0", "ghostscript": "AGPL-3.0", "itext7": "AGPL-3.0", "mysql-connector-python": "GPL-2.0",
                  "jsonwebtoken": "MIT", "@babel/traverse": "MIT"}


def _ver(v: str):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", re.sub(r"^[^\d]*", "", v))[:4])


def parse_manifests(root: str) -> list[dict]:
    comps = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".venv"}]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            if fn == "package.json":
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    continue
                for sect, scope in (("dependencies", "required"), ("devDependencies", "optional")):
                    for n, v in (data.get(sect) or {}).items():
                        comps.append({"ecosystem": "npm", "name": n, "version": v.lstrip("^~>=< "), "file": rel, "scope": scope})
            elif re.match(r"requirements.*\.txt$", fn):
                dev = bool(re.search(r"(dev|test|lint|doc)", fn))
                for ln in text.splitlines():
                    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|~=|>|<=|<|!=)?\s*([\w.\-*]+)?", ln.split("#")[0])
                    if not m or not m.group(1) or ln.strip().startswith(("-", "#")):
                        continue
                    extras = {e.strip() for e in (m.group(2) or "").strip("[]").split(",") if e.strip()}
                    version = m.group(4) if m.group(3) == "==" else None
                    spec = ln.split("#")[0].split(";")[0].strip()[len(m.group(1)) + len(m.group(2) or ""):].strip()
                    comps.append({"ecosystem": "pypi", "name": vulndb.norm_name("pypi", m.group(1)), "version": version,
                                  "spec": spec, "extras": extras, "file": rel, "scope": "optional" if dev else "required"})
            elif fn == "go.mod":
                for m in re.finditer(r"^\s*([\w./\-]+)\s+v([\w.\-+]+)", text, re.M):
                    comps.append({"ecosystem": "go", "name": m.group(1), "version": m.group(2), "file": rel, "scope": "required"})
    from . import manifests
    comps += manifests.declared(root)       # .NET, Maven, Gradle, pyproject/Pipfile, Cargo, composer, Gemfile
    for c in comps:
        c["license"] = KNOWN_LICENSES.get(c["name"], "unknown")
        c["purl"] = f"pkg:{c['ecosystem']}/{c['name'].replace(':', '/')}@{c['version']}"
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


def inventory(root: str, external: bool = True) -> list[dict]:
    """Every third-party component: manifests (direct), lockfiles (exact transitive) and, for Python requirements
    without a lockfile, transitive dependencies resolved from PyPI. Licences filled in from the registries."""
    st = vulndb.scan_status()
    st["sources"].clear(); st["errors"].clear(); st.setdefault("resolution", set()).clear()
    direct = parse_manifests(root)
    for c in direct:
        c.setdefault("via", None)
        if c["ecosystem"] == "pypi" and not c["version"] and not vulndb.offline():
            c["version"] = _pick_pypi(c["name"], c.get("spec"))
            if c["version"]:
                c["resolved"] = True
    direct = [c for c in direct if c["version"]]
    for c in direct:
        c["purl"] = f"pkg:{c['ecosystem']}/{c['name'].replace(':', '/')}@{c['version']}"
    locked = vulndb.parse_lockfiles(root)
    # Lockfile resolved versions override ranges in manifests; retain both evidence paths.
    direct_by_key = {(c["ecosystem"], c["name"]): c for c in direct}
    locked_by_key = {}
    for c in locked:
        locked_by_key.setdefault((c["ecosystem"], c["name"]), []).append(c)
    for key, manifest in direct_by_key.items():
        candidates = locked_by_key.get(key) or []
        if not candidates:
            continue
        selected = candidates[0]
        selected["scope"] = manifest.get("scope", "required")
        selected["evidence_files"] = sorted(set(selected.get("evidence_files") or [selected.get("file", "")]) |
                                            {manifest.get("file", "")})
    direct = [c for c in direct if (c["ecosystem"], c["name"]) not in locked_by_key]
    locked_ecos = {c["ecosystem"] for c in locked}
    trans = [] if "pypi" in locked_ecos or vulndb.offline() else \
        vulndb.resolve_pypi([c for c in direct if c["ecosystem"] == "pypi"])
    from . import resolve
    extra = resolve.extra_components(root, external)            # Trivy SBOM, npm/Gradle/NuGet resolution (see resolve.py)
    # A version range in package.json ("^4.17.1") is not the installed version: when a lock file or the resolved tree
    # gives the real version of the same package in the same folder, the declared entry is dropped
    exact = {}
    for c in locked + extra:
        if c["ecosystem"] == "npm":
            exact.setdefault((os.path.dirname(c["file"] or ""), c["name"]), []).append(c)
    kept = []
    for c in direct:
        cands = exact.get((os.path.dirname(c["file"] or ""), c["name"])) if c["ecosystem"] == "npm" else None
        if not cands:
            kept.append(c)
            continue
        major = (c.get("version") or "").split(".")[0]
        pick = next((x for x in cands if x["version"].split(".")[0] == major), cands[0])
        pick["scope"] = c["scope"]                     # the declared dependency, at its installed version
        pick.setdefault("declared", c.get("version"))
    direct = kept
    from . import discovery
    embedded = discovery.embedded_components(root)   # copied libraries, archives and committed vendor folders
    comps, seen = [], {}
    for c in direct + locked + trans + extra + embedded:
        k = (c["ecosystem"], c["name"].lower() if c["ecosystem"] in ("nuget", "maven") else c["name"], c["version"])
        if k not in seen:
            seen[k] = c
            comps.append(c)
        elif seen[k].get("license", "unknown") == "unknown" and c.get("license", "unknown") != "unknown":
            seen[k]["license"] = c["license"]
    if not vulndb.offline():
        from concurrent.futures import ThreadPoolExecutor
        todo = [c for c in comps if c.get("license", "unknown") == "unknown"]
        with ThreadPoolExecutor(max_workers=8) as ex:
            for c, lic in zip(todo, ex.map(vulndb.licence, todo)):
                c["license"] = lic
        if any(c["license"] != "unknown" for c in todo):
            vulndb.scan_status()["sources"].add("package registries (licences)")
    return comps


def _reach(pkg, hint):
    if hint is None:
        return None
    hit, unknown = hint
    return None if pkg in unknown else (pkg in hit)


def _dep_type(c):
    return {"required": "direct", "optional": "dev", "dev": "dev", "transitive": "transitive", "embedded": "embedded"}.get(c.get("scope"), "direct")


def match_advisories(comps: list[dict], repo: str = "local", reachable_hint: set | None = None, *, advisory_lookup=None) -> list[dict]:
    out, seen = [], set()
    pairs = vulndb.vulnerabilities(comps)
    if advisory_lookup and comps:
        from . import advisories
        try:
            pairs += advisories.evaluate(comps, advisory_lookup, pairs)
        except Exception as exc:
            vulndb.scan_status()["errors"].add(f"tenant advisory store unavailable: {type(exc).__name__}")
    merged, by_component = {}, {}
    for c, v in pairs:
        key = (c["ecosystem"], c["name"], c["version"], v["cve"] or v["id"])
        prior = merged.get(key)
        if prior is not None:
            for field in ("aliases", "references", "advisory_sources"):
                prior[field] = sorted({*(prior.get(field) or []), *(v.get(field) or [])})
            if not prior.get("fixed") and v.get("fixed"):
                prior["fixed"] = v["fixed"]
            if prior.get("cvss") is None and v.get("cvss") is not None:
                prior.update(cvss=v["cvss"], severity=v["severity"], severity_known=True)
            continue
        by_component.setdefault(key[:3], c)
        merged[key] = dict(v)
    for key, v in merged.items():
        seen.add(key)
        c = by_component[key[:3]]
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
            "nvd_intelligence": v.get("nvd"), "advisory_sources": v.get("advisory_sources", []),
            "references": v.get("references", []), "package": c["name"], "version": c["version"],
            "fixed_version": v["fixed"], "file": c["file"], "repo": repo, "ecosystem": c["ecosystem"], "purl": c["purl"],
            "reachable": _reach(c.get("via") or c["name"], reachable_hint), "exposure": "internet",
            "dependency_type": _dep_type(c), "introduced_by": c.get("via"), "autofix": bool(v["fixed"]) and not c.get("detection"),
            "detection": c.get("detection"), "scope": c.get("scope"),
            "evidence": f"{c['name']} {c['version']}{via} · advisory {v['id']}" + ("" if v["severity_known"] else " · severity not published; severity unknown"),
            "remediation": (f"Upgrade {c['name']} to {v['fixed']} or later" + (f" (it comes in through {c['via']}: upgrade {c['via']} to a release that allows it)" if c.get("via") else "") + ".")
            if v["fixed"] else f"No fixed release published for {c['name']}; assess exposure, apply the advisory's workaround or replace the component.",
        })
    for c in comps:
        for eco, pkg, below, fixed, cve, cvss, epss, kev, cwe, title in ADVISORIES:
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
                    "remediation": f"Upgrade {pkg} to {fixed} or later. RAT Flea DevSec AutoFix can open a PR with the upgrade and lockfile refresh.",
                })
        kind = licence_kind(c.get("license"))
        if kind == "strong":
            out.append({"engine": "license", "rule_id": "NM-LIC-001", "title": f"Copyleft licence {c['license']} in {c['name']}",
                        "severity": "high", "package": c["name"], "version": c["version"], "file": c["file"], "repo": repo,
                        "license": c["license"], "dependency_type": _dep_type(c),
                        "remediation": "Strong copyleft can require releasing your source code when you distribute or host the product. "
                                       "Replace the component or obtain a commercial licence; legal review required."})
        elif kind == "weak":
            out.append({"engine": "license", "rule_id": "NM-LIC-002", "title": f"Weak copyleft licence {c['license']} in {c['name']}",
                        "severity": "info", "package": c["name"], "version": c["version"], "file": c["file"], "repo": repo,
                        "license": c["license"], "dependency_type": _dep_type(c),
                        "remediation": "Usually fine when used unmodified as a separate library; modifications to this component "
                                       "must be published under the same licence. Record it in your third-party notices."})
    return out


def cyclonedx(comps: list[dict], name: str = "application") -> dict:
    """Build a CycloneDX BOM with stable component refs and an explicit dependency graph.

    The graph is based only on dependency relationships resolved by the inventory engine.
    Unknown parent relationships are not guessed; they remain attached to the application root.
    """
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", str(name)).strip("-") or "application"
    app_ref = f"urn:myelin:application:{safe_name}"
    components = []
    by_name = {}
    for c in comps:
        purl = c["purl"]
        by_name.setdefault(c["name"], []).append(purl)
        components.append({
            "type": "library", "bom-ref": purl, "name": c["name"], "version": c["version"],
            "purl": purl,
            "licenses": [{"license": {"id": c["license"]}}] if c.get("license") and c["license"] != "unknown" else [],
            "scope": "optional" if c.get("scope") in ("optional", "dev") else "required",
            "properties": [
                {"name": "myelin:dependency", "value": _dep_type(c)},
                {"name": "myelin:manifest", "value": c.get("file", "")},
            ] + ([{"name": "myelin:introduced-by", "value": c["via"]}] if c.get("via") else [])
              + ([{"name": "myelin:detection", "value": c["detection"]}] if c.get("detection") else []),
            **({"evidence": {"identity": {"field": "purl", "confidence": 0.8 if "banner" in c["detection"] or "constant" in c["detection"]
                                                                     else 0.6 if "file name" in c["detection"] else 1.0,
                                          "methods": [{"technique": "binary-analysis" if re.search(r"\.(jar|war|ear|nupkg|whl)", c.get("file", ""))
                                                       else "filename" if "file name" in c["detection"] else "manifest-analysis"
                                                       if "committed" in c["detection"] else "source-code-analysis",
                                                       "confidence": 0.8, "value": c["detection"]}]},
                             "occurrences": [{"location": c.get("file", "")}]}} if c.get("detection") else {}),
        })

    edges = {app_ref: set()}
    for c in comps:
        child = c["purl"]
        parent_name = c.get("via")
        parents = by_name.get(parent_name, []) if parent_name else []
        # A relationship is emitted only when the inventory resolved one unambiguous parent.
        if len(parents) == 1 and parents[0] != child:
            edges.setdefault(parents[0], set()).add(child)
            edges.setdefault(child, set())
        elif not parent_name:
            edges[app_ref].add(child)
            edges.setdefault(child, set())
        else:
            # Ambiguous or unresolved ancestry remains visible as a direct application dependency.
            edges[app_ref].add(child)
            edges.setdefault(child, set())

    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "RAT Flea DevSec", "name": "RAT Flea DevSec", "version": "1.0.0"}],
            "component": {"type": "application", "bom-ref": app_ref, "name": name},
            "properties": [{"name": "myelin:inventory", "value": "manifest-and-lockfile-derived"}],
        },
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": sorted(children)} for ref, children in sorted(edges.items())],
    }
