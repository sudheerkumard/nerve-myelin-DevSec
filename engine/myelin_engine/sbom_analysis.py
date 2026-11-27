# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Analyse uploaded SBOMs as one project: licence decisions and known vulnerabilities per component.

Accepts CycloneDX (JSON or XML) and SPDX 2.x JSON, one file, several files, or ZIP archives of them. All
components of the files become one project inventory (deduplicated by package and version), so a product made of
several services or modules gets one licence report.
"""
from __future__ import annotations

import io
import json
import re
import time
import xml.etree.ElementTree as ET  # noqa: S405 - parsed with entity expansion disabled below
import zipfile

from . import license_policy, resolve, sbom, vulndb

MAX_FILES = 500
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
SBOM_SUFFIX = re.compile(r"(?i)\.(json|xml|cdx|spdx|bom)$")


class SbomError(ValueError):
    pass


def expand(files: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    """Unpack ZIP archives (one level of nesting) and return (name, bytes) for each candidate SBOM file."""
    out, total = [], 0

    def add(name, data):
        nonlocal total
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise SbomError(f"the upload is larger than {MAX_TOTAL_BYTES // (1024 * 1024)} MB")
        if len(out) >= MAX_FILES:
            raise SbomError(f"more than {MAX_FILES} files")
        out.append((name, data))

    def walk(name, data, depth=0):
        if data[:4] == b"PK\x03\x04":
            if depth > 1:
                return
            try:
                z = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile:
                raise SbomError(f"{name}: not a readable ZIP archive") from None
            for info in z.infolist():
                if info.is_dir() or info.file_size > MAX_FILE_BYTES or "__MACOSX" in info.filename:
                    continue
                inner = info.filename
                if inner.lower().endswith(".zip") or SBOM_SUFFIX.search(inner):
                    walk(f"{name}/{inner}", z.read(info), depth + 1)
            return
        if len(data) > MAX_FILE_BYTES:
            raise SbomError(f"{name} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        add(name, data)

    for name, data in files:
        walk(name, data)
    return out


def _spdx_components(doc: dict) -> list[dict]:
    comps = []
    for pkg in doc.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        purl = next((str(x.get("referenceLocator")) for x in pkg.get("externalRefs") or []
                     if isinstance(x, dict) and str(x.get("referenceType", "")).lower() == "purl"), "")
        lic = next((x for x in (pkg.get("licenseConcluded"), pkg.get("licenseDeclared"))
                    if x and str(x).upper() not in ("NOASSERTION", "NONE")), None)
        comps.append({"type": "library", "bom-ref": pkg.get("SPDXID"), "name": pkg.get("name"),
                      "version": pkg.get("versionInfo"), "purl": purl,
                      "licenses": [{"expression": lic}] if lic else []})
    return comps


def _xml_components(data: bytes) -> list[dict]:
    if b"<!ENTITY" in data or b"<!DOCTYPE" in data:
        raise SbomError("XML SBOMs with DOCTYPE or entity declarations are not accepted")
    root = ET.fromstring(data)  # noqa: S314 - DOCTYPE/entities rejected above
    ns = re.match(r"\{[^}]+\}", root.tag)
    p = ns.group(0) if ns else ""
    if not root.tag.endswith("bom"):
        raise SbomError("XML is not a CycloneDX BOM")
    comps = []
    for c in root.iter(f"{p}component"):
        purl = (c.findtext(f"{p}purl") or "").strip()
        lic = None
        for L in c.iter(f"{p}license"):
            lic = (L.findtext(f"{p}id") or L.findtext(f"{p}name") or "").strip() or None
            if lic:
                break
        if not lic:
            lic = (c.findtext(f"{p}licenses/{p}expression") or "").strip() or None
        comps.append({"type": c.get("type") or "library", "bom-ref": c.get("bom-ref"), "name": c.findtext(f"{p}name"),
                      "version": c.findtext(f"{p}version"), "purl": purl,
                      "licenses": [{"license": {"id": lic}}] if lic else []})
    return comps


def _flatten(items: list) -> list:
    out = []
    for c in items or []:
        if isinstance(c, dict):
            out.append(c)
            out.extend(_flatten(c.get("components")))
    return out


def parse(name: str, data: bytes) -> tuple[list[dict], str]:
    """Components (engine shape) and the detected format of one SBOM file."""
    text = data.lstrip()[:1]
    if text == b"<":
        raw, fmt = _xml_components(data), "CycloneDX XML"
        doc = {"components": raw}
    else:
        try:
            doc = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SbomError(f"{name}: not JSON or XML") from None
        if not isinstance(doc, dict):
            raise SbomError(f"{name}: not an SBOM document")
        if doc.get("bomFormat") == "CycloneDX":
            fmt = f"CycloneDX {doc.get('specVersion') or ''}".strip()
            doc = {**doc, "components": _flatten(doc.get("components"))}
        elif str(doc.get("spdxVersion") or "").startswith("SPDX-"):
            fmt = doc["spdxVersion"]
            doc = {"components": _spdx_components(doc)}
        else:
            raise SbomError(f"{name}: not a CycloneDX or SPDX JSON document")
    comps = resolve._cdx_components(doc, name)
    without_purl = sum(1 for c in doc.get("components") or [] if isinstance(c, dict) and not c.get("purl")
                       and c.get("type") not in ("application", "operating-system", "file"))
    for c in comps:
        c["source_sbom"] = name
        if str(c.get("license") or "").lower() in ("unknown", "noassertion", "none", ""):
            c["license"] = None
    if without_purl:
        fmt += f" ({without_purl} components without a package URL were skipped)"
    return comps, fmt


def merge(components: list[dict]) -> list[dict]:
    """One entry per (ecosystem, name, version); keeps every source file and the first known licence."""
    by = {}
    for c in components:
        key = (c["ecosystem"], c["name"].lower() if c["ecosystem"] in ("nuget", "maven") else c["name"], c["version"])
        if key not in by:
            by[key] = {**c, "sources": [c.get("source_sbom")]}
            continue
        b = by[key]
        if c.get("source_sbom") not in b["sources"]:
            b["sources"].append(c.get("source_sbom"))
        if not b.get("license") and c.get("license"):
            b["license"] = c["license"]
    return list(by.values())


def _resolve_licences(comps: list[dict], budget=300, seconds=45) -> int:
    if vulndb.offline():
        return 0
    deadline, n = time.monotonic() + seconds, 0
    for c in comps:
        if c.get("license") or budget <= 0 or time.monotonic() > deadline:
            continue
        budget -= 1
        try:
            lic = vulndb.licence(c)
        except Exception:
            lic = None
        if lic:
            c["license"], c["license_source"] = lic, "package registry"
            n += 1
    return n


def analyse(project: str, files: list[tuple[str, bytes]], policy: dict | None = None, *, vulnerabilities=True) -> dict:
    """Parse, merge and evaluate. Returns the project record (summary, files, licences, vulnerabilities, sbom)."""
    expanded = expand(files)
    if not expanded:
        raise SbomError("no SBOM files found (upload CycloneDX or SPDX JSON/XML files, or a ZIP of them)")
    parsed, everything = [], []
    for name, data in expanded:
        try:
            comps, fmt = parse(name, data)
            parsed.append({"file": name, "format": fmt, "components": len(comps)})
            everything += comps
        except (SbomError, ET.ParseError) as e:
            parsed.append({"file": name, "error": str(e)[:300]})
    comps = merge(everything)
    if not comps:
        raise SbomError("the SBOM files contain no components with package URLs; " +
                        "; ".join(f"{p['file']}: {p.get('error') or 'no components'}" for p in parsed)[:600])
    resolved = _resolve_licences(comps)
    with vulndb.scan_intelligence():
        vulns = sbom.match_advisories(comps, repo=f"sbom:{project}") if vulnerabilities else []
        status = vulndb.scan_status()
        intel = {"sources": sorted(status["sources"]), "errors": sorted(status["errors"])[:10], "offline": vulndb.offline()}
    lic_rows = license_policy.evaluate_components(
        [{"name": c["name"], "version": c["version"], "purl": c.get("purl"), "license": c.get("license") or "unknown"}
         for c in comps], policy)
    for row, c in zip(lic_rows, comps):
        row.update(ecosystem=c["ecosystem"], sources=c.get("sources"), license_source=c.get("license_source") or "SBOM"
                   if c.get("license") else None, scope=c.get("scope"))
    sev = {}
    for v in vulns:
        sev[v.get("severity", "medium")] = sev.get(v.get("severity", "medium"), 0) + 1
    counts = {k: sum(1 for r in lic_rows if r["decision"] == k) for k in ("allow", "review", "deny")}
    by_cat = {}
    for r in lic_rows:
        by_cat[r.get("category") or "unknown"] = by_cat.get(r.get("category") or "unknown", 0) + 1
    return {
        "name": project, "files": parsed, "components": len(comps),
        "summary": {"licence_decisions": counts, "licence_categories": by_cat, "licences_resolved_online": resolved,
                    "vulnerabilities": len(vulns), "vulnerability_severity": sev,
                    "ecosystems": sorted({c["ecosystem"] for c in comps})},
        "licences": lic_rows, "vulnerabilities": vulns, "intelligence": intel,
        "sbom": sbom.cyclonedx(comps, project),
    }


def _e(x) -> str:
    import html
    return html.escape("" if x is None else str(x), quote=True)


def render_html(rec: dict, organisation: str = "") -> str:
    """Self-contained licence and vulnerability report for one SBOM project, with mitigation steps."""
    from . import __version__, mitigation
    s = rec.get("summary") or {}
    lic = rec.get("licences") or []
    vul = sorted(rec.get("vulnerabilities") or [],
                 key=lambda v: ("critical", "high", "medium", "low", "info").index(v.get("severity", "medium"))
                 if v.get("severity") in ("critical", "high", "medium", "low", "info") else 5)
    order = {"deny": 0, "review": 1, "allow": 2}
    lic = sorted(lic, key=lambda r: (order.get(r.get("decision"), 3), str(r.get("package"))))
    d = s.get("licence_decisions") or {}
    sev = s.get("vulnerability_severity") or {}
    chip = lambda t, c: f'<span class="chip {c}">{_e(t)}</span>'  # noqa: E731
    dc = {"deny": "bad", "review": "warn", "allow": "ok"}
    files = "".join(f"<tr><td class=mono>{_e(f['file'])}</td><td>{_e(f.get('format') or '')}</td>"
                    f"<td>{_e(f.get('components', ''))}</td><td class=bad-t>{_e(f.get('error') or '')}</td></tr>"
                    for f in rec.get("files") or [])
    lic_rows = "".join(
        f"<tr><td class=mono>{_e(r.get('package'))}</td><td>{_e(r.get('version'))}</td><td class=mono>{_e(r.get('expression'))}"
        f"{'<div class=muted>from ' + _e(r['license_source']) + '</div>' if r.get('license_source') == 'package registry' else ''}</td>"
        f"<td>{chip(r.get('decision'), dc.get(r.get('decision'), ''))}</td><td>{_e((r.get('category') or '').replace('_', ' '))}</td>"
        f"<td>{_e(r.get('reason'))}<div class=muted><b>Obligations:</b> {_e(r.get('obligations'))}</div>"
        f"<div><b>Action:</b> {_e(r.get('action'))}</div></td></tr>" for r in lic)
    vul_rows = []
    for v in vul:
        g = mitigation.guidance(v)
        steps = "".join(f"<li>{_e(x)}</li>" for x in g["steps"])
        vul_rows.append(
            f"<tr><td>{chip(v.get('severity'), {'critical': 'bad', 'high': 'bad', 'medium': 'warn'}.get(v.get('severity'), ''))}</td>"
            f"<td class=mono>{_e(v.get('package'))}@{_e(v.get('version'))}</td><td class=mono>{_e(v.get('cve') or v.get('advisory'))}"
            f"{' · KEV' if v.get('kev') else ''}</td><td>{_e(v.get('title'))}</td><td>{_e(v.get('fixed_version') or 'no fix published')}</td>"
            f"<td><ol>{steps}</ol><div class=muted>Verify: {_e(g['verify'])}</div></td></tr>")
    gen = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    return f"""<!DOCTYPE html><html lang=en><head><meta charset=utf-8><title>SBOM report — {_e(rec.get('name'))}</title>
<style>body{{font:13px/1.45 system-ui,Segoe UI,Arial,sans-serif;color:#0f172a;margin:28px;max-width:1400px}}
h1{{font-size:22px;margin:0}}h2{{font-size:16px;margin:26px 0 8px;border-bottom:2px solid #e2e8f0;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;table-layout:fixed}}th,td{{border-bottom:1px solid #e2e8f0;padding:6px 8px;text-align:left;
vertical-align:top;word-break:break-word}}th{{background:#f8fafc;font-size:11px;text-transform:uppercase;letter-spacing:.04em}}
.mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}.muted{{color:#64748b;font-size:12px;margin-top:3px}}
.chip{{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;border:1px solid #cbd5e1}}
.ok{{background:#ecfdf5;color:#047857}}.warn{{background:#fffbeb;color:#b45309}}.bad{{background:#fef2f2;color:#b91c1c}}
.bad-t{{color:#b91c1c}}.kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}}.kpi{{border:1px solid #e2e8f0;border-radius:8px;
padding:10px 14px;min-width:150px}}.kpi b{{font-size:22px;display:block}}ol{{margin:0;padding-left:18px}}
@media print{{body{{margin:10mm}}tr{{break-inside:avoid}}}}</style></head><body>
<h1>SBOM licence and vulnerability report — {_e(rec.get('name'))}</h1>
<div class=muted>{_e(organisation)} · generated {gen} · RAT Flea DevSec {__version__} · {rec.get('components', 0)} components ·
ecosystems {_e(', '.join(s.get('ecosystems') or []))}</div>
<div class=kpis><div class=kpi><b>{d.get('deny', 0)}</b>licences denied</div><div class=kpi><b>{d.get('review', 0)}</b>licences to review</div>
<div class=kpi><b>{d.get('allow', 0)}</b>licences allowed</div><div class=kpi><b>{sev.get('critical', 0) + sev.get('high', 0)}</b>critical/high vulnerabilities</div>
<div class=kpi><b>{s.get('vulnerabilities', 0)}</b>vulnerabilities in total</div></div>
<h2>SBOM files analysed</h2><table><colgroup><col style="width:45%"><col style="width:20%"><col style="width:10%"><col></colgroup>
<tr><th>File</th><th>Format</th><th>Components</th><th>Problem</th></tr>{files}</table>
<h2>Licence findings</h2><p class=muted>Each component's licence is checked against the SPDX licence policy. Licences missing from the
SBOM were looked up in the package registry where possible. This is triage guidance, not legal advice.</p>
<table><colgroup><col style="width:22%"><col style="width:8%"><col style="width:12%"><col style="width:8%"><col style="width:10%"><col></colgroup>
<tr><th>Package</th><th>Version</th><th>Licence</th><th>Decision</th><th>Category</th><th>Reason, obligations and action</th></tr>{lic_rows}</table>
<h2>Known vulnerabilities</h2>{'' if vul_rows else '<p>No known vulnerabilities were found for these component versions in the advisory sources used.</p>'}
{'<table><colgroup><col style="width:7%"><col style="width:17%"><col style="width:12%"><col style="width:22%"><col style="width:9%"><col></colgroup><tr><th>Severity</th><th>Component</th><th>Advisory</th><th>Title</th><th>Fixed in</th><th>Mitigation steps</th></tr>' + ''.join(vul_rows) + '</table>' if vul_rows else ''}
<p class=muted>Advisory sources: {_e(', '.join((rec.get('intelligence') or {}).get('sources') or []) or 'none reachable')}.
{_e('; '.join((rec.get('intelligence') or {}).get('errors') or []))}</p>
<p class=muted>RAT Flea DevSec Product designed and developed by Sudheer Kumar — https://github.com/sudheerkumard/nervve-devsecops</p>
</body></html>"""


def to_csv(rec: dict) -> str:
    q = lambda v: '"' + str("" if v is None else v).replace('"', '""') + '"'  # noqa: E731
    lines = [",".join(["type", "package", "version", "licence", "decision", "category", "severity", "advisory",
                       "fixed_version", "reason", "obligations", "action", "sbom_files"])]
    for r in rec.get("licences") or []:
        lines.append(",".join(q(x) for x in ["licence", r.get("package"), r.get("version"), r.get("expression"),
                                             r.get("decision"), r.get("category"), "", "", "", r.get("reason"),
                                             r.get("obligations"), r.get("action"), "; ".join(r.get("sources") or [])]))
    from . import mitigation
    for v in rec.get("vulnerabilities") or []:
        lines.append(",".join(q(x) for x in ["vulnerability", v.get("package"), v.get("version"), "", "", "",
                                             v.get("severity"), v.get("cve") or v.get("advisory"), v.get("fixed_version"),
                                             v.get("title"), "", mitigation.as_text(v), ""]))
    return "\r\n".join(lines)
