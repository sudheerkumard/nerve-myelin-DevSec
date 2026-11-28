# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Corporate application-security assessment report for a repository scan.

One self-contained HTML document (no external assets, no scripts required) that prints to a paginated A4 PDF from
any browser: cover, document control, contents, executive summary with charts, framework alignment (OWASP, CWE Top 25,
OWASP CI/CD, PCI DSS v4.0, ISO/IEC 27001:2022, NIST SSDF, NIST SP 800-53, SOC 2, CIS), remediation roadmap, detailed
findings, software bill of materials, methodology, definitions and attestation.

audience="external" produces the version a customer can hand to *their* customers: code evidence, line numbers and
secret locations are withheld, and the wording addresses an outside reader.
"""
import hashlib
import html
from collections import Counter, defaultdict
from datetime import datetime, timezone

from . import frameworks as FW
from . import mitigation as MIT

SEV = ["critical", "high", "medium", "low", "info"]
# Severity is a status-style encoding: always shown with its label, never by colour alone.
SEV_COL = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#2a78d6", "info": "#898781"}
SEV_INK = {"critical": "#fff", "high": "#0b0b0b", "medium": "#0b0b0b", "low": "#fff", "info": "#fff"}
STATUS = {  # framework control evidence status
    "gap": ("Gap", "#d03b3b", "✕"), "observation": ("Observation", "#fab219", "!"),
    "clear": ("No issues found", "#0ca30c", "✓"), "not_tested": ("Not assessed", "#c3c2b7", "–"),
}
ENGINES = [
    ("sast", "Source code analysis (SAST)", "Flaws in first-party code: injection, weak cryptography, unsafe deserialisation, disabled verification."),
    ("sca", "Software components (SCA)", "Known vulnerabilities (CVE) and end of life in third-party packages (direct and transitive, "
            "with reachability), operating-system packages, native binaries, firmware, drivers, and the databases, middleware "
            "and platforms declared in infrastructure code."),
    ("secrets", "Secrets exposure", "Credentials, keys and tokens committed to the repository."),
    ("iac", "Infrastructure as Code", "Misconfiguration in Dockerfiles, Kubernetes, Helm, Terraform, Bicep, Compose and cloud templates."),
    ("cicd", "CI/CD pipeline & deployment", "Build pipelines and continuous delivery: script injection, unpinned actions, token scope, "
                                            "GitOps (Argo CD / Flux), approvals, release integrity."),
    ("license", "Licence compliance", "Third-party licences that conflict with the organisation's policy."),
    ("supply", "Software supply chain", "Known-malicious, typosquatted or unpublished packages, install scripts and dependency confusion."),
    ("aibom", "AI components (AI-BOM)", "Models, prompts and agents: unpinned models, remote code, prompt injection, excessive agency."),
    ("dast", "Live application & API testing (DAST)", "Transport security, headers, authentication enforcement and multi-user authorisation "
                                                     "(object, property and function level) against the running service."),
]
CODE_AREAS = [k for k, *_ in ENGINES if k != "dast"]
PRIORITY = {"P0": ("Immediate", 2), "P1": ("Urgent", 7), "P2": ("Planned", 30), "P3": ("Routine", 90)}


def _e(x):
    return html.escape("" if x is None else str(x), quote=True)


def _css(x):
    """Text for a CSS string inside <style> (HTML entities are not decoded there)."""
    return "".join(c for c in str(x or "") if c not in '<>\\"\n\r{};')[:120]


def _risk(fs):
    sev = Counter(f.get("severity") for f in fs)
    pri = Counter(f.get("priority") for f in fs)
    if sev["critical"] or pri["P0"]:
        return "Critical", "#d03b3b", "#fff", "At least one critical weakness is open; exploitation could lead to compromise of the application or its data."
    if sev["high"] or pri["P1"]:
        return "High", "#ec835a", "#0b0b0b", "High-severity weaknesses are open; they should be remediated before the next release."
    if sev["medium"]:
        return "Medium", "#fab219", "#0b0b0b", "Only medium and low-severity weaknesses are open; remediate within the planned cycle."
    if sev["low"] or sev["info"]:
        return "Low", "#2a78d6", "#fff", "Only low-severity observations are open."
    return "Minimal", "#0ca30c", "#fff", "No open weaknesses were identified by the automated assessment."


def _sevchip(s):
    s = s or "info"
    return f'<span class="sev" style="background:{SEV_COL.get(s, "#898781")};color:{SEV_INK.get(s, "#fff")}">{_e(s)}</span>'


def _bars(rows, total=None, color="#2a78d6", unit=""):
    """Horizontal bar chart (one series): rows = [(label, value, optional colour)]. Values are labelled directly."""
    if not rows:
        return '<p class="muted">Nothing to chart.</p>'
    m = max(v for _, v, *_ in rows) or 1
    out = []
    for label, v, *c in rows:
        col = c[0] if c else color
        pct = 100 * v / m
        share = f" · {100 * v / total:.0f}%" if total else ""
        out.append(f'<div class="bar-row" title="{_e(label)}: {v}{unit}{share}"><div class="bar-l">{_e(label)}</div>'
                   f'<div class="bar-t"><div class="bar" style="width:{max(pct, 0.8):.2f}%;background:{col}"></div></div>'
                   f'<div class="bar-v">{v}{unit}<span class="muted">{share}</span></div></div>')
    return '<div class="bars">' + "".join(out) + "</div>"


def _stack(parts, total):
    """A single 100% stacked bar: parts = [(label, value, colour)] with 2px surface gaps between segments."""
    if not total:
        return '<div class="stack empty"></div>'
    segs = "".join(f'<div class="seg" title="{_e(lab)}: {v}" style="flex:{v};background:{col}"></div>' for lab, v, col in parts if v)
    return f'<div class="stack">{segs}</div>'


from .brand import PRODUCT, REPO_URL, logo_svg  # noqa: E402
VENDOR = PRODUCT                                 # "Prepared by"
SITE = REPO_URL.split("://", 1)[1]


def vuln_id(f):
    """The public identifier of a dependency vulnerability: CVE first, otherwise the advisory (GHSA, PYSEC, OSV …)."""
    if f.get("cve"):
        return str(f["cve"])
    for a in [f.get("advisory"), f.get("rule_id")] + list(f.get("aliases") or []):
        if a and not str(a).startswith("NM-"):
            return str(a)
    return ""


def vuln_url(i):
    i = str(i)
    if i.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{i}"
    if i.startswith("GHSA-"):
        return f"https://github.com/advisories/{i}"
    return f"https://osv.dev/vulnerability/{i}"


def _vlink(i):
    return f'<a class="ext" href="{_e(vuln_url(i))}" target="_blank" rel="noopener">{_e(i)}</a>' if i else ""


def _cwelink(c):
    n = str(c or "").upper().replace("CWE-", "")
    return f'<a class="ext" href="https://cwe.mitre.org/data/definitions/{_e(n)}.html" target="_blank" rel="noopener">CWE-{_e(n)}</a>' if n.isdigit() else _e(c)


def vmax(vs):
    """Highest version, compared as versions (5.2.17 > 4.10.1), not as text."""
    try:
        from packaging.version import Version
        return str(max(vs, key=Version))
    except Exception:  # noqa: BLE001  (non-PEP 440 versions)
        return max(vs, key=lambda v: [int(x) if x.isdigit() else 0 for x in str(v).replace("-", ".").split(".")])


def _pct(v):
    return "—" if v in (None, "") else f"{float(v) * 100:.1f}%"


def _kpis(cards):
    """KPI strip: (label, value, sub-label, accent colour)."""
    return '<div class="kpis">' + "".join(
        f'<div class="kpi" style="--a:{a}"><div class="kpi-l">{_e(l)}</div><div class="kpi-v">{v}</div><div class="kpi-s">{s}</div></div>'
        for l, v, s, a in cards) + "</div>"


def _sev_strip(sev, total):
    """Severity mix as one 100% bar with 2px gaps, labelled legend underneath (identity never by colour alone)."""
    order = ["critical", "high", "medium", "low"] + (["info"] if sev.get("info") else [])
    if not total:
        return '<div class="strip empty"></div><p class="clear">✓ No open findings.</p>'
    segs = "".join(f'<div class="seg" style="flex:{sev[k]};background:{SEV_COL[k]}" title="{k.capitalize()}: {sev[k]}"></div>'
                   for k in order if sev.get(k))
    leg = "".join(f'<div class="sl"><span class="sw" style="background:{SEV_COL[k]}"></span><b>{sev.get(k, 0)}</b>'
                  f'<span>{k.capitalize()}</span><i>{100 * sev.get(k, 0) / total:.0f}%</i></div>' for k in order)
    return f'<div class="strip">{segs}</div><div class="sleg">{leg}</div>'


def _area_stack(fs, areas):
    """Open findings per area, stacked by severity, on one shared scale."""
    rows = []
    for k, name in areas:
        c = Counter(f.get("severity") for f in fs if f.get("engine") == k)
        rows.append((name, c, sum(c.values())))
    rows = [r for r in rows if r[2]]
    if not rows:
        return '<p class="clear">✓ No open findings.</p>'
    m = max(r[2] for r in rows)
    out = []
    for name, c, t in sorted(rows, key=lambda r: -r[2]):
        segs = "".join(f'<div class="seg" style="flex:{c[k]};background:{SEV_COL[k]}" title="{_e(name)} · {k}: {c[k]}"></div>'
                       for k in SEV if c.get(k))
        out.append(f'<div class="ar"><div class="ar-l">{_e(name)}</div><div class="ar-t"><div class="ar-b" style="width:{100 * t / m:.1f}%">{segs}</div></div>'
                   f'<div class="ar-v">{t}</div></div>')
    leg = "".join(f'<span><i style="background:{SEV_COL[k]}"></i>{k.capitalize()}</span>' for k in ["critical", "high", "medium", "low"])
    return '<div class="areas">' + "".join(out) + f'</div><div class="mini-leg">{leg}</div>'


def _hist(fs):
    """Distribution of risk scores (0-100) in ten buckets: SVG columns, one hue."""
    b = [0] * 10
    for f in fs:
        b[min(int(float(f.get("mrs") or 0) // 10), 9)] += 1
    if not fs:
        return ""
    W, H, pad, top = 340, 130, 22, 14
    m = max(b) or 1
    bw = (W - 8) / 10
    cols = []
    for i, v in enumerate(b):
        h = (H - pad - top) * v / m
        x, y = 4 + i * bw + 3, H - pad - h
        col = "#d03b3b" if i >= 8 else "#ec835a" if i >= 6 else "#2a78d6"
        if v:
            cols.append(f'<path d="M{x:.1f},{H - pad} V{y + 4:.1f} Q{x:.1f},{y:.1f} {x + 4:.1f},{y:.1f} H{x + bw - 10:.1f} '
                        f'Q{x + bw - 6:.1f},{y:.1f} {x + bw - 6:.1f},{y + 4:.1f} V{H - pad} Z" fill="{col}"><title>Risk score {i * 10}–{i * 10 + 9}: {v}</title></path>'
                        f'<text x="{x + (bw - 6) / 2:.1f}" y="{y - 3:.1f}" text-anchor="middle" class="hv">{v}</text>')
        cols.append(f'<text x="{x + (bw - 6) / 2:.1f}" y="{H - 8}" text-anchor="middle" class="hx">{i * 10}</text>')
    return (f'<svg viewBox="0 0 {W} {H}" class="hist" role="img" aria-label="Distribution of risk scores">'
            f'<line x1="4" x2="{W - 4}" y1="{H - pad}" y2="{H - pad}" stroke="#c3c2b7"/>{"".join(cols)}</svg>'
            '<div class="mini-leg"><span><i style="background:#2a78d6"></i>0–59</span><span><i style="background:#ec835a"></i>60–79</span>'
            '<span><i style="background:#d03b3b"></i>80–100</span></div>')


def _heat(matrix):
    """Control-level heat strip: one cell per control, coloured by evidence status, labelled by the control id on hover."""
    rows = []
    for m in matrix:
        if m["id"] == "cwe25":
            continue
        cells = []
        for c in m["controls"]:
            lab, col, ic = STATUS[c["status"]]
            n = f" ({c['count']} open)" if c["count"] else ""
            cells.append(f'<span class="hc" style="background:{col}" title="{_e(c["id"])} — {_e(c["title"])}: {lab}{n}">'
                         f'{ic if c["status"] != "not_tested" else ""}</span>')
        cells = "".join(cells)
        tot = len(m["controls"]) or 1
        ok = 100 * m["clear"] / tot
        rows.append(f'<div class="hr"><div class="hr-l"><b>{_e(m["name"])}</b><span>{_e(m["version"])}</span></div><div class="hr-c">{cells}</div>'
                    f'<div class="hr-v"><b>{m["gaps"]}</b> gaps · {ok:.0f}% clear</div></div>')
    leg = "".join(f'<span><i style="background:{STATUS[k][1]}"></i>{STATUS[k][0]}</span>' for k in STATUS if k != "not_tested")
    return '<div class="heat">' + "".join(rows) + f'</div><div class="mini-leg">{leg}</div>'


def _timeline(pri):
    steps = []
    for p, (lab, days) in PRIORITY.items():
        n = len(pri.get(p, []))
        col = {"P0": "#d03b3b", "P1": "#ec835a", "P2": "#fab219", "P3": "#2a78d6"}[p]
        steps.append(f'<div class="tl" style="--c:{col}"><div class="tl-d">{days} days</div><div class="tl-n">{n}</div>'
                     f'<div class="tl-p"><b>{p}</b> {lab}</div></div>')
    return '<div class="timeline">' + "".join(steps) + "</div>"


def _loc(f, external):
    if f.get("engine") in ("sca", "license", "aibom") and f.get("package"):
        return f'{f.get("package")} {f.get("version") or ""}'.strip() + (f' · {f["file"]}' if f.get("file") else "")
    if f.get("engine") == "dast":
        return f.get("file") or f.get("url") or ""
    if external and f.get("engine") == "secrets":
        return "withheld in the external edition"
    file = f.get("file") or ""
    return file if external or not f.get("line") else f"{file}:{f['line']}"


def render(result, *, issuer="", prepared_for="", source_url="", classification="Confidential", audience="internal",
           title="Application Security Assessment", logo_text="", now=None, kind="code"):
    external = audience == "external"
    dast = kind == "dast"
    now = now or datetime.now(timezone.utc)
    when = now.strftime("%d %B %Y")
    scan_date = when
    if result.get("started_at"):
        try:
            scan_date = datetime.fromisoformat(result["started_at"]).strftime("%d %B %Y")
        except (TypeError, ValueError):
            pass
    cov = result.get("coverage") or {}
    recorded_findings = [f for f in result.get("findings", []) if f.get("engine") != "meta"]
    if dast:
        engines_run = ["dast"] if result.get("requests") or recorded_findings else []
    elif "coverage" in result:
        engines_run = [k for k, c in cov.items() if c.get("assessed")]
    else:                                       # older reports: findings are the only proof of assessment
        engines_run = sorted({f["engine"] for f in recorded_findings if f.get("engine")})
    fs_all = [f for f in recorded_findings if f.get("engine") in engines_run]
    fs = [f for f in fs_all if f.get("status", "open") not in ("suppressed", "fixed", "risk_accepted", "accepted", "false_positive")]
    excluded = len(fs_all) - len(fs)
    fs.sort(key=lambda f: (SEV.index(f.get("severity", "info")) if f.get("severity") in SEV else 9, -float(f.get("mrs") or 0)))
    sev = Counter(f.get("severity", "info") for f in fs)
    by_eng = Counter(f.get("engine") for f in fs)
    comps = ((result.get("sbom") or {}).get("components") or []) if {"sca", "license", "supply"} & set(engines_run) else []
    failed_tools = sorted({f["rule_id"].split(":", 1)[1] for f in result.get("findings", [])
                           if f.get("engine") == "meta" and str(f.get("rule_id", "")).startswith("tool-error:")}
                          | {t["name"] for c in cov.values() for t in c.get("tools") or [] if t.get("error")})
    zap = (result.get("stats") or {}).get("zap") or {}
    partial = {k for k in engines_run if cov.get(k, {}).get("status") == "partial"}
    if dast and zap.get("complete") is False:
        partial.update(engines_run)
    incomplete = bool(partial or failed_tools or not engines_run)
    empty_findings = ('<p class="muted">No open findings were recorded. Coverage is incomplete.</p>' if incomplete
                      else '<p class="clear">✓ No open findings.</p>')
    # Only controls an assessed area tests are reported; frameworks with none are left out
    matrix = []
    for m in FW.matrix(fs, [k for k in engines_run if k not in partial and k != "dast"]):
        m["controls"] = [c for c in m["controls"] if c["status"] != "not_tested"]
        m["not_tested"] = 0
        if m["controls"]:
            matrix.append(m)
    risk, rcol, rink, rtext = _risk(fs)
    if not fs and incomplete:
        risk, rcol, rink, rtext = "Undetermined", "#766336", "#fff", "Coverage is incomplete."
    d = result.get("decision") or {}
    repo = result.get("repo") or (result.get("name") if dast else None) or ("application" if dast else "repository")
    src = source_url or result.get("target") or result.get("path") or ""
    commit = result.get("commit") or ""
    rid = "NM-" + now.strftime("%Y%m%d") + "-" + hashlib.sha256(f"{repo}{commit}{now.isoformat()}".encode()).hexdigest()[:6].upper()
    customer = issuer or ""                     # the tenant: the organisation that owns the assessed code
    issuer = VENDOR
    cves = sorted({f["cve"] for f in fs if f.get("cve")})
    kev = sum(1 for f in fs if f.get("kev"))
    reach = sum(1 for f in fs if f.get("reachable"))

    # ------------------------------------------------------------ executive summary
    [(s.capitalize(), sev[s], SEV_COL[s]) for s in SEV if s != "info" or sev[s]]
    eng_rows = [(name, by_eng[k]) for k, name, _ in ENGINES if k in engines_run or by_eng[k]]
    eng_rows.sort(key=lambda r: -r[1])
    gaps_fw = [m for m in matrix if m["gaps"]]
    keymsgs = []
    if sev["critical"] or sev["high"]:
        keymsgs.append(f'<b>{sev["critical"] + sev["high"]}</b> critical or high-severity weaknesses require remediation before release.')
    top_area = max(eng_rows, key=lambda r: r[1]) if eng_rows and eng_rows[0][1] else None
    if top_area:
        keymsgs.append(f'The largest share of findings is in <b>{_e(top_area[0])}</b> ({top_area[1]} of {len(fs)}).')
    if cves:
        keymsgs.append(f'<b>{len(cves)}</b> distinct CVEs affect third-party components{f"; <b>{kev}</b> are on the CISA Known Exploited Vulnerabilities list" if kev else ""}'
                       f'{f"; <b>{reach}</b> findings are reachable from first-party code" if reach else ""}.')
    if by_eng["secrets"]:
        keymsgs.append(f'<b>{by_eng["secrets"]}</b> secret(s) were found in source; they must be revoked and rotated, not only deleted.')
    if gaps_fw:
        keymsgs.append("Gaps were identified against " + ", ".join(f'<b>{_e(m["name"])}</b>' for m in gaps_fw[:5]) + ".")
    if incomplete:
        keymsgs.append("Coverage is incomplete. Findings and risk ratings reflect the checks that returned results.")
    elif not fs:
        keymsgs.append("No open weaknesses were identified across the assessed areas.")
    if d.get("decision"):
        keymsgs.append(f'Release gate ({_e(d.get("policy") or "default policy")}): <b>{_e(str(d["decision"]).upper())}</b>'
                       f' — {d.get("blocking", 0)} blocking, {d.get("warnings", 0)} warnings.')

    # ------------------------------------------------------------ framework summary + detail
    fw_rows, fw_detail = [], []
    for i, m in enumerate(matrix):
        tot = len(m["controls"])
        parts = [("Gap", m["gaps"], STATUS["gap"][1]), ("Observation", m["observations"], STATUS["observation"][1]),
                 ("No issues found", m["clear"], STATUS["clear"][1])]
        if m["id"] == "cwe25":
            fw_rows.append(f'<tr><td><a href="#fw-{m["id"]}"><b>{_e(m["name"])}</b></a><div class="muted">{_e(m["version"])}</div></td>'
                           f'<td colspan="4">{tot} of the 25 weaknesses present ({sum(c["count"] for c in m["controls"])} findings)</td></tr>')
        else:
            fw_rows.append(f'<tr><td><a href="#fw-{m["id"]}"><b>{_e(m["name"])}</b></a><div class="muted">{_e(m["version"])}</div></td>'
                           f'<td class="num">{m["gaps"]}</td><td class="num">{m["observations"]}</td><td class="num">{m["clear"]}</td>'
                           f'<td style="width:34%">{_stack(parts, tot)}</td></tr>')
        crow = []
        for c in m["controls"]:
            lab, col, ic = STATUS[c["status"]]
            sv = " ".join(f'{_sevchip(s)} {c["severity"][s]}' for s in SEV if c["severity"].get(s))
            crow.append(f'<tr><td class="mono nowrap">{_e(c["id"])}</td><td>{_e(c["title"])}</td>'
                        f'<td class="nowrap"><span class="st" style="--c:{col}">{ic}</span> {lab}</td><td>{sv or "—"}</td></tr>')
        empty = '<tr><td colspan="4" class="muted">None of the CWE Top 25 weaknesses were found.</td></tr>' if m["id"] == "cwe25" else ""
        fw_detail.append(f'<h3 id="fw-{m["id"]}">6.{i + 2} {_e(m["name"])} <span class="muted">{_e(m["version"])}</span></h3>'
                         f'<table class="ctl"><thead><tr><th>Control</th><th>Requirement</th><th>Evidence status</th><th>Open findings</th></tr></thead>'
                         f'<tbody>{"".join(crow) or empty}</tbody></table>')

    # ------------------------------------------------------------ top risks
    top = sorted(fs, key=lambda f: -float(f.get("mrs") or 0))[:10]
    top_rows = "".join(
        f'<tr><td class="num">{i + 1}</td><td><a href="#{_e(f.get("id"))}"><b>{_e(f.get("title"))}</b></a>'
        f'<div class="muted">{_e(dict((k, n) for k, n, _ in ENGINES).get(f.get("engine"), f.get("engine")))} · {_e(_loc(f, external))}</div></td>'
        f'<td>{_sevchip(f.get("severity"))}</td><td class="num">{_e(f.get("priority"))}</td><td><div class="mrs" style="--c:{SEV_COL.get(f.get("severity"), "#898781")}"><i style="width:{float(f.get("mrs") or 0) * .5:.0f}px"></i><b>{_e(f.get("mrs"))}</b></div></td>'
        f'<td class="nowrap">{_vlink(vuln_id(f)) if f.get("engine") == "sca" and vuln_id(f) else _cwelink(f.get("cwe")) if f.get("cwe") else ""}</td></tr>'
        for i, f in enumerate(top))

    # ------------------------------------------------------------ remediation roadmap
    pri = defaultdict(list)
    for f in fs:
        pri[f.get("priority") or "P3"].append(f)
    road = []
    for p, (lab, days) in PRIORITY.items():
        items = pri.get(p, [])
        areas = Counter(f.get("engine") for f in items)
        road.append(f'<tr><td><b>{p}</b> · {lab}</td><td>within {days} days</td><td class="num"><b>{len(items)}</b></td>'
                    f'<td>{", ".join(f"{_e(dict((k, n) for k, n, _ in ENGINES).get(a, a))} ({c})" for a, c in areas.most_common()) or "—"}</td></tr>')
    upgrades = defaultdict(set)
    for f in fs:
        if f.get("engine") == "sca" and f.get("package") and f.get("fixed_version"):
            upgrades[(f["package"], f.get("version"))].add(str(f["fixed_version"]))
    up_rows = "".join(f'<tr><td class="mono">{_e(p)}</td><td class="mono">{_e(v)}</td><td class="mono">{_e(vmax(fx))}</td>'
                      f'<td class="num">{sum(1 for f in fs if f.get("package") == p and f.get("version") == v)}</td></tr>'
                      for (p, v), fx in sorted(upgrades.items())[:40])

    # ------------------------------------------------------------ detailed findings
    {k: n for k, n, _ in ENGINES}
    det = []
    sec_no = 0
    for k, name, what in ENGINES:
        items = [f for f in fs if f.get("engine") == k]
        if k not in engines_run and not items:
            continue
        sec_no += 1
        cards = []
        for f in items:
            meta = []
            vid = vuln_id(f) if k == "sca" else ""
            if vid:
                meta.append(f'<span><i>{"CVE" if vid.startswith("CVE-") else "Advisory"}</i> {_vlink(vid)}</span>')
                other = [a for a in (f.get("aliases") or []) if a != vid and str(a).startswith(("CVE-", "GHSA-"))][:3]
                if other:
                    meta.append("<span><i>Also</i> " + ", ".join(_vlink(a) for a in other) + "</span>")
            if f.get("cwe"):
                meta.append(f"<span><i>CWE</i> {_cwelink(f['cwe'])}</span>")
            if f.get("cvss") not in (None, ""):
                meta.append(f"<span><i>CVSS</i> {_e(f['cvss'])}</span>")
            if f.get("epss") not in (None, ""):
                meta.append(f"<span><i>EPSS</i> {float(f['epss']) * 100:.1f}%</span>")
            if f.get("kev"):
                meta.append("<span><i>KEV</i> known exploited</span>")
            if f.get("reachable") and k == "sca":
                meta.append("<span><i>Reachability</i> reachable from code</span>")
            if f.get("dependency_type") and k in ("sca", "license"):
                meta.append(f'<span><i>Dependency</i> {_e(f["dependency_type"])}{" via " + _e(f["introduced_by"]) if f.get("introduced_by") else ""}</span>')
            fwt = "".join(f'<span class="fw">{_e(t)}</span>' for t in FW.short(f))
            ev = "" if external or not f.get("evidence") else f'<div class="ev"><b>Evidence</b><code>{_e(str(f["evidence"])[:500])}</code></div>'
            fix = f.get("remediation") or (f'Upgrade to {f["fixed_version"]} or later.' if f.get("fixed_version") else "")
            fix = fix.replace("RAT Flea DevSec AutoFix can open a PR with the upgrade and lockfile refresh.", "").strip()
            endpoints = f.get("affected_endpoints") or []
            if k == "dast" and f.get("instances"):
                meta.append(f'<span><i>Instances</i> {_e(f["instances"])}</span>')
            affected = (f'<div class="ev"><b>Affected endpoints</b><code>{_e(", ".join(endpoints))}</code></div>'
                        if endpoints and not external else "")
            g = MIT.guidance(f)
            fix = fix or g["summary"]
            steps = "".join(f"<li>{_e(x)}</li>" for x in g["steps"])
            locs = (f.get("locations") or [])[1:6]
            locs_html = ("" if external or not locs else '<div class="ev"><b>Also found at</b><code>'
                         + _e("; ".join(f"{x.get('file')}:{x.get('line')}" + (f" (commit {x['commit']})" if x.get("commit") else "")
                                         for x in locs)) + (f" … {len(f['locations']) - 6} more" if len(f.get("locations") or []) > 6 else "")
                         + "</code></div>")
            mit = (f'<div class=fix><b>Mitigation steps</b><ol class="steps">{steps}</ol>'
                   f'<p><b>Verify</b> {_e(g["verify"])} · <a class=ext href="{_e(g["reference"])}" target=_blank rel=noopener>guidance</a></p></div>')
            cards.append(
                f'<div class="card" id="{_e(f.get("id"))}"><div class="card-h">{_sevchip(f.get("severity"))}'
                f'<b>{_e(f.get("title"))}</b><span class="rid mono">{_e(f.get("id"))}</span></div>'
                f'<div class="kvs"><span><i>Priority</i> {_e(f.get("priority"))} · fix within {_e(f.get("sla_days") or PRIORITY.get(f.get("priority"), ("", 90))[1])} days</span>'
                f'<span><i>Risk score</i> {_e(f.get("mrs"))}</span><span><i>Rule</i> {_e(f.get("rule_id"))}</span>'
                f'<span><i>Location</i> <span class="mono">{_e(_loc(f, external))}</span>'
                f'{"" if external or not str(f.get("code_url", "")).startswith("https://") else " " + chr(183) + " <a class=ext href=" + chr(34) + _e(f["code_url"]) + chr(34) + " target=_blank rel=noopener>open in source</a>"}</span>{"".join(meta)}</div>'
                f'{ev}{affected}{locs_html}{f"<div class=fix><b>Remediation</b> {_e(fix)}</div>" if fix else ""}{mit}'
                f'{f"<div class=fws>{fwt}</div>" if fwt else ""}</div>')
        body = "".join(cards) if items else (empty_findings if k in partial else '<p class="clear">✓ No open findings in this area.</p>')
        det.append(f'<h3 id="d-{k}">8.{sec_no} {_e(name)} <span class="cnt">{len(items)}</span></h3><p class="muted">{_e(what)}</p>{body}')

    # ------------------------------------------------------------ SBOM
    def lic_id(c):
        ls = c.get("licenses") or [{}]
        l0 = ls[0] if ls else {}
        return (l0.get("license") or {}).get("id") or (l0.get("license") or {}).get("name") or l0.get("expression") or "Unknown"
    lic = Counter(lic_id(c) for c in comps)
    lic_top = lic.most_common(8)
    if len(lic) > 8:
        lic_top.append(("Other", sum(v for k, v in lic.items() if k not in dict(lic_top))))
    dep = Counter(next((p.get("value") for p in c.get("properties") or [] if p.get("name") == "myelin:dependency"), "direct") for c in comps)
    eco = Counter((c.get("purl") or "pkg:other/").split(":", 1)[-1].split("/", 1)[0] for c in comps)
    vuln_pk = defaultdict(list)
    for f in fs:
        if f.get("engine") == "sca" and vuln_id(f):
            vuln_pk[(f.get("package"), f.get("version"))].append(vuln_id(f))
    vulns = sorted([f for f in fs if f.get("engine") == "sca"], key=lambda f: (-float(f.get("cvss") or 0), str(f.get("package"))))
    cve_rows = "".join(
        f'<tr><td class="nowrap">{_vlink(vuln_id(f)) or "—"}</td><td>{_sevchip(f.get("severity"))}</td><td class="mono">{_e(f.get("package"))}</td>'
        f'<td class="mono">{_e(f.get("version"))}</td><td class="mono">{_e(f.get("fixed_version") or "no fix yet")}</td>'
        f'<td class="num">{_e(f.get("cvss") if f.get("cvss") is not None else "—")}</td>'
        f'<td class="num">{_pct(f.get("epss"))}</td>'
        f'<td>{"<b class=dn>Yes</b>" if f.get("kev") else "No"}</td><td>{"Yes" if f.get("reachable") else "—"}</td></tr>' for f in vulns)
    has_cve = not dast and "sca" in engines_run
    has_sbom = not dast and bool(comps)
    no_cve, no_sbom = "9", ("10" if has_cve else "9")
    no_method = "9" if dast else str(9 + has_cve + has_sbom)
    cve_section = "" if not has_cve else (
        f'<section id="cve"><h2><span class="no">{no_cve}</span>Vulnerability register (CVE)</h2>'
        '<p class="lede">Every known vulnerability found in third-party components. Each identifier links to the public record '
        '(NVD for CVEs, GitHub Advisory Database or OSV for other advisories).</p>'
        + (f'<table><thead><tr><th>CVE / advisory</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed in</th>'
           f'<th class="num">CVSS</th><th class="num">EPSS</th><th>KEV</th><th>Reachable</th></tr></thead><tbody>{cve_rows}</tbody></table>'
           if vulns else '<p class="clear">✓ No known vulnerabilities were found in the inventoried components.</p>') + "</section>")
    sbom_rows = "".join(
        f'<tr><td>{_e(c.get("name"))}</td><td class="mono">{_e(c.get("version"))}</td><td>{_e(lic_id(c))}</td>'
        f'<td>{_e(next((p.get("value") for p in c.get("properties") or [] if p.get("name") == "myelin:dependency"), "direct"))}</td>'
        f'<td>{", ".join(_vlink(i) for i in vuln_pk[(c.get("name"), c.get("version"))][:4]) if (c.get("name"), c.get("version")) in vuln_pk else "—"}</td></tr>'
        for c in sorted(comps, key=lambda c: ((c.get("name"), c.get("version")) not in vuln_pk, str(c.get("name")).lower()))[:600])

    intel = result.get("intelligence") or {}
    srcs = ", ".join(intel.get("sources") or ["bundled advisory pack"])
    toc = [("1", "Document control", "doc"), ("2", "Executive summary", "exec"), ("3", "Assessment scope", "scope"),
           ("4", "Top risks", "top"), ("5", "Risk by area", "areas"), ("6", "Framework & compliance alignment", "fw"),
           ("7", "Remediation roadmap", "road"), ("8", "Detailed findings", "det"), ("9", "Vulnerability register (CVE)", "cve"),
           ("10", "Software bill of materials", "sbom"), ("11", "Methodology", "method"), ("A", "Appendix — definitions", "app"), ("B", "Attestation & disclaimer", "att")]
    names = {k: (n, w) for k, n, w in ENGINES}

    def _tools(c):
        return ", ".join(_e(t["name"]) + (f' <span class="muted">{_e(t["version"])}</span>' if t.get("version") else "")
                         + (' <b class="dn">failed</b>' if t.get("error") else "") for t in c.get("tools") or [])
    eng_cov = ""
    for k in [k for k, *_ in ENGINES if k in engines_run]:
        n, w = names[k]
        c = cov.get(k) or {}
        detail = " · ".join(x for x in (c.get("examined"), c.get("depth")) if x) or w
        eng_cov += (f'<tr><td><a href="#d-{k}"><b>{_e(n)}</b></a><div class="muted">{_e(detail)}</div>'
                    + ('<div class="muted">Partial coverage</div>' if k in partial else "")
                    + "".join(f'<div class="muted">{_e(note)}</div>' for note in c.get("limitations", []))
                    + f'</td><td>{_tools(c) if c else "<span class=muted>—</span>"}</td><td class="num">{by_eng[k]}</td></tr>')
    if not dast and comps:
        eng_cov += (f'<tr><td><a href="#sbom"><b>Software bill of materials (SBOM)</b></a><div class="muted">Inventory of every third-party component '
                    f'(direct and transitive) with version, licence and package URL; exported as CycloneDX 1.5.</div></td>'
                    f'<td>CycloneDX 1.5</td><td class="num">{len(comps)} component{"" if len(comps) == 1 else "s"}</td></tr>')
    if comps:
        sbom_body = (f'<div class="grid2"><div class="panel"><h4>Licences</h4>{_bars(lic_top, total=len(comps))}</div>'
                     f'<div class="panel"><h4>Ecosystems</h4>{_bars(eco.most_common(8), total=len(comps))}'
                     f'<h4 style="margin-top:16px">Dependency type</h4>{_bars(sorted(dep.items(), key=lambda x: -x[1]), total=len(comps))}</div></div>'
                     f'<h3>Components{" (first 600)" if len(comps) > 600 else ""}</h3>'
                     f'<table><thead><tr><th>Component</th><th>Version</th><th>Licence</th><th>Type</th><th>Vulnerabilities</th></tr></thead><tbody>{sbom_rows}</tbody></table>')
    else:
        sbom_body = '<p class="muted">No dependency manifests were found in the repository.</p>'
    # End-of-life software, components found outside package manifests, and the repository's own licensing.
    eol_fs = [f for f in fs if f.get("category") == "eol"]
    if eol_fs:
        rows = "".join(f'<tr><td>{_e(f.get("severity"))}</td><td class="mono">{_e(f.get("package"))} {_e(f.get("version"))}</td>'
                       f'<td style="white-space:nowrap">{_e(f.get("eol_date") or "—")}</td><td class="mono" style="word-break:break-all">{_e(f.get("file"))}</td>'
                       f'<td>{_e(f.get("fixed_version") or "—")}</td></tr>' for f in eol_fs[:200])
        sbom_body += (f'<h3>End-of-life software ({len(eol_fs)})</h3><p class="muted">Runtimes, base images, frameworks and '
                      f'libraries whose release line no longer receives security fixes, or will stop within 180 days. Product '
                      f'lifecycle data from endoflife.date.</p><table style="table-layout:fixed"><colgroup><col style="width:11%">'
                      f'<col style="width:19%"><col style="width:15%"><col><col style="width:16%"></colgroup><thead><tr><th>Severity</th><th>Product and release</th>'
                      f'<th>End of support</th><th>Found in</th><th>Move to</th></tr></thead><tbody>{rows}</tbody></table>')
    def _prop(c, k):
        return next((p.get("value") for p in c.get("properties") or [] if p.get("name") == k), None)
    emb = [dict(c, detection=_prop(c, "myelin:detection"), file=_prop(c, "myelin:manifest"))
           for c in comps if _prop(c, "myelin:detection")]
    if emb:
        vuln_by = Counter(f.get("package") for f in fs if f.get("engine") == "sca" and f.get("detection"))
        rows = "".join(f'<tr><td class="mono">{_e(c.get("name"))}</td><td>{_e(c.get("version"))}</td>'
                       f'<td>{_e(c.get("detection"))}</td><td class="mono" style="word-break:break-all">{_e(c.get("file"))}</td>'
                       f'<td class="num">{vuln_by.get(c.get("name"), 0)}</td></tr>' for c in emb[:200])
        sbom_body += (f'<h3>Components found outside package manifests ({len(emb)})</h3><p class="muted">Libraries copied into '
                      f'the repository (minified scripts, bundled archives, vendored folders). They are identified from '
                      f'their own banners and metadata and checked for vulnerabilities like declared dependencies.</p>'
                      f'<table style="table-layout:fixed"><colgroup><col style="width:22%"><col style="width:11%">'
                      f'<col style="width:24%"><col><col style="width:13%"></colgroup><thead><tr><th>Component</th><th>Version</th><th>Identified by</th><th>File</th>'
                      f'<th>Vulns</th></tr></thead><tbody>{rows}</tbody></table>')
    lic = result.get("licensing") or {}
    if lic.get("licence_files") or lic.get("copyrights"):
        files = "".join(f'<tr><td class="mono">{_e(x.get("file"))}</td><td>{_e(x.get("licence") or "not identified")}</td></tr>'
                        for x in (lic.get("licence_files") or [])[:60])
        cps = "".join(f'<li>{_e(c)}</li>' for c in (lic.get("copyrights") or [])[:80])
        sbom_body += (f'<h3>Repository licensing</h3><p>Project licence: <b>{_e(lic.get("project_licence") or "not declared")}</b>. '
                      f'{len(lic.get("spdx_tags") or {})} distinct SPDX licence identifiers are declared in source file headers.</p>'
                      + (f'<table><thead><tr><th>Licence file</th><th>Identified licence</th></tr></thead><tbody>{files}</tbody></table>' if files else "")
                      + (f'<details><summary>Copyright notices for the attribution file ({len(lic.get("copyrights") or [])})</summary>'
                         f'<ul class="mono">{cps}</ul></details>' if cps else ""))
    sbom_section = "" if not has_sbom else (
        f'<section id="sbom" class="pb"><h2><span class="no">{no_sbom}</span>Software bill of materials</h2>'
        f'<p class="lede">{len(comps)} third-party components were inventoried, including transitive dependencies. '
        f'The machine-readable CycloneDX 1.5 SBOM is available from the RAT Flea DevSec console.</p>{sbom_body}</section>')
    if dast:
        stats = result.get("stats") or {}
        idents = result.get("identities") or []
        tools_run = result.get("tools") or []
        scope_rows = (f'<tr><th>Target</th><td class="mono">{_e(src)}</td></tr>'
                      + (f'<tr><th>API specification</th><td>{_e(result["spec_operations"])} operations</td></tr>' if result.get("spec_operations") else "")
                      + (f'<tr><th>Test identities</th><td>{_e(", ".join(map(str, idents)))}</td></tr>' if idents else "")
                      + f'<tr><th>Assessment date</th><td>{scan_date} (automated, {_e(result.get("duration_s"))} s, '
                        f'{_e(result.get("requests", 0))} requests)</td></tr>')
        method_rows = [("Approach", "Automated dynamic testing of the running service.")]
        if "myelin-dast" in tools_run:
            method_rows.append(("Baseline checks", "Transport and response checks."))
        if stats.get("baseline_auth_checks"):
            method_rows.append(("Authentication checks", str(stats["baseline_auth_checks"])))
        if "myelin-authz" in tools_run:
            method_rows.append(("Authorisation", "Multi-user checks with the configured test identities."))
        if "myelin-crawler" in tools_run:
            method_rows.append(("Crawler", f'{stats.get("crawled_endpoints", 0)} endpoints discovered.'))
        if "myelin-active" in tools_run:
            method_rows.append(("Active checks", "Built-in active checks were enabled for this run."))
        if zap:
            detail = f'OWASP ZAP {zap.get("version", "")}: {zap.get("urls", 0)} URLs discovered, {zap.get("mode", "unknown")} mode.'
            if zap.get("complete") is False:
                detail += " ZAP did not complete. Results cover only the work it returned."
            method_rows.append(("OWASP ZAP", detail))
        elif "zap" in tools_run:
            method_rows.append(("OWASP ZAP", "ZAP results were collected. Completion details are unavailable."))
        method_rows += [
            ("Prioritisation", "RAT Flea DevSec Risk Score (0–100) combines severity, exploitability, exposure and asset criticality; it sets the priority (P0–P3)."),
            ("Limitations", "Automated testing does not replace manual penetration testing of business logic, chained attacks or write operations. "
                            "Results reflect the state of the service at the time of testing."),
        ]
    else:
        scope_rows = (f'<tr><th>Repository</th><td class="mono">{_e(src)}</td></tr>'
                      + (f'<tr><th>Snapshot</th><td>{_e(result.get("branch") or "")}{", " if result.get("branch") and commit else ""}'
                         f'{"commit " + _e(commit) if commit else ""}</td></tr>' if result.get("branch") or commit else "")
                      + f'<tr><th>Assessment date</th><td>{scan_date} (automated, {_e(result.get("duration_s"))} s)</td></tr>'
                      + (f'<tr><th>Components inventoried</th><td>{len(comps)} ({dep.get("direct", 0)} direct, {dep.get("transitive", 0)} transitive)</td></tr>'
                         if comps else ""))
        area_names = [names[k][0] for k in [k for k, *_ in ENGINES if k in engines_run]]
        tool_list = sorted({f'{t["name"]} {t.get("version", "")}'.strip() for k in engines_run
                            for t in cov.get(k, {}).get("tools", []) if not t.get("error")})
        depth = []
        for k in engines_run:
            c = cov.get(k) or {}
            if c.get("depth"):
                depth.append(f"{names[k][0]}: {c['depth']}.")
        method_rows = [
            ("Approach", "Automated static assessment of the repository snapshot. Areas examined: " + (", ".join(area_names) or "none")
                         + ". No code was executed and no live system was tested."),
            *([("Analysis engines", ", ".join(tool_list))] if tool_list else []),
        ]
        if depth:
            method_rows.append(("Depth of analysis", " ".join(depth)))
        if "sca" in engines_run:
            method_rows.append(("Vulnerability intelligence", f'{srcs}{" — offline mode" if intel.get("offline") else ""}. CVSS v3 base scores; '
                                                             f'EPSS exploit probability; CISA KEV catalogue.'
                                                             + (f' Unavailable during this scan: {", ".join(intel["errors"])}.' if intel.get("errors") else "")))
        if intel.get("notes"):
            method_rows.append(("Unpacking and inventory notes", "; ".join(intel["notes"][:12]) + "."))
        if intel.get("resolution"):
            method_rows.append(("Dependency resolution", "Lock files and manifests, plus: " + ", ".join(intel["resolution"])
                                + ". Transitive dependencies are resolved to the versions a build would install."))
        if failed_tools:
            method_rows.append(("Tool errors", "These tools did not complete: " + ", ".join(failed_tools)
                                + ". Any findings they returned are included."))
        method_rows += [
            ("Prioritisation", "RAT Flea DevSec Risk Score (0–100) combines severity, exploit likelihood, known exploitation, reachability from "
                               "first-party code, exposure and asset criticality. The score sets the priority (P0–P3) and the remediation target."),
            ("Noise control", "Duplicate results from different engines are merged; findings in tests, fixtures and vendored code are "
                              "de-prioritised or excluded; suppressions require a recorded reason and are audited."),
            ("Limitations", "Static analysis identifies likely weaknesses and may miss issues in business logic, runtime configuration or code "
                            "not present in the repository. Results reflect the snapshot above only."),
        ]
    terms = [("CWE", "Common Weakness Enumeration identifier of the weakness type.")]
    if has_cve or dast:
        terms = [("CVE", "Common Vulnerabilities and Exposures identifier of a publicly disclosed vulnerability."), *terms,
                 ("CVSS", "Common Vulnerability Scoring System base score (0–10).")]
    if has_cve:
        terms += [("EPSS", "Exploit Prediction Scoring System: probability of exploitation in the next 30 days."),
                  ("KEV", "Listed in the CISA Known Exploited Vulnerabilities catalogue.")]
    if has_sbom:
        terms.append(("SBOM", "Software bill of materials — inventory of third-party components (CycloneDX)."))
    if any(f.get("dataflow") for f in fs):
        terms.append(("Data flow", "The finding was confirmed by following untrusted input from where it enters the application to the "
                                   "dangerous operation (taint analysis); the evidence shows the path."))
    terms_html = "".join(f"<tr><th>{_e(a)}</th><td>{_e(b)}</td></tr>" for a, b in terms)
    method_section = (f'<section id="method"><h2><span class="no">{no_method}</span>Methodology</h2><table class="kv">'
                      + "".join(f"<tr><th>{_e(a)}</th><td>{_e(b)}</td></tr>" for a, b in method_rows) + "</table></section>")
    toc = [t for t in toc if (t[2] != "cve" or has_cve) and (t[2] != "sbom" or has_sbom)]
    toc = [((no_cve if t[2] == "cve" else no_sbom if t[2] == "sbom" else no_method), t[1], t[2])
           if t[2] in ("cve", "sbom", "method") else t for t in toc]
    subtitle = "Live application security assessment" if dast else "Repository security assessment"
    lede_tail = (f' and {result["requests"]} requests recorded by the built-in scanner' if dast and result.get("requests")
                 else f' and {len(comps)} third-party components inventoried' if comps else "")
    target_label, snap_label = ("Target", "Identities") if dast else ("Repository", "Snapshot")
    snap_value = ", ".join(map(str, result.get("identities") or [])) if dast else (
        f'{result.get("branch") or ""}{" @ " if commit and result.get("branch") else ""}{commit[:12]}')
    n_areas = len([k for k, *_ in ENGINES if k in engines_run])
    ch = sev["critical"] + sev["high"]
    fw_gap_total = sum(m["gaps"] for m in matrix if m["id"] != "cwe25")
    fw_ctl_total = sum(len(m["controls"]) for m in matrix if m["id"] != "cwe25")
    kpi_html = _kpis([
        ("Open findings", len(fs), f"across {n_areas} area{'' if n_areas == 1 else 's'}", "#0b2a4a"),
        ("Critical & high", ch, f"{len(pri.get('P0', [])) + len(pri.get('P1', []))} due within 7 days", "#d03b3b" if ch else "#0ca30c"),
        *([("Requests recorded", result.get("requests", 0), "built-in scanner", "#2a78d6")] if dast and engines_run else []),
        *([("Distinct CVEs", len(cves), f"{kev} known exploited" if kev else f"{len(comps)} components", "#2a78d6")]
          if "sca" in engines_run else []),
        ("Control gaps", fw_gap_total, f"of {fw_ctl_total} mapped controls", "#ec835a" if fw_gap_total else "#0ca30c"),
    ])
    "".join(f'<div class="tile"><b>{sev[s]}</b><span>{_sevchip(s)}</span></div>' for s in ["critical", "high", "medium", "low"])
    aud = "External edition — prepared for distribution to third parties" if external else "Internal edition — contains technical evidence"
    footer_class = _e(classification)

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)} — {_e(repo)}</title>
<style>
:root{{--ink:#0b0b0b;--ink2:#52514e;--mute:#898781;--line:#e1e0d9;--base:#c3c2b7;--surf:#fcfcfb;--brand:#0b2a4a;--accent:#2a78d6}}
*{{box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:var(--ink);margin:0;background:#ecebe6;font-size:13px;line-height:1.5}}
.sheet{{max-width:860px;margin:18px auto;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.12);padding:46px 56px}}
.cover{{max-width:860px;margin:18px auto 0;background:var(--brand);color:#fff;min-height:1080px;padding:56px;position:relative;display:flex;flex-direction:column}}
.cover .brand{{display:flex;align-items:center;gap:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;font-size:13px}}
.cover .by{{font-weight:500;letter-spacing:.08em;font-size:11px;color:#9ec5f4;margin-top:2px}}
.cover .cust{{display:block;font-size:20px;font-weight:600;color:#cde2fb;margin-bottom:4px}}
a.ext{{color:#1c5cab;text-decoration:underline;text-underline-offset:2px}}
.cover .product-mark{{flex:none}}.endmark .product-mark{{vertical-align:middle;margin-right:6px}}
.cover .wm{{position:absolute;right:48px;bottom:120px;opacity:.07}}
.cover .kind{{margin-top:170px;color:#9ec5f4;letter-spacing:.2em;font-size:12px;font-weight:700;text-transform:uppercase}}
.cover h1{{font-size:38px;line-height:1.15;margin:10px 0 12px;font-weight:700}}
.cover .sub{{font-size:18px;color:#cde2fb;margin:0}}
.cover .meta{{margin-top:auto;display:grid;grid-template-columns:1fr 1fr;gap:16px 40px;border-top:1px solid rgba(255,255,255,.25);padding-top:22px}}
.cover .meta i{{display:block;font-style:normal;color:#86b6ef;font-size:11px;text-transform:uppercase;letter-spacing:.08em}}
.cover .meta b{{font-weight:600;font-size:14px;word-break:break-all}}
.cover .rating{{position:absolute;top:56px;right:56px;text-align:right}}
.cover .rating i{{display:block;font-style:normal;font-size:11px;color:#86b6ef;text-transform:uppercase;letter-spacing:.08em}}
.cover .rating span{{display:inline-block;margin-top:6px;padding:6px 16px;border-radius:6px;font-weight:700;font-size:16px}}
.cover .cls{{position:absolute;bottom:20px;left:56px;right:56px;font-size:11px;color:#86b6ef;display:flex;justify-content:space-between}}
h2{{font-size:21px;margin:0 0 4px;color:var(--brand);padding-top:6px}}
h2 .no{{color:var(--accent);margin-right:10px}}
.lede{{color:var(--ink2);margin:0 0 16px}}
h3{{font-size:15px;margin:22px 0 8px;color:var(--brand)}}
section{{margin-bottom:34px}} section.pb{{break-before:page}}
table{{border-collapse:collapse;width:100%;font-size:12.5px}}
th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
thead th,th{{color:var(--ink2);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--base)}}
.kv th{{width:190px;text-transform:none;font-size:12.5px;letter-spacing:0;border-bottom:1px solid var(--line)}}
.num{{text-align:right;font-variant-numeric:tabular-nums}} .nowrap{{white-space:nowrap}}
.mono,code{{font-family:ui-monospace,Consolas,"Courier New",monospace;font-size:11.5px}}
.muted{{color:var(--ink2);font-size:11.5px}}
.sev{{display:inline-block;border-radius:4px;padding:1px 7px;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.03em}}
.cnt{{font-size:12px;background:#f0efec;border-radius:10px;padding:1px 9px;color:var(--ink2);font-weight:600}}
.tiles{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}}
.tile{{border:1px solid var(--line);border-radius:8px;padding:12px 14px}}
.tile b{{display:block;font-size:28px;font-weight:700;line-height:1.1}} .tile span{{color:var(--ink2);font-size:12px}}
.hero{{display:grid;grid-template-columns:220px 1fr;gap:18px;align-items:stretch;margin:6px 0 16px}}
.riskbox{{border-radius:10px;padding:16px 18px}} .riskbox i{{font-style:normal;font-size:11px;text-transform:uppercase;letter-spacing:.08em;opacity:.85}}
.riskbox b{{display:block;font-size:30px;margin:4px 0 2px}}
.msgs{{margin:0;padding-left:18px}} .msgs li{{margin:4px 0}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:26px}}
.panel h4{{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2)}}
.bars{{display:grid;gap:7px}}
.bar-row{{display:grid;grid-template-columns:150px 1fr 70px;gap:8px;align-items:center;font-size:12px}}
.bar-l{{color:var(--ink2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.bar-t{{height:12px;border-left:1px solid var(--base)}}
.bar{{height:12px;border-radius:0 4px 4px 0}}
.bar-v{{font-variant-numeric:tabular-nums;font-weight:600}} .bar-v .muted{{font-weight:400}}
.stack{{display:flex;gap:2px;height:12px;border-radius:4px;overflow:hidden;background:#fff;min-width:120px}}
.stack.empty{{background:#f0efec}} .seg{{min-width:3px}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0 18px}}
.kpi{{border:1px solid var(--line);border-top:3px solid var(--a);border-radius:8px;padding:11px 13px;background:#fff}}
.kpi-l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink2);font-weight:600}}
.kpi-v{{font-size:30px;font-weight:700;line-height:1.15;margin-top:4px}} .kpi-s{{font-size:11.5px;color:var(--ink2)}}
.strip{{display:flex;gap:2px;height:18px;border-radius:5px;overflow:hidden}} .strip.empty{{background:#f0efec}}
.sleg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:6px;margin-top:9px}}
.sl{{display:flex;align-items:baseline;gap:6px;font-size:12px}} .sl b{{font-size:17px}} .sl i{{font-style:normal;color:var(--mute);font-size:11px}}
.sw{{width:10px;height:10px;border-radius:2px;display:inline-block;align-self:center}}
.areas{{display:grid;gap:8px}} .ar{{display:grid;grid-template-columns:168px 1fr 30px;gap:8px;align-items:center;font-size:12px}}
.ar-l{{color:var(--ink2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}} .ar-t{{border-left:1px solid var(--base);height:14px}}
.ar-b{{display:flex;gap:2px;height:14px;border-radius:0 4px 4px 0;overflow:hidden}} .ar-v{{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}}
.mini-leg{{display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:var(--ink2);margin-top:8px}}
.mini-leg i{{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:4px;vertical-align:-1px}}
.hist{{width:100%;height:auto;display:block}} .hist .hv{{font-size:10px;font-weight:700;fill:#0b0b0b}} .hist .hx{{font-size:9px;fill:#898781}}
.heat{{display:grid;gap:7px}} .hr{{display:grid;grid-template-columns:190px 1fr 120px;gap:10px;align-items:center}}
.hr-l b{{display:block;font-size:12px}} .hr-l span{{font-size:10.5px;color:var(--mute)}}
.hr-c{{display:flex;flex-wrap:wrap;gap:3px}} .hc{{width:20px;height:20px;border-radius:4px;display:grid;place-items:center;color:#fff;font-size:10px;font-weight:800}}
.hr-v{{font-size:11.5px;color:var(--ink2);text-align:right}} .hr-v b{{color:var(--ink)}}
.timeline{{display:grid;grid-template-columns:repeat(4,1fr);gap:0;margin:14px 0 18px;position:relative}}
.tl{{padding:12px 14px;border-top:4px solid var(--c);background:#faf9f6;margin-right:6px;border-radius:0 0 8px 8px}}
.tl-d{{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink2);font-weight:600}}
.tl-n{{font-size:28px;font-weight:700;line-height:1.2}} .tl-p{{font-size:12px;color:var(--ink2)}} .tl-p b{{color:var(--ink)}}
.mrs{{display:flex;align-items:center;gap:6px;justify-content:flex-end}} .mrs i{{display:block;height:6px;border-radius:0 3px 3px 0;background:var(--c)}}
.dash{{display:grid;grid-template-columns:1.35fr .65fr;gap:22px;margin:4px 0 6px}}
.box{{border:1px solid var(--line);border-radius:10px;padding:14px 16px;background:#fff}}
.box h4{{margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink2)}}
.endmark{{margin-top:34px;padding-top:14px;border-top:2px solid var(--brand);display:grid;gap:3px;font-size:12.5px}}
.review{{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 16px;margin-top:18px;background:#f8fafd}}
.review h4{{margin:0 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--brand)}}
.legend{{display:flex;gap:14px;flex-wrap:wrap;font-size:11.5px;color:var(--ink2);margin:8px 0}}
.legend span::before{{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--c);margin-right:5px;vertical-align:-1px}}
.st{{display:inline-grid;place-items:center;width:16px;height:16px;border-radius:50%;background:var(--c);color:#fff;font-size:10px;font-weight:800;line-height:1}}
.card{{border:1px solid var(--line);border-radius:8px;padding:11px 13px;margin:9px 0;break-inside:avoid}}
.card-h{{display:flex;gap:9px;align-items:baseline}} .card-h b{{flex:1}} .rid{{color:var(--mute)}}
.kvs{{display:flex;flex-wrap:wrap;gap:4px 16px;margin:7px 0 4px;font-size:12px}}
.kvs i{{font-style:normal;color:var(--mute);font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;margin-right:4px}}
.ev{{margin-top:6px;font-size:12px}} .ev code{{display:block;background:#f6f6f3;border:1px solid var(--line);border-radius:5px;padding:6px 8px;margin-top:3px;white-space:pre-wrap;word-break:break-all}}
.fix{{margin-top:6px;font-size:12px}} .fix b{{color:#006300;margin-right:4px}}
.fix ol.steps{{margin:4px 0 2px 18px;padding:0}} .fix ol.steps li{{margin:2px 0}} .fix p{{margin:3px 0 0}}
.fws{{margin-top:7px;display:flex;flex-wrap:wrap;gap:4px}}
.fw{{font-size:10.5px;border:1px solid #cde2fb;background:#f3f8fe;color:#184f95;border-radius:4px;padding:0 6px}}
.clear{{color:#006300;font-weight:600}} .dn{{color:#b42318}}
.toc a{{display:flex;gap:10px;color:var(--ink);text-decoration:none;padding:6px 0;border-bottom:1px dotted var(--base)}}
.toc a b{{width:28px;color:var(--accent)}}
a{{color:#1c5cab}}
.sig{{display:grid;grid-template-columns:1fr 1fr;gap:30px;margin-top:26px}} .sig div{{border-top:1px solid var(--ink);padding-top:6px;font-size:12px;color:var(--ink2)}}
.note{{background:#f6f6f3;border-left:3px solid var(--accent);padding:10px 14px;font-size:12px;color:var(--ink2)}}
.bar-print{{max-width:860px;margin:14px auto 0;display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--ink2)}}
.bar-print button{{font:inherit;border:1px solid var(--base);background:#fff;border-radius:7px;padding:7px 14px;cursor:pointer;color:var(--ink)}}
@page{{size:A4;margin:16mm 14mm 18mm;
  @bottom-center{{content:"{SITE}";font-size:8pt;color:#898781;font-family:system-ui,sans-serif}}
  @bottom-left{{content:"RAT Flea DevSec · {_css(classification)}";font-size:8pt;color:#898781;font-family:system-ui,sans-serif}}
  @bottom-right{{content:"Page " counter(page) " of " counter(pages);font-size:8pt;color:#898781;font-family:system-ui,sans-serif}}}}
@page :first{{margin:0;@bottom-left{{content:none}}@bottom-center{{content:none}}@bottom-right{{content:none}}}}
@media print{{
  body{{background:#fff;font-size:10pt}} .bar-print{{display:none}}
  .cover{{margin:0;max-width:none;min-height:297mm;height:297mm;break-after:page;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .sheet{{margin:0;max-width:none;box-shadow:none;padding:0}}
  *{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  h2,h3{{break-after:avoid}} tr,.tile,.bar-row{{break-inside:avoid}}
}}
@media(max-width:760px){{.sheet,.cover{{padding:24px}}.tiles{{grid-template-columns:repeat(2,1fr)}}.grid2,.hero{{grid-template-columns:1fr}}.cover .rating{{position:static;text-align:left;margin-top:20px}}.cover .kind{{margin-top:60px}}}}
</style></head><body>
<div class="bar-print"><span>{_e(aud)}</span><button onclick="window.print()">Download PDF / print</button></div>

<div class="cover">
  <div class="brand">{logo_svg(56)}<div><div>{_e(PRODUCT)}</div><div class="by">{SITE}</div></div></div>
  <div class="rating"><i>Overall risk rating</i><span style="background:{rcol};color:{rink}">{risk}</span></div>
  <div class="kind">{_e(title)}</div>
  <h1>{f'<span class="cust">{_e(customer)}</span>' if customer else ""}{_e(repo)}</h1>
  <p class="sub">{_e(subtitle)}</p>
  <div class="meta">
    <div><i>Prepared for</i><b>{_e(prepared_for or customer or "—")}</b></div>
    <div><i>Prepared by</i><b>{_e(VENDOR)}</b></div>
    <div><i>Report date</i><b>{when}</b></div>
    <div><i>Report reference</i><b class="mono">{rid}</b></div>
    <div><i>{target_label}</i><b>{_e(src)}</b></div>
    {f'<div><i>{snap_label}</i><b>{_e(snap_value)}</b></div>' if snap_value else ""}
  </div>
  <div class="wm" aria-hidden="true">{logo_svg(300, cls="wm-mark")}</div>
  <div class="cls"><span>{footer_class} · {_e("External edition" if external else "Internal edition")}</span><span>{_e(PRODUCT)} · {SITE}</span></div>
</div>

<div class="sheet">
<section id="doc"><h2><span class="no">1</span>Document control</h2>
<table class="kv">
<tr><th>Document</th><td>{_e(title)} — {_e(customer + " · " if customer else "")}{_e(repo)}</td></tr>
<tr><th>Reference</th><td class="mono">{rid}</td></tr>
<tr><th>Version</th><td>1.0 — issued {when}</td></tr>
<tr><th>Classification</th><td>{footer_class}</td></tr>
<tr><th>Edition</th><td>{_e(aud)}</td></tr>
<tr><th>Prepared by</th><td>{_e(VENDOR)}</td></tr>
<tr><th>Prepared for</th><td>{_e(prepared_for or customer or "—")}</td></tr>
{f'<tr><th>Code owner</th><td>{_e(customer)}</td></tr>' if customer and prepared_for and prepared_for != customer else ""}
<tr><th>Assessment platform</th><td>{_e(PRODUCT)} — <a class="ext" href="{REPO_URL}" target="_blank" rel="noopener">{SITE}</a></td></tr>
<tr><th>Review</th><td>Released for review by the responsible DevOps and engineering team (see appendix B)</td></tr>
</table>
<h3>Contents</h3><div class="toc">{"".join(f'<a href="#{a}"><b>{n}</b>{_e(t)}</a>' for n, t, a in toc)}</div>
</section>

<section id="exec" class="pb"><h2><span class="no">2</span>Executive summary</h2>
<p class="lede">An automated assessment of <b>{_e(repo)}</b> was performed on {scan_date} across {n_areas} security area{"" if n_areas == 1 else "s"}{lede_tail}.</p>
<div class="hero">
  <div class="riskbox" style="background:{rcol};color:{rink}"><i>Overall risk rating</i><b>{risk}</b><div style="font-size:12px">{_e(rtext)}</div></div>
  <div><h4 style="margin:0 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2)">Key messages</h4><ul class="msgs">{"".join(f"<li>{m}</li>" for m in keymsgs)}</ul></div>
</div>
{kpi_html}
<div class="box" style="margin-bottom:16px"><h4>Severity mix of open findings</h4>{_sev_strip(sev, len(fs)) if fs else empty_findings}</div>
<div class="dash">
  <div class="box"><h4>Open findings by area and severity</h4>{_area_stack(fs, [(k, n) for k, n, _ in ENGINES if k in engines_run]) if fs else empty_findings}</div>
  <div class="box"><h4>Risk score distribution</h4>{_hist(fs) or empty_findings}</div>
</div>
<h3>Control coverage heat map</h3>
<p class="muted" style="margin:-4px 0 10px">Each square is one control of the framework; hover in the HTML edition for its name.</p>
{_heat(matrix)}
</section>

<section id="scope"><h2><span class="no">3</span>Assessment scope</h2>
<table class="kv">
{scope_rows}
<tr><th>Findings excluded</th><td>{excluded} (fixed, accepted risk, false positive or governed suppression)</td></tr>
</table>
<h3>Areas assessed</h3>
<p class="muted">Only areas that apply to this {"service" if dast else "repository"} and were examined are listed.</p>
<table><thead><tr><th>Area and coverage</th><th>Analysis tools</th><th class="num">Findings</th></tr></thead><tbody>{eng_cov}</tbody></table>
</section>

<section id="top"><h2><span class="no">4</span>Top risks</h2>
<p class="lede">The ten findings with the highest RAT Flea DevSec Risk Score — fix these first.</p>
{f'<table><thead><tr><th class="num">#</th><th>Finding</th><th>Severity</th><th class="num">Priority</th><th style="text-align:right">Risk score</th><th>Reference</th></tr></thead><tbody>{top_rows}</tbody></table>' if top else empty_findings}
</section>

<section id="areas"><h2><span class="no">5</span>Risk by area</h2>
<table><thead><tr><th>Area</th>{"".join(f'<th class="num">{_sevchip(s)}</th>' for s in ["critical", "high", "medium", "low"])}<th class="num">Total</th></tr></thead><tbody>
{"".join(f'<tr><td><a href="#d-{k}">{_e(n)}</a></td>' + "".join(f'<td class="num">{sum(1 for f in fs if f.get("engine") == k and f.get("severity") == s) or "·"}</td>' for s in ["critical", "high", "medium", "low"]) + f'<td class="num"><b>{by_eng[k]}</b></td></tr>' for k, n, _ in ENGINES if k in engines_run or by_eng[k])}
<tr><td><b>Total</b></td>{"".join(f'<td class="num"><b>{sev[s]}</b></td>' for s in ["critical", "high", "medium", "low"])}<td class="num"><b>{len(fs)}</b></td></tr>
</tbody></table>
</section>

<section id="fw" class="pb"><h2><span class="no">6</span>Framework &amp; compliance alignment</h2>
<p class="lede">Each finding is mapped to the controls it bears on. A control is shown as a <b>gap</b> when critical or high-severity findings are open against it,
an <b>observation</b> when only medium or low findings are open, and <b>no issues found</b> when an assessed area tests for it and found nothing.
The table lists controls mapped to recorded findings or checks from completed scan areas.</p>
<div class="note">Automated evidence supports — but does not by itself establish — compliance with a standard. Controls that depend on process, people or
physical security are outside the scope of this assessment.</div>
<h3>6.1 Summary</h3>
<table><thead><tr><th>Framework</th><th class="num">Gaps</th><th class="num">Observ.</th><th class="num">No issues</th><th>Controls tested</th></tr></thead>
<tbody>{"".join(fw_rows)}</tbody></table>
{"".join(fw_detail)}
</section>

<section id="road"><h2><span class="no">7</span>Remediation roadmap</h2>
<p class="lede">Remediation targets follow the priority assigned to each finding from its risk score.</p>
{_timeline(pri)}
<table><thead><tr><th>Priority</th><th>Target</th><th class="num">Findings</th><th>Areas</th></tr></thead><tbody>{"".join(road)}</tbody></table>
{f'<h3>Dependency upgrades</h3><p class="muted">Upgrading these packages closes the listed vulnerabilities.</p><table><thead><tr><th>Package</th><th>Current</th><th>Upgrade to</th><th class="num">Findings closed</th></tr></thead><tbody>{up_rows}</tbody></table>' if up_rows else ""}
</section>

<section id="det" class="pb"><h2><span class="no">8</span>Detailed findings</h2>
<p class="lede">Findings are grouped by area and ordered by severity and risk score. Framework references show which controls each finding bears on.{" Code evidence is withheld in this external edition." if external else ""}</p>
{"".join(det)}
</section>

{cve_section}
{sbom_section}

{method_section}

<section id="app"><h2><span class="no">A</span>Appendix — definitions</h2>
<h3>Severity</h3>
<table><tbody>
<tr><td>{_sevchip("critical")}</td><td>Directly exploitable; likely to lead to compromise of the system, its data or its credentials.</td></tr>
<tr><td>{_sevchip("high")}</td><td>Exploitable with modest preconditions; significant impact on confidentiality, integrity or availability.</td></tr>
<tr><td>{_sevchip("medium")}</td><td>Exploitation requires specific conditions or has limited impact; weakens defence in depth.</td></tr>
<tr><td>{_sevchip("low")}</td><td>Hardening opportunity or best-practice deviation with low direct impact.</td></tr>
</tbody></table>
<h3>Priority and remediation targets</h3>
<table><tbody>{"".join(f"<tr><td><b>{p}</b></td><td>{lab}</td><td>fix within {days} days</td></tr>" for p, (lab, days) in PRIORITY.items())}</tbody></table>
<h3>Terms</h3>
<table class="kv">
{terms_html}
</table>
</section>

<section id="att" class="pb"><h2><span class="no">B</span>Attestation &amp; disclaimer</h2>
<p>This report records the results of an automated security assessment of the {"application identified" if dast else "repository snapshot identified"} in section 3, performed on {scan_date}{" for " + _e(customer) if customer else ""} using {_e(PRODUCT)}.
The findings reflect {"the state of the service at the time of testing" if dast else "the state of the code at that commit"} only.</p>
<p>The assessment is a point-in-time evaluation and is not a guarantee that the software is free of vulnerabilities. Framework mappings indicate where automated evidence
bears on a control; they do not constitute a certification or an auditor's opinion.</p>
<p>{"This external edition omits source-code evidence and secret locations. The full technical edition is available to authorised recipients on request." if external else "This internal edition contains technical evidence and must be handled according to its classification."}</p>
<div class="review"><h4>Review and use of findings</h4>
<p style="margin:0">The findings in this report are produced by automated analysis and are released for review by the responsible DevOps and engineering
team as part of the standard delivery process. That team validates each finding in the context of its environment, prioritises remediation
according to the targets in section 7 and records accepted risks or false positives in RAT Flea DevSec, where every decision is audited.
Product information: <a class="ext" href="{REPO_URL}" target="_blank" rel="noopener">{SITE}</a>.</p></div>
<div class="endmark"><div>{logo_svg(26, fg="#0b2a4a", eye="#18a689")}<b>{_e(PRODUCT)}</b> · product designed and developed by Sudheer Kumar</div><div><a class="ext" href="{REPO_URL}" target="_blank" rel="noopener">{SITE}</a></div>
<div class="muted">{footer_class} · {rid}</div></div>
</section>
</div></body></html>"""
