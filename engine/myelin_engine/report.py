# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Self-contained HTML assessment report for a live-application test (no external assets — works offline and prints to PDF)."""
import html
from collections import Counter

SEV = ["critical", "high", "medium", "low", "info"]
COL = {"critical": "#b42318", "high": "#c2410c", "medium": "#b7791f", "low": "#2563eb", "info": "#64748b"}
WHAT = {
    "API1": "Users can read objects that belong to other users by changing an identifier.",
    "API2": "Data or operations are available without authentication.",
    "API3": "Responses expose properties the client should not receive.",
    "API5": "Lower-privileged users can call administrative functions.",
    "API8": "Configuration weaknesses in transport, headers, CORS, cookies or error handling.",
    "API9": "API inventory and documentation are exposed.",
}


def _e(x):
    return html.escape(str(x if x is not None else ""))


def _curl(f, identities):
    f.get("evidence", "")
    hdr = ' -H "Authorization: <token of the second user>"' if f["rule_id"] == "NM-DAST-020" else \
          ' -H "Authorization: <token of a non-privileged user>"' if f["rule_id"] == "NM-DAST-023" else ""
    method = (f.get("file") or "GET").split(" ")[0]
    return f'curl -i -X {method}{hdr} "{f.get("url", "")}"' if f.get("url") else ""


def render(result, customer="", assessor="", classification="Confidential"):
    fs = [f for f in result["findings"] if f.get("status") != "suppressed"]
    counts = Counter(f["severity"] for f in fs)
    owasp = Counter((f.get("owasp_api") or "Other").split(":")[0] for f in fs)
    d = result.get("decision") or {}
    verdict = {"block": ("Not acceptable for release", "#b42318"), "warn": ("Acceptable with remediation plan", "#b7791f"),
               "pass": ("No blocking issues found", "#15803d")}.get(d.get("decision"), ("—", "#64748b"))
    rows = "".join(
        f'<tr><td><span class="sev" style="background:{COL[f["severity"]]}">{_e(f["severity"])}</span></td><td>{_e(f["priority"])}</td>'
        f'<td>{_e(f["mrs"])}</td><td><a href="#{_e(f["id"])}">{_e(f["title"])}</a></td><td>{_e((f.get("owasp_api") or "").split(" ")[0])}</td></tr>'
        for f in fs)
    details = "".join(
        f'''<section class="finding" id="{_e(f["id"])}">
  <h3><span class="sev" style="background:{COL[f["severity"]]}">{_e(f["severity"])}</span> {_e(f["title"])}</h3>
  <table class="kv">
    <tr><th>ID / rule</th><td>{_e(f["id"])} · {_e(f["rule_id"])}</td></tr>
    <tr><th>Priority / risk score</th><td>{_e(f["priority"])} · MRS {_e(f["mrs"])} / 100 · fix within {_e(f.get("sla_days"))} days</td></tr>
    <tr><th>Location</th><td><code>{_e(f.get("file"))}</code></td></tr>
    {f'<tr><th>Affected endpoints</th><td><code>{_e(", ".join(f["affected_endpoints"]))}</code></td></tr>' if f.get("affected_endpoints") else ""}
    <tr><th>Classification</th><td>{_e(f.get("owasp_api"))}{" · " + _e(f["cwe"]) if f.get("cwe") else ""}</td></tr>
    <tr><th>What it means</th><td>{_e(WHAT.get((f.get("owasp_api") or "").split(":")[0], ""))}</td></tr>
    <tr><th>Evidence</th><td><code>{_e(f.get("evidence"))}</code></td></tr>
    <tr><th>Reproduce</th><td><code>{_e(_curl(f, result.get("identities")))}</code></td></tr>
    <tr><th>Remediation</th><td>{_e(f.get("remediation"))}</td></tr>
  </table>
</section>''' for f in fs)
    by_owasp = "".join(f"<tr><td>{_e(k)}</td><td>{_e(WHAT.get(k, ''))}</td><td>{v}</td></tr>" for k, v in sorted(owasp.items()))
    tiles = "".join(f'<div class="tile"><b style="color:{COL[s]}">{counts.get(s, 0)}</b><span>{s}</span></div>' for s in SEV)
    stats = result.get("stats", {})
    tools = result.get("tools") or []
    zap = stats.get("zap") or {}
    checks = []
    if "myelin-dast" in tools:
        checks.append("Baseline transport and response checks")
    if stats.get("baseline_auth_checks"):
        checks.append(f'Baseline authentication checks: {stats["baseline_auth_checks"]}')
    if "myelin-authz" in tools:
        checks.append(f'Multi-user authorisation: {stats.get("object_checks", 0)} object and {stats.get("function_checks", 0)} function checks')
    if "myelin-crawler" in tools:
        checks.append(f'Crawler: {stats.get("crawled_endpoints", 0)} endpoints discovered')
    if "myelin-active" in tools:
        checks.append("Built-in active checks were enabled")
    if zap.get("complete") is False:
        verdict = ("Incomplete coverage: OWASP ZAP did not finish", "#b7791f")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>API security assessment — {_e(result["repo"])}</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;color:#0c1218;margin:0;background:#f4f7fa}}
.page{{max-width:980px;margin:0 auto;background:#fff;padding:40px 48px}}
.cover{{background:#0c1218;color:#fff;padding:36px 48px;max-width:980px;margin:0 auto;box-sizing:border-box}}
.cover .eb{{color:#7fd8cc;letter-spacing:3px;font-size:12px;font-weight:700}}
.cover h1{{margin:8px 0 6px;font-size:28px}} .cover p{{color:#c9d3dd;margin:2px 0}}
h2{{border-bottom:2px solid #0f9f8f;padding-bottom:6px;margin-top:34px;font-size:20px}} h3{{font-size:16px;margin:0 0 10px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #e2e8f0;vertical-align:top}}
th{{background:#f1f5f8}} .kv th{{width:170px;background:none;color:#5b6b7c;font-weight:600}}
.sev{{color:#fff;border-radius:4px;padding:2px 7px;font-size:11px;font-weight:700;text-transform:uppercase}}
.tiles{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:14px 0}} .tile{{border:1px solid #e2e8f0;border-radius:8px;padding:12px;text-align:center}}
.tile b{{display:block;font-size:26px}} .tile span{{font-size:12px;color:#5b6b7c;text-transform:capitalize}}
.verdict{{border-left:5px solid {verdict[1]};background:#f8fafc;padding:12px 16px;margin:12px 0;font-size:15px}}
.finding{{border:1px solid #e2e8f0;border-radius:10px;padding:16px 18px;margin:14px 0;page-break-inside:avoid}}
code{{font-family:Consolas,"Courier New",monospace;font-size:12px;word-break:break-all;background:#f1f5f8;padding:1px 4px;border-radius:3px}}
.muted{{color:#5b6b7c;font-size:12px}} a{{color:#0f766e}}
@media(max-width:700px){{.page,.cover{{padding:22px 16px}}.tiles{{grid-template-columns:repeat(3,1fr)}}.kv th{{width:110px}}}}
@media print{{body{{background:#fff}}.page{{padding:0 10px}}}}
</style></head><body>
<div class="cover"><div class="eb">NERVVE DEVSECOPS · LIVE APPLICATION SECURITY ASSESSMENT</div>
<h1>API security assessment — {_e(result["repo"])}</h1>
<p>Target: {_e(result["target"])}</p><p>Date: {_e(result.get("started_at", "")[:10])} · Mode: {_e(result.get("mode"))}{" · Prepared for " + _e(customer) if customer else ""}</p>
<p>{_e(classification)}</p></div>
<div class="page">
<h2>1. Executive summary</h2>
<div class="verdict"><b>{verdict[0]}.</b> Policy “{_e(d.get("policy"))}”: {_e((d.get("decision") or "").upper())} — {d.get("blocking", 0)} blocking, {d.get("warnings", 0)} warnings.</div>
<div class="tiles">{tiles}</div>
<table><tr><th>OWASP API Top 10 (2023)</th><th>Meaning</th><th>Findings</th></tr>{by_owasp or '<tr><td colspan="3">No findings</td></tr>'}</table>
<h2>2. Scope and method</h2>
<table class="kv">
<tr><th>Target</th><td><code>{_e(result["target"])}</code></td></tr>
{f'<tr><th>API specification</th><td>{_e(result["spec_operations"])} operations</td></tr>' if result.get("spec_operations") else ""}
{f'<tr><th>Test identities</th><td>{_e(", ".join(result["identities"]))}</td></tr>' if result.get("identities") else ""}
{f'<tr><th>Checks</th><td>{_e("; ".join(checks))}</td></tr>' if checks else ""}
<tr><th>Mode and scope</th><td>{_e(result.get("mode"))}. Built-in scanner: {result.get("requests", 0)} requests.
  Total duration: {_e(result.get("duration_s"))} s.</td></tr>
<tr><th>Tools</th><td>{_e(", ".join(result.get("tools", [])))} · NERvvE DevSecOps {_e(result.get("scanner_version"))}</td></tr>
<tr><th>Limitations</th><td>Automated testing does not replace manual penetration testing of business logic, chained attacks or write operations.</td></tr>
</table>
<h2>3. Findings overview</h2>
<table><tr><th>Severity</th><th>Priority</th><th>MRS</th><th>Finding</th><th>OWASP</th></tr>{rows or '<tr><td colspan="5">No findings</td></tr>'}</table>
<h2>4. Finding details</h2>{details or "<p>No findings.</p>"}
<p class="muted">Generated by NERvvE DevSecOps {_e(result.get("scanner_version"))}{" · Assessor: " + _e(assessor) if assessor else ""}. Tokens and credentials are never written to this report.
© 2026 Sudheer Kumar · NERvvE DevSecOps. {_e(classification)}.</p>
</div></body></html>"""
