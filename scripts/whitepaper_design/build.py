#!/usr/bin/env python3
"""Designed edition of the RAT Flea DevSec whitepaper: fixed A4 page layouts, rendered to PDF by render.js.

Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only.

Output: docs/whitepaper/designed/index.html plus img/ (public screenshots and public-edition diagrams), so the same
folder is safe to publish and renders identically everywhere.
    python scripts/whitepaper_design/build.py
    NODE_PATH=<puppeteer> node scripts/whitepaper_design/render.js     # -> docs/whitepaper/RAT-Flea-DevSec-Whitepaper.pdf
"""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from parts import BLUE, CSS, DOCS, NAVY, ORANGE, REPO, SKY, bars, cover_art, icon, legend, qr_svg  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "docs", "whitepaper", "designed")
IMG = os.path.join(OUT, "img")
SHOTS = ["overview", "finding-drawer", "pipelines", "defence", "cnapp", "attack-path-drawer"]
DIAGRAMS = ["architecture", "data-flow", "attack-path", "risk-score"]
TITLE = "The Front Door Has Moved"
ATTR = "RAT Flea DevSec Product designed and developed by Sudheer Kumar"

POLICY = """name: production
mode: enforce          # audit | warn | enforce
gates:
  - id: block-known-exploited
    when: { kev: true }
    action: block
  - id: block-critical-reachable
    when: { severity: [critical], reachable: true }
    action: block
  - id: block-secrets
    when: { engine: [secrets], severity: [critical, high] }
    action: block
  - id: block-mrs-80
    when: { mrs_gte: 80 }    # RAT Flea Risk Score, P0
    action: block"""


def _yaml_line(line):
    import html as _h
    import re as _re
    code, _, comment = line.partition("#")
    e = _h.escape(code)
    e = _re.sub(r"^(\s*-?\s*)([a-z_]+):", r'\1<span style="color:#9ec5f4">\2</span>:', e)
    e = _re.sub(r"action: block", 'action: <span style="color:#ffa37a">block</span>', e)
    if comment:
        e += '<span style="color:#7f93ad">#' + _h.escape(comment) + "</span>"
    return e.replace("  ", "&nbsp;&nbsp;")


POLICY_HTML = "<br>".join(_yaml_line(x) for x in POLICY.split("\n"))

AUTHOR_BIO = ("Sudheer designs, assesses and transforms security across enterprise IT, OT/ICS, cloud, SaaS, telecommunications "
              "and AI ecosystems. He helps organisations turn cybersecurity from a set of technical controls into a business "
              "capability: lower risk, stronger resilience and secure transformation. His recent work centres on securing LLM "
              "applications and agentic AI platforms, from threat modelling and red teaming to Responsible AI governance. He is "
              "the author of <i>Navigating the Digital Frontier: Cyber Security Manager's Handbook</i> (2024) and designed and "
              "developed RAT Flea DevSec.")
EXPERTISE = ["Security strategy &amp; architecture", "CISO advisory", "Cloud security · Azure · AWS · CNAPP", "Zero Trust · IAM · PAM",
             "AI &amp; agentic AI security", "AI red teaming", "OT/ICS · IEC 62443", "DevSecOps &amp; AppSec", "SOC · SIEM · SOAR",
             "Exposure management", "Incident response &amp; resilience", "Risk, governance &amp; compliance"]
APPROACH = ["Understand the business", "Identify the risk", "Design the architecture", "Enable the teams", "Measure the outcome"]

pages = []


def page(body, section="", dark=False, number=True):
    pages.append((body, section, dark, number))


def head(section, dark=False):
    return f'<div class="run-head"><span><b>RAT Flea DevSec</b> &nbsp;·&nbsp; Whitepaper</span><span>{section}</span></div>'


def chap(num, title, lede=None):
    s = f'<div class="chap"><span class="num">{num}</span><h2>{title}</h2></div>'
    return s + (f'<p class="lede">{lede}</p>' if lede else "")


def card(ic, title, text, dark=False):
    return (f'<div class="card"><div class="ico">{icon(ic, SKY if dark else BLUE)}</div><h4>{title}</h4>'
            f'<p>{text}</p></div>')


def stat(value, text, src):
    return f'<div class="stat"><b>{value}</b><span>{text} <i>{src}</i></span></div>'


# ---------------------------------------------------------------- 1 cover
page(f"""{cover_art(side=True)}
<div style="position:absolute;left:16mm;top:16mm" class="brand"><span class="mark">RF</span>
  <div>RAT Flea DevSec<small>{DOCS.split('://')[1].rstrip('/')}</small></div></div>
<div style="position:absolute;left:16mm;right:16mm;top:150mm">
  <div class="kicker">Whitepaper · November 2026</div>
  <h1 style="font-size:46pt;line-height:1.02;font-weight:800;margin:5mm 0 6mm;max-width:150mm">{TITLE}</h1>
  <p style="font-size:14pt;line-height:1.45;color:#cfe0f6;max-width:142mm">Why software delivery is now a board-level
  risk, and how to secure it from code to cloud to runtime with one risk score, one policy and one evidence trail.</p>
</div>
<div style="position:absolute;left:16mm;right:16mm;bottom:16mm;display:flex;justify-content:space-between;
  border-top:1px solid rgba(255,255,255,.22);padding-top:5mm;font-size:8.4pt;color:#cfe0f6">
  <span>{ATTR.replace('Sudheer Kumar', '<b style="color:#fff">Sudheer Kumar</b>')}</span><span>{REPO.split('://')[1]}</span></div>
""", dark=True, number=False)

# ---------------------------------------------------------------- 2 leadership summary + contents
five = [
    ("Software delivery is now the front door.", "Exploiting a vulnerability has become the most common way into an organisation, and almost half of breaches involve a third party."),
    ("The cost is rising, and so is accountability.", "The average breach costs a record USD 4.99 million, and EU rules make management bodies answerable for cyber risk."),
    ("Regulators have a 24-hour clock.", "Since 11 September 2026, actively exploited vulnerabilities in products sold in the EU must be reported within 24 hours."),
    ("Point tools cannot answer the board.", "Separate scanners give separate numbers. Leadership needs one auditable answer to: are we safer, and can we prove it?"),
    ("RAT Flea DevSec gives that answer.", "One platform for code, pipelines, cloud and runtime that ranks the few risks that matter, stops unsafe releases and produces the evidence."),
]
toc = [("01", "The front door has moved", 3), ("02", "Why point tools fall short", 5), ("03", "One platform, one answer", 6),
       ("04", "How it works", 7), ("05", "From finding to fix", 10), ("06", "Code to cloud to runtime", 12),
       ("07", "The console", 13), ("08", "Value for the business", 15), ("09", "Trusted by design", 17),
       ("", "About the author and references", 18)]
page(f"""{head('At a glance')}<div class="inner">
<div class="kicker">For leadership</div>
<h2 class="disp" style="font-size:26pt;color:{NAVY};line-height:1.1;margin:2mm 0 6mm">Five things to know</h2>
<div style="display:grid;gap:4.2mm">{''.join(f'''<div style="display:grid;grid-template-columns:13mm 1fr;gap:3mm;align-items:start">
<span class="num-big">0{i + 1}</span><div><h3 style="margin-bottom:.6mm">{t}</h3><p style="margin:0;color:#4a5a72">{d}</p></div></div>'''
for i, (t, d) in enumerate(five))}</div>
<div style="position:absolute;left:0;right:0;bottom:0;background:#f4f7fb;border-radius:3mm;padding:6mm 7mm">
<div class="kicker" style="margin-bottom:3mm">Contents</div>
<div style="columns:2;column-gap:10mm;font-size:9pt">{''.join(f'''<div style="display:flex;gap:3mm;padding:1.6mm 0;border-bottom:1px dotted #c8d2df;break-inside:avoid">
<b style="color:{BLUE};width:7mm">{n}</b><span style="flex:1">{t}</span><span style="color:#8a96a8">{p}</span></div>''' for n, t, p in toc)}</div></div>
</div>""", "At a glance")

# ---------------------------------------------------------------- 3 threat
chart_trend = bars([("Exploited vulnerability as the way in", [14, 20, 31]), ("Third party involved", [15, 30, 48])],
                   ["DBIR 2024", "DBIR 2025", "DBIR 2026"], maxv=56, h=200)
page(f"""{head('01 · The front door has moved')}<div class="inner">
{chap('01', 'The front door has moved', 'For the first time in the 19 years of the Verizon Data Breach Investigations Report, exploiting a software vulnerability is the most common way attackers get in. The software delivery chain is now the attack surface.')}
<div class="band c4" style="grid-template-columns:repeat(4,1fr);margin:6mm 0 7mm">
{stat('31%', 'of breaches start with an exploited vulnerability, ahead of stolen credentials', '[1]')}
{stat('48%', 'of breaches involve a third party, after a 60% rise in one year', '[1]')}
{stat('$4.99M', 'average cost of a breach, the highest on record', '[2]')}
{stat('24 h', 'to warn EU authorities of an actively exploited vulnerability', '[3]')}</div>
<div class="cols" style="grid-template-columns:1.35fr 1fr;gap:8mm">
<div><h3>Two trends moving the wrong way</h3>
<p style="font-size:8.6pt;color:#4a5a72;margin-bottom:1mm">Share of breaches, by edition of the Verizon DBIR</p>
{legend([('Exploited vulnerability as initial access', BLUE), ('Third party involved', ORANGE)])}{chart_trend}
<p class="src">Sources: Verizon DBIR 2024, 2025 and 2026 [1].</p></div>
<div><h3>What changed</h3>
<p>Attackers now use AI to cut the time from a published vulnerability to a working exploit from months to hours [1].
A vulnerable dependency, a leaked pipeline token or a misconfigured cloud account is reachable long before a quarterly
scan or an annual penetration test would find it.</p>
<p>At the same time, more of every application is built from other people's code: open-source packages, build actions,
container images and AI models. Each one is a door, and each belongs to a supplier.</p>
<div class="quote" style="font-size:13.5pt;margin-top:5mm">The question for leadership is no longer whether to secure
the delivery chain, but whether it can be shown to be secure.</div></div></div>
</div>""", "01 · The front door has moved")

# ---------------------------------------------------------------- 4 cost & regulation
cost = bars([("Global average cost of a breach", [4.88, 4.44, 4.99])], ["2024", "2025", "2026"], unit="", maxv=6, h=180, dec=2)
tl = [("17 Jan 2025", "DORA applies", "Management body accountable for ICT and ICT third-party risk in financial services [4]"),
      ("11 Sep 2026", "CRA reporting starts", "24-hour early warning for actively exploited vulnerabilities and severe incidents [3]"),
      ("Nov 2026", "Today", "Reporting duties already in force; fines up to EUR 15M or 2.5% of worldwide turnover [3]"),
      ("11 Dec 2027", "CRA fully applies", "Essential cybersecurity requirements for every product with digital elements [3]")]
page(f"""{head('01 · The front door has moved')}<div class="inner">
<div class="kicker">Cost and accountability</div>
<h2 class="disp" style="font-size:20pt;color:{NAVY};margin:2mm 0 5mm;line-height:1.15">The cost lands on the business, and the accountability on the board</h2>
<div class="cols" style="grid-template-columns:1fr 1.1fr;gap:9mm">
<div><h3>Average cost of a breach (USD millions)</h3>{cost}
<p class="src">IBM and Ponemon Institute, Cost of a Data Breach Report 2024–2026 [2].</p>
<p style="margin-top:4mm">Costs rose 12% in a year, driven by detection, escalation and lost business. The same research
finds that organisations using security AI and automation extensively cut breach costs by almost USD 2 million [2].
<b>Automation is now a financial lever.</b></p></div>
<div><h3>The regulatory clock</h3>
<div style="position:relative;padding-left:8mm;margin-top:3mm">
<div style="position:absolute;left:2.4mm;top:2mm;bottom:2mm;width:.6mm;background:#cfd8e5"></div>
{''.join(f'''<div style="position:relative;margin-bottom:4.6mm"><span style="position:absolute;left:-7.6mm;top:.6mm;width:4.4mm;height:4.4mm;border-radius:50%;
background:{ORANGE if t == 'Today' else BLUE};box-shadow:0 0 0 1.2mm #fff"></span>
<div style="font-size:7.4pt;font-weight:800;letter-spacing:.1em;color:{ORANGE if t == 'Today' else BLUE}">{d.upper()}</div>
<div style="font-family:'Inter Display';font-weight:700;color:{NAVY};font-size:10.6pt">{t}</div>
<div style="font-size:8.2pt;color:#4a5a72">{x}</div></div>''' for d, t, x in tl)}</div></div></div>
<div style="margin-top:5mm;background:#f4f7fb;border-radius:3mm;padding:5mm 6mm">
<h3>The EU Cyber Resilience Act reporting clock</h3>
<div class="cols c3" style="gap:5mm;margin-top:3mm">
{''.join(f'''<div style="border-top:1.2mm solid {c};padding-top:2.4mm"><div class="disp" style="font-weight:800;font-size:20pt;color:{NAVY}">{v}</div>
<div style="font-size:8.4pt;color:#4a5a72">{t}</div></div>''' for v, t, c in (('24 hours', 'Early warning after becoming aware of active exploitation', ORANGE),
('72 hours', 'Vulnerability notification with first details and mitigations', BLUE), ('14 days', 'Final report after a corrective measure is available', NAVY)))}</div>
<p style="font-size:8.4pt;margin:3.4mm 0 0;color:#4a5a72">NIS2 adds the same direction of travel for essential and important
entities: management bodies approve and oversee cybersecurity measures, must be trained, and can be held liable [5].</p></div>
</div>""", "01 · The front door has moved")

# ---------------------------------------------------------------- 5 problem
stages = [("code", "Code", "Injection, weak crypto"), ("package", "Dependencies", "Vulnerable or malicious packages"),
          ("key", "Secrets", "Tokens in source and pipelines"), ("layers", "Infrastructure", "Public storage, open ports"),
          ("pipeline", "CI pipeline", "Script injection, token theft"), ("rocket", "CD / GitOps", "Unreviewed production deploys"),
          ("globe", "Running APIs", "Broken authorisation"), ("brain", "AI components", "Prompt injection, unpinned models"),
          ("cloud", "Cloud accounts", "Over-privileged identities"), ("pulse", "Workloads", "Attackers already active")]
page(f"""{head('02 · Why point tools fall short')}<div class="inner">
{chap('02', 'Why point tools fall short', 'Most organisations protect each stage of delivery with its own tool, its own severity scale and its own dashboard. Each sees one stage. None can tell the board where the organisation stands.')}
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:3.4mm;margin:7mm 0">
{''.join(f'''<div class="card" style="padding:3.6mm;text-align:left"><div class="ico">{icon(i, ORANGE)}</div><h4 style="font-size:9.4pt">{t}</h4>
<p style="font-size:7.8pt">{d}</p></div>''' for i, t, d in stages)}</div>
<div class="cols c2" style="gap:9mm;align-items:start">
<div class="quote">Ten stages. Ten tools. Ten different answers to "how exposed are we?"</div>
<div><p>The result is predictable. Security teams triage thousands of alerts that describe the same problem in different
words. Engineering receives tickets it cannot prioritise. Releases go out because nothing joined the dots between a
vulnerable package, the pipeline that built it and the cloud identity it runs as.</p>
<p>And when the board asks whether the organisation is getting safer, the answer is assembled by hand, from screenshots,
the night before the meeting.</p></div></div>
<div style="margin-top:7mm;border:1px solid #dfe5ee;border-radius:3mm;padding:5mm 6mm;display:grid;grid-template-columns:repeat(3,1fr);gap:6mm">
{''.join(f'<div><div class="disp" style="font-weight:800;color:{BLUE};font-size:15pt">{a}</div><div style="font-size:8.4pt;color:#4a5a72">{b}</div></div>'
for a, b in (('Alert fatigue', 'The same weakness reported by several tools, each with its own severity'),
             ('Blind spots', 'Nobody sees the path from a code flaw to a cloud admin right'),
             ('No proof', 'Reporting is manual, so it is late, partial and hard to audit')))}</div>
</div>""", "02 · Why point tools fall short")

# ---------------------------------------------------------------- 6 platform
LEDE3 = ("RAT Flea DevSec is a single DevSecOps and cloud security platform that covers the whole delivery chain, "
         "from a developer's commit to a running container, against one policy.")
pillars = [("inbox", "One finding model", "Every engine and every imported scanner produces the same record, de-duplicated."),
           ("gauge", "One risk score", "Severity, exploit probability, known exploitation, reachability, exposure and business criticality."),
           ("scale", "One policy", "Versioned policy as code for pull requests, pipelines and deployments."),
           ("shield", "One release gate", "The exact commit being deployed must pass, or it does not ship."),
           ("ticket", "One closed loop", "Routed tickets, AutoFix pull requests and automatic closure when a re-scan confirms the fix.")]
outcomes = [("Fewer, better alerts", "De-duplication and governed suppressions before anyone triages"),
            ("Faster remediation", "Upgrade plans, AutoFix and SLAs per priority"),
            ("Safe releases", "A gate that fails closed on unscanned or incomplete scans"),
            ("Provable compliance", "Framework-mapped reports, SBOM and VEX"),
            ("Supply-chain resilience", "Malicious, look-alike and hallucinated packages caught"),
            ("Code-to-cloud context", "Attack paths traced back to the line of code")]
page(f"""{head('03 · One platform, one answer', True)}<div class="inner">
{chap('03', 'One platform, one answer', LEDE3)}
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:3.4mm;margin:8mm 0 9mm">
{''.join(card(i, t, d, True) for i, t, d in pillars)}</div>
<div class="kicker" style="margin-bottom:3mm">What changes for the organisation</div>
<div class="cols c3" style="gap:4mm">{''.join(f'''<div style="border-top:1px solid rgba(255,255,255,.2);padding-top:3mm">
<div style="font-family:'Inter Display';font-weight:700;font-size:11pt;color:#fff">{t}</div><div style="font-size:8.4pt;color:#b9c9df">{d}</div></div>''' for t, d in outcomes)}</div>
<div style="position:absolute;left:0;right:0;bottom:0;display:grid;grid-template-columns:repeat(4,1fr);gap:5mm;
 border-top:1px solid rgba(255,255,255,.2);padding-top:6mm">
{''.join(f'<div><div class="disp" style="font-weight:800;font-size:24pt;color:#fff">{a}</div><div style="font-size:8pt;color:{SKY}">{b}</div></div>'
for a, b in (('15', 'security engines in one scan'), ('280', 'built-in detection rules'), ('3', 'clouds and Kubernetes, read-only'), ('0', 'lines of code leave your runner')))}</div>
</div>""", "03 · One platform, one answer", dark=True)

# ---------------------------------------------------------------- 7 architecture
page(f"""{head('04 · How it works')}<div class="inner">
{chap('04', 'How it works', 'A stateless API, a single policy engine and tenant-isolated storage, deployable as SaaS, single-tenant, on-premises or fully air-gapped.')}
<figure class="diag" style="margin:5mm 0 6mm"><img src="img/architecture.svg" alt="RAT Flea DevSec architecture"></figure>
<div class="cols c4" style="gap:4mm">
{card('server', 'Scales out', 'Stateless API behind a bounded scan queue; add replicas as load grows.')}
{card('lock', 'Isolated tenants', 'PostgreSQL forced row-level security: one tenant cannot read another, even through a bug.')}
{card('key', 'Secrets in the vault', 'Source, ticketing and cloud credentials live in the vault, never in the database or reports.')}
{card('eye', 'Code stays home', 'Scans run on your runner. Findings are uploaded; source code is not.')}</div>
</div>""", "04 · How it works")

# ---------------------------------------------------------------- 8 data flow
page(f"""{head('04 · How it works')}<div class="inner">
<div class="kicker">Data flow</div>
<h2 class="disp" style="font-size:20pt;color:{NAVY};margin:2mm 0 2mm">From a commit to a decision in eight steps</h2>
<p class="lede" style="font-size:10pt">Every step is recorded, so the path from a developer's change to a release
decision, a ticket and a closed finding can be shown to an auditor.</p>
<figure class="diag" style="margin:5mm 0 6mm"><img src="img/data-flow.svg" alt="RAT Flea DevSec data flow"></figure>
<div class="cols c2" style="gap:8mm">
<div style="background:#f4f7fb;border-radius:3mm;padding:5mm 6mm"><h3>What leaves your network</h3>
<ul class="tick" style="font-size:8.6pt"><li>Findings, the SBOM and the policy decision</li><li>Cloud configuration metadata, read-only, never data or Kubernetes Secrets</li>
<li>Runtime detections, with tokens and passwords redacted before storage</li></ul></div>
<div style="background:#f4f7fb;border-radius:3mm;padding:5mm 6mm"><h3>What never does</h3>
<ul class="tick" style="font-size:8.6pt"><li>Source code: it is read where the scan runs</li><li>Secret values: detected secrets are fingerprinted, not stored</li>
<li>Anything at all in air-gapped mode, where advisories are carried in offline</li></ul></div></div>
</div>""", "04 · How it works")

# ---------------------------------------------------------------- 9 engines
engines = [("code", "SAST", "40 rules + Bandit"), ("package", "SCA", "OSV · KEV · EPSS · NVD"), ("key", "Secrets", "15 rules"),
           ("layers", "Infrastructure as Code", "29 rules + Checkov"), ("pipeline", "CI pipeline posture", "21 rules"),
           ("chain", "Supply-chain defence", "10 rules"), ("rocket", "CD / GitOps posture", "14 rules"),
           ("scale", "Licence governance", "SPDX policy"), ("brain", "AI application security", "32 rules"),
           ("globe", "Live app and API testing", "23 checks"), ("cloud", "Cloud posture (CSPM)", "67 checks"),
           ("wheel", "Kubernetes posture (KSPM)", "25 checks"), ("user", "Identities (CIEM)", "14 checks"),
           ("pulse", "Runtime (CWPP)", "Falco · Tetragon"), ("path", "Attack paths", "Code to cloud")]
page(f"""{head('04 · How it works')}<div class="inner">
<div style="display:flex;justify-content:space-between;align-items:end">
<div><div class="kicker">Coverage</div><h2 class="disp" style="font-size:20pt;color:{NAVY};margin:2mm 0 0">Fifteen engines. One scan. One result.</h2></div>
<div style="text-align:right"><div class="disp" style="font-weight:800;font-size:34pt;color:{BLUE};line-height:1">280</div>
<div style="font-size:8pt;color:#4a5a72">built-in detection rules</div></div></div>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:4.2mm;margin:8mm 0 9mm">
{''.join(f'''<div class="card" style="display:grid;grid-template-columns:11mm 1fr;gap:3mm;align-items:center;padding:6mm 4.4mm">
<div class="ico" style="margin:0">{icon(i)}</div><div><h4 style="margin:0;font-size:9.8pt">{t}</h4><p style="font-size:7.8pt">{d}</p></div></div>''' for i, t, d in engines)}</div>
<div class="band" style="grid-template-columns:1fr 2.4fr;align-items:center">
<div class="disp" style="font-weight:800;font-size:13pt">Bring your own scanner</div>
<div style="font-size:8.6pt;color:#cfdcee">SARIF 2.1, CycloneDX, Trivy, Grype, Semgrep, Gitleaks, Checkov, Bandit and OWASP ZAP results become
the same findings, with the same score, policy and tickets. Existing investments keep their value.</div></div>
<p style="margin-top:7mm;font-size:10.4pt;line-height:1.55">Every result carries severity, a P0–P3 priority with an SLA, the risk score and CISA SSVC
decision, CWE and CVE references, the framework controls it affects, and the exact location: the file and line at the
scanned commit, or the package and version.</p>
</div>""", "04 · How it works")

# ---------------------------------------------------------------- 10 prioritise
sla = [("P0", "Immediate", "2 days", ORANGE), ("P1", "Urgent", "7 days", "#c2551f"), ("P2", "Planned", "30 days", BLUE), ("P3", "Routine", "90 days", "#6b7f99")]
page(f"""{head('05 · From finding to fix')}<div class="inner">
{chap('05', 'From finding to fix', 'Severity alone does not say what to fix first. A critical issue in a test fixture matters less than a high one that is exploited in the wild and reachable from the internet.')}
<figure class="diag" style="margin:4mm 0 5mm"><img src="img/risk-score.svg" alt="RAT Flea Risk Score"></figure>
<div class="cols c4" style="gap:4mm;margin-bottom:6mm">{''.join(f'''<div style="border-radius:3mm;padding:4mm;background:{c};color:#fff">
<div class="disp" style="font-weight:800;font-size:20pt">{p}</div><div style="font-size:8.4pt;opacity:.9">{m}</div>
<div style="font-weight:700;margin-top:1mm">Fix within {d}</div></div>''' for p, m, d, c in sla)}</div>
<div class="cols c2" style="gap:8mm">
<div><h3>Aligned with CISA SSVC</h3><p>Every finding is placed on the CISA decision tree (Track, Track*, Attend, Act) using
exploitation, automatability, technical impact and mission impact [6]. The decision points are shown, so an analyst can
see and challenge them, and they are recomputed when intelligence changes.</p></div>
<div><h3>Noise removed before anyone looks</h3><ul class="tick"><li>Results describing the same problem are merged</li>
<li>Test, fixture and vendored code is de-prioritised</li><li>Suppressions need a reason and are audited</li><li>Accepted risks must expire</li></ul></div></div>
<div style="margin-top:6mm;border:1px solid #dfe5ee;border-radius:3mm;padding:5mm 6mm">
<div style="display:flex;justify-content:space-between;align-items:baseline"><h3>Worked example: one vulnerable library, scored</h3>
<span class="chip" style="background:#fdeee6;color:#a3400f">P0 · fix within 2 days</span></div>
<p style="font-size:8.4pt;color:#4a5a72;margin-bottom:3mm">A remote-code-execution flaw in a logging library, in an internet-facing payments service (demo data)</p>
<div style="display:flex;height:9mm;border-radius:2mm;overflow:hidden;font-size:7.6pt;font-weight:700;color:#fff">
<div style="flex:40;background:#0b1f3a;display:grid;place-items:center">Impact (CVSS 10) +40</div>
<div style="flex:24.4;background:#2a78d6;display:grid;place-items:center">EPSS +24</div>
<div style="flex:15;background:#eb6834;display:grid;place-items:center">KEV +15</div>
<div style="flex:10;background:#6fa6e6;display:grid;place-items:center">Exposed +10</div>
<div style="flex:10;background:#9ec5f4;color:#0b1f3a;display:grid;place-items:center">Reachable +10</div></div>
<div style="display:flex;justify-content:space-between;font-size:7.6pt;color:#8a96a8;margin-top:1.6mm"><span>0</span>
<span>Capped at <b style="color:#0b1f3a">100 / 100</b> · business criticality weighting applied · SSVC: <b style="color:#a3400f">Act</b></span></div></div>
</div>""", "05 · From finding to fix")

# ---------------------------------------------------------------- 11 gate + loop
flow = [("code", "Commit", "Developer pushes a change"), ("eye", "Scan", "Fifteen engines on your runner"),
        ("scale", "Decide", "One policy: pass, warn or block"), ("shield", "Gate", "Exact commit checked at deploy")]
loop = [("ticket", "Assign", "Routed ticket, one per finding"), ("bolt", "Fix", "Upgrade plan or AutoFix pull request"),
        ("check", "Verify", "Re-scan closes it automatically"), ("doc", "Prove", "Report, SBOM, VEX and audit trail")]
page(f"""{head('05 · From finding to fix')}<div class="inner">
<div class="kicker">Release gate and closed loop</div>
<h2 class="disp" style="font-size:20pt;color:{NAVY};margin:2mm 0 5mm">Unsafe code does not ship. Fixed code closes itself.</h2>
<div style="display:grid;grid-template-columns:1fr 6mm 1fr 6mm 1fr 6mm 1fr 6mm 1.05fr;align-items:stretch;gap:0">
{''.join(f'''<div class="card" style="text-align:center;padding:4mm 2mm"><div class="ico" style="margin:0 auto 2mm">{icon(i)}</div><h4>{t}</h4><p style="font-size:7.6pt">{d}</p></div>
<div style="display:grid;place-items:center;color:{BLUE};font-weight:800">›</div>''' for i, t, d in flow)}
<div style="display:grid;gap:2mm"><div style="border-radius:3mm;background:#e3f5ec;padding:3mm;text-align:center"><b style="color:#0b6b3a">Deploy</b>
<div style="font-size:7.4pt;color:#3d6b52">Passed policy</div></div>
<div style="border-radius:3mm;background:#fdeee6;padding:3mm;text-align:center"><b style="color:#a3400f">Blocked</b>
<div style="font-size:7.4pt;color:#8a4a2a">Owner told why</div></div></div></div>
<div class="cols c3" style="gap:5mm;margin:5mm 0">
{card('stop', 'Fails closed', 'A commit that was never scanned, or scanned without a required engine, is blocked.')}
{card('flag', 'Only what is new', 'With --scope new, only findings a commit introduced can block, so old debt does not stall releases.')}
{card('team', 'Governed exceptions', 'Time-boxed, exactly scoped, approved by someone other than the requester, with MFA.')}</div>
<div style="background:#f4f7fb;border-radius:3mm;padding:5mm 6mm">
<h3 style="margin-bottom:3mm">The closed loop</h3>
<div class="cols c4" style="gap:4mm">{''.join(f'''<div style="display:grid;grid-template-columns:9mm 1fr;gap:2.4mm;align-items:start">
<div class="ico" style="margin:0;background:#fff">{icon(i)}</div><div><b style="color:{NAVY}">{t}</b><div style="font-size:7.8pt;color:#4a5a72">{d}</div></div></div>''' for i, t, d in loop)}</div>
<p style="font-size:8.4pt;margin:4mm 0 0;color:#4a5a72">Works with GitHub Actions, Azure Pipelines, GitLab, Jenkins, Bitbucket and Argo CD,
with tickets in Jira, ServiceNow and Azure Boards and alerts in Teams and Slack.</p></div>
<div style="display:grid;grid-template-columns:1.55fr 1fr;gap:6mm;margin-top:4.5mm;align-items:center">
<div style="background:#071427;border-radius:3mm;padding:4.6mm 5mm;font:7.4pt/1.62 'DejaVu Sans Mono',monospace;color:#e3eefc;white-space:nowrap">{POLICY_HTML}</div>
<div><h3>One policy file, every stage</h3><p>The same versioned policy decides pull requests, pipeline runs and deployments.
It is approved by a second person, identified by its content, and runs in audit, warn or enforce mode, so teams can
roll it out without stopping delivery.</p></div></div>
</div>""", "05 · From finding to fix")

# ---------------------------------------------------------------- 12 code to cloud
page(f"""{head('06 · Code to cloud to runtime')}<div class="inner">
{chap('06', 'Code to cloud to runtime', 'Configuration, identities and live detections are joined to the code that created them. When exposure, an exploitable weakness and privileged access meet on one workload, it is reported as a single attack path.')}
<figure class="diag" style="margin:5mm 0 5mm"><img src="img/attack-path.svg" alt="Attack path"></figure>
<div class="cols c4" style="gap:4mm">
{card('cloud', 'Cloud posture', '67 checks across Azure, AWS and Google Cloud, by CIS section, collected read-only.')}
{card('wheel', 'Kubernetes', '25 checks: Pod Security, RBAC, exposure and isolation. Cannot read Secrets.')}
{card('user', 'Identities', '14 checks on effective privilege, MFA, key age, escalation and public access.')}
{card('pulse', 'Runtime', 'Falco and Tetragon detections, grouped per workload, mapped to MITRE ATT&amp;CK.')}</div>
<div style="margin-top:6mm;background:#f4f7fb;border-radius:3mm;padding:5mm 6mm">
<h3 style="margin-bottom:3mm">Example: one path, five links (demo data)</h3>
<div style="display:grid;grid-template-columns:repeat(9,auto);align-items:center;gap:1.6mm;font-size:7.6pt">
<div style="background:#fff;border:1px solid #9aa6b8;border-top:1mm solid #9aa6b8;border-radius:2mm;padding:2.4mm 2.6mm"><b style="color:#0b1f3a">Internet</b><div style="color:#4a5a72">public address</div></div><span style="color:#2a78d6;font-weight:800">›</span><div style="background:#fff;border:1px solid #eb6834;border-top:1mm solid #eb6834;border-radius:2mm;padding:2.4mm 2.6mm"><b style="color:#0b1f3a">Exposure</b><div style="color:#4a5a72">open port on a worker</div></div><span style="color:#2a78d6;font-weight:800">›</span><div style="background:#fff;border:1px solid #eb6834;border-top:1mm solid #eb6834;border-radius:2mm;padding:2.4mm 2.6mm"><b style="color:#0b1f3a">Weakness</b><div style="color:#4a5a72">critical library flaw</div></div><span style="color:#2a78d6;font-weight:800">›</span><div style="background:#fff;border:1px solid #2a78d6;border-top:1mm solid #2a78d6;border-radius:2mm;padding:2.4mm 2.6mm"><b style="color:#0b1f3a">Identity</b><div style="color:#4a5a72">admin cloud role</div></div><span style="color:#2a78d6;font-weight:800">›</span><div style="background:#fff;border:1px solid #0b1f3a;border-top:1mm solid #0b1f3a;border-radius:2mm;padding:2.4mm 2.6mm"><b style="color:#0b1f3a">Data</b><div style="color:#4a5a72">customer documents</div></div>
</div><p style="font-size:8.2pt;color:#4a5a72;margin:3mm 0 0">Linked to the repository and file that built the workload, so the fix can start in code.</p></div>
<div class="quote" style="margin-top:7mm;font-size:14pt">Every attack path shows each link, so the team can break the cheapest one:
close the exposure, fix the code, or reduce the identity's rights.</div>
</div>""", "06 · Code to cloud to runtime")

# ---------------------------------------------------------------- 13 console 1
page(f"""{head('07 · The console')}<div class="inner">
{chap('07', 'The console', 'One console for leadership, security engineering and DevOps, computed from stored scans. Nothing is estimated.')}
<figure class="shot" style="margin:5mm 0 6mm"><img src="img/overview.webp" alt="Executive overview" style="height:96mm;object-fit:cover;object-position:top">
<figcaption><b>Executive overview.</b> Posture score, SLA compliance, mean time to remediate, release-gate pass rate and the
90-day open-risk trend, with views for leadership, security engineering and DevOps.</figcaption></figure>
<figure class="shot"><img src="img/finding-drawer.webp" alt="Finding detail" style="height:88mm;object-fit:cover;object-position:top">
<figcaption><b>Every finding explains itself.</b> The risk-score breakdown, blast radius across repositories, exact location,
framework mapping and the CISA SSVC decision.</figcaption></figure>
</div>""", "07 · The console")

# ---------------------------------------------------------------- 14 console 2
page(f"""{head('07 · The console')}<div class="inner">
<div class="cols c2" style="gap:8mm;row-gap:12mm">
<figure class="shot"><img src="img/pipelines.webp" alt="Pipelines"><figcaption><b>Pipelines.</b> Every run gated by policy, with the
OWASP Top 10 CI/CD risks across all pipelines.</figcaption></figure>
<figure class="shot"><img src="img/defence.webp" alt="Supply-chain defence"><figcaption><b>Supply-chain defence.</b> Malicious releases,
look-alike and hallucinated packages, worm indicators and CI jobs exposing secrets.</figcaption></figure>
<figure class="shot"><img src="img/cnapp.webp" alt="Cloud overview"><figcaption><b>Cloud overview.</b> Attack paths across accounts and
clusters, linked to the code that created them.</figcaption></figure>
<figure class="shot"><img src="img/attack-path-drawer.webp" alt="Attack path detail"><figcaption><b>Attack path detail.</b> Exposure,
weakness, identity and data on one workload, with the evidence for each step.</figcaption></figure></div>
<div class="band" style="margin-top:8mm;grid-template-columns:repeat(3,1fr)">
{''.join(f'<div><div class="disp" style="font-weight:700;font-size:11.5pt">{a}</div><div style="font-size:8.2pt;color:#b9cde8">{b}</div></div>'
for a, b in (('Corporate reports', 'Internal and customer-publishable editions mapped to OWASP, PCI DSS, ISO/IEC 27001, NIST, SOC 2 and CIS'),
             ('AI assistant', 'Explains and fixes findings, suggests triage and writes the executive briefing, with your own model or none'),
             ('Exports everywhere', 'CSV, CycloneDX SBOM and CBOM, VEX and the hash-chained audit trail for any SIEM')))}</div>
</div>""", "07 · The console")

# ---------------------------------------------------------------- 15 value
levers = [("inbox", "Analyst time", "Duplicates merged, noise removed before triage", "Findings removed × minutes per triage × hourly cost"),
          ("clock", "Faster remediation", "Teams fix the few findings that matter first", "Days of exposure removed for P0 and P1"),
          ("rocket", "Release confidence", "Unsafe releases stopped at the exact commit", "Emergency fixes and rollbacks avoided"),
          ("doc", "Audit effort", "Framework-mapped evidence replaces manual collection", "Hours per audit cycle × cycles per year"),
          ("layers", "Tool consolidation", "One platform, policy and finding model", "Licences, integrations and upkeep replaced"),
          ("flag", "Regulatory exposure", "Exploited vulnerabilities found with the clock running", "Missed or late reports avoided")]
page(f"""{head('08 · Value for the business')}<div class="inner">
{chap('08', 'Value for the business', 'Every lever below is measured by the platform from your own scans, so the business case is built from evidence, not estimates.')}
<div class="cols c3" style="gap:4mm;margin:6mm 0 7mm">{''.join(f'''<div class="card"><div class="ico">{icon(i)}</div><h4>{t}</h4><p>{w}</p>
<div style="margin-top:2.4mm;padding-top:2.4mm;border-top:1px dashed #c8d2df;font-size:7.6pt;color:{NAVY}"><b>Measure:</b> {f}</div></div>''' for i, t, w, f in levers)}</div>
<div class="band" style="grid-template-columns:1.1fr 2fr;align-items:center">
<div><div class="disp" style="font-weight:800;font-size:15pt">Build the case in two weeks</div>
<div style="font-size:8.2pt;color:#b9cde8;margin-top:1.4mm">Run the free Community edition on 3–5 representative repositories, one pipeline and one non-production cloud account.</div></div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:5mm">
<div style="border-left:.8mm solid {SKY};padding-left:3.4mm"><b>Week 1 · Baseline</b><div style="font-size:8.2pt;color:#cfdcee">Open findings, P0/P1 counts, MTTR and hours spent on the last audit. Policy in audit mode.</div></div>
<div style="border-left:.8mm solid {ORANGE};padding-left:3.4mm"><b>Week 2 · Compare</b><div style="font-size:8.2pt;color:#cfdcee">The same figures from the platform's dashboards, ready for finance and audit to check.</div></div></div></div>
<div class="cols c3" style="gap:5mm;margin-top:6mm">
<div style="border-top:1.2mm solid #2a78d6;padding-top:2.6mm"><div class="disp" style="font-weight:700;color:#0b1f3a;font-size:11pt">What finance sees</div><div style="font-size:8.4pt;color:#4a5a72">Time saved, tools replaced and exposure reduced, each with the formula and the figures behind it</div></div><div style="border-top:1.2mm solid #0b1f3a;padding-top:2.6mm"><div class="disp" style="font-weight:700;color:#0b1f3a;font-size:11pt">What audit sees</div><div style="font-size:8.4pt;color:#4a5a72">Control-by-control evidence, approvals and a tamper-evident history of every decision</div></div><div style="border-top:1.2mm solid #eb6834;padding-top:2.6mm"><div class="disp" style="font-weight:700;color:#0b1f3a;font-size:11pt">What engineering sees</div><div style="font-size:8.4pt;color:#4a5a72">Fewer, clearer tickets with the fix attached, and releases that are not stopped by old debt</div></div></div>
<p class="src" style="margin-top:5mm">Industry context: organisations using security AI and automation extensively report breach costs almost USD 2 million lower on average [2].</p>
</div>""", "08 · Value for the business")

# ---------------------------------------------------------------- 18 metrics
kpis = [("Security posture score", "0–100", "One number for exposure across repositories, pipelines and cloud", "up", "↑ Up"),
        ("Open P0 and P1", "count", "The risks that need action now", "down", "↓ Down"),
        ("SLA compliance", "% by priority", "Fixed within the agreed time: P0 in 2 days, P1 in 7", "up", "↑ Up"),
        ("Mean time to remediate", "days by severity", "How quickly exposure is removed", "down", "↓ Down"),
        ("Release-gate pass rate", "% of runs", "Unsafe code stopped before production", "up", "↑ Up"),
        ("Known-exploited open", "CISA KEV", "Exposure to attacks happening now", "zero", "→ Zero"),
        ("Attack paths open", "count", "Routes from the internet to data or admin rights", "down", "↓ Down"),
        ("Supply-chain threats", "count", "Malicious, look-alike and hallucinated packages", "zero", "→ Zero"),
        ("Framework alignment", "% of controls", "PCI DSS, ISO/IEC 27001, SOC 2, NIST, EU CRA", "up", "↑ Up"),
        ("CRA reportable items", "with clock", "Reported on time, every time", "zero", "→ On time")]
page(f"""{head('08 · Value for the business')}<div class="inner">
<div class="kicker">Built-in measurement</div>
<h2 class="disp" style="font-size:20pt;color:{NAVY};margin:2mm 0 2mm">What the platform measures for you</h2>
<p class="lede" style="font-size:10pt">Ten measures on the leadership dashboard, computed from stored scan history. None is estimated, and every figure links to the findings behind it.</p>
<div class="cols c2" style="gap:4.6mm;margin-top:7mm">{''.join(f'''<div class="kpi" style="min-height:36mm;padding:5mm"><span class="dir {d}">{a}</span><div class="lab">{u}</div><h4>{t}</h4><p>{x}</p></div>''' for t, u, x, d, a in kpis)}</div>
</div>""", "08 · Value for the business")

# ---------------------------------------------------------------- 21 trust
controls = [("user", "Identity", "OIDC single sign-on with Keycloak, Microsoft Entra ID or Okta; MFA and step-up"),
            ("team", "Authorisation", "Role-based permissions on every endpoint: viewer to tenant admin"),
            ("lock", "Tenant isolation", "PostgreSQL forced row-level security; keys bound to one tenant"),
            ("key", "Secrets", "Credentials in the vault; nothing secret in reports or logs"),
            ("doc", "Audit", "Append-only, hash-chained audit trail exportable to any SIEM"),
            ("globe", "Network", "Server-side request forgery guard on every outbound call"),
            ("package", "Supply chain", "Pinned dependencies, its own SBOM, scanned by itself before release"),
            ("eye", "Honest limits", "Evidence and location on every finding; every triage decision reversible"),
            ("server", "Air-gapped ready", "Runs with no internet; advisories carried in offline")]
deploy = [("Multi-tenant SaaS", "Fastest start, regional hosting"), ("Dedicated single-tenant", "Isolated infrastructure for regulated organisations"),
          ("On-premises", "Docker Compose or Helm on Kubernetes, inside your network"), ("Air-gapped", "No internet access; offline intelligence packs")]
page(f"""{head('09 · Trusted by design')}<div class="inner">
{chap('09', 'Trusted by design', 'A security platform must meet the standard it enforces. RAT Flea DevSec is built, tested and released to the same policy it applies to your code.')}
<div class="cols c3" style="gap:4mm;margin:6mm 0 7mm">{''.join(card(i, t, d) for i, t, d in controls)}</div>
<div class="kicker" style="margin-bottom:3mm">Deploy it your way</div>
<div class="cols c4" style="gap:4mm">{''.join(f'''<div style="border-top:1.2mm solid {BLUE};padding-top:2.6mm"><div class="disp" style="font-weight:700;color:{NAVY};font-size:10.6pt">{t}</div>
<div style="font-size:8.2pt;color:#4a5a72">{d}</div></div>''' for t, d in deploy)}</div>
<p class="src" style="margin-top:5mm">Framework mappings are evidence aids: they show where automated testing bears on a control and are not a certification.
A labelled benchmark of vulnerable and safe code runs on every change; precision and recall must not regress.</p>
</div>""", "09 · Trusted by design")

# ---------------------------------------------------------------- 22 author + references
refs = [("Verizon, 2026 Data Breach Investigations Report (May 2026); 2025 and 2024 editions.", "verizon.com/about/news/breach-industry-wide-dbir-finds"),
        ("IBM and Ponemon Institute, Cost of a Data Breach Report 2026 (July 2026); 2025 and 2024 editions.", "newsroom.ibm.com"),
        ("Regulation (EU) 2024/2847, Cyber Resilience Act, Articles 14 and 64.", "eur-lex.europa.eu/eli/reg/2024/2847/oj"),
        ("Regulation (EU) 2022/2554, Digital Operational Resilience Act, Articles 5 and 28.", "eur-lex.europa.eu/eli/reg/2022/2554/oj"),
        ("Directive (EU) 2022/2555, NIS2, Article 20.", "eur-lex.europa.eu/eli/dir/2022/2555/oj"),
        ("CISA, Stakeholder-Specific Vulnerability Categorization (SSVC).", "cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc"),
        ("FIRST, Exploit Prediction Scoring System (EPSS).", "first.org/epss"),
        ("OpenSSF, Open Source Project Security Baseline.", "baseline.openssf.org")]
page(f"""{head('About the author and references')}<div class="inner">
<div style="display:grid;grid-template-columns:34mm 1fr;gap:7mm;align-items:start">
<div style="width:34mm;height:34mm;border-radius:50%;background:radial-gradient(circle at 30% 30%,#13508c,{NAVY});display:grid;place-items:center;
font-family:'Inter Display';font-weight:800;font-size:24pt;color:#fff">SK</div>
<div><div class="kicker">About the author</div><h2 class="disp" style="font-size:21pt;color:{NAVY};margin:1.4mm 0 .6mm">Sudheer Kumar</h2>
<div style="font-size:9.4pt;font-weight:700;color:{BLUE};margin-bottom:3mm">Cybersecurity &amp; Enterprise Security Architect · 16 years</div>
<p style="font-size:9.4pt">{AUTHOR_BIO}</p></div></div>
<div style="display:flex;flex-wrap:wrap;gap:1.8mm;margin:4mm 0 4mm">{''.join(f'<span class="chip">{x}</span>' for x in EXPERTISE)}</div>
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:1.6mm;background:{NAVY};border-radius:3mm;padding:3.4mm">
{''.join(f'''<div style="text-align:center;color:#fff"><div class="disp" style="font-weight:800;color:{SKY};font-size:11pt">{i + 1}</div>
<div style="font-size:8pt;line-height:1.3">{t}</div></div>''' for i, t in enumerate(APPROACH))}</div>
<div style="margin-top:6mm;border-top:1px solid #dfe5ee;padding-top:4.4mm">
<div class="kicker" style="margin-bottom:2.4mm">References</div>
<ol style="padding-left:5mm;font-size:7.8pt;color:#4a5a72">{''.join(f'<li style="margin-bottom:1.2mm">{t} <span style="color:{BLUE}">{u}</span></li>' for t, u in refs)}</ol>
<p class="src" style="margin-top:3mm">Figures from third-party research are quoted as published by their authors and are not RAT Flea DevSec measurements.</p></div>
<div style="position:absolute;left:0;right:0;bottom:0;border-top:1px solid #dfe5ee;padding-top:4mm;font-size:7.6pt;color:#8a96a8;line-height:1.5">
The RAT Flea DevSec Community edition is free and open-source software under the GNU Affero General Public License v3.0, with every feature included
and no licence key required. You own your code, scan results and reports. Commercial licences, support and enterprise editions are available from the author.
Full terms: LICENSE and NOTICE.md in the repository. Copyright © 2026 Sudheer Kumar.</div>
</div>""", "About the author and references")

# ---------------------------------------------------------------- 23 back cover
page(f"""{cover_art(seed=21, side=True)}
<div style="position:absolute;left:16mm;top:16mm" class="brand"><span class="mark">RF</span><div>RAT Flea DevSec</div></div>
<div style="position:absolute;left:10mm;top:54mm;width:132mm;height:104mm;border-radius:4mm;background:rgba(7,20,39,.72);
 border:1px solid rgba(158,197,244,.18)"></div>
<div style="position:absolute;left:16mm;right:16mm;top:62mm">
<div class="kicker">Next steps</div>
<h2 class="disp" style="font-size:34pt;line-height:1.05;font-weight:800;margin:4mm 0 8mm;max-width:150mm">See it on your own code.</h2>
<div style="display:grid;gap:5mm;max-width:120mm">{''.join(f'''<div style="display:grid;grid-template-columns:12mm 1fr;gap:3mm;align-items:start">
<div class="ico" style="width:11mm;height:11mm">{icon(i, SKY)}</div><div><div class="disp" style="font-weight:700;font-size:13pt;color:#fff">{t}</div>
<div style="font-size:9.4pt;color:#cfdcee">{d}</div></div></div>''' for i, t, d in (
('eye', 'Explore', 'Documentation, diagrams and the interactive architecture explorer.'),
('rocket', 'Run it free', 'Download the open-source Community edition and scan your own code today.'),
('team', 'Get support', 'Commercial licences, support and enterprise options from the author.')))}</div></div>
<div style="position:absolute;left:16mm;right:16mm;bottom:30mm;display:flex;gap:8mm;align-items:center">
{qr_svg(DOCS, 32)}<div><div style="font-size:8pt;letter-spacing:.16em;text-transform:uppercase;color:{SKY};font-weight:700">Scan or visit</div>
<div class="disp" style="font-size:15pt;font-weight:700;color:#fff;margin-top:1.4mm">{DOCS.split('://')[1].rstrip('/')}</div>
<div style="font-size:9pt;color:#cfdcee;margin-top:1mm">Open source on GitHub: {REPO.split('://')[1]}</div></div></div>
<div style="position:absolute;left:16mm;right:16mm;bottom:12mm;border-top:1px solid rgba(255,255,255,.22);padding-top:4mm;
font-size:8pt;color:#cfe0f6;display:flex;justify-content:space-between"><span><b style="color:#fff">{ATTR}.</b></span><span>© 2026 Sudheer Kumar · Open source under the GNU AGPL-3.0</span></div>
""", dark=True, number=False)


def build():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(IMG)
    for s in SHOTS:
        shutil.copy2(os.path.join(ROOT, "docs", "assets", "screenshots-public", s + ".webp"), IMG)
    env = dict(os.environ, MYELIN_DOCS_EDITION="public", MYELIN_DOCS_OUT=IMG)
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "docs_diagrams.py")], env=env, check=True, stdout=subprocess.DEVNULL)
    for f in os.listdir(IMG):
        if f.endswith(".svg") and f[:-4] not in DIAGRAMS:
            os.remove(os.path.join(IMG, f))
    total = len(pages)
    html = []
    for n, (body, section, dark, number) in enumerate(pages, 1):
        foot = (f'<div class="run-foot"><span>{DOCS.split("://")[1].rstrip("/")}</span><span>{n:02d} / {total:02d}</span></div>'
                if number else "")
        html.append(f'<section class="page{" dark" if dark else ""}" data-page="{n}">{body}{foot}</section>')
    doc = (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>RAT Flea DevSec — {TITLE} · Whitepaper</title>'
           f'<meta name="viewport" content="width=device-width,initial-scale=1"><style>{CSS}</style></head><body>{"".join(html)}</body></html>')
    with open(os.path.join(OUT, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(doc)
    return os.path.join(OUT, "index.html"), total


if __name__ == "__main__":
    print(*build())
