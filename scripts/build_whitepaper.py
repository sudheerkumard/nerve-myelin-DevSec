# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Render docs/whitepaper/RAT-Flea-DevSec-Whitepaper.md into a designed, print-ready HTML file (open in a browser → PDF).

    python scripts/build_whitepaper.py            # writes docs/whitepaper/RAT-Flea-DevSec-Whitepaper.html
"""
import os
import re

import markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.environ.get("MYELIN_WP_SRC") or os.path.join(ROOT, "docs", "whitepaper", "RAT-Flea-DevSec-Whitepaper.md")
OUT = os.environ.get("MYELIN_WP_OUT") or os.path.join(ROOT, "docs", "whitepaper", "RAT-Flea-DevSec-Whitepaper.html")  # env: public edition builds
REPO = "https://github.com/sudheerkumard/nervve-devsecops"
DOCS = "https://sudheerkumard.github.io/nervve-devsecops/"

ARCH = """<figure class="arch"><svg viewBox="0 0 860 430" role="img" aria-label="RAT Flea DevSec architecture">
<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="#5a6b85"/></marker></defs>
<g font-family="system-ui,Segoe UI,Arial" font-size="12">
<rect x="20" y="14" width="390" height="58" rx="10" fill="#eef4ff" stroke="#b8cdf5"/><text x="215" y="38" text-anchor="middle" font-weight="700" fill="#0b2a4a">Developers · CI / CD · GitOps</text>
<text x="215" y="57" text-anchor="middle" fill="#46566e">myelin CLI · pipeline templates · Argo CD PreSync gate</text>
<rect x="450" y="14" width="390" height="58" rx="10" fill="#eef4ff" stroke="#b8cdf5"/><text x="645" y="38" text-anchor="middle" font-weight="700" fill="#0b2a4a">Security · DevOps · Leadership</text>
<text x="645" y="57" text-anchor="middle" fill="#46566e">web console · dashboards · reports · VEX</text>
<line x1="215" y1="72" x2="215" y2="104" stroke="#5a6b85" stroke-width="1.6" marker-end="url(#ar)"/><line x1="645" y1="72" x2="645" y2="104" stroke="#5a6b85" stroke-width="1.6" marker-end="url(#ar)"/>
<rect x="20" y="106" width="820" height="150" rx="12" fill="#0b2a4a"/>
<text x="430" y="132" text-anchor="middle" font-weight="700" font-size="14" fill="#fff">RAT Flea DevSec API</text>
<text x="430" y="152" text-anchor="middle" fill="#9ec5f4">Scan ingest · Repository sources · Import · Release gate · Reports · VEX · ITSM · Audit</text>
<g fill="#13406f" stroke="#2a78d6">
<rect x="40" y="170" width="92" height="30" rx="6"/><rect x="140" y="170" width="92" height="30" rx="6"/><rect x="240" y="170" width="92" height="30" rx="6"/><rect x="340" y="170" width="92" height="30" rx="6"/>
<rect x="440" y="170" width="92" height="30" rx="6"/><rect x="540" y="170" width="92" height="30" rx="6"/><rect x="640" y="170" width="92" height="30" rx="6"/><rect x="740" y="170" width="80" height="30" rx="6"/>
<rect x="40" y="210" width="152" height="30" rx="6"/><rect x="198" y="210" width="152" height="30" rx="6"/><rect x="356" y="210" width="152" height="30" rx="6"/><rect x="514" y="210" width="152" height="30" rx="6"/><rect x="672" y="210" width="148" height="30" rx="6"/></g>
<g fill="#fff" text-anchor="middle" font-size="11.5" font-weight="600">
<text x="86" y="190">SAST</text><text x="186" y="190">SCA + intel</text><text x="286" y="190">Secrets</text><text x="386" y="190">IaC</text>
<text x="486" y="190">CI posture</text><text x="586" y="190">CD posture</text><text x="686" y="190">Licences</text><text x="780" y="190">AI-BOM</text>
<text x="116" y="230">Supply-chain defence</text><text x="274" y="230">Live API · multi-user</text><text x="432" y="230">Posture · CBOM · CRA</text><text x="590" y="230">Scanner import</text><text x="746" y="230">Risk · SSVC · gate</text></g>
<g stroke="#5a6b85" stroke-width="1.4" marker-end="url(#ar)"><line x1="100" y1="256" x2="100" y2="300"/><line x1="265" y1="256" x2="265" y2="300"/><line x1="430" y1="256" x2="430" y2="300"/><line x1="595" y1="256" x2="595" y2="300"/><line x1="760" y1="256" x2="760" y2="300"/></g>
<g><rect x="20" y="302" width="160" height="110" rx="10" fill="#f6f6f3" stroke="#d6d3ca"/><rect x="185" y="302" width="160" height="110" rx="10" fill="#f6f6f3" stroke="#d6d3ca"/>
<rect x="350" y="302" width="160" height="110" rx="10" fill="#f6f6f3" stroke="#d6d3ca"/><rect x="515" y="302" width="160" height="110" rx="10" fill="#f6f6f3" stroke="#d6d3ca"/><rect x="680" y="302" width="160" height="110" rx="10" fill="#f6f6f3" stroke="#d6d3ca"/></g>
<g text-anchor="middle" fill="#0b0b0b"><text x="100" y="326" font-weight="700">PostgreSQL</text><text x="265" y="326" font-weight="700">OpenBao / Vault</text><text x="430" y="326" font-weight="700">Identity provider</text><text x="595" y="326" font-weight="700">Source platforms</text><text x="760" y="326" font-weight="700">ITSM · ChatOps</text></g>
<g text-anchor="middle" fill="#52514e" font-size="11"><text x="100" y="348">row-level security</text><text x="100" y="364">per tenant</text><text x="100" y="380">hash-chained audit</text>
<text x="265" y="348">source &amp; ITSM tokens</text><text x="265" y="364">test identities</text><text x="265" y="380">never in DB or reports</text>
<text x="430" y="348">Keycloak · Entra ID</text><text x="430" y="364">Okta · OIDC + MFA</text><text x="430" y="380">roles per tenant</text>
<text x="595" y="348">GitHub · GitLab · Azure</text><text x="595" y="364">Bitbucket · CodeCommit</text><text x="595" y="380">Google Cloud · Git</text>
<text x="760" y="348">Jira · ServiceNow</text><text x="760" y="364">Azure Boards</text><text x="760" y="380">Teams / Slack webhook</text></g></g></svg>
<figcaption>Figure 1 — RAT Flea DevSec architecture</figcaption></figure>"""

CSS = """
:root{--brand:#0b2a4a;--acc:#2a78d6;--ink:#0b0b0b;--ink2:#46566e;--line:#e1e0d9}
*{box-sizing:border-box} body{margin:0;font:11pt/1.55 system-ui,"Segoe UI",Arial,sans-serif;color:var(--ink);background:#ecebe6}
.page{max-width:820px;margin:18px auto;background:#fff;padding:52px 60px;box-shadow:0 1px 4px rgba(0,0,0,.12)}
.cover{max-width:820px;margin:18px auto 0;min-height:1060px;background:linear-gradient(160deg,#0b2a4a 0%,#0e3a66 62%,#13508c 100%);color:#fff;padding:64px 60px;display:flex;flex-direction:column;position:relative;overflow:hidden}
.cover::after{content:"";position:absolute;right:-180px;top:180px;width:560px;height:560px;border-radius:50%;border:2px solid rgba(158,197,244,.18);box-shadow:0 0 0 60px rgba(158,197,244,.05),0 0 0 140px rgba(158,197,244,.035)}
.brand{display:flex;gap:12px;align-items:center;font-weight:700;letter-spacing:.14em;text-transform:uppercase;font-size:12.5px}
.mark{width:40px;height:40px;border-radius:10px;background:#fff;color:var(--brand);display:grid;place-items:center;font-weight:800;letter-spacing:0;font-size:15px}
.kind{margin-top:210px;color:#9ec5f4;letter-spacing:.22em;text-transform:uppercase;font-size:12px;font-weight:700}
.cover h1{font-size:44px;line-height:1.08;margin:12px 0 14px;position:relative;z-index:1}
.cover .sub{font-size:19px;color:#cde2fb;max-width:600px;margin:0;position:relative;z-index:1}
.cover .foot{margin-top:auto;border-top:1px solid rgba(255,255,255,.25);padding-top:20px;display:flex;justify-content:space-between;font-size:12.5px;color:#cde2fb;position:relative;z-index:1}
.cover .foot b{color:#fff}
h2{color:var(--brand);font-size:20pt;margin:34px 0 10px;padding-top:8px;border-top:3px solid var(--acc);display:inline-block}
h2:first-child{margin-top:0} h3{color:var(--brand)}
p,li{color:#1d2633} a{color:#1c5cab}
table{border-collapse:collapse;width:100%;margin:12px 0 18px;font-size:9.8pt}
th{background:#f2f6fc;color:var(--brand);text-align:left;font-weight:700;padding:8px 9px;border-bottom:2px solid #b8cdf5}
td{padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
tr:nth-child(even) td{background:#fbfbfa}
code{font:9.5pt ui-monospace,Consolas,monospace;background:#f2f4f7;padding:1px 5px;border-radius:4px}
pre{background:#0b2a4a;color:#e8f1fd;padding:14px 16px;border-radius:8px;overflow:auto;font-size:9pt}
hr{border:0;border-top:1px solid var(--line);margin:22px 0}
.shot{margin:12px 0 18px} .shot img{width:100%;height:auto;border:1px solid #d8dee8;border-radius:6px;display:block}
.arch{margin:14px 0 20px} .arch svg{width:100%;height:auto} figcaption{font-size:9pt;color:var(--ink2);text-align:center;margin-top:6px}
.lead{font-size:12.5pt;color:var(--ink2)}
blockquote{margin:0 0 22px;padding:22px 26px;background:linear-gradient(150deg,#0b2a4a,#13508c);color:#fff;border-radius:10px}
blockquote p,blockquote li{color:#e3eefc} blockquote strong{color:#fff} blockquote p:first-child{font-size:13pt;margin-top:0}
blockquote ol{margin:8px 0 0;padding-left:20px} blockquote li{margin:7px 0} blockquote sup.ref a{color:#9ec5f4}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0 20px}
.stats div{border:1px solid #d6e3f6;border-top:4px solid var(--acc);border-radius:8px;padding:12px 12px 10px;background:#f6f9fe}
.stats b{display:block;font-size:20pt;line-height:1.1;color:var(--brand)} .stats span{display:block;font-size:8.6pt;color:var(--ink2);margin-top:6px;line-height:1.35}
sup.ref{font-size:7pt;line-height:0} sup.ref a{text-decoration:none;color:var(--acc);font-weight:700}
table.dense{font-size:8.2pt} table.dense th,table.dense td{padding:5px 5px} table.dense td:not(:first-child){text-align:center}
ol.refs{font-size:8.8pt;color:var(--ink2)} ol.refs li{margin:5px 0;word-break:break-word}
.toc{columns:2;column-gap:28px;font-size:10pt;margin:6px 0 10px} .toc a{display:block;color:var(--ink);text-decoration:none;padding:4px 0;border-bottom:1px dotted #d0d6e0;break-inside:avoid}
.toc a span{color:var(--acc);font-weight:700;display:inline-block;width:26px}
.tochead{color:var(--brand);font-size:20pt;font-weight:700;margin:0 0 8px;padding-top:8px;border-top:3px solid var(--acc);display:inline-block}
.end{margin-top:30px;padding:16px 18px;border-left:4px solid var(--acc);background:#f6f9fe;border-radius:6px}
.bar-print{max-width:820px;margin:14px auto 0;text-align:right} .bar-print button{font:inherit;border:1px solid #c3c2b7;background:#fff;border-radius:7px;padding:7px 14px;cursor:pointer}
@page{size:A4;margin:16mm 15mm 18mm;@bottom-left{content:"RAT Flea DevSec · Whitepaper";font:8pt system-ui;color:#898781}
  @bottom-center{content:"sudheerkumard.github.io/nervve-devsecops";font:8pt system-ui;color:#898781}
  @bottom-right{content:"Page " counter(page) " of " counter(pages);font:8pt system-ui;color:#898781}}
@page :first{margin:0;@bottom-left{content:none}@bottom-center{content:none}@bottom-right{content:none}}
@media print{body{background:#fff;font-size:10pt}.bar-print{display:none}.cover{margin:0;max-width:none;height:297mm;min-height:297mm;break-after:page}
  .page{margin:0;max-width:none;box-shadow:none;padding:0}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  tr,figure,.stats,blockquote,.keeptog{break-inside:avoid} thead{display:table-header-group} h2,h3{break-after:avoid} .contents{break-after:page}}
"""


def build():
    md = open(SRC, encoding="utf-8").read()
    body = md.split("\n---\n", 1)[1] if "\n---\n" in md else md
    body = re.sub(r"```\n Developers.*?```", "%%ARCH%%", body, flags=re.S)
    # Python-Markdown needs a blank line before a list (and before nested list items' parents)
    lines, fixed = body.split("\n"), []
    for i, ln in enumerate(lines):
        is_item = bool(re.match(r"\s*(- |\d+\. )", ln))
        prev = fixed[-1] if fixed else ""
        if is_item and prev.strip() and not re.match(r"\s*(- |\d+\. )", prev) and not prev.startswith("|"):
            fixed.append("")
        if is_item and ln.startswith("  - "):
            ln = "    " + ln[2:]                       # nested items: 4-space indent
        fixed.append(ln)
    body = "\n".join(fixed)
    html = markdown.markdown(body, extensions=["tables", "fenced_code", "sane_lists"])
    html = html.replace("<p>%%ARCH%%</p>", ARCH).replace("%%ARCH%%", ARCH)
    # Console screenshots: captioned figures, from the public screenshot set (no demo banner).
    html = re.sub(r'<p><img alt="([^"]*)" src="([^"]+)" ?/?>\s*<em>(.*?)</em></p>',
                  lambda m: f'<figure class="shot"><img alt="{m.group(1)}" src="{m.group(2).replace("/screenshots/", "/screenshots-public/")}">'
                            f'<figcaption>{m.group(3)}</figcaption></figure>', html, flags=re.S)
    html = html.replace("<h2>1. Executive summary</h2>", '<h2 class="keep">1. Executive summary</h2>', 1)
    # Citations [n] -> superscript links to the reference list; the reference list gets anchors.
    html = re.sub(r"(?<![\w`])\[(\d{1,2})\](?![(:])", r'<sup class="ref"><a href="#ref-\1">[\1]</a></sup>', html)
    html = re.sub(r"(<h2[^>]*>\d+\. References</h2>\s*)<ol>", r'\1<ol class="refs">', html)
    n = iter(range(1, 100))
    html = re.sub(r'(<ol class="refs">)(.*?)(</ol>)', lambda m: m.group(1) + re.sub(r"<li>", lambda _: f'<li id="ref-{next(n)}">', m.group(2)) + m.group(3), html, flags=re.S)
    # Wide matrices (seven or more columns) use a compact style.
    html = re.sub(r"<table>(.*?)</table>", lambda m: ('<table class="dense">' if m.group(1).split("</thead>")[0].count("<th") >= 7
                                                     else "<table>") + m.group(1) + "</table>", html, flags=re.S)
    # Keep every section heading on the same page as its first block (no stranded headings).
    first_block = r'(<div class="stats">(?:\s*<div>.*?</div>)*\s*</div>|<(p|table|ul|ol|blockquote|figure)\b.*?</\3>)'
    html = re.sub(r"(<h2\b[^>]*>.*?</h2>)\s*" + first_block, r'<div class="keeptog">\1\2</div>', html, flags=re.S)
    # Contents page from the numbered sections.
    heads = re.findall(r"<h2[^>]*>(\d+)\. (.*?)</h2>", html)
    html = re.sub(r"<h2([^>]*)>(\d+)\. ", lambda m: f'<h2{m.group(1)} id="s{m.group(2)}">{m.group(2)}. ', html)
    toc = "".join(f'<a href="#s{k}"><span>{k}</span>{re.sub("<[^>]+>", "", t)}</a>' for k, t in heads)
    first_hr = html.find("<hr")
    contents = f'<div class="contents"><div class="tochead">Contents</div><div class="toc">{toc}</div></div>'
    html = html[:first_hr] + contents + html[first_hr:] if first_hr > 0 else contents + html
    html = re.sub(r"<p><strong>RAT Flea DevSec Product designed and developed by Sudheer Kumar\.</strong>(.*?)</p>",
                  r'<div class="end"><p><strong>RAT Flea DevSec Product designed and developed by Sudheer Kumar.</strong>\1</p></div>', html, flags=re.S)
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RAT Flea DevSec · Whitepaper</title><style>{CSS}</style></head><body>
<div class="bar-print"><button onclick="window.print()">Download PDF / print</button></div>
<div class="cover"><div class="brand"><span class="mark">RF</span><div>RAT Flea DevSec<div style="font-weight:500;letter-spacing:.06em;font-size:11px;color:#9ec5f4;margin-top:2px">github.com/sudheerkumard/nervve-devsecops</div></div></div>
<div class="kind">Whitepaper · November 2026</div>
<h1>Securing the whole software delivery chain</h1>
<p class="sub">From code to cloud to runtime: one risk score, one policy, one release gate and one evidence trail that leadership, auditors and regulators can trust.</p>
<div class="foot"><span>RAT Flea DevSec Product designed and developed by <b>Sudheer Kumar</b></span><span><a href="{DOCS}" style="color:#fff">{DOCS.split('://')[1].rstrip('/')}</a> · <a href="{REPO}" style="color:#fff">{REPO.split('://')[1]}</a></span></div></div>
<div class="page">{html}</div></body></html>"""
    open(OUT, "w", encoding="utf-8").write(doc)
    return OUT


if __name__ == "__main__":
    print(build())
