#!/usr/bin/env python3
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Generate the documentation diagrams (self-contained SVG: no fonts, scripts or images are loaded).

    python scripts/docs_diagrams.py          ->  docs/assets/diagrams/*.svg

Visual language: dark canvas, rounded cards, one accent colour per concern, numbered steps, animated flow lines
(the animation stops for readers who prefer reduced motion). Icons are adapted from Feather (MIT, see
THIRD-PARTY-NOTICES.md)."""
import html
import os

OUT = os.environ.get("MYELIN_DOCS_OUT") or os.path.join(os.path.dirname(__file__), "..", "docs", "assets", "diagrams")
# Public edition (scripts/release/public_export.py): describes outcomes, not the unfiled attestation and evidence mechanisms.
PUBLIC = os.environ.get("MYELIN_DOCS_EDITION") == "public"


def T(full, public):
    return public if PUBLIC else full
BG, PANEL, PANEL2, LINE, TX, TX2, TX3 = "#0B1220", "#111A2E", "#16213A", "#26324D", "#EAF0FA", "#A9B6CF", "#6F7E9C"
C = {"teal": "#14B8A6", "blue": "#3B82F6", "violet": "#8B5CF6", "amber": "#F59E0B", "red": "#EF4444", "green": "#22C55E",
     "pink": "#EC4899", "cyan": "#06B6D4", "slate": "#64748B", "orange": "#F97316"}
FONT = "Inter, 'Segoe UI', system-ui, -apple-system, Roboto, Arial, sans-serif"
ICONS = {  # 24x24 stroke icons
    "code": '<path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/>',
    "git": '<circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="9" r="3"/><path d="M6 9v6M18 12c0 4-6 3-9 6"/>',
    "user": '<path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    "users": '<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>',
    "server": '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01M6 18h.01"/>',
    "cloud": '<path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "db": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    "key": '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
    "bolt": '<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>',
    "ticket": '<path d="M9 5H5a2 2 0 00-2 2v3a2 2 0 010 4v3a2 2 0 002 2h4M15 5h4a2 2 0 012 2v3a2 2 0 000 4v3a2 2 0 01-2 2h-4M9 5v14M15 5v14"/>',
    "chart": '<path d="M18 20V10M12 20V4M6 20v-6"/>',
    "check": '<path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/>',
    "layers": '<path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>',
    "cpu": '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
    "file": '<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8"/>',
    "refresh": '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>',
    "box": '<path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/><path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12"/>',
    "eye": '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    "alert": '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01"/>',
    "route": '<circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 000-7h-11a3.5 3.5 0 010-7H15"/><circle cx="18" cy="5" r="3"/>',
    "sparkle": '<path d="M12 3l1.9 5.8L20 11l-6.1 2.2L12 19l-1.9-5.8L4 11l6.1-2.2z"/>',
    "wrench": '<path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/>',
}


def esc(s):
    return html.escape(str(s), quote=True)


def wrap(text, width_px, size):
    per = max(4, int(width_px / (size * 0.56)))
    lines, cur = [], ""
    for w in str(text).split():
        if len(cur) + len(w) + (1 if cur else 0) > per:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


class SVG:
    def __init__(self, w, h, title, desc):
        self.w, self.h, self.title, self.desc, self.parts, self.markers = w, h, title, desc, [], set()
        self.under, self.over, self.zones_ = [], [], []          # flow lines are painted below the cards, their labels above

    def add(self, s):
        self.parts.append(s)

    def text(self, x, y, s, size=14, color=TX, weight=400, anchor="start", width=None, lh=1.3, italic=False, ls=0):
        lines = wrap(s, width, size) if width else [str(s)]
        spans = "".join(f'<tspan x="{x}" dy="{0 if i == 0 else size * lh:.1f}">{esc(t)}</tspan>' for i, t in enumerate(lines))
        st = ' font-style="italic"' if italic else ""
        sp = f' letter-spacing="{ls}"' if ls else ""
        self.add(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}" text-anchor="{anchor}"{st}{sp}>{spans}</text>')
        return len(lines)

    def icon(self, name, x, y, size=22, color=TX):
        s = size / 24
        self.add(f'<g transform="translate({x},{y}) scale({s:.3f})" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" '
                 f'stroke-linejoin="round">{ICONS[name]}</g>')

    def card(self, x, y, w, h, color, title=None, sub=None, icon=None, items=None, fill=PANEL, title_size=16, glow=True, r=14, chips=None, rpad=12):
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{color}" stroke-opacity=".55" stroke-width="1.4"'
                 + (' filter="url(#sh)"' if glow else '') + '/>')
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="4" rx="2" fill="{color}"/>')
        cy = y + 30
        tx = x + 16
        if icon:
            self.add(f'<rect x="{x + 14}" y="{y + 16}" width="34" height="34" rx="9" fill="{color}" fill-opacity=".16"/>')
            self.icon(icon, x + 20, y + 22, 22, color)
            tx = x + 58
            cy = y + 32
        if title:
            n = self.text(tx, cy, title, title_size, TX, 700, width=w - (tx - x) - rpad)
            cy += title_size * 1.3 * n
        if sub:
            n = self.text(tx, cy, sub, 12, TX2, 400, width=w - (tx - x) - 12)
            cy += 12 * 1.3 * n
        cy = max(cy, y + 62 if icon else cy) + 6
        for it in items or []:
            self.add(f'<circle cx="{x + 22}" cy="{cy - 4}" r="2.6" fill="{color}"/>')
            n = self.text(x + 32, cy, it, 12.5, TX2, 400, width=w - 44)
            cy += 12.5 * 1.35 * n + 4
        if chips:
            self.chips(x + 14, cy + 2, chips, color, w - 28)
        return cy

    def chips(self, x, y, labels, color, maxw, size=11.5):
        cx, cy = x, y
        for lab in labels:
            cw = len(lab) * size * 0.58 + 16
            if cx + cw > x + maxw:
                cx, cy = x, cy + size + 14
            self.add(f'<rect x="{cx}" y="{cy - size - 3}" width="{cw:.0f}" height="{size + 9}" rx="{(size + 9) / 2}" fill="{color}" fill-opacity=".14" '
                     f'stroke="{color}" stroke-opacity=".45"/>')
            self.text(cx + cw / 2, cy, lab, size, TX, 500, "middle")
            cx += cw + 6
        return cy

    def zone(self, x, y, w, h, label, color, dashed=True, fill_op=".05"):
        da = ' stroke-dasharray="7 6"' if dashed else ""
        self.zones_.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="18" fill="{color}" fill-opacity="{fill_op}" stroke="{color}" stroke-opacity=".6" stroke-width="1.5"{da}/>')
        lw = len(label) * (10.5 * 0.66 + 1.2) + 26
        keep = self.parts
        self.parts = self.zones_
        self.add(f'<rect x="{x + 16}" y="{y - 11}" width="{lw:.0f}" height="22" rx="11" fill="{BG}" stroke="{color}" stroke-opacity=".7"/>')
        self.text(x + 16 + lw / 2, y + 4, label.upper(), 10.5, color, 700, "middle", ls=1.2)
        self.parts = keep

    def badge(self, x, y, n, color, r=13):
        self.add(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{color}"/><circle cx="{x}" cy="{y}" r="{r + 4}" fill="none" stroke="{color}" stroke-opacity=".35" stroke-width="2"/>')
        self.text(x, y + 4.5, n, 12.5, BG, 800, "middle")

    def flow(self, d, color, label=None, lx=None, ly=None, animated=True, width=2.2, back=False, label_w=None):
        self.markers.add(color)
        mid = color.strip("#")
        cls = ' class="flow"' if animated else ""
        self.under.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-opacity=".28" stroke-width="{width + 4}" stroke-linecap="round"/>')
        self.under.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linecap="round"{cls} marker-end="url(#ar{mid})"/>')
        if label and lx is not None:
            lines = wrap(label, label_w or 200, 11)
            lw = min(label_w or 200, max(len(t) for t in lines) * 11 * 0.58) + 16
            lh = len(lines) * 14.5 + 8
            keep = self.parts
            self.parts = self.over
            self.add(f'<rect x="{lx - lw / 2:.0f}" y="{ly - 14:.0f}" width="{lw:.0f}" height="{lh:.0f}" rx="7" fill="{BG}" stroke="{color}" stroke-opacity=".55"/>')
            self.text(lx, ly, label, 11, TX, 500, "middle", width=label_w or 200, lh=1.32)
            self.parts = keep

    def render(self, light=False):
        marks = "".join(f'<marker id="ar{c.strip("#")}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                        f'<path d="M0 0L10 5L0 10z" fill="{c}"/></marker>' for c in sorted(self.markers))
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" role="img" '
                f'aria-labelledby="t d" font-family="{FONT}">'
                f'<title id="t">{esc(self.title)}</title><desc id="d">{esc(self.desc)}</desc>'
                '<style>.flow{stroke-dasharray:7 9;animation:fl 1.1s linear infinite}@keyframes fl{to{stroke-dashoffset:-32}}'
                '.pulse{animation:pu 2.4s ease-in-out infinite}@keyframes pu{50%{opacity:.45}}'
                '@media (prefers-reduced-motion:reduce){.flow,.pulse{animation:none}}</style>'
                f'<defs>{marks}<filter id="sh" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="6" stdDeviation="8" '
                'flood-color="#000" flood-opacity=".35"/></filter>'
                f'<radialGradient id="bgg" cx="20%" cy="0%" r="110%"><stop offset="0" stop-color="#14304A"/><stop offset=".55" stop-color="{BG}"/>'
                f'<stop offset="1" stop-color="#090E1A"/></radialGradient>'
                f'<linearGradient id="core" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0F2A3F"/><stop offset="1" stop-color="#151C3A"/></linearGradient>'
                '</defs>'
                f'<rect width="{self.w}" height="{self.h}" rx="22" fill="url(#bgg)"/>' + "".join(self.zones_) + "".join(self.under) + "".join(self.parts)
                + "".join(self.over) + "</svg>")

    def header(self, eyebrow, title, sub):
        self.text(48, 52, eyebrow.upper(), 12, C["teal"], 700, ls=2.2)
        self.text(48, 86, title, 28, TX, 800)
        self.text(48, 114, sub, 14.5, TX2, 400, width=self.w - 96)
        self.text(self.w - 48, 52, "RAT FLEA DEVSEC", 12, TX3, 700, "end", ls=2.2)

    def footer(self, note):
        self.text(48, self.h - 22, note, 11.5, TX3, 400)
        self.text(self.w - 48, self.h - 22, "© 2026 Sudheer Kumar · RAT Flea DevSec", 11.5, TX3, 400, "end")


# ===================================================================================== 1. platform architecture
def architecture():
    s = SVG(1680, 1110, "RAT Flea DevSec platform architecture",
            "Who uses the platform, the control plane with its engines and services, the data stores and the outbound integrations.")
    s.header("Architecture", "One platform from code to cloud to runtime",
             "Clients and sensors on top, the stateless control plane in the middle, tenant-isolated data underneath and the systems RAT Flea talks to on the right.")
    # clients row
    clients = [("Developers & AI assistants", "code", C["blue"], ["myelin CLI", "pre-commit hook", "MCP server"]),
               ("CI/CD pipelines", "git", C["violet"], ["GitHub Actions", "Azure Pipelines", "GitLab CI", "Jenkins", "Argo CD"]),
               ("Security, DevOps, leadership", "users", C["teal"], ["Web console", "reports", "AI assistant"]),
               ("Cloud accounts & clusters", "cloud", C["cyan"], ["Azure", "AWS", "Google Cloud", "Kubernetes"]),
               ("Runtime sensors", "bolt", C["pink"], ["Falco", "Tetragon"])]
    cw, gap, x0, y0 = 288, 22, 48, 150
    for i, (t, ic, col, ch) in enumerate(clients):
        x = x0 + i * (cw + gap)
        s.card(x, y0, cw, 132, col, t, None, ic, chips=ch, title_size=15)
    # edge
    s.zone(48, 330, 1584, 76, "Edge · TLS 1.2+", C["slate"], dashed=False, fill_op=".08")
    for i, (lab, ic) in enumerate([("OIDC sign-in + MFA (step-up)", "lock"), ("Hashed, expiring API keys", "key"), ("CSRF-protected sessions", "shield"),
                                   ("Rate limits · request IDs", "chart"), ("Tenant from the validated identity only", "users")]):
        x = 72 + i * 312
        s.icon(ic, x, 356, 20, C["teal"])
        s.text(x + 30, 371, lab, 13.5, TX, 600)
    for i in range(5):
        cx = x0 + i * (cw + gap) + cw / 2
        s.flow(f"M{cx} 284 L{cx} 326", clients[i][2])
    # control plane
    s.add(f'<rect x="48" y="436" width="1180" height="430" rx="20" fill="url(#core)" stroke="{C["teal"]}" stroke-opacity=".7" stroke-width="1.6" filter="url(#sh)"/>')
    s.text(72, 470, "CONTROL PLANE · STATELESS API (FastAPI) + DURABLE WORKER", 11.5, C["teal"], 700, ls=1.6)
    mods = [("Ingest & normalise", "layers", C["blue"], "Scans, imports, SBOMs, inventories and runtime events become one finding schema; fingerprints de-duplicate."),
            ("Risk score & SSVC", "chart", C["amber"], "CVSS, EPSS, KEV, reachability, exposure, runtime and attack paths, weighted by business criticality."),
            ("Policy & gates", "shield", C["violet"], "Versioned policy as code, approval workflow, commit-bound CI/CD gate that fails closed."),
            ("Triage & remediation", "wrench", C["green"], "Assessments, time-boxed exceptions, campaigns, AutoFix pull requests, tickets."),
            ("Cloud analysis", "route", C["cyan"], "Cloud, Kubernetes and identity rules, code-to-cloud links, attack paths across accounts."),
            ("Reports & evidence", "file", C["teal"], "Corporate reports, VEX, SBOM / CBOM, retained evidence, hash-chained audit."),
            ("AI assistant", "sparkle", C["pink"], "Explain, triage, ask and brief; built-in knowledge offline or the tenant's own model."),
            ("Advisory worker", "refresh", C["orange"], "OSV, NVD, GHSA, KEV, EPSS sync with leases and retries; offline exports for air-gapped sites.")]
    mw, mh = 272, 150
    for i, (t, ic, col, d) in enumerate(mods):
        x, y = 72 + (i % 4) * (mw + 14), 490 + (i // 4) * (mh + 14)
        s.card(x, y, mw, mh, col, t, None, ic, fill=PANEL2, glow=False, title_size=14.5)
        s.text(x + 16, y + 80, d, 12, TX2, width=mw - 30)
    s.text(72, 840, "ENGINES", 11, TX3, 700, ls=1.6)
    s.chips(146, 844, ["SAST", "SCA", "Secrets", "IaC", "Containers", "CI posture", "CD posture", "Licences", "AI-BOM", "Supply chain",
                       "DAST", "CSPM", "KSPM", "CIEM", "Runtime", "Attack paths"], C["teal"], 1060, 11)
    s.flow("M638 406 L638 432", C["teal"])
    # integrations column
    s.zone(1262, 436, 370, 430, "Outbound integrations", C["violet"])
    ints = [("Source platforms", "git", "Pull requests (AutoFix) · read-only fetch", C["violet"]),
            ("Ticketing & ChatOps", "ticket", "Jira · ServiceNow · Azure Boards · Teams / Slack", C["green"]),
            ("SIEM", "eye", "Audit and gate events (JSON lines / CSV)", C["amber"]),
            ("Threat intelligence", "globe", "OSV · NVD · GHSA · CISA KEV · FIRST EPSS", C["orange"]),
            ("Your AI model (optional)", "sparkle", "Anthropic · OpenAI · Azure OpenAI · private", C["pink"])]
    for i, (t, ic, d, col) in enumerate(ints):
        y = 462 + i * 79
        s.add(f'<rect x="1282" y="{y}" width="330" height="72" rx="12" fill="{PANEL}" stroke="{col}" stroke-opacity=".45"/>')
        s.icon(ic, 1296, y + 12, 20, col)
        s.text(1326, y + 27, t, 13.5, TX, 700)
        s.text(1296, y + 50, d, 11.5, TX2, width=318, lh=1.25)
    s.flow("M1228 650 L1258 650", C["violet"])
    # data row
    s.zone(48, 900, 1584, 170, "Data · encrypted, tenant-isolated", C["amber"], dashed=False, fill_op=".06")
    stores = [("PostgreSQL 16", "db", "Forced row-level security on every tenant table; the app role cannot bypass it.", C["amber"]),
              ("Vault / OpenBao", "key", "Source, ticketing, cloud and test-identity credentials; the database keeps only references.", C["red"]),
              ("Evidence store", "lock", "Reports, exports and audit evidence kept for the retention period.", C["teal"]),
              ("Identity provider", "users", "Keycloak bundled, or Entra ID, Okta and SAML IdPs; MFA policy and groups.", C["blue"])]
    for i, (t, ic, d, col) in enumerate(stores):
        x = 72 + i * 392
        s.card(x, 930, 372, 118, col, t, None, ic, fill=PANEL2, glow=False, title_size=15)
        s.text(x + 16, 1000, d, 12, TX2, width=340)
    s.flow("M638 866 L638 896", C["amber"])
    s.footer("Source code stays in the customer's runner: only findings, SBOMs and metadata are uploaded.")
    return s


# ===================================================================================== 2. end-to-end data flow
def data_flow():
    s = SVG(1720, 990, "RAT Flea DevSec end-to-end data flow",
            "Eight numbered stages from a code change to proof for auditors, with the cloud and runtime lane joining at enrichment.")
    s.header("Data flow", "From a code change to proof, in eight steps",
             "Every number is a stage the data passes through. The cloud and runtime lane joins at step 4, so risk is judged with the context of where the code runs.")
    stages = [("1", "Change", "code", C["blue"], ["Commit or pull request", "Pre-commit hook and AI assistant (MCP) check first"]),
              ("2", "Scan in the runner", "cpu", C["violet"], ["15 engines + your scanners", "Source code never leaves the runner"]),
              ("3", "Ingest", "layers", C["cyan"], ["One finding schema", "Fingerprints de-duplicate across engines"]),
              ("4", "Enrich & score", "chart", C["amber"], ["EPSS, KEV, reachability, exposure", "RAT Flea Risk Score + CISA SSVC"]),
              ("5", "Decide", "shield", C["red"], ["Policy gate: pass / warn / block", "Deployment allowed or stopped"]),
              ("6", "Act", "wrench", C["green"], ["Tickets routed to the owner", "AutoFix pull requests, campaigns"]),
              ("7", "Verify", "refresh", C["teal"], ["Re-scan closes what is fixed", "Regressions reopen automatically"]),
              ("8", "Prove", "file", C["pink"], ["Reports, VEX, SBOM / CBOM", "Evidence + hash-chained audit"])]
    w, h, gx, y = 186, 196, 21, 196
    for i, (n, t, ic, col, items) in enumerate(stages):
        x = 48 + i * (w + gx)
        s.card(x, y, w, h, col, t, None, ic, items=items, title_size=14.5, rpad=44)
        s.badge(x + w - 22, y + 24, n, col)
        if i < 7:
            s.flow(f"M{x + w + 2} {y + 98} L{x + w + gx - 2} {y + 98}", col)
    # data labels under the main lane
    labels = [(1, "findings + SBOM, JSON over TLS, API key", C["violet"]), (3, "normalised, fingerprinted findings", C["cyan"]),
              (4, "gate decision", C["red"]), (6, "status changes, tickets resolved", C["teal"])]
    for i, lab, col in labels:
        x = 48 + i * (w + gx) + w + gx / 2
        s.add(f'<line x1="{x}" y1="{y + 110}" x2="{x}" y2="{y + 236}" stroke="{col}" stroke-opacity=".5" stroke-dasharray="3 4"/>')
        s.flow(f"M{x} {y + 236} L{x} {y + 237}", col, lab, min(x, s.w - 140), y + 262, animated=False, label_w=170)
    # feedback loop 7 -> 1
    x1, x7 = 48 + w / 2, 48 + 6 * (w + gx) + w / 2
    s.flow(f"M{x7} {y - 6} C {x7} {y - 46}, {x1} {y - 46}, {x1} {y - 6}", C["teal"], "next change starts from a cleaner baseline", (x1 + x7) / 2, y - 40, label_w=320)
    # cloud & runtime lane
    ly = 560
    s.zone(48, ly, 1624, 300, "Cloud & runtime lane", C["cyan"])
    lane = [("Read-only collectors", "cloud", C["cyan"], "Azure Resource Graph · AWS APIs · Google Cloud Asset Inventory · Kubernetes API · or an uploaded inventory"),
            ("Normalised inventory", "box", C["blue"], "Resources, identities and grants in one shape. Configuration only; never data, never Kubernetes Secrets"),
            ("Posture & identity rules", "check", C["violet"], "67 cloud · 25 Kubernetes · 14 identity checks, each with its CIS section"),
            ("Code to cloud + attack paths", "route", C["red"], "Exposure + weakness + privilege or data, linked to the repository by IaC tags, annotations or the image")]
    lw = 370
    for i, (t, ic, col, d) in enumerate(lane):
        x = 72 + i * (lw + 26)
        s.card(x, ly + 34, lw, 126, col, t, None, ic, title_size=14.5)
        s.text(x + 16, ly + 104, d, 12, TX2, width=lw - 30)
        if i < 3:
            s.flow(f"M{x + lw + 2} {ly + 96} L{x + lw + 24} {ly + 96}", col)
    rx = 72
    s.card(rx, ly + 182, 760, 100, C["pink"], "Runtime sensors → grouped detections", None, "bolt", title_size=14.5)
    s.text(rx + 16, ly + 252, "Falco and Tetragon events are redacted, grouped per workload, image and rule, and mapped to MITRE ATT&CK.", 12, TX2, width=720)
    s.flow(f"M{rx + 762} {ly + 232} C {rx + 1000} {ly + 232}, {72 + 3 * 396 + 40} {ly + 232}, {72 + 3 * 396 + 60} {ly + 162}", C["pink"], "runtime detections",
           rx + 990, ly + 240, label_w=160)
    # join to step 4
    x4 = 48 + 3 * (w + gx) + w / 2
    ax = 72 + 3 * 396 + 185
    s.flow(f"M{ax} {ly + 32} L{ax} {ly - 36} Q {ax} {ly - 50} {ax - 14} {ly - 50} L{x4 + 14} {ly - 50} Q {x4} {ly - 50} {x4} {ly - 64} L{x4} {y + h + 4}", C["red"],
           "cloud findings + attack paths join the queue at step 4", (x4 + ax) / 2, ly - 46, label_w=420)
    # bottom guarantees
    g = [("lock", "TLS everywhere; credentials only in the vault"), ("users", "Every row carries its tenant; PostgreSQL enforces isolation"),
         ("eye", "Secrets and tokens redacted before storage"), ("shield", "Every decision audited in a hash chain")]
    for i, (ic, t) in enumerate(g):
        x = 60 + i * 410
        s.icon(ic, x, 900, 20, C["teal"])
        s.text(x + 30, 915, t, 13, TX, 600, width=370)
    s.footer("Numbers match the step-by-step walkthrough on the Data flow page.")
    return s


# ===================================================================================== 3. trust boundaries
def trust_boundaries():
    s = SVG(1900, 1000, "Trust boundaries and protected data flows",
            "Zones the data crosses and the control applied at each crossing.")
    s.header("Security", "Trust boundaries and the control on every crossing",
             "Each arrow crosses a boundary; its letter matches the table on the Security architecture page, and the label names what is sent.")
    s.zone(40, 160, 320, 760, "Customer network", C["blue"])
    s.zone(500, 160, 760, 760, "RAT Flea DevSec namespace", C["teal"])
    s.zone(1420, 160, 440, 330, "Customer cloud & clusters", C["cyan"])
    s.zone(1420, 530, 440, 390, "Third-party services", C["violet"])
    left = [("Developer workstation", "code", "CLI, pre-commit, MCP"), ("CI runner", "git", "myelin scan · myelin gate"), ("Browser", "user", "console"),
            ("Runtime sensor", "bolt", "Falco / Tetragon in your cluster")]
    ys = [210, 380, 550, 720]
    for (t, ic, sub), y in zip(left, ys):
        s.card(66, y, 268, 116, C["blue"], t, sub, ic, title_size=15)
    s.card(528, 200, 196, 690, C["teal"], "Edge / ingress", None, "lock", title_size=15,
           items=["TLS 1.2+ termination", "OIDC sign-in, MFA step-up", "API keys hashed and expiring", "CSRF on cookie sessions", "request size limits", "tenant from the identity only"])
    s.card(752, 200, 480, 136, C["teal"], "API (stateless)", "RBAC on every route · SSRF guard on every outbound call · secrets redacted", "server", title_size=15)
    data = [("PostgreSQL", "db", "forced RLS per tenant"), ("Vault", "key", "credential references"), ("Evidence", "lock", "retained, audited")]
    for i, (t, ic, sub) in enumerate(data):
        s.card(752 + i * 164, 380, 152, 128, C["amber"], t, sub, ic, title_size=14)
        s.flow(f"M{828 + i * 164} 338 L{828 + i * 164} 376", C["amber"])
    s.card(752, 540, 480, 104, C["orange"], "Advisory & collection worker", "leases, retries, tenant allowlists", "refresh", title_size=15)
    s.card(752, 676, 480, 214, C["slate"], "Never enters the platform", None, "eye", title_size=15, glow=False,
           items=["source code (scans run in your runner)", "secret values found by scanners (redacted)", "data inside buckets, databases and Kubernetes Secrets",
                  "tokens in runtime command lines (redacted)"])
    clouds = [("Azure · AWS · Google Cloud", "cloud", "read-only roles · AWS ExternalId"), ("Kubernetes API", "box", "get/list ClusterRole · no Secrets")]
    for i, (t, ic, sub) in enumerate(clouds):
        s.card(1446, 206 + i * 140, 388, 112, C["cyan"], t, sub, ic, title_size=15)
    tp = [("Identity provider", "users", "OIDC + PKCE · MFA policy"), ("Source & ticketing", "ticket", "scoped tokens from the vault"),
          ("Intelligence feeds", "globe", "public data; no tenant data sent")]
    for i, (t, ic, sub) in enumerate(tp):
        s.card(1446, 574 + i * 112, 388, 92, C["violet"], t, sub, ic, title_size=14.5)
    for (lab, col), y in zip([("A · findings + SBOM over TLS, API key", C["blue"]), ("B · gate decision for one commit", C["blue"]),
                              ("C · console session + CSRF token", C["blue"]), ("D · runtime events, API key", C["pink"])], ys):
        s.flow(f"M336 {y + 58} L524 {y + 58}", col, lab, 430, y + 36, label_w=168)
    s.flow("M726 268 L748 268", C["teal"])
    s.flow("M1416 262 L1236 262", C["cyan"], "E · configuration only, read-only", 1326, 214, label_w=160, back=True)
    s.flow("M1236 592 C 1330 592, 1330 402, 1442 402", C["cyan"])
    s.flow("M1442 620 C 1330 620, 1330 300, 1236 300", C["violet"], "F · ID token (PKCE)", 1326, 470, label_w=150)
    s.flow("M1236 610 C 1330 610, 1330 732, 1442 732", C["violet"], "G · tickets and PRs, vault-held token", 1326, 700, label_w=150)
    s.flow("M1236 630 C 1300 630, 1300 844, 1442 844", C["orange"], "H · advisory download", 1326, 820, label_w=150)
    s.footer("Letters A–H are explained in the table on the Security architecture page.")
    return s


# ===================================================================================== 4. finding lifecycle
def lifecycle():
    s = SVG(1600, 760, "Finding lifecycle", "States a finding moves through and what moves it.")
    s.header("Lifecycle", "The life of a finding",
             "Scans open and close findings automatically; people decide on exceptions; nothing is closed by an outside document alone.")
    L, M, R, T, B = 240, 800, 1360, 270, 520
    st = [(L, T, C["blue"], "New in a scan", "fingerprint not seen before"), (M, T, C["red"], "Open", "reported by the latest scan of the engine that found it"),
          (R, T, C["green"], "Fixed", "the engine ran again and no longer reports it"), (L, B, C["slate"], "False positive", "with the analyst's reason; audited"),
          (M, B, C["amber"], "Risk accepted", "time-boxed, approved by a second person"),
          (R, B, C["violet"], "Not affected (VEX)", "only after an analyst applies the statement")]
    for x, y, col, t, sub in st:
        s.card(x - 160, y - 62, 320, 124, col, t, sub, None, title_size=17)
    fl = [(f"M{L + 162} {T} L{M - 166} {T}", C["blue"], "triage queue, ticket, SLA", (L + M) / 2, T - 26),
          (f"M{M + 162} {T - 20} L{R - 166} {T - 20}", C["green"], "re-scan: gone", (M + R) / 2, T - 46),
          (f"M{R - 162} {T + 22} L{M + 166} {T + 22}", C["red"], "regression: back again", (M + R) / 2, T + 52),
          (f"M{M + 30} {T + 64} L{M + 30} {B - 68}", C["amber"], "exception approved", M + 120, (T + B) / 2 - 8),
          (f"M{M - 30} {B - 64} L{M - 30} {T + 68}", C["red"], "expiry date passes", M - 120, (T + B) / 2 - 8),
          (f"M{M - 120} {T + 64} L{L + 60} {B - 66}", C["slate"], "analyst: false positive", (M + L) / 2 - 20, (T + B) / 2 + 20),
          (f"M{M + 120} {T + 64} L{R - 60} {B - 66}", C["violet"], "VEX reviewed + applied", (M + R) / 2 + 20, (T + B) / 2 + 20)]
    for d, col, lab, lx, ly in fl:
        s.flow(d, col, lab, lx, ly, label_w=200)
    s.card(80, 630, 1440, 64, C["teal"], None, None, None, glow=False)
    s.text(104, 668, "Every transition is written to the hash-chained audit log with actor and reason, and synced to the linked ticket.", 14, TX, 600)
    return s


# ===================================================================================== 5. cloud & runtime analysis
def cnapp():
    s = SVG(1680, 900, "Cloud and runtime analysis", "Collectors, normalised inventory, rule engines, code-to-cloud graph and attack paths.")
    s.header("Cloud & runtime", "How cloud, cluster and runtime data become attack paths",
             "Four sources feed one inventory; rules produce posture and identity findings; the graph joins them with code findings and runtime detections.")
    src = [("Azure", "Resource Graph + role assignments", C["blue"]), ("AWS", "read-only APIs + IAM details", C["orange"]),
           ("Google Cloud", "Cloud Asset Inventory + IAM", C["green"]), ("Kubernetes", "API server, no Secrets", C["cyan"]),
           ("Uploaded inventory", "air-gapped sites, native exports", C["slate"])]
    for i, (t, d, col) in enumerate(src):
        y = 170 + i * 118
        s.card(48, y, 300, 100, col, t, d, "cloud" if i < 3 else "box" if i == 3 else "file", title_size=15)
        s.flow(f"M350 {y + 50} C 410 {y + 50}, 410 470, 446 470", col)
    s.card(450, 360, 300, 220, C["blue"], "Normalised inventory", None, "layers", title_size=15,
           items=["resources with configuration", "identities and their grants", "tags and annotations for code links", "latest per account or cluster"])
    rules = [("Cloud posture", "67 checks · CIS sections", C["violet"]), ("Kubernetes posture", "25 checks · Pod Security, RBAC", C["cyan"]),
             ("Identities", "14 checks · effective privilege", C["amber"])]
    for i, (t, d, col) in enumerate(rules):
        y = 210 + i * 150
        s.card(830, y, 300, 120, col, t, d, "check", title_size=15)
        s.flow(f"M752 470 C 790 470, 790 {y + 60}, 826 {y + 60}", col)
        s.flow(f"M1132 {y + 60} C 1170 {y + 60}, 1170 470, 1206 470", col)
    s.card(1210, 330, 420, 280, C["red"], "Graph: code to cloud + attack paths", None, "route", title_size=15,
           items=["joins code findings (SCA, SAST, secrets, images)", "joins runtime detections per workload",
                  "exposure + weakness + privileged identity or data", "stored as findings: ranked, ticketed, gated, closed when a link breaks"])
    s.card(830, 700, 520, 110, C["pink"], "Runtime sensors", "Falco and Tetragon → redacted, grouped, MITRE ATT&CK", "bolt", title_size=15)
    s.flow("M1352 755 C 1420 755, 1420 640, 1420 614", C["pink"], "detections", 1460, 700, label_w=110)
    s.card(1210, 170, 420, 110, C["teal"], "Code findings", "repositories, images, pipelines", "code", title_size=15)
    s.flow("M1420 282 L1420 326", C["teal"])
    s.footer("Collectors read configuration with least-privilege, read-only credentials held in the vault.")
    return s


# ===================================================================================== 6. attack path example
def attack_path():
    s = SVG(1680, 520, "Example attack path", "Internet to Kubernetes Secrets through an exploitable, attacked workload.")
    s.header("Attack path", "One finding that tells the whole story",
             "Each link is evidence from a different engine. Breaking any one of them closes the path.")
    steps = [("Internet", "globe", C["slate"], "anyone"), ("Public LoadBalancer", "alert", C["amber"], "service payments-web"),
             ("Workload", "box", C["blue"], "payments-web · image from the payments-web repository"),
             ("Weakness", "alert", C["red"], "Log4Shell (CVE-2021-44228), known exploited"),
             ("Runtime", "bolt", C["pink"], "shell spawned in the container"), ("Identity", "key", C["orange"], "service account can read Secrets"),
             ("Data", "db", C["violet"], "Kubernetes Secrets, all namespaces")]
    w, gx = 206, 22
    for i, (t, ic, col, d) in enumerate(steps):
        x = 48 + i * (w + gx)
        s.card(x, 170, w, 180, col, t, None, ic, title_size=15)
        s.text(x + 16, 248, d, 12.5, TX2, width=w - 30)
        if i < len(steps) - 1:
            s.flow(f"M{x + w + 2} 260 L{x + w + gx - 2} 260", col)
    fixes = [(2, "Restrict the service to known ranges", C["amber"]), (3, "Upgrade log4j-core (AutoFix PR)", C["red"]), (6, "Remove the Secret-reading binding", C["orange"])]
    for i, t, col in fixes:
        x = 48 + (i - 1 if i == 2 else i if i == 3 else 5) * (w + gx) + w / 2
        s.add(f'<line x1="{x}" y1="352" x2="{x}" y2="392" stroke="{col}" stroke-dasharray="3 4"/>')
        s.add(f'<rect x="{x - 120}" y="392" width="240" height="44" rx="10" fill="{col}" fill-opacity=".14" stroke="{col}"/>')
        s.text(x, 419, "✓ " + t, 12.5, TX, 600, "middle")
    s.footer("Example from the demo tenant (fictional). Score 100, SSVC decision Act.")
    return s


# ===================================================================================== 7. risk score
def risk_score():
    s = SVG(1600, 720, "RAT Flea Risk Score", "Components of the risk score and the priority bands they produce.")
    s.header("Prioritisation", "What the RAT Flea Risk Score is made of",
             "Points add up to at most 100, then business criticality weights the result. The score sets the priority and the fix-by date.")
    parts = [("Impact", "CVSS × 4", 40, C["blue"]), ("Exploit likelihood", "EPSS × 25", 25, C["violet"]), ("Known exploited", "CISA KEV", 15, C["red"]),
             ("Exposure", "internet / internal", 10, C["amber"]), ("Reachable", "first-party code path", 10, C["teal"]), ("Live secret", "provider confirmed", 25, C["orange"]),
             ("Malicious release", "indicator / OSV MAL", 30, C["pink"]), ("Runtime attack", "critical / high detection", 15, C["pink"]), ("Attack path", "exposure + weakness + impact", 20, C["red"])]
    x, y, scale = 48, 200, 3.6
    for i, (t, d, pts, col) in enumerate(parts):
        bw = pts * scale
        yy = y + i * 46
        s.text(x, yy + 22, t, 14, TX, 700)
        s.text(x + 200, yy + 22, d, 12, TX2)
        s.add(f'<rect x="{x + 420}" y="{yy + 6}" width="{bw:.0f}" height="26" rx="7" fill="{col}"/>')
        s.text(x + 428 + bw, yy + 25, f"+{pts}", 13, TX, 700)
    s.text(x, y + 9 * 46 + 22, "× 0.45 when the vulnerable code is proven unreachable  ·  × (0.8 + 0.2 × criticality) for the asset", 13, TX2, width=960)
    bands = [("P0", "80–100", "2 days", C["red"]), ("P1", "60–79", "7 days", C["orange"]), ("P2", "35–59", "30 days", C["amber"]), ("P3", "0–34", "90 days", C["green"])]
    for i, (p, r, sla, col) in enumerate(bands):
        yy = 200 + i * 104
        s.card(1060, yy, 492, 88, col, None, None, None, glow=False)
        s.text(1086, yy + 56, p, 34, col, 800)
        s.text(1170, yy + 40, f"score {r}", 15, TX, 700)
        s.text(1170, yy + 64, f"fix within {sla}", 13, TX2)
    s.footer("Every component is shown in the finding drawer, so an analyst can see and challenge the score.")
    return s


# ===================================================================================== 8. integrations map
def integrations():
    s = SVG(1600, 960, "Integrations map", "Systems RAT Flea DevSec connects to, grouped by purpose.")
    s.header("Integrations", "Fits the tools you already run",
             "Inbound sources on the left, where results go on the right. Every credential is held in your vault.")
    cx, cy = 800, 540
    s.add(f'<circle cx="{cx}" cy="{cy}" r="118" fill="url(#core)" stroke="{C["teal"]}" stroke-width="2" filter="url(#sh)"/>')
    s.add(f'<circle cx="{cx}" cy="{cy}" r="138" fill="none" stroke="{C["teal"]}" stroke-opacity=".3" stroke-width="2" class="pulse"/>')
    s.icon("shield", cx - 20, cy - 58, 40, C["teal"])
    s.text(cx, cy + 10, "RAT Flea DevSec", 22, TX, 800, "middle")
    s.text(cx, cy + 34, "one finding queue", 13, TX2, 400, "middle")
    left = [("Source & CI", "git", C["violet"], ["GitHub", "GitLab", "Azure DevOps", "Bitbucket", "Jenkins", "CodeCommit"]),
            ("Clouds & clusters", "cloud", C["cyan"], ["Azure", "AWS", "Google Cloud", "Kubernetes", "Kyverno"]),
            ("Runtime sensors", "bolt", C["pink"], ["Falco", "Tetragon"]),
            ("Your scanners", "cpu", C["blue"], ["SARIF", "CycloneDX", "Trivy", "Grype", "Semgrep", "Gitleaks", "Checkov", "ZAP"])]
    right = [("Work management", "ticket", C["green"], ["Jira", "ServiceNow", "Azure Boards", "Teams", "Slack"]),
             ("SIEM", "eye", C["amber"], ["Sentinel", "Splunk", "Wazuh", "Elastic"]),
             ("Identity", "users", C["blue"], ["Keycloak", "Entra ID", "Okta", "SAML via Keycloak"]),
             ("Intelligence", "globe", C["orange"], ["OSV", "NVD", "GHSA", "CISA KEV", "EPSS"])]
    for side, items in ((0, left), (1, right)):
        for i, (t, ic, col, chips) in enumerate(items):
            x = 48 if side == 0 else 1172
            y = 160 + i * 190
            s.card(x, y, 380, 160, col, t, None, ic, chips=chips, title_size=16)
            if side == 0:
                s.flow(f"M430 {y + 80} C 560 {y + 80}, 600 {cy}, {cx - 140} {cy}", col)
            else:
                s.flow(f"M{cx + 140} {cy} C 1000 {cy}, 1040 {y + 80}, 1168 {y + 80}", col)
    s.footer("Product names are trademarks of their owners; listed to identify compatible products.")
    return s


# ===================================================================================== 9. data model
def data_model():
    s = SVG(1680, 1020, "Data model", "Main entities, their key fields and relationships. Every entity belongs to one tenant.")
    s.header("Data model", "What RAT Flea DevSec stores",
             "Every table below carries tenant_id and is protected by PostgreSQL forced row-level security.")
    ent = {
        "tenant": (720, 150, C["teal"], "Tenant", ["id · slug · name", "plan · region · settings"]),
        "repo": (90, 330, C["blue"], "Repository", ["name · business unit", "criticality · project"]),
        "scan": (90, 530, C["blue"], "Scan", ["repo · commit · decision", "engines that ran · SBOM"]),
        "finding": (520, 450, C["red"], "Finding", ["fingerprint (unique)", "engine · rule · severity", "risk score · priority · SLA", "status · triage · ticket", "data: location, evidence, SSVC"]),
        "policy": (90, 730, C["violet"], "Policy", ["versions (immutable)", "approvals · bindings", "exceptions (time-boxed)"]),
        "audit": (520, 790, C["amber"], "Audit event", ["actor · event · detail", "prev_hash → hash"]),
        "evidence": (950, 790, C["amber"], "Evidence", ["sha256 · storage URI", "reviews · retention"]),
        "cloud": (1330, 330, C["cyan"], "Cloud account", ["provider · scope", "credential reference"]),
        "inv": (1330, 530, C["cyan"], "Cloud inventory", ["key (account / cluster)", "resources · identities · grants"]),
        "rt": (1330, 730, C["pink"], "Runtime event", ["cluster · workload · rule", "severity · tactics · time"]),
        "integ": (950, 330, C["green"], "Integrations", ["repo sources · ticketing", "connectors · DAST targets"]),
        "users": (1080, 150, C["slate"], "Users & API keys", ["identity binding · roles", "hashed, expiring keys"]),
    }
    for k, (x, y, col, t, fields) in ent.items():
        h = 52 + len(fields) * 20
        s.add(f'<rect x="{x}" y="{y}" width="290" height="{h}" rx="12" fill="{PANEL}" stroke="{col}" stroke-opacity=".7" stroke-width="1.4" filter="url(#sh)"/>')
        s.add(f'<rect x="{x}" y="{y}" width="290" height="36" rx="12" fill="{col}" fill-opacity=".22"/>')
        s.text(x + 16, y + 24, t, 15, TX, 700)
        for i, fl in enumerate(fields):
            s.text(x + 16, y + 58 + i * 20, fl, 12.5, TX2)
    rel = [("M720 190 C 400 190, 235 230, 235 326", C["blue"], "1 : n"), ("M235 418 L235 526", C["blue"], "1 : n"),
           ("M382 590 L516 560", C["red"], "scan reports"), ("M235 374 C 420 374, 520 420, 560 446", C["red"], "repo has"),
           ("M865 210 L865 446", C["teal"], "tenant owns all"), ("M665 640 L665 786", C["amber"], "every change"),
           ("M1475 418 L1475 526", C["cyan"], "collected into"), ("M1326 590 L812 520", C["cyan"], "cloud findings"),
           ("M1326 780 L812 580", C["pink"], "runtime findings"), ("M1010 330 L812 480", C["green"], "tickets · PRs"),
           ("M382 790 L516 610", C["violet"], "gates evaluate")]
    for d, col, lab in rel:
        s.flow(d, col, animated=False, width=1.6)
    s.footer("Credentials are never stored in these tables: they live in the vault and are referenced by path.")
    return s


ALL = {"architecture": architecture, "data-flow": data_flow, "trust-boundaries": trust_boundaries, "finding-lifecycle": lifecycle,
       "cloud-runtime": cnapp, "attack-path": attack_path, "risk-score": risk_score, "integrations": integrations, "data-model": data_model}


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, fn in ALL.items():
        with open(os.path.join(OUT, f"{name}.svg"), "w", encoding="utf-8") as fh:
            fh.write(fn().render())
        print("wrote", os.path.join(OUT, f"{name}.svg"))


if __name__ == "__main__":
    main()
