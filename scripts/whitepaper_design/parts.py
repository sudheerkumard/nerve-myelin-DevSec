"""Building blocks for the designed NERvvE DevSecOps whitepaper: styles, icons, charts and cover art.

Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only.
All artwork, icons and charts are drawn here from simple shapes; no third-party images or icon sets are used.
"""
import math
import random

DOCS = "https://sudheerkumard.github.io/nerve-myelin-DevSec/"
REPO = "https://github.com/sudheerkumard/nerve-myelin-DevSec"

NAVY, DEEP, BLUE, SKY, ORANGE, INK, INK2, LINE, SURF = (
    "#0b1f3a", "#071427", "#2a78d6", "#9ec5f4", "#eb6834", "#0b1220", "#4a5a72", "#dfe5ee", "#f4f7fb")

CSS = f"""
@page {{ size: A4; margin: 0; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{ background: #6b7686; }}
body {{ font-family: Inter, "DejaVu Sans", sans-serif; color: {INK}; font-size: 9.6pt; line-height: 1.5;
  -webkit-print-color-adjust: exact; print-color-adjust: exact; font-feature-settings: "ss01", "cv11"; }}
.page {{ width: 210mm; height: 297mm; position: relative; overflow: hidden; background: #fff; margin: 0 auto 8mm;
  break-after: page; page-break-after: always; }}
@media print {{ .page {{ margin: 0; }} html, body {{ background: #fff; }} }}
.inner {{ position: absolute; left: 16mm; right: 16mm; top: 22mm; bottom: 20mm; }}
.dark {{ background: radial-gradient(120% 90% at 85% 10%, #13508c 0%, {NAVY} 45%, {DEEP} 100%); color: #fff; }}
.dark p, .dark li {{ color: #cfdcee; }}
h1, h2, h3, .disp {{ font-family: "Inter Display", Inter, sans-serif; letter-spacing: -0.01em; }}
.run-head {{ position: absolute; top: 9mm; left: 16mm; right: 16mm; display: flex; justify-content: space-between;
  font-size: 7.2pt; letter-spacing: .12em; text-transform: uppercase; color: {INK2}; border-bottom: 1px solid {LINE};
  padding-bottom: 2.2mm; }}
.run-head b {{ color: {NAVY}; font-weight: 700; }}
.dark .run-head {{ color: {SKY}; border-color: rgba(255,255,255,.18); }} .dark .run-head b {{ color: #fff; }}
.run-foot {{ position: absolute; bottom: 8mm; left: 16mm; right: 16mm; display: flex; justify-content: space-between;
  font-size: 7pt; color: #8a96a8; }}
.dark .run-foot {{ color: #8fa6c6; }}
.kicker {{ font-size: 7.6pt; font-weight: 700; letter-spacing: .2em; text-transform: uppercase; color: {BLUE}; }}
.dark .kicker {{ color: {SKY}; }}
.chap {{ display: flex; align-items: baseline; gap: 4mm; margin: 1mm 0 3mm; }}
.chap .num {{ font-family: "Inter Display"; font-weight: 800; font-size: 34pt; color: {BLUE}; line-height: 1; }}
.chap h2 {{ font-size: 23pt; line-height: 1.12; font-weight: 750; color: {NAVY}; }}
.dark .chap h2 {{ color: #fff; }} .dark .chap .num {{ color: {SKY}; }}
.lede {{ font-size: 11.2pt; line-height: 1.5; color: {INK2}; max-width: 158mm; }}
.dark .lede {{ color: #cfdcee; }}
h3 {{ font-size: 12pt; color: {NAVY}; font-weight: 700; margin: 0 0 1.6mm; }}
.dark h3 {{ color: #fff; }}
p {{ margin: 0 0 2.4mm; color: #253247; }}
.cols {{ display: grid; gap: 7mm; }} .c2 {{ grid-template-columns: 1fr 1fr; }} .c3 {{ grid-template-columns: repeat(3, 1fr); }}
.c4 {{ grid-template-columns: repeat(4, 1fr); }} .c5 {{ grid-template-columns: repeat(5, 1fr); }}
.card {{ background: {SURF}; border: 1px solid {LINE}; border-radius: 3mm; padding: 4.2mm 4.4mm; }}
.card h4 {{ font-family: "Inter Display"; font-size: 10.4pt; color: {NAVY}; margin-bottom: 1.2mm; font-weight: 700; }}
.card p {{ font-size: 8.6pt; line-height: 1.45; margin: 0; color: {INK2}; }}
.dark .card {{ background: rgba(255,255,255,.06); border-color: rgba(255,255,255,.14); }}
.dark .card h4 {{ color: #fff; }} .dark .card p {{ color: #b9c9df; }}
.ico {{ width: 9mm; height: 9mm; border-radius: 2.4mm; background: #e6f0fc; display: grid; place-items: center; margin-bottom: 2.4mm; }}
.ico svg {{ width: 5.4mm; height: 5.4mm; }}
.dark .ico {{ background: rgba(158,197,244,.16); }}
.band {{ background: {NAVY}; color: #fff; border-radius: 3.2mm; padding: 5mm 6mm; display: grid; gap: 5mm; }}
.stat b {{ display: block; font-family: "Inter Display"; font-weight: 800; font-size: 25pt; line-height: 1; color: #fff; }}
.stat span {{ display: block; font-size: 8pt; line-height: 1.38; color: #b9cde8; margin-top: 2mm; }}
.stat i {{ font-style: normal; color: {SKY}; font-size: 6.8pt; }}
.quote {{ font-family: "Inter Display"; font-size: 17pt; line-height: 1.28; font-weight: 600; color: {NAVY};
  border-left: 1.6mm solid {ORANGE}; padding: 1mm 0 1mm 6mm; }}
.dark .quote {{ color: #fff; }}
.src {{ font-size: 6.8pt; color: #8a96a8; line-height: 1.4; }}
.dark .src {{ color: #8fa6c6; }}
.chip {{ display: inline-block; font-size: 7.4pt; font-weight: 700; padding: .8mm 2.4mm; border-radius: 10mm; background: #e6f0fc; color: {NAVY}; }}
figure.shot img {{ width: 100%; display: block; border-radius: 2.4mm; border: 1px solid #cfd8e5; box-shadow: 0 2mm 6mm rgba(11,31,58,.14); }}
figure.shot figcaption, .cap {{ font-size: 7.8pt; color: {INK2}; margin-top: 2.2mm; line-height: 1.4; }}
figure.diag img {{ width: 100%; display: block; }}
ul.tick {{ list-style: none; }} ul.tick li {{ position: relative; padding-left: 5.4mm; margin: 0 0 1.8mm; color: #253247; }}
ul.tick li::before {{ content: ""; position: absolute; left: 0; top: 1.6mm; width: 2.6mm; height: 2.6mm; border-radius: 50%;
  background: {BLUE}; box-shadow: inset 0 0 0 .7mm #fff; border: .4mm solid {BLUE}; }}
.dark ul.tick li {{ color: #cfdcee; }}
table.t {{ width: 100%; border-collapse: collapse; font-size: 8.2pt; }}
table.t th {{ text-align: left; font-size: 7.2pt; letter-spacing: .06em; text-transform: uppercase; color: {INK2};
  border-bottom: .5mm solid {NAVY}; padding: 1.8mm 2mm; }}
table.t td {{ border-bottom: 1px solid {LINE}; padding: 2mm; vertical-align: top; color: #253247; }}
.badge {{ display: inline-grid; place-items: center; width: 6.4mm; height: 6.4mm; border-radius: 1.4mm; font-weight: 800; font-size: 8pt; }}
.bA {{ background: {NAVY}; color: #fff; }} .bR {{ background: {BLUE}; color: #fff; }} .bC {{ background: #cfe1f8; color: {NAVY}; }}
.bI {{ background: #eef2f7; color: #8a96a8; }}
.cover-art {{ position: absolute; inset: 0; }}
.mark {{ width: 11mm; height: 11mm; border-radius: 2.6mm; background: #fff; color: {NAVY}; display: grid; place-items: center;
  font-family: "Inter Display"; font-weight: 800; font-size: 12pt; }}
.brand {{ display: flex; align-items: center; gap: 3.4mm; font-size: 8pt; letter-spacing: .2em; font-weight: 700; text-transform: uppercase; }}
.brand small {{ display: block; letter-spacing: .04em; text-transform: none; font-weight: 500; color: {SKY}; font-size: 7.4pt; margin-top: .6mm; }}
.num-big {{ font-family: "Inter Display"; font-weight: 800; color: {BLUE}; font-size: 22pt; line-height: 1; }}
.kpi {{ border: 1px solid {LINE}; border-radius: 3mm; padding: 4mm; position: relative; background: #fff; }}
.kpi .lab {{ font-size: 7.2pt; letter-spacing: .08em; text-transform: uppercase; color: {INK2}; font-weight: 700; }}
.kpi .dir {{ position: absolute; right: 4mm; top: 3.6mm; font-size: 7.4pt; font-weight: 800; padding: .6mm 2mm; border-radius: 10mm; }}
.up {{ background: #e3f5ec; color: #0b6b3a; }} .down {{ background: #fdeee6; color: #a3400f; }} .zero {{ background: #eef2f7; color: {NAVY}; }}
.kpi p {{ font-size: 8.2pt; color: {INK2}; margin: 1.6mm 0 0; }}
.kpi h4 {{ font-family: "Inter Display"; font-size: 11pt; color: {NAVY}; margin-top: 1.4mm; }}
"""


def icon(name, color=BLUE, sw=1.8):
    """Simple line icons drawn on a 24x24 grid."""
    paths = {
        "code": '<path d="M8 7l-5 5 5 5M16 7l5 5-5 5M13.5 4l-3 16"/>',
        "package": '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/>',
        "key": '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l2.5 2.5M18.5 4.5l2 2"/>',
        "layers": '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
        "pipeline": '<circle cx="5" cy="12" r="2.4"/><circle cx="12" cy="12" r="2.4"/><circle cx="19" cy="12" r="2.4"/><path d="M7.4 12h2.2M14.4 12h2.2"/>',
        "chain": '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
        "rocket": '<path d="M12 3c4 2 6 6 6 10l-3 3H9l-3-3c0-4 2-8 6-10z"/><circle cx="12" cy="10" r="1.8"/><path d="M9 16l-2 4M15 16l2 4"/>',
        "scale": '<path d="M12 4v16M6 20h12M5 8h14"/><path d="M5 8l-3 6h6zM19 8l-3 6h6z"/>',
        "brain": '<path d="M9 4a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 3 3V4zM15 4a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-3 3V4z"/>',
        "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>',
        "cloud": '<path d="M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9.5 4.3 4.3 0 0 0 7 18z"/>',
        "wheel": '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="2.2"/><path d="M12 3.5v6.3M12 14.2v6.3M3.5 12h6.3M14.2 12h6.3M6 6l4.4 4.4M13.6 13.6L18 18M18 6l-4.4 4.4M10.4 13.6L6 18"/>',
        "user": '<circle cx="12" cy="8" r="3.6"/><path d="M4.5 20c1.2-4 4.2-6 7.5-6s6.3 2 7.5 6"/>',
        "pulse": '<path d="M3 12h4l2-5 4 10 2-5h6"/>',
        "path": '<circle cx="5" cy="18" r="2.2"/><circle cx="19" cy="6" r="2.2"/><path d="M7 17c6 0 2-10 10-10"/>',
        "inbox": '<path d="M4 13l2.5-8h11l2.5 8v6H4z"/><path d="M4 13h5l1 2h4l1-2h5"/>',
        "shield": '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
        "lock": '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
        "gauge": '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4-6"/><circle cx="12" cy="17" r="1.2"/>',
        "ticket": '<path d="M4 7h16v3a2 2 0 0 0 0 4v3H4v-3a2 2 0 0 0 0-4z"/><path d="M14 7v10" stroke-dasharray="1.6 1.6"/>',
        "doc": '<path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4M9.5 12h6M9.5 15.5h6"/>',
        "server": '<rect x="4" y="4" width="16" height="7" rx="1.6"/><rect x="4" y="13" width="16" height="7" rx="1.6"/><path d="M8 7.5h.01M8 16.5h.01"/>',
        "eye": '<path d="M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.5S2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>',
        "flag": '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
        "check": '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16.5 9"/>',
        "stop": '<path d="M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2z"/><path d="M9 12h6"/>',
        "bolt": '<path d="M13 3L5 13h6l-1 8 8-10h-6z"/>',
        "team": '<circle cx="9" cy="9" r="3"/><circle cx="17" cy="10" r="2.4"/><path d="M3.5 19c.8-3.2 3-5 5.5-5s4.7 1.8 5.5 5M14.5 15.2c2.4-.6 4.8.7 5.8 3.8"/>',
        "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
    }
    return (f'<svg viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="{sw}" stroke-linecap="round" '
            f'stroke-linejoin="round">{paths[name]}</svg>')


def cover_art(seed=7, side=False):
    """An original 'nerve' illustration: neurons joined by axons wrapped in myelin segments."""
    rnd = random.Random(seed)
    W, H = 794, 1123
    out = [f'<svg class="cover-art" viewBox="0 0 {W} {H}" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">',
           '<defs><radialGradient id="glow" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="#7cc4ff" stop-opacity=".9"/>'
           '<stop offset="1" stop-color="#7cc4ff" stop-opacity="0"/></radialGradient>'
           '<linearGradient id="fade" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#071427" stop-opacity="0"/>'
           '<stop offset=".62" stop-color="#071427" stop-opacity="0"/><stop offset="1" stop-color="#071427" stop-opacity=".85"/></linearGradient>'
           '<linearGradient id="side" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#071427" stop-opacity=".92"/>'
           '<stop offset=".55" stop-color="#071427" stop-opacity=".35"/><stop offset="1" stop-color="#071427" stop-opacity="0"/></linearGradient></defs>']
    nodes = [(rnd.uniform(330, 780), rnd.uniform(60, 640)) for _ in range(16)] + [(600, 330), (470, 210), (700, 520)]
    # concentric rings behind the hub
    for r, o in ((300, .05), (220, .07), (140, .09)):
        out.append(f'<circle cx="600" cy="330" r="{r}" fill="none" stroke="#9ec5f4" stroke-opacity="{o}" stroke-width="1.2"/>')
    for i, (x1, y1) in enumerate(nodes):
        near = sorted(nodes, key=lambda p: (p[0] - x1) ** 2 + (p[1] - y1) ** 2)[1:3]
        for (x2, y2) in near:
            mx, my = (x1 + x2) / 2 + rnd.uniform(-60, 60), (y1 + y2) / 2 + rnd.uniform(-60, 60)
            out.append(f'<path d="M{x1:.0f} {y1:.0f} Q{mx:.0f} {my:.0f} {x2:.0f} {y2:.0f}" fill="none" stroke="#5aa2ee" '
                       f'stroke-opacity=".35" stroke-width="1.1"/>')
            # myelin sheath segments along the axon
            for t in (0.28, 0.5, 0.72):
                px = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * mx + t ** 2 * x2
                py = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * my + t ** 2 * y2
                dx = 2 * (1 - t) * (mx - x1) + 2 * t * (x2 - mx)
                dy = 2 * (1 - t) * (my - y1) + 2 * t * (y2 - my)
                ang = math.degrees(math.atan2(dy, dx))
                out.append(f'<rect x="{px - 9:.1f}" y="{py - 2.6:.1f}" width="18" height="5.2" rx="2.6" fill="#9ec5f4" '
                           f'fill-opacity=".55" transform="rotate({ang:.1f} {px:.1f} {py:.1f})"/>')
    for (x, y) in nodes:
        r = rnd.uniform(3, 6.5)
        out.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r * 4:.0f}" fill="url(#glow)" opacity=".35"/>'
                   f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r:.1f}" fill="#e8f3ff"/>')
    out.append('<circle cx="600" cy="330" r="70" fill="url(#glow)" opacity=".55"/><circle cx="600" cy="330" r="12" fill="#fff"/>')
    out.append(f'<rect width="{W}" height="{H}" fill="url(#fade)"/>')
    if side:
        out.append(f'<rect width="{W}" height="{H}" fill="url(#side)"/>')
    out.append('</svg>')
    return "".join(out)


def bars(series, cats, unit="%", w=520, h=210, colors=(BLUE, ORANGE), maxv=None, labels=None, dec=0):
    """Grouped vertical bar chart with direct value labels (no dual axis, recessive grid)."""
    n, k = len(cats), len(series)
    maxv = maxv or max(max(v for v in s[1]) for s in series) * 1.18
    left, bottom, top = 34, 30, 14
    pw, ph = w - left - 8, h - bottom - top
    gw = pw / n
    bw = min(40, (gw * 0.62) / k)
    o = [f'<svg viewBox="0 0 {w} {h}" width="100%" xmlns="http://www.w3.org/2000/svg" font-family="Inter" font-size="10">']
    for t in range(0, 5):
        v = maxv * t / 4
        y = top + ph - ph * t / 4
        o.append(f'<line x1="{left}" x2="{w - 8}" y1="{y:.1f}" y2="{y:.1f}" stroke="#e3e8ef" stroke-width="1"/>'
                 f'<text x="{left - 6}" y="{y + 3:.1f}" text-anchor="end" fill="#8a96a8" font-size="9">{v:.{dec}f}{unit}</text>')
    for i, c in enumerate(cats):
        gx = left + gw * i + (gw - bw * k - 4 * (k - 1)) / 2
        for j, (name, vals) in enumerate(series):
            v = vals[i]
            if v is None:
                continue
            bh = ph * v / maxv
            x = gx + j * (bw + 4)
            y = top + ph - bh
            o.append(f'<path d="M{x:.1f} {top + ph:.1f} V{y + 4:.1f} Q{x:.1f} {y:.1f} {x + 4:.1f} {y:.1f} H{x + bw - 4:.1f} '
                     f'Q{x + bw:.1f} {y:.1f} {x + bw:.1f} {y + 4:.1f} V{top + ph:.1f}Z" fill="{colors[j]}"/>'
                     f'<text x="{x + bw / 2:.1f}" y="{y - 5:.1f}" text-anchor="middle" fill="#0b1220" font-weight="700" '
                     f'font-size="10.5">{v:.{dec}f}{unit}</text>')
        o.append(f'<text x="{left + gw * i + gw / 2:.1f}" y="{h - 10}" text-anchor="middle" fill="#4a5a72" font-size="10">{c}</text>')
    o.append(f'<line x1="{left}" x2="{w - 8}" y1="{top + ph}" y2="{top + ph}" stroke="#9aa6b8" stroke-width="1"/></svg>')
    return "".join(o)


def legend(items):
    return '<div style="display:flex;gap:5mm;font-size:7.8pt;color:#4a5a72;margin:1mm 0 1.5mm">' + "".join(
        f'<span style="display:inline-flex;align-items:center;gap:1.6mm"><i style="width:3mm;height:3mm;border-radius:.8mm;'
        f'background:{c};display:inline-block"></i>{t}</span>' for t, c in items) + "</div>"


def qr_svg(url, size_mm=30):
    import qrcode
    q = qrcode.QRCode(border=1, error_correction=qrcode.constants.ERROR_CORRECT_M)
    q.add_data(url)
    q.make(fit=True)
    m = q.get_matrix()
    n = len(m)
    rects = "".join(f'<rect x="{x}" y="{y}" width="1.02" height="1.02"/>' for y, row in enumerate(m) for x, v in enumerate(row) if v)
    return (f'<svg viewBox="0 0 {n} {n}" width="{size_mm}mm" height="{size_mm}mm" shape-rendering="crispEdges" '
            f'style="background:#fff;border-radius:1.6mm"><g fill="#0b1f3a">{rects}</g></svg>')
