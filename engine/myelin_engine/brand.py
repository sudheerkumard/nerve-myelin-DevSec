# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Product identity shared by every generated report: name, attribution, repository link and the product mark.

The mark is the same vector drawing as the console logo, inlined as SVG so reports stay single self-contained
files that render offline, print sharply and need no image hosting.
"""
PRODUCT = "RAT Flea DevSec"
COMPANY = "RAT Flea Cyber"
REPO_URL = "https://github.com/sudheerkumard/nervve-devsecops"
ATTRIBUTION = "RAT Flea DevSec Product designed and developed by Sudheer Kumar"

_PATHS = ('<path d="M56 77 74 98H95" fill="none" stroke="{fg}" stroke-width="10" stroke-linecap="round" '
          'stroke-linejoin="round"/><path fill="{fg}" fill-rule="evenodd" d="M8 59C23 41 44 29 68 29c22 0 41 10 55 28'
          '-15 16-33 28-56 28C44 85 23 76 8 59ZM35 43c4-2 7-4 11-5 5 12 3 25-5 38-4-1-7-3-10-5 8-11 9-20 4-28ZM51 35c4-1 '
          '7-1 11-1 6 14 4 33-5 46-4 0-7-1-10-2 8-14 10-28 4-43ZM101 56a16 16 0 1 0-32 0 16 16 0 0 0 32 0Z"/>'
          '<circle cx="85" cy="56" r="8" fill="{eye}"/>')


def logo_svg(width: int = 44, fg: str = "#F3FAF8", eye: str = "#59E3C2", cls: str = "product-mark") -> str:
    """The product mark. fg is the body colour: light on dark headers, ink (#0b2a4a) on white pages."""
    h = round(width * 100 / 128)
    return (f'<svg class="{cls}" viewBox="0 16 128 100" width="{width}" height="{h}" role="img" '
            f'aria-label="{PRODUCT} logo"><g>{_PATHS.format(fg=fg, eye=eye)}</g></svg>')


def report_header(title: str, subtitle: str = "") -> str:
    """A branded band for the top of a white-page report (remediation plan, SBOM licence report)."""
    from html import escape
    sub = f'<div class="rf-sub">{escape(subtitle)}</div>' if subtitle else ""
    return (f'<header class="rf-band">{logo_svg(46)}<div class="rf-id"><div class="rf-name">{PRODUCT}</div>'
            f'<div class="rf-by">{escape(REPO_URL.split("://", 1)[1])}</div></div>'
            f'<div class="rf-title"><h1>{escape(title)}</h1>{sub}</div></header>')


HEADER_CSS = (".rf-band{display:flex;align-items:center;gap:14px;background:#0b2a4a;color:#fff;padding:14px 20px;"
              "border-radius:10px;margin:0 0 16px;-webkit-print-color-adjust:exact;print-color-adjust:exact}"
              ".rf-id{border-right:1px solid #335a80;padding-right:16px}.rf-name{font-weight:700;letter-spacing:.06em}"
              ".rf-by{font-size:11px;color:#9ec5f4}.rf-title h1{margin:0;font-size:20px;color:#fff}"
              ".rf-sub{font-size:12px;color:#cde2fb}"
              ".rf-foot{margin-top:24px;padding-top:10px;border-top:1px solid #e2e8f0;color:#64748b;font-size:11px;"
              "display:flex;align-items:center;gap:8px}")


def report_footer() -> str:
    return (f'<footer class="rf-foot">{logo_svg(22, fg="#0b2a4a", eye="#18a689")}<span>{ATTRIBUTION} · '
            f'<a href="{REPO_URL}">{REPO_URL.split("://", 1)[1]}</a></span></footer>')
