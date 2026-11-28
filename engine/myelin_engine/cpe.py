# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Vulnerability matching by CPE (vendor, product, version), for components without a package-manager identity.

Native libraries and executables, firmware, operating systems, drivers, databases, middleware and servers are named
in NVD by CPE. Matching uses the CPE section of the offline advisory pack (every NVD CVE with its vulnerable CPE
ranges) when present, otherwise the NVD API (``MYELIN_NVD_URL``, ``NVD_API_KEY`` for higher rate limits).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse

NVD_URL = os.environ.get("MYELIN_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
_PACK: dict = {"loaded": False, "data": None}
_PRE = {"dev": -5, "alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cr": -1}


def _key(v: str):
    """Ordering for the version strings NVD uses (1.1.1k, 2.4.58, 7.88.1, 4.19.0-rc3, 2016.01, 9.0p1)."""
    out = []
    for tok in re.findall(r"\d+|[a-z]+", str(v).lower()):
        if tok.isdigit():
            out.append((1, int(tok), ""))
        elif tok in _PRE:
            out.append((0, _PRE[tok], ""))
        else:
            out.append((1, -1, tok)) if not out else out.append((2, 0, tok))
    return out


def vcmp(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    n = max(len(ka), len(kb))
    pad = (1, 0, "")
    for i in range(n):
        x = ka[i] if i < len(ka) else pad
        y = kb[i] if i < len(kb) else pad
        if x != y:
            return -1 if x < y else 1
    return 0


def affected(version: str, exact, s_inc, s_exc, e_inc, e_exc) -> bool:
    if exact is not None:
        return vcmp(version, exact) == 0
    if s_inc and vcmp(version, s_inc) < 0:
        return False
    if s_exc and vcmp(version, s_exc) <= 0:
        return False
    if e_inc and vcmp(version, e_inc) > 0:
        return False
    if e_exc and vcmp(version, e_exc) >= 0:
        return False
    return True


def _score(m):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = (m or {}).get(key) or []
        row = next((r for r in rows if r.get("type") == "Primary"), rows[0] if rows else None)
        if row:
            d = row.get("cvssData") or {}
            return d.get("baseScore"), ((d.get("baseSeverity") or row.get("baseSeverity") or "").lower() or None)
    return None, None


class _Pack:
    """The CPE section of the advisory pack: product rows and CVE metadata read from the zip on demand."""

    def __init__(self, path):
        import zipfile
        self.z = zipfile.ZipFile(path)
        self.names = set(self.z.namelist())
        self.cache, self.meta_cache = {}, {}

    def rows(self, product):
        if product not in self.cache:
            name = "p/" + product.replace("/", "%2F") + ".json"
            self.cache[product] = json.loads(self.z.read(name)) if name in self.names else []
        return self.cache[product]

    def meta(self, cve):
        sh = hashlib.sha1(cve.encode()).hexdigest()[:3]
        if sh not in self.meta_cache:
            name = f"m/{sh}.json"
            self.meta_cache[sh] = json.loads(self.z.read(name)) if name in self.names else {}
        return self.meta_cache[sh].get(cve)

    def has(self, product):
        return "p/" + product.replace("/", "%2F") + ".json" in self.names


def pack():
    if _PACK["loaded"]:
        return _PACK["data"]
    _PACK["loaded"] = True
    from .vulndb import OSV_EXPORT_MANIFEST, export_dir, scan_status
    d = export_dir()
    if not d:
        return None
    try:
        entry = json.load(open(os.path.join(d, OSV_EXPORT_MANIFEST), encoding="utf-8")).get("cpe")
        if not entry or os.path.basename(entry.get("file", "")) != entry.get("file"):
            return None
        path = os.path.join(d, entry["file"])
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != entry.get("sha256"):
            scan_status()["errors"].add("offline CPE data checksum mismatch; ignored")
            return None
        _PACK["data"] = _Pack(path)
    except (OSError, ValueError):
        _PACK["data"] = None
    return _PACK["data"]


def cve_meta(cve: str) -> dict:
    """{'cvss', 'severity', 'cwe', 'summary'} from NVD (pack, or what the NVD API returned this run)."""
    p = pack()
    row = p.meta(cve) if p else None
    if not row:
        return dict(_ONLINE_META.get(cve) or {})
    score, sev, cwe, summary = row
    return {"cvss": score, "severity": sev, "cwe": cwe, "summary": summary}


def lookup(products: list[str], version: str) -> list[dict]:
    """Advisories for one component version under any of its CPE products ('a:openssl:openssl')."""
    from .vulndb import scan_status
    p = pack()
    found = {}
    for prod in products:
        rows = p.rows(prod) if p else None
        source = "NVD CPE data (offline advisory pack)"
        if rows is None and p is None:
            rows = _nvd_rows(prod)
            source = "NVD API"
        if not rows:
            continue
        scan_status()["sources"].add(source)
        for cve, exact, s_inc, s_exc, e_inc, e_exc in rows:
            try:
                if cve not in found and affected(version, exact, s_inc, s_exc, e_inc, e_exc):
                    fixed = e_exc if e_exc else None
                    found[cve] = {"id": cve, "fixed": fixed, **cve_meta(cve)}
                elif cve in found and e_exc and affected(version, exact, s_inc, s_exc, e_inc, e_exc):
                    found[cve]["fixed"] = found[cve]["fixed"] or e_exc
            except (TypeError, ValueError):
                continue
    return list(found.values())


_ONLINE_META: dict = {}


def _nvd_rows(product: str) -> list | None:
    """CPE match rows for one product from the NVD API (paged), in the pack's row format."""
    from .vulndb import _http_json, offline, scan_status
    if offline():
        return None
    part, vendor, prod = product.split(":", 2)
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else None
    rows, start = [], 0
    while True:
        q = urllib.parse.urlencode({"virtualMatchString": f"cpe:2.3:{part}:{vendor}:{prod}", "startIndex": start,
                                    "resultsPerPage": 2000})
        data = _http_json(f"{NVD_URL}?{q}", ttl=24 * 3600, headers=headers)
        if data is None:
            scan_status()["errors"].add("NVD API unavailable for CPE matching")
            return rows or None
        items = data.get("vulnerabilities") or []
        for item in items:
            c = item.get("cve") or {}
            cve = c.get("id")
            if not cve:
                continue
            score, sev = _score(c.get("metrics") or {})
            cwe = next((x["value"] for w in c.get("weaknesses") or [] for x in w.get("description") or []
                        if str(x.get("value", "")).startswith("CWE-")), None)
            summary = next((x["value"] for x in c.get("descriptions") or [] if x.get("lang") == "en"), "")[:160]
            _ONLINE_META[cve] = {"cvss": score, "severity": sev, "cwe": cwe, "summary": summary}
            for conf in c.get("configurations") or []:
                for node in conf.get("nodes") or []:
                    for m in node.get("cpeMatch") or []:
                        parts = (m.get("criteria") or "").split(":")
                        if not m.get("vulnerable") or len(parts) < 7 or f"{parts[2]}:{parts[3]}:{parts[4]}" != product:
                            continue
                        exact = None if parts[5] in ("*", "-") else parts[5] + ("" if parts[6] in ("*", "-") else parts[6])
                        rows.append([cve, exact, m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                                     m.get("versionEndIncluding"), m.get("versionEndExcluding")])
        start += len(items)
        if not items or start >= int(data.get("totalResults") or 0):
            return rows
