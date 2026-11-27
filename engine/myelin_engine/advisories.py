# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Normalized package advisory evidence and conservative scan-time matching."""
import re
from urllib.parse import unquote

from . import vulndb

GITHUB_ECOSYSTEM = {"pip": "pypi", "npm": "npm", "maven": "maven", "go": "go", "rust": "cargo",
                    "nuget": "nuget", "rubygems": "gem", "composer": "composer", "erlang": "hex",
                    "pub": "pub", "swift": "swift"}
OSV_ECOSYSTEM = {v: k for k, v in vulndb.OSV_ECO.items()}


def package_key(eco, name):
    if not eco or not name:
        return None
    name = vulndb.norm_name(eco, name)
    return f"{eco}:{name.lower() if eco == 'nuget' else name}"


def component_keys(components):
    return sorted({key for c in components if (key := package_key(c.get("ecosystem"), c.get("name")))})


def _purl_key(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    eco, sep, name = purl[4:].partition("/")
    if not sep or "@" not in name:
        return None
    name = unquote(name.rsplit("@", 1)[0])
    if eco == "maven":
        name = name.replace("/", ":", 1)
    return package_key(eco, name)


def _references(doc):
    return sorted({url for r in (doc.get("references") or [])
                   if isinstance(url := (r.get("url") if isinstance(r, dict) else r), str)
                   and url.startswith(("https://", "http://"))})


def _product_purls(tree):
    parts = [tree]
    out = {}
    while parts:
        item = parts.pop()
        if not isinstance(item, dict):
            continue
        if "product_id" in item:
            purl = (item.get("product_identification_helper") or {}).get("purl")
            if _purl_key(purl):
                out[item["product_id"]] = purl
        for key in ("branches", "relationships", "full_product_names"):
            parts.extend(item.get(key) or [])
        for key in ("product", "full_product_name"):
            if item.get(key):
                parts.append(item[key])
    return out


def normalize(source, doc, purl=None):
    """Retain source fields for API readers and store versioned matching rules alongside them."""
    rules, aliases, cvss = [], [], None
    if source == "OSV":
        ident, modified, withdrawn = doc.get("id"), doc.get("modified"), doc.get("withdrawn")
        aliases = list(doc.get("aliases") or [])
        cvss, severity = vulndb._severity_of(doc)
        # Label-derived estimates are not published CVSS scores.
        if not any(x.get("type", "").startswith("CVSS_V3") and vulndb._cvss3(x.get("score", "")) is not None
                   for x in doc.get("severity") or []):
            cvss = None
        for item in doc.get("affected") or []:
            pkg = item.get("package") or {}
            key = package_key(OSV_ECOSYSTEM.get(pkg.get("ecosystem")), pkg.get("name"))
            if key:
                rules.append({"key": key, "versions": item.get("versions") or [], "ranges": item.get("ranges") or []})
        payload = {**doc, "purl": purl}
    elif source == "GITHUB":
        ident, modified, withdrawn = doc.get("ghsa_id"), doc.get("updated_at"), doc.get("withdrawn_at")
        aliases = [doc["cve_id"]] if doc.get("cve_id") else []
        cvss = (doc.get("cvss_severities") or {}).get("cvss_v4") or {}
        cvss = cvss if cvss.get("vector_string") else doc.get("cvss") or {}
        cvss = cvss.get("score")
        severity = doc.get("severity")
        for item in doc.get("vulnerabilities") or []:
            pkg = item.get("package") or {}
            key = package_key(GITHUB_ECOSYSTEM.get(pkg.get("ecosystem")), pkg.get("name"))
            fixed = item.get("first_patched_version")
            if key and item.get("vulnerable_version_range"):
                rules.append({"key": key, "constraint": item["vulnerable_version_range"],
                              "fixed": fixed.get("identifier") if isinstance(fixed, dict) else fixed})
        payload = {**doc, "id": ident, "cve": doc.get("cve_id")}
    elif source == "NVD":
        ident, modified = doc.get("id"), doc.get("lastModified")
        withdrawn = (modified or True) if doc.get("vulnStatus") == "Rejected" else None
        metrics = doc.get("metrics") or {}
        rows = next((metrics[k] for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2") if metrics.get(k)), [])
        chosen = next((r for r in rows if r.get("type") == "Primary"), rows[0] if rows else {})
        metric = chosen.get("cvssData") or {}
        cvss, severity = metric.get("baseScore"), metric.get("baseSeverity") or chosen.get("baseSeverity")
        description = next((x.get("value") for x in doc.get("descriptions") or [] if x.get("lang") == "en"), "")
        payload = {**doc, "cve": ident, "description": description, "last_modified": modified}
    elif source == "REDHAT":
        head = doc.get("document") or {}
        tracking = head.get("tracking") or {}
        ident, modified, withdrawn = tracking.get("id"), tracking.get("current_release_date"), None
        if (head.get("publisher") or {}).get("namespace") != "https://www.redhat.com":
            raise ValueError("unexpected CSAF publisher")
        products = _product_purls(doc.get("product_tree") or {})
        records = []
        for v in doc.get("vulnerabilities") or []:
            cve = v.get("cve")
            if not cve:
                continue
            status = v.get("product_status") or {}
            for product in status.get("known_affected") or []:
                affected = products.get(product)
                if affected:
                    records.append({"key": _purl_key(affected), "purl": affected, "cve": cve})
            aliases.append(cve)
        rules = records
        severity = (head.get("aggregate_severity") or {}).get("text")
        payload = {**doc, "id": ident, "summary": head.get("title"), "references": head.get("references") or [],
                   "fixed_products": sorted({products[p] for v in doc.get("vulnerabilities") or []
                                             for p in [*((v.get("product_status") or {}).get("fixed") or []),
                                                       *((v.get("product_status") or {}).get("first_fixed") or [])]
                                             if p in products})}
    else:
        raise ValueError("unsupported advisory source")
    if not isinstance(ident, str) or not ident or len(ident) > 200:
        raise ValueError("source record has no valid advisory identifier")
    label = _label(severity)
    if label == "unknown" and isinstance(cvss, (int, float)) and 0 <= cvss <= 10:
        label = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
    normalized = {"schema": 1, "source": source, "id": ident, "aliases": sorted(set(aliases)), "withdrawn": withdrawn,
                  "summary": payload.get("summary") or payload.get("description") or "", "cvss": cvss,
                  "severity": label, "references": _references(payload), "rules": rules}
    payload.update(normalized=normalized, package_keys=sorted({r["key"] for r in rules}),
                   cve_ids=sorted({x for x in [ident, *aliases] if re.fullmatch(r"CVE-\d{4}-\d{4,}", x)}))
    # Keep legacy dashboard fields compatible; GitHub's raw score remains an object.
    if source == "NVD":
        payload.update(cvss=cvss, severity=severity)
    return {"advisory_id": ident, "modified_at": modified, "payload": payload}


def _label(value):
    label = str(value or "").lower()
    return {"moderate": "medium", "important": "high"}.get(label, label) if label in {
        "critical", "high", "important", "medium", "moderate", "low"} else "unknown"


SEMVER = re.compile(r"[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?")


def _comparison(eco, left, right, *, semver=False):
    if eco == "pypi" and not semver:
        from packaging.version import InvalidVersion, Version
        try:
            left, right = Version(left), Version(right)
        except InvalidVersion:
            return None
    elif semver or eco in {"npm", "go", "cargo"}:
        def key(value):
            match = SEMVER.fullmatch(value)
            if not match:
                return None
            major, minor, patch, pre = match.groups()
            parts = tuple((0, int(x)) if x.isdigit() else (1, x) for x in pre.split(".")) if pre else ()
            return (int(major), int(minor), int(patch), pre is None, parts)
        left, right = key(left), key(right)
        if left is None or right is None:
            return None
    elif left != right:
        # For unsupported schemes compare plain numeric releases only. Qualifier
        # precedence varies and must not be guessed across ecosystems.
        if not all(re.fullmatch(r"\d+(?:\.\d+)*", v) for v in (left, right)):
            return None
        left, right = (tuple(int(x) for x in v.split(".")) for v in (left, right))
        width = max(len(left), len(right))
        left += (0,) * (width - len(left))
        right += (0,) * (width - len(right))
    return (left > right) - (left < right)


def _constraints(eco, version, expression):
    # GHSA uses comma-separated comparator expressions. Unrecognized syntax does not match.
    parts = [re.fullmatch(r"(<=|>=|<|>|=)?\s*([vV]?\d[0-9A-Za-z.\-+_!:]*)", p.strip()) for p in expression.split(",")]
    if not all(parts) or not re.match(r"^[vV]?\d", version):
        return False
    for p in parts:
        op, target = p.groups()
        order = _comparison(eco, version, target)
        if order is None or not {"=": order == 0, "<": order == -1, ">": order == 1,
                                 "<=": order in (-1, 0), ">=": order in (0, 1)}[op or "="]:
            return False
    return True


def _matches(rule, component):
    eco, version = component["ecosystem"], str(component["version"])
    if "purl" in rule:
        return rule["purl"] == component.get("purl"), None
    if "constraint" in rule:
        return _constraints(eco, version, rule["constraint"]), rule.get("fixed")
    explicit = version in rule.get("versions", [])
    for interval in rule.get("ranges") or []:
        if interval.get("type") not in {"ECOSYSTEM", "SEMVER"}:
            continue
        inside = False
        compare = lambda boundary: _comparison(eco, version, boundary, semver=interval["type"] == "SEMVER")
        for event in interval.get("events") or []:
            if "introduced" in event:
                inside = event["introduced"] == "0" or compare(event["introduced"]) in (0, 1)
            elif inside:
                boundary = next((k for k in ("fixed", "last_affected", "limit") if k in event), None)
                if not boundary:
                    continue
                order = compare(event[boundary])
                if order == -1 or (boundary == "last_affected" and order == 0):
                    return True, event["fixed"] if boundary == "fixed" else None
                inside = False
        if inside:
            return True, None
    return explicit, None


def evaluate(components, lookup, live):
    """Read a fresh tenant catalog on each scan. NVD may enrich a match, never create one by CPE guess."""
    fetched = lookup(component_keys(components), sorted({v["cve"] for _, v in live if v.get("cve")}))
    enrichment = {}
    by_key = {}
    for record in fetched:
        data = record["payload"].get("normalized") or {}
        if data.get("schema") != 1 or data.get("withdrawn"):
            continue
        if data["source"] in {"NVD", "REDHAT"}:
            for cve in record["payload"].get("cve_ids") or []:
                enrichment.setdefault(cve, []).append(data)
        for rule in data.get("rules", []):
            by_key.setdefault(rule["key"], []).append((data, rule))
    out = []
    for c in components:
        for data, rule in by_key.get(package_key(c.get("ecosystem"), c.get("name")), []):
            match, fixed = _matches(rule, c)
            if not match:
                continue
            aliases = [data["id"], *data["aliases"]]
            cve = rule.get("cve") or next((a for a in aliases if a.startswith("CVE-")), None)
            cvss = data["cvss"]
            label = data["severity"]
            out.append((c, {"id": cve if data["source"] == "REDHAT" else data["id"],
                            "cve": cve, "aliases": aliases, "cvss": cvss, "severity": label,
                            "severity_known": cvss is not None or label != "unknown", "cwe": None,
                            "fixed": fixed, "summary": data["summary"][:200],
                            "advisory_sources": [data["source"]], "references": data["references"]}))
    for _, v in [*live, *out]:
        extras = enrichment.get(v.get("cve"), [])
        if extras:
            v["advisory_sources"] = sorted({*(v.get("advisory_sources") or []), *(e["source"] for e in extras)})
            v["references"] = sorted({*(v.get("references") or []), *(ref for e in extras for ref in e["references"])})
            metric = next((e for e in extras if e["source"] == "NVD" and e.get("cvss") is not None), None)
            if metric and v.get("cvss") is None:
                v.update(cvss=metric["cvss"], severity=metric["severity"], severity_known=True)
    for source in {v["source"] for records in enrichment.values() for v in records} | {src for _, v in out for src in v["advisory_sources"]}:
        vulndb.scan_status()["sources"].add(f"tenant advisory store: {source}")
    return out
