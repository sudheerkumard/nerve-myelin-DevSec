# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Vulnerability Exploitability eXchange (VEX) and CSAF disposition ingestion.

The importer is deliberately conservative: dispositions are applied only when both a
vulnerability identifier and an exact component purl can be established. Unknown,
ambiguous, malformed, or merely under-investigation statements never suppress a finding.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json


_STATES = {
    "not_affected": "not_affected",
    "not-affected": "not_affected",
    "fixed": "fixed",
    "resolved": "fixed",
    "known_affected": "affected",
    "known-affected": "affected",
    "affected": "affected",
    "under_investigation": "under_investigation",
    "under-investigation": "under_investigation",
    "exploitable": "affected",
}


def _norm_id(value):
    return str(value or "").strip().upper()


def _norm_purl(value):
    return str(value or "").strip()


def _digest(document):
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _date(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def _openvex(doc):
    """Normalize OpenVEX statements only when a product is an exact package URL."""
    digest = _digest(doc)
    out = []
    for statement in doc.get("statements") or []:
        vulnerability = statement.get("vulnerability") or {}
        vid = _norm_id(vulnerability.get("name") or vulnerability.get("@id"))
        state = _STATES.get(str(statement.get("status") or "").lower())
        if not vid or not state:
            continue
        purls = []
        for product in statement.get("products") or []:
            if isinstance(product, str):
                purls += [product] if product.startswith("pkg:") else []
                continue
            if not isinstance(product, dict):
                continue
            cand = [product.get("purl"), product.get("package_url"), (product.get("identifiers") or {}).get("purl"),
                    product.get("@id") if str(product.get("@id") or "").startswith("pkg:") else None]
            subs = [(x.get("@id") if str(x.get("@id") or "").startswith("pkg:") else (x.get("identifiers") or {}).get("purl"))
                    for x in product.get("subcomponents") or [] if isinstance(x, dict)]
            # OpenVEX 0.2: subcomponents name the affected components inside the product
            purls += [p for p in (subs if any(subs) else cand) if p]
        for purl in dict.fromkeys(purls):
            out.append({"vulnerability": vid, "purl": _norm_purl(purl), "state": state,
                "justification": statement.get("justification"),
                "detail": str(statement.get("impact_statement") or statement.get("action_statement") or "")[:2000],
                "source": "openvex", "source_id": doc.get("@id"), "source_digest": digest,
                "issuer": doc.get("author"), "timestamp": _date(doc.get("timestamp"))})
    return out

def _cyclonedx(doc):
    """Return normalized statements from a CycloneDX 1.4/1.5/1.6 VEX document."""
    components = {}
    for component in doc.get("components") or []:
        ref = component.get("bom-ref")
        purl = component.get("purl")
        if ref and purl:
            components[ref] = purl
    digest = _digest(doc)
    out = []
    for vuln in doc.get("vulnerabilities") or []:
        vid = _norm_id(vuln.get("id"))
        analysis = vuln.get("analysis") or {}
        state = _STATES.get(str(analysis.get("state") or "").lower())
        if not vid or not state:
            continue
        justification = analysis.get("justification")
        detail = analysis.get("detail") or vuln.get("detail") or ""
        for affect in vuln.get("affects") or []:
            ref = affect.get("ref")
            purl = affect.get("purl") or components.get(ref)
            if not purl:
                continue
            out.append({
                "vulnerability": vid, "purl": purl, "state": state,
                "justification": justification, "detail": str(detail)[:2000],
                "source": "cyclonedx-vex", "source_id": doc.get("serialNumber"), "source_digest": digest,
                "issuer": (doc.get("metadata") or {}).get("supplier", {}).get("name"),
                "timestamp": _date((doc.get("metadata") or {}).get("timestamp")),
            })
    return out


def _csaf(doc):
    """Normalize CSAF 2.0 product-status statements using explicit product purl identifiers."""
    tree = doc.get("product_tree") or {}
    purls = {}
    for branch in tree.get("branches") or []:
        stack = [branch]
        while stack:
            node = stack.pop()
            product = node.get("product") or {}
            pid = product.get("product_id")
            helper = product.get("product_identification_helper") or {}
            purl = helper.get("purl")
            if pid and purl:
                purls[pid] = purl
            stack.extend(node.get("branches") or [])
    digest = _digest(doc)
    out = []
    for vuln in doc.get("vulnerabilities") or []:
        ids = vuln.get("ids") or []
        vid = _norm_id(vuln.get("cve") or (ids[0].get("text") if ids and isinstance(ids[0], dict) else ""))
        if not vid:
            continue
        statuses = vuln.get("product_status") or {}
        mapping = (
            ("known_not_affected", "not_affected"),
            ("fixed", "fixed"),
            ("known_affected", "affected"),
            ("under_investigation", "under_investigation"),
        )
        for key, state in mapping:
            for pid in statuses.get(key) or []:
                purl = purls.get(pid)
                if purl:
                    out.append({
                        "vulnerability": vid, "purl": purl, "state": state,
                        "justification": None,
                        "detail": str(vuln.get("notes", [{}])[0].get("text", ""))[:2000],
                        "source": "csaf-2.0", "source_id": (doc.get("document") or {}).get("tracking", {}).get("id"),
                        "source_digest": digest,
                        "issuer": (doc.get("document") or {}).get("publisher", {}).get("name"),
                        "timestamp": _date((doc.get("document") or {}).get("tracking", {}).get("current_release_date")),
                    })
    return out


def normalize_document(document: dict) -> list[dict]:
    """Normalize a CycloneDX VEX or CSAF 2.0 document; unsupported formats fail closed."""
    if not isinstance(document, dict):
        raise ValueError("VEX document must be a JSON object")
    if isinstance(document.get("statements"), list):
        return _openvex(document)
    if document.get("bomFormat") == "CycloneDX":
        return _cyclonedx(document)
    if str(document.get("document", {}).get("category", "")).lower() == "csaf_vex" or document.get("csaf_version"):
        return _csaf(document)
    raise ValueError("Unsupported VEX format; expected CycloneDX or CSAF 2.0")


def apply(findings: list[dict], documents: list[dict] | None) -> dict:
    """Attach exact-match dispositions to findings and return an auditable summary.

    Only not_affected and fixed dispositions change finding lifecycle status. An
    under-investigation statement is annotation only and cannot lower a gate decision.
    Conflicting statements for the same CVE+purl are treated as ambiguous and ignored.
    """
    statements = []
    for doc in documents or []:
        statements.extend(normalize_document(doc))
    grouped = {}
    for statement in statements:
        key = (_norm_id(statement["vulnerability"]), _norm_purl(statement["purl"]))
        grouped.setdefault(key, []).append(statement)
    applied = 0
    ambiguous = 0
    for finding in findings:
        vuln_ids = {_norm_id(finding.get("cve")), _norm_id(finding.get("rule_id"))}
        vuln_ids.discard("")
        purl = _norm_purl(finding.get("purl"))
        if not purl or not vuln_ids:
            continue
        matches = [s for (vid, component), items in grouped.items() if vid in vuln_ids and component == purl
                   for s in items]
        if not matches:
            continue
        states = {s["state"] for s in matches}
        if len(states) != 1:
            finding["vex"] = {"state": "ambiguous", "sources": sorted({s["source"] for s in matches})}
            ambiguous += 1
            continue
        statement = sorted(matches, key=lambda s: (s.get("timestamp") or "", s["source"]))[-1]
        state = statement["state"]
        finding["vex"] = {k: statement.get(k) for k in
                          ("state", "justification", "detail", "source", "source_id", "source_digest", "issuer", "timestamp")}
        if state == "not_affected":
            finding["status"] = "not_affected"
        elif state == "fixed":
            finding["status"] = "fixed"
        # affected and under-investigation remain open and retain their original risk.
        applied += 1
    return {"documents": len(documents or []), "statements": len(statements),
            "applied": applied, "ambiguous": ambiguous,
            "not_affected": sum(1 for f in findings if (f.get("vex") or {}).get("state") == "not_affected"),
            "fixed": sum(1 for f in findings if (f.get("vex") or {}).get("state") == "fixed")}


# ─── export: VEX documents built from NERvvE DevSecOps triage decisions ─────────────────────────────────────────────
# fixed -> fixed · suppressed / not_affected -> not_affected (justification from the recorded reason)
# risk_accepted -> affected (action: accepted until …) · open with fix -> affected (upgrade) · open, untriaged -> under_investigation
JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist")
CDX_JUSTIFICATION = {"component_not_present": "code_not_present", "vulnerable_code_not_present": "code_not_present",
                     "vulnerable_code_not_in_execute_path": "code_not_reachable",
                     "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
                     "inline_mitigations_already_exist": "protected_by_mitigating_control"}


def _vid(f):
    from .report_enterprise import vuln_id
    return vuln_id(f)


def _justification(reason: str) -> str:
    r = (reason or "").lower()
    for j in JUSTIFICATIONS:
        if j in r or j.replace("_", " ") in r:
            return j
    if "not present" in r or "not used" in r or "unused" in r:
        return "vulnerable_code_not_present"
    if "mitigat" in r or "waf" in r or "compensating" in r:
        return "inline_mitigations_already_exist"
    return "vulnerable_code_not_in_execute_path"


def _status(f):
    st, t = f.get("status", "open"), f.get("triage") or {}
    if st == "fixed":
        return "fixed", {}
    if st in ("suppressed", "false_positive"):
        return "not_affected", {"justification": _justification(t.get("reason", "")),
                                "impact_statement": (t.get("reason") or "Not exploitable in this product.")[:500]}
    if st == "risk_accepted":
        return "affected", {"action_statement": f"Risk accepted until {t.get('expires', 'review')}: {t.get('reason', '')}"[:500]}
    if f.get("ticket") or f.get("fixed_version"):
        return "affected", {"action_statement": (f"Upgrade {f.get('package')} to {f['fixed_version']} or later."
                                                 if f.get("fixed_version") else "Remediation tracked in " + str((f.get("ticket") or {}).get("key")))}
    return "under_investigation", {}


def _purl(f):
    if f.get("purl"):
        return f["purl"]
    eco = f.get("ecosystem") or "generic"
    return f"pkg:{eco}/{str(f.get('package', 'unknown')).replace(':', '/')}@{f.get('version', '')}"


def openvex(findings, product: str, author: str = "NERvvE DevSecOps", now=None) -> dict:
    now = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stmts, seen = [], set()
    for f in findings:
        if f.get("engine") not in ("sca", "container") or not _vid(f):
            continue
        key = (_vid(f), _purl(f))
        if key in seen:
            continue
        seen.add(key)
        st, extra = _status(f)
        aliases = [a for a in (f.get("aliases") or []) if a != _vid(f)][:5]
        stmts.append({"vulnerability": {"name": _vid(f), **({"aliases": aliases} if aliases else {})},
                      "products": [{"@id": _purl(f), "identifiers": {"purl": _purl(f)}}],
                      "status": st, **extra, "timestamp": (f.get("triage") or {}).get("at", now)[:19] + "Z"
                      if (f.get("triage") or {}).get("at") else now})
    h = hashlib.sha256(f"{product}{now}{len(stmts)}".encode()).hexdigest()[:16]
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"https://openvex.dev/docs/myelin-{h}", "author": author,
            "role": "Document Creator", "timestamp": now, "version": 1, "tooling": "NERvvE DevSecOps", "statements": stmts}


def cyclonedx_vex(findings, product: str, now=None) -> dict:
    now = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    comps, vulns, seen = {}, [], set()
    state = {"fixed": "resolved", "not_affected": "not_affected", "affected": "exploitable", "under_investigation": "in_triage"}
    for f in findings:
        if f.get("engine") not in ("sca", "container") or not _vid(f):
            continue
        p = _purl(f)
        key = (_vid(f), p)
        if key in seen:
            continue
        seen.add(key)
        comps.setdefault(p, {"type": "library", "bom-ref": p, "name": f.get("package") or p, "version": f.get("version") or "",
                             "purl": p})
        st, extra = _status(f)
        analysis = {"state": state[st]}
        if st == "not_affected":
            analysis.update(justification=CDX_JUSTIFICATION[extra["justification"]], detail=extra["impact_statement"])
        elif extra.get("action_statement"):
            analysis.update(response=["update"] if f.get("fixed_version") else ["will_not_fix"] if f.get("status") == "risk_accepted"
                            else ["workaround_available"], detail=extra["action_statement"])
        v = {"id": _vid(f), "source": {"name": "NVD" if _vid(f).startswith("CVE-") else "OSV"}, "analysis": analysis,
             "affects": [{"ref": p}]}
        if f.get("cvss") is not None:
            v["ratings"] = [{"score": f["cvss"], "severity": f.get("severity"), "method": "CVSSv31"}]
        vulns.append(v)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": now, "tools": [{"vendor": "NERvvE DevSecOps", "name": "NERvvE DevSecOps"}],
                         "component": {"type": "application", "name": product, "bom-ref": product}},
            "components": list(comps.values()), "vulnerabilities": vulns}




def match_statements(findings: list[dict], documents: list[dict]) -> tuple[list[tuple[dict, dict]], int]:
    """Exact (vulnerability id or alias, component purl) matches between findings and VEX statements.
    Conflicting statements for the same pair are ambiguous and never applied. Returns (matches, ambiguous)."""
    statements = []
    for doc in documents:
        statements.extend(normalize_document(doc))
    grouped = {}
    for st in statements:
        grouped.setdefault((_norm_id(st["vulnerability"]), _norm_purl(st["purl"])), []).append(st)
    out, ambiguous = [], 0
    for f in findings:
        if f.get("engine") not in ("sca", "container"):
            continue
        ids = {_norm_id(x) for x in [f.get("cve"), f.get("advisory"), f.get("rule_id")] + list(f.get("aliases") or []) if x}
        purl = _norm_purl(_purl(f))
        hits = [st for (vid, comp), items in grouped.items() if vid in ids and comp == purl for st in items]
        if not hits:
            continue
        if len({h["state"] for h in hits}) != 1:
            ambiguous += 1
            continue
        out.append((f, sorted(hits, key=lambda h: (h.get("timestamp") or "", h["source"]))[-1]))
    return out, ambiguous
