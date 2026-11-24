# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Cloud-native application protection: cloud posture (CSPM), Kubernetes posture (KSPM), identity and entitlements
(CIEM), runtime workload protection (CWPP), code-to-cloud links and attack paths.

    inv = inventory.load(doc)          # or collect_azure / collect_aws / collect_gcp / collect_k8s .collect(...)
    findings = evaluate(inv)           # CSPM / KSPM / CIEM findings in the unified finding schema
"""
from . import ciem, cspm, inventory, kspm  # noqa: F401 -- inventory is part of the package API

ENGINES = {"azure": ["cspm", "ciem"], "aws": ["cspm", "ciem"], "gcp": ["cspm", "ciem"], "kubernetes": ["kspm", "ciem"]}


def evaluate(inv: dict) -> list[dict]:
    if inv.get("provider") == "kubernetes":
        out = kspm.evaluate(inv)
    else:
        out = cspm.evaluate(inv)
    return out + ciem.evaluate(inv)


def summary(inv: dict) -> dict:
    types = {}
    for r in inv.get("resources") or []:
        types[r["type"]] = types.get(r["type"], 0) + 1
    return {"provider": inv["provider"], "account": inv["account"], "collected_at": inv.get("collected_at"),
            "resources": len(inv.get("resources") or []), "identities": len(inv.get("identities") or []),
            "grants": len(inv.get("grants") or []), "types": types, "collector": inv.get("collector") or {"source": "import"}}


def catalogue() -> list[dict]:
    return [dict(r, engine="cspm") for r in cspm.catalogue()] + [dict(r, engine="kspm") for r in kspm.catalogue()] + \
        [dict(r, engine="ciem") for r in ciem.catalogue()]
