# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Admission-decision ingestion, the integration catalogue and plan claims."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient  # noqa: E402

from app import main, plans  # noqa: E402

c = TestClient(main.app)
H = {"X-API-Key": "nm_demo_9f2c41e7b8"}


def test_kyverno_policy_reports_become_admission_decisions():
    rep = {"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport", "metadata": {"namespace": "payments"},
           "results": [{"policy": "myelin-verify-supply-chain", "rule": "verify-signature-and-provenance", "result": "fail",
                        "message": "image signature not found", "resources": [{"kind": "Pod", "name": "web-1", "namespace": "payments"}]},
                       {"policy": "myelin-verify-supply-chain", "rule": "disallow-latest-tag", "result": "fail",
                        "resources": [{"kind": "Pod", "name": "web-2"}]},
                       {"policy": "myelin-verify-supply-chain", "rule": "verify-signature-and-provenance", "result": "pass",
                        "resources": [{"kind": "Pod", "name": "api-1"}]},
                       {"policy": "other-team-policy", "rule": "x", "result": "fail", "resources": [{"kind": "Pod", "name": "z"}]}]}
    r = c.post("/api/v1/admission/reports", headers=H, json={"reports": [rep], "cluster": "aks-prod"})
    assert r.status_code == 200 and r.json() == {"recorded": 3}
    adm = c.get("/api/supply-chain", headers=H).json()["admission_events_24h"]
    assert adm["available"] and adm["allowed"] >= 1 and adm["blocked_unsigned"] >= 1 and adm["blocked_policy"] >= 1
    assert c.post("/api/v1/admission/reports", headers=H, json={"reports": [{"kind": "Pod"}]}).status_code == 422
    names = {i["name"]: i for i in c.get("/api/integrations", headers=H).json()}
    assert names["Kubernetes admission — Kyverno policy + policy-report ingestion"]["connected"] is True


def test_catalogue_lists_only_shipped_integrations():
    items = c.get("/api/integrations", headers=H).json()
    assert items and all(i["status"] in ("connected", "available") for i in items)
    text = " ".join(plans.FEATURES.values())
    for claim in ("SCIM", "30+ languages", "registry scanning", "OT/IoT", "auto-revoc"):
        assert claim not in text, claim
