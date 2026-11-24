# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Built-in crawler and authorised active checks against the fictional demo application (demo/vulnerable-api /portal)."""
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "engine"))
from myelin_engine import assessment, dast, dast_active  # noqa: E402

from tests.vapi import start  # noqa: E402

PORT = 8097


@pytest.fixture(scope="module")
def target():
    srv, _ = start(PORT)
    yield f"http://127.0.0.1:{PORT}"
    srv.should_exit = True


def test_crawler_discovers_links_forms_and_parameters(target):
    c = dast.Client(delay=0, max_requests=200, scope_host="127.0.0.1")
    eps = dast_active.crawl(c, target, target + "/portal")
    found = {e["url"].rsplit("/", 1)[-1]: e for e in eps}
    assert set(found) == {"greeting", "search", "statements", "continue", "download"}
    assert found["greeting"]["source"] == "form" and found["greeting"]["params"] == ["name"]
    assert all(entry["method"] == "GET" for entry in c.log)


def test_active_checks_confirm_each_injection_class(target):
    c = dast.Client(delay=0, max_requests=300, scope_host="127.0.0.1")
    fs, stats = dast_active.active_checks(c, dast_active.crawl(c, target, target + "/portal"))
    by = {f["rule_id"]: f for f in fs}
    assert set(by) == {"NM-DAST-030", "NM-DAST-031", "NM-DAST-032", "NM-DAST-033", "NM-DAST-034"}
    assert by["NM-DAST-030"]["parameter"] == "q" and by["NM-DAST-031"]["severity"] == "critical"
    assert by["NM-DAST-032"]["parameter"] == "next" and by["NM-DAST-033"]["parameter"] == "file"
    assert stats["parameters_tested"] == 5 and all(f["confirmed"] for f in fs)


def test_safe_mode_and_crawl_only_send_no_payloads(target):
    res = assessment.run(target + "/portal", None, None, None, "portal", "medium", 300, 0, True, crawl=True)
    sent = " ".join(e["url"] for e in res["request_log"])
    assert "myl" not in sent and "passwd" not in sent and "7%2A191" not in sent
    assert not [f for f in res["findings"] if f["rule_id"] in ("NM-DAST-030", "NM-DAST-031")]
    assert res["stats"]["crawled_endpoints"] == 5 and res["mode"] == "safe (read-only) with crawling"


def test_active_assessment_runs_inside_the_scope_and_budget(target):
    res = assessment.run(target + "/portal", None, None, None, "portal", "high", 400, 0, True, probe=True)
    assert {"NM-DAST-031", "NM-DAST-033"} <= {f["rule_id"] for f in res["findings"]}
    assert res["mode"] == "active checks (authorised)" and res["requests"] <= 400
    assert all(e["url"].startswith(target) or e["url"].startswith("http://127.0.0.1/") for e in res["request_log"])


def test_platform_targets_run_active_checks_only_after_ownership_is_verified(target):
    from datetime import datetime, timezone

    from fastapi.testclient import TestClient

    from app import main
    H = {"X-API-Key": "nm_demo_9f2c41e7b8"}
    c = TestClient(main.app)
    t = c.post("/api/v1/dast/targets", headers=H, json={"name": "portal-active", "base_url": target + "/portal", "active_checks": True}).json()
    assert t["config"]["active_checks"] is True and t["config"]["crawl"] is True
    c.post(f"/api/v1/dast/targets/{t['id']}/run?wait=true", headers=H)
    first = c.get(f"/api/v1/dast/targets/{t['id']}/result", headers=H).json()
    assert first["stats"]["crawled_endpoints"] == 5 and not [f for f in first["findings"] if f["rule_id"].startswith("NM-DAST-03")]
    main.TARGETS.update(main.DEMO_TENANT, t["id"], verified_at=datetime.now(timezone.utc))
    c.post(f"/api/v1/dast/targets/{t['id']}/run?wait=true", headers=H)
    second = c.get(f"/api/v1/dast/targets/{t['id']}/result", headers=H).json()
    assert {"NM-DAST-030", "NM-DAST-031"} <= {f["rule_id"] for f in second["findings"]}
    c.delete(f"/api/v1/dast/targets/{t['id']}", headers=H)
