# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Feed normalization, durable revisions and scan-time tenant matching."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import advisory_feeds as feeds
from myelin_engine import advisories, orchestrator


GHSA = {
    "ghsa_id": "GHSA-test-pipeline",
    "cve_id": "CVE-2025-98765",
    "summary": "Example component advisory",
    "updated_at": "2026-10-21T11:00:00Z",
    "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "Intel_Demo"},
                         "vulnerable_version_range": ">= 1.0, < 2.0", "first_patched_version": "2.0"}],
}


def test_osv_batch_hydrates_details_and_follows_per_query_cursor():
    def request(method, url, **kw):
        if method == "GET":
            return SimpleNamespace(content=b"{}", json=lambda: {
                "id": url.rsplit("/", 1)[-1], "modified": "2026-10-21T11:00:00Z",
                "references": [{"url": "https://example.test/reference"}],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "intel-demo"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}]}]})
        query, = kw["json"]["queries"]
        page = query.get("page_token")
        assert page in (None, "next")
        row = {"vulns": [{"id": "OSV-EXAMPLE-2" if page else "OSV-EXAMPLE-1"}]}
        if not page:
            row["next_page_token"] = "next"
        return SimpleNamespace(content=b"{}", json=lambda: {"results": [row]})

    records = feeds.collect("OSV", request, purls=["pkg:pypi/intel-demo@1.1"])
    assert {r["advisory_id"] for r in records} == {"OSV-EXAMPLE-1", "OSV-EXAMPLE-2"}
    assert all(r["payload"]["package_keys"] == ["pypi:intel-demo"] for r in records)
    component = {"ecosystem": "pypi", "name": "intel-demo", "version": "1.1"}
    matches = advisories.evaluate([component], lambda keys, cves: records, [])
    assert len(matches) == 2 and all(v["fixed"] == "2.0" for _, v in matches)


def test_github_changes_paginates_and_refuses_a_truncated_window():
    def request(method, url, **kw):
        assert url == feeds.GITHUB and method == "GET" and ".." in kw["params"]["modified"]
        cursor = kw["params"].get("after")
        links = {} if cursor else {"next": {"url": feeds.GITHUB + "?after=trusted-next"}}
        row = {**GHSA, "ghsa_id": GHSA["ghsa_id"] + "-2"} if cursor else GHSA
        return SimpleNamespace(content=b"{}", links=links, json=lambda: [row])

    scope = {"window_start": "2026-10-21T10:00:00Z", "window_end": "2026-10-21T12:00:00Z"}
    rows = feeds.collect("GITHUB", request, scope={**scope, "limit": 2})
    assert len(rows) == 2 and rows[0]["payload"]["package_keys"] == ["pypi:intel-demo"]
    with pytest.raises(feeds.WindowTooLarge):
        feeds.collect("GITHUB", request, scope={**scope, "limit": 1})


def test_vendor_requires_explicit_affected_product_identity():
    purl = "pkg:rpm/redhat/intel-demo@1.1?arch=x86_64"
    doc = {"document": {"publisher": {"namespace": "https://www.redhat.com"},
                        "tracking": {"id": "RHSA-2026:1234", "current_release_date": "2026-10-21T11:00:00Z"}},
           "product_tree": {"full_product_names": [
               {"product_id": "a", "product_identification_helper": {"purl": purl}},
               {"product_id": "f", "product_identification_helper": {"purl": purl.replace("1.1", "2.0")}}]},
           "vulnerabilities": [{"cve": GHSA["cve_id"], "product_status": {"known_affected": ["a"], "fixed": ["f"]}}]}
    record = advisories.normalize("REDHAT", doc)
    comps = [{"ecosystem": "rpm", "name": "redhat/intel-demo", "version": "1.1", "purl": u}
             for u in (purl, purl.replace("x86_64", "aarch64"), purl.replace("1.1", "2.0"))]
    matches = advisories.evaluate(comps, lambda keys, cves: [record], [])
    assert [c for c, _ in matches] == comps[:1]
    assert record["payload"]["fixed_products"] == [purl.replace("1.1", "2.0")]


def test_changes_queue_does_not_need_existing_findings_and_partial_cannot_advance(monkeypatch):
    from app import main
    from app.store import DemoStore
    from fastapi.testclient import TestClient

    store = DemoStore({"tenant": {"name": "pipeline test"}, "audit": [], "findings": [], "repos": []})
    store.audit_event = lambda *args: None
    monkeypatch.setattr(main, "DEMO", store)
    monkeypatch.setattr(feeds, "collect", lambda *a, **kw: (_ for _ in ()).throw(feeds.WindowTooLarge("narrower window")))
    # Call the route function with an authorized context to isolate feed behavior
    # from the seeded demo authentication and licence fixtures.
    scope = main.AdvisorySyncIn(mode="changes")
    item = main.start_advisory_sync("NVD", scope, SimpleNamespace(store=store, p=SimpleNamespace(actor="operator")))["job"]
    main._run_advisory_feed_sync(item["id"], "NVD", main.DEMO_TENANT, [], [], "operator", scope=item["counters"])
    assert item["status"] == "partial" and store.advisory_watermark("NVD", []) is None
    assert TestClient(main.app).get("/api/health").status_code == 200


def test_postgres_updates_next_scan_and_preserves_tenant_isolation(tmp_path, monkeypatch):
    from app.db import admin
    from app.store import PgStore
    from tests import pg

    if not pg.PG:
        pytest.skip("requires PostgreSQL integration database")
    monkeypatch.setenv("MYELIN_OFFLINE", "1")
    urls = pg.provision()
    try:
        store_a = PgStore(urls["app"], admin.create_tenant(urls["owner"], "feeds-a", "Feeds A"))
        store_b = PgStore(urls["app"], admin.create_tenant(urls["owner"], "feeds-b", "Feeds B"))
        (tmp_path / "requirements.txt").write_text("intel-demo==1.4\n")
        def scan(store):
            res = orchestrator.scan(str(tmp_path), engines=["sca"], use_external=False, advisory_lookup=store.advisories_for)
            assert not any("tenant advisory store unavailable" in x for x in res["intelligence"]["errors"]), res["intelligence"]
            return [f for f in res["findings"] if f.get("cve") == GHSA["cve_id"]]

        assert scan(store_a) == []
        store_a.upsert_advisories("GITHUB", [advisories.normalize("GITHUB", GHSA)])
        store_a.upsert_advisories("NVD", [advisories.normalize("NVD", {
            "id": GHSA["cve_id"], "lastModified": GHSA["updated_at"],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}]},
            "references": [{"url": "https://example.test/nvd-reference"}]})])
        found, = scan(store_a)
        assert (found["fixed_version"], found["cvss"], found["advisory_sources"]) == ("2.0", 8.1, ["GITHUB", "NVD"])
        assert found["references"] == ["https://example.test/nvd-reference"] and scan(store_b) == []
        (tmp_path / "requirements.txt").write_text("intel-demo==2.0\n")
        assert scan(store_a) == []
        (tmp_path / "requirements.txt").write_text("intel-demo==1.4\n")
        newer = {**GHSA, "updated_at": "2026-10-22T11:00:00Z", "withdrawn_at": "2026-10-22T11:00:00Z"}
        store_a.upsert_advisories("GITHUB", [advisories.normalize("GITHUB", newer)])
        store_a.upsert_advisories("GITHUB", [advisories.normalize("GITHUB", GHSA)])
        assert scan(store_a) == []  # neither stale payload replay nor NVD metadata creates a package finding
        job = {"id": "477ba26e-c19d-4f88-9d39-474221372c82", "kind": "advisory_sync", "source": "GITHUB",
               "requested_by": "operator", "counters": {"rolling": True, "ecosystems": [],
                                                        "window_end": datetime.now(timezone.utc).isoformat()}}
        store_a.create_import_job(job)
        store_a.update_import_job(job["id"], "succeeded")
        assert store_a.advisory_watermark("GITHUB", []) == job["counters"]["window_end"]
        assert store_b.advisory_watermark("GITHUB", []) is None
    finally:
        pg.drop(urls["db"])


def test_semver_prerelease_stays_before_fixed_release():
    source = {**GHSA, "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "intel-demo"},
        "vulnerable_version_range": "< 2.0.0", "first_patched_version": "2.0.0"}]}
    record = advisories.normalize("GITHUB", source)
    components = [{"ecosystem": "npm", "name": "intel-demo", "version": v}
                  for v in ("2.0.0-rc.1", "2.0.0+build.7", "2.0.1")]
    assert [c for c, _ in advisories.evaluate(components, lambda keys, cves: [record], [])] == components[:1]
