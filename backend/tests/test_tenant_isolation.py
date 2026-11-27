# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Cross-tenant isolation tests against a real PostgreSQL with production roles and RLS.

Every test connects as the application login (member of myelin_app, NOBYPASSRLS) — the same privileges
the API has in production."""
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text, update, delete
from sqlalchemy.exc import DBAPIError, ProgrammingError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests.pg import needs_pg, provision, drop  # noqa: E402

pytestmark = needs_pg


@pytest.fixture(scope="module")
def env():
    from app.db import admin
    from app.db.models import ApiKey, AuditEvent, Evidence, Finding, PolicyVersion, PolicyApprovalRequest, PolicyBinding
    from app.db.session import tenant_tx
    urls = provision()
    a = admin.create_tenant(urls["owner"], "acme", "Acme Bank", bindings=[("https://kc/realms/myelin", "acme")])
    b = admin.create_tenant(urls["owner"], "globex", "Globex Insurance", bindings=[("https://kc/realms/myelin", "globex")])
    for tid, n in ((a, "a"), (b, "b")):
        version_id = uuid.uuid4()
        with tenant_tx(urls["app"], tid) as s:
            s.add(Finding(id=f"NM-{n}1", tenant_id=tid, fingerprint=f"fp-{n}1", repo=f"{n}-repo", engine="sca",
                          severity="critical", priority="P0", mrs=91.0, data={"title": f"secret of {n}"}))
            s.add(ApiKey(id=f"key{n}", tenant_id=tid, name="ci", secret_hash="x" * 64, roles=["integration"], created_by="t"))
            s.add(AuditEvent(tenant_id=tid, actor="t", event="seed", detail={}, prev_hash="0" * 64, hash="1" * 64))
            s.add(Evidence(tenant_id=tid, name="report.json", kind="scan-report", sha256="a" * 64, size=1, media_type="application/json",
                           storage_uri=f"file:///e/{n}", source="test", collected_by="t",
                           retention_until=datetime.now(timezone.utc) + timedelta(days=365)))
            s.add(PolicyVersion(id=version_id, tenant_id=tid, name="baseline", version=1, content_sha256=(n * 64)[:64],
                content={"mode": "enforce", "gates": [], "exceptions": []}, status="published", created_by="test"))
            s.flush()
            s.add(PolicyApprovalRequest(id=uuid.uuid4(), tenant_id=tid, policy_version_id=version_id,
                requested_by=f"author-{n}", status="pending"))
            s.add(PolicyBinding(id=uuid.uuid4(), tenant_id=tid, scope_type="repository", scope_key=f"{n}-repo",
                policy_version_id=version_id, updated_by="test"))
    yield {"urls": urls, "a": a, "b": b}
    drop(urls["db"])


def test_tenant_sees_only_its_own_rows(env):
    from app.db.models import Finding
    from app.db.session import tenant_tx
    with tenant_tx(env["urls"]["app"], env["a"]) as s:
        rows = s.scalars(select(Finding)).all()
    assert [r.id for r in rows] == ["NM-a1"]


def test_direct_lookup_of_other_tenants_id_returns_nothing(env):
    from app.db.models import Finding
    from app.db.session import tenant_tx
    with tenant_tx(env["urls"]["app"], env["a"]) as s:
        assert s.get(Finding, "NM-b1") is None
        assert s.execute(text("SELECT count(*) FROM findings WHERE id = 'NM-b1'")).scalar() == 0


def test_no_tenant_context_fails_closed_on_every_table(env):
    from app.db.models import TENANT_TABLES
    from app.db.session import system_tx
    with system_tx(env["urls"]["app"]) as s:
        for t in TENANT_TABLES + ["tenants"]:
            assert s.execute(text(f"SELECT count(*) FROM {t}")).scalar() == 0, t


def test_cannot_insert_row_for_another_tenant(env):
    from app.db.models import Finding
    from app.db.session import tenant_tx
    with pytest.raises(DBAPIError, match="row-level security"):
        with tenant_tx(env["urls"]["app"], env["a"]) as s:
            s.add(Finding(id="NM-x", tenant_id=env["b"], fingerprint="fp-x", repo="r", engine="sca",
                          severity="low", priority="P3", mrs=1, data={}))


def test_cannot_update_or_delete_other_tenants_rows(env):
    from app.db.models import Finding
    from app.db.session import tenant_tx
    with tenant_tx(env["urls"]["app"], env["a"]) as s:
        assert s.execute(update(Finding).where(Finding.id == "NM-b1").values(status="fixed")).rowcount == 0
        assert s.execute(delete(Finding).where(Finding.id == "NM-b1")).rowcount == 0
    with tenant_tx(env["urls"]["app"], env["b"]) as s:
        assert s.get(Finding, "NM-b1").status == "open"


def test_cannot_move_own_row_into_another_tenant(env):
    from app.db.models import Finding
    from app.db.session import tenant_tx
    with pytest.raises(DBAPIError, match="row-level security"):
        with tenant_tx(env["urls"]["app"], env["a"]) as s:
            s.execute(update(Finding).where(Finding.id == "NM-a1").values(tenant_id=env["b"]))


def test_tenant_context_does_not_leak_through_the_pool(env):
    from app.db.session import system_tx, tenant_tx
    with tenant_tx(env["urls"]["app"], env["a"]) as s:
        assert s.execute(text("SELECT current_setting('app.tenant_id', true)")).scalar() == str(env["a"])
    for _ in range(5):
        with system_tx(env["urls"]["app"]) as s:
            assert (s.execute(text("SELECT current_setting('app.tenant_id', true)")).scalar() or "") == ""


def test_tenant_id_must_be_a_uuid(env):
    from app.db.session import tenant_tx
    with pytest.raises(ValueError):
        with tenant_tx(env["urls"]["app"], "' OR 1=1 --"):
            pass


def test_app_role_cannot_disable_rls_or_escalate(env):
    from app.db.session import system_tx
    for stmt in ("ALTER TABLE findings DISABLE ROW LEVEL SECURITY", "ALTER TABLE findings NO FORCE ROW LEVEL SECURITY",
                 "SET ROLE myelin_admin", "SET ROLE myelin_auth", "DROP POLICY tenant_isolation ON findings",
                 "SET session_replication_role = replica", "INSERT INTO tenant_identity_bindings (issuer, claim_value, tenant_id) "
                 "VALUES ('x', 'y', gen_random_uuid())"):
        with pytest.raises((ProgrammingError, DBAPIError)):
            with system_tx(env["urls"]["app"]) as s:
                s.execute(text(stmt))


def test_auth_lookup_functions_reveal_only_tenant_id(env):
    from app.db.session import lookup_api_key_tenant
    assert lookup_api_key_tenant(env["urls"]["app"], "keya") == env["a"]
    assert lookup_api_key_tenant(env["urls"]["app"], "keyb") == env["b"]
    assert lookup_api_key_tenant(env["urls"]["app"], "nope") is None


def test_identity_binding_resolves_tenant(env):
    from app.db.session import resolve_tenant_binding
    assert resolve_tenant_binding(env["urls"]["app"], "https://kc/realms/myelin", "globex") == env["b"]
    assert resolve_tenant_binding(env["urls"]["app"], "https://evil/realms/myelin", "globex") is None


def test_audit_log_is_append_only(env):
    from app.db.session import tenant_tx
    for stmt in ("UPDATE audit_log SET actor = 'x'", "DELETE FROM audit_log"):
        with pytest.raises((ProgrammingError, DBAPIError)):
            with tenant_tx(env["urls"]["app"], env["a"]) as s:
                s.execute(text(stmt))


def test_evidence_cannot_be_deleted_or_altered_even_by_admin(env):
    from app.db import admin
    for stmt in ("DELETE FROM evidence", "UPDATE evidence SET sha256 = repeat('b', 64)",
                 "UPDATE evidence SET retention_until = now()"):
        with pytest.raises(DBAPIError, match="retention|cannot be altered"):
            with admin.admin_tx(env["urls"]["owner"]) as s:
                s.execute(text(stmt))


def test_app_role_cannot_delete_evidence(env):
    from app.db.session import tenant_tx
    with pytest.raises(ProgrammingError, match="permission denied"):
        with tenant_tx(env["urls"]["app"], env["a"]) as s:
            s.execute(text("DELETE FROM evidence"))


def test_policy_governance_rows_are_tenant_isolated(env):
    from app.db.models import PolicyVersion, PolicyApprovalRequest, PolicyBinding
    from app.db.session import tenant_tx
    with tenant_tx(env["urls"]["app"], env["a"]) as s:
        assert len(s.scalars(select(PolicyVersion)).all()) == 1
        assert len(s.scalars(select(PolicyApprovalRequest)).all()) == 1
        assert len(s.scalars(select(PolicyBinding)).all()) == 1
        assert s.execute(text("SELECT count(*) FROM policy_versions WHERE name = 'baseline' AND tenant_id = :tid"),
                         {"tid": str(env["b"])}).scalar() == 0


def test_policy_version_definition_cannot_be_mutated_or_deleted(env):
    from app.db.models import PolicyVersion
    from app.db.session import tenant_tx
    with tenant_tx(env["urls"]["app"], env["a"]) as s:
        version = s.scalars(select(PolicyVersion)).one()
        version.status = "superseded"  # lifecycle metadata is mutable
    with pytest.raises(DBAPIError, match="policy version content is immutable"):
        with tenant_tx(env["urls"]["app"], env["a"]) as s:
            version = s.scalars(select(PolicyVersion)).one()
            version.content = {"mode": "audit", "gates": [], "exceptions": []}
    with pytest.raises(DBAPIError, match="policy versions are retained"):
        with tenant_tx(env["urls"]["app"], env["a"]) as s:
            s.execute(delete(PolicyVersion))


def test_cloud_inventories_accounts_and_runtime_events_are_isolated(env):
    """Cloud inventories, accounts and runtime events written for one tenant are invisible to another."""
    import json as _json
    from app import cnapp
    root = os.path.join(os.path.dirname(__file__), "..", "..", "demo", "cloud")
    store = cnapp.PgCloud(env["urls"]["app"])
    with open(os.path.join(root, "aks-prod-cin.kubectl.json"), "rb") as fh:
        inv = cnapp.load_upload(fh.read(), "kubernetes", "acme-cluster")
    store.save_inventory(env["a"], inv, "t")
    store.save_inventory(env["a"], inv, "t")                                   # upsert, not a duplicate
    acc = cnapp.new_account({"provider": "aws", "name": "acme aws", "config": {"regions": ["ap-south-1"]}}, "t")
    store.add_account(env["a"], acc)
    with open(os.path.join(root, "runtime-events.json")) as fh:
        events, _ = cnapp.runtime_ingest(store, env["a"], _json.load(fh), "acme-cluster")
    assert len(events) == 5
    since = "2000-01-01T00:00:00+00:00"
    assert [i["key"] for i in store.list_inventories(env["a"])] == ["k8s:acme-cluster"]
    assert len(store.list_events(env["a"], since)) == 5 and len(store.list_accounts(env["a"])) == 1
    assert store.list_inventories(env["b"]) == [] and store.inventory_docs(env["b"]) == []
    assert store.list_events(env["b"], since) == [] and store.list_accounts(env["b"]) == []
    with pytest.raises(cnapp.CloudError):
        store.get_account(env["b"], acc["id"])
    with pytest.raises(cnapp.CloudError):
        store.delete_inventory(env["b"], "k8s:acme-cluster")


def test_sbom_projects_and_repository_purge_in_postgres(env):
    from app.store import PgStore
    from app.db.models import Finding
    from app.db.session import tenant_tx
    a = PgStore(env["urls"]["app"], env["a"])
    b = PgStore(env["urls"]["app"], env["b"])
    a.save_sbom_project("suite", {"name": "suite", "components": 2, "summary": {}, "licences": [{"package": "x"}],
                                  "vulnerabilities": [], "sbom": {"bomFormat": "CycloneDX", "components": []}}, "t")
    a.save_sbom_project("suite", {"name": "suite", "components": 3, "summary": {}, "licences": [], "vulnerabilities": [],
                                  "sbom": {"bomFormat": "CycloneDX"}}, "t")       # replace, not duplicate
    assert [p["components"] for p in a.sbom_projects()] == [3] and "licences" not in a.sbom_projects()[0]
    assert a.sbom_project("suite")["sbom"]["bomFormat"] == "CycloneDX" and b.sbom_project("suite") is None
    assert not [p for p in a.pipelines() if str(p.get("repo", "")).startswith("sbom-project:")]
    assert b.delete_sbom_project("suite") is False and a.delete_sbom_project("suite") is True
    with tenant_tx(env["urls"]["app"], env["a"]) as s:
        s.add(Finding(id="NM-purge", tenant_id=env["a"], fingerprint="fp-purge", repo="gone-repo", engine="sast",
                      severity="low", priority="P3", mrs=1.0, data={"title": "x"}))
    assert b.purge_repo("gone-repo")["findings"] == 0                                 # other tenant: nothing
    assert a.purge_repo("gone-repo")["findings"] == 1 and not [f for f in a.findings() if f["repo"] == "gone-repo"]
