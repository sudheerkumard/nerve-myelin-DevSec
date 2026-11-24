# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Platform administration (tenant provisioning, identity bindings, retention purge).

Runs with the OWNER connection and `SET LOCAL ROLE myelin_admin` — never from the request path of the API.
Invoked by the admin CLI (python -m app.admin_cli) and scheduled jobs.
"""
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import Evidence, Tenant, TenantIdentityBinding
from .session import engine_for


@contextmanager
def admin_tx(owner_url: str):
    with Session(engine_for(owner_url), expire_on_commit=False) as s:
        with s.begin():
            s.execute(text("SET LOCAL ROLE myelin_admin"))
            yield s


def create_tenant(owner_url: str, slug: str, name: str, plan: str = "business", devs: int = 0, region: str = "",
                  bindings: list[tuple[str, str]] | None = None, settings: dict | None = None) -> uuid.UUID:
    with admin_tx(owner_url) as s:
        t = Tenant(slug=slug, name=name, plan=plan, devs=devs, region=region,
                   settings=settings or {"retention_days": {"default": 2555}, "require_mfa": True})
        s.add(t)
        s.flush()
        for issuer, value in bindings or []:
            s.add(TenantIdentityBinding(issuer=issuer, claim_value=value, tenant_id=t.id))
        return t.id


def bind_identity(owner_url: str, tenant_id: uuid.UUID, issuer: str, claim_value: str) -> None:
    with admin_tx(owner_url) as s:
        s.add(TenantIdentityBinding(issuer=issuer, claim_value=claim_value, tenant_id=tenant_id))


def list_tenants(owner_url: str) -> list[dict]:
    with admin_tx(owner_url) as s:
        return [{"id": str(t.id), "slug": t.slug, "name": t.name, "plan": t.plan, "status": t.status}
                for t in s.scalars(select(Tenant).order_by(Tenant.slug))]


def purge_expired_evidence(owner_url: str, delete_object) -> list[str]:
    """Delete evidence past retention and not on legal hold. The database trigger independently refuses
    any deletion that violates retention or legal hold. delete_object(storage_uri) removes the stored blob
    (immutable stores reject deletion before their own retention date as a third safeguard)."""
    now = datetime.now(timezone.utc)
    purged = []
    with admin_tx(owner_url) as s:
        rows = s.scalars(select(Evidence).where(Evidence.retention_until < now, Evidence.legal_hold.is_(False))).all()
        for ev in rows:
            delete_object(ev.storage_uri)
            s.delete(ev)
            purged.append(str(ev.id))
    return purged
