# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Tenant-scoped database access.

Every request that touches tenant data runs inside `tenant_tx(tenant_id)`, which opens a transaction and
sets the transaction-local GUC `app.tenant_id`. PostgreSQL row-level security policies compare each row's
tenant_id to that value. Because the setting is transaction-local (set_config(..., true)) it can never
leak to another request through the connection pool, and if it is missing every policy evaluates to
false: queries fail closed and return no rows.
"""
import uuid
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

_ENGINES: dict[str, object] = {}


def engine_for(url: str):
    if url not in _ENGINES:
        _ENGINES[url] = create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=10, future=True)
    return _ENGINES[url]


@contextmanager
def tenant_tx(url: str, tenant_id: uuid.UUID | str):
    """Open a transaction bound to one tenant. tenant_id MUST come from a validated token or session."""
    tid = str(uuid.UUID(str(tenant_id)))  # rejects anything that is not a UUID
    with Session(engine_for(url), expire_on_commit=False) as s:
        with s.begin():
            s.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tid})
            yield s


@contextmanager
def system_tx(url: str):
    """Transaction with no tenant context: only non-tenant tables and SECURITY DEFINER lookups are visible."""
    with Session(engine_for(url), expire_on_commit=False) as s:
        with s.begin():
            yield s


def resolve_tenant_binding(url: str, issuer: str, claim_value: str) -> uuid.UUID | None:
    with system_tx(url) as s:
        row = s.execute(text("SELECT tenant_id FROM tenant_identity_bindings WHERE issuer = :i AND claim_value = :v"),
                        {"i": issuer, "v": claim_value}).first()
        return row[0] if row else None


def lookup_api_key_tenant(url: str, key_id: str) -> uuid.UUID | None:
    with system_tx(url) as s:
        row = s.execute(text("SELECT myelin_auth_api_key_tenant(:k)"), {"k": key_id}).first()
        return row[0] if row and row[0] else None


def lookup_session_tenant(url: str, id_hash: str) -> uuid.UUID | None:
    with system_tx(url) as s:
        row = s.execute(text("SELECT myelin_auth_session_tenant(:h)"), {"h": id_hash}).first()
        return row[0] if row and row[0] else None
