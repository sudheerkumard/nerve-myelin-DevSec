"""Audit-chain verification endpoint (hash-chained, append-only audit log).

Copyright (c) 2026 Sudheer Kumar. All rights reserved.
Kept separate from the evidence-store API so the audit log works in every edition.
"""
from fastapi import APIRouter, Request

from ..db.session import tenant_tx
from . import audit


def router(principal_for, db_url: str) -> APIRouter:
    r = APIRouter(prefix="/api/v1/evidence", tags=["audit"])

    @r.get("/audit/verify")
    def audit_verify(request: Request):
        p = principal_for(request, "audit:read")
        with tenant_tx(db_url, p.tenant_id) as s:
            return audit.verify_chain(s, p.tenant_id)

    return r
