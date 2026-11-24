# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
import os
import sys
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..config import settings
from ..db.models import Connector as ConnectorRow
from ..db.session import tenant_tx
from ..evidence import audit
try:   # optional module; not part of every edition
    from ..evidence import service as evidence
except ImportError:
    evidence = None
from ..store import PgStore
from . import aws, azure, github  # noqa: F401  (register connector types)
from .base import REGISTRY, ConnectorError, validate_credential_ref

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "engine"))
from myelin_engine import policy as pol  # noqa: E402
from myelin_engine.scoring import enrich  # noqa: E402


class ConnectorIn(BaseModel):
    kind: str
    name: str = Field(min_length=1, max_length=200)
    config: dict = {}
    credential_ref: str = Field(min_length=8, max_length=512)


def _row(c: ConnectorRow) -> dict:
    return {"id": str(c.id), "kind": c.kind, "name": c.name, "config": c.config, "credential_ref": c.credential_ref, "status": c.status,
            "last_sync_at": c.last_sync_at.isoformat() if c.last_sync_at else None, "last_error": c.last_error}


OVERRIDES: dict = {}     # test hook: kind -> callable(row) returning a connector with mocked transport


def router(principal_for, db_url: str, factory_overrides: dict | None = None) -> APIRouter:
    r = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])
    overrides = factory_overrides if factory_overrides is not None else OVERRIDES

    def build(c: ConnectorRow):
        cls = REGISTRY[c.kind]
        return overrides[c.kind](c) if c.kind in overrides else cls(c.config, c.credential_ref)

    @r.get("/types")
    def types(request: Request):
        principal_for(request, "connectors:read")
        return [{"kind": k, "title": v.title, "config_fields": v.config_fields, "least_privilege": v.least_privilege} for k, v in REGISTRY.items()]

    @r.get("")
    def list_connectors(request: Request):
        p = principal_for(request, "connectors:read")
        with tenant_tx(db_url, p.tenant_id) as s:
            return [_row(c) for c in s.scalars(select(ConnectorRow).order_by(ConnectorRow.created_at))]

    @r.post("")
    def create(body: ConnectorIn, request: Request):
        p = principal_for(request, "connectors:manage")
        if body.kind not in REGISTRY:
            raise HTTPException(400, f"unknown connector kind; supported: {', '.join(REGISTRY)}")
        try:
            validate_credential_ref(body.credential_ref, p.tenant_id)
            REGISTRY[body.kind](body.config, body.credential_ref, resolve=lambda _: "{}")   # validates config shape only
        except ConnectorError as e:
            raise HTTPException(400, str(e)) from None
        with tenant_tx(db_url, p.tenant_id) as s:
            c = ConnectorRow(tenant_id=p.tenant_id, kind=body.kind, name=body.name, config=body.config,
                             credential_ref=body.credential_ref, created_by=p.actor)
            s.add(c)
            s.flush()
            audit.append(s, p.tenant_id, p.actor, "connector.created", {"connector": str(c.id), "kind": c.kind, "name": c.name})
            return _row(c)

    def _get(s, cid):
        c = s.get(ConnectorRow, cid)
        if not c:
            raise HTTPException(404, "connector not found")
        return c

    @r.post("/{cid}/test")
    def test(cid: uuid.UUID, request: Request):
        p = principal_for(request, "connectors:manage")
        with tenant_tx(db_url, p.tenant_id) as s:
            c = _get(s, cid)
            try:
                res = build(c).test()
                c.status, c.last_error = "connected", None
            except Exception as e:  # noqa: BLE001
                c.status, c.last_error = "error", f"{type(e).__name__}: {e}"[:500]
                res = {"ok": False, "error": c.last_error}
            audit.append(s, p.tenant_id, p.actor, "connector.tested", {"connector": str(cid), "ok": res.get("ok", False)})
            return res

    @r.post("/{cid}/sync")
    def sync(cid: uuid.UUID, request: Request):
        """Synchronous for clarity; production deployments run this from the worker queue on a schedule."""
        p = principal_for(request, "connectors:manage")
        with tenant_tx(db_url, p.tenant_id) as s:
            c = _get(s, cid)
            conn, kind, name = build(c), c.kind, c.name
        try:
            res = conn.sync()
        except Exception as e:  # noqa: BLE001
            with tenant_tx(db_url, p.tenant_id) as s:
                c = _get(s, cid)
                c.status, c.last_error = "error", f"{type(e).__name__}: {e}"[:500]
                audit.append(s, p.tenant_id, p.actor, "connector.sync_failed", {"connector": str(cid), "error": c.last_error})
            raise HTTPException(502, "connector sync failed; see connector status") from None
        fs = [enrich(dict(f, status="open")) for f in res.findings]
        by_repo: dict[str, list] = {}
        for f in fs:
            by_repo.setdefault(f["repo"], []).append(f)
        store, new = PgStore(db_url, p.tenant_id), 0
        for repo, items in by_repo.items():
            new += store.add_scan(repo, "connector", "", items, None, pol.evaluate(items), f"connector:{name}")[1]
        with tenant_tx(db_url, p.tenant_id) as s:
            for ev_name, ev_kind, data, media in (res.evidence if evidence else []):
                evidence.collect(s, settings.evidence_store, p.tenant_id, f"connector:{name}", ev_name, ev_kind, data, media, f"{kind}-connector")
            c = _get(s, cid)
            c.status, c.last_sync_at, c.last_error = "connected", datetime.now(timezone.utc), None
            audit.append(s, p.tenant_id, p.actor, "connector.synced",
                         {"connector": str(cid), "findings": len(fs), "new": new, "assets": len(res.assets), "evidence": len(res.evidence)})
        return {"findings": len(fs), "new": new, "assets": len(res.assets), "evidence": len(res.evidence)}

    @r.delete("/{cid}")
    def remove(cid: uuid.UUID, request: Request):
        p = principal_for(request, "connectors:manage")
        with tenant_tx(db_url, p.tenant_id) as s:
            c = _get(s, cid)
            s.delete(c)
            audit.append(s, p.tenant_id, p.actor, "connector.deleted", {"connector": str(cid)})
            return {"deleted": True}

    return r
