# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Hash-chained, append-only audit log (per tenant).

hash_n = SHA-256( hash_{n-1} || canonical_json(tenant_id, ts, actor, event, detail) )
A per-tenant advisory lock serialises appends so the chain cannot fork under concurrency. The database
blocks UPDATE/DELETE (trigger + revoked privileges); `verify_chain` detects any out-of-band tampering."""
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select, text

from ..db.models import AuditEvent

GENESIS = "0" * 64


def _canonical(tenant_id, ts: datetime, actor: str, event: str, detail: dict) -> str:
    return json.dumps({"tenant_id": str(tenant_id), "ts": ts.astimezone(timezone.utc).isoformat(timespec="microseconds"),
                       "actor": actor, "event": event, "detail": detail}, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(prev: str, tenant_id, ts, actor, event, detail) -> str:
    return hashlib.sha256((prev + _canonical(tenant_id, ts, actor, event, detail)).encode()).hexdigest()


def append(session, tenant_id, actor: str, event: str, detail: dict | None = None) -> AuditEvent:
    detail = detail or {}
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:t))"), {"t": "audit:" + str(tenant_id)})
    prev = session.execute(select(AuditEvent.hash).where(AuditEvent.tenant_id == tenant_id)
                           .order_by(AuditEvent.id.desc()).limit(1)).scalar() or GENESIS
    ts = datetime.now(timezone.utc)
    ev = AuditEvent(tenant_id=tenant_id, ts=ts, actor=actor, event=event, detail=detail, prev_hash=prev,
                    hash=entry_hash(prev, tenant_id, ts, actor, event, detail))
    session.add(ev)
    session.flush()
    return ev


def verify_chain(session, tenant_id) -> dict:
    prev, n = GENESIS, 0
    for ev in session.scalars(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id).order_by(AuditEvent.id)):
        if ev.prev_hash != prev or ev.hash != entry_hash(prev, ev.tenant_id, ev.ts, ev.actor, ev.event, ev.detail):
            return {"valid": False, "broken_at": ev.id, "checked": n}
        prev, n = ev.hash, n + 1
    return {"valid": True, "checked": n, "head": prev}
