# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Independent PostgreSQL-backed MYELIN advisory worker.

Run from the backend directory:
    MYELIN_MODE=enterprise MYELIN_WORKER_TENANT_IDS=<tenant-uuid,...> python -m app.worker

The API only persists jobs. This process claims them under tenant RLS with SKIP LOCKED,
executes fixed-host feed synchronization and lets a lease expire after an ungraceful crash.
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import time
import uuid

from .config import settings

log = logging.getLogger("myelin.worker")
_STOP = False


def _stop(_signum, _frame):
    global _STOP
    _STOP = True


def main() -> int:
    if settings.mode != "enterprise":
        raise SystemExit("MYELIN worker requires MYELIN_MODE=enterprise; demo memory queues are not shared across processes")
    if not settings.database_url:
        raise SystemExit("MYELIN_DATABASE_URL must be configured for the worker")
    if not settings.worker_tenant_ids:
        raise SystemExit("MYELIN_WORKER_TENANT_IDS must contain explicit tenant UUIDs assigned to this worker")
    tenant_ids = []
    for value in settings.worker_tenant_ids:
        try:
            tenant_ids.append(uuid.UUID(value))
        except ValueError:
            raise SystemExit("MYELIN_WORKER_TENANT_IDS contains an invalid UUID") from None

    # Import the API module only after validating the worker mode and allowlist.
    from . import main as platform

    if not platform.ENTERPRISE:
        raise SystemExit("worker/API enterprise configuration mismatch")
    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    logging.basicConfig(level=settings.log_level.upper(),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    stores = [(tid, platform.PgStore(platform.DB_URL, tid)) for tid in tenant_ids]
    log.info("worker started id=%s tenant_count=%d lease_seconds=%d",
             worker_id, len(stores), settings.worker_lease_seconds)

    while not _STOP:
        claimed = False
        for tenant_id, store in stores:
            if _STOP:
                break
            try:
                n = platform.drain_advisory_jobs(store, tenant_id, worker_id, settings.worker_lease_seconds,
                                                 settings.worker_max_attempts, stop=lambda: _STOP)
                if n:
                    claimed = True
                    log.info("finished %d job(s) tenant=%s", n, tenant_id)
            except Exception:
                log.exception("worker cycle failed tenant=%s", tenant_id)
        if not claimed:
            time.sleep(settings.worker_poll_seconds)

    log.info("worker stopping id=%s", worker_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
