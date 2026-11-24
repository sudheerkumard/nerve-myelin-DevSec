# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Production operations: security headers, request IDs, structured JSON logs, Prometheus metrics,
liveness/readiness probes, request size limit."""
import json
import logging
import sys
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
    REQS = Counter("myelin_http_requests_total", "HTTP requests", ["method", "route", "status"])
    LAT = Histogram("myelin_http_request_seconds", "HTTP request latency", ["method", "route"],
                    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10))
    AUTHFAIL = Counter("myelin_auth_failures_total", "Authentication/authorisation failures", ["status"])
    from prometheus_client import Gauge
    LIC_DAYS = Gauge("myelin_license_days_remaining", "Days until licence expiry (negative = expired)")
    LIC_USABLE = Gauge("myelin_license_usable", "1 when the licence permits full service, 0 when restricted")
except ImportError:  # metrics optional in the CLI image
    REQS = LAT = AUTHFAIL = LIC_DAYS = LIC_USABLE = None

MAX_BODY = 25 * 1024 * 1024
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    # console is a single self-contained page; fonts from Google Fonts only
    "Content-Security-Policy": ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                                "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; "
                                "base-uri 'none'; form-action 'self'"),
}


class JsonFormatter(logging.Formatter):
    def format(self, r: logging.LogRecord) -> str:
        d = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(r.created)) + "Z", "level": r.levelname, "logger": r.name, "msg": r.getMessage()}
        for k in ("request_id", "tenant", "actor", "method", "path", "status", "ms"):
            if hasattr(r, k):
                d[k] = getattr(r, k)
        return json.dumps(d)


def _logger(level: str) -> logging.Logger:
    log = logging.getLogger("myelin")
    if not log.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(JsonFormatter())
        log.addHandler(h)
    log.setLevel(level.upper())
    log.propagate = False
    return log


def install(app: FastAPI, settings) -> None:
    log = _logger(settings.log_level)

    @app.middleware("http")
    async def _ops(request: Request, call_next):
        rid = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        t0 = time.perf_counter()
        response = await call_next(request)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        route = getattr(request.scope.get("route"), "path", "unmatched")
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith(("/api", "/auth")):
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = rid
        if REQS:
            REQS.labels(request.method, route, response.status_code).inc()
            LAT.labels(request.method, route).observe(ms / 1000)
            if response.status_code in (401, 403):
                AUTHFAIL.labels(response.status_code).inc()
        p = getattr(request.state, "principal", None)
        if route not in ("/healthz", "/readyz", "/metrics"):
            log.info("request", extra={"request_id": rid, "method": request.method, "path": route, "status": response.status_code, "ms": ms,
                                       "tenant": str(p.tenant_id) if p else None, "actor": p.actor if p else None})
        return response


def register_readiness(app: FastAPI, settings, db_url, auth) -> None:
    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "alive"}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        checks = {}
        if db_url:
            try:
                from ..db.session import system_tx
                with system_tx(db_url) as s:
                    s.execute(text("SELECT 1"))
                    rev = s.execute(text("SELECT version_num FROM alembic_version")).scalar()
                checks["database"] = "ok"
                checks["schema"] = rev
            except Exception as e:  # noqa: BLE001
                checks["database"] = f"error: {type(e).__name__}"
        if auth:
            checks["identity_providers"] = len(auth.idps)
        ok = all(not str(v).startswith("error") for v in checks.values())
        return JSONResponse({"status": "ready" if ok else "not_ready", "checks": checks}, status_code=200 if ok else 503)

    if settings.metrics_enabled and REQS:
        @app.get("/metrics", include_in_schema=False)
        def metrics():
            return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
