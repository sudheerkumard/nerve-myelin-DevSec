# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Orion Payments API (fictional) — a deliberately misconfigured API for NERvvE DevSecOps DAST demonstrations.
DO NOT DEPLOY. Run locally only:  python demo/vulnerable-api/app.py   →  http://127.0.0.1:8090
"""
import traceback

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPBearer

bearer = HTTPBearer(auto_error=False)
app = FastAPI(title="Orion Payments API", version="2.3.1")   # /docs and /openapi.json left public (inventory issue)


@app.middleware("http")
async def weak_headers(request: Request, call_next):
    try:
        resp = await call_next(request)
    except Exception:                                          # verbose errors leak internals
        return PlainTextResponse(traceback.format_exc(), status_code=500)
    origin = request.headers.get("origin")
    if origin:                                                 # CORS reflects any origin, with credentials
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Server"] = "Kestrel/6.0.1"                   # version disclosure
    resp.headers["X-Powered-By"] = "ASP.NET 4.0.30319"
    if request.method == "OPTIONS":
        resp.headers["Allow"] = "GET, POST, OPTIONS, TRACE"
    return resp


@app.options("/{path:path}")
def options(path: str):
    return PlainTextResponse("")


@app.get("/")
def root():
    r = JSONResponse({"service": "orion-payments", "status": "ok"})
    r.set_cookie("session", "demo-session-id")                # cookie without Secure / HttpOnly / SameSite
    return r


# Declared as secured in the OpenAPI spec, but the dependency result is never checked (broken authentication).
@app.get("/api/v1/accounts", openapi_extra={"security": [{"HTTPBearer": []}]})
def accounts():
    return [{"id": "ACC-1001", "holder": "A. Sharma", "balance": 15230.55}]


@app.get("/api/v1/health", openapi_extra={"security": []})
def health():
    return {"ok": True}


@app.get("/api/v1/transfers", openapi_extra={"security": [{"HTTPBearer": []}]})
def transfers(request: Request):
    if not request.headers.get("authorization"):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return []


# ---------------- multi-user part (for authorisation testing) ----------------
USERS = {"alice-token": ("alice", "customer"), "bob-token": ("bob", "customer"), "admin-token": ("admin", "admin")}
ACCOUNTS = {"ACC-2001": {"owner": "alice", "balance": 8120.40}, "ACC-2002": {"owner": "alice", "balance": 77.10},
            "ACC-3001": {"owner": "bob", "balance": 450.00}}
CARDS = {"CRD-71": "alice", "CRD-88": "bob"}


def _who(request: Request):
    tok = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
    return USERS.get(tok)


def _need(request: Request):
    u = _who(request)
    if not u:
        raise _Unauth()
    return u


class _Unauth(Exception):
    pass


@app.exception_handler(_Unauth)
def _unauth(request, exc):
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)


SEC = {"security": [{"HTTPBearer": []}]}


@app.get("/api/v2/me/accounts", openapi_extra=SEC)
def my_accounts(request: Request):
    user, _ = _need(request)
    return {"items": [{"accountId": k, "balance": v["balance"]} for k, v in ACCOUNTS.items() if v["owner"] == user]}


@app.get("/api/v2/accounts/{accountId}", openapi_extra=SEC)
def account(accountId: str, request: Request):
    _need(request)                                            # BOLA: authenticated, but ownership never checked
    a = ACCOUNTS.get(accountId)
    return {"accountId": accountId, **a} if a else JSONResponse({"detail": "not found"}, status_code=404)


@app.get("/api/v2/me/cards", openapi_extra=SEC)
def my_cards(request: Request):
    user, _ = _need(request)
    return [{"cardId": k} for k, o in CARDS.items() if o == user]


@app.get("/api/v2/cards/{cardId}", openapi_extra=SEC)
def card(cardId: str, request: Request):
    user, _ = _need(request)                                  # control: ownership enforced correctly
    if CARDS.get(cardId) != user:
        return JSONResponse({"detail": "not found"}, status_code=404)
    return {"cardId": cardId, "last4": "4417"}


@app.get("/api/v2/me/profile", openapi_extra=SEC)
def profile(request: Request):
    user, _ = _need(request)                                  # excessive data exposure
    return {"username": user, "email": f"{user}@orion.example", "password_hash": "$2b$12$Qk8...", "pan": "ABCDE1234F"}


@app.get("/api/v2/admin/users", openapi_extra={**SEC, "tags": ["admin"]})
def admin_users(request: Request):
    _need(request)                                            # BFLA: any logged-in user can call an admin function
    return [{"username": u, "role": r} for u, r in USERS.values()]


@app.get("/api/v2/admin/audit", openapi_extra={**SEC, "tags": ["admin"]})
def admin_audit(request: Request):
    _, role = _need(request)                                  # control: role enforced correctly
    if role != "admin":
        return JSONResponse({"detail": "forbidden"}, status_code=403)
    return [{"event": "login", "user": "alice"}]


# --- web front end with injection flaws for the crawler and the authorised active checks (all simulated) ---------
from fastapi.responses import HTMLResponse, RedirectResponse  # noqa: E402


@app.get("/portal", response_class=HTMLResponse)
def portal():
    return ("<html><body><h1>Orion customer portal</h1><a href='/portal/search?q=cards'>Search</a> "
            "<a href='/portal/statements?account=ACC-1001'>Statements</a> <a href='/portal/continue?next=/portal'>Continue</a> "
            "<a href='/portal/download?file=terms.pdf'>Terms</a><form action='/portal/greeting' method='get'>"
            "<input name='name'><input type='submit'></form></body></html>")


@app.get("/portal/search", response_class=HTMLResponse)
def portal_search(q: str = ""):
    return f"<html><body>Results for {q}</body></html>"           # reflected without encoding (XSS)


@app.get("/portal/statements")
def portal_statements(account: str = ""):
    if "'" in account:                                           # simulated database error leak (SQL injection)
        return PlainTextResponse(f'ERROR: syntax error at or near "{account[-3:]}" LINE 1: SELECT * FROM statements WHERE acct = \'{account}\'',
                                 status_code=500)
    return {"account": account, "statements": []}


@app.get("/portal/continue")
def portal_continue(next: str = "/portal"):                      # noqa: A002 - open redirect
    return RedirectResponse(next, status_code=302)


@app.get("/portal/download")
def portal_download(file: str = ""):
    if ".." in file or "%2f" in file.lower():                    # simulated traversal: returns a fake passwd file
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
    return PlainTextResponse("Terms and conditions")


@app.get("/portal/greeting", response_class=HTMLResponse)
def portal_greeting(name: str = ""):
    rendered = name.replace("{{7*191}}", "1337").replace("${7*191}", "1337")   # simulated template evaluation
    return f"<html><body>Hello {rendered.replace('<', '&lt;')}</body></html>"


@app.get("/{path:path}")
def catch_all(path: str):
    raise RuntimeError(f"Route resolution failed for {path!r}")   # surfaces as a stack trace


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi
    s = get_openapi(title=app.title, version=app.version, routes=app.routes)
    s.setdefault("components", {})["securitySchemes"] = {"HTTPBearer": {"type": "http", "scheme": "bearer"}}
    app.openapi_schema = s
    return s


app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8090, server_header=False)
