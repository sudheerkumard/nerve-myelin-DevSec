# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Request authentication for enterprise mode.

Accepted credentials, in order:
  1. Authorization: Bearer <JWT>   — access token from a trusted IdP (API clients, automation with OIDC)
  2. Authorization: Bearer nm_...  — tenant API key (CI pipelines, integrations); X-API-Key also accepted
  3. __Host-myelin_session cookie  — console session (BFF: tokens never reach the browser)
Unsafe methods with a session cookie must also carry X-CSRF-Token matching the session's CSRF token.

Console login uses the Authorization Code flow with PKCE (S256), state and nonce, as a confidential client.
"""
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select

from .. import secrets as sm
from ..db.models import ApiKey, User, WebSession
from ..db.session import lookup_api_key_tenant, lookup_session_tenant, resolve_tenant_binding, tenant_tx
from . import apikeys
from .crypto import b64u, consteq, decrypt, derive_key, encrypt, hmac_sha256, random_token, sign_state, verify_state
from .oidc import AuthError, IdP, TokenVerifier, load_idps
from .rbac import Principal

import logging
log = logging.getLogger("myelin.auth")

SESSION_COOKIE, CSRF_COOKIE, STATE_COOKIE = "__Host-myelin_session", "__Host-myelin_csrf", "__Host-myelin_oidc"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


class AuthService:
    def __init__(self, settings, http: httpx.Client | None = None, jwks=None):
        self.s = settings
        self.db = sm.resolve(settings.database_url, allow_plain=True)
        master = sm.resolve(settings.session_secret_ref).encode()
        self.k_session, self.k_state, self.k_refresh = (derive_key(master, p) for p in ("session", "state", "refresh"))
        self.pepper = sm.resolve(settings.api_key_pepper_ref).encode()
        self.idps: dict[str, IdP] = load_idps(settings.idp_config)
        self.by_name = {i.name: i for i in self.idps.values()}
        self.verifier = TokenVerifier(self.idps, lambda iss, v: resolve_tenant_binding(self.db, iss, v), jwks)
        self.http = http or httpx.Client(timeout=10)

    # ------------------------------------------------------------------ request authentication
    def authenticate(self, request: Request) -> Principal:
        authz = request.headers.get("authorization", "")
        bearer = authz[7:].strip() if authz.lower().startswith("bearer ") else ""
        key = bearer if bearer.startswith("nm_") else request.headers.get("x-api-key", "")
        try:
            if bearer and not bearer.startswith("nm_"):
                return self.verifier.verify(bearer)[0]
            if key:
                return self._api_key(key)
            sid = request.cookies.get(SESSION_COOKIE)
            if sid:
                return self._session(request, sid)
        except AuthError as e:
            headers = {"WWW-Authenticate": 'Bearer error="insufficient_user_authentication", acr_values="mfa"'} if e.step_up else {}
            raise HTTPException(e.status, str(e), headers=headers) from None
        raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})

    def _api_key(self, key: str) -> Principal:
        parsed = apikeys.parse(key)
        if not parsed:
            raise AuthError("malformed API key")
        key_id, secret = parsed
        tenant = lookup_api_key_tenant(self.db, key_id)
        if not tenant:
            raise AuthError("invalid API key")
        with tenant_tx(self.db, tenant) as s:
            row = s.get(ApiKey, key_id)
            if not row or not apikeys.verify(self.pepper, secret, row.secret_hash):
                raise AuthError("invalid API key")
            row.last_used_at = datetime.now(timezone.utc)
            return Principal(tenant_id=tenant, subject=f"apikey:{key_id}", issuer="myelin", roles=frozenset(row.roles),
                             name=row.name, method="api_key", mfa=False)

    def _session(self, request: Request, sid: str) -> Principal:
        h = hmac_sha256(self.k_session, sid)
        tenant = lookup_session_tenant(self.db, h)
        if not tenant:
            raise AuthError("session expired")
        now = datetime.now(timezone.utc)
        with tenant_tx(self.db, tenant) as s:
            ws = s.get(WebSession, h)
            if not ws or ws.revoked or ws.absolute_expiry < now or ws.last_seen_at + timedelta(minutes=self.s.session_idle_minutes) < now:
                if ws:
                    ws.revoked = True
                raise AuthError("session expired")
            if request.method in UNSAFE:
                sent = request.headers.get("x-csrf-token", "")
                if not sent or not consteq(hmac_sha256(self.k_session, "csrf:" + sent), ws.csrf_hash):
                    raise AuthError("CSRF token missing or invalid", 403)
            ws.last_seen_at = now
            c = ws.claims
            return Principal(tenant_id=tenant, subject=c["sub"], issuer=c["iss"], roles=frozenset(c.get("roles", [])),
                             email=c.get("email", ""), name=c.get("name", ""), method="session", mfa=c.get("mfa", False))

    # ------------------------------------------------------------------ API keys
    def create_api_key(self, p: Principal, name: str, roles: list[str], days: int = 90) -> str:
        full, key_id, secret = apikeys.generate()
        with tenant_tx(self.db, p.tenant_id) as s:
            s.add(ApiKey(id=key_id, tenant_id=p.tenant_id, name=name, secret_hash=apikeys.hash_secret(self.pepper, secret),
                         roles=roles, created_by=p.actor, expires_at=apikeys.default_expiry(days)))
        return full

    # ------------------------------------------------------------------ console login (BFF)
    def router(self) -> APIRouter:
        r = APIRouter(prefix="/auth", tags=["auth"])
        secure = self.s.cookie_secure

        @r.get("/providers")
        def providers():
            return [{"name": i.name, "type": i.type, "display_name": getattr(i, "display_name", "") or f"Sign in with {i.name}"}
                    for i in self.by_name.values()]

        @r.get("/login")
        def login(idp: str, return_to: str = "/"):
            prov = self.by_name.get(idp)
            if not prov:
                raise HTTPException(404, "unknown identity provider")
            if not return_to.startswith("/") or return_to.startswith("//"):
                return_to = "/"                                   # no open redirects
            verifier, state, nonce = random_token(48), random_token(), random_token()
            challenge = b64u(__import__("hashlib").sha256(verifier.encode()).digest())
            disc = self.verifier.jwks.discovery(prov)
            params = {"response_type": "code", "client_id": prov.client_id, "redirect_uri": self.s.public_url + "/auth/callback",
                      "scope": prov.scopes, "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
            if prov.require_mfa and prov.acr_values:
                params["acr_values"] = prov.acr_values[0]      # primary value; IdPs reject unknown acr strings
            resp = RedirectResponse(disc["authorization_endpoint"] + "?" + urlencode(params), 302)
            resp.set_cookie(STATE_COOKIE, sign_state(self.k_state, {"s": state, "n": nonce, "v": verifier, "i": prov.issuer, "r": return_to}, 600),
                            httponly=True, secure=secure, samesite="lax", path="/", max_age=600)
            return resp

        @r.get("/callback")
        def callback(request: Request, code: str = "", state: str = "", error: str = ""):
            """Browser-facing: failures render a readable page (with the same HTTP status), not raw JSON."""
            try:
                return _callback(request, code, state, error)
            except HTTPException as e:
                return _login_problem(e.status_code, str(e.detail))

        def _login_problem(status: int, detail: str):
            import html as _h
            low = detail.lower()
            if "invalid_client" in low or "unauthorized_client" in low or "client credentials" in low:
                hint = ("The platform's client secret does not match the one stored in the identity provider. On the evaluation "
                        "stack, run scripts\\windows\\start-enterprise.ps1 again (it re-synchronises the secret); otherwise ask your administrator.")
            elif "not provisioned" in low:
                hint = ("Your account names an organisation that does not exist on this platform yet. Create it first, for example "
                        "on the evaluation stack: scripts\\windows\\new-tenant.ps1 -Slug <organisation> -Name \"<display name>\" "
                        "(or myelin admin tenant-create), then sign in again. See the first-time setup guide in the documentation.")
            elif "tenant" in low:
                hint = ("Your account is not linked to an organisation. In Keycloak (realm 'myelin') open Users, select the user named "
                        "in the reason below, set the field 'RAT Flea DevSec tenant' to an existing organisation (for example acme "
                        "or globex), assign a role such as myelin-tenant-admin, save, then sign in again. On the evaluation stack, "
                        "scripts\\windows\\new-tenant.ps1 -User <username> does this for you. With another identity provider, ask "
                        "your administrator to add the tenant claim.")
            elif "multi-factor" in low or "insufficient" in low:
                hint = "Multi-factor authentication is required. Sign in again and complete the second step."
            elif "invalid_grant" in low or "expired" in low or "again" in low:
                hint = "The sign-in took too long or was opened in another tab. Please start again."
            else:
                hint = "Sign-in could not be completed."
            page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in problem · RAT Flea DevSec</title><style>body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#070b12;
font-family:Arial,sans-serif;color:#e6edf6}}.c{{width:min(440px,92vw);background:#0f1622;border:1px solid #1f2a3a;border-radius:16px;padding:30px}}
h1{{font-size:22px;margin:0 0 10px}}p{{color:#9fb0c3;line-height:1.5}}code{{color:#7fd8cc;font-size:12px}}a{{display:inline-block;margin-top:14px;
background:#1d4ed8;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none}}</style></head><body><div class="c">
<h1>We couldn't sign you in</h1><p>{_h.escape(hint)}</p><p><code>Reason: {_h.escape(detail)} (HTTP {status})</code></p>
<a href="/">Back to sign-in</a></div></body></html>"""
            from fastapi.responses import HTMLResponse
            resp = HTMLResponse(page, status_code=status, headers={"Cache-Control": "no-store"})
            resp.delete_cookie(STATE_COOKIE, path="/", secure=secure, httponly=True, samesite="lax")
            return resp

        def _callback(request: Request, code: str, state: str, error: str):
            st = verify_state(self.k_state, request.cookies.get(STATE_COOKIE, ""))
            if error or not st or not consteq(st["s"], state) or not code:
                raise HTTPException(400, "login failed or expired; start again")
            prov = self.idps[st["i"]]
            disc = self.verifier.jwks.discovery(prov)
            secret = sm.resolve(prov.client_secret_ref) if prov.client_secret_ref else None
            tok = self.http.post(disc["token_endpoint"], data={"grant_type": "authorization_code", "code": code,
                                 "redirect_uri": self.s.public_url + "/auth/callback", "code_verifier": st["v"], "client_id": prov.client_id},
                                 auth=(prov.client_id, secret) if secret else None)
            if tok.status_code != 200:
                try:                                          # IdP error codes are safe to show; never echo secrets
                    e = tok.json()
                    why = f"{e.get('error', '')}: {e.get('error_description', '')}".strip(": ")[:200]
                except ValueError:
                    why = ""
                log.warning("token exchange failed idp=%s status=%s error=%s", prov.name, tok.status_code, why)
                raise HTTPException(401, f"token exchange failed (identity provider said: {why or tok.status_code})")
            tj = tok.json()
            try:
                principal, claims = self.verifier.verify(tj["id_token"], nonce=st["n"])
            except AuthError as e:
                raise HTTPException(e.status, str(e)) from None
            sid, csrf = random_token(), random_token()
            now = datetime.now(timezone.utc)
            with tenant_tx(self.db, principal.tenant_id) as s:
                u = s.scalars(select(User).where(User.issuer == principal.issuer, User.subject == principal.subject)).first()
                if not u:
                    u = User(tenant_id=principal.tenant_id, issuer=principal.issuer, subject=principal.subject)
                    s.add(u)
                u.email, u.display_name, u.roles, u.last_login_at = principal.email, principal.name, sorted(principal.roles), now
                s.flush()
                s.add(WebSession(id_hash=hmac_sha256(self.k_session, sid), tenant_id=principal.tenant_id, user_id=u.id,
                                 claims={"sub": principal.subject, "iss": principal.issuer, "email": principal.email,
                                         "name": principal.name, "roles": sorted(principal.roles), "mfa": principal.mfa},
                                 csrf_hash=hmac_sha256(self.k_session, "csrf:" + csrf),
                                 refresh_token_enc=encrypt(self.k_refresh, tj["refresh_token"], str(principal.tenant_id)) if tj.get("refresh_token") else None,
                                 absolute_expiry=now + timedelta(hours=self.s.session_absolute_hours)))
            resp = RedirectResponse(st["r"], 302)
            resp.delete_cookie(STATE_COOKIE, path="/", secure=secure, httponly=True, samesite="lax")
            resp.set_cookie(SESSION_COOKIE, sid, httponly=True, secure=secure, samesite="lax", path="/",
                            max_age=self.s.session_absolute_hours * 3600)
            resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="strict", path="/",
                            max_age=self.s.session_absolute_hours * 3600)
            return resp

        @r.post("/logout")
        def logout(request: Request):
            p = self.authenticate(request)              # also enforces CSRF
            sid = request.cookies.get(SESSION_COOKIE, "")
            end_session = None
            if sid:
                with tenant_tx(self.db, p.tenant_id) as s:
                    ws = s.get(WebSession, hmac_sha256(self.k_session, sid))
                    if ws:
                        ws.revoked, ws.refresh_token_enc = True, None
                prov = self.idps.get(p.issuer)
                if prov:
                    try:
                        ep = self.verifier.jwks.discovery(prov).get("end_session_endpoint")
                    except Exception:                       # IdP unreachable: local logout still completes
                        ep = None
                    if ep:                                   # also end the IdP's single sign-on session
                        from urllib.parse import urlencode
                        end_session = ep + "?" + urlencode({"client_id": prov.client_id,
                                                             "post_logout_redirect_uri": (self.s.public_url or "").rstrip("/") + "/"})
            resp = JSONResponse({"logged_out": True, "end_session_endpoint": end_session})
            # __Host- cookies are only replaced/removed when the deletion carries the same Secure/path attributes
            resp.delete_cookie(SESSION_COOKIE, path="/", secure=secure, httponly=True, samesite="lax")
            resp.delete_cookie(CSRF_COOKIE, path="/", secure=secure, httponly=False, samesite="strict")
            return resp

        @r.get("/me")
        def me(request: Request):
            p = self.authenticate(request)
            return {"tenant_id": str(p.tenant_id), "subject": p.subject, "email": p.email, "name": p.name,
                    "roles": sorted(p.roles), "permissions": sorted(p.permissions), "method": p.method, "mfa": p.mfa}

        return r

    def refresh_token(self, p: Principal, ws: WebSession) -> str | None:
        return decrypt(self.k_refresh, ws.refresh_token_enc, str(p.tenant_id)) if ws.refresh_token_enc else None


def demo_principal(tenant_id: uuid.UUID, admin: bool) -> Principal:
    return Principal(tenant_id=tenant_id, subject="demo", issuer="demo", method="demo", mfa=False,
                     roles=frozenset({"tenant_admin"} if admin else {"viewer"}))
