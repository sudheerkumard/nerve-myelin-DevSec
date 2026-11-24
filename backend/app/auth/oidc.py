# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""OpenID Connect token verification for any standards-compliant identity provider.

Keycloak is the reference IdP shipped with NERvvE DevSecOps. Customers can instead (or additionally) trust
Microsoft Entra ID, Okta, Auth0, Ping Identity, Google Workspace or any OIDC-certified provider; SAML-only
IdPs (ADFS, PingFederate, Shibboleth) are connected by brokering them through Keycloak, which then issues
OIDC tokens to NERvvE. Several issuers can be trusted at once (one per customer in SaaS).

For each trusted issuer, verification enforces:
  * signature with a key from the issuer's JWKS (fetched over HTTPS, cached, refreshed on unknown `kid`);
  * an asymmetric algorithm allow-list (no `none`, no HS*);
  * exact `iss`, required audience/`azp`, `exp`/`nbf`/`iat` with bounded clock skew, maximum token age;
  * MFA: `acr` in the configured values or `amr` containing a configured method (RFC 9470 step-up on failure);
  * tenant: taken ONLY from a configured claim of the validated token and resolved through a server-side
    binding (issuer, claim value) -> tenant. Headers, query strings and request bodies are never used.
"""
import time
from dataclasses import dataclass, field
from typing import Callable

import httpx
import jwt
import yaml

from .rbac import Principal, map_roles

ALLOWED_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"]

PRESETS = {
    # issuer template, tenant claim, role claim paths, MFA signals
    "keycloak": {"tenant_claim": "tenant", "role_claims": ["realm_access.roles", "resource_access.{client_id}.roles"],
                 "acr_values": ["mfa", "2", "urn:myelin:acr:mfa"], "amr_values": ["otp", "mfa", "hwk", "swk", "webauthn"]},
    "entra": {"tenant_claim": "tid", "role_claims": ["roles"], "acr_values": [], "amr_values": ["mfa"]},
    "okta": {"tenant_claim": "myelin_tenant", "role_claims": ["groups"], "acr_values": ["urn:okta:loa:2fa:any", "phr"],
             "amr_values": ["mfa", "otp", "sms", "hwk", "swk", "pop"]},
    "auth0": {"tenant_claim": "https://sudheerkumard.github.io/nerve-myelin/tenant", "role_claims": ["https://github.com/sudheerkumard/nervve-devsecops/roles"],
              "acr_values": ["http://schemas.openid.net/pape/policies/2007/06/multi-factor"], "amr_values": ["mfa"]},
    "ping": {"tenant_claim": "myelin_tenant", "role_claims": ["groups"], "acr_values": ["MFA"], "amr_values": ["mfa", "otp"]},
    "google": {"tenant_claim": "hd", "role_claims": ["groups"], "acr_values": [], "amr_values": ["mfa"]},
    "generic": {"tenant_claim": "tenant", "role_claims": ["roles"], "acr_values": ["mfa"], "amr_values": ["mfa", "otp", "hwk", "swk"]},
}


class AuthError(Exception):
    def __init__(self, msg: str, status: int = 401, step_up: bool = False):
        super().__init__(msg)
        self.status, self.step_up = status, step_up


@dataclass
class IdP:
    name: str
    issuer: str
    client_id: str
    type: str = "generic"
    audiences: list[str] = field(default_factory=list)
    tenant_claim: str | None = None
    role_claims: list[str] | None = None
    role_mapping: dict[str, str] = field(default_factory=dict)
    require_mfa: bool = True
    acr_values: list[str] | None = None
    amr_values: list[str] | None = None
    max_token_age: int = 3600 * 12
    leeway: int = 60
    jwks_uri: str | None = None
    client_secret_ref: str | None = None     # confidential client (console BFF); a secret reference, never a value
    scopes: str = "openid profile email"
    display_name: str = ""                   # label on the console sign-in button

    def __post_init__(self):
        p = PRESETS.get(self.type, PRESETS["generic"])
        self.tenant_claim = self.tenant_claim or p["tenant_claim"]
        self.role_claims = [c.replace("{client_id}", self.client_id) for c in (self.role_claims or p["role_claims"])]
        self.acr_values = self.acr_values if self.acr_values is not None else p["acr_values"]
        self.amr_values = self.amr_values if self.amr_values is not None else p["amr_values"]
        self.audiences = self.audiences or [self.client_id]
        self.issuer = self.issuer.rstrip("/")


def load_idps(path: str) -> dict[str, IdP]:
    doc = yaml.safe_load(open(path)) or {}
    out = {}
    for d in doc.get("providers", []):
        idp = IdP(**d)
        out[idp.issuer] = idp
    return out


def _claim(claims: dict, path: str):
    if path in claims:                                   # URL-style namespaced claims contain dots
        return claims[path]
    cur = claims
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


class JWKSCache:
    def __init__(self, fetch: Callable[[str], dict] | None = None, ttl: int = 3600, min_refresh: int = 30):
        self._fetch = fetch or (lambda url: httpx.get(url, timeout=10).raise_for_status().json())
        self._keys: dict[str, tuple[float, dict]] = {}
        self._discovery: dict[str, dict] = {}
        self._last_refresh: dict[str, float] = {}
        self.ttl, self.min_refresh = ttl, min_refresh

    def discovery(self, idp: IdP) -> dict:
        if idp.issuer not in self._discovery:
            doc = self._fetch(idp.issuer + "/.well-known/openid-configuration")
            if doc.get("issuer", "").rstrip("/") != idp.issuer:
                raise AuthError("discovery document issuer mismatch", 500)
            self._discovery[idp.issuer] = doc
        return self._discovery[idp.issuer]

    def key(self, idp: IdP, kid: str):
        uri = idp.jwks_uri or self.discovery(idp)["jwks_uri"]
        if not uri.startswith("https://") and not uri.startswith("http://localhost") and not uri.startswith("http://keycloak"):
            raise AuthError("JWKS must be served over HTTPS", 500)
        cached = self._keys.get(uri)
        now = time.time()
        if not cached or cached[0] < now or (kid not in cached[1] and now - self._last_refresh.get(uri, 0) > self.min_refresh):
            jwks = self._fetch(uri)
            self._keys[uri] = (now + self.ttl, {k.get("kid"): k for k in jwks.get("keys", []) if k.get("use", "sig") == "sig"})
            self._last_refresh[uri] = now
        jwk = self._keys[uri][1].get(kid)
        if not jwk:
            raise AuthError("signing key not found")
        return jwt.PyJWK(jwk).key


class TokenVerifier:
    def __init__(self, idps: dict[str, IdP], resolve_tenant: Callable[[str, str], object], jwks: JWKSCache | None = None):
        self.idps, self.resolve_tenant, self.jwks = idps, resolve_tenant, jwks or JWKSCache()

    def verify(self, token: str, nonce: str | None = None) -> tuple[Principal, dict]:
        try:
            header = jwt.get_unverified_header(token)
            # Routing only: read `iss` to pick the trusted IdP and its keys. Nothing from this copy is trusted;
            # the token is fully verified (signature, iss, aud, exp, nbf, iat) below before any claim is used.
            unverified = jwt.decode(token, options={"verify_signature": False})  # myelin:ignore[NM-SAST-009] -- issuer routing only; full verification follows
        except jwt.PyJWTError:
            raise AuthError("malformed token") from None
        if header.get("alg") not in ALLOWED_ALGS:
            raise AuthError("token algorithm not allowed")
        idp = self.idps.get(str(unverified.get("iss", "")).rstrip("/"))
        if not idp:
            raise AuthError("untrusted issuer")
        key = self.jwks.key(idp, header.get("kid"))
        try:
            claims = jwt.decode(token, key=key, algorithms=ALLOWED_ALGS, audience=idp.audiences, issuer=idp.issuer,
                                leeway=idp.leeway, options={"require": ["exp", "iat", "iss", "sub"]})
        except jwt.ExpiredSignatureError:
            raise AuthError("token expired") from None
        except jwt.PyJWTError as e:
            raise AuthError(f"invalid token: {type(e).__name__}") from None
        if claims.get("azp") and claims["azp"] not in idp.audiences:
            raise AuthError("authorized party not allowed")
        if time.time() - float(claims["iat"]) > idp.max_token_age:
            raise AuthError("token too old")
        if nonce is not None and claims.get("nonce") != nonce:
            raise AuthError("nonce mismatch")
        mfa = str(claims.get("acr", "")) in idp.acr_values or bool(set(claims.get("amr") or []) & set(idp.amr_values))
        if idp.require_mfa and not mfa:
            raise AuthError("multi-factor authentication required", 401, step_up=True)
        tval = _claim(claims, idp.tenant_claim)
        if isinstance(tval, dict):            # e.g. Keycloak organizations claim {"acme": {...}}
            tval = next(iter(tval), None) if len(tval) == 1 else None
        if isinstance(tval, list):
            tval = tval[0] if len(tval) == 1 else None
        if not tval:
            who = claims.get("preferred_username") or claims.get("email") or claims.get("sub")
            raise AuthError(f"no tenant for user '{who}': the '{idp.tenant_claim}' claim is missing or has several values — "
                            f"set the user's '{idp.tenant_claim}' attribute in the identity provider", 403)
        tenant_id = self.resolve_tenant(idp.issuer, str(tval))
        if not tenant_id:
            raise AuthError("tenant not provisioned for this identity provider", 403)
        raw_roles: list[str] = []
        for path in idp.role_claims:
            v = _claim(claims, path)
            raw_roles += v if isinstance(v, list) else ([v] if isinstance(v, str) else [])
        roles = map_roles(raw_roles, idp.role_mapping or {r: r for r in raw_roles})
        p = Principal(tenant_id=tenant_id, subject=claims["sub"], issuer=idp.issuer, roles=roles,
                      email=claims.get("email", ""), name=claims.get("name", ""), method="oidc", mfa=mfa)
        return p, claims
