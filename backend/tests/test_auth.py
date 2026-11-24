# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
import os
import sys
import time
import uuid

import jwt
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.auth import apikeys  # noqa: E402
from app.auth.crypto import decrypt, derive_key, encrypt, sign_state, verify_state  # noqa: E402
from app.auth.oidc import AuthError, IdP, JWKSCache, TokenVerifier  # noqa: E402
from app.auth.rbac import ROLE_PERMISSIONS, Principal  # noqa: E402
from tests.idp_fixture import FakeIdP  # noqa: E402

ACME = uuid.uuid4()
MAPPING = {"myelin-security-lead": "security_lead", "myelin-auditor": "auditor", "myelin-tenant-admin": "tenant_admin"}


def verifier(fake, **idp_kw):
    idp = IdP(name="kc", type="keycloak", issuer=fake.issuer, client_id="myelin-console", role_mapping=MAPPING, **idp_kw)
    bindings = {(fake.issuer, "acme"): ACME}
    return TokenVerifier({idp.issuer: idp}, lambda i, v: bindings.get((i, v)), JWKSCache(fetch=fake.fetch))


def test_valid_keycloak_token_with_mfa():
    fake = FakeIdP()
    p, claims = verifier(fake).verify(fake.token())
    assert p.tenant_id == ACME and p.roles == {"security_lead"} and p.mfa and p.email == "alice@acme.test"
    assert p.can("findings:triage") and not p.can("users:manage")


@pytest.mark.parametrize("claims,msg", [
    ({"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}, "expired"),
    ({"aud": "some-other-app"}, "invalid token"),
    ({"acr": None, "amr": None}, "multi-factor"),
    ({"tenant": "globex"}, "tenant not provisioned"),
    ({"tenant": None}, "no tenant for user"),
    ({"tenant": ["acme", "globex"]}, "no tenant for user"),
    ({"azp": "evil-client"}, "authorized party"),
    ({"iat": int(time.time()) - 13 * 3600, "exp": int(time.time()) + 60}, "too old"),
    ({"sub": None}, "invalid token"),
])
def test_rejections(claims, msg):
    fake = FakeIdP()
    with pytest.raises(AuthError, match=msg):
        verifier(fake).verify(fake.token(**claims))


def test_mfa_failure_requests_step_up():
    fake = FakeIdP()
    with pytest.raises(AuthError) as e:
        verifier(fake).verify(fake.token(acr="1", amr=["pwd"]))
    assert e.value.step_up and e.value.status == 401


def test_amr_otp_satisfies_mfa():
    fake = FakeIdP()
    p, _ = verifier(fake).verify(fake.token(acr="1", amr=["pwd", "otp"]))
    assert p.mfa


def test_untrusted_issuer_rejected():
    fake, attacker = FakeIdP(), FakeIdP(issuer="https://evil.test/realms/myelin")
    with pytest.raises(AuthError, match="untrusted issuer"):
        verifier(fake).verify(attacker.token(iss=attacker.issuer))


def test_alg_none_and_hs256_confusion_rejected():
    fake = FakeIdP()
    v = verifier(fake)
    none_tok = jwt.encode({"iss": fake.issuer, "sub": "x", "aud": "myelin-console", "iat": int(time.time()), "exp": int(time.time()) + 60},
                          None, algorithm="none")
    with pytest.raises(AuthError, match="algorithm"):
        v.verify(none_tok)
    pub_pem = fake.keys["k1"].public_key().public_bytes(encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
                                                         format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo)
    import hmac, hashlib, base64, json
    h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": "k1"}).encode()).rstrip(b"=")
    b = base64.urlsafe_b64encode(json.dumps({"iss": fake.issuer, "sub": "x"}).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(hmac.new(pub_pem, h + b"." + b, hashlib.sha256).digest()).rstrip(b"=")
    with pytest.raises(AuthError, match="algorithm"):
        v.verify((h + b"." + b + b"." + sig).decode())


def test_tampered_signature_rejected():
    fake = FakeIdP()
    tok = fake.token()
    head, body, sig = tok.split(".")
    forged = jwt.encode({**jwt.decode(tok, options={"verify_signature": False}), "tenant": "acme",
                         "realm_access": {"roles": ["myelin-tenant-admin"]}}, "x", algorithm="HS256").split(".")[1]
    with pytest.raises(AuthError, match="invalid token"):
        verifier(fake).verify(f"{head}.{forged}.{sig}")


def test_key_rotation_refreshes_jwks_once():
    fake = FakeIdP()
    v = verifier(fake)
    v.jwks.min_refresh = 0
    v.verify(fake.token())
    fake.rotate("k2")
    p, _ = v.verify(fake.token(kid="k2"))
    assert p.tenant_id == ACME


def test_unknown_roles_are_ignored():
    fake = FakeIdP()
    p, _ = verifier(fake).verify(fake.token(realm_access={"roles": ["offline_access", "superuser"]}))
    assert p.roles == frozenset() and p.permissions == set()


def test_entra_preset_tid_amr_roles():
    fake = FakeIdP(issuer="https://login.microsoftonline.com/1111-2222/v2.0")
    idp = IdP(name="entra", type="entra", issuer=fake.issuer, client_id="app-id", role_mapping={"NERvvE.Auditor": "auditor"})
    v = TokenVerifier({idp.issuer: idp}, lambda i, val: ACME if val == "1111-2222" else None, JWKSCache(fetch=fake.fetch))
    p, _ = v.verify(fake.token(aud="app-id", tid="1111-2222", tenant=None, acr=None, amr=["pwd", "mfa"], roles=["NERvvE.Auditor"],
                               realm_access=None))
    assert p.roles == {"auditor"} and p.mfa and p.can("evidence:review")


def test_okta_es256_groups():
    fake = FakeIdP(issuer="https://acme.okta.com/oauth2/default", alg="ES256")
    idp = IdP(name="okta", type="okta", issuer=fake.issuer, client_id="0oa1", role_mapping={"appsec": "security_lead"})
    v = TokenVerifier({idp.issuer: idp}, lambda i, val: ACME if val == "acme" else None, JWKSCache(fetch=fake.fetch))
    p, _ = v.verify(fake.token(aud="0oa1", myelin_tenant="acme", tenant=None, groups=["appsec", "everyone"], acr=None, amr=["mfa"],
                               realm_access=None))
    assert p.roles == {"security_lead"}


def test_api_key_format_and_hashing():
    full, kid, secret = apikeys.generate()
    assert apikeys.parse(full) == (kid, secret)
    h = apikeys.hash_secret(b"pepper", secret)
    assert apikeys.verify(b"pepper", secret, h) and not apikeys.verify(b"other", secret, h)
    assert apikeys.parse("nm_short_x") is None and apikeys.parse("Bearer x") is None


def test_state_and_encryption_helpers():
    k = derive_key(b"master", "state")
    tok = sign_state(k, {"s": "abc"}, 60)
    assert verify_state(k, tok)["s"] == "abc"
    assert verify_state(k, tok[:-2] + "xx") is None
    assert verify_state(derive_key(b"master", "other"), tok) is None
    assert verify_state(k, sign_state(k, {"s": "abc"}, -1)) is None
    ek = derive_key(b"master", "refresh")
    ct = encrypt(ek, "refresh-token", "tenant-a")
    assert decrypt(ek, ct, "tenant-a") == "refresh-token"
    with pytest.raises(Exception):
        decrypt(ek, ct, "tenant-b")          # bound to tenant via AAD


def test_rbac_least_privilege():
    assert "users:manage" not in ROLE_PERMISSIONS["security_lead"]
    assert ROLE_PERMISSIONS["integration"] == {"scans:write", "evidence:collect", "findings:read"}
    p = Principal(tenant_id=ACME, subject="s", issuer="i", roles=frozenset({"viewer"}))
    assert p.can("findings:read") and not p.can("findings:triage")
    with pytest.raises(ValueError):
        p.can("not:a:permission")


def test_shipped_identity_provider_files_load():
    """Every IdP file shipped in the product must load (Helm values, Compose stack, default config)."""
    import yaml
    from app.auth.oidc import load_idps
    root = os.path.join(os.path.dirname(__file__), "..", "..")
    for rel in ("config/backend/identity-providers.yaml", "deploy/compose/identity-providers.compose.yaml"):
        assert load_idps(os.path.join(root, rel))
    vals = yaml.safe_load(open(os.path.join(root, "deploy/helm/myelin/values.yaml")))["identityProviders"]
    cust = yaml.safe_load(open(os.path.join(root, "config/deploy/values-customer.example.yaml")))["identityProviders"]
    import tempfile
    for doc in (vals, cust):
        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        yaml.safe_dump(doc, f); f.close()
        assert load_idps(f.name)
