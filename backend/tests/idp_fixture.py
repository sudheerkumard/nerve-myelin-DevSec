# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""A fake OIDC provider for tests: real RSA/EC keys, discovery document, JWKS and token minting."""
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ISSUER = "https://auth.test/realms/myelin"


class FakeIdP:
    def __init__(self, issuer=ISSUER, alg="RS256"):
        self.issuer, self.alg = issuer, alg
        self.keys = {}
        self.rotate("k1")
        self.fetches = 0

    def rotate(self, kid):
        priv = ec.generate_private_key(ec.SECP256R1()) if self.alg.startswith("ES") else rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys[kid] = priv
        self.kid = kid

    def jwks(self):
        out = []
        for kid, priv in self.keys.items():
            alg = jwt.algorithms.ECAlgorithm if self.alg.startswith("ES") else jwt.algorithms.RSAAlgorithm
            jwk = json.loads(alg.to_jwk(priv.public_key()))
            jwk.update({"kid": kid, "use": "sig", "alg": self.alg})
            out.append(jwk)
        return {"keys": out}

    def fetch(self, url):
        self.fetches += 1
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": self.issuer, "jwks_uri": self.issuer + "/protocol/openid-connect/certs",
                    "authorization_endpoint": self.issuer + "/protocol/openid-connect/auth",
                    "token_endpoint": self.issuer + "/protocol/openid-connect/token",
                    "end_session_endpoint": self.issuer + "/protocol/openid-connect/logout"}
        return self.jwks()

    def token(self, kid=None, **claims):
        now = int(time.time())
        body = {"iss": self.issuer, "sub": "user-1", "aud": "myelin-console", "iat": now, "exp": now + 300,
                "email": "alice@acme.test", "name": "Alice", "acr": "mfa", "tenant": "acme",
                "realm_access": {"roles": ["myelin-security-lead"]}}
        body.update(claims)
        for k in [k for k, v in body.items() if v is None]:
            body.pop(k)
        kid = kid or self.kid
        return jwt.encode(body, self.keys[kid], algorithm=self.alg, headers={"kid": kid})
