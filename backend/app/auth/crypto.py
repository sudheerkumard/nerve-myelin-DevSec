# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Small, audited crypto helpers built on the `cryptography` package. No custom primitives."""
import base64
import hashlib
import hmac
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def random_token(nbytes: int = 32) -> str:
    return b64u(os.urandom(nbytes))


def hmac_sha256(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def derive_key(master: bytes, purpose: str) -> bytes:
    """Domain-separated sub-keys from one master secret (HMAC-based key derivation)."""
    return hmac.new(master, b"myelin/" + purpose.encode(), hashlib.sha256).digest()


def encrypt(key: bytes, plaintext: str, aad: str = "") -> str:
    nonce = os.urandom(12)
    return b64u(nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), aad.encode()))


def decrypt(key: bytes, token: str, aad: str = "") -> str:
    raw = b64u_dec(token)
    return AESGCM(key).decrypt(raw[:12], raw[12:], aad.encode()).decode()


def sign_state(key: bytes, payload: dict, ttl: int) -> str:
    """Tamper-proof, expiring state (OIDC login state/nonce/PKCE verifier)."""
    body = b64u(json.dumps({**payload, "exp": int(time.time()) + ttl}, separators=(",", ":")).encode())
    return body + "." + b64u(hmac.new(key, body.encode(), hashlib.sha256).digest())


def verify_state(key: bytes, token: str) -> dict | None:
    try:
        body, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(b64u(hmac.new(key, body.encode(), hashlib.sha256).digest()), sig):
        return None
    data = json.loads(b64u_dec(body))
    return data if data.get("exp", 0) >= time.time() else None
