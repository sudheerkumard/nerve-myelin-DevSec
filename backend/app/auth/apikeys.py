# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Tenant-scoped API keys for CI pipelines and integrations.

Format: nm_<key_id>_<secret>. Only HMAC-SHA256(pepper, secret) is stored; the pepper is a platform secret
held in the secret manager, so a database dump alone cannot be used to verify guesses."""
import re
from datetime import datetime, timedelta, timezone

from .crypto import consteq, hmac_sha256, random_token

KEY_RE = re.compile(r"^nm_([a-z0-9]{12})_([A-Za-z0-9_\-]{32,})$")


def generate() -> tuple[str, str, str]:
    """Returns (full_key_to_show_once, key_id, secret)."""
    key_id = random_token(9).lower().replace("-", "a").replace("_", "b")[:12]
    secret = random_token(32)
    return f"nm_{key_id}_{secret}", key_id, secret


def parse(key: str) -> tuple[str, str] | None:
    m = KEY_RE.match(key or "")
    return (m.group(1), m.group(2)) if m else None


def hash_secret(pepper: bytes, secret: str) -> str:
    return hmac_sha256(pepper, secret)


def verify(pepper: bytes, secret: str, stored_hash: str) -> bool:
    return consteq(hash_secret(pepper, secret), stored_hash)


def default_expiry(days: int = 90) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)
