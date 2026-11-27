# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Offline-verifiable licence keys.

A licence is one line:  NMLIC1.<base64url(JSON payload)>.<base64url(Ed25519 signature)>
signed by the RAT Flea DevSec vendor key (scripts/licensing/myelin_license.py). The platform verifies it
against public keys shipped in app/licensing_keys/ — no call home, so it works in air-gapped sites.

Enforcement is deliberately graceful, because a licence problem must never take a customer's
security tooling or audit evidence offline:
  valid / expiring   full service (expiring = within warn_days of expiry: header + metric warning)
  grace              expired less than grace_days ago: full service, loud warnings
  restricted         missing, invalid, not yet valid or past grace: everything stays readable and
                     exportable (findings, evidence, audit, review, signing of existing evidence);
                     new scans, triage, connector changes/syncs and new evidence collection return 402
Limits: max_tenants is enforced when tenants are created; max_developers is a soft limit reported
as over_limit (header, metric, console) for true-up, never blocking.
"""
import base64
import glob
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREFIX = "NMLIC1"
KEY_DIR = os.path.join(os.path.dirname(__file__), "licensing_keys")
BLOCKED_WHEN_RESTRICTED = {"scans:write", "scans:run", "findings:triage", "findings:fix", "policies:write",
                           "connectors:manage", "evidence:collect", "dast:manage", "dast:run"}
REQUIRED = ("lid", "licensee", "plan", "issued_at", "expires_at", "kid")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def load_trusted_keys(directory: str = KEY_DIR) -> dict[str, Ed25519PublicKey]:
    """Vendor public keys by key id (file name without .pem). Several keys allow rotation."""
    keys = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.pem"))):
        k = serialization.load_pem_public_key(open(path, "rb").read())
        if isinstance(k, Ed25519PublicKey):
            keys[os.path.basename(path)[:-4]] = k
    return keys


TRUSTED_KEYS = load_trusted_keys()


def sign(payload: dict, private_key) -> str:
    body = _b64e(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    sig = private_key.sign(f"{PREFIX}.{body}".encode())
    return f"{PREFIX}.{body}.{_b64e(sig)}"


class LicenseError(ValueError):
    pass


def decode(token: str, keys: dict | None = None) -> dict:
    """Verify signature and structure; returns the payload. Does not judge dates."""
    keys = TRUSTED_KEYS if keys is None else keys
    parts = (token or "").strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise LicenseError("not a RAT Flea DevSec licence key")
    try:
        payload = json.loads(_b64d(parts[1]))
        sig = _b64d(parts[2])
    except Exception:
        raise LicenseError("licence key is corrupted") from None
    key = keys.get(payload.get("kid", ""))
    if key is None:
        raise LicenseError(f"licence signed by unknown key '{payload.get('kid')}'")
    try:
        key.verify(sig, f"{PREFIX}.{parts[1]}".encode())
    except InvalidSignature:
        raise LicenseError("licence signature is invalid") from None
    missing = [k for k in REQUIRED if k not in payload]
    if missing:
        raise LicenseError(f"licence is missing fields: {', '.join(missing)}")
    return payload


def _ts(v: str) -> datetime:
    d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@dataclass
class LicenseStatus:
    state: str                       # community | valid | expiring | grace | restricted
    reason: str = ""
    payload: dict = field(default_factory=dict)
    days_remaining: int | None = None

    @property
    def usable(self) -> bool:
        return self.state in ("community", "valid", "expiring", "grace")

    @property
    def features(self) -> set[str] | None:
        """Features the licence grants (plan + add-ons); None when no licence restricts features."""
        if not self.payload:
            return None
        from . import plans
        try:
            base = set(plans.plan(self.payload["plan"])["features"])
        except StopIteration:
            base = set()
        return base | set(self.payload.get("addons", []))

    def public(self, usage: dict | None = None) -> dict:
        p = self.payload
        out = {"state": self.state, "reason": self.reason, "days_remaining": self.days_remaining,
               "licensee": p.get("licensee"), "license_id": p.get("lid"), "plan": p.get("plan"),
               "addons": p.get("addons", []), "expires_at": p.get("expires_at"),
               "limits": {"max_developers": p.get("max_developers"), "max_tenants": p.get("max_tenants")},
               "deployment": p.get("deployment"), "support_until": p.get("support_until")}
        if usage:
            out["usage"] = usage
            md = p.get("max_developers")
            out["over_limit"] = bool(md and usage.get("developers", 0) > md)
        return out


def evaluate(token: str | None, deployment_id: str = "", now: datetime | None = None, keys: dict | None = None) -> LicenseStatus:
    now = now or datetime.now(timezone.utc)
    if not token:
        # Community edition: free and open source (AGPL-3.0); every feature works without a licence key.
        # A commercial licence key, when installed, is still verified below.
        return LicenseStatus("community", "Community edition (AGPL-3.0); no licence key required")
    try:
        p = decode(token, keys)
    except LicenseError as e:
        return LicenseStatus("restricted", str(e))
    if p.get("deployment_id") and p["deployment_id"] != deployment_id:
        return LicenseStatus("restricted", "licence is bound to a different deployment id", p)
    if p.get("not_before") and now < _ts(p["not_before"]):
        return LicenseStatus("restricted", "licence is not valid yet", p)
    exp = _ts(p["expires_at"])
    days = int((exp - now).total_seconds() // 86400)
    if now <= exp:
        warn = int(p.get("warn_days", 30))
        return LicenseStatus("expiring" if days < warn else "valid", f"expires in {days} days" if days < warn else "", p, days)
    grace = int(p.get("grace_days", 30))
    if days >= -grace:
        return LicenseStatus("grace", f"licence expired {-days} days ago; {grace + days} grace days left — renew now", p, days)
    return LicenseStatus("restricted", "licence expired and the grace period has ended", p, days)


class LicenseManager:
    """Resolves the licence from a secret reference and re-evaluates it periodically, so replacing the
    licence secret takes effect without a restart."""

    def __init__(self, ref: str, deployment_id: str = "", ttl: int = 300, keys: dict | None = None):
        self.ref, self.deployment_id, self.ttl, self.keys = ref, deployment_id, ttl, keys
        self._status, self._at = None, 0.0

    def status(self) -> LicenseStatus:
        if self._status is None or time.monotonic() - self._at > self.ttl:
            from . import secrets as sm
            token = None
            if self.ref:
                try:
                    token = sm.resolve(self.ref)
                except sm.SecretError:
                    token = None
            self._status, self._at = evaluate(token, self.deployment_id, keys=self.keys), time.monotonic()
        return self._status

    def refresh(self) -> LicenseStatus:
        self._status = None
        return self.status()
