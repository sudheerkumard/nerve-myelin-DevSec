# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Role-based access control. Roles come from the identity provider (mapped per IdP); permissions are
defined here, in code, and checked on every route. Deny by default."""
import uuid
from dataclasses import dataclass, field

PERMISSIONS = {
    "findings:read", "findings:triage", "findings:fix", "scans:write", "scans:run",
    "policies:read", "policies:write", "policies:approve", "connectors:read", "connectors:manage",
    "evidence:read", "evidence:collect", "evidence:review", "evidence:sign",
    "audit:read", "users:manage", "apikeys:manage", "settings:manage", "plans:read",
    "dast:read", "dast:manage", "dast:run",
}
_VIEW = {"findings:read", "policies:read", "plans:read"}
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": _VIEW,
    "developer": _VIEW | {"findings:fix", "dast:read"},
    "auditor": _VIEW | {"evidence:read", "evidence:review", "audit:read", "connectors:read", "dast:read"},
    "security_lead": _VIEW | {"findings:triage", "findings:fix", "scans:write", "scans:run", "policies:write",
                              "connectors:read", "evidence:read", "evidence:collect", "evidence:review", "evidence:sign", "audit:read",
                              "dast:read", "dast:manage", "dast:run"},
    "policy_approver": _VIEW | {"policies:approve", "audit:read"},
    "tenant_admin": set(PERMISSIONS),
    "integration": {"scans:write", "evidence:collect", "findings:read"},   # service accounts / CI API keys
}
ROLES = set(ROLE_PERMISSIONS)


@dataclass(frozen=True)
class Principal:
    tenant_id: uuid.UUID
    subject: str
    issuer: str
    roles: frozenset = field(default_factory=frozenset)
    email: str = ""
    name: str = ""
    method: str = "oidc"            # oidc | session | api_key | demo
    mfa: bool = False

    @property
    def permissions(self) -> set[str]:
        out: set[str] = set()
        for r in self.roles:
            out |= ROLE_PERMISSIONS.get(r, set())
        return out

    def can(self, perm: str) -> bool:
        if perm not in PERMISSIONS:
            raise ValueError(f"unknown permission {perm}")
        return perm in self.permissions

    @property
    def actor(self) -> str:
        return self.email or f"{self.method}:{self.subject}"


def map_roles(idp_values: list[str], mapping: dict[str, str]) -> frozenset:
    """Translate IdP roles/groups to RAT Flea roles. Unknown values are ignored (deny by default)."""
    out = set()
    for v in idp_values:
        r = mapping.get(v)
        if r in ROLES:
            out.add(r)
    return frozenset(out)
