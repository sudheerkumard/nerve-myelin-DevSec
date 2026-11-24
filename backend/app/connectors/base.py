# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Connector framework.

A connector reads security-relevant state from a customer platform with least-privilege, read-only
credentials and returns findings, assets and evidence. Credentials are *references* into the customer's
secret manager, and must be namespaced to the tenant (the reference path contains the tenant id) so one
tenant can never point a connector at another tenant's or the platform's secrets. env:// and file:// are
reserved for the platform itself.
"""
import json
from dataclasses import dataclass, field
from typing import Callable

import httpx

from .. import secrets as sm

TENANT_SCHEMES = ("azkv", "awssm", "vault")


class ConnectorError(Exception):
    pass


@dataclass
class SyncResult:
    findings: list[dict] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    evidence: list[tuple[str, str, bytes, str]] = field(default_factory=list)   # (name, kind, content, media_type)


def validate_credential_ref(ref: str, tenant_id) -> None:
    scheme, _, rest = (ref or "").partition("://")
    if scheme not in TENANT_SCHEMES or not rest:
        raise ConnectorError("credential_ref must be an azkv://, awssm:// or vault:// secret reference")
    if str(tenant_id) not in rest:
        raise ConnectorError("credential_ref path must contain your tenant id (tenant-namespaced secrets only)")


class Connector:
    kind = "base"
    title = ""
    config_fields: dict[str, str] = {}          # name -> description (required unless prefixed with '?')
    least_privilege: dict = {}                  # human-readable permission summary + policy file path

    def __init__(self, config: dict, credential_ref: str, http: httpx.Client | None = None,
                 resolve: Callable[[str], str] | None = None):
        missing = [k for k in self.config_fields if not k.startswith("?") and not config.get(k)]
        if missing:
            raise ConnectorError(f"missing config: {', '.join(missing)}")
        self.config, self.credential_ref = config, credential_ref
        self.http = http or httpx.Client(timeout=20, follow_redirects=False)
        self._resolve = resolve or sm.resolve

    def secret(self) -> str:
        return self._resolve(self.credential_ref)

    def secret_json(self) -> dict:
        try:
            return json.loads(self.secret())
        except json.JSONDecodeError:
            raise ConnectorError("credential secret must be JSON for this connector") from None

    def test(self) -> dict:
        raise NotImplementedError

    def sync(self) -> SyncResult:
        raise NotImplementedError


REGISTRY: dict[str, type[Connector]] = {}


def register(cls):
    REGISTRY[cls.kind] = cls
    return cls
