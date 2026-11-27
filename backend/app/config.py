# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Central configuration for the RAT Flea DevSec platform API.

Order of precedence (highest first):
  1. Process environment variables (MYELIN_*)
  2. The env file named by MYELIN_ENV_FILE
  3. config/backend/myelin.env (if present; never committed — copy from myelin.env.example)
  4. Built-in defaults below (safe for local demos only)
"""
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _load_env_file(path: str) -> dict:
    vals = {}
    if path and os.path.isfile(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip().strip('"').strip("'")
    return vals


_FILE = _load_env_file(os.getenv("MYELIN_ENV_FILE") or os.path.join(ROOT, "config", "backend", "myelin.env"))


def _get(key: str, default: str = "") -> str:
    return os.getenv(key, _FILE.get(key, default))


def _bool(key: str, default: bool) -> bool:
    return _get(key, str(default)).lower() in ("1", "true", "yes", "on")


class Settings:
    # Mode: "demo" (in-memory sample tenant, demo keys) or "enterprise" (PostgreSQL + OIDC + RLS)
    mode = _get("MYELIN_MODE", "demo")
    # Enterprise: values ending in _ref are secret references (env://, file://, azkv://, awssm://, vault://)
    database_url = _get("MYELIN_DATABASE_URL", "")                 # app role (NOBYPASSRLS); may be a secret reference
    idp_config = _get("MYELIN_IDP_CONFIG", os.path.join(ROOT, "config", "backend", "identity-providers.yaml"))
    session_secret_ref = _get("MYELIN_SESSION_SECRET_REF", "env://MYELIN_SESSION_SECRET")
    api_key_pepper_ref = _get("MYELIN_API_KEY_PEPPER_REF", "env://MYELIN_API_KEY_PEPPER")
    evidence_signing_key_ref = _get("MYELIN_EVIDENCE_SIGNING_KEY_REF", "env://MYELIN_EVIDENCE_SIGNING_KEY")
    evidence_store = _get("MYELIN_EVIDENCE_STORE", "file://" + os.path.join(ROOT, "var", "evidence"))
    public_url = _get("MYELIN_PUBLIC_URL", "http://localhost:8080").rstrip("/")
    cookie_secure = _bool("MYELIN_COOKIE_SECURE", True)
    session_idle_minutes = int(_get("MYELIN_SESSION_IDLE_MINUTES", "30"))
    session_absolute_hours = int(_get("MYELIN_SESSION_ABSOLUTE_HOURS", "12"))
    metrics_enabled = _bool("MYELIN_METRICS_ENABLED", True)
    license_ref = _get("MYELIN_LICENSE_REF", "env://MYELIN_LICENSE")      # NMLIC1.… key issued for RAT Flea DevSec
    deployment_id = _get("MYELIN_DEPLOYMENT_ID", "")                  # optional: binds a licence to one installation
    # Online live-application testing. SaaS: keep defaults. Self-hosted scanning of internal APIs: allow private networks.
    dast_allow_private = _bool("MYELIN_DAST_ALLOW_PRIVATE", False)
    dast_require_verification = _bool("MYELIN_DAST_REQUIRE_VERIFICATION", True)
    dast_max_requests = int(_get("MYELIN_DAST_MAX_REQUESTS", "1500"))
    # Security
    api_keys = [k.strip() for k in _get("MYELIN_API_KEYS", "nm_demo_9f2c41e7b8").split(",") if k.strip()]
    demo_open = _bool("MYELIN_DEMO_OPEN", True)          # read-only GETs without a key; must be false outside demos
    cors_origins = [o.strip() for o in _get("MYELIN_CORS", "*").split(",") if o.strip()]
    # Tenant / branding shown in the API
    tenant_name = _get("MYELIN_TENANT_NAME", "Orion Financial Group")
    tenant_plan = _get("MYELIN_TENANT_PLAN", "enterprise")
    tenant_devs = int(_get("MYELIN_TENANT_DEVS", "640"))
    tenant_region = _get("MYELIN_TENANT_REGION", "Azure Central India")
    tenant_sso = _get("MYELIN_TENANT_SSO", "Entra ID (SAML)")
    # Data and policy
    seed_demo_data = _bool("MYELIN_SEED_DEMO_DATA", True)
    policy_file = _get("MYELIN_POLICY_FILE", "")          # e.g. policies/myelin-policy.yaml; empty = built-in default
    live_scan_root = _get("MYELIN_LIVE_SCAN_ROOT", ROOT)   # live-scan paths must stay inside this directory
    # UI
    console_path = _get("MYELIN_CONSOLE_PATH", os.path.join(ROOT, "console", "index.html"))
    log_level = _get("MYELIN_LOG_LEVEL", "info")
    # Independent durable advisory worker. Tenant IDs are explicitly allow-listed per deployment.
    worker_tenant_ids = [x.strip() for x in _get("MYELIN_WORKER_TENANT_IDS", "").split(",") if x.strip()]
    worker_poll_seconds = max(1, int(_get("MYELIN_WORKER_POLL_SECONDS", "5")))
    worker_lease_seconds = max(60, int(_get("MYELIN_WORKER_LEASE_SECONDS", "900")))
    worker_max_attempts = max(1, int(_get("MYELIN_WORKER_MAX_ATTEMPTS", "5")))


settings = Settings()
