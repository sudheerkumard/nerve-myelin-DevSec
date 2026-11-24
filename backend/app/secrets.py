# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Secret references. Configuration and the database hold only *references*; values are fetched at use time.

  env://VAR_NAME                         environment variable (injected by the orchestrator)
  file:///run/secrets/name               mounted file (Kubernetes Secret, CSI Secrets Store, Docker secret)
  azkv://<vault-name>/<secret-name>      Azure Key Vault          (pip install azure-identity azure-keyvault-secrets)
  awssm://<region>/<secret-id>[#json-key] AWS Secrets Manager     (pip install boto3)
  vault://<mount>/<path>#<key>           HashiCorp Vault / OpenBao KV v2 (VAULT_ADDR + VAULT_TOKEN or VAULT_TOKEN_FILE)

Values are cached briefly in memory and never logged. A plain string without a scheme is rejected in
enterprise mode so that secrets cannot be committed to configuration by mistake.
"""
import json
import os
import time

_CACHE: dict[str, tuple[float, str]] = {}
TTL = 300
SCHEMES = {"env", "file", "azkv", "awssm", "vault"}


class SecretError(RuntimeError):
    pass


def resolve(ref: str, allow_plain: bool = False) -> str:
    if not ref:
        raise SecretError("empty secret reference")
    hit = _CACHE.get(ref)
    if hit and hit[0] > time.time():
        return hit[1]
    scheme, _, rest = ref.partition("://")
    if not rest or scheme not in SCHEMES:
        if allow_plain:      # e.g. a database URL that carries no password (IAM / mTLS / socket auth)
            return ref
        raise SecretError("secret must be a reference (env://, file://, azkv://, awssm://, vault://), not a literal value")
    if scheme == "env":
        val = os.environ.get(rest)
        if val is None:
            raise SecretError(f"environment variable {rest} is not set")
    elif scheme == "file":
        try:
            val = open(rest, encoding="utf-8").read().strip()
        except OSError as e:
            raise SecretError(f"cannot read secret file: {e.strerror}") from None
    elif scheme == "azkv":
        vault, name = rest.split("/", 1)
        from azure.identity import DefaultAzureCredential          # workload identity / managed identity
        from azure.keyvault.secrets import SecretClient
        val = SecretClient(f"https://{vault}.vault.azure.net", DefaultAzureCredential()).get_secret(name).value
    elif scheme == "awssm":
        region, _, sid = rest.partition("/")
        sid, _, key = sid.partition("#")
        import boto3                                               # IRSA / instance role
        val = boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=sid)["SecretString"]
        if key:
            val = json.loads(val)[key]
    elif scheme == "vault":
        import httpx
        path, _, key = rest.partition("#")
        mount, _, sub = path.partition("/")
        if not os.environ.get("VAULT_ADDR"):
            raise SecretError("a vault:// reference is used but no Vault/OpenBao is configured (VAULT_ADDR)")
        addr, token = _vault_auth()
        r = httpx.get(f"{addr}/v1/{mount}/data/{sub}", headers={"X-Vault-Token": token}, timeout=10)
        if r.status_code == 404:
            raise SecretError(f"secret not found in Vault: {mount}/{sub} (store it first)")
        if r.status_code == 403:
            raise SecretError(f"Vault denied access to {mount}/{sub}")
        r.raise_for_status()
        data = r.json()["data"]["data"]
        if key not in data:
            raise SecretError(f"secret {mount}/{sub} has no field '{key}'")
        val = data[key]
    else:
        raise SecretError(f"unsupported secret scheme: {scheme}")
    val = val.rstrip("\r\n") if isinstance(val, str) else val    # files and piped input end with a newline
    _CACHE[ref] = (time.time() + TTL, val)
    return val


def _vault_auth():
    if not os.environ.get("VAULT_ADDR"):
        raise SecretError("no Vault/OpenBao is configured (VAULT_ADDR)")
    token = os.environ.get("VAULT_TOKEN", "")
    if not token and os.environ.get("VAULT_TOKEN_FILE"):              # token rotated by the operator / start script
        try:
            with open(os.environ["VAULT_TOKEN_FILE"], encoding="utf-8") as fh:
                token = fh.read().strip()
        except OSError as e:
            raise SecretError(f"cannot read VAULT_TOKEN_FILE: {e.strerror}") from None
    return os.environ["VAULT_ADDR"].rstrip("/"), token


def vault_available() -> bool:
    return bool(os.environ.get("VAULT_ADDR"))


def store(ref: str, value: str) -> None:
    """Write a value to a vault:// reference (KV v2). Used when a user pastes a token in the console: the platform
    keeps only the reference. The vault policy must allow create/update on the tenant's path."""
    import httpx
    scheme, _, rest = ref.partition("://")
    if scheme != "vault":
        raise SecretError("tokens can only be stored in a Vault/OpenBao vault")
    path, _, key = rest.partition("#")
    mount, _, sub = path.partition("/")
    addr, token = _vault_auth()
    r = httpx.post(f"{addr}/v1/{mount}/data/{sub}", headers={"X-Vault-Token": token},
                   json={"data": {key or "token": value.strip()}}, timeout=10)
    if r.status_code in (401, 403):
        raise SecretError("the vault refused to store the token (the platform's vault policy is read-only); "
                          "store it in the vault yourself and give its reference instead")
    r.raise_for_status()
    _CACHE.pop(ref, None)


def forget(ref: str) -> None:
    """Delete a stored token (all versions). Best effort."""
    import httpx
    try:
        scheme, _, rest = ref.partition("://")
        if scheme != "vault":
            return
        mount, _, sub = rest.partition("#")[0].partition("/")
        addr, token = _vault_auth()
        httpx.delete(f"{addr}/v1/{mount}/metadata/{sub}", headers={"X-Vault-Token": token}, timeout=10)
    except Exception:  # noqa: BLE001 - deletion is best effort
        pass
    _CACHE.pop(ref, None)


def clear_cache():
    _CACHE.clear()
