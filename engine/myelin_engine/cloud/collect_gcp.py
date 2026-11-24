# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Live Google Cloud collection through the Cloud Asset Inventory API (read-only).

Permissions: roles/cloudasset.viewer and roles/iam.securityReviewer on the project, folder or organisation.
Credentials (JSON): a downloaded service-account key file (with client_email and private_key fields), or
an object with an access_token (for example from `gcloud auth print-access-token` or workload identity federation)."""
import base64
import json
import time
import urllib.parse

from . import http
from .inventory import from_gcp_assets

ASSET_TYPES = ["storage.googleapis.com/Bucket", "compute.googleapis.com/Firewall", "compute.googleapis.com/Instance",
               "sqladmin.googleapis.com/Instance", "container.googleapis.com/Cluster", "cloudkms.googleapis.com/CryptoKey",
               "iam.googleapis.com/ServiceAccount", "iam.googleapis.com/ServiceAccountKey", "cloudresourcemanager.googleapis.com/Project"]
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
MAX_ASSETS = 50000


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token(cred: dict) -> str:
    if cred.get("access_token"):
        return cred["access_token"]
    if cred.get("type") != "service_account" or not cred.get("private_key"):
        raise http.CollectorError("Google Cloud credential needs a service-account key or access_token")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    now = int(time.time())
    uri = cred.get("token_uri", "https://oauth2.googleapis.com/token")
    head = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": cred.get("private_key_id", "")}).encode())
    claims = _b64(json.dumps({"iss": cred["client_email"], "scope": SCOPE, "aud": uri, "iat": now, "exp": now + 3600}).encode())
    key = serialization.load_pem_private_key(cred["private_key"].encode(), password=None)
    sig = _b64(key.sign(f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256()))
    form = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": f"{head}.{claims}.{sig}"})
    status, raw = http.request("POST", uri, {"Content-Type": "application/x-www-form-urlencoded"}, form.encode())
    body = http._json(raw)
    if status != 200 or "access_token" not in body:
        raise http.CollectorError(f"Google sign-in failed ({status}): {body.get('error_description', body.get('error', ''))[:200]}")
    return body["access_token"]


def list_assets(tok: str, parent: str, content_type: str) -> list[dict]:
    out, page = [], None
    while len(out) < MAX_ASSETS:
        q = [("contentType", content_type), ("pageSize", "1000")] + [("assetTypes", t) for t in ASSET_TYPES]
        if page:
            q.append(("pageToken", page))
        status, body = http.get_json(f"https://cloudasset.googleapis.com/v1/{parent}/assets?{urllib.parse.urlencode(q)}",
                                     {"Authorization": f"Bearer {tok}"})
        if status == 403:
            raise http.CollectorError("Cloud Asset API: permission denied (grant roles/cloudasset.viewer, and enable the API)")
        if status != 200:
            raise http.CollectorError(f"Cloud Asset API failed ({status}): {str(body)[:200]}")
        out += body.get("assets") or []
        page = body.get("nextPageToken")
        if not page:
            break
    return out


def collect(cred: dict, parent: str, account: str = "") -> dict:
    """parent: projects/<id>, folders/<id> or organizations/<id>."""
    if not parent or parent.split("/")[0] not in ("projects", "folders", "organizations"):
        raise http.CollectorError("parent must be projects/<id>, folders/<id> or organizations/<id>")
    tok = token(cred)
    res = list_assets(tok, parent, "RESOURCE")
    pol = list_assets(tok, parent, "IAM_POLICY")
    by = {a["name"]: a for a in res}
    for p in pol:      # merge IAM policies into their resource so public buckets are recognised
        if p["name"] in by:
            by[p["name"]]["iamPolicy"] = p.get("iamPolicy")
        else:
            res.append(p)
    inv = from_gcp_assets(res, account or parent.split("/")[-1])
    inv["collector"] = {"source": "gcp-cloud-asset", "parent": parent, "assets": len(res)}
    return inv
