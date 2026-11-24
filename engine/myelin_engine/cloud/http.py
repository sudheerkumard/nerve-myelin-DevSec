# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Minimal HTTPS client for the read-only cloud collectors (standard library only).

TRANSPORT can be replaced (tests, proxies): callable(method, url, headers, body: bytes|None) -> (status, bytes)."""
import json
import ssl
import urllib.error
import urllib.request

TRANSPORT = None
TIMEOUT = 30


class CollectorError(RuntimeError):
    pass


def request(method: str, url: str, headers: dict | None = None, body=None, ca_file: str | None = None, insecure: bool = False):
    if not url.startswith("https://"):
        raise CollectorError("collectors only call HTTPS endpoints")
    h = {"Accept": "application/json", "User-Agent": "NERvvE-DevSecOps-Cloud/1.0", **(headers or {})}
    data = body if isinstance(body, (bytes, type(None))) else (json.dumps(body).encode() if not isinstance(body, str) else body.encode())
    if data is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/json"
    if TRANSPORT:
        status, raw = TRANSPORT(method, url, h, data)
    else:
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        if insecure:                                   # only for a cluster CA the operator explicitly chose not to verify
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:  # myelin:ignore[NM-SAST-010] -- fixed provider API hosts or the operator's cluster API server
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise CollectorError(f"cannot reach {url.split('/')[2]}: {e}") from None
    return status, raw


def get_json(url, headers=None, **kw):
    status, raw = request("GET", url, headers, **kw)
    return status, _json(raw)


def post_json(url, body, headers=None, **kw):
    status, raw = request("POST", url, headers, body, **kw)
    return status, _json(raw)


def _json(raw):
    try:
        return json.loads(raw or b"{}")
    except (ValueError, UnicodeDecodeError):
        return {"raw": (raw or b"")[:500].decode("utf-8", "replace")}
