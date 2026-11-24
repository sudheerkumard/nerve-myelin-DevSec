# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Live validation of detected credentials against the issuing provider (opt-in).

A detected key is only reported as *live* after the provider accepted it in a read-only identity call. Validation
sends the credential to its own provider over HTTPS and nowhere else; it is off unless MYELIN_VALIDATE_SECRETS=1
(and never in offline mode). Results:

  live         the provider accepted the credential (rotate now)
  revoked      the provider rejected it (still remove it from history)
  error        the provider could not be reached; no claim is made
  unsupported  no safe read-only check exists for this credential type
  not_checked  validation is switched off
"""
import json
import os
import urllib.error
import urllib.request

TIMEOUT = 8
# rule id -> (method, url, header builder, success test)
CHECKS = {
    "NM-SEC-002": ("GET", "https://api.github.com/user", lambda k: {"Authorization": f"token {k}", "Accept": "application/vnd.github+json"}, None),
    "NM-SEC-003": ("GET", "https://api.github.com/user", lambda k: {"Authorization": f"Bearer {k}", "Accept": "application/vnd.github+json"}, None),
    "NM-SEC-004": ("POST", "https://slack.com/api/auth.test", lambda k: {"Authorization": f"Bearer {k}"},
                   lambda body: bool(json.loads(body or b"{}").get("ok"))),
    "NM-SEC-008": ("GET", "https://api.stripe.com/v1/balance", lambda k: {"Authorization": f"Bearer {k}"}, None),
    "NM-SEC-012": ("GET", "https://api.openai.com/v1/models", lambda k: {"Authorization": f"Bearer {k}"}, None),
    "NM-SEC-013": ("GET", "https://api.anthropic.com/v1/models", lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01"}, None),
    "NM-SEC-014": ("GET", "https://huggingface.co/api/whoami-v2", lambda k: {"Authorization": f"Bearer {k}"}, None),
}
# Structured provider formats (fixed prefix and length): a format match is high confidence even before validation.
HIGH_CONFIDENCE = {"NM-SEC-001", "NM-SEC-002", "NM-SEC-003", "NM-SEC-004", "NM-SEC-005", "NM-SEC-006", "NM-SEC-008",
                   "NM-SEC-012", "NM-SEC-013", "NM-SEC-014"}
TRANSPORT = None          # test hook: callable(method, url, headers) -> (status, body)


def enabled() -> bool:
    return os.environ.get("MYELIN_VALIDATE_SECRETS", "").lower() in ("1", "true", "yes") and \
        os.environ.get("MYELIN_OFFLINE", "").lower() not in ("1", "true", "yes")


def _call(method, url, headers):
    if TRANSPORT:
        return TRANSPORT(method, url, headers)
    req = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None,
                                 headers={"User-Agent": "NERvvE-DevSecOps-secret-validation", **headers})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # myelin:ignore[NM-SAST-010] -- fixed provider endpoints only
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def validate(rule_id: str, value: str) -> str:
    if not enabled():
        return "not_checked"
    chk = CHECKS.get(rule_id)
    if not chk or not value:
        return "unsupported"
    method, url, hdr, ok = chk
    try:
        status, body = _call(method, url, hdr(value))
    except Exception:  # noqa: BLE001 - network failure: no claim either way
        return "error"
    if status in (401, 403):
        return "revoked"
    if 200 <= status < 300:
        if ok is None:
            return "live"
        try:
            return "live" if ok(body) else "revoked"
        except ValueError:
            return "error"
    return "error"
