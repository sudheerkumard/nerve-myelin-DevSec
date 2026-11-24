# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""vault:// references against a minimal KV v2 server: token file, trailing newlines, clear errors."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import secrets

TOKEN = "s.api-read-only"
DATA = {"/v1/secret/data/myelin/tenants/t1/dast/customer-a": {"token": "Bearer eyJ.alice\r\n"}}


class _KV(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("X-Vault-Token") != TOKEN:
            self.send_response(403); self.end_headers(); return
        d = DATA.get(self.path)
        self.send_response(200 if d else 404)
        self.send_header("Content-Type", "application/json"); self.end_headers()
        if d:
            self.wfile.write(json.dumps({"data": {"data": d}}).encode())

    def log_message(self, *a):
        pass


@pytest.fixture()
def vault(tmp_path, monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _KV)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    tf = tmp_path / "api-token"
    tf.write_text(TOKEN + "\n")
    monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_TOKEN_FILE", str(tf))
    secrets.clear_cache()
    yield tf
    srv.shutdown()
    secrets.clear_cache()


def test_token_file_and_newline_stripped(vault):
    assert secrets.resolve("vault://secret/myelin/tenants/t1/dast/customer-a#token") == "Bearer eyJ.alice"


def test_missing_secret_is_explained(vault):
    with pytest.raises(secrets.SecretError, match="not found"):
        secrets.resolve("vault://secret/myelin/tenants/t1/dast/nobody#token")


def test_missing_field_is_explained(vault):
    with pytest.raises(secrets.SecretError, match="no field 'password'"):
        secrets.resolve("vault://secret/myelin/tenants/t1/dast/customer-a#password")


def test_wrong_token_is_denied(vault):
    vault.write_text("s.wrong")
    with pytest.raises(secrets.SecretError, match="denied"):
        secrets.resolve("vault://secret/myelin/tenants/t1/dast/customer-a#token")


def test_no_vault_configured(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    secrets.clear_cache()
    with pytest.raises(secrets.SecretError, match="VAULT_ADDR"):
        secrets.resolve("vault://secret/x#token")
