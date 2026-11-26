#!/bin/sh
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
# Generate fresh platform secrets for config/backend/enterprise.env (never commit the output).
set -eu
r() { python3 -c "import secrets;print(secrets.token_urlsafe($1))"; }
cat <<OUT
MYELIN_DB_OWNER_PASSWORD=$(r 24)
MYELIN_DB_APP_PASSWORD=$(r 24)
KEYCLOAK_DB_PASSWORD=$(r 24)
KEYCLOAK_ADMIN_PASSWORD=$(r 18)
MYELIN_OIDC_CLIENT_SECRET=$(r 32)
MYELIN_ZAP_API_KEY=$(r 32)
MYELIN_SESSION_SECRET=$(r 48)
MYELIN_API_KEY_PEPPER=$(r 48)
MYELIN_EVIDENCE_SIGNING_KEY=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
OUT
