#!/bin/sh
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
# Container entrypoint: api | worker | migrate | admin <args> | check
set -eu
cd /opt/myelin/backend
cmd="${1:-api}"; [ $# -gt 0 ] && shift
case "$cmd" in
  api)
    exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8080}" \
      --proxy-headers --forwarded-allow-ips "${MYELIN_TRUSTED_PROXIES:-127.0.0.1}" \
      --workers "${MYELIN_WORKERS:-2}" --no-server-header --timeout-graceful-shutdown 25 "$@" ;;
  worker)
    exec python -m app.worker "$@" ;;
  migrate)
    : "${MYELIN_MIGRATIONS_DATABASE_URL:?MYELIN_MIGRATIONS_DATABASE_URL must be set}"
    alembic -c alembic.ini upgrade head
    if [ -n "${MYELIN_APP_LOGIN:-}" ]; then        # attach the API login to the least-privilege, NOBYPASSRLS role
      exec python -m app.admin_cli grant-app-login --login "$MYELIN_APP_LOGIN"
    fi ;;
  admin)
    exec python -m app.admin_cli "$@" ;;
  check)
    exec python -c "import app.main" ;;
  *)
    echo "usage: myelin [api|worker|migrate|admin <args>|check]" >&2; exit 64 ;;
esac
