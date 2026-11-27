#!/bin/sh
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
# Restore a RAT Flea DevSec backup into an EMPTY database, verify integrity, then re-check isolation.
#   scripts/ops/restore.sh /path/myelin-20261113T011700Z.dump postgresql://owner@host/myelin_restore
# Run with the owner (migrations) role. Roles myelin_app/myelin_auth/myelin_admin must already exist on the
# target cluster (create them by running `myelin migrate` once against any database on that cluster).
set -eu
DUMP=${1:?dump file}; TARGET=${2:?target database url}
if [ -f "$DUMP.sha256" ]; then
  [ "$(sha256sum "$DUMP" | awk '{print $1}')" = "$(cat "$DUMP.sha256")" ] || { echo "CHECKSUM MISMATCH - refusing to restore" >&2; exit 4; }
  echo "checksum ok"
fi
N=$(psql "$TARGET" -Atc "select count(*) from information_schema.tables where table_schema='public'")
[ "$N" = "0" ] || { echo "target database is not empty ($N tables) - refusing" >&2; exit 5; }
pg_restore --dbname="$TARGET" --no-owner --exit-on-error --single-transaction "$DUMP"
psql "$TARGET" -v ON_ERROR_STOP=1 -Atc "
  select 'schema='||version_num from alembic_version;
  select 'rls_tables='||count(*) from pg_class where relrowsecurity and relforcerowsecurity and relnamespace='public'::regnamespace;
  select 'tenants='||count(*) from tenants;"
echo "restore complete - now run: myelin admin verify-audit --tenant <slug>  (hash chain must report valid)"
