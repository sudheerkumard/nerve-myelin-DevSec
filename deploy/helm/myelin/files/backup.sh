#!/bin/sh
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
# RAT Flea DevSec database backup: pg_dump -> SHA-256 manifest -> object storage.
# BACKUP_DEST: s3://bucket/prefix | azblob://account/container/prefix | file:///path
set -eu
: "${MYELIN_MIGRATIONS_DATABASE_URL:?}" "${BACKUP_DEST:?}"
URL=$(printf '%s' "$MYELIN_MIGRATIONS_DATABASE_URL" | sed 's#^postgresql+psycopg://#postgresql://#')
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=/work/myelin-$STAMP.dump
echo "backup start $STAMP"
pg_dump --dbname="$URL" --role=myelin_admin --enable-row-security --format=custom --compress=9 --no-owner --serializable-deferrable --file="$OUT"
sha256sum "$OUT" | awk '{print $1}' > "$OUT.sha256"
pg_restore --list "$OUT" > /dev/null
SIZE=$(wc -c < "$OUT")
case "$BACKUP_DEST" in
  file://*)
    D=${BACKUP_DEST#file://}
    mkdir -p "$D"
    cp "$OUT" "$OUT.sha256" "$D"/
    find "$D" -name 'myelin-*.dump*' -mtime +"${BACKUP_RETENTION_DAYS:-35}" -delete
    ;;
  s3://*)
    command -v aws >/dev/null || { echo "AWS CLI missing from backup image" >&2; exit 3; }
    aws s3 cp "$OUT" "$BACKUP_DEST/" --sse aws:kms
    aws s3 cp "$OUT.sha256" "$BACKUP_DEST/" --sse aws:kms
    ;;
  azblob://*)
    command -v az >/dev/null || { echo "Azure CLI missing from backup image" >&2; exit 3; }
    if [ -n "${AZURE_FEDERATED_TOKEN_FILE:-}" ]; then
      : "${AZURE_CLIENT_ID:?}" "${AZURE_TENANT_ID:?}"
      az login --service-principal --username "$AZURE_CLIENT_ID" --tenant "$AZURE_TENANT_ID" \
        --federated-token "$(cat "$AZURE_FEDERATED_TOKEN_FILE")" --allow-no-subscriptions >/dev/null
    elif [ -n "${AZURE_CLIENT_ID:-}" ]; then
      az login --identity --client-id "$AZURE_CLIENT_ID" --allow-no-subscriptions >/dev/null
    else
      az login --identity --allow-no-subscriptions >/dev/null
    fi
    R=${BACKUP_DEST#azblob://}
    ACC=${R%%/*}
    R=${R#*/}
    CON=${R%%/*}
    PFX=${R#*/}
    for f in "$OUT" "$OUT.sha256"; do
      az storage blob upload --auth-mode login --account-name "$ACC" -c "$CON" \
        -n "$PFX/$(basename "$f")" -f "$f" --only-show-errors
    done
    ;;
  *)
    echo "unsupported BACKUP_DEST" >&2
    exit 2
    ;;
esac
echo "backup ok file=$(basename "$OUT") bytes=$SIZE sha256=$(cat "$OUT.sha256")"
